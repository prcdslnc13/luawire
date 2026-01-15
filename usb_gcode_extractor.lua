-- USB Leftover Capture Data Extractor for Wireshark
-- Extracts G-code or raw data from USB traffic to CNC/3D printer devices
--
-- Usage:
--   1. Copy this script to your Wireshark plugins directory, or
--   2. Load via: wireshark -X lua_script:usb_gcode_extractor.lua -r capture.pcapng
--   3. Access via Tools > Extract USB Data after loading a capture
--
-- Configuration options below:

-- Set to true for raw hex output, false for ASCII G-code interpretation
local OUTPUT_RAW_HEX = false

-- Set to true to include non-printable characters as escape sequences
local SHOW_ESCAPE_SEQUENCES = false

-- Minimum data length to include (filters out very short packets)
local MIN_DATA_LENGTH = 2

--------------------------------------------------------------------------------
-- Field extractors
--------------------------------------------------------------------------------
local usb_capdata = Field.new("usb.capdata")
local usb_src = Field.new("usb.src")
local usb_dst = Field.new("usb.dst")
local usb_data_fragment = Field.new("usb.data_fragment")
local usb_data_len = Field.new("usb.data_len")
local usbpcap_header_len = Field.new("usb.usbpcap_header_len")
local frame_time = Field.new("frame.time")
local frame_number = Field.new("frame.number")
local frame_len = Field.new("frame.len")

--------------------------------------------------------------------------------
-- Helper functions
--------------------------------------------------------------------------------

-- Convert ByteArray to hex string
local function bytearray_to_hex(bytes)
    if not bytes then return "" end
    local hex = {}
    for i = 0, bytes:len() - 1 do
        hex[#hex + 1] = string.format("%02X", bytes:get_index(i))
    end
    return table.concat(hex, " ")
end

-- Convert ByteArray to ASCII string, replacing non-printable chars
local function bytearray_to_ascii(bytes, show_escapes)
    if not bytes then return "" end
    local chars = {}
    for i = 0, bytes:len() - 1 do
        local byte = bytes:get_index(i)
        if byte >= 32 and byte <= 126 then
            -- Printable ASCII
            chars[#chars + 1] = string.char(byte)
        elseif byte == 10 then
            -- Newline
            chars[#chars + 1] = "\n"
        elseif byte == 13 then
            -- Carriage return - skip or show
            if show_escapes then
                chars[#chars + 1] = "\\r"
            end
        elseif byte == 9 then
            -- Tab
            chars[#chars + 1] = "\t"
        elseif show_escapes then
            -- Show as hex escape
            chars[#chars + 1] = string.format("\\x%02X", byte)
        end
    end
    return table.concat(chars)
end

-- Convert tvb range to hex string
local function tvb_to_hex(tvb, offset, length)
    if not tvb or length <= 0 then return "" end
    local hex = {}
    for i = 0, length - 1 do
        hex[#hex + 1] = string.format("%02X", tvb(offset + i, 1):uint())
    end
    return table.concat(hex, " ")
end

-- Convert tvb range to ASCII string
local function tvb_to_ascii(tvb, offset, length, show_escapes)
    if not tvb or length <= 0 then return "" end
    local chars = {}
    for i = 0, length - 1 do
        local byte = tvb(offset + i, 1):uint()
        if byte >= 32 and byte <= 126 then
            chars[#chars + 1] = string.char(byte)
        elseif byte == 10 then
            chars[#chars + 1] = "\n"
        elseif byte == 13 then
            if show_escapes then
                chars[#chars + 1] = "\\r"
            end
        elseif byte == 9 then
            chars[#chars + 1] = "\t"
        elseif show_escapes then
            chars[#chars + 1] = string.format("\\x%02X", byte)
        end
    end
    return table.concat(chars)
end

--------------------------------------------------------------------------------
-- Main extraction function
--------------------------------------------------------------------------------

local function extract_usb_data()
    -- Prompt user for output filename
    new_dialog(
        "USB Data Extractor - Output Settings",
        function(settings)
            local output_file = settings[1]
            local raw_mode = settings[2] == "true"

            if not output_file or output_file == "" then
                output_file = "usb_extracted_data.txt"
            elseif not output_file:match("%.txt$") then
                output_file = output_file .. ".txt"
            end

            -- Run the extraction
            do_extraction(output_file, raw_mode)
        end,
        "Output filename:", "usb_extracted_data.txt",
        "Raw hex mode (true/false):", tostring(OUTPUT_RAW_HEX)
    )
end

function do_extraction(output_filename, raw_mode)
    local file, err = io.open(output_filename, "w")
    if not file then
        report_failure("Cannot open output file: " .. output_filename .. "\nError: " .. (err or "unknown"))
        return
    end

    -- Write header
    file:write("=" .. string.rep("=", 78) .. "\n")
    file:write("USB Leftover Capture Data Extraction\n")
    file:write("Generated: " .. os.date("%Y-%m-%d %H:%M:%S") .. "\n")
    file:write("Mode: " .. (raw_mode and "Raw Hex" or "ASCII/G-code") .. "\n")
    file:write("=" .. string.rep("=", 78) .. "\n\n")

    local packet_count = 0
    local data_packet_count = 0

    -- Create a tap listener
    local tap = Listener.new("usb")

    function tap.packet(pinfo, tvb)
        packet_count = packet_count + 1

        -- Get data length and frame info
        local data_len_field = usb_data_len()
        local header_len_field = usbpcap_header_len()
        local flen = frame_len()

        local data_len = data_len_field and data_len_field.value or 0
        local header_len = header_len_field and header_len_field.value or 27
        local frame_length = flen and flen.value or 0

        -- Try multiple methods to get payload data
        local data_bytes = nil
        local data_hex = nil
        local data_ascii = nil
        local actual_len = 0

        -- Method 1: Check usb.capdata field
        local capdata = usb_capdata()
        if capdata then
            data_bytes = capdata.range:bytes()
        end

        -- Method 2: Check usb.data_fragment field
        if not data_bytes or data_bytes:len() == 0 then
            local data_frag = usb_data_fragment()
            if data_frag then
                data_bytes = data_frag.range:bytes()
            end
        end

        -- Method 3: Read directly from tvb after USB header (for CDC/bulk data)
        if (not data_bytes or data_bytes:len() == 0) and data_len > 0 then
            local payload_offset = header_len
            local payload_len = frame_length - header_len

            if payload_len > 0 and payload_offset + payload_len <= tvb:len() then
                data_hex = tvb_to_hex(tvb, payload_offset, payload_len)
                data_ascii = tvb_to_ascii(tvb, payload_offset, payload_len, SHOW_ESCAPE_SEQUENCES)
                actual_len = payload_len
            end
        end

        -- Process data_bytes if we got them from fields
        if data_bytes and data_bytes:len() > 0 then
            actual_len = data_bytes:len()
            data_hex = bytearray_to_hex(data_bytes)
            data_ascii = bytearray_to_ascii(data_bytes, SHOW_ESCAPE_SEQUENCES)
        end

        -- Skip if no data or too short
        if actual_len < MIN_DATA_LENGTH then
            return
        end

        -- Skip if ASCII mode and no meaningful content
        if not raw_mode and (not data_ascii or data_ascii:match("^%s*$")) then
            return
        end

        data_packet_count = data_packet_count + 1

        -- Get packet info
        local src = usb_src()
        local dst = usb_dst()
        local ftime = frame_time()
        local fnum = frame_number()

        local src_str = src and tostring(src) or "unknown"
        local dst_str = dst and tostring(dst) or "unknown"
        local time_str = ftime and tostring(ftime) or tostring(pinfo.abs_ts)
        local frame_str = fnum and tostring(fnum) or "?"

        -- Write packet header
        file:write(string.format("--- Packet #%s ---\n", frame_str))
        file:write(string.format("Time: %s\n", time_str))
        file:write(string.format("Source: %s  ->  Destination: %s\n", src_str, dst_str))
        file:write(string.format("Length: %d bytes\n", actual_len))
        file:write("Data:\n")

        -- Write data in requested format
        if raw_mode then
            file:write(data_hex or "")
        else
            file:write(data_ascii or "")
        end

        file:write("\n\n")
    end

    function tap.draw()
        -- Write summary
        file:write("=" .. string.rep("=", 78) .. "\n")
        file:write(string.format("Summary: %d packets with data out of %d total USB packets\n",
            data_packet_count, packet_count))
        file:write("=" .. string.rep("=", 78) .. "\n")

        file:close()

        -- Notify user
        report_failure(string.format(
            "Extraction complete!\n\nOutput: %s\nPackets with data: %d\nTotal USB packets: %d",
            output_filename, data_packet_count, packet_count
        ))
    end

    function tap.reset()
        packet_count = 0
        data_packet_count = 0
    end

    -- Trigger retap to process all packets
    retap_packets()
end

--------------------------------------------------------------------------------
-- Post-dissector for live viewing in packet details
--------------------------------------------------------------------------------

local usb_data_proto = Proto("usbdata", "USB Data Extractor")

local pf_ascii_data = ProtoField.string("usbdata.ascii", "ASCII Data")
local pf_hex_data = ProtoField.string("usbdata.hex", "Hex Data")

usb_data_proto.fields = { pf_ascii_data, pf_hex_data }

function usb_data_proto.dissector(tvb, pinfo, tree)
    -- Get data length and frame info
    local data_len_field = usb_data_len()
    local header_len_field = usbpcap_header_len()
    local flen = frame_len()

    local data_len = data_len_field and data_len_field.value or 0
    local header_len = header_len_field and header_len_field.value or 27
    local frame_length = flen and flen.value or 0

    local data_bytes = nil
    local data_hex = nil
    local data_ascii = nil
    local actual_len = 0

    -- Try usb.capdata
    local capdata = usb_capdata()
    if capdata then
        data_bytes = capdata.range:bytes()
    end

    -- Try usb.data_fragment
    if not data_bytes or data_bytes:len() == 0 then
        local data_frag = usb_data_fragment()
        if data_frag then
            data_bytes = data_frag.range:bytes()
        end
    end

    -- Try direct tvb access
    if (not data_bytes or data_bytes:len() == 0) and data_len > 0 then
        local payload_offset = header_len
        local payload_len = frame_length - header_len

        if payload_len > 0 and payload_offset + payload_len <= tvb:len() then
            data_hex = tvb_to_hex(tvb, payload_offset, payload_len)
            data_ascii = tvb_to_ascii(tvb, payload_offset, payload_len, false)
            actual_len = payload_len
        end
    end

    if data_bytes and data_bytes:len() > 0 then
        actual_len = data_bytes:len()
        data_hex = bytearray_to_hex(data_bytes)
        data_ascii = bytearray_to_ascii(data_bytes, false)
    end

    if actual_len < MIN_DATA_LENGTH then
        return
    end

    local subtree = tree:add(usb_data_proto, tvb(), "USB Extracted Data")
    if data_ascii and not data_ascii:match("^%s*$") then
        subtree:add(pf_ascii_data, data_ascii)
    end
    if data_hex then
        subtree:add(pf_hex_data, data_hex)
    end
end

register_postdissector(usb_data_proto)

--------------------------------------------------------------------------------
-- Register menu item
--------------------------------------------------------------------------------

if gui_enabled() then
    register_menu("Extract USB Data", extract_usb_data, MENU_TOOLS_UNSORTED)
end

print("USB G-code/Data Extractor loaded successfully")
print("Access via: Tools > Extract USB Data")
