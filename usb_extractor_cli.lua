-- USB Leftover Capture Data Extractor - CLI/tshark version
--
-- Usage with tshark:
--   tshark -r input.pcapng -X lua_script:usb_extractor_cli.lua 2>/dev/null
--
-- Environment variables:
--   USB_OUTPUT_FILE  - Output filename (default: derived from input or "usb_output.txt")
--   USB_RAW_MODE     - Set to "1" for raw hex output (default: ASCII/G-code mode)
--
-- Example:
--   USB_OUTPUT_FILE=mydata.txt USB_RAW_MODE=0 tshark -r capture.pcapng -X lua_script:usb_extractor_cli.lua

--------------------------------------------------------------------------------
-- Configuration (override via environment variables)
--------------------------------------------------------------------------------

local OUTPUT_FILE = os.getenv("USB_OUTPUT_FILE") or "usb_output.txt"
local RAW_MODE = os.getenv("USB_RAW_MODE") == "1"

--------------------------------------------------------------------------------
-- Field extractors
--------------------------------------------------------------------------------

local usb_src = Field.new("usb.src")
local usb_dst = Field.new("usb.dst")
local usb_data_len = Field.new("usb.data_len")
local usb_capdata = Field.new("usb.capdata")
local usb_data_fragment = Field.new("usb.data_fragment")
local frame_time_epoch = Field.new("frame.time_epoch")
local frame_number = Field.new("frame.number")
local frame_len = Field.new("frame.len")

-- USB header length field (for USBPcap format)
local usbpcap_header_len = Field.new("usb.usbpcap_header_len")

--------------------------------------------------------------------------------
-- State
--------------------------------------------------------------------------------

local output_file = nil
local packet_count = 0
local data_packet_count = 0
local initialized = false

--------------------------------------------------------------------------------
-- Helper functions
--------------------------------------------------------------------------------

local function bytes_to_hex(tvb, offset, length)
    if not tvb or length <= 0 then return "" end
    local hex = {}
    for i = 0, length - 1 do
        hex[#hex + 1] = string.format("%02X", tvb(offset + i, 1):uint())
    end
    return table.concat(hex, " ")
end

local function bytes_to_ascii(tvb, offset, length)
    if not tvb or length <= 0 then return "" end
    local chars = {}
    for i = 0, length - 1 do
        local byte = tvb(offset + i, 1):uint()
        if byte >= 32 and byte <= 126 then
            chars[#chars + 1] = string.char(byte)
        elseif byte == 10 then
            chars[#chars + 1] = "\n"
        elseif byte == 13 then
            -- Skip carriage returns for cleaner output
        elseif byte == 9 then
            chars[#chars + 1] = "\t"
        end
    end
    return table.concat(chars)
end

local function bytearray_to_hex(bytes)
    if not bytes then return "" end
    local hex = {}
    for i = 0, bytes:len() - 1 do
        hex[#hex + 1] = string.format("%02X", bytes:get_index(i))
    end
    return table.concat(hex, " ")
end

local function bytearray_to_ascii(bytes)
    if not bytes then return "" end
    local chars = {}
    for i = 0, bytes:len() - 1 do
        local byte = bytes:get_index(i)
        if byte >= 32 and byte <= 126 then
            chars[#chars + 1] = string.char(byte)
        elseif byte == 10 then
            chars[#chars + 1] = "\n"
        elseif byte == 13 then
            -- Skip carriage returns
        elseif byte == 9 then
            chars[#chars + 1] = "\t"
        end
    end
    return table.concat(chars)
end

local function format_timestamp(epoch_val)
    if not epoch_val then return "0.000000" end
    local ts = tonumber(tostring(epoch_val))
    if not ts then return tostring(epoch_val) end
    return os.date("%Y-%m-%d %H:%M:%S", math.floor(ts)) ..
           string.format(".%06d", math.floor((ts % 1) * 1000000))
end

--------------------------------------------------------------------------------
-- Tap listener
--------------------------------------------------------------------------------

local tap = Listener.new("usb")

function tap.packet(pinfo, tvb)
    -- Initialize output file on first packet
    if not initialized then
        output_file = io.open(OUTPUT_FILE, "w")
        if not output_file then
            error("Cannot open output file: " .. OUTPUT_FILE)
        end

        output_file:write("================================================================================\n")
        output_file:write("USB Leftover Capture Data Extraction\n")
        output_file:write("Generated: " .. os.date("%Y-%m-%d %H:%M:%S") .. "\n")
        output_file:write("Mode: " .. (RAW_MODE and "Raw Hex" or "ASCII/G-code") .. "\n")
        output_file:write("================================================================================\n\n")

        initialized = true
    end

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
    local data_source = nil

    -- Method 1: Check usb.capdata field
    local capdata = usb_capdata()
    if capdata then
        data_bytes = capdata.range:bytes()
        data_source = "capdata"
    end

    -- Method 2: Check usb.data_fragment field
    if not data_bytes or data_bytes:len() == 0 then
        local data_frag = usb_data_fragment()
        if data_frag then
            data_bytes = data_frag.range:bytes()
            data_source = "data_fragment"
        end
    end

    -- Method 3: Read directly from tvb after USB header (for CDC/bulk data)
    if (not data_bytes or data_bytes:len() == 0) and data_len > 0 then
        local payload_offset = header_len
        local payload_len = frame_length - header_len

        if payload_len > 0 and payload_offset + payload_len <= tvb:len() then
            data_hex = bytes_to_hex(tvb, payload_offset, payload_len)
            data_ascii = bytes_to_ascii(tvb, payload_offset, payload_len)
            data_source = "tvb_payload"
            data_len = payload_len
        end
    end

    -- Skip packets without meaningful data
    if not data_bytes and not data_hex then
        return
    end

    if data_bytes and data_bytes:len() == 0 then
        return
    end

    -- Get actual data length
    local actual_len = 0
    if data_bytes then
        actual_len = data_bytes:len()
        data_hex = bytearray_to_hex(data_bytes)
        data_ascii = bytearray_to_ascii(data_bytes)
    else
        actual_len = data_len
    end

    -- Skip single-byte interrupt packets (usually status bytes)
    if actual_len < 2 then
        return
    end

    -- Check if ASCII output has meaningful content
    if not RAW_MODE and (not data_ascii or data_ascii:match("^%s*$")) then
        return
    end

    data_packet_count = data_packet_count + 1

    -- Extract packet info
    local src = usb_src()
    local dst = usb_dst()
    local ftime = frame_time_epoch()
    local fnum = frame_number()

    local src_str = src and tostring(src) or "?"
    local dst_str = dst and tostring(dst) or "?"
    local time_str = format_timestamp(ftime)
    local frame_str = fnum and tostring(fnum) or "?"

    -- Write to file
    output_file:write(string.format("--- Packet #%s ---\n", frame_str))
    output_file:write(string.format("Time: %s\n", time_str))
    output_file:write(string.format("Source: %s  ->  Destination: %s\n", src_str, dst_str))
    output_file:write(string.format("Length: %d bytes\n", actual_len))
    output_file:write("Data:\n")

    if RAW_MODE then
        output_file:write(data_hex or "")
    else
        output_file:write(data_ascii or "")
    end

    output_file:write("\n\n")
end

function tap.draw()
    if output_file then
        output_file:write("================================================================================\n")
        output_file:write(string.format("Extraction Complete\n"))
        output_file:write(string.format("Packets with data: %d / %d total USB packets\n",
            data_packet_count, packet_count))
        output_file:write("================================================================================\n")
        output_file:close()

        io.stderr:write(string.format("\nExtraction complete: %s\n", OUTPUT_FILE))
        io.stderr:write(string.format("Packets with data: %d / %d\n", data_packet_count, packet_count))
    end
end

function tap.reset()
    packet_count = 0
    data_packet_count = 0
    initialized = false
end
