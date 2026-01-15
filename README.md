# Luawire - USB G-code Extractor for Wireshark

Lua scripts for Wireshark that extract payload data from USB traffic captures. Designed for analyzing communication with CNC routers, laser cutters, 3D printers, and similar devices that use G-code over USB serial (CDC) connections.

## Features

- Extracts "leftover capture data" from USB packets
- Filters out packets without payload data
- Outputs ASCII text (G-code) or raw hexadecimal
- Includes packet metadata: timestamp, source, destination, data length
- Works with both Wireshark GUI and tshark command-line
- Supports USBPcap format captures

## Requirements

- **Wireshark** 3.0+ with Lua support enabled
- **tshark** (included with Wireshark) for CLI usage
- **Bash** shell for the wrapper script (macOS/Linux)

### Verifying Lua Support

```bash
tshark -v | grep -i lua
```

You should see "with Lua 5.x" in the output.

## Installation

### Option 1: Load on Demand

Use the `-X lua_script:` flag when launching Wireshark or tshark:

```bash
wireshark -X lua_script:usb_gcode_extractor.lua -r capture.pcapng
tshark -r capture.pcapng -X lua_script:usb_extractor_cli.lua
```

### Option 2: Install to Plugins Directory

Copy the scripts to your Wireshark plugins directory:

| Platform | Path |
|----------|------|
| macOS | `~/.config/wireshark/plugins/` |
| Linux | `~/.local/lib/wireshark/plugins/` |
| Windows | `%APPDATA%\Wireshark\plugins\` |

The scripts will load automatically when Wireshark starts.

## Usage

### CLI - Shell Wrapper (Recommended)

The easiest way to extract data from the command line:

```bash
# Basic usage - output goes to <input>_extracted.txt
./extract_usb_data.sh capture.pcapng

# Custom output filename
./extract_usb_data.sh capture.pcapng -o my_gcode.txt

# Raw hexadecimal mode
./extract_usb_data.sh capture.pcapng --raw

# Combined options
./extract_usb_data.sh capture.pcapng --raw -o raw_dump.txt
```

### CLI - Direct tshark Usage

```bash
# Basic extraction
tshark -r capture.pcapng -X lua_script:usb_extractor_cli.lua

# Custom output file
USB_OUTPUT_FILE=output.txt tshark -r capture.pcapng -X lua_script:usb_extractor_cli.lua

# Raw hex mode
USB_RAW_MODE=1 tshark -r capture.pcapng -X lua_script:usb_extractor_cli.lua
```

### Wireshark GUI

1. Open Wireshark with the script loaded:
   ```bash
   wireshark -X lua_script:usb_gcode_extractor.lua -r capture.pcapng
   ```
2. Go to **Tools > Extract USB Data**
3. Enter output filename and select mode (ASCII or raw hex)
4. Click OK to extract

The script also registers a post-dissector that adds an "USB Extracted Data" section to the packet details pane for packets containing payload data.

## Output Format

### ASCII Mode (Default)

```
================================================================================
USB Leftover Capture Data Extraction
Generated: 2025-01-15 14:36:22
Mode: ASCII/G-code
================================================================================

--- Packet #71 ---
Time: 2025-01-15 14:36:22.959355
Source: 1.10.1  ->  Destination: host
Length: 21 bytes
Data:
M116 X0 Y40 B1 P0 L0

--- Packet #73 ---
Time: 2025-01-15 14:36:22.960123
Source: host  ->  Destination: 1.10.3
Length: 126 bytes
Data:
G1 X-0.12S74.6
G1 X-0.12S83.4
G1 X-0.12S87.3

================================================================================
Extraction Complete
Packets with data: 90562 / 181769 total USB packets
================================================================================
```

### Raw Hex Mode

```
--- Packet #71 ---
Time: 2025-01-15 14:36:22.959355
Source: 1.10.1  ->  Destination: host
Length: 21 bytes
Data:
4D 31 31 36 20 58 30 20 59 34 30 20 42 31 20 50 30 20 4C 30 0A
```

## How It Works

The scripts use multiple methods to extract USB payload data:

1. **usb.capdata** - Standard "Leftover Capture Data" field
2. **usb.data_fragment** - Fragmented USB data
3. **Direct TVB access** - Reads raw packet bytes after the USB header for CDC/bulk transfers

This multi-method approach handles various USB capture formats and device types.

## Current Limitations

- **USBPcap format only**: Tested with Windows USBPcap captures. Linux usbmon format may require adjustments.
- **Single-byte filtering**: Packets with only 1 byte of data are filtered out (typically status/interrupt packets).
- **No reassembly**: USB packets are processed individually without reassembling fragmented transfers.
- **ASCII filtering**: In ASCII mode, non-printable characters (except newline/tab) are stripped.

## Potential Future Improvements

- [ ] **Linux usbmon support**: Detect and handle Linux USB capture format
- [ ] **Packet reassembly**: Reassemble fragmented USB transfers into complete messages
- [ ] **Direction filtering**: Option to extract only host-to-device or device-to-host traffic
- [ ] **Device filtering**: Filter by specific USB device address
- [ ] **G-code validation**: Optionally validate extracted text as valid G-code syntax
- [ ] **Streaming output**: Write output incrementally for very large captures
- [ ] **JSON output**: Structured output format for programmatic processing
- [ ] **Timestamp formats**: Configurable timestamp output (relative, epoch, ISO 8601)
- [ ] **Windows batch script**: `.bat` wrapper for Windows users

## File Descriptions

| File | Description |
|------|-------------|
| `usb_gcode_extractor.lua` | Full Wireshark GUI plugin with menu integration and post-dissector |
| `usb_extractor_cli.lua` | Lightweight CLI version for tshark batch processing |
| `extract_usb_data.sh` | Bash wrapper script for easy command-line usage |

## Capturing USB Traffic

### Windows (USBPcap)

1. Install [USBPcap](https://desowin.org/usbpcap/)
2. Run USBPcapCMD or use Wireshark's USBPcap interface
3. Select the USB root hub for your device
4. Capture traffic while operating your CNC/laser/3D printer

### Linux (usbmon)

```bash
# Load usbmon kernel module
sudo modprobe usbmon

# Find your device's bus number
lsusb

# Capture on that bus (e.g., bus 1)
sudo tshark -i usbmon1 -w capture.pcapng
```

### macOS

macOS does not natively support USB packet capture. Options:
- Use a Windows VM with USB passthrough
- Use a hardware USB protocol analyzer

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please open an issue or pull request on GitHub.
