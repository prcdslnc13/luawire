#!/bin/bash
#
# USB Data Extractor - Command Line Wrapper
#
# Extracts leftover capture data (G-code, etc.) from USB packet captures
#
# Usage:
#   ./extract_usb_data.sh <input_file.pcapng> [options]
#
# Options:
#   -o, --output <file>   Output filename (default: input_name_extracted.txt)
#   -r, --raw             Output raw hex instead of ASCII
#   -h, --help            Show this help message
#
# Examples:
#   ./extract_usb_data.sh capture.pcapng
#   ./extract_usb_data.sh capture.pcapng -o my_gcode.txt
#   ./extract_usb_data.sh capture.pcapng --raw -o raw_dump.txt

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LUA_SCRIPT="${SCRIPT_DIR}/usb_extractor_cli.lua"

# Default values
OUTPUT_FILE=""
RAW_MODE="0"
INPUT_FILE=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    echo "USB Data Extractor - Extract G-code/data from USB packet captures"
    echo ""
    echo "Usage: $0 <input_file> [options]"
    echo ""
    echo "Options:"
    echo "  -o, --output <file>   Output filename (default: <input>_extracted.txt)"
    echo "  -r, --raw             Output raw hex instead of ASCII/G-code"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 capture.pcapng"
    echo "  $0 capture.pcapng -o my_gcode.txt"
    echo "  $0 capture.pcapng --raw"
    exit 0
}

error() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

info() {
    echo -e "${GREEN}$1${NC}"
}

warn() {
    echo -e "${YELLOW}$1${NC}"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -r|--raw)
            RAW_MODE="1"
            shift
            ;;
        -*)
            error "Unknown option: $1"
            ;;
        *)
            if [[ -z "$INPUT_FILE" ]]; then
                INPUT_FILE="$1"
            else
                error "Multiple input files not supported"
            fi
            shift
            ;;
    esac
done

# Validate input
if [[ -z "$INPUT_FILE" ]]; then
    echo "Usage: $0 <input_file.pcapng> [options]"
    echo "Run '$0 --help' for more information."
    exit 1
fi

if [[ ! -f "$INPUT_FILE" ]]; then
    error "Input file not found: $INPUT_FILE"
fi

if [[ ! -f "$LUA_SCRIPT" ]]; then
    error "Lua script not found: $LUA_SCRIPT"
fi

# Check for tshark
if ! command -v tshark &> /dev/null; then
    error "tshark not found. Please install Wireshark."
fi

# Generate output filename if not specified
if [[ -z "$OUTPUT_FILE" ]]; then
    # Remove extension and add _extracted.txt
    BASENAME=$(basename "$INPUT_FILE")
    BASENAME_NO_EXT="${BASENAME%.*}"
    OUTPUT_FILE="${BASENAME_NO_EXT}_extracted.txt"
fi

# Show settings
echo "========================================"
echo "USB Data Extractor"
echo "========================================"
echo "Input:  $INPUT_FILE"
echo "Output: $OUTPUT_FILE"
if [[ "$RAW_MODE" == "1" ]]; then
    echo "Mode:   Raw Hex"
else
    echo "Mode:   ASCII/G-code"
fi
echo "========================================"
echo ""

# Run extraction
info "Extracting USB data..."

USB_OUTPUT_FILE="$OUTPUT_FILE" USB_RAW_MODE="$RAW_MODE" \
    tshark -r "$INPUT_FILE" -X lua_script:"$LUA_SCRIPT" 2>&1 | grep -v "^$" || true

# Check if output was created
if [[ -f "$OUTPUT_FILE" ]]; then
    LINES=$(wc -l < "$OUTPUT_FILE" | tr -d ' ')
    SIZE=$(ls -lh "$OUTPUT_FILE" | awk '{print $5}')
    echo ""
    info "Success! Output written to: $OUTPUT_FILE"
    echo "  Size: $SIZE ($LINES lines)"
else
    warn "Warning: Output file was not created. The capture may not contain USB data."
fi
