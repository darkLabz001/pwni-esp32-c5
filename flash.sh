#!/bin/sh
# Flash a PWNI release from the files in this directory.
# Usage: ./flash.sh [serial-port]
set -eu
PORT="${1:-/dev/ttyACM0}"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python -m esptool --chip esp32c5 -p "$PORT" -b 460800 \
  --before default_reset --after hard_reset \
  write_flash --flash_mode dio --flash_size 32MB --flash_freq 80m \
  0x2000 "$HERE/bootloader.bin" \
  0x8000 "$HERE/partition-table.bin" \
  0xd000 "$HERE/ota_data_initial.bin" \
  0x20000 "$HERE/esp32touch.bin"
echo "flashed. Device should boot and show its IP on the SET screen."
