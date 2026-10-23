#!/bin/sh
# Install the PWNI cracker watcher for the current user. It starts hidden at
# login and opens automatically when the device is reachable.
set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
AUTOSTART="$HOME/.config/autostart"
APPS="$HOME/.local/share/applications"
mkdir -p "$AUTOSTART" "$APPS"
sed "s|@DIR@|$DIR|g" "$DIR/pwn-crack.desktop.in" > "$AUTOSTART/pwn-crack.desktop"
cp "$AUTOSTART/pwn-crack.desktop" "$APPS/pwn-crack.desktop"
chmod +x "$DIR/pwn_crack.py"

echo "installed: $AUTOSTART/pwn-crack.desktop"
echo "installed: $APPS/pwn-crack.desktop"
echo "start now with:"
echo "  python3 $DIR/pwn_crack.py --watch &"
