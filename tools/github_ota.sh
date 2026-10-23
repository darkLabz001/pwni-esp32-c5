#!/bin/sh
# Update a PWNI device from the latest GitHub release.
#
# Usage:
#   tools/github_ota.sh <device-ip> [phrase]
#
# Requires curl and python3. The firmware is downloaded from the public
# release asset and uploaded to the device's /api/ota endpoint.
set -eu

REPO="${PWNI_REPO:-darkLabz001/pwni-esp32-c5}"
IP="${1:-}"
PHRASE="${2:-${PWNI_PHRASE:-ADMIN}}"
[ -n "$IP" ] || { echo "usage: $0 <device-ip> [phrase]" >&2; exit 2; }

TMP=$(mktemp /tmp/pwni-ota.XXXXXX.bin)
trap 'rm -f "$TMP"' EXIT

URL=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(a["browser_download_url"] for a in d.get("assets",[]) if a["name"]=="esp32touch.bin"))')
[ -n "$URL" ] || { echo "no esp32touch.bin in latest release" >&2; exit 3; }

echo "release: $URL"
curl -fL --retry 2 -o "$TMP" "$URL"
echo "downloaded $(wc -c < "$TMP") bytes"

code=$(curl -sS -o /tmp/pwni-auth.json -w '%{http_code}' \
    -X POST -H 'Content-Type: application/json' \
    -d "{\"phrase\":\"$PHRASE\"}" "http://$IP/api/auth")
[ "$code" = "200" ] || { echo "unlock failed ($code): $(cat /tmp/pwni-auth.json)" >&2; exit 4; }

echo "flashing..."
curl -sS --max-time 120 -X POST -H 'Content-Type: application/octet-stream' \
    --data-binary @"$TMP" "http://$IP/api/ota"
echo
echo "device is rebooting; wait ~15 s, then open http://$IP/"
