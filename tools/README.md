# PWNI PCAP Cracker

`pwn_crack.py` is a small GUI/CLI that finds the PWNI ESP32-C5 on the LAN,
reads its SD-backed handshake list, downloads PCAPs, and cracks WPA/WPA2
4-way handshakes with `aircrack-ng`. `crack.py` is an alias for the same tool.

## Quick start

```sh
cd /path/to/esp32touch
python3 tools/crack.py                     # open now
python3 tools/crack.py --watch             # start hidden; open when device appears
python3 tools/crack.py --list              # CLI: device, handshakes, SD files
python3 tools/crack.py --wordlists         # show discovered wordlists
```

The current device is auto-discovered on the local network (or from the last
known IP). The watcher also scans the local `/24` if the DHCP address changed.

## Crack a capture

1. Wait for the header to show the device IP and `SD: ready`.
2. Select a **complete** handshake (or a **saved** PCAP) in the table.
3. The wordlist defaults to `rockyou.txt`, then the SecLists top-1M list,
   then the small bundled `common.txt`. Use **Browse...** or the drop-down to
   choose another.
4. Click **Crack selected**. The log shows aircrack-ng output and a
   `KEY FOUND` result appears at the bottom; **Copy key** copies it.

If the lists are missing:

```sh
tools/get_wordlists.sh
```

It downloads `rockyou.txt` (about 134 MB) and the SecLists top-1M list into
`tools/wordlists/`. The cracker always prefers rockyou, then SecLists, then
`common.txt`.

The device stores only EAPOL frames, not beacons, so the tool passes both the
BSSID and ESSID to aircrack-ng. Saved files are named
`SSID_<12-hex-BSSID>.pcap`, which lets the tool recover both from files that
are not in the live handshake table.

## SD card

The SD card stays in the device. The tool reads it through the device API:

- header `SD: ready` / `files: N` comes from `/api/status` and `/api/hs`;
- **Test SD** downloads the newest file and verifies the PCAP magic;
- **Download PCAP** caches files under `~/.cache/pwni-crack/pcaps/`;
- **Add local PCAP...** cracks a file copied from the card or received another
  way, with no device connected.

If the header says `SD: NOT MOUNTED`, the device is not exposing the card even
if the card is good. Reboot the device and check the serial boot log for
`SD card mounted` / `SD probe write=4`. Live partial handshakes remain in RAM;
only saved complete handshakes appear as files.

## Auto-open when the device appears

```sh
tools/install_autostart.sh
```

This installs a per-user autostart entry and an application-menu entry. The
watcher starts hidden at login and opens the window when the device becomes
reachable. To start it immediately:

```sh
python3 tools/crack.py --watch &
```

Closing the window exits that watcher; it will start again at next login.

## CLI

```sh
# list device + handshakes + SD files
python3 tools/crack.py --list

# see the wordlist search order
python3 tools/crack.py --wordlists

# crack a local capture (uses rockyou by default)
python3 tools/crack.py --crack /path/hs.pcap \
  --bssid AA:BB:CC:DD:EE:FF --essid MyNetwork

# or force a specific list
python3 tools/crack.py --crack /path/hs.pcap \
  --bssid AA:BB:CC:DD:EE:FF --essid MyNetwork \
  --wordlist tools/wordlists/SecLists/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt
```

## Requirements / limits

- `aircrack-ng` (installed here).
- `tkinter` for the GUI (installed here).
- Wordlists: rockyou and the SecLists top-1M list are present under
  `tools/wordlists/`. `tools/get_wordlists.sh` re-downloads them if removed.
- 4-way handshakes only. PMKID cracking is not automated; the device reports
  PMKID captures, but this tool does not convert them to a hashcat/aircrack
  PMKID string yet.
- PMF/802.11w clients cannot be deauthenticated with standard deauth frames;
  that does not affect offline PCAP cracking.
- Only use captures from networks you own or have explicit permission to test.

## Device OTA from GitHub

Firmware updates are initiated from the device dashboard, not this host tool:

**Settings → Maintenance → Update from GitHub**

The device downloads the current `dist/esp32touch.bin` from GitHub over HTTPS
and reboots. There is no automatic check. OTA is gated by the authorization
phrase.
