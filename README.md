# pwni — a Pwnagotchi-style Wi-Fi pet for the Waveshare ESP32-C5-Touch-LCD-3.5

`pwni` turns the [Waveshare ESP32-C5-Touch-LCD-3.5](https://www.waveshare.com/esp32-c5-touch-lcd-3.5.htm) into a standalone, touch-first Wi-Fi awareness pet. It passively sniffs 2.4 GHz and 5 GHz, tracks access points and clients, captures WPA/WPA2/WPA3 handshakes and RSN PMKIDs, writes radiotap PCAPs to microSD, and learns channel-hopping strategies on-device. A 320×480 LVGL interface shows an animated face plus **SCAN**, **LOOT**, and **SET** screens. Once connected to Wi-Fi, a built-in web dashboard exposes the same telemetry and controls from a browser.

> [!WARNING]
> Active deauthentication is compiled into this build (`PWN_ENABLE_DEAUTH=1`) but remains **locked at runtime**. You must enter the authorization phrase on the device, over serial, or in the web UI. Auto-deauth is off by default. Only use active features against networks you own or have explicit written permission to test. See [docs/LEGAL.md](docs/LEGAL.md).
>
> **ESP32-C5 deauth patch:** stock ESP-IDF rejects raw deauthentication frames with `ESP_ERR_INVALID_ARG`. This workspace applies the one-instruction `libnet80211.a` patch and was tested by disconnecting a real client with the 8-second burst. If you reinstall/update ESP-IDF, reapply it with `python3 tools/patch_c5_deauth.py --apply` and rebuild. See [docs/C5_DEAUTH.md](docs/C5_DEAUTH.md).
>
> **Deauth is an 8-second burst**, not a single frame. Clients often reassociate in about a second after one frame; the burst keeps them down while it runs. The web UI has a **Stop** button, and the device skips its own STA. Targeting the machine running your browser will drop the dashboard until that client reconnects.

## What works

- **Passive dual-band sniffer** — promiscuous 2.4 GHz + 5 GHz capture with 802.11 management/data parsing.
- **Handshake and PMKID capture** — EAPOL M1–M4 classification, RSN PMKID extraction, per `(BSSID, STA)` slots, deduplication, and PCAP output.
- **microSD storage** — PCAPs written to `/sdcard/handshakes/`; the card is mounted at 10 MHz because the LCD and SD share one SPI bus. Web/SET show free space and a **Remount SD** action; writes are atomic (temp + rename), timestamped (`SSID_20261023-160000_BSSID.pcap`), and paired with a `<pcap>.json` sidecar (SSID, BSSID, STA, channel, RSSI, frames, completion/PMKID flags, save time). A dedicated writer task drains a PSRAM queue, so the sniffer never blocks on SD I/O and writes are serialized against display flushes.
- **Richer PCAPs** — each saved handshake now includes a beacon/probe-response context frame and radiotap channel/RSSI, so aircrack/hcxtools can identify the ESSID and band without manual hints.
- **On-device learning** — a compact REINFORCE MLP (8→16→6) chooses between six hop plans; weights persist in NVS.
- **Touch UI** — animated face, moods, XP/level/bond, live stats, event log, network scanner, capture list, and settings. Bottom navigation: **FACE / SCAN / LOOT / SET**.
- **On-device Wi-Fi setup** — scan from the device, pick an AP, type the password on the LVGL keyboard, and save credentials to NVS. Autoconnect is configurable.
- **Setup AP fallback** — with no saved credentials, or after 30 seconds of failed station joins, the device starts an open `PWNI-Setup-XXXX` SoftAP at `http://192.168.4.1/` so the dashboard can be used to configure Wi-Fi. The AP is pinned to channel 1, channel hopping pauses, and the AP stops as soon as the station gets an IP. The setup AP has **no Wi-Fi password**; anyone in radio range can reach the dashboard while it is active, though the dashboard still requires `admin` / `ADMIN` Basic auth. Use it only long enough to join your own network.
- **Web dashboard** — served on port 80 at `http://<device-ip>/` with live status, networks, clients, captures, PCAP download, attack controls, and settings.
- **Host PCAP cracker** — `tools/pwn_crack.py` (alias `tools/crack.py`) auto-discovers the device, lists SD-backed handshakes, downloads PCAPs, and runs `aircrack-ng` with **rockyou.txt**, the **SecLists top-1M** list, or a custom wordlist. `tools/install_autostart.sh` starts it hidden at login and opens it when the device appears. See [tools/README.md](tools/README.md).
- **Runtime-gated active attacks** — unlock with `ADMIN` (case-insensitive), then deauth from the device, web, or API. This workspace uses the patched C5 WiFi library, so frames are actually transmitted; stock ESP-IDF blocks them. Deauth runs as a configurable burst (5/8/15/30 s in web; 8 s on device) with **Stop** on both, shows **PMF** AP badges, and warns when PMF may make deauth ineffective. Locking and auto-deauth remain explicit user actions.
- **Capture hunt** — a bounded, deauth-assisted handshake capture. Pick a target AP (and optionally one observed client) in the web **Attacks** tab or from the device AP detail sheet; the firmware sends a limited deauth burst, polls the capture table, and stops as soon as a complete 4-way handshake or PMKID is saved, or after 20 s. It never targets the device's own STA, skips broadcast for the AP the device is associated with, and reports PMF warnings.
- **Diagnostics** — `selftest` injects a synthetic handshake and verifies the resulting PCAP; `shot`, `tab`, and `touchtest` help with UI/touch bring-up.
- **Stable clocks** — CPU 240 MHz, flash 80 MHz QIO, PSRAM 80 MHz quad. The build favors stability over the highest possible clock.

## Hardware target

See [docs/HARDWARE.md](docs/HARDWARE.md) for the full board and pin notes.

- ESP32-C5HR8, 32 MB flash, 8 MB PSRAM
- 320×480 ST7796 SPI display
- FT6336 capacitive touch (I²C)
- microSD via SPI2 (shared with the LCD)
- ES8311 audio, BF3901 camera, AXP2101 PMU, QMI8658 IMU, SHTC3 sensor, PCF85063 RTC
- Native USB-Serial/JTAG on USB-C (`/dev/ttyACM0` on Linux)

## Build and flash

```bash
cd /path/to/esp32touch
source ~/esp/esp-idf/export.sh
idf.py build
idf.py -p /dev/ttyACM0 flash
```

Open the serial console at 115200 baud, or use `idf.py -p /dev/ttyACM0 monitor`. The boot log should show:

```text
capture: SD card mounted, handshakes -> /sdcard/handshakes
esp32_c5_touch_lcd_3_5: Touch ready: raw 320x480 swap=0 mirror_x=0 mirror_y=0
esp_lvgl:touch: Touch input device registered successfully (IRQ mode: disabled)
web: web UI listening on :80 (21 handlers)
net: got IP <device-ip> — web UI: http://<device-ip>/
```

The IP address depends on your network. There is **no mDNS**; use the address printed in the log (or the device's `SET` screen).

## First boot and Wi-Fi setup

### On the device

1. Tap **SET** in the bottom navigation.
2. In **WIFI CONNECTION**, tap **SCAN**. This switches to the **SCAN** tab and starts a network scan.
3. Tap the network you want. The AP card shows channel, security, RSSI, and WPS status.
4. Tap **CONNECT**. For a secured network, the password keyboard opens. Use the `ABC` / `1#` keys on the keyboard for uppercase and symbols.
5. The credentials are saved to NVS and used on subsequent boots. Use the **reconnect at boot** switch to control autoconnect.
6. **DISCONNECT** leaves the current AP; **FORGET** also erases the saved credentials.

### Headless / serial

```text
wifi <ssid> <password>
```

This connects immediately and saves the credentials to NVS. The password is not echoed by the device. Use `wifi <ssid>` for an open network.

### Web dashboard

Open `http://<device-ip>/` from a device on the same network. If the device is in setup mode, join the open `PWNI-Setup-XXXX` network and open `http://192.168.4.1/` instead; the dashboard shows a setup banner until the device joins your Wi-Fi. The dashboard has six tabs:

- **Dash** — mood, level, bond, reward, live AP/client/capture counts, channel, strategy, recent events.
- **Nets** — nearby APs with SSID/BSSID/channel/RSSI/security; scan and connect.
- **Clients** — observed stations with BSSID/RSSI.
- **Caps** — captured handshakes and PMKIDs from this session, plus a **Saved PCAPs** table read from the SD card (survives reboots), with PCAP download.
- **Attack** — authorization state, deauthentication, capture hunt, auto-deauth, pause/hop controls.
- **Set** — Wi-Fi connection, display brightness, maintenance, system information.

### API

All responses are JSON unless noted. `POST` bodies use `Content-Type: application/json`.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/status` | Firmware, uptime, heap, pet, radio, SD, network, and build info |
| GET | `/api/aps` | Access-point table |
| GET | `/api/clients` | Observed client table (unicast only) |
| GET | `/api/hs` | Captured handshakes / PMKIDs plus saved PCAP files |
| GET | `/api/pcap?name=<file>` | Download a PCAP from `/sdcard/handshakes/` |
| GET | `/api/hs_meta?name=<file>` | Download the JSON sidecar for a saved PCAP |
| POST | `/api/scan` | Start a network scan |
| POST | `/api/connect` | Connect to an AP (`ssid`, `pass`, `save`) |
| POST | `/api/disconnect` | Disconnect (`forget` optional) |
| POST | `/api/auth` | Unlock with `{"phrase":"..."}`; lock with `{"off":true}` |
| POST | `/api/attacks` | Set auto-deauth (`auto`) while unlocked |
| POST | `/api/deauth` | Start an 8-second deauth burst (`bssid`, `sta` or `all`, optional `duration_ms`, `interval_ms`, `reason`); `{"stop":true}` stops it; requires unlock |
| POST | `/api/hunt` | Deauth-assisted capture hunt (`bssid`, optional `sta`, optional `duration_ms`, default 20 s, max 60 s); `{"stop":true}` stops it; requires unlock |
| POST | `/api/hop` | Park the sniffer on a channel (blocked while associated) |
| POST | `/api/hop_ap` | Park on an AP's channel (blocked while associated) |
| POST | `/api/pause` | Pause/resume hopping (`paused`) |
| POST | `/api/strategy` | Force a hop plan (`action`, `-1` = auto) |
| POST | `/api/brightness` | Set backlight percent (`percent`, 10–100) |
| POST | `/api/autoconnect` | Set the autoconnect flag (`on`) |
| POST | `/api/reset_brain` | Wipe the learned policy |
| POST | `/api/reboot` | Restart the device |

The authorization phrase is `ADMIN` and matching is case-insensitive. The phrase is a deliberate speed bump, not a security boundary. `ADMIN` is intentionally weak and guessable; change `PWN_AUTH_PHRASE` in `main/pwn_config.h` if the device is accessible to others. Auto-deauth defaults to off. Deauth starts an 8-second burst and returns immediately; send `{"stop":true}` to stop it. Deauth and hop calls that need an exclusive radio return `409 Conflict` while associated.

`POST /api/hunt` returns immediately with `started`, the target `bssid`/`sta`, `duration_ms`, and a PMF `warning` when relevant. `/api/status` exposes `hunt_active`, `hunt_result` (`idle`, `hunting`, `captured`, `timeout`, `stopped`, `error`), `hunt_bssid`, `hunt_sta`, `hunt_elapsed_ms`, `hunt_duration_ms`, `hunt_file`, and `hunt_message`. The deauth burst is stopped as soon as a complete 4-way handshake or PMKID is saved for the target, or when the duration expires; hunts require the same runtime unlock as deauth.

`/api/status` also exposes network state: `connected`, `connecting`, `have_creds`, `autoconnect`, `ssid`, `ip`, `rssi`, `sta_channel`, and the setup fallback fields `setup_mode`, `ap_active`, `ap_ssid`, and `ap_ip`. When `setup_mode` is true, use the existing Settings Wi-Fi panel at `http://192.168.4.1/`; submitting valid credentials starts a station join and the AP is removed once an IP is obtained.

## On-device UI

| Tab | What it does |
|---|---|
| **FACE** | Animated eyes/mouth, blink and mood changes, XP/level/bond, channel/AP/HS stats, last event. Tap the face to pet it. |
| **SCAN** | AP list with RSSI bars, channel, security, WPS, and handshake badges. Tap a row for details, connect, or (after unlocking) deauth or run a 20-second **HUNT**. The scan button refreshes. |
| **LOOT** | Captured handshakes from the current session, with BSSID and `PMKID` / `4WAY` / `SAVED` tags. Tap a row to show its file name. The web **Caps** tab also lists saved PCAPs from the SD card. |
| **SET** | Wi-Fi connection and autoconnect, setup-AP SSID/URL with a scannable QR code when fallback is active, web dashboard URL with a QR code, active-attack unlock/lock, auto-deauth, strategy override, display brightness and screen timeout, reset-brain, reboot. The settings page scrolls. |

The bottom navigation is always available. The backlight can be dimmed from the settings slider.

The panel dims to 15% after 45 seconds without a touch and blanks after 60
seconds by default. The first tap restores the slider level and is swallowed so
it cannot press an invisible control. **SET → DISPLAY → sleep** offers 30 s,
60 s, 2 min, 5 min, or off; the choice is stored in NVS. The panel stays awake
while a text-entry/modal dialog is open, during an active deauth burst or capture hunt, and
during GitHub OTA. The dashboard QR is generated on-device from
`http://<device-ip>/` and refreshes whenever the IP changes; offline it shows a
`no link` placeholder.

## Serial CLI

Type `help` at the `pwni>` prompt. Commands:

```text
status              pet + radio summary
aps [n]             list access points by signal
clients [n]         list stations
hs                  captured handshakes / PMKIDs
scan                force a synchronous scan
plan <name>         force a hop plan (linger-2g, hop-2g,
                    scan-5g-low, scan-5g-high, hunt, rest)
hop <ch>            park on one channel
selftest            inject a fake handshake, verify the PCAP
shot                dump a small BMP screenshot over serial
tab <0-3>           show FACE/SCAN/LOOT/SET screen
touchtest           print touch coordinates for 10 seconds
wifi <ssid> <pass>  connect headlessly (saved to NVS)
pause | resume      stop/start channel hopping
auth <phrase>       unlock active attacks (build-gated)
reset-brain         wipe the learned policy
save                flush handshakes to SD
reboot              restart the device
help                this text
```

`selftest` is safe: it feeds a synthetic beacon, PMKID M1, and M2 through the real parser, writes a test PCAP, and verifies the link type and packet count. It does not transmit.

## Configuration

Key settings live in [`main/pwn_config.h`](main/pwn_config.h):

- `PWN_ENABLE_DEAUTH` — defaults to `1`. Set to `0` for a passive-only firmware; the UI/API deauth paths then remain unavailable.
- `PWN_AUTH_PHRASE` — the runtime unlock phrase. Matching is case-insensitive across the UI, CLI, and web.
- `PWN_COUNTRY` — regulatory domain; defaults to `US`. Change it to your country.
- `PWN_EPOCH_MS`, `PWN_MAX_APS`, `PWN_MAX_CLIENTS`, `PWN_MAX_HS`, `PWN_RB_BYTES` — behavior and table sizing.

Build defaults live in [`sdkconfig.defaults`](sdkconfig.defaults): ESP-IDF 5.5, `esp32c5`, 32 MB flash, 8 MB quad PSRAM at 80 MHz, 80 MHz QIO flash, LVGL 9 with Montserrat/UNSCII fonts, USB-Serial/JTAG console, FATFS long filenames, and the web-server socket limits.

### Touch orientation

The FT6336 and the 320×480 panel share the same portrait orientation. The BSP uses the raw controller coordinates directly:

```c
.touch_flags = {
    .swap_xy = 0,
    .mirror_x = 0,
    .mirror_y = 0
}
```

The boot log should report `raw 320x480 swap=0 mirror_x=0 mirror_y=0`. If you have a panel revision with a different orientation, change these flags in `bsp_display_start()` in the vendored BSP. The LVGL input adapter follows the display rotation.

### microSD

The card is mounted at **10 MHz** on the shared SPI2 bus. 20 MHz was marginal on this board and produced `EIO` on multi-block writes. SD access in the web/PCAP path is serialized against display flushes with `capture_bus_lock()` / `capture_bus_unlock()`. If the card is missing or unwritable, the firmware keeps running and reports `sd: false`; captures stay in RAM.

## Project structure

```text
main/
├── app_main.c          # Bring-up order
├── pwn_config.h        # Tunables and feature flags
├── pwn_brain.*         # REINFORCE MLP + hop policies
├── pwn_capture.*       # EAPOL/PMKID parsing, slots, PCAP writer, SD mount
├── pwn_hunt.*          # Bounded deauth-assisted capture task
├── pwn_wifi.*          # Sniffer, AP/client tables, scan, hopping, deauth, selftest
├── pwn_net.*           # STA manager, setup SoftAP fallback, NVS credentials, channel lock
├── pwn_web.*           # HTTP server, JSON APIs, PCAP download
├── pwn_web_page.h      # Embedded dashboard HTML/JS/CSS
├── pwn_pet.*           # Moods, XP/bond, epochs, reward, learning loop
├── pwn_ui.*            # LVGL face, tabs, scanner, loot, settings, touch UI
└── pwn_cli.*           # USB-Serial/JTAG CLI
components/waveshare__esp32_c5_touch_lcd_3_5/  # Vendored BSP
components/esp_lcd_touch_ft6336/                # FT6336 driver
docs/                   # Hardware, architecture, legal notes
```

## Troubleshooting

- **Touch is offset or only part of the screen works** — check the boot log line `Touch ready: raw ... swap=... mirror_x=... mirror_y=...`. On this panel it must be `320x480 swap=0 mirror_x=0 mirror_y=0`. If not, fix `touch_flags` in the BSP and rebuild. `touchtest` prints transformed coordinates; tapping the FACE button should print roughly `x=44 y=453`.
- **`sd: false` or mount failures** — use a FAT32 card, reseat it, and check the boot log. The firmware tries 10 MHz; very slow or counterfeit cards may still fail. Use **Remount SD** in the web **SET** tab; the dashboard now shows free/total space. Complete/PMKID handshakes are queued immediately; partial M1+M2 stays in RAM until a complete handshake, slot eviction, or an explicit `save`/reboot flush.
- **Handshake counts reset after reboot** — the live slot table is in RAM. Saved PCAPs remain on the card and are listed under **Caps → Saved PCAPs** in the web UI (and can still be downloaded by filename).
- **Web page unreachable** — confirm the device is associated and use the exact IP from the boot log or `SET` screen. The dashboard is on port 80 and there is no mDNS. Client isolation on some hotspots blocks device-to-device traffic.
- **Wi-Fi will not connect** — verify the password and security mode. The device scans 2.4 GHz and 5 GHz; the station connects on the AP's channel. Watch the serial log for the disconnect reason. After 30 seconds without a connection the device starts the open `PWNI-Setup-XXXX` SoftAP; join it and open `http://192.168.4.1/` to fix the credentials. The AP stops when the station gets an IP.
- **Setup AP is visible but you do not want it** — it appears only with no saved credentials or after a failed join window, and it is removed as soon as the station connects. Save valid credentials from the dashboard's **Settings → WiFi connection** panel (or the device **SET** screen). There is no separate setup password, so keep the setup window short.
- **UI freezes during heavy SD activity** — SD and LCD share SPI2; the firmware serializes access, but a failing card can still stall. Remove the card and reboot to confirm.
- **Deauth returns 403** — active attacks are locked. Unlock with `ADMIN` (case-insensitive) in `SET`, the CLI, or `/api/auth`. While associated, deauth/hop requests that need an exclusive radio return `409`.
- **Deauth says `0 frames` or `tx_error: ESP_ERR_INVALID_ARG`** — you are unlocked, but the C5 Wi-Fi library is refusing the frame. Run `python3 tools/patch_c5_deauth.py --check`. If it says `STOCK`, apply the patch (`--apply`), run `idf.py fullclean && idf.py build`, and reflash. If it says `PATCHED`, the target is on another channel while associated (disconnect first), the BSSID/station is invalid, or the client uses protected management frames (PMF). See [docs/C5_DEAUTH.md](docs/C5_DEAUTH.md).
- **The deauth burst works but the client comes back after 8 seconds** — that is the burst ending. Run it again, use a longer `duration_ms`, or target the client from the Clients tab for a per-client burst. PMF clients ignore unprotected deauth entirely.
- **The web dashboard drops during deauth** — you targeted the machine running the browser (or its AP with broadcast). The firmware skips its own STA, but it cannot protect your laptop/phone. Use a second device to watch, or reconnect after the burst.


## Dashboard login

The web dashboard uses HTTP Basic auth: user `admin`, password `ADMIN` (the same runtime phrase). It is a LAN speed bump, not TLS; do not expose the device directly to the internet. The setup SoftAP is open at the Wi-Fi layer, so treat it as a short-lived provisioning network and join your real Wi-Fi promptly.

## Releases and OTA

Prebuilt firmware and the host tool are published at:

<https://github.com/darkLabz001/pwni-esp32-c5/releases>

- Download `esp32touch.bin`, `bootloader.bin`, `partition-table.bin`,
  `ota_data_initial.bin`, and `flash.sh`, then run `./flash.sh [port]`.
- Update a reachable device manually from **Settings → Maintenance → Update from GitHub**. The device downloads `dist/esp32touch.bin` from this repo; nothing is automatic.
- The release tool zip contains the PCAP cracker and C5 deauth patch helper;
  wordlists are fetched by `tools/get_wordlists.sh`, not bundled.

The firmware binary contains no Wi-Fi credentials; NVS on the device holds
those. Public docs use placeholders for IPs, SSIDs, and BSSIDs.

## Documentation

- [docs/HARDWARE.md](docs/HARDWARE.md) — board, pins, buses, bring-up, touch, SD, clocks.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — tasks, modules, data flow, memory, concurrency.
- [docs/C5_DEAUTH.md](docs/C5_DEAUTH.md) — ESP32-C5 deauth patch, verification, and limitations.
- [tools/README.md](tools/README.md) — host PCAP cracker, auto-open watcher, SD-backed handshakes, aircrack-ng.
- [docs/LEGAL.md](docs/LEGAL.md) — authorized-use, privacy, and safety notes.

## License / status

This is a personal port and research toy, not a commercial product. The vendored BSP and ESP-IDF components retain their original licenses. There is no warranty; you are responsible for how you use the radio.
