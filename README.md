# pwni — a Pwnagotchi-style Wi-Fi pet for the Waveshare ESP32-C5-Touch-LCD-3.5

`pwni` turns the [Waveshare ESP32-C5-Touch-LCD-3.5](https://www.waveshare.com/esp32-c5-touch-lcd-3.5.htm) into a standalone, touch-first Wi-Fi awareness pet. It passively sniffs 2.4 GHz and 5 GHz, tracks access points and clients, captures WPA/WPA2/WPA3 handshakes and RSN PMKIDs, writes radiotap PCAPs to microSD, and learns channel-hopping strategies on-device. A 320×480 LVGL interface shows an animated face plus **SCAN**, **LOOT**, and **SET** screens. Once connected to Wi-Fi, a built-in web dashboard exposes the same telemetry and controls from a browser.

> [!WARNING]
> Active deauthentication is compiled into this build (`PWN_ENABLE_DEAUTH=1`) but remains **locked at runtime**. You must enter the authorization phrase on the device, over serial, or in the web UI. Auto-deauth is off by default. Only use active features against networks you own or have explicit written permission to test. See [docs/LEGAL.md](docs/LEGAL.md).
>
> **BLE HID keyboard is experimental and active.** It advertises as `PWNI-KBD` and types a payload into the host that connects. It is opt-in, requires the authorization phrase, is off after every boot, and pauses the passive BLE scanner while active. Never run it against a host you do not own or have explicit written permission to test. See [docs/HID.md](docs/HID.md).
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
- **Web dashboard** — served on port 80 at `http://<device-ip>/` with live status, networks, clients, passive recon, captures, PCAP download, attack controls, and settings.
- **Passive BLE observer** — opt-in NimBLE scanner (off by default) that records address/address type, name, RSSI, advertised service UUIDs, and common beacon types (iBeacon, Eddystone, AltBeacon, Exposure Notification, Fast Pair). It never connects, pairs, writes, or sends scan requests. Wi-Fi keeps coexistence priority; scanning pauses while the setup AP or a deauth burst owns the radio.
- **BLE HID keyboard (experimental)** — opt-in, runtime-authorized HID-over-GATT keyboard. It advertises as `PWNI-KBD`, accepts a host connection, and types a selected DuckyScript-style text payload from `/sdcard/payloads/*.txt` (text, `DELAY`, `ENTER`/`TAB`/`ESC`, modifier combos, `REM`). HID mode is never started automatically, pauses the passive BLE scanner for the whole session, releases keys on stop, and logs start/stop/execution in `last_event`. It stores no target data. Only use it on hosts you own or have written permission to test. See [docs/HID.md](docs/HID.md).
- **Passive DNS / SNI / HTTP visibility** — parses DNS question names, TLS ClientHello SNI, and HTTP `Host` headers from unprotected 802.11 data frames, with bounded tables, counts, and timestamps. Only metadata is retained: no payloads, URLs, cookies, query answers, or credentials. WPA/WPA2/WPA3 traffic is encrypted and remains invisible.
- **Client fingerprinting** — a small built-in OUI vendor table, locally-administered/randomized MAC detection, first/last-seen timestamps, and the last few unique probe-request SSIDs per client.
- **Persistent watchlist** — add watched SSIDs, Wi-Fi MACs, or BLE addresses/names from the web UI. Matches are stored in NVS, raise a dashboard badge/toast, and appear in `/api/status` (`watch_*` fields plus `last_event`). Passive matching only.
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
web: web UI listening on :80 (37 handlers)
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

Open `http://<device-ip>/` from a device on the same network. If the device is in setup mode, join the open `PWNI-Setup-XXXX` network and open `http://192.168.4.1/` instead; the dashboard shows a setup banner until the device joins your Wi-Fi. The dashboard has eight tabs:

- **Dash** — mood, level, bond, reward, live AP/client/capture/BLE counts, channel, strategy, recent events.
- **Nets** — nearby APs with SSID/BSSID/channel/RSSI/security; scan and connect.
- **Clients** — observed stations with vendor/randomized flags, RSSI, probe history, first/last seen, plus the watchlist editor.
- **BLE** — opt-in passive BLE scanner state and recent advertisers (address type, name, RSSI, service UUIDs, beacon type).
- **Net intel** — recent DNS queries, TLS SNI hosts, HTTP `Host` headers, and top talkers.
- **Caps** — captured handshakes and PMKIDs from this session, plus a **Saved PCAPs** table read from the SD card (survives reboots), with PCAP download.
- **Attack** — authorization state, deauthentication, capture hunt, BLE HID keyboard payloads, auto-deauth, pause/hop controls.
- **Set** — Wi-Fi connection, display brightness, maintenance, system information.

### API

All responses are JSON unless noted. `POST` bodies use `Content-Type: application/json`.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/status` | Firmware, uptime, heap, pet, radio, SD, network, and build info |
| GET | `/api/aps` | Access-point table |
| GET | `/api/clients` | Observed client table with vendor, randomized flag, probes, first/last seen |
| GET | `/api/ble` | Passive BLE state and recent advertisers |
| POST | `/api/ble` | Enable/disable passive BLE scanning (`{"enabled":true}`) |
| GET | `/api/hid` | BLE HID state and `/sdcard/payloads` list |
| POST | `/api/hid` | Start HID mode, run a payload, or stop (`action`: `start`, `run`, `stop`) |
| POST | `/api/hid_payload?name=<file>` | Upload a raw text payload (1–16 KiB, `.txt`) |
| GET | `/api/dns` | Recent DNS question names with counts and timestamps |
| GET | `/api/sni` | Recent TLS ClientHello SNI hosts with counts and timestamps |
| GET | `/api/network` | Combined DNS/SNI/HTTP metadata plus top talkers |
| GET | `/api/watch` | Persistent watchlist, hit count, and last alert |
| POST | `/api/watch` | Add/remove watched values (`action`, `type`, `value`) or `{"clear":true}` |
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

BLE HID is a separate, explicitly authorized mode. `POST /api/hid {"action":"start","payload":"hello.txt"}` starts advertising but does **not** type anything; `{"action":"run","payload":"hello.txt"}` types a payload only after a host is connected and subscribed. `{"action":"stop"}` releases keys, disconnects, and restores the observer. `/api/status` exposes `hid_supported`, `hid_active`, `hid_connected`, `hid_encrypted`, `hid_subscribed`, `hid_executing`, `hid_state`, `hid_payload`, `hid_line`, `hid_lines`, and `hid_chars`. HID mode pauses the passive BLE scanner (Wi-Fi and BLE share the radio) and stops on lock, BLE reset, or after 5 minutes with no host. It is off after every boot and never runs a payload automatically. See [docs/HID.md](docs/HID.md).

Passive recon is always receive-only. `/api/ble` reports `supported`, `enabled`, `scanning`, `gated`, and a bounded `devices` table; scanning is off after boot until explicitly enabled, and pauses when `ap_active`/`setup_mode` or a deauth burst is using the radio. `/api/dns`, `/api/sni`, and `/api/network` contain names, counts, and uptime-based `first_seen_ms`/`last_seen_ms` only; they cannot see WPA/WPA2/WPA3-encrypted payloads. `/api/watch` accepts `type` values `ssid`, `mac`, and `ble` (BLE address or advertised name). Matches are stored in NVS and reported through `/api/status` as `watch_count`, `watch_hits`, `watch_last`, and `watch_age_ms`; a recent match also replaces `last_event` for 60 seconds so it is visible to simple pollers.

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
- Passive recon tables are fixed at compile time: `PWN_DNS_MAX`, `PWN_HOST_MAX`, `PWN_TALKER_MAX` in `main/pwn_netmeta.h`, `PWN_BLE_MAX` in `main/pwn_ble.h`, and `PWN_WATCH_MAX` in `main/pwn_watch.h`. The AP/client/BLE tables and large web snapshots live in PSRAM.
- BLE HID limits and paths live in `main/pwn_hid.h`: `/sdcard/payloads`, 24 listed payloads, 64-character names, and a 16 KiB payload cap. HID mode always requires the runtime authorization phrase. There is no separate compile-time HID switch; remove the `pwn_hid.c` source and HID GATT calls if you need a build with no HID code.

Build defaults include the NimBLE observer role only (`CONFIG_BT_NIMBLE_ENABLED=y`, observer on, central/peripheral/broadcaster/security/GATT off). BLE scanning itself remains a runtime opt-in and starts **off** after every boot; `/api/ble` or the web **BLE** tab enables it for the current session. If you need a smaller image with no Bluetooth at all, remove the `bt`/`esp_coex` requirements and the BLE source from `main/CMakeLists.txt` and the `CONFIG_BT_*` block from `sdkconfig.defaults`; the web API then reports `ble_supported: false`.

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
├── pwn_watch.*         # Persistent SSID/MAC/BLE watchlist and alert cooldown
├── pwn_netmeta.*       # Passive DNS/SNI/HTTP metadata and top-talker counters
├── pwn_ble.*           # Opt-in passive NimBLE observer
├── pwn_hid.*           # Opt-in BLE HID keyboard + payload parser
├── pwn_oui.*           # Small built-in OUI vendor table / randomized-MAC bit
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
- **BLE tab stays empty** — BLE scanning is opt-in and off after every boot. Enable it in the **BLE** tab or with `POST /api/ble {"enabled":true}`. If `gated` is true, the setup AP or an active deauth burst owns the radio; wait for it to finish. `supported: false` means the firmware was built without NimBLE.
- **BLE scanning pauses or feels slow** — Wi-Fi and BLE share the 2.4 GHz radio. The firmware sets Wi-Fi coexistence priority and uses a low-duty passive scan; expect fewer advertisers than a dedicated BLE scanner. If you see Wi-Fi drops while BLE is on, leave BLE off; it is not required for any other feature.
- **HID mode will not start** — unlock active features first (`ADMIN` in **Attacks** or `POST /api/auth`). HID also needs the SD card mounted for payloads and cannot advertise while the setup AP or a deauth burst owns the radio. Starting HID always pauses the BLE scanner; the dashboard shows `HID: advertising` in `last_event`.
- **Host sees `PWNI-KBD` but never receives keystrokes** — the payload only runs after the host subscribes to the keyboard input report. Pair/connect from the host, wait for `hid_subscribed: true` (or the dashboard's "keyboard reports subscribed"), then press **Type payload**. Some Linux/BlueZ setups expose the GATT service without binding the HID input driver until the host pairs explicitly. HID mode is experimental; use a host that supports BLE HID keyboards.
- **HID stopped by itself** — the firmware stops HID when the authorization is revoked, when NimBLE resets, or after 5 minutes with no host. It also aborts typing if the host disconnects. Nothing is auto-restarted after a reboot.
- **DNS/SNI/HTTP tables stay empty on a WPA2/WPA3 network** — expected. Those payloads are encrypted; the parser only sees unprotected frames (open networks or unencrypted management/data). It stores names and counters only, never payloads or credentials.
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
- Update a reachable device manually from **Settings → Maintenance → Update from GitHub**. The device fetches the tag-pinned `dist/ota.json`, downloads the image to SD, verifies its SHA-256, and only then writes the inactive OTA slot and reboots. A missing SD card, bad manifest, or hash mismatch aborts without touching the running firmware. Nothing is automatic.
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
