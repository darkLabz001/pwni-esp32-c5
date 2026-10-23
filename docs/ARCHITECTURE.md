# Architecture

## Overview

`pwni` is a task-based ESP-IDF firmware. The main task owns the pet/epoch loop and bring-up; a dedicated recon task drains the sniffer ring buffer; LVGL renders the UI; the HTTP server serves the dashboard; and the USB-Serial/JTAG CLI task handles console commands.

```text
Wi-Fi promiscuous callback
        │  copy frame into ring buffer (no parsing in the callback)
        ▼
   recon_task ──► 802.11 parser ──► AP/client tables
        │                 │
        │                 └──────► pwn_capture (EAPOL/PMKID, slots, PCAP)
        │
        └──► hop policy / scan / channel lock

app_main ──► pet_tick() every 100 ms ──► pwn_pet (moods, reward, brain)
   │
   ├──► pwn_ui timer (200 ms) ──► LVGL snapshots of pet/wifi state
   ├──► pwn_net (STA manager) ──► locks sniffer channel while associated
   └──► pwn_web (HTTP server) ──► JSON snapshots + control APIs
```

## Tasks

| Task | Where | Role |
|---|---|---|
| `app_main` | `main/app_main.c` | Bring-up, then `pet_tick()` every 100 ms |
| `recon` | `main/pwn_wifi.c` | Ring-buffer receive, 802.11 parsing, table updates, EAPOL/PMKID handoff, hopping, scan |
| LVGL task | `esp_lvgl_adapter` | Rendering; the UI timer runs inside the LVGL context |
| HTTP server | `main/pwn_web.c` | `esp_http_server` on port 80, 8 KiB stack, 4 open sockets |
| CLI | `main/pwn_cli.c` | USB-Serial/JTAG line input, 16 KiB stack (large enough to snapshot UI state) |

The CLI stack was raised from 5 KiB to **16 KiB** because snapshotting the settings screen while LVGL drew a scrollbar overflowed the smaller stack.

## Modules

### `pwn_brain` — REINFORCE policy

- Network: 8 inputs → 16 hidden (ReLU) → 6 outputs (softmax).
- Policy-gradient update with a value baseline; features are normalized counts of handshakes, APs, clients, deauths seen, blind/inactive/active epochs, and epoch index.
- Six actions map to channel plans and dwell times: `linger-2g`, `hop-2g`, `scan-5g-low`, `scan-5g-high`, `hunt`, `rest`.
- Weights are saved to NVS every 10 epochs and loaded at boot. `reset-brain` wipes the learned policy.

### `pwn_wifi` — sniffer, tables, scan, hopping

- `esp_wifi` runs in STA mode. The promiscuous RX callback copies frames into a 48 KiB ring buffer; the recon task does the parsing.
- Parses beacons/probe requests/probe responses, deauth/disassoc, QoS/data headers, LLC/SNAP, and EAPOL-Key.
- Maintains fixed AP and client tables. Client insertion ignores group/multicast MAC addresses, so broadcast/multicast destinations do not appear as stations.
- Channel hopping follows the active policy. `esp_wifi_set_channel()` is used with a band-switch fallback for 5 GHz.
- While associated, the station owns the radio. `pwn_wifi_set_locked(true, channel)` records the AP channel in the stats and stops hopping; a failed `set_channel()` is expected in that state and does not invalidate the lock.
- `pwn_wifi_force_channel()` is used for manual parking and deauth targeting. It is rejected while associated (single radio).
- `pwn_wifi_deauth()` checks the runtime authorization gate before transmitting. Auto-deauth is off by default. A single frame is usually not enough because clients reassociate quickly, so the UI and `/api/deauth` start an 8-second burst through `pwn_wifi_deauth_start()` (worker task, one round every 50 ms); the web supports 5/8/15/30 s, both web and device expose **Stop**, and `deauth_active` reports the state. The device's own STA is skipped, and broadcast fallback is skipped when targeting the current AP. APs are tagged with a PMF flag parsed from the RSN capabilities; the API/web warn when deauth may be ignored. The local ESP-IDF installation has the one-instruction C5 deauth patch applied (`tools/patch_c5_deauth.py`, [C5_DEAUTH.md](C5_DEAUTH.md)); with stock ESP-IDF, `esp_wifi_80211_tx()` returns `ESP_ERR_INVALID_ARG`.
- `pwn_wifi_scan_now()` performs a synchronous scan in a background task, so the LVGL UI does not freeze.
- `selftest` injects a synthetic beacon, PMKID M1, and M2 through the real parser and verifies the PCAP written to SD.

### `pwn_capture` — handshakes and PCAP

- Slot table keyed by `(BSSID, STA)`, up to `PWN_HS_FRAMES` frames per slot. Slots live in PSRAM so internal RAM stays available for task stacks.
- A handshake is counted when a PMKID is present, M1+M2 are seen, or all four messages are seen. The SD write happens only for a PMKID or a complete handshake; partial M1+M2 stays in RAM until a complete handshake or eviction.
- Each slot carries a beacon/probe-response context frame plus channel/RSSI. PCAP format: little-endian global header, microsecond timestamps, link type 127, a 24-byte radiotap header with channel/frequency/dBm, then the context and 802.11 frames.
- Files are written atomically to `/sdcard/handshakes/` (temp file + rename), with a free-space guard. `capture_sd_info()` reports total/free; `capture_sd_remount()` re-mounts after a card/write failure; `capture_sd_prune()` enforces a file-count limit.
- The live slot table is RAM-only and resets on reboot. `capture_list_files()` scans the directory for the web **Caps → Saved PCAPs** table, so files on the card remain visible and downloadable across reboots.
- The SD card is mounted at 10 MHz on SPI2. `capture_bus_lock()` / `capture_bus_unlock()` serialize SD I/O with LVGL panel flushes. Large snapshot arrays use PSRAM to keep internal RAM for the CLI/HTTP/LVGL tasks.

### `pwn_net` — station manager

- NVS namespace `pwnnet` stores SSID/password and the autoconnect flag.
- `net_connect(ssid, pass, save)` configures the STA, connects, and optionally persists credentials.
- `net_disconnect(forget)` leaves the AP and optionally erases credentials.
- On `WIFI_EVENT_STA_CONNECTED`, the manager calls `pwn_wifi_set_locked(true, ev->channel)` so the sniffer reports and uses the AP channel. On disconnect it unlocks hopping.
- The web UI and the on-device `SET` screen both use this API.
- The station connection state is exposed through `pwn_net_status_t` (connected, IP, netmask, gateway, RSSI, channel, BSSID, reason).

### `pwn_web` — dashboard and JSON API

- `esp_http_server` on port 80; 21 registered handlers; 4 open sockets; LRU purge enabled.
- The root page is embedded from `pwn_web_page.h` (about 23 KB) and uses a dark dashboard with tabs: Dash, Nets, Clients, Caps, Attack, Set.
- Read APIs snapshot the pet/wifi/capture tables into `cJSON` documents. `/api/hs` also scans `/sdcard/handshakes` for saved PCAPs, so the dashboard's archive survives reboots.
- Control APIs call `pwn_net`, `pwn_wifi`, `pwn_pet`, and `bsp_display_brightness_set`.
- PCAP download validates the requested basename with `safe_name()`, opens the file under the SD bus lock, and streams it with `Content-Disposition: attachment`.
- Active-attack endpoints check `pwn_wifi_authorized()` and return `403` while locked. Channel-changing endpoints return `409 Conflict` while associated.
- Authorization is case-insensitive: `/api/auth` with `{"phrase":"ADMIN"}` (or any case variant) unlocks; `{"off":true}` locks.

### `pwn_pet` — behavior

- 20-second epochs: computes deltas from Wi-Fi/capture stats, builds a Pwnagotchi-style reward, calls the brain, saves periodically, updates XP/level/bond, selects a mood, and picks the next action.
- Moods: `sleeping`, `observing`, `happy`, `excited`, `bored`, `sad`, `motivated`, `demotivated`.
- `pet_touch()` (tap the face) updates bond and the status line.
- Strategy overrides from the UI/web are stored as an action index; `-1` restores automatic selection.

### `pwn_ui` — LVGL interface

- 320×480 portrait, dark theme, green accent, Montserrat for body text and UNSCII for the pixel-font stats/face-adjacent details.
- Four screens: FACE, SCAN, LOOT, SET, with a persistent bottom navigation. `ui_show_tab()` switches screens.
- FACE: large animated eyes with pupils, a mouth arc, blink, idle eye darts, mood, status, `CH/AP/HS` and `PWN/PMK/CLI` stats, bond/level/XP, last event. Tapping the face calls `pet_touch()`.
- SCAN: AP rows built from a snapshot; RSSI bars; tap opens a modal with BSSID/channel/security/RSSI/WPS and CONNECT / DEAUTH / CLOSE actions. Secured connections open the password keyboard.
- LOOT: capture rows with `PMKID` / `4WAY` / `SAVED` tags; tapping shows the PCAP file name.
- SET: scrollable panels for WIFI CONNECTION, WEB DASHBOARD, ACTIVE ATTACKS, DISPLAY, and SYSTEM. The WiFi panel opens the SCAN tab; the active-attacks panel exposes UNLOCK/LOCK, auto-deauth, and the strategy dropdown; DISPLAY drives the backlight slider; SYSTEM shows firmware/heap/SD/network info plus RESET BRAIN and REBOOT.
- Keyboard modals use the LVGL keyboard. Password entry is masked; the authorization phrase is visible and starts in uppercase mode. Phrase matching is case-insensitive.
- A single `lv_timer` (200 ms) reads `pet_snapshot()` and `pwn_wifi_stats()` and updates labels, face geometry, and the scan/loot lists. Labels that must stay on one line get an explicit line-height; intentional multi-line labels use `label_lines()`.
- Touch is polled through the BSP input device. The FT6336 gesture mode is disabled; the panel uses raw 320×480 coordinates with no swap/mirror.

### `pwn_cli` — console

- USB-Serial/JTAG line input with a `pwni>` prompt.
- Commands cover status/list/scan/plan/hop, capture/selftest/save, pause/resume, auth, reset-brain/reboot, WiFi connect, and the UI diagnostics (`shot`, `tab`, `touchtest`).
- `shot` emits a 160×240 24-bit BMP as base64 between `SHOT-BEGIN 160 240` and `SHOT-END`; this is used for headless layout inspection.
- `touchtest` temporarily disables the LVGL input device, prints transformed coordinates for 10 seconds, and re-enables it.

## Concurrency and locking

- **Sniffer ring buffer**: single producer (Wi-Fi callback) / single consumer (recon task).
- **AP/client tables**: protected by `s_tab_lock`; snapshots copy under the lock.
- **Capture slots**: protected by a capture-specific lock; the web/UI only read snapshots.
- **SD vs LCD**: both on SPI2. `capture_bus_lock()` / `capture_bus_unlock()` serialize every SD access against panel flushes.
- **LVGL**: only the LVGL task / UI timer touches LVGL objects. The CLI's `shot` and `tab` helpers are diagnostic and run at the user's request.
- **Channel ownership**: while the STA is associated, the Wi-Fi driver owns the channel. The sniffer lock follows the AP channel; manual hop/deauth requests that need an exclusive channel are refused with `409`.

## Memory

- Sniffer ring buffer: `PWN_RB_BYTES` = 48 KiB.
- Handshake slots: heap-allocated, up to roughly 75 KiB with `PWN_FRAME_MAX=512`; intended for PSRAM.
- AP table: `PWN_MAX_APS` (96) entries; client table: `PWN_MAX_CLIENTS` (128) entries; handshake table: `PWN_MAX_HS` (24).
- LVGL draw buffers and UI snapshot buffers live in PSRAM.
- Task stacks: CLI 16 KiB, HTTP server 8 KiB, LVGL draw thread 8 KiB, main task 8 KiB.

## Build configuration

- ESP-IDF v5.5.x, target `esp32c5`.
- Flash: 32 MB, QIO 80 MHz. PSRAM: 8 MB quad, 80 MHz. CPU: 240 MHz.
- LVGL 9, RGB565, Montserrat 12/14/16/20/24/28 and UNSCII 8/16 fonts.
- USB-Serial/JTAG console (`CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y`, UART console off).
- FATFS long filenames, Wi-Fi RX/TX buffer tuning, HTTP server limits (`CONFIG_LWIP_MAX_SOCKETS=10`, 1024-byte request headers, 512-byte URI).
- `PWN_ENABLE_DEAUTH` defaults to `1`, but active transmissions require the runtime phrase; `PWN_AUTH_PHRASE` is `ADMIN` and matching is case-insensitive. Auto-deauth defaults to off. Setting `PWN_ENABLE_DEAUTH` to `0` removes the active path entirely. Active deauth on the C5 also needs the local `libnet80211.a` patch; see [C5_DEAUTH.md](C5_DEAUTH.md). Stock IDF returns `ESP_ERR_INVALID_ARG`.
