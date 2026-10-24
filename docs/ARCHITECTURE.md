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
| `recon` | `main/pwn_wifi.c` | Ring-buffer receive, 802.11 parsing, table updates, passive DNS/SNI/HTTP parsing, watchlist rescan, EAPOL/PMKID handoff, hopping, scan |
| `pwn_ble` | `main/pwn_ble.c` | NimBLE host task + supervisor; passive advertisements, watch matches, HID radio gate |
| `pwn_hid` | `main/pwn_hid.c` | Authorized BLE HID keyboard GATT service, payload parser, typing task |
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
- Maintains fixed AP and client tables in PSRAM. Client insertion ignores group/multicast MAC addresses, so broadcast/multicast destinations do not appear as stations. Clients keep `first_seen_ms`, `last_seen_ms`, a locally-administered/randomized flag, and the last four unique probe-request SSIDs.
- Passive metadata parser (`pwn_netmeta`) receives unprotected data frame bodies from the same recon task: DNS questions (UDP/53), TLS ClientHello SNI (TCP/443, 8443, 993, 995, 465), HTTP `Host` headers (TCP/80, 8000, 8080, 8888), and per-source-MAC talker counters. Protected frames still contribute talker header metadata but no payload parsing. Names/counters are bounded; payloads are discarded immediately.
- The watchlist is re-evaluated against the live AP/client tables every 2 s, so an entry added after a device was first seen still alerts.
- Channel hopping follows the active policy. `esp_wifi_set_channel()` is used with a band-switch fallback for 5 GHz.
- While associated, the station owns the radio. `pwn_wifi_set_locked(true, channel)` records the AP channel in the stats and stops hopping; a failed `set_channel()` is expected in that state and does not invalidate the lock.
- `pwn_wifi_force_channel()` is used for manual parking and deauth targeting. It is rejected while associated (single radio).
- `pwn_wifi_deauth()` checks the runtime authorization gate before transmitting. Auto-deauth is off by default. A single frame is usually not enough because clients reassociate quickly, so the UI and `/api/deauth` start an 8-second burst through `pwn_wifi_deauth_start()` (worker task, one round every 50 ms); the web supports 5/8/15/30 s, both web and device expose **Stop**, and `deauth_active` reports the state. The device's own STA is skipped, and broadcast fallback is skipped when targeting the current AP. APs are tagged with a PMF flag parsed from the RSN capabilities; the API/web warn when deauth may be ignored. The local ESP-IDF installation has the one-instruction C5 deauth patch applied (`tools/patch_c5_deauth.py`, [C5_DEAUTH.md](C5_DEAUTH.md)); with stock ESP-IDF, `esp_wifi_80211_tx()` returns `ESP_ERR_INVALID_ARG`.
- `pwn_wifi_scan_now()` performs a synchronous scan in a background task, so the LVGL UI does not freeze.
- `selftest` injects a synthetic beacon, PMKID M1, and M2 through the real parser and verifies the PCAP written to SD.

### `pwn_capture` — handshakes and PCAP

- Slot table keyed by `(BSSID, STA)`, up to `PWN_HS_FRAMES` frames per slot. Slots live in PSRAM so internal RAM stays available for task stacks.
- A handshake is counted when a PMKID is present, M1+M2 are seen, or all four messages are seen. PMKID/complete slots are queued immediately; partial M1+M2 stays in RAM until a complete handshake, eviction, or an explicit flush.
- `capture_add_eapol()` never touches the SD card. It copies the slot into PSRAM and posts it to a queue drained by the `pwn_sd` writer task, which takes `capture_bus_lock()` and freezes the snapshot while it writes.
- Each slot carries a beacon/probe-response context frame plus channel/RSSI. PCAP format: little-endian global header, microsecond timestamps, link type 127, a 24-byte radiotap header with channel/frequency/dBm, then the context and 802.11 frames.
- Files are named `SSID_YYYYmmdd-HHMMSS_BSSID.pcap` (or `SSID_bootNNNNN_BSSID.pcap` before SNTP sync) and written atomically to `/sdcard/handshakes/` (temp file + rename), with a free-space guard. A `<pcap>.json` sidecar carries the SSID, BSSID, STA, channel, RSSI, frame count, completion/PMKID flags and save time. `capture_sd_info()` reports total/free; `capture_sd_remount()` re-mounts after a card/write failure; `capture_sd_prune()` enforces a file-count limit and removes sidecars with their PCAP.
- The live slot table is RAM-only and resets on reboot. `capture_list_files()` scans the directory for the web **Caps → Saved PCAPs** table, so files on the card remain visible and downloadable across reboots.
- The SD card is mounted at 10 MHz on SPI2. `capture_bus_lock()` / `capture_bus_unlock()` serialize SD I/O with LVGL panel flushes. Large snapshot arrays use PSRAM to keep internal RAM for the CLI/HTTP/LVGL tasks.

### `pwn_hunt` — deauth-assisted capture

- A background `pwn_hunt` task owns one hunt at a time. `pwn_hunt_start()` validates the target, requires runtime authorization, rejects the device's own MAC, requires the AP to be in the scan table, and parks the radio on the target channel when the STA is disconnected.
- The task starts through the existing `pwn_wifi_deauth_start()` worker with a 400 ms round interval and a duration equal to the hunt timeout (default 20 s, max 60 s). If a usable capture already exists it exits before transmitting anything.
- Every 200 ms it calls `capture_find_usable()` (a lock-protected scan of the handshake slots, preferring SD-saved matches). It stops the deauth as soon as a complete 4-way handshake or PMKID is saved, or when the duration expires. A capture that is present but unsaved is accepted after a short grace period when no SD card is mounted.
- The self-AP guard is reused: for the AP the STA is associated with, a station-specific hunt is allowed but an AP-wide hunt targets observed clients only and never falls back to broadcast. PMF targets are allowed with a warning.
- Status (`hunt_active`, `hunt_result`, target, elapsed, file) is exposed through `/api/status`; `/api/hunt` starts or stops a hunt.

### `pwn_net` — station manager

- NVS namespace `pwnnet` stores SSID/password and the autoconnect flag.
- `net_connect(ssid, pass, save)` configures the STA, connects, and optionally persists credentials.
- `net_disconnect(forget)` leaves the AP and optionally erases credentials.
- On `WIFI_EVENT_STA_CONNECTED`, the manager calls `pwn_wifi_set_locked(true, ev->channel)` so the sniffer reports and uses the AP channel. On disconnect it unlocks hopping.
- The web UI and the on-device `SET` screen both use this API.
- The station connection state is exposed through `pwn_net_status_t` (connected, IP, netmask, gateway, RSSI, channel, BSSID, reason).

### `pwn_watch` — persistent watchlist

- NVS namespace `pwnwatch`, one blob key `items`, up to `PWN_WATCH_MAX` (24) records. Types: `ssid`, `mac`, `ble` (BLE address or advertised name).
- Matching is passive and bounded. A per-entry 60 s cooldown prevents a beaconing AP or chatty BLE device from flooding the event log.
- A match increments `watch_hits`, stores `watch_last`, and calls the shared `pwn_wifi_event()` so `/api/status`'s `last_event` reflects it for 60 s. The web header badge and optional toast read the same counters.

### `pwn_netmeta` — DNS/SNI/HTTP metadata

- Fixed tables: `PWN_DNS_MAX`, `PWN_HOST_MAX` (separate SNI/HTTP tables), and `PWN_TALKER_MAX`. Each entry stores a name/host or MAC/IP plus counts and uptime timestamps. LRU replacement keeps memory bounded.
- DNS: parses only the question section, handles compression pointers defensively, and ignores responses. SNI: bounds-checked TLS record/handshake/extension walk. HTTP: request methods only, extracts `Host`, strips a non-IPv6 port. No query answers, URLs, cookies, or bodies are retained.
- IPv4 only; WPA/WPA2/WPA3 data frames are encrypted and therefore not visible. The parser is bounds-checked and is validated with synthetic DNS/SNI/HTTP frames that exercise name compression, SNI extension walking, Host parsing, and talker accounting.

### `pwn_ble` — passive NimBLE observer and HID radio gate

- Built with the NimBLE observer + peripheral/broadcaster/GATT-server roles and SMP. `nimble_port_freertos_init()` owns the host task; a 1 s supervisor starts/stops scanning. The observer never connects, pairs, writes, or sends scan requests.
- Scan parameters are passive with a low duty cycle (100 ms interval / 40 ms window) and duplicate filtering off for fresh RSSI. `esp_coex_preference_set(ESP_COEX_PREFER_WIFI)` keeps Wi-Fi first on the shared 2.4 GHz radio.
- Runtime opt-in, off after every boot. Scanning is gated off while the setup AP is active, a deauth burst is in flight, or BLE HID mode is active. `ble_hid_set_active(true)` cancels discovery synchronously before HID starts advertising; clearing it lets the supervisor restart the scan if the user had enabled it.
- Parses address/address type, name, RSSI, 16/32/128-bit service UUIDs, and common beacon formats (iBeacon, Eddystone, AltBeacon, Exposure Notification, Fast Pair, URI). The device table lives in PSRAM and is LRU-bounded.

### `pwn_hid` — authorized BLE HID keyboard

- Registers a keyboard-only HID-over-GATT service during BLE bring-up: HID Information, Report Map, Control Point, Protocol Mode, Report (Report ID 2, input and LED output), and Boot Keyboard input/output. Appearance is `0x03C1`; the advertising name is `PWNI-KBD`.
- Off after every boot. `hid_start()` requires `pwn_wifi_authorized()` and only enables connectable advertising; it never executes a payload. `hid_run()` additionally requires a connected host with a subscription to the Report or Boot Keyboard Input characteristic.
- SMP is enabled for Just Works pairing with bonding and LE Secure Connections; bonds use the NimBLE store and Wi-Fi credentials remain in their own NVS entries. The firmware deliberately does **not** send an early Security Request on connect: BlueZ rejects that before service discovery and the CCCD write can hang. A host that requires encryption initiates pairing itself. Report characteristics are readable without encryption so generic GATT clients can subscribe and receive reports; if the host pairs, `hid_encrypted` becomes true.
- The payload parser supports `REM`, `DELAY`, `DEFAULTDELAY`, `STRING`/`STRINGLN`, plain text, navigation/function keys, US-layout shifted symbols, and modifier combinations. Runs are line-by-line with a 16 KiB file cap.
- The typing task copies the SD file into PSRAM under `capture_bus_lock()` and releases the shared SD/display bus before sending reports. Reports are 8 bytes (modifiers, reserved, six keys); a key press is always followed by a release, including on abort.
- LVGL is paused with `esp_lv_adapter_pause()` for the duration of a payload and resumed when it ends. The LCD's SPI flush falls back to an internal DMA bounce buffer because the draw buffers are in PSRAM; BLE notification traffic can fragment the internal heap enough that the bounce allocation fails and LVGL waits forever for a flush completion. The web UI still reports progress while rendering is paused. The BSP draw buffer is 20 lines (~12.8 KiB per transfer) for the same headroom reason.
- HID mode stops on authorization revocation, NimBLE reset, or 5 minutes without a host. Disconnect aborts the run. No target address, typed text, or payload output is stored; `last_event` carries only start/stop/connection/execution status.

### `pwn_web` — dashboard and JSON API

- `esp_http_server` on port 80; registered handlers cover status, recon, captures, controls, HID, and OTA; 4 open sockets; LRU purge enabled.
- The root page is embedded from `pwn_web_page.h` and uses a dark dashboard with tabs: Dash, Nets, Clients, BLE, Net intel, Caps, Attack, Set.
- Read APIs snapshot the pet/wifi/capture/BLE/netmeta tables into `cJSON` documents. `/api/hs` also scans `/sdcard/handshakes` for saved PCAPs, so the dashboard's archive survives reboots.
- Recon APIs: `/api/ble`, `/api/dns`, `/api/sni`, `/api/network`, and `/api/watch`. `/api/clients` adds `vendor`, `randomized`, `probes`, `first_seen_ms`, and `last_seen_ms`. `/api/status` adds passive counters, BLE state, HID state, internal-heap diagnostics, and watch fields.
- HID APIs: `GET /api/hid` lists state and `/sdcard/payloads`; `POST /api/hid` performs `start`/`run`/`stop`; `POST /api/hid_payload?name=` uploads a text payload atomically (1–16 KiB). Start/run/upload require the runtime unlock.
- Control APIs call `pwn_net`, `pwn_wifi`, `pwn_hunt`, `pwn_hid`, `pwn_pet`, and `bsp_display_brightness_set`.
- PCAP download validates the requested basename with `safe_name()`, opens the file under the SD bus lock, and streams it with `Content-Disposition: attachment`.
- Active-attack endpoints check `pwn_wifi_authorized()` and return `403` while locked. `/api/hunt` starts/stops the capture hunt and `/api/status` reports its state. Channel-changing endpoints return `409 Conflict` while associated.
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
- SCAN: AP rows built from a snapshot; RSSI bars; tap opens a modal with BSSID/channel/security/RSSI/WPS and CONNECT / DEAUTH / CLIENTS / HUNT / CLOSE actions. Secured connections open the password keyboard. HUNT starts a 20-second deauth-assisted capture for the selected AP.
- LOOT: capture rows with `PMKID` / `4WAY` / `SAVED` tags; tapping shows the PCAP file name.
- SET: scrollable panels for WIFI CONNECTION, WEB DASHBOARD, ACTIVE ATTACKS, DISPLAY, and SYSTEM. The WiFi panel opens the SCAN tab; the active-attacks panel exposes UNLOCK/LOCK, auto-deauth, the strategy dropdown, and the hunt state; DISPLAY drives the backlight slider; SYSTEM shows firmware/heap/SD/network info plus RESET BRAIN and REBOOT.
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
- AP table: `PWN_MAX_APS` (96) entries; client table: `PWN_MAX_CLIENTS` (128) entries; handshake table: `PWN_MAX_HS` (24). AP/client/BLE tables and large UI/web snapshots are allocated in PSRAM; this keeps enough internal SRAM for the NimBLE host/controller, Wi-Fi, TLS, HTTP, and task stacks. Measured idle internal-heap headroom with BLE available but not scanning is about 48–50 KiB, with a similar minimum.
- Passive recon tables: DNS 24 × 80 B, SNI/HTTP 24 × 80 B each, talkers 16 entries, BLE 48 devices, watchlist 24 entries. Bounds are compile-time constants.
- LVGL draw buffers and UI snapshot buffers live in PSRAM.
- Task stacks: CLI 16 KiB, HTTP server 8 KiB, LVGL draw thread 8 KiB, main task 8 KiB, NimBLE host 4 KiB, BLE supervisor 3 KiB, HID supervisor 3 KiB, HID typist 6 KiB (created only while a payload runs).

## Build configuration

- ESP-IDF v5.5.x, target `esp32c5`.
- Flash: 32 MB, QIO 80 MHz. PSRAM: 8 MB quad, 80 MHz. CPU: 240 MHz.
- LVGL 9, RGB565, Montserrat 12/14/16/20/24/28 and UNSCII 8/16 fonts.
- USB-Serial/JTAG console (`CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y`, UART console off).
- FATFS long filenames, Wi-Fi RX/TX buffer tuning, HTTP server limits (`CONFIG_LWIP_MAX_SOCKETS=10`, 1024-byte request headers, 512-byte URI).
- NimBLE observer + HID peripheral: Bluetooth enabled, NimBLE host, observer/peripheral/broadcaster roles, GATT server, SMP with Just Works bonding, internal memory allocation, no central role, no extended advertising. BLE scanning and HID mode are separate runtime opt-ins and both default off; HID additionally requires the authorization phrase and pauses the observer.
- `PWN_ENABLE_DEAUTH` defaults to `1`, but active transmissions require the runtime phrase; `PWN_AUTH_PHRASE` is `ADMIN` and matching is case-insensitive. Auto-deauth defaults to off. Setting `PWN_ENABLE_DEAUTH` to `0` removes the active path entirely. Active deauth on the C5 also needs the local `libnet80211.a` patch; see [C5_DEAUTH.md](C5_DEAUTH.md). Stock IDF returns `ESP_ERR_INVALID_ARG`.
