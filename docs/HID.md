# BLE HID keyboard (experimental)

PWNI can advertise as a Bluetooth Low Energy HID-over-GATT keyboard and type a
DuckyScript-style text payload from the microSD card. This is the firmware's
"BadUSB-style" feature. It is **opt-in**, **runtime-authorized**, and **never
starts automatically**. HID mode is off after every boot and stops as soon as
the authorization is revoked.

> [!WARNING]
> Use HID payloads only on machines you own or have explicit written permission
> to test. HID mode types into whichever host connects and has focus. The
> authorization phrase is a speed bump, not a security boundary. The device does
> not store host addresses, target data, or payload output.

## Requirements

- firmware 0.3.5 or newer with NimBLE peripheral/GATT support
- a FAT32 microSD card mounted at `/sdcard`
- the runtime authorization phrase (`ADMIN` by default)
- a host that supports BLE HID keyboards (Windows 10/11, macOS, Linux, iOS,
  Android). Some hosts require the device to be paired/bonded before they
  subscribe to reports.

## Payloads

Put UTF-8/ASCII `.txt` files in `/sdcard/payloads/`. You can also upload one
from **Attacks → BLE HID keyboard → Upload .txt** in the dashboard. The
directory is created automatically when the SD card is available. Filenames
are limited to letters, digits, `.`, `_`, and `-` and must end in `.txt`.

Sample benign payloads live in [`dist/payloads`](../dist/payloads):

- `hello.txt` — types a test string into the focused window
- `notepad-windows.txt` — opens Notepad and types a test string
- `textedit-macos.txt` — opens TextEdit and types a test string

No malicious payloads are bundled.

### Supported syntax

| Line | Meaning |
|---|---|
| `REM comment` | Ignored |
| `DELAY 500` | Wait 500 ms (maximum 600000) |
| `DEFAULTDELAY 20` | Delay after every key; `DEFAULT_DELAY` also works |
| `STRING text` | Type `text` in the US keyboard layout |
| `STRINGLN text` | Type `text`, then press Enter |
| Plain line | Line that is not a command is typed as text |
| `ENTER`, `TAB`, `ESC`, `SPACE`, `BACKSPACE`, `DELETE`, `INSERT` | Press one key |
| `UP`, `DOWN`, `LEFT`, `RIGHT`, `HOME`, `END`, `PAGEUP`, `PAGEDOWN` | Navigation |
| `F1`–`F12`, `CAPSLOCK`, `PRINTSCREEN`, `SCROLLLOCK`, `PAUSE`, `NUMLOCK` | Function keys |
| `MENU` / `APP` | Context-menu key |
| `GUI r`, `CTRL ALT t`, `CTRL SHIFT ESC`, `ALT F4` | Modifier + key |
| `CTRL+ALT+DELETE` | `+` is treated like a space |
| `GUI`, `CTRL`, `ALT`, `SHIFT` | Press and release the modifier alone |

Modifier names: `CTRL`/`CONTROL`, `SHIFT`, `ALT`, `GUI`/`WIN`/`WINDOWS`/`CMD`,
and the right-hand variants `RCTRL`, `RSHIFT`, `RALT`, `RGUI`.

Text is typed with a US QWERTY mapping, including shifted symbols. Bytes above
0x7F and unsupported control characters are skipped rather than sent as
undefined keys. Payloads are capped at 16 KiB.

## Using the feature

1. Unlock active features with the authorization phrase in **Attacks** (or
   `POST /api/auth`).
2. Open **Attacks → BLE HID keyboard**.
3. Select a payload (or upload one), then press **Start HID mode**.
4. Pair with **PWNI-KBD** on the host if it asks. SMP is enabled with Just
   Works pairing, bonding, and LE Secure Connections. If the host offers a PIN,
   dismiss it and use Just Works; there is no display or keypad. Some hosts
   (including generic BlueZ GATT clients) subscribe without pairing because the
   report attributes are intentionally unencrypted; others insist on an
   encrypted link and will start pairing themselves.
5. Wait for the dashboard to show that keyboard reports are subscribed.
6. Press **Type payload** and confirm. The dashboard shows line/character
   progress.
7. Press **Stop & disconnect** when done. This releases keys, disconnects the
   host, and resumes the passive BLE scanner if it was enabled.

The device also stops HID mode when the authorization is revoked, when the BLE
stack resets, or after 5 minutes with no host connected. A disconnect during
typing aborts the run and releases the current key.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/hid` | State, payload list, warnings |
| POST | `/api/hid` | `{"action":"start","payload":"hello.txt"}`, `{"action":"run","payload":"hello.txt"}`, or `{"action":"stop"}` |
| POST | `/api/hid_payload?name=hello.txt` | Upload a raw text payload body (1–16 KiB) |

All HID endpoints require the dashboard's Basic auth. Start/run/upload also
require the runtime authorization phrase and return `403` while locked. Start
only advertises; it never runs a payload. Run returns `409` if there is no
connection, no keyboard subscription, or a payload is already running.

Relevant `/api/status` fields:

- `hid_supported`, `hid_authorized`, `hid_active`
- `hid_connected`, `hid_encrypted`, `hid_subscribed`, `hid_boot_mode`
- `hid_executing`, `hid_state`, `hid_payload`, `hid_error`
- `hid_line`, `hid_lines`, `hid_chars`, `hid_age_ms`

`last_event` records HID start, stop, connection, subscription, execution, and
failure messages. No target address or typed content is logged.

## Radio coexistence and limitations

- The ESP32-C5 has one 2.4 GHz radio shared by Wi-Fi and BLE. HID mode pauses
  the passive BLE observer for the entire session; the observer restarts after
  HID stops if the user had enabled it. Wi-Fi keeps coexistence priority.
- LVGL rendering is paused for the duration of a payload (the dashboard keeps
  updating over HTTP). The LCD and SD share one SPI bus and the LCD flush uses
  an internal DMA bounce buffer; BLE notification traffic can otherwise
  fragment that heap enough for the flush to fail. The screen resumes when the
  payload finishes or is stopped.
- HID mode is not available while the setup SoftAP or a deauth burst owns the
  radio. Starting it still stops the BLE observer; if advertising fails, the
  dashboard reports the error and turns HID mode off.
- Host behaviour varies. Some operating systems pair and subscribe
  automatically; others need to be told to connect to the new keyboard. BlueZ
  (Linux) may expose the GATT service without auto-binding the HID input
  driver unless the host pairs explicitly. The firmware advertises the HID
  service (`0x1812`), keyboard appearance (`0x03C1`), report protocol (Report
  ID 2), and the boot keyboard input/output characteristics.
- Only keyboard reports are implemented. There is no mouse, consumer-control,
  media-key, or vendor report.
- The feature is not a substitute for a hardware USB HID device: BLE pairing,
  OS HID policy, and the shared radio can all prevent typing on a given host.
- No persistence: payloads persist on SD, but HID mode and the selected payload
  do not survive a reboot.

## Design notes

The HID GATT service is registered once during BLE bring-up. Advertising starts
only after an authorized `start` request. On connect the firmware initiates
Just Works security and waits for the host to subscribe to either the Report
characteristic (`0x2A4D`, Report ID 2) or the Boot Keyboard Input
characteristic (`0x2A22`). Reports are 8 bytes: modifier mask, reserved byte,
and up to six key codes. The output report (`0x2A4D` / `0x2A32`) accepts LED
state and is otherwise ignored.

The typing task copies the payload into PSRAM under the shared SD/display bus
lock, then releases the lock before sending reports. This keeps a long payload
from stalling LVGL or the PCAP writer.
