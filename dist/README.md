# PWNI release files

This directory mirrors the GitHub release so users can clone the repo and
flash without any server or host dependency.

- `flash.sh` — flash bootloader/table/app to an ESP32-C5
- `esp32touch.bin` — application image
- `bootloader.bin`, `partition-table.bin`, `ota_data_initial.bin`
- `pwni-tools.zip` — PCAP cracker, C5 deauth patch helper, and benign BLE
  HID payload examples
- `payloads/` — benign BLE HID example payloads (`*.txt`); copy them to
  `/sdcard/payloads/` on the device or upload from the dashboard

```sh
./flash.sh /dev/ttyACM0
```

Release page: <https://github.com/darkLabz001/pwni-esp32-c5/releases/latest>

The firmware includes no Wi-Fi credentials; credentials live in device NVS.
With no saved credentials (or after 30 s of failed station joins) it starts an
open `PWNI-Setup-XXXX` SoftAP at `http://192.168.4.1/` for dashboard-based
provisioning; the AP stops after the station gets an IP. Only use active
features on networks you own or are authorized to test.

Version 0.3.5 adds an experimental BLE HID keyboard (opt-in, runtime-authorized,
off after every boot). It advertises as `PWNI-KBD`, types selected
DuckyScript-style text payloads from `/sdcard/payloads/`, and pauses the passive
BLE scanner while active. HID mode is never auto-started and stores no target
data. Only use it on hosts you own or have written permission to test. See
[docs/HID.md](../docs/HID.md) and the bundled `payloads/` examples.

Version 0.3.4 added passive BLE scanning (opt-in, off by default), DNS/SNI/HTTP
Host visibility for unprotected frames, OUI/randomized-MAC client fingerprinting
with probe history, and a persistent watchlist. Those recon features remain
receive-only; they never connect, inject, or decrypt traffic.
