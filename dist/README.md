# PWNI release files

This directory mirrors the GitHub release so users can clone the repo and
flash without any server or host dependency.

- `flash.sh` — flash bootloader/table/app to an ESP32-C5
- `esp32touch.bin` — application image
- `bootloader.bin`, `partition-table.bin`, `ota_data_initial.bin`
- `pwni-tools.zip` — PCAP cracker and C5 deauth patch helper

```sh
./flash.sh /dev/ttyACM0
```

Release page: <https://github.com/darkLabz001/pwni-esp32-c5/releases/latest>

The firmware includes no Wi-Fi credentials; credentials live in device NVS.
With no saved credentials (or after 30 s of failed station joins) it starts an
open `PWNI-Setup-XXXX` SoftAP at `http://192.168.4.1/` for dashboard-based
provisioning; the AP stops after the station gets an IP. Only use active
features on networks you own or are authorized to test.
