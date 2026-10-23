# ESP32-C5 active deauthentication patch

The ESP32-C5 build needs a small patch to ESP-IDF's precompiled Wi-Fi library
before `esp_wifi_80211_tx()` will transmit deauthentication frames. This is a
property of Espressif's stock library, not of the authorization gate or the
application code.

## Status in this workspace

The patch is **applied** to the local ESP-IDF v5.5.4 installation and the
firmware was rebuilt and tested on the Waveshare ESP32-C5-Touch-LCD-3.5:

- unlock with `ADMIN` works,
- deauth now runs as an **8-second burst** (`/api/deauth` returns
  `started: true`, `targets`, `duration_ms`),
- a real associated client was disconnected during the burst (verified with
  `wpa_cli` events), and the device stayed online,
- the web **Stop** button and `{"stop":true}` stop the burst,
- the station stays connected and the web UI stays online unless you target
  the machine running the browser.

A single frame is not enough in practice: clients often reassociate in about a
second. The burst sends one round every 50 ms for 8 seconds, so the client
cannot immediately come back. When the burst ends, a client with autoconnect
may return; run it again or increase `duration_ms`.

The stock library is kept at:

```
$IDF_PATH/components/esp_wifi/lib/esp32c5/libnet80211.a.stock
```

## Why the patch is needed

Inside `ieee80211_output.o`, `ieee80211_raw_frame_sanity_check()` validates raw
frames before `esp_wifi_80211_tx()` queues them. Stock v5.5.4 accepts the action
frame type (`0xD0`) but rejects the deauthentication type (`0xC0`), returning
`ESP_ERR_INVALID_ARG`. The API therefore reports:

```json
{"sent":0,"tx_error":"ESP_ERR_INVALID_ARG"}
```

The patch changes one instruction in that function:

```
- li a3, 208   # 0xD0 (action)
+ li a3, 192   # 0xC0 (deauth)
```

The length, address, sequence, and interface checks remain in place. This is the
same one-instruction change used by the ESP32-C5 deauth community builds. It is
not a general bypass of the sanity check.

## Apply / verify / restore

```sh
source ~/esp/esp-idf/export.sh
cd /path/to/esp32touch

python3 tools/patch_c5_deauth.py --check     # STOCK or PATCHED
python3 tools/patch_c5_deauth.py --apply     # creates .stock backup first
idf.py fullclean
idf.py build
idf.py -p /dev/ttyACM0 flash

# return to the stock library if needed
python3 tools/patch_c5_deauth.py --restore
idf.py fullclean && idf.py build
```

The script searches the sanity-check section for the exact stock instruction,
refuses to patch if the bytes are unexpected, and verifies the result. It also
works on a copy:

```sh
python3 tools/patch_c5_deauth.py --lib /tmp/libnet80211.a --apply
python3 tools/patch_c5_deauth.py --lib /tmp/libnet80211.a --check
```

## After flashing

1. Unlock in **SET → ACTIVE ATTACKS**, the web **Attacks** tab, or the CLI
   (`auth ADMIN`).
2. Pick a target and press Deauth. The device starts an 8-second burst; the web
   UI lets you choose 5/8/15/30 seconds.
3. A successful request returns `started: true` and the number of clients
   targeted. The web **Stop** button, the device **STOP DEAUTH** button, or
   `{"stop":true}` cancels it early.
4. Access points that advertise PMF are marked **PMF** in the web AP list and
   device detail screen. Deauth can still be sent, but PMF clients may ignore
   it; the API returns a warning in that case.
5. If the request returns `started: false` or `tx_error`, run `--check`. If it
   says `STOCK`, reapply the patch and rebuild. If it says `PATCHED`, the target
   is on another channel while the station is associated, the target is
   invalid, or the client/AP is using protected management frames (PMF).
6. If the client comes back after the burst, run it again or pass a longer
   `duration_ms` (maximum 60000).

## Limitations

- The patch targets **ESP-IDF v5.5.4 / ESP32-C5**. A future IDF update replaces
  the library; rerun `--apply` and rebuild.
- This is an unsupported modification of a precompiled Espressif library.
  Rebuild and test after any IDF change.
- While associated to an AP, the single radio is pinned to that channel. Deauth
  requests for an AP on another channel return `409 Conflict`. Disconnect first
  for 5 GHz or cross-channel targets; the on-device UI has a **DISCONNECT**
  button in **SET**.
- PMF/802.11w clients may ignore unprotected deauth frames even when they are
  transmitted.
- Auto-deauth remains off by default. The runtime phrase is still required for
  every active attack.
- Use active deauthentication only on networks you own or have explicit written
  permission to test. See [LEGAL.md](LEGAL.md).
