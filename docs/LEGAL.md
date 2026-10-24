# Legal, privacy, and safety notes

> This is not legal advice. Radio and computer-misuse laws vary by country, state, and even municipality. If you are unsure whether a test is authorized, stop and get written permission or use an isolated lab.

## What this firmware does

`pwni` is a passive-first Wi-Fi awareness tool. In its normal state it:

- receives 802.11 management and data frames in promiscuous mode,
- records access points, clients, handshakes, and PMKIDs,
- writes captured frames to a microSD card as PCAP files,
- and runs a local web UI on your own network.

Passive reception of radio traffic is still regulated in many places, and captured frames can contain personal data (MAC addresses, SSIDs, device fingerprints, and sometimes handshake material). Treat capture files as sensitive.

## Passive recon

The BLE scanner, DNS/SNI/HTTP parser, client fingerprinting, and watchlist are receive-only:

- BLE uses passive advertisements. It never connects, pairs, writes, or sends scan requests.
- The network metadata parser stores DNS question names, TLS SNI, and HTTP `Host` headers plus counters/timestamps. It does **not** store payloads, URLs, cookies, query answers, or credentials. WPA/WPA2/WPA3 data frames are encrypted and are not decrypted.
- Client fingerprinting stores MAC addresses, a small OUI vendor label, a randomized-MAC flag, timestamps, and the last few probe-request SSIDs. Probe requests and BLE advertisements can reveal personal habits or device presence even though no payload is captured.
- The watchlist is a local convenience feature. It does not transmit anything; it only marks matches in the dashboard and status API.

Even passive metadata can be personal data under privacy laws. Use the feature only where you have a lawful basis, keep the device on networks you control, and delete watchlists/PCAPs when they are no longer needed. Do not publish observed SSIDs, MAC addresses, BLE device names, or hostnames without consent.

## Active deauthentication

This build compiles the active-deauth path in (`PWN_ENABLE_DEAUTH=1`) so the UI and API can expose it after an explicit unlock. It is **not** enabled by default at runtime:

1. The firmware starts locked. The FACE/SCAN/SET UI and web dashboard show `locked` / `passive only`.
2. To unlock, an operator must enter the phrase `ADMIN` on the device, in the CLI, or through `/api/auth`. Matching is case-insensitive.
3. Auto-deauth is a separate switch and defaults to **off**.
4. While the station is associated, the radio is pinned to the AP channel. Cross-channel hop/deauth requests are refused with `409 Conflict`; deauth on the current channel is allowed. Disconnect first for 5 GHz or a different channel.
5. Sending a deauth requires a second explicit action (the deauth button/API call) after unlocking. It runs as an **8-second burst**; the web UI has a **Stop** button and `{"stop":true}` cancels it. The burst is more disruptive than a single frame, so use it only on authorized networks.

**ESP32-C5 driver patch:** with stock ESP-IDF, `esp_wifi_80211_tx()` rejects raw deauthentication frames with `ESP_ERR_INVALID_ARG`; unlocking works, but the request cannot transmit. This workspace applies a local one-instruction patch to `libnet80211.a` (see [C5_DEAUTH.md](C5_DEAUTH.md)) so deauth frames can be transmitted. The patch is an unsupported modification of a precompiled Espressif library; it does not change the legal or authorization requirements. The `deauths` counter includes deauth frames observed on the air, so verify effectiveness by watching the target disconnect, not just the counter.

The phrase is a deliberate speed bump, **not a security control**. It is printed in this repository and can be read from the firmware image. This build uses `ADMIN`, which is trivially guessable; change `PWN_AUTH_PHRASE` in `main/pwn_config.h` if the device is accessible to others. It does not make an unauthorized test lawful.

## When active features are lawful

Only use active features when at least one of the following is true:

- You own the network and the equipment.
- You have explicit, written permission from the network owner to test it.
- You are in an isolated lab or a dedicated test range with no third-party traffic.
- A specific law or regulation in your jurisdiction explicitly permits the test.

Do **not** use active features against:

- public, guest, corporate, or neighbor networks without permission,
- emergency, medical, industrial, aviation, or critical-infrastructure networks,
- networks you are not authorized to test, even if the signal is strong or the network is open,
- any network while driving or while operating equipment that requires your attention.

## Legal frameworks (examples only)

The following are examples, not a complete list and not legal advice:

- **United States**: the Computer Fraud and Abuse Act (CFAA), the Electronic Communications Privacy Act / Wiretap Act, and Federal Communications Commission rules on radio transmission and interception. State laws may add restrictions.
- **United Kingdom**: the Computer Misuse Act 1990 and the Wireless Telegraphy Act, among others.
- **European Union**: national implementations of computer-misuse, privacy, and electronic-communications laws (for example, GDPR and ePrivacy rules can apply to captured identifiers).
- **Elsewhere**: many countries prohibit unauthorized access to computer systems and unauthorized interception or jamming of radio communications.

Interference with radio communications can carry separate civil and criminal penalties, even when the network itself is yours to test. Do not transmit deauth or other disruptive frames outside a controlled, authorized environment.

## Privacy

- PCAPs can contain MAC addresses, SSIDs, probe requests, and handshake frames. They may be personal data under privacy laws.
- Store captures on a trusted SD card, encrypt or delete them when no longer needed, and do not publish them without consent.
- The web dashboard uses HTTP Basic auth (`admin` / `ADMIN` by default) but is plain HTTP on the LAN. Anyone who can reach the device's IP and knows/guesses the phrase can read its status, metadata tables, watchlist, and captures. Use a trusted network, change the phrase, or keep the device off untrusted networks.
- The CLI and web API can reboot the device and change settings. Treat physical and network access accordingly.

## Safety

- Do not operate the device in a way that distracts you while driving or working with hazardous equipment.
- Keep the antenna and board away from medical devices and sensitive electronics.
- The board and PMU can produce heat; use a proper enclosure and do not cover the vents.
- RF exposure limits vary. Do not modify the antenna or increase transmit power without checking local rules.
- Deauth frames can disrupt legitimate users, including emergency calls and industrial control traffic. Never send them casually.

## How to disable active features

For a purely passive build, set the following in [`main/pwn_config.h`](../main/pwn_config.h) and rebuild:

```c
#define PWN_ENABLE_DEAUTH 0
```

With that flag at `0`, the active deauth path is compiled out. Leaving the runtime lock engaged has the same practical effect for normal use, but the compile-time flag is the stronger guarantee.

## No warranty

This project is a personal research toy. It is provided as-is, without warranty of any kind. The authors are not responsible for misuse, regulatory violations, network damage, data loss, or legal consequences. You are responsible for how you use the radio and the captured data.
