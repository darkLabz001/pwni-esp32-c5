#pragma once

/* -------------------------------------------------------------------------
 * esp32touch / PWNI — build-time configuration
 *
 * This firmware is a Pwnagotchi-style WiFi awareness tool. It is passive by
 * default. Active deauthentication is compiled out unless you explicitly
 * enable PWN_ENABLE_DEAUTH *and* unlock it at runtime with the authorization
 * phrase. Only run active features against networks you own or have written
 * permission to test.
 * ---------------------------------------------------------------------- */

#define PWN_VERSION "0.2.0"

/* Passive/active policy. Active deauthentication is still gated behind a
 * runtime authorization phrase, but is compiled in so the web UI and CLI can
 * use it after unlocking. Set to 0 for a purely passive build. */
#ifndef PWN_ENABLE_DEAUTH
#define PWN_ENABLE_DEAUTH 1
#endif

/* Runtime unlock phrase (device UI, web dashboard, or USB serial console).
 * Matching is case-insensitive. This is a speed bump, not a security
 * control; change it if you want something less guessable. */
#define PWN_AUTH_PHRASE "ADMIN"

/* Regulatory domain used for channel access. Change to your country code.
 * Only affects which channels the radio is allowed to tune to. */
#define PWN_COUNTRY "US"

/* Table sizes. */
#define PWN_MAX_APS      96
#define PWN_MAX_CLIENTS  128
#define PWN_MAX_HS       24
#define PWN_HS_FRAMES    6
#define PWN_FRAME_MAX    512

/* Sniffer ring buffer. */
#define PWN_RB_BYTES     (48 * 1024)

/* Capture storage. */
#define PWN_SD_MOUNT     "/sdcard"
#define PWN_HS_DIR       PWN_SD_MOUNT "/handshakes"
#define PWN_PCAP_DIR     PWN_SD_MOUNT "/pcap"

/* Channel plans. */
#define PWN_2G_COUNT 13
#define PWN_5G_COUNT 25
#define PWN_ALL_COUNT (PWN_2G_COUNT + PWN_5G_COUNT)

/* Pwnagotchi reward tuning. */
#define PWN_EPOCH_MS     20000
#define PWN_ACTIVE_EPOCHS_EXCITED 3
#define PWN_BORED_EPOCHS 8
#define PWN_SAD_EPOCHS   16

/* UI. */
#define PWN_FACE_COLOR_HEX 0x8CF58C

/* Manual GitHub OTA (only runs when requested from Settings; never automatic). */
#define PWN_OTA_URL "https://raw.githubusercontent.com/darkLabz001/pwni-esp32-c5/master/dist/esp32touch.bin"
