#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "pwn_config.h"

/* -------------------------------------------------------------------------
 * BLE HID keyboard (opt-in, runtime-authorized, never auto-starts)
 *
 * This is the "BadUSB-style" half of the project: a BLE HID-over-GATT
 * keyboard that types a DuckyScript-like text file from
 * text files in /sdcard/payloads. It shares the single 2.4 GHz radio with Wi-Fi and
 * the passive BLE observer, so the observer is paused for the whole time HID
 * mode is active.
 *
 * Only use this against machines you own or have explicit written permission
 * to test. Nothing is persisted: HID mode is off after every boot and stops
 * immediately if the runtime authorization is revoked.
 * ---------------------------------------------------------------------- */

#define PWN_HID_PAYLOAD_DIR PWN_SD_MOUNT "/payloads"
#define PWN_HID_MAX_PAYLOADS 24
#define PWN_HID_PAYLOAD_NAME_MAX 64
#define PWN_HID_PAYLOAD_MAX (16 * 1024)
#define PWN_HID_DEVICE_NAME "PWNI-KBD"

typedef struct {
    char     name[PWN_HID_PAYLOAD_NAME_MAX];
    uint32_t size;
} pwn_hid_payload_t;

typedef enum {
    PWN_HID_OFF = 0,
    PWN_HID_ADVERTISING,
    PWN_HID_CONNECTED,
    PWN_HID_RUNNING,
    PWN_HID_DONE,
    PWN_HID_ERROR,
} pwn_hid_state_t;

typedef struct {
    bool     supported;
    bool     active;          /* HID mode enabled (advertising/connected) */
    bool     authorized;      /* runtime unlock currently valid */
    bool     connected;
    bool     encrypted;
    bool     boot_mode;
    bool     executing;
    bool     subscribed;
    pwn_hid_state_t state;
    char     selected[PWN_HID_PAYLOAD_NAME_MAX];
    char     error[96];
    uint32_t line;
    uint32_t lines;
    uint32_t chars;
    uint32_t age_ms;
} pwn_hid_status_t;

/* Initialise the module (no radio activity). Creates /sdcard/payloads when
 * the card is ready. Call after capture_init(). */
void hid_init(void);

/* Register the HID GATT services. Called by ble_init() after NimBLE starts,
 * before the host task runs. Safe to call once. */
void hid_gatt_init(void);

/* Called by the BLE module when the host synchronises or resets. */
void hid_on_ble_sync(void);
void hid_on_ble_reset(void);

bool hid_supported(void);

/* List *.txt files in /sdcard/payloads. Returns the number written. */
int  hid_list_payloads(pwn_hid_payload_t *out, int max);

/* Save a UTF-8/ASCII text payload to /sdcard/payloads/<name> atomically.
 * Rejects names with path separators and anything larger than
 * PWN_HID_PAYLOAD_MAX. Never executes the payload. */
bool hid_write_payload(const char *name, const char *data, size_t len,
                       char *err, size_t errsz);

/* Select a payload for a later run. Returns false for an invalid/missing
 * name. Never executes anything. */
bool hid_select(const char *name);

/* Enable HID advertising. Requires runtime authorization. Never executes a
 * payload; the operator must call hid_run() after a host connects. */
bool hid_start(void);

/* Stop typing, stop advertising, and disconnect the host. Also clears the
 * scanner gate so the passive observer can resume if it was enabled. */
void hid_stop(void);

/* Execute the selected payload (or the named one) on the connected host.
 * Fails unless HID mode is active, a host is connected, and it has
 * subscribed to the keyboard input report. */
bool hid_run(const char *name);

/* Copy the current state for the web UI. */
void hid_status(pwn_hid_status_t *out);

const char *hid_state_name(pwn_hid_state_t state);
