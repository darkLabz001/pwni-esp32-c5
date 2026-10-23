#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

/* Deauth-assisted handshake capture ("hunt"). A hunt sends a bounded deauth
 * burst at one BSSID (optionally a single station) and polls the capture slots
 * until a complete 4-way handshake or PMKID is saved, or the duration expires.
 *
 * Runtime authorization is required. The device's own station MAC is never
 * targeted, and broadcast is skipped when the target is the AP this device is
 * associated with (observed clients only). */

#define PWN_HUNT_DEFAULT_MS 20000
#define PWN_HUNT_MIN_MS     1000
#define PWN_HUNT_MAX_MS     60000

typedef enum {
    PWN_HUNT_IDLE = 0,
    PWN_HUNT_RUNNING,
    PWN_HUNT_CAPTURED,
    PWN_HUNT_TIMEOUT,
    PWN_HUNT_STOPPED,
    PWN_HUNT_ERROR,
} pwn_hunt_state_t;

typedef struct {
    pwn_hunt_state_t state;
    bool     active;
    uint8_t  bssid[6];
    uint8_t  sta[6];
    bool     have_sta;
    bool     pmf;
    bool     saved;           /* capture was written to SD */
    uint32_t duration_ms;
    uint32_t elapsed_ms;
    char     ssid[33];
    char     file[96];
    char     message[64];
} pwn_hunt_status_t;

void pwn_hunt_init(void);

/* Starts the background task. sta may be NULL to target any observed client.
 * Returns ESP_ERR_INVALID_STATE when locked or another hunt is running,
 * ESP_ERR_INVALID_ARG for a bad target, and ESP_ERR_NOT_FOUND when the AP is
 * not in the current scan table. `err` receives a human-readable reason. */
esp_err_t pwn_hunt_start(const uint8_t bssid[6], const uint8_t *sta,
                         uint32_t duration_ms, char *err, size_t errlen);

/* Ask an active hunt to stop. Safe to call when idle. */
void pwn_hunt_stop(void);

bool pwn_hunt_active(void);
void pwn_hunt_status(pwn_hunt_status_t *out);

const char *pwn_hunt_state_name(pwn_hunt_state_t state);
