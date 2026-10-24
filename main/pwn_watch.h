#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

/* Persistent passive watchlist. Entries are matched against observed SSIDs,
 * Wi-Fi MAC addresses, and BLE addresses or advertised names. Matching only
 * raises a dashboard/status event; it never transmits or connects. */
#define PWN_WATCH_MAX 24
#define PWN_WATCH_VALUE_MAX 33

typedef enum {
    PWN_WATCH_SSID = 0,
    PWN_WATCH_MAC  = 1,
    PWN_WATCH_BLE  = 2,
} pwn_watch_type_t;

typedef struct {
    uint8_t type;
    char    value[PWN_WATCH_VALUE_MAX];
} pwn_watch_item_t;

void watch_init(void);
int  watch_count(void);
int  watch_snapshot(pwn_watch_item_t *out, int max);

/* Add one entry. type is "ssid", "mac" or "ble". Returns ESP_OK, or
 * ESP_ERR_INVALID_ARG / ESP_ERR_NO_MEM with a short reason in err. */
esp_err_t watch_add(const char *type, const char *value, char *err, size_t errsz);
bool watch_remove(const char *type, const char *value);
int  watch_clear(void);
const char *watch_type_name(uint8_t type);

/* Matching checks. Each match raises at most one alert per entry per minute
 * so a beaconing AP or a chatty BLE device cannot flood the event log. */
bool watch_check_ssid(const char *ssid);
bool watch_check_mac(const uint8_t mac[6]);
bool watch_check_ble(const uint8_t addr[6], const char *name);

/* Snapshot of alert state for /api/status. */
void watch_status(int *count, uint32_t *hits, char *last, size_t lastsz,
                  uint32_t *age_ms);
