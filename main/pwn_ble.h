#pragma once

#include <stdint.h>
#include <stdbool.h>

/* Passive BLE observer. Opt-in and off by default. The scanner only listens
 * for advertisements: it never connects, pairs, writes, or sends scan
 * requests. */
#define PWN_BLE_MAX 48

typedef struct {
    uint8_t  addr[6];
    uint8_t  addr_type;
    uint8_t  event_type;
    int8_t   rssi;
    uint16_t count;
    uint32_t first_seen_ms;
    uint32_t last_seen_ms;
    char     name[32];
    char     services[64];
    char     beacon[16];
} pwn_ble_dev_t;

/* Initialise NimBLE and the scan supervisor. Safe to call when Bluetooth is
 * not compiled in: the module then reports unsupported. */
void ble_init(void);

bool ble_supported(void);
bool ble_set_enabled(bool on);
bool ble_enabled(void);
bool ble_scanning(void);
bool ble_gated(void);
int  ble_device_count(void);
int  ble_snapshot(pwn_ble_dev_t *out, int max);

const char *ble_addr_type_name(uint8_t type);
