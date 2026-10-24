#pragma once

#include <stdint.h>
#include <stdbool.h>

/* Small built-in OUI table for observed Wi-Fi/BLE clients. This is a
 * convenience label, not an authoritative device identification: OUIs can be
 * reassigned, and locally administered (randomized) addresses have no vendor.
 * The table is intentionally tiny so it costs no runtime allocations. */
const char *pwn_oui_vendor(const uint8_t mac[6]);

/* True when the locally administered bit is set. Android/iOS/macOS use this
 * for randomized Wi-Fi MACs; BLE random addresses also present as locally
 * administered. */
bool pwn_oui_randomized(const uint8_t mac[6]);
