#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "pwn_config.h"
#include "pwn_brain.h"

#define PWN_BCN_MAX 512

typedef enum {
    SEC_OPEN = 0,
    SEC_WEP,
    SEC_WPA,
    SEC_WPA2,
    SEC_WPA3,
    SEC_UNKNOWN,
} pwn_security_t;

typedef struct {
    uint8_t  bssid[6];
    char     ssid[33];
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  security;
    bool     wps;
    bool     hidden;
    bool     has_handshake;
    bool     pmf;
    uint32_t beacons;
    uint32_t last_seen_ms;
    uint16_t bcn_len;
    uint8_t  bcn[PWN_BCN_MAX];
} pwn_ap_t;

typedef struct {
    uint8_t  mac[6];
    uint8_t  bssid[6];
    int8_t   rssi;
    uint32_t frames;
    uint32_t last_seen_ms;
} pwn_client_t;

typedef struct {
    volatile uint32_t frames;
    volatile uint32_t mgmt;
    volatile uint32_t data;
    volatile uint32_t beacons;
    volatile uint32_t probes;
    volatile uint32_t eapol;
    volatile uint32_t deauths;
    volatile uint32_t disassoc;
    volatile uint32_t hops;
    volatile uint32_t dropped;
    volatile uint32_t ap_count;
    volatile uint32_t client_count;
    volatile uint32_t hs_count;
    volatile uint32_t pmkid_count;
    volatile uint32_t saved_count;
    volatile uint32_t channel;
    volatile uint32_t band;
    volatile int32_t  last_rssi;
    volatile bool     sd_ready;
    volatile bool     authorized;
    char last_ssid[33];
    char last_event[80];
} pwn_wifi_stats_t;

esp_err_t pwn_wifi_start(void);
void      pwn_wifi_stop(void);

/* Reconfigure channel plan / dwell from the current brain action. */
void pwn_wifi_apply_policy(const brain_policy_t *p, bool authorized);

void pwn_wifi_set_paused(bool paused);
bool pwn_wifi_paused(void);

/* Active attack. Returns ESP_ERR_INVALID_STATE unless the runtime has been
 * authorized. Never called unless the build enables deauth. */
esp_err_t pwn_wifi_deauth(const uint8_t *bssid, const uint8_t *sta, uint8_t reason);

/* Timed deauth burst. The worker task sends one round every interval_ms for
 * duration_ms, which keeps a client down instead of letting it reassociate
 * after a single frame. Runtime authorization is required. */
typedef struct {
    uint8_t  bssid[6];
    uint8_t  sta[6];
    bool     have_sta;
    bool     all;                /* target observed clients of bssid */
    bool     target_is_self_ap;  /* skip broadcast fallback for our own AP */
    uint32_t duration_ms;
    uint16_t interval_ms;
    uint8_t  reason;
} pwn_deauth_job_t;

esp_err_t pwn_wifi_deauth_start(const pwn_deauth_job_t *job);
void      pwn_wifi_deauth_stop(void);
bool      pwn_wifi_deauth_active(void);

/* Copy the station interface MAC (used to avoid deauthing ourselves). */
void pwn_wifi_self_mac(uint8_t out[6]);

/* Last raw 802.11 TX result reported by the driver callback. */
typedef struct {
    bool     valid;
    uint8_t  src[6];
    uint8_t  dst[6];
    uint8_t  len;       /* frame body length, excluding the MAC header */
    int      status;    /* 0 = WIFI_SEND_SUCCESS */
    uint8_t  raw[32];   /* copy of the MAC header + body, for diagnostics */
    uint8_t  raw_len;
} pwn_wifi_tx_t;
void pwn_wifi_last_tx(pwn_wifi_tx_t *out);
void pwn_wifi_clear_last_tx(void);

const pwn_wifi_stats_t *pwn_wifi_stats(void);
int pwn_wifi_ap_snapshot(pwn_ap_t *out, int max);
int pwn_wifi_client_snapshot(pwn_client_t *out, int max);

void pwn_wifi_set_authorized(bool on);
bool pwn_wifi_authorized(void);

/* One-shot synchronous scan, used by the CLI. Returns APs found. */
int pwn_wifi_scan_now(void);

/* Park the radio on one channel (debug / manual tuning). */
esp_err_t pwn_wifi_force_channel(uint8_t channel);

/* Called by the network module when the station joins an AP: hopping would
 * break the connection, so the sniffer is pinned to the AP's channel until
 * the station disconnects. */
void pwn_wifi_set_locked(bool locked, uint8_t channel);
bool pwn_wifi_locked(void);

/* Let hunting epochs send deauths automatically. Off by default; requires
 * the runtime authorization phrase and a build with PWN_ENABLE_DEAUTH. */
void pwn_wifi_set_auto_deauth(bool on);
bool pwn_wifi_auto_deauth(void);

/* Inject a synthetic beacon + PMKID-bearing handshake through the same
 * parser used by the sniffer and verify the resulting PCAP. Returns 0 on
 * success, negative on failure. */
int pwn_wifi_selftest(void);
