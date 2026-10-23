#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

/* Station-mode network manager: saved credentials in NVS, auto-reconnect,
 * and integration with the sniffer (hopping stops while associated). */

typedef struct {
    bool    connected;
    bool    connecting;
    bool    have_creds;
    bool    autoconnect;
    bool    setup_mode;      /* setup fallback has been entered */
    bool    ap_active;       /* SoftAP interface is running */
    char    ssid[33];
    char    ip[16];
    char    netmask[16];
    char    gw[16];
    char    ap_ssid[33];
    char    ap_ip[16];
    int8_t  rssi;
    uint8_t channel;
    uint8_t bssid[6];
    int     reason;          /* last disconnect reason */
} pwn_net_status_t;

esp_err_t net_init(void);

/* Join an AP. If save is true the credentials are written to NVS and used on
 * the next boot. Empty password means an open network. */
esp_err_t net_connect(const char *ssid, const char *pass, bool save);

/* Leave the current AP. forget also erases the stored credentials. */
esp_err_t net_disconnect(bool forget);
esp_err_t net_forget(void);

void net_get_status(pwn_net_status_t *out);
bool net_connected(void);
bool net_have_creds(void);
bool net_setup_active(void);

/* Force the provisioning SoftAP on/off. Normally driven automatically. */
esp_err_t net_set_setup(bool on);

void net_set_autoconnect(bool on);
bool net_get_autoconnect(void);
