#include "pwn_net.h"

#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"

#include "pwn_config.h"
#include "pwn_wifi.h"

static const char *TAG = "net";

#define NVS_NS  "pwnnet"

static pwn_net_status_t s_st;
static esp_netif_t *s_netif;
static esp_timer_handle_t s_retry_timer;
static esp_timer_handle_t s_watch_timer;
static volatile bool s_want_connect;
static volatile bool s_stopping;
static volatile bool s_setup;
static int  s_retries;
static uint32_t s_attempt_since;
static char s_pass[64];

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

static void load_creds(void)
{
    nvs_handle_t h;
    s_st.have_creds = false;
    s_st.autoconnect = true;
    s_pass[0] = 0;

    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) {
        return;
    }
    size_t len = sizeof(s_st.ssid) - 1;
    if (nvs_get_str(h, "ssid", s_st.ssid, &len) == ESP_OK && s_st.ssid[0]) {
        s_st.have_creds = true;
    }
    len = sizeof(s_pass) - 1;
    nvs_get_str(h, "pass", s_pass, &len);
    uint8_t ac = 1;
    if (nvs_get_u8(h, "auto", &ac) == ESP_OK) {
        s_st.autoconnect = ac != 0;
    }
    nvs_close(h);
}

static void save_creds(const char *ssid, const char *pass, bool autoconnect)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "nvs open failed: %s", esp_err_to_name(err));
        return;
    }
    if (ssid && ssid[0]) {
        nvs_set_str(h, "ssid", ssid);
        nvs_set_str(h, "pass", pass ? pass : "");
    } else {
        nvs_erase_key(h, "ssid");
        nvs_erase_key(h, "pass");
    }
    nvs_set_u8(h, "auto", autoconnect ? 1 : 0);
    nvs_commit(h);
    nvs_close(h);
}

static void save_auto(bool autoconnect)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) {
        return;
    }
    nvs_set_u8(h, "auto", autoconnect ? 1 : 0);
    nvs_commit(h);
    nvs_close(h);
}

static void update_ip(void)
{
    if (!s_netif) {
        return;
    }
    esp_netif_ip_info_t ip = {0};
    if (esp_netif_get_ip_info(s_netif, &ip) == ESP_OK && ip.ip.addr) {
        snprintf(s_st.ip, sizeof(s_st.ip), IPSTR, IP2STR(&ip.ip));
        snprintf(s_st.netmask, sizeof(s_st.netmask), IPSTR, IP2STR(&ip.netmask));
        snprintf(s_st.gw, sizeof(s_st.gw), IPSTR, IP2STR(&ip.gw));
    } else {
        s_st.ip[0] = 0;
        s_st.netmask[0] = 0;
        s_st.gw[0] = 0;
    }
}

static void arm_retry(void)
{
    if (!s_retry_timer) {
        return;
    }
    esp_timer_stop(s_retry_timer);
    esp_timer_start_once(s_retry_timer, 3000 * 1000ULL);
}

/* ---- setup SoftAP fallback ------------------------------------------- */

static bool enter_setup(const char *why)
{
    if (s_setup) {
        return true;
    }
    s_setup = true;
    s_st.setup_mode = true;
    /* While the setup AP is up there is no point hammering a dead network;
     * the next connect attempt comes from the user or a reboot. */
    s_want_connect = false;
    s_st.connecting = false;
    s_retries = 0;

    ESP_LOGW(TAG, "entering setup mode (%s)", why);
    esp_err_t err = pwn_wifi_set_ap(true, s_st.ap_ssid);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "setup AP start failed: %s", esp_err_to_name(err));
        s_setup = false;
        s_st.setup_mode = false;
        s_st.ap_active = false;
        return false;
    }
    s_st.ap_active = true;
    /* The setup AP now owns the channel; drop any STA pin so scans can
     * restore the AP channel and so hopping resumes when the AP stops. */
    pwn_wifi_set_locked(false, 0);
    ESP_LOGW(TAG, "setup AP ready: join %s (open) then open http://%s/",
             s_st.ap_ssid, s_st.ap_ip);
    return true;
}

static void stop_setup(void)
{
    if (!s_setup && !pwn_wifi_ap_active()) {
        return;
    }
    esp_err_t err = pwn_wifi_set_ap(false, NULL);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "setup AP stop failed: %s", esp_err_to_name(err));
        return;
    }
    s_setup = false;
    s_st.setup_mode = false;
    s_st.ap_active = false;
    if (!s_st.connected) {
        pwn_wifi_set_locked(false, 0);
    }
    ESP_LOGI(TAG, "setup mode off; station is in charge");
}

static void watch_cb(void *arg)
{
    (void)arg;
    if (s_setup || s_st.connected || s_stopping) {
        return;
    }
    if (!s_st.have_creds || !s_attempt_since) {
        return;
    }
    uint32_t elapsed = now_ms() - s_attempt_since;
    if (elapsed >= PWN_SETUP_TIMEOUT_MS) {
        char why[64];
        snprintf(why, sizeof(why), "STA join failed for %us",
                 (unsigned)(PWN_SETUP_TIMEOUT_MS / 1000));
        s_attempt_since = 0;
        enter_setup(why);
    }
}

static void retry_cb(void *arg)
{
    (void)arg;
    if (!s_want_connect || s_st.connected || s_stopping) {
        return;
    }
    if (s_retries >= 3) {
        ESP_LOGW(TAG, "giving up after %d attempts; setup fallback at %us",
                 s_retries, (unsigned)(PWN_SETUP_TIMEOUT_MS / 1000));
        s_want_connect = false;
        s_st.connecting = false;
        if (!s_attempt_since) {
            pwn_wifi_set_locked(false, 0);
        }
        return;
    }
    s_retries++;
    ESP_LOGI(TAG, "reconnect attempt %d", s_retries);
    /* Keep the radio parked while the station scans/associates; hopping
     * during connection attempts only adds failures and log noise. */
    pwn_wifi_set_locked(true, 0);
    esp_wifi_connect();
}

static void wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)base;

    switch (id) {
    case WIFI_EVENT_STA_CONNECTED: {
        wifi_event_sta_connected_t *ev = data;
        s_st.connected = true;
        s_st.connecting = false;
        s_st.reason = 0;
        s_retries = 0;
        memcpy(s_st.bssid, ev->bssid, 6);
        s_st.channel = ev->channel;
        memcpy(s_st.ssid, ev->ssid, sizeof(s_st.ssid) - 1);
        s_st.ssid[sizeof(s_st.ssid) - 1] = 0;
        /* Hopping would drop the link; pin the sniffer to the AP channel.
         * In setup mode the AP still owns the radio until DHCP completes,
         * so defer the pin until IP_EVENT_STA_GOT_IP. */
        if (!s_setup) {
            pwn_wifi_set_locked(true, ev->channel);
        }
        ESP_LOGI(TAG, "associated with %s on channel %u", s_st.ssid, ev->channel);
        break;
    }
    case WIFI_EVENT_STA_DISCONNECTED: {
        wifi_event_sta_disconnected_t *ev = data;
        s_st.connected = false;
        s_st.reason = ev->reason;
        s_st.rssi = 0;
        s_st.channel = 0;
        s_st.ip[0] = 0;
        s_st.netmask[0] = 0;
        s_st.gw[0] = 0;
        if (!s_setup) {
            if (!s_want_connect) {
                pwn_wifi_set_locked(false, 0);
            }
        }
        ESP_LOGW(TAG, "disconnected (reason %d)%s", ev->reason,
                 s_want_connect ? ", will retry" : "");
        if (s_want_connect && !s_stopping) {
            s_st.connecting = true;
            if (!s_attempt_since) {
                s_attempt_since = now_ms();
            }
            arm_retry();
        } else {
            s_st.connecting = false;
        }
        break;
    }
    default:
        break;
    }
}

static void ip_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)base;
    (void)data;

    if (id == IP_EVENT_STA_GOT_IP) {
        s_st.connected = true;
        s_st.connecting = false;
        s_st.reason = 0;
        s_retries = 0;
        s_attempt_since = 0;
        update_ip();
        s_st.rssi = 0;

        wifi_ap_record_t ap;
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
            s_st.rssi = ap.rssi;
            s_st.channel = ap.primary;
        }

        /* The station has an address, so provisioning is done. Pin first so
         * there is no hop window, then drop the setup AP. */
        if (s_st.channel) {
            pwn_wifi_set_locked(true, s_st.channel);
        }
        if (s_setup) {
            stop_setup();
        }
        ESP_LOGI(TAG, "got IP %s — web UI: http://%s/", s_st.ip, s_st.ip);
    } else if (id == IP_EVENT_STA_LOST_IP) {
        s_st.ip[0] = 0;
    }
}

esp_err_t net_init(void)
{
    memset(&s_st, 0, sizeof(s_st));
    snprintf(s_st.ap_ip, sizeof(s_st.ap_ip), "192.168.4.1");
    load_creds();

    uint8_t mac[6] = {0};
    if (esp_wifi_get_mac(WIFI_IF_STA, mac) != ESP_OK) {
        ESP_LOGW(TAG, "could not read station MAC for setup SSID");
    }
    snprintf(s_st.ap_ssid, sizeof(s_st.ap_ssid), "%s-%02X%02X",
             PWN_SETUP_AP_PREFIX, mac[4], mac[5]);

    s_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!s_netif) {
        s_netif = esp_netif_create_default_wifi_sta();
    }
    if (s_netif) {
        esp_netif_set_hostname(s_netif, "pwni");
    }

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                               wifi_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, ESP_EVENT_ANY_ID,
                                               ip_event, NULL));

    const esp_timer_create_args_t args = {
        .callback = retry_cb,
        .name = "net_retry",
    };
    esp_timer_create(&args, &s_retry_timer);

    const esp_timer_create_args_t watch_args = {
        .callback = watch_cb,
        .name = "net_watch",
    };
    if (esp_timer_create(&watch_args, &s_watch_timer) == ESP_OK) {
        esp_timer_start_periodic(s_watch_timer, 1000 * 1000ULL);
    }

    if (!s_st.have_creds) {
        enter_setup("no saved credentials");
    } else if (s_st.autoconnect) {
        ESP_LOGI(TAG, "autoconnecting to saved network %s", s_st.ssid);
        net_connect(s_st.ssid, s_pass, false);
    }
    return ESP_OK;
}

esp_err_t net_connect(const char *ssid, const char *pass, bool save)
{
    if (!ssid || !ssid[0] || strlen(ssid) > 32) {
        return ESP_ERR_INVALID_ARG;
    }
    const char *pw = pass;
    if (!pw && strcmp(ssid, s_st.ssid) == 0) {
        pw = s_pass;
    }
    if (pw && pw[0] && (strlen(pw) < 8 || strlen(pw) > 63)) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Already there? Do not drop the link just to reconnect. */
    if (s_st.connected && strcmp(ssid, s_st.ssid) == 0 && (!pass || !pass[0])) {
        return ESP_OK;
    }

    wifi_config_t cfg = {0};
    snprintf((char *)cfg.sta.ssid, sizeof(cfg.sta.ssid), "%s", ssid);
    if (pw && pw[0]) {
        snprintf((char *)cfg.sta.password, sizeof(cfg.sta.password), "%s", pw);
    }
    cfg.sta.threshold.authmode = (pw && pw[0]) ? WIFI_AUTH_WPA2_PSK
                                               : WIFI_AUTH_OPEN;
    cfg.sta.pmf_cfg.capable = true;
    cfg.sta.pmf_cfg.required = false;

    s_stopping = true;
    esp_wifi_disconnect();
    s_stopping = false;

    esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &cfg);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "set_config failed: %s", esp_err_to_name(err));
        return err;
    }

    snprintf(s_st.ssid, sizeof(s_st.ssid), "%s", ssid);
    if (pw) {
        snprintf(s_pass, sizeof(s_pass), "%s", pw);
    }
    s_st.have_creds = true;
    s_st.connecting = true;
    s_st.connected = false;
    s_want_connect = true;
    s_retries = 0;
    s_attempt_since = now_ms();
    pwn_wifi_set_locked(true, 0);

    if (save) {
        save_creds(ssid, pw, s_st.autoconnect);
    }

    ESP_LOGI(TAG, "connecting to %s%s", ssid, (pw && pw[0]) ? "" : " (open)");
    err = esp_wifi_connect();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "connect failed: %s", esp_err_to_name(err));
        s_st.connecting = false;
        s_want_connect = false;
    }
    return err;
}

esp_err_t net_disconnect(bool forget)
{
    s_want_connect = false;
    s_st.connecting = false;
    s_attempt_since = 0;
    s_stopping = true;
    esp_err_t err = esp_wifi_disconnect();
    s_stopping = false;
    if (forget) {
        net_forget();
    }
    return err;
}

esp_err_t net_forget(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) {
        return ESP_FAIL;
    }
    nvs_erase_key(h, "ssid");
    nvs_erase_key(h, "pass");
    nvs_commit(h);
    nvs_close(h);

    s_st.have_creds = false;
    s_st.ssid[0] = 0;
    s_pass[0] = 0;
    s_want_connect = false;
    s_st.connecting = false;
    s_attempt_since = 0;
    ESP_LOGI(TAG, "saved credentials erased");
    /* No credentials means there is no way back in except the setup AP. */
    enter_setup("credentials erased");
    return ESP_OK;
}

void net_get_status(pwn_net_status_t *out)
{
    if (!out) {
        return;
    }
    if (s_st.connected) {
        update_ip();
        wifi_ap_record_t ap;
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
            s_st.rssi = ap.rssi;
        }
    }
    s_st.ap_active = pwn_wifi_ap_active();
    s_st.setup_mode = s_setup;
    *out = s_st;
}

bool net_connected(void)
{
    return s_st.connected;
}

bool net_have_creds(void)
{
    return s_st.have_creds;
}

bool net_setup_active(void)
{
    return s_setup;
}

esp_err_t net_set_setup(bool on)
{
    if (on) {
        return enter_setup("requested") ? ESP_OK : ESP_FAIL;
    }
    stop_setup();
    return ESP_OK;
}

void net_set_autoconnect(bool on)
{
    s_st.autoconnect = on;
    save_auto(on);
    if (on && s_st.have_creds && !s_st.connected) {
        net_connect(s_st.ssid, s_pass, false);
    }
}

bool net_get_autoconnect(void)
{
    return s_st.autoconnect;
}
