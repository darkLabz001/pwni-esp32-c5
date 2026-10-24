#include "pwn_web.h"

#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_http_client.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "esp_ota_ops.h"
#include "esp_crt_bundle.h"
#include "mbedtls/sha256.h"
#include "esp_sntp.h"
#include <time.h>
#include "cJSON.h"
#include "bsp/esp-bsp.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "pwn_config.h"
#include "pwn_wifi.h"
#include "pwn_capture.h"
#include "pwn_hunt.h"
#include "pwn_pet.h"
#include "pwn_net.h"
#include "pwn_web_page.h"
#include "pwn_watch.h"
#include "pwn_ble.h"
#include "pwn_hid.h"
#include "pwn_netmeta.h"
#include "pwn_oui.h"

static const char *TAG = "web";

/* Large snapshot arrays live in PSRAM so internal RAM stays available for
 * task stacks (the CLI uses a 16 KiB stack). */
static void *big_calloc(size_t n, size_t size)
{
    void *p = heap_caps_calloc(n, size, MALLOC_CAP_SPIRAM);
    return p ? p : calloc(n, size);
}
static httpd_handle_t s_server;

/* Manual GitHub OTA state (reported by /api/status). */
#define OTA_ERR_MAX 192

typedef enum {
    OTA_ST_IDLE = 0,
    OTA_ST_DOWNLOADING,
    OTA_ST_VERIFYING,
    OTA_ST_FLASHING,
    OTA_ST_ERROR,
} ota_state_t;

static const char *ota_state_name(ota_state_t st);
static void ota_status_snapshot(ota_state_t *st, int *progress,
                                char *err, size_t errsz);

/* ---- helpers ---------------------------------------------------------- */

#define BODY_MAX 1024

static esp_err_t send_json(httpd_req_t *req, cJSON *root)
{
    char *out = root ? cJSON_PrintUnformatted(root) : NULL;
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t err = httpd_resp_sendstr(req, out ? out : "{}");
    free(out);
    if (root) {
        cJSON_Delete(root);
    }
    return err;
}

static esp_err_t fail(httpd_req_t *req, const char *status, const char *msg)
{
    httpd_resp_set_status(req, status);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "error", msg);
    return send_json(req, r);
}

static cJSON *read_body(httpd_req_t *req, char *buf, size_t buflen)
{
    int len = req->content_len;
    if (len <= 0 || len >= (int)buflen) {
        return NULL;
    }
    int got = 0;
    while (got < len) {
        int r = httpd_req_recv(req, buf + got, len - got);
        if (r <= 0) {
            return NULL;
        }
        got += r;
    }
    buf[got] = 0;
    return cJSON_Parse(buf);
}

static bool parse_mac(const char *s, uint8_t out[6])
{
    if (!s) {
        return false;
    }
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        out[i] = (uint8_t)v[i];
    }
    return true;
}

static void mac_str(const uint8_t *m, char out[18])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static const char *sec_name(uint8_t s)
{
    switch (s) {
    case SEC_OPEN: return "open";
    case SEC_WEP:  return "WEP";
    case SEC_WPA:  return "WPA";
    case SEC_WPA2: return "WPA2";
    case SEC_WPA3: return "WPA3";
    default:       return "?";
    }
}

static const char *flash_speed(void)
{
    return CONFIG_ESPTOOLPY_FLASHFREQ;
}

static const char *psram_speed(void)
{
#if CONFIG_SPIRAM_SPEED_120M
    return "120 MHz";
#elif CONFIG_SPIRAM_SPEED_80M
    return "80 MHz";
#else
    return "40 MHz";
#endif
}

static const char *psram_mode(void)
{
#if CONFIG_SPIRAM_MODE_OCT
    return "octal";
#else
    return "quad";
#endif
}

static void hid_status_fields(cJSON *r)
{
    pwn_hid_status_t hid;
    hid_status(&hid);
    cJSON_AddBoolToObject(r, "hid_supported", hid.supported);
    cJSON_AddBoolToObject(r, "hid_active", hid.active);
    cJSON_AddBoolToObject(r, "hid_authorized", hid.authorized);
    cJSON_AddBoolToObject(r, "hid_connected", hid.connected);
    cJSON_AddBoolToObject(r, "hid_encrypted", hid.encrypted);
    cJSON_AddBoolToObject(r, "hid_subscribed", hid.subscribed);
    cJSON_AddBoolToObject(r, "hid_boot_mode", hid.boot_mode);
    cJSON_AddBoolToObject(r, "hid_executing", hid.executing);
    cJSON_AddStringToObject(r, "hid_state", hid_state_name(hid.state));
    cJSON_AddStringToObject(r, "hid_payload", hid.selected);
    cJSON_AddStringToObject(r, "hid_error", hid.error);
    cJSON_AddNumberToObject(r, "hid_line", hid.line);
    cJSON_AddNumberToObject(r, "hid_lines", hid.lines);
    cJSON_AddNumberToObject(r, "hid_chars", hid.chars);
    cJSON_AddNumberToObject(r, "hid_age_ms", hid.age_ms);
}

/* ---- page ------------------------------------------------------------- */

static bool web_auth(httpd_req_t *req)
{
    char hdr[128];
    if (httpd_req_get_hdr_value_str(req, "Authorization", hdr, sizeof(hdr)) != ESP_OK ||
        strcmp(hdr, "Basic YWRtaW46QURNSU4=") != 0) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"PWNI\"");
        httpd_resp_sendstr(req, "authentication required\n");
        return false;
    }
    return true;
}

static esp_err_t page_get(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Cache-Control", "max-age=60");
    return httpd_resp_send(req, PWN_WEB_PAGE, sizeof(PWN_WEB_PAGE) - 1);
}

static esp_err_t favicon_get(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    httpd_resp_set_status(req, "204 No Content");
    return httpd_resp_send(req, NULL, 0);
}

/* ---- status ----------------------------------------------------------- */

static esp_err_t status_get(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    pwn_pet_t pet;
    pet_snapshot(&pet);
    const pwn_wifi_stats_t *st = pwn_wifi_stats();
    pwn_net_status_t net;
    net_get_status(&net);

    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "fw", PWN_VERSION);
    cJSON_AddNumberToObject(r, "uptime", esp_timer_get_time() / 1000000ULL);
    cJSON_AddNumberToObject(r, "heap_free", esp_get_free_heap_size());
    cJSON_AddNumberToObject(r, "heap_internal_free",
                            heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(r, "heap_internal_min",
                            heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(r, "psram_free",
                            heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

    cJSON_AddStringToObject(r, "mood", pet_mood_name(pet.mood));
    cJSON_AddStringToObject(r, "status", pet.status);
    cJSON_AddNumberToObject(r, "level", pet.level);
    cJSON_AddNumberToObject(r, "xp", pet.xp);
    cJSON_AddNumberToObject(r, "bond", pet.bond);
    cJSON_AddNumberToObject(r, "epochs", pet.epochs);
    cJSON_AddStringToObject(r, "action", pet_action_name(pet.action));
    cJSON_AddNumberToObject(r, "action_override", pet_action_override());
    cJSON_AddNumberToObject(r, "reward", pet.reward);
    cJSON_AddNumberToObject(r, "avg_reward", pet.avg_reward);

    cJSON_AddNumberToObject(r, "ap_count", st->ap_count);
    cJSON_AddNumberToObject(r, "client_count", st->client_count);
    cJSON_AddNumberToObject(r, "hs_count", st->hs_count);
    cJSON_AddNumberToObject(r, "pmkid_count", st->pmkid_count);
    cJSON_AddNumberToObject(r, "saved_count", st->saved_count);
    cJSON_AddNumberToObject(r, "hs_writer_dropped", capture_dropped_count());
    cJSON_AddNumberToObject(r, "frames", st->frames);
    cJSON_AddNumberToObject(r, "eapol", st->eapol);
    cJSON_AddNumberToObject(r, "deauths", st->deauths);
    cJSON_AddNumberToObject(r, "dropped", st->dropped);
    cJSON_AddNumberToObject(r, "channel", st->channel);
    cJSON_AddNumberToObject(r, "band", st->band);

    /* Passive recon counters. All values are metadata only. */
    pwn_netmeta_counts_t nm;
    netmeta_counts(&nm);
    cJSON_AddNumberToObject(r, "dns_total", nm.dns_total);
    cJSON_AddNumberToObject(r, "dns_count", nm.dns_count);
    cJSON_AddNumberToObject(r, "sni_total", nm.sni_total);
    cJSON_AddNumberToObject(r, "sni_count", nm.sni_count);
    cJSON_AddNumberToObject(r, "http_total", nm.http_total);
    cJSON_AddNumberToObject(r, "http_count", nm.http_count);
    cJSON_AddNumberToObject(r, "talker_count", nm.talker_count);
    cJSON_AddBoolToObject(r, "ble_supported", ble_supported());
    cJSON_AddBoolToObject(r, "ble_enabled", ble_enabled());
    cJSON_AddBoolToObject(r, "ble_scanning", ble_scanning());
    cJSON_AddBoolToObject(r, "ble_gated", ble_gated());
    cJSON_AddNumberToObject(r, "ble_count", ble_device_count());
    hid_status_fields(r);

    int watch_count = 0;
    uint32_t watch_hits = 0;
    uint32_t watch_age = 0;
    char watch_last[96] = "";
    watch_status(&watch_count, &watch_hits, watch_last, sizeof(watch_last),
                 &watch_age);
    cJSON_AddNumberToObject(r, "watch_count", watch_count);
    cJSON_AddNumberToObject(r, "watch_hits", watch_hits);
    cJSON_AddStringToObject(r, "watch_last", watch_last);
    cJSON_AddNumberToObject(r, "watch_age_ms", watch_age);
    cJSON_AddBoolToObject(r, "paused", pet.paused);
    cJSON_AddBoolToObject(r, "locked", pwn_wifi_locked());
    cJSON_AddBoolToObject(r, "authorized", pwn_wifi_authorized());
    cJSON_AddBoolToObject(r, "auto_deauth", pwn_wifi_auto_deauth());
    cJSON_AddBoolToObject(r, "deauth_active", pwn_wifi_deauth_active());

    pwn_hunt_status_t hunt;
    pwn_hunt_status(&hunt);
    char hunt_bssid[18] = "";
    char hunt_sta[18] = "";
    if ((hunt.bssid[0] | hunt.bssid[1] | hunt.bssid[2] |
         hunt.bssid[3] | hunt.bssid[4] | hunt.bssid[5]) != 0) {
        mac_str(hunt.bssid, hunt_bssid);
    }
    if (hunt.have_sta &&
        (hunt.sta[0] | hunt.sta[1] | hunt.sta[2] |
         hunt.sta[3] | hunt.sta[4] | hunt.sta[5]) != 0) {
        mac_str(hunt.sta, hunt_sta);
    }
    cJSON_AddBoolToObject(r, "hunt_active", hunt.active);
    cJSON_AddStringToObject(r, "hunt_result",
                            pwn_hunt_state_name(hunt.state));
    cJSON_AddStringToObject(r, "hunt_bssid", hunt_bssid);
    cJSON_AddStringToObject(r, "hunt_sta", hunt_sta);
    cJSON_AddNumberToObject(r, "hunt_duration_ms", hunt.duration_ms);
    cJSON_AddNumberToObject(r, "hunt_elapsed_ms", hunt.elapsed_ms);
    cJSON_AddBoolToObject(r, "hunt_pmf", hunt.pmf);
    cJSON_AddBoolToObject(r, "hunt_saved", hunt.saved);
    cJSON_AddStringToObject(r, "hunt_file", hunt.file);
    cJSON_AddStringToObject(r, "hunt_message", hunt.message);
    const char *last_event = st->last_event[0] ? st->last_event : "listening...";
    if (watch_last[0] && watch_age < 60000) {
        last_event = watch_last;   /* keep a recent watch hit visible */
    }
    cJSON_AddStringToObject(r, "last_event", last_event);
    cJSON_AddBoolToObject(r, "sd", capture_sd_ready());
    pwn_sd_info_t sdinfo;
    if (capture_sd_info(&sdinfo)) {
        cJSON_AddNumberToObject(r, "sd_total", sdinfo.total_bytes);
        cJSON_AddNumberToObject(r, "sd_free", sdinfo.free_bytes);
        cJSON_AddBoolToObject(r, "sd_writable", sdinfo.writable);
    } else {
        cJSON_AddNumberToObject(r, "sd_total", 0);
        cJSON_AddNumberToObject(r, "sd_free", 0);
        cJSON_AddBoolToObject(r, "sd_writable", false);
    }
    cJSON_AddStringToObject(r, "hs_dir", PWN_HS_DIR);
    const esp_partition_t *runpart = esp_ota_get_running_partition();
    cJSON_AddStringToObject(r, "ota_running", runpart ? runpart->label : "?");
    ota_state_t ota_st;
    int ota_prog;
    char ota_err[OTA_ERR_MAX];
    ota_status_snapshot(&ota_st, &ota_prog, ota_err, sizeof(ota_err));
    cJSON_AddStringToObject(r, "ota_state", ota_state_name(ota_st));
    cJSON_AddNumberToObject(r, "ota_progress", ota_prog);
    cJSON_AddStringToObject(r, "ota_error", ota_err);

    cJSON_AddBoolToObject(r, "connected", net.connected);
    cJSON_AddBoolToObject(r, "connecting", net.connecting);
    cJSON_AddBoolToObject(r, "have_creds", net.have_creds);
    cJSON_AddBoolToObject(r, "autoconnect", net.autoconnect);
    cJSON_AddBoolToObject(r, "setup_mode", net.setup_mode);
    cJSON_AddBoolToObject(r, "ap_active", net.ap_active);
    cJSON_AddStringToObject(r, "ap_ssid", net.ap_ssid);
    cJSON_AddStringToObject(r, "ap_ip", net.ap_ip);
    cJSON_AddStringToObject(r, "ssid", net.ssid);
    cJSON_AddStringToObject(r, "ip", net.ip);
    cJSON_AddNumberToObject(r, "rssi", net.rssi);
    cJSON_AddNumberToObject(r, "sta_channel", net.channel);
    cJSON_AddNumberToObject(r, "net_reason", net.reason);
    uint8_t self[6];
    char selfmac[18];
    pwn_wifi_self_mac(self);
    mac_str(self, selfmac);
    cJSON_AddStringToObject(r, "self_mac", selfmac);

    cJSON *build = cJSON_AddObjectToObject(r, "build");
    cJSON_AddStringToObject(build, "version", PWN_VERSION);
    cJSON_AddNumberToObject(build, "cpu_mhz", CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ);
    cJSON_AddStringToObject(build, "flash", flash_speed());
    char ps[48];
    snprintf(ps, sizeof(ps), "%s %s", psram_mode(), psram_speed());
    cJSON_AddStringToObject(build, "psram", ps);
    cJSON_AddBoolToObject(build, "deauth", PWN_ENABLE_DEAUTH != 0);

    return send_json(req, r);
}

/* ---- tables ----------------------------------------------------------- */

static esp_err_t aps_get(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    pwn_ap_t *aps = big_calloc(PWN_MAX_APS, sizeof(pwn_ap_t));
    if (!aps) {
        return fail(req, "500 Internal Server Error", "out of memory");
    }
    int n = pwn_wifi_ap_snapshot(aps, PWN_MAX_APS);
    pwn_client_t *cls = big_calloc(PWN_MAX_CLIENTS, sizeof(pwn_client_t));
    int cn = cls ? pwn_wifi_client_snapshot(cls, PWN_MAX_CLIENTS) : 0;
    uint8_t self[6];
    pwn_wifi_self_mac(self);

    cJSON *root = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(root, "aps");
    for (int i = 0; i < n; i++) {
        cJSON *o = cJSON_CreateObject();
        char b[18];
        mac_str(aps[i].bssid, b);
        cJSON_AddStringToObject(o, "ssid", aps[i].ssid);
        cJSON_AddStringToObject(o, "bssid", b);
        cJSON_AddNumberToObject(o, "ch", aps[i].channel);
        cJSON_AddNumberToObject(o, "rssi", aps[i].rssi);
        cJSON_AddStringToObject(o, "sec", sec_name(aps[i].security));
        cJSON_AddBoolToObject(o, "wps", aps[i].wps);
        cJSON_AddBoolToObject(o, "pmf", aps[i].pmf);
        cJSON_AddBoolToObject(o, "hidden", aps[i].hidden);
        cJSON_AddBoolToObject(o, "hs", aps[i].has_handshake);
        cJSON_AddNumberToObject(o, "beacons", aps[i].beacons);
        int cc = 0;
        for (int j = 0; j < cn; j++) {
            if (memcmp(cls[j].bssid, aps[i].bssid, 6) == 0 &&
                memcmp(cls[j].mac, self, 6) != 0) {
                cc++;
            }
        }
        cJSON_AddNumberToObject(o, "clients", cc);
        cJSON_AddItemToArray(arr, o);
    }
    free(cls);
    free(aps);
    return send_json(req, root);
}

static esp_err_t clients_get(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    pwn_client_t *c = big_calloc(PWN_MAX_CLIENTS, sizeof(pwn_client_t));
    if (!c) {
        return fail(req, "500 Internal Server Error", "out of memory");
    }
    int n = pwn_wifi_client_snapshot(c, PWN_MAX_CLIENTS);
    uint8_t self[6];
    pwn_wifi_self_mac(self);

    cJSON *root = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(root, "clients");
    for (int i = 0; i < n; i++) {
        cJSON *o = cJSON_CreateObject();
        char mac[18], bssid[18];
        mac_str(c[i].mac, mac);
        mac_str(c[i].bssid, bssid);
        cJSON_AddStringToObject(o, "mac", mac);
        cJSON_AddStringToObject(o, "bssid", bssid);
        cJSON_AddNumberToObject(o, "rssi", c[i].rssi);
        cJSON_AddNumberToObject(o, "frames", c[i].frames);
        cJSON_AddStringToObject(o, "vendor", pwn_oui_vendor(c[i].mac));
        cJSON_AddBoolToObject(o, "randomized", c[i].randomized != 0);
        cJSON_AddNumberToObject(o, "first_seen_ms", c[i].first_seen_ms);
        cJSON_AddNumberToObject(o, "last_seen_ms", c[i].last_seen_ms);
        cJSON *probes = cJSON_AddArrayToObject(o, "probes");
        for (int k = 0; k < c[i].probe_count &&
                        k < (int)(sizeof(c[i].probes) / sizeof(c[i].probes[0])); k++) {
            cJSON_AddItemToArray(probes,
                                 cJSON_CreateString(c[i].probes[k]));
        }
        bool zero_bssid = (c[i].bssid[0] | c[i].bssid[1] | c[i].bssid[2] |
                           c[i].bssid[3] | c[i].bssid[4] | c[i].bssid[5]) == 0;
        bool self_bssid = memcmp(c[i].bssid, c[i].mac, 6) == 0;
        cJSON_AddBoolToObject(o, "self", memcmp(c[i].mac, self, 6) == 0);
        cJSON_AddBoolToObject(o, "has_ap", !zero_bssid && !self_bssid);
        cJSON_AddItemToArray(arr, o);
    }
    free(c);
    return send_json(req, root);
}

static void add_talker_array(cJSON *root)
{
    pwn_talker_t *t = big_calloc(PWN_TALKER_MAX, sizeof(*t));
    int n = t ? netmeta_talker_snapshot(t, PWN_TALKER_MAX) : 0;
    if (n > 1) {
        for (int i = 1; i < n; i++) {
            pwn_talker_t key = t[i];
            int j = i - 1;
            while (j >= 0 && t[j].bytes < key.bytes) {
                t[j + 1] = t[j];
                j--;
            }
            t[j + 1] = key;
        }
    }
    cJSON *arr = cJSON_AddArrayToObject(root, "talkers");
    for (int i = 0; i < n; i++) {
        cJSON *o = cJSON_CreateObject();
        char mac[18];
        mac_str(t[i].mac, mac);
        cJSON_AddStringToObject(o, "mac", mac);
        cJSON_AddStringToObject(o, "vendor", pwn_oui_vendor(t[i].mac));
        cJSON_AddStringToObject(o, "ip", t[i].ip);
        cJSON_AddNumberToObject(o, "frames", t[i].frames);
        cJSON_AddNumberToObject(o, "bytes", t[i].bytes);
        cJSON_AddNumberToObject(o, "first_seen_ms", t[i].first_seen_ms);
        cJSON_AddNumberToObject(o, "last_seen_ms", t[i].last_seen_ms);
        cJSON_AddItemToArray(arr, o);
    }
    free(t);
}

static void add_dns_array(cJSON *root)
{
    pwn_dns_entry_t *d = big_calloc(PWN_DNS_MAX, sizeof(*d));
    int n = d ? netmeta_dns_snapshot(d, PWN_DNS_MAX) : 0;
    cJSON *arr = cJSON_AddArrayToObject(root, "dns");
    for (int i = 0; i < n; i++) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "name", d[i].name);
        cJSON_AddNumberToObject(o, "qtype", d[i].qtype);
        cJSON_AddNumberToObject(o, "count", d[i].count);
        cJSON_AddNumberToObject(o, "first_seen_ms", d[i].first_seen_ms);
        cJSON_AddNumberToObject(o, "last_seen_ms", d[i].last_seen_ms);
        cJSON_AddItemToArray(arr, o);
    }
    free(d);
}

static void add_host_array(cJSON *root, const char *key, pwn_host_entry_t *h,
                           int n)
{
    cJSON *arr = cJSON_AddArrayToObject(root, key);
    for (int i = 0; i < n; i++) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "host", h[i].host);
        cJSON_AddNumberToObject(o, "count", h[i].count);
        cJSON_AddNumberToObject(o, "first_seen_ms", h[i].first_seen_ms);
        cJSON_AddNumberToObject(o, "last_seen_ms", h[i].last_seen_ms);
        cJSON_AddItemToArray(arr, o);
    }
}

static esp_err_t ble_get(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    pwn_ble_dev_t *d = big_calloc(PWN_BLE_MAX, sizeof(*d));
    if (!d) {
        return fail(req, "500 Internal Server Error", "out of memory");
    }
    int n = ble_snapshot(d, PWN_BLE_MAX);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "supported", ble_supported());
    cJSON_AddBoolToObject(root, "enabled", ble_enabled());
    cJSON_AddBoolToObject(root, "scanning", ble_scanning());
    cJSON_AddBoolToObject(root, "gated", ble_gated());
    cJSON_AddNumberToObject(root, "count", n);
    cJSON *arr = cJSON_AddArrayToObject(root, "devices");
    for (int i = 0; i < n; i++) {
        cJSON *o = cJSON_CreateObject();
        char addr[18];
        mac_str(d[i].addr, addr);
        cJSON_AddStringToObject(o, "addr", addr);
        cJSON_AddStringToObject(o, "addr_type",
                                ble_addr_type_name(d[i].addr_type));
        cJSON_AddBoolToObject(o, "randomized", d[i].addr_type != 0);
        cJSON_AddStringToObject(o, "name", d[i].name);
        cJSON_AddNumberToObject(o, "rssi", d[i].rssi);
        cJSON_AddNumberToObject(o, "count", d[i].count);
        cJSON_AddStringToObject(o, "services", d[i].services);
        cJSON_AddStringToObject(o, "beacon", d[i].beacon);
        cJSON_AddNumberToObject(o, "first_seen_ms", d[i].first_seen_ms);
        cJSON_AddNumberToObject(o, "last_seen_ms", d[i].last_seen_ms);
        cJSON_AddStringToObject(o, "vendor",
            d[i].addr_type == 0 ? pwn_oui_vendor(d[i].addr) : "randomized");
        cJSON_AddItemToArray(arr, o);
    }
    free(d);
    return send_json(req, root);
}

static esp_err_t ble_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char buf[BODY_MAX];
    cJSON *body = read_body(req, buf, sizeof(buf));
    if (!body) {
        return fail(req, "400 Bad Request", "invalid JSON");
    }
    cJSON *en = cJSON_GetObjectItem(body, "enabled");
    if (!en) {
        en = cJSON_GetObjectItem(body, "scan");
    }
    bool on = cJSON_IsTrue(en);
    cJSON_Delete(body);

    if (!ble_supported()) {
        return fail(req, "503 Service Unavailable",
                    "BLE scanner is not available in this build");
    }
    ble_set_enabled(on);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "ok", true);
    cJSON_AddBoolToObject(r, "supported", true);
    cJSON_AddBoolToObject(r, "enabled", ble_enabled());
    cJSON_AddBoolToObject(r, "scanning", ble_scanning());
    cJSON_AddBoolToObject(r, "gated", ble_gated());
    cJSON_AddStringToObject(r, "note",
        "passive scan only; no connections or writes");
    return send_json(req, r);
}

static esp_err_t hid_get(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    pwn_hid_payload_t *p = big_calloc(PWN_HID_MAX_PAYLOADS, sizeof(*p));
    if (!p) {
        return fail(req, "500 Internal Server Error", "out of memory");
    }
    int n = hid_list_payloads(p, PWN_HID_MAX_PAYLOADS);

    cJSON *root = cJSON_CreateObject();
    hid_status_fields(root);
    cJSON_AddStringToObject(root, "dir", PWN_HID_PAYLOAD_DIR);
    cJSON_AddNumberToObject(root, "max_payloads", PWN_HID_MAX_PAYLOADS);
    cJSON_AddStringToObject(root, "warning",
        "Authorized use only. HID mode types into the connected host and "
        "pauses the passive BLE scanner. Never run it against a device you "
        "do not own or have written permission to test.");
    cJSON *arr = cJSON_AddArrayToObject(root, "payloads");
    for (int i = 0; i < n; i++) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "name", p[i].name);
        cJSON_AddNumberToObject(o, "size", p[i].size);
        cJSON_AddItemToArray(arr, o);
    }
    free(p);
    return send_json(req, root);
}

static esp_err_t hid_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char buf[BODY_MAX];
    cJSON *body = read_body(req, buf, sizeof(buf));
    if (!body) {
        return fail(req, "400 Bad Request", "invalid JSON");
    }
    cJSON *act = cJSON_GetObjectItem(body, "action");
    cJSON *pay = cJSON_GetObjectItem(body, "payload");
    char action[16];
    char payload[PWN_HID_PAYLOAD_NAME_MAX];
    snprintf(action, sizeof(action), "%.*s", (int)sizeof(action) - 1,
             cJSON_IsString(act) ? act->valuestring : "");
    snprintf(payload, sizeof(payload), "%.*s", (int)sizeof(payload) - 1,
             cJSON_IsString(pay) ? pay->valuestring : "");

    if (!pwn_wifi_authorized()) {
        cJSON_Delete(body);
        return fail(req, "403 Forbidden",
                    "unlock active features with the authorization phrase first");
    }
    if (!strcmp(action, "stop")) {
        cJSON_Delete(body);
        hid_stop();
        pwn_wifi_event("HID: stopped from web UI");
        cJSON *r = cJSON_CreateObject();
        cJSON_AddBoolToObject(r, "ok", true);
        hid_status_fields(r);
        return send_json(req, r);
    }
    if (strcmp(action, "start") && strcmp(action, "run")) {
        cJSON_Delete(body);
        return fail(req, "400 Bad Request",
                    "action must be start, run, or stop");
    }
    if (!hid_supported()) {
        cJSON_Delete(body);
        return fail(req, "503 Service Unavailable",
                    "BLE HID is not available in this build");
    }
    if (payload[0] && !hid_select(payload)) {
        cJSON_Delete(body);
        return fail(req, "404 Not Found",
                    "payload not found (expected /sdcard/payloads/*.txt)");
    }

    bool ok = true;
    if (!strcmp(action, "start")) {
        ok = hid_start();
    } else {
        ok = hid_run(payload[0] ? payload : NULL);
    }
    cJSON_Delete(body);

    pwn_hid_status_t st;
    hid_status(&st);
    if (!ok) {
        return fail(req, "409 Conflict", st.error[0] ? st.error : "HID request failed");
    }
    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "ok", true);
    cJSON_AddStringToObject(r, "action", action);
    hid_status_fields(r);
    return send_json(req, r);
}

static esp_err_t hid_payload_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    if (!pwn_wifi_authorized()) {
        return fail(req, "403 Forbidden",
                    "unlock active features with the authorization phrase first");
    }
    char query[192];
    char name[PWN_HID_PAYLOAD_NAME_MAX];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
        httpd_query_key_value(query, "name", name, sizeof(name)) != ESP_OK) {
        return fail(req, "400 Bad Request", "missing payload name");
    }
    int len = req->content_len;
    if (len <= 0) {
        return fail(req, "400 Bad Request", "empty payload");
    }
    if (len > PWN_HID_PAYLOAD_MAX) {
        return fail(req, "413 Payload Too Large", "payload exceeds 16 KiB");
    }
    char *buf = heap_caps_malloc((size_t)len + 1,
                                 MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!buf) {
        buf = malloc((size_t)len + 1);
    }
    if (!buf) {
        return fail(req, "500 Internal Server Error", "out of memory");
    }
    int got = 0;
    while (got < len) {
        int r = httpd_req_recv(req, buf + got, len - got);
        if (r <= 0) {
            free(buf);
            return fail(req, "400 Bad Request", "upload interrupted");
        }
        got += r;
    }
    buf[got] = 0;
    char err[96] = "";
    bool ok = hid_write_payload(name, buf, (size_t)got, err, sizeof(err));
    free(buf);
    if (!ok) {
        return fail(req, "400 Bad Request", err[0] ? err : "cannot save payload");
    }
    pwn_wifi_event("HID: payload %s saved (%d bytes)", name, got);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "ok", true);
    cJSON_AddStringToObject(r, "name", name);
    cJSON_AddNumberToObject(r, "size", got);
    cJSON_AddStringToObject(r, "selected", name);
    return send_json(req, r);
}

static esp_err_t dns_get(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    pwn_netmeta_counts_t nm;
    netmeta_counts(&nm);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "total", nm.dns_total);
    cJSON_AddNumberToObject(root, "count", nm.dns_count);
    add_dns_array(root);
    return send_json(req, root);
}

static esp_err_t sni_get(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    pwn_netmeta_counts_t nm;
    netmeta_counts(&nm);
    pwn_host_entry_t *h = big_calloc(PWN_HOST_MAX, sizeof(*h));
    int n = h ? netmeta_sni_snapshot(h, PWN_HOST_MAX) : 0;
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "total", nm.sni_total);
    cJSON_AddNumberToObject(root, "count", nm.sni_count);
    add_host_array(root, "hosts", h, n);
    free(h);
    return send_json(req, root);
}

static esp_err_t network_get(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    pwn_netmeta_counts_t nm;
    netmeta_counts(&nm);
    cJSON *root = cJSON_CreateObject();
    cJSON *counts = cJSON_AddObjectToObject(root, "counts");
    cJSON_AddNumberToObject(counts, "dns_total", nm.dns_total);
    cJSON_AddNumberToObject(counts, "dns", nm.dns_count);
    cJSON_AddNumberToObject(counts, "sni_total", nm.sni_total);
    cJSON_AddNumberToObject(counts, "sni", nm.sni_count);
    cJSON_AddNumberToObject(counts, "http_total", nm.http_total);
    cJSON_AddNumberToObject(counts, "http", nm.http_count);
    cJSON_AddNumberToObject(counts, "talkers", nm.talker_count);
    add_dns_array(root);
    pwn_host_entry_t *h = big_calloc(PWN_HOST_MAX, sizeof(*h));
    int n = h ? netmeta_sni_snapshot(h, PWN_HOST_MAX) : 0;
    add_host_array(root, "sni", h, n);
    n = h ? netmeta_http_snapshot(h, PWN_HOST_MAX) : 0;
    add_host_array(root, "http", h, n);
    free(h);
    add_talker_array(root);
    return send_json(req, root);
}

static void add_watch_fields(cJSON *root)
{
    int count = 0;
    uint32_t hits = 0;
    uint32_t age = 0;
    char last[96] = "";
    watch_status(&count, &hits, last, sizeof(last), &age);
    cJSON_AddNumberToObject(root, "count", count);
    cJSON_AddNumberToObject(root, "hits", hits);
    cJSON_AddStringToObject(root, "last", last);
    cJSON_AddNumberToObject(root, "age_ms", age);
    cJSON_AddNumberToObject(root, "max", PWN_WATCH_MAX);
    pwn_watch_item_t *items = big_calloc(PWN_WATCH_MAX, sizeof(*items));
    int n = items ? watch_snapshot(items, PWN_WATCH_MAX) : 0;
    cJSON *arr = cJSON_AddArrayToObject(root, "items");
    for (int i = 0; i < n; i++) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "type", watch_type_name(items[i].type));
        cJSON_AddStringToObject(o, "value", items[i].value);
        cJSON_AddItemToArray(arr, o);
    }
    free(items);
}

static esp_err_t watch_get(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    cJSON *root = cJSON_CreateObject();
    add_watch_fields(root);
    return send_json(req, root);
}

static esp_err_t watch_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char buf[BODY_MAX];
    cJSON *body = read_body(req, buf, sizeof(buf));
    if (!body) {
        return fail(req, "400 Bad Request", "invalid JSON");
    }
    if (cJSON_IsTrue(cJSON_GetObjectItem(body, "clear"))) {
        int removed = watch_clear();
        cJSON_Delete(body);
        cJSON *r = cJSON_CreateObject();
        add_watch_fields(r);
        cJSON_AddNumberToObject(r, "removed", removed);
        return send_json(req, r);
    }

    const char *action = cJSON_GetStringValue(
        cJSON_GetObjectItem(body, "action"));
    const char *type = cJSON_GetStringValue(cJSON_GetObjectItem(body, "type"));
    const char *value = cJSON_GetStringValue(cJSON_GetObjectItem(body, "value"));
    if (!action || !type || !value) {
        cJSON_Delete(body);
        return fail(req, "400 Bad Request", "action, type and value are required");
    }

    if (strcasecmp(action, "add") == 0) {
        char err[96];
        esp_err_t e = watch_add(type, value, err, sizeof(err));
        cJSON_Delete(body);
        if (e != ESP_OK) {
            const char *status = "400 Bad Request";
            if (e == ESP_ERR_INVALID_STATE) {
                status = "409 Conflict";
            } else if (e == ESP_ERR_NO_MEM) {
                status = "409 Conflict";
            }
            return fail(req, status, err[0] ? err : esp_err_to_name(e));
        }
    } else if (strcasecmp(action, "remove") == 0) {
        bool ok = watch_remove(type, value);
        cJSON_Delete(body);
        if (!ok) {
            return fail(req, "404 Not Found", "watch entry not found");
        }
    } else {
        cJSON_Delete(body);
        return fail(req, "400 Bad Request", "action must be add, remove or clear");
    }

    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "ok", true);
    add_watch_fields(r);
    return send_json(req, r);
}

static esp_err_t hs_get(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    pwn_handshake_t *hs = big_calloc(PWN_MAX_HS, sizeof(pwn_handshake_t));
    if (!hs) {
        return fail(req, "500 Internal Server Error", "out of memory");
    }
    int n = capture_snapshot(hs, PWN_MAX_HS);

    cJSON *root = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(root, "hs");
    for (int i = 0; i < n; i++) {
        cJSON *o = cJSON_CreateObject();
        char bssid[18], sta[18];
        mac_str(hs[i].bssid, bssid);
        mac_str(hs[i].sta, sta);
        cJSON_AddStringToObject(o, "ssid", hs[i].ssid);
        cJSON_AddStringToObject(o, "bssid", bssid);
        cJSON_AddStringToObject(o, "sta", sta);
        cJSON_AddNumberToObject(o, "channel", hs[i].channel);
        cJSON_AddNumberToObject(o, "rssi", hs[i].rssi);
        cJSON_AddNumberToObject(o, "mask", hs[i].msg_mask);
        cJSON_AddNumberToObject(o, "frames", hs[i].nframes);
        cJSON_AddBoolToObject(o, "complete", hs[i].complete);
        cJSON_AddBoolToObject(o, "pmkid", hs[i].has_pmkid);
        if (hs[i].has_pmkid) {
            char pmkid_hex[33];
            for (int k = 0; k < 16; k++) {
                snprintf(pmkid_hex + k * 2, 3, "%02x", hs[i].pmkid[k]);
            }
            cJSON_AddStringToObject(o, "pmkid_hex", pmkid_hex);
        }
        cJSON_AddBoolToObject(o, "saved", hs[i].saved);
        cJSON_AddStringToObject(o, "file", hs[i].file);
        cJSON_AddItemToArray(arr, o);
    }
    free(hs);

    /* The live slot table is RAM-only.  List the PCAPs that survived on the
     * SD card so the dashboard still shows them after a reboot. */
    enum { HS_FILE_MAX = 128 };
    pwn_pcap_file_t *files = big_calloc(HS_FILE_MAX, sizeof(*files));
    int nf = files ? capture_list_files(files, HS_FILE_MAX) : 0;
    cJSON *fa = cJSON_AddArrayToObject(root, "files");
    for (int i = 0; i < nf; i++) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "name", files[i].name);
        cJSON_AddNumberToObject(o, "size", files[i].size);
        cJSON_AddItemToArray(fa, o);
    }
    free(files);
    return send_json(req, root);
}

/* ---- actions ---------------------------------------------------------- */

static esp_err_t scan_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    int found = pwn_wifi_scan_now();
    cJSON *r = cJSON_CreateObject();
    if (found < 0) {
        cJSON_AddStringToObject(r, "error", "scan failed");
        httpd_resp_set_status(req, "500 Internal Server Error");
    } else {
        cJSON_AddNumberToObject(r, "found", found);
    }
    return send_json(req, r);
}

static esp_err_t connect_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char buf[BODY_MAX];
    cJSON *body = read_body(req, buf, sizeof(buf));
    if (!body) {
        return fail(req, "400 Bad Request", "invalid JSON");
    }
    const char *ssid = cJSON_GetStringValue(cJSON_GetObjectItem(body, "ssid"));
    const char *pass = cJSON_GetStringValue(cJSON_GetObjectItem(body, "password"));
    cJSON *save = cJSON_GetObjectItem(body, "save");
    bool do_save = save ? cJSON_IsTrue(save) : true;

    if (!ssid || !ssid[0]) {
        cJSON_Delete(body);
        return fail(req, "400 Bad Request", "ssid required");
    }
    esp_err_t err = net_connect(ssid, pass, do_save);
    cJSON_Delete(body);

    if (err != ESP_OK) {
        return fail(req, "400 Bad Request", esp_err_to_name(err));
    }
    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "ok", true);
    cJSON_AddBoolToObject(r, "connected", net_connected());
    cJSON_AddBoolToObject(r, "connecting", true);
    cJSON_AddBoolToObject(r, "setup_mode", net_setup_active());
    return send_json(req, r);
}

static esp_err_t disconnect_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char buf[BODY_MAX];
    cJSON *body = read_body(req, buf, sizeof(buf));
    bool forget = body && cJSON_IsTrue(cJSON_GetObjectItem(body, "forget"));
    if (body) {
        cJSON_Delete(body);
    }
    net_disconnect(forget);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "ok", true);
    return send_json(req, r);
}

static bool phrase_matches(const char *phrase)
{
    if (!phrase) {
        return false;
    }
    while (*phrase && isspace((unsigned char)*phrase)) {
        phrase++;
    }
    size_t len = strlen(phrase);
    while (len > 0 && isspace((unsigned char)phrase[len - 1])) {
        len--;
    }
    size_t want = strlen(PWN_AUTH_PHRASE);
    return len == want && strncasecmp(phrase, PWN_AUTH_PHRASE, len) == 0;
}

static esp_err_t sd_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char buf[BODY_MAX];
    cJSON *body = read_body(req, buf, sizeof(buf));
    if (!body) {
        return fail(req, "400 Bad Request", "invalid JSON");
    }
    bool remount = cJSON_IsTrue(cJSON_GetObjectItem(body, "remount"));
    cJSON *prune_j = cJSON_GetObjectItem(body, "prune");
    int prune = prune_j ? prune_j->valueint : -1;
    cJSON_Delete(body);

    bool ok = capture_sd_ready();
    if (remount) {
        ok = capture_sd_remount();
    }
    int removed = 0;
    if (prune >= 0) {
        if (prune > 256) prune = 256;
        removed = capture_sd_prune(prune);
        ok = capture_sd_ready();
    }

    pwn_sd_info_t info;
    capture_sd_info(&info);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "sd", ok);
    cJSON_AddBoolToObject(r, "remounted", remount);
    cJSON_AddNumberToObject(r, "pruned", removed);
    cJSON_AddBoolToObject(r, "writable", info.writable);
    cJSON_AddNumberToObject(r, "total", info.total_bytes);
    cJSON_AddNumberToObject(r, "free", info.free_bytes);
    return send_json(req, r);
}

static esp_err_t auth_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char buf[BODY_MAX];
    cJSON *body = read_body(req, buf, sizeof(buf));
    if (!body) {
        return fail(req, "400 Bad Request", "invalid JSON");
    }
    if (cJSON_IsTrue(cJSON_GetObjectItem(body, "off"))) {
        pwn_wifi_set_authorized(false);
        pwn_hunt_stop();
        cJSON_Delete(body);
        cJSON *r = cJSON_CreateObject();
        cJSON_AddBoolToObject(r, "authorized", false);
        return send_json(req, r);
    }
    const char *phrase = cJSON_GetStringValue(cJSON_GetObjectItem(body, "phrase"));
    bool ok = phrase_matches(phrase);
    pwn_wifi_set_authorized(ok);
    cJSON_Delete(body);

    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "authorized", ok);
    if (!ok) {
        httpd_resp_set_status(req, "403 Forbidden");
    }
    return send_json(req, r);
}

static esp_err_t attacks_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char buf[BODY_MAX];
    cJSON *body = read_body(req, buf, sizeof(buf));
    if (!body) {
        return fail(req, "400 Bad Request", "invalid JSON");
    }
    cJSON *auto_j = cJSON_GetObjectItem(body, "auto");
    if (!pwn_wifi_authorized()) {
        cJSON_Delete(body);
        return fail(req, "403 Forbidden", "unlock attacks first");
    }
    pwn_wifi_set_auto_deauth(cJSON_IsTrue(auto_j));
    cJSON_Delete(body);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "auto", pwn_wifi_auto_deauth());
    return send_json(req, r);
}

static esp_err_t deauth_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char buf[BODY_MAX];
    cJSON *body = read_body(req, buf, sizeof(buf));
    if (!body) {
        return fail(req, "400 Bad Request", "invalid JSON");
    }
    if (cJSON_IsTrue(cJSON_GetObjectItem(body, "stop"))) {
        pwn_wifi_deauth_stop();
        cJSON_Delete(body);
        cJSON *r = cJSON_CreateObject();
        cJSON_AddBoolToObject(r, "stopped", true);
        cJSON_AddBoolToObject(r, "active", false);
        return send_json(req, r);
    }
    if (!pwn_wifi_authorized()) {
        cJSON_Delete(body);
        return fail(req, "403 Forbidden", "unlock attacks first");
    }

    uint8_t bssid[6];
    uint8_t sta[6];
    bool have_sta = parse_mac(cJSON_GetStringValue(
                        cJSON_GetObjectItem(body, "sta")), sta);
    bool all = cJSON_IsTrue(cJSON_GetObjectItem(body, "all"));
    if (!parse_mac(cJSON_GetStringValue(cJSON_GetObjectItem(body, "bssid")),
                   bssid)) {
        cJSON_Delete(body);
        return fail(req, "400 Bad Request", "bssid required");
    }
    cJSON *count_j = cJSON_GetObjectItem(body, "count");
    int count = count_j ? count_j->valueint : 3;
    cJSON *reason_j = cJSON_GetObjectItem(body, "reason");
    int reason = reason_j ? reason_j->valueint : 1;
    cJSON *duration_j = cJSON_GetObjectItem(body, "duration_ms");
    int duration_ms = duration_j ? duration_j->valueint : 8000;
    cJSON *interval_j = cJSON_GetObjectItem(body, "interval_ms");
    int interval_ms = interval_j ? interval_j->valueint : 50;
    cJSON_Delete(body);
    if (count < 1) count = 1;
    if (count > 16) count = 16;
    if (reason < 1 || reason > 9) reason = 1;
    if (duration_ms < 0) duration_ms = 0;
    if (duration_ms > 60000) duration_ms = 60000;
    if (interval_ms < 20) interval_ms = 20;
    if (interval_ms > 1000) interval_ms = 1000;

    uint8_t self[6];
    pwn_wifi_self_mac(self);
    if ((bssid[0] | bssid[1] | bssid[2] | bssid[3] | bssid[4] | bssid[5]) == 0) {
        return fail(req, "400 Bad Request", "invalid bssid");
    }
    if (have_sta && memcmp(sta, self, 6) == 0) {
        return fail(req, "400 Bad Request", "refusing to deauth this device");
    }

    const pwn_wifi_stats_t *st = pwn_wifi_stats();
    pwn_net_status_t net;
    net_get_status(&net);

    /* Single radio: while associated we are pinned to the AP channel. */
    pwn_ap_t *aps = big_calloc(PWN_MAX_APS, sizeof(pwn_ap_t));
    int n = aps ? pwn_wifi_ap_snapshot(aps, PWN_MAX_APS) : 0;
    uint8_t target_ch = 0;
    bool target_pmf = false;
    for (int i = 0; i < n; i++) {
        if (memcmp(aps[i].bssid, bssid, 6) == 0) {
            target_ch = aps[i].channel;
            target_pmf = aps[i].pmf;
            break;
        }
    }
    free(aps);

    if (target_ch && target_ch != st->channel) {
        if (net.connected) {
            return fail(req, "409 Conflict",
                        "single radio is pinned to your AP channel; "
                        "pick a target on the current channel");
        }
        pwn_wifi_force_channel(target_ch);
    }

    const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    bool target_is_self_ap = net.connected &&
                             memcmp(net.bssid, bssid, 6) == 0;

    if (duration_ms > 0) {
        int targets = have_sta ? 1 : 0;
        if (all && !have_sta) {
            pwn_client_t *cl = big_calloc(PWN_MAX_CLIENTS, sizeof(pwn_client_t));
            int cn = cl ? pwn_wifi_client_snapshot(cl, PWN_MAX_CLIENTS) : 0;
            for (int i = 0; i < cn; i++) {
                if (memcmp(cl[i].bssid, bssid, 6) == 0 &&
                    memcmp(cl[i].mac, self, 6) != 0) {
                    targets++;
                }
            }
            free(cl);
            if (targets == 0 && target_is_self_ap) {
                cJSON *r = cJSON_CreateObject();
                cJSON_AddBoolToObject(r, "started", false);
                cJSON_AddNumberToObject(r, "targets", 0);
                cJSON_AddStringToObject(r, "tx_error",
                    "no other clients seen; broadcast skipped to keep this link up");
                return send_json(req, r);
            }
        }

        pwn_deauth_job_t job = {0};
        memcpy(job.bssid, bssid, 6);
        memcpy(job.sta, sta, 6);
        job.have_sta = have_sta;
        job.all = all;
        job.target_is_self_ap = target_is_self_ap;
        job.duration_ms = (uint32_t)duration_ms;
        job.interval_ms = (uint16_t)interval_ms;
        job.reason = (uint8_t)reason;

        esp_err_t err = pwn_wifi_deauth_start(&job);
        if (err != ESP_OK) {
            return fail(req, "503 Service Unavailable",
                        "deauth worker is not available");
        }

        cJSON *r = cJSON_CreateObject();
        cJSON_AddBoolToObject(r, "started", true);
        cJSON_AddNumberToObject(r, "targets", targets);
        cJSON_AddNumberToObject(r, "duration_ms", duration_ms);
        cJSON_AddNumberToObject(r, "interval_ms", interval_ms);
        cJSON_AddNumberToObject(r, "reason", reason);
        cJSON_AddBoolToObject(r, "pmf", target_pmf);
        const char *warn = NULL;
        if (target_pmf && !all && !have_sta && target_is_self_ap) {
            warn = "target advertises PMF; broadcast may be ignored and can disconnect this device";
        } else if (target_pmf) {
            warn = "target advertises PMF; deauth may be ignored by clients";
        } else if (!all && !have_sta && target_is_self_ap) {
            warn = "broadcast to the current AP may disconnect this device";
        }
        if (warn) {
            cJSON_AddStringToObject(r, "warning", warn);
        }
        return send_json(req, r);
    }

    int sent = 0;
    int targets = 0;
    esp_err_t last_err = ESP_OK;
    pwn_wifi_clear_last_tx();

    if (have_sta) {
        targets = 1;
        for (int i = 0; i < count; i++) {
            esp_err_t err = pwn_wifi_deauth(bssid, sta, (uint8_t)reason);
            if (err == ESP_OK) {
                sent++;
            } else {
                last_err = err;
            }
        }
    } else if (all) {
        pwn_client_t *cl = big_calloc(PWN_MAX_CLIENTS, sizeof(pwn_client_t));
        int cn = cl ? pwn_wifi_client_snapshot(cl, PWN_MAX_CLIENTS) : 0;
        for (int i = 0; i < cn; i++) {
            if (memcmp(cl[i].bssid, bssid, 6) != 0) {
                continue;
            }
            if (memcmp(cl[i].mac, self, 6) == 0) {
                continue;   /* don't kick our own STA */
            }
            targets++;
            for (int k = 0; k < count; k++) {
                esp_err_t err = pwn_wifi_deauth(bssid, cl[i].mac, (uint8_t)reason);
                if (err == ESP_OK) {
                    sent++;
                } else {
                    last_err = err;
                }
            }
            vTaskDelay(pdMS_TO_TICKS(2));
        }
        free(cl);
        /* Broadcast is a fallback for unknown clients.  Do not use it on the
         * AP we are associated with: that would deauth this device itself. */
        if (targets == 0 && !target_is_self_ap) {
            for (int i = 0; i < count; i++) {
                esp_err_t err = pwn_wifi_deauth(bssid, bcast, (uint8_t)reason);
                if (err == ESP_OK) {
                    sent++;
                } else {
                    last_err = err;
                }
            }
        }
    } else {
        for (int i = 0; i < count; i++) {
            esp_err_t err = pwn_wifi_deauth(bssid, bcast, (uint8_t)reason);
            if (err == ESP_OK) {
                sent++;
            } else {
                last_err = err;
            }
            vTaskDelay(pdMS_TO_TICKS(2));
        }
    }

    /* The driver reports the actual source/destination asynchronously. */
    vTaskDelay(pdMS_TO_TICKS(30));
    pwn_wifi_tx_t tx;
    pwn_wifi_last_tx(&tx);

    ESP_LOGW(TAG, "deauth %02x:%02x:%02x:%02x:%02x:%02x: sent %d/%d (%s)",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], sent,
             targets, esp_err_to_name(last_err));

    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "sent", sent);
    cJSON_AddNumberToObject(r, "targets", targets);
    cJSON_AddNumberToObject(r, "reason", reason);
    cJSON_AddBoolToObject(r, "pmf", target_pmf);
    if (sent == 0) {
        if (all && targets == 0 && target_is_self_ap) {
            cJSON_AddStringToObject(r, "tx_error",
                "no other clients seen; broadcast skipped to keep this link up");
        } else {
            cJSON_AddStringToObject(r, "tx_error", esp_err_to_name(last_err));
        }
    }
    const char *warn = NULL;
    if (target_pmf) {
        warn = "target advertises PMF; deauth may be ignored by clients";
    } else if (!all && !have_sta && target_is_self_ap) {
        warn = "broadcast to the current AP may disconnect this device";
    }
    if (warn) {
        cJSON_AddStringToObject(r, "warning", warn);
    }
    if (tx.valid) {
        char src[18], dst[18];
        mac_str(tx.src, src);
        mac_str(tx.dst, dst);
        cJSON_AddStringToObject(r, "tx_src", src);
        cJSON_AddStringToObject(r, "tx_dst", dst);
        cJSON_AddNumberToObject(r, "tx_status", tx.status);
        cJSON_AddNumberToObject(r, "tx_len", tx.len);
        if (tx.raw_len) {
            char hex[sizeof(tx.raw) * 3 + 1];
            size_t p = 0;
            for (unsigned i = 0; i < tx.raw_len && p + 3 < sizeof(hex); i++) {
                p += snprintf(hex + p, sizeof(hex) - p, "%02x", tx.raw[i]);
            }
            cJSON_AddStringToObject(r, "tx_raw", hex);
        }
    }
    return send_json(req, r);
}

static void hunt_add_status(cJSON *r, const pwn_hunt_status_t *h)
{
    char bssid[18] = "";
    char sta[18] = "";
    if ((h->bssid[0] | h->bssid[1] | h->bssid[2] |
         h->bssid[3] | h->bssid[4] | h->bssid[5]) != 0) {
        mac_str(h->bssid, bssid);
    }
    if (h->have_sta &&
        (h->sta[0] | h->sta[1] | h->sta[2] |
         h->sta[3] | h->sta[4] | h->sta[5]) != 0) {
        mac_str(h->sta, sta);
    }
    cJSON_AddBoolToObject(r, "hunt_active", h->active);
    cJSON_AddStringToObject(r, "hunt_result", pwn_hunt_state_name(h->state));
    cJSON_AddStringToObject(r, "bssid", bssid);
    cJSON_AddStringToObject(r, "sta", sta);
    cJSON_AddNumberToObject(r, "duration_ms", h->duration_ms);
    cJSON_AddNumberToObject(r, "elapsed_ms", h->elapsed_ms);
    cJSON_AddBoolToObject(r, "pmf", h->pmf);
    cJSON_AddBoolToObject(r, "saved", h->saved);
    cJSON_AddStringToObject(r, "file", h->file);
    cJSON_AddStringToObject(r, "message", h->message);
}

static esp_err_t hunt_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char buf[BODY_MAX];
    cJSON *body = read_body(req, buf, sizeof(buf));
    if (!body) {
        return fail(req, "400 Bad Request", "invalid JSON");
    }
    if (cJSON_IsTrue(cJSON_GetObjectItem(body, "stop"))) {
        pwn_hunt_stop();
        cJSON_Delete(body);
        pwn_hunt_status_t h;
        pwn_hunt_status(&h);
        cJSON *r = cJSON_CreateObject();
        cJSON_AddBoolToObject(r, "stopped", true);
        cJSON_AddBoolToObject(r, "hunt_active", h.active);
        cJSON_AddStringToObject(r, "hunt_result",
                                pwn_hunt_state_name(h.state));
        return send_json(req, r);
    }
    if (!pwn_wifi_authorized()) {
        cJSON_Delete(body);
        return fail(req, "403 Forbidden", "unlock attacks first");
    }

    uint8_t bssid[6];
    uint8_t sta[6];
    bool have_sta = false;
    if (!parse_mac(cJSON_GetStringValue(cJSON_GetObjectItem(body, "bssid")),
                   bssid)) {
        cJSON_Delete(body);
        return fail(req, "400 Bad Request", "bssid required");
    }
    cJSON *sta_j = cJSON_GetObjectItem(body, "sta");
    if (sta_j && cJSON_IsString(sta_j)) {
        if (!parse_mac(sta_j->valuestring, sta)) {
            cJSON_Delete(body);
            return fail(req, "400 Bad Request", "invalid sta");
        }
        have_sta = true;
    }
    cJSON *duration_j = cJSON_GetObjectItem(body, "duration_ms");
    int duration_ms = duration_j ? duration_j->valueint : 0;
    cJSON_Delete(body);
    if (duration_ms < 0) {
        duration_ms = 0;
    }
    if (duration_ms > PWN_HUNT_MAX_MS) {
        duration_ms = PWN_HUNT_MAX_MS;
    }

    char err[96] = "";
    esp_err_t e = pwn_hunt_start(bssid, have_sta ? sta : NULL,
                                 (uint32_t)duration_ms, err, sizeof(err));
    if (e != ESP_OK) {
        const char *status = "500 Internal Server Error";
        if (e == ESP_ERR_INVALID_ARG) {
            status = "400 Bad Request";
        } else if (e == ESP_ERR_NOT_FOUND) {
            status = "404 Not Found";
        } else if (e == ESP_ERR_INVALID_STATE) {
            status = "409 Conflict";
        } else if (e == ESP_ERR_NO_MEM) {
            status = "503 Service Unavailable";
        }
        return fail(req, status, err[0] ? err : esp_err_to_name(e));
    }

    pwn_hunt_status_t h;
    pwn_hunt_status(&h);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "started", true);
    hunt_add_status(r, &h);
    if (h.pmf) {
        cJSON_AddStringToObject(r, "warning",
            "target advertises PMF; deauth may be ignored and the hunt may time out");
    }
    ESP_LOGW(TAG, "hunt started for %02x:%02x:%02x:%02x:%02x:%02x%s for %ums",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
             have_sta ? " (single station)" : "", (unsigned)h.duration_ms);
    return send_json(req, r);
}

static esp_err_t hop_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char buf[BODY_MAX];
    cJSON *body = read_body(req, buf, sizeof(buf));
    if (!body) {
        return fail(req, "400 Bad Request", "invalid JSON");
    }
    cJSON *ch_j = cJSON_GetObjectItem(body, "channel");
    int ch = ch_j ? ch_j->valueint : 0;
    cJSON_Delete(body);

    pwn_net_status_t net;
    net_get_status(&net);
    if (net.connected) {
        return fail(req, "409 Conflict",
                    "disconnect WiFi before changing channel");
    }
    if (ch <= 0 || (ch > 14 && ch < 36) || ch > 165) {
        return fail(req, "400 Bad Request", "invalid channel");
    }
    esp_err_t err = pwn_wifi_force_channel((uint8_t)ch);
    if (err != ESP_OK) {
        return fail(req, "500 Internal Server Error", esp_err_to_name(err));
    }
    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "channel", ch);
    return send_json(req, r);
}

static esp_err_t hop_ap_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char buf[BODY_MAX];
    cJSON *body = read_body(req, buf, sizeof(buf));
    if (!body) {
        return fail(req, "400 Bad Request", "invalid JSON");
    }
    uint8_t bssid[6];
    bool ok = parse_mac(cJSON_GetStringValue(cJSON_GetObjectItem(body, "bssid")),
                        bssid);
    cJSON_Delete(body);
    if (!ok) {
        return fail(req, "400 Bad Request", "bssid required");
    }

    pwn_net_status_t net;
    net_get_status(&net);
    if (net.connected) {
        return fail(req, "409 Conflict",
                    "disconnect WiFi before changing channel");
    }

    pwn_ap_t *aps = big_calloc(PWN_MAX_APS, sizeof(pwn_ap_t));
    int n = aps ? pwn_wifi_ap_snapshot(aps, PWN_MAX_APS) : 0;
    uint8_t ch = 0;
    for (int i = 0; i < n; i++) {
        if (memcmp(aps[i].bssid, bssid, 6) == 0) {
            ch = aps[i].channel;
            break;
        }
    }
    free(aps);
    if (!ch) {
        return fail(req, "404 Not Found", "AP not in table");
    }
    esp_err_t err = pwn_wifi_force_channel(ch);
    if (err != ESP_OK) {
        return fail(req, "500 Internal Server Error", esp_err_to_name(err));
    }
    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "channel", ch);
    return send_json(req, r);
}

static esp_err_t pause_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char buf[BODY_MAX];
    cJSON *body = read_body(req, buf, sizeof(buf));
    bool paused = body && cJSON_IsTrue(cJSON_GetObjectItem(body, "paused"));
    if (body) {
        cJSON_Delete(body);
    }
    pet_set_paused(paused);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "paused", paused);
    return send_json(req, r);
}

static esp_err_t strategy_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char buf[BODY_MAX];
    cJSON *body = read_body(req, buf, sizeof(buf));
    if (!body) {
        return fail(req, "400 Bad Request", "invalid JSON");
    }
    cJSON *a = cJSON_GetObjectItem(body, "action");
    int action = a ? a->valueint : -1;
    cJSON_Delete(body);
    pet_set_action(action);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "action", pet_action_override());
    return send_json(req, r);
}

static esp_err_t brightness_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char buf[BODY_MAX];
    cJSON *body = read_body(req, buf, sizeof(buf));
    if (!body) {
        return fail(req, "400 Bad Request", "invalid JSON");
    }
    cJSON *p = cJSON_GetObjectItem(body, "percent");
    int percent = p ? p->valueint : 100;
    cJSON_Delete(body);
    if (percent < 1) percent = 1;
    if (percent > 100) percent = 100;
    bsp_display_brightness_set(percent);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "percent", percent);
    return send_json(req, r);
}

static esp_err_t autoconnect_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char buf[BODY_MAX];
    cJSON *body = read_body(req, buf, sizeof(buf));
    if (!body) {
        return fail(req, "400 Bad Request", "invalid JSON");
    }
    bool on = cJSON_IsTrue(cJSON_GetObjectItem(body, "on"));
    cJSON_Delete(body);
    net_set_autoconnect(on);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "autoconnect", net_get_autoconnect());
    return send_json(req, r);
}

static esp_err_t reset_brain_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    pet_reset_brain();
    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "ok", true);
    return send_json(req, r);
}

static esp_err_t reboot_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "ok", true);
    send_json(req, r);
    vTaskDelay(pdMS_TO_TICKS(400));
    esp_restart();
    return ESP_OK;
}

/* ---- pcap download ---------------------------------------------------- */

static bool safe_name(const char *s)
{
    if (!s || !s[0]) {
        return false;
    }
    for (const char *p = s; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' ||
              *p == '.')) {
            return false;
        }
    }
    return strstr(s, "..") == NULL;
}


static esp_err_t pcap_delete_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char buf[BODY_MAX];
    cJSON *body = read_body(req, buf, sizeof(buf));
    if (!body) {
        return fail(req, "400 Bad Request", "invalid JSON");
    }
    const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(body, "name"));
    if (!name || !name[0] || strstr(name, "..") || strchr(name, '/') || strchr(name, '\\')) {
        cJSON_Delete(body);
        return fail(req, "400 Bad Request", "invalid filename");
    }
    char path[160];
    snprintf(path, sizeof(path), PWN_HS_DIR "/%s", name);
    int rc = unlink(path);
    char meta[176];
    snprintf(meta, sizeof(meta), "%s.json", path);
    unlink(meta);
    cJSON_Delete(body);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "ok", rc == 0);
    if (rc != 0) {
        cJSON_AddStringToObject(r, "error", "delete failed");
        httpd_resp_set_status(req, "404 Not Found");
    }
    return send_json(req, r);
}

/* Serve the JSON sidecar for a saved PCAP. Accepts either the PCAP basename
 * or the ".json" name. */
static esp_err_t hs_meta_get(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char q[128];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) != ESP_OK) {
        return fail(req, "400 Bad Request", "missing file");
    }
    char name[96];
    if (httpd_query_key_value(q, "name", name, sizeof(name)) != ESP_OK ||
        !safe_name(name)) {
        return fail(req, "400 Bad Request", "invalid file name");
    }
    size_t len = strlen(name);
    if (len > 5 && strcasecmp(name + len - 5, ".json") == 0) {
        name[len - 5] = 0;
        len -= 5;
    }
    if (len == 0) {
        return fail(req, "400 Bad Request", "invalid file name");
    }

    char path[160];
    snprintf(path, sizeof(path), PWN_HS_DIR "/%s.json", name);

    if (!capture_bus_lock(portMAX_DELAY)) {
        return fail(req, "503 Service Unavailable", "display busy");
    }
    struct stat stt;
    if (stat(path, &stt) != 0 || !S_ISREG(stt.st_mode) ||
        stt.st_size <= 0 || stt.st_size > 8192) {
        capture_bus_unlock();
        return fail(req, "404 Not Found", "no such sidecar");
    }
    char *buf = malloc((size_t)stt.st_size + 1);
    if (!buf) {
        capture_bus_unlock();
        return fail(req, "500 Internal Server Error", "out of memory");
    }
    FILE *f = fopen(path, "rb");
    if (!f) {
        free(buf);
        capture_bus_unlock();
        return fail(req, "500 Internal Server Error", "open failed");
    }
    size_t got = fread(buf, 1, (size_t)stt.st_size, f);
    fclose(f);
    capture_bus_unlock();
    if (got != (size_t)stt.st_size) {
        free(buf);
        return fail(req, "500 Internal Server Error", "read failed");
    }
    buf[got] = 0;

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    char disp[128];
    snprintf(disp, sizeof(disp), "attachment; filename=\"%s.json\"", name);
    httpd_resp_set_hdr(req, "Content-Disposition", disp);
    esp_err_t err = httpd_resp_send(req, buf, got);
    free(buf);
    return err;
}

static esp_err_t pcap_get(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    char q[128];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) != ESP_OK) {
        return fail(req, "400 Bad Request", "missing file");
    }
    char name[96];
    if (httpd_query_key_value(q, "name", name, sizeof(name)) != ESP_OK ||
        !safe_name(name)) {
        return fail(req, "400 Bad Request", "invalid file name");
    }

    char path[192];
    snprintf(path, sizeof(path), PWN_HS_DIR "/%s", name);

    /* stat/open/read all hit the SD card, which shares the SPI bus with the
     * LCD. Serialize against display flushes. */
    if (!capture_bus_lock(portMAX_DELAY)) {
        return fail(req, "503 Service Unavailable", "display busy");
    }
    struct stat stt;
    if (stat(path, &stt) != 0 || !S_ISREG(stt.st_mode)) {
        capture_bus_unlock();
        return fail(req, "404 Not Found", "no such capture");
    }
    FILE *f = fopen(path, "rb");
    if (!f) {
        capture_bus_unlock();
        return fail(req, "500 Internal Server Error", "open failed");
    }

    httpd_resp_set_type(req, "application/vnd.tcpdump.pcap");
    char disp[128];
    snprintf(disp, sizeof(disp), "attachment; filename=\"%s\"", name);
    httpd_resp_set_hdr(req, "Content-Disposition", disp);

    char *chunk = malloc(2048);
    if (!chunk) {
        fclose(f);
        capture_bus_unlock();
        return fail(req, "500 Internal Server Error", "out of memory");
    }
    size_t n;
    esp_err_t err = ESP_OK;
    for (;;) {
        n = fread(chunk, 1, 2048, f);
        if (n == 0) {
            fclose(f);
            capture_bus_unlock();
            break;
        }
        /* Do not hold the bus lock (and freeze the UI) while the socket
         * may block on a slow client. */
        capture_bus_unlock();
        err = httpd_resp_send_chunk(req, chunk, n);
        if (err != ESP_OK) {
            if (capture_bus_lock(portMAX_DELAY)) {
                fclose(f);
                capture_bus_unlock();
            } else {
                fclose(f);
            }
            break;
        }
        if (!capture_bus_lock(portMAX_DELAY)) {
            err = ESP_FAIL;
            fclose(f);
            break;
        }
    }
    free(chunk);
    if (err == ESP_OK) {
        httpd_resp_send_chunk(req, NULL, 0);
    }
    return err;
}

/* ---- server ----------------------------------------------------------- */



#define OTA_MANIFEST_MAX  4096
#define OTA_MIN_IMAGE     (64 * 1024)
#define OTA_SD_RESERVE    (256 * 1024)

static portMUX_TYPE s_ota_mux = portMUX_INITIALIZER_UNLOCKED;
static ota_state_t s_ota_state = OTA_ST_IDLE;
static int s_ota_progress;
static char s_ota_error[OTA_ERR_MAX];
static volatile bool s_github_ota_busy;

static const char *ota_state_name(ota_state_t st)
{
    switch (st) {
    case OTA_ST_DOWNLOADING: return "downloading";
    case OTA_ST_VERIFYING:   return "verifying";
    case OTA_ST_FLASHING:    return "flashing";
    case OTA_ST_ERROR:       return "error";
    default:                 return "idle";
    }
}

static void ota_str_copy(char *dst, size_t dstsz, const char *src)
{
    if (!dst || dstsz == 0) {
        return;
    }
    if (!src) {
        src = "";
    }
    size_t n = strlen(src);
    if (n >= dstsz) {
        n = dstsz - 1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void ota_state_set(ota_state_t st, const char *err)
{
    taskENTER_CRITICAL(&s_ota_mux);
    s_ota_state = st;
    if (err && err[0]) {
        ota_str_copy(s_ota_error, sizeof(s_ota_error), err);
    } else {
        s_ota_error[0] = '\0';
    }
    taskEXIT_CRITICAL(&s_ota_mux);
}

static void ota_progress_set(int progress)
{
    if (progress < 0) {
        progress = 0;
    } else if (progress > 100) {
        progress = 100;
    }
    taskENTER_CRITICAL(&s_ota_mux);
    s_ota_progress = progress;
    taskEXIT_CRITICAL(&s_ota_mux);
}

static void ota_status_snapshot(ota_state_t *st, int *progress,
                                char *err, size_t errsz)
{
    taskENTER_CRITICAL(&s_ota_mux);
    *st = s_ota_state;
    *progress = s_ota_progress;
    ota_str_copy(err, errsz, s_ota_error);
    taskEXIT_CRITICAL(&s_ota_mux);
}

static void ota_fail(const char *fmt, ...)
{
    char msg[OTA_ERR_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    ESP_LOGE(TAG, "GitHub OTA failed: %s", msg);
    ota_state_set(OTA_ST_ERROR, msg);
    s_github_ota_busy = false;
}

static bool ota_sync_time(void)
{
    static bool started;
    if (!started) {
        esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
        esp_sntp_setservername(0, "pool.ntp.org");
        esp_sntp_init();
        started = true;
    }
    for (int i = 0; i < 24; i++) {
        time_t now = time(NULL);
        if (now > 1700000000) {
            return true;
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    return false;
}

/* ---- verified download ------------------------------------------------ */

typedef enum {
    OTA_DL_MANIFEST = 0,
    OTA_DL_IMAGE,
} ota_dl_kind_t;

typedef struct {
    ota_dl_kind_t kind;
    char *mem;
    size_t mem_len;
    size_t mem_cap;
    int64_t total;
    char location[512];
    char err[OTA_ERR_MAX];
} ota_dl_t;

static void ota_dl_error(ota_dl_t *dl, const char *fmt, ...)
{
    if (!dl || dl->err[0]) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(dl->err, sizeof(dl->err), fmt, ap);
    va_end(ap);
}

static esp_err_t ota_http_event(esp_http_client_event_t *evt)
{
    ota_dl_t *dl = (ota_dl_t *)evt->user_data;
    if (dl && evt->event_id == HTTP_EVENT_ON_HEADER &&
        evt->header_key && evt->header_value &&
        strcasecmp(evt->header_key, "Location") == 0) {
        ota_str_copy(dl->location, sizeof(dl->location), evt->header_value);
    }
    return ESP_OK;
}

static esp_http_client_handle_t ota_http_init(const char *url, ota_dl_t *dl)
{
    esp_http_client_config_t cfg = {
        .url = url,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 30000,
        .keep_alive_enable = false,
        .buffer_size = 4096,
        .buffer_size_tx = 1024,
        .event_handler = ota_http_event,
        .user_data = dl,
    };
    return esp_http_client_init(&cfg);
}

/* Open a GET request and follow redirects manually so the caller controls
 * streaming and can abort without buffering the image in RAM. */
static esp_err_t ota_http_open(esp_http_client_handle_t client, ota_dl_t *dl)
{
    for (int hop = 0; hop < 5; hop++) {
        dl->location[0] = '\0';
        esp_err_t err = esp_http_client_open(client, 0);
        if (err != ESP_OK) {
            ota_dl_error(dl, "connect failed: %s", esp_err_to_name(err));
            return err;
        }
        int64_t len = esp_http_client_fetch_headers(client);
        if (len < 0) {
            ota_dl_error(dl, "header read failed");
            esp_http_client_close(client);
            return ESP_FAIL;
        }
        dl->total = len;
        int status = esp_http_client_get_status_code(client);
        if (status == 200) {
            return ESP_OK;
        }
        if ((status == 301 || status == 302 || status == 303 ||
             status == 307 || status == 308) && dl->location[0]) {
            ESP_LOGW(TAG, "GitHub OTA: HTTP %d redirect -> %s",
                     status, dl->location);
            esp_http_client_close(client);
            if (esp_http_client_set_url(client, dl->location) != ESP_OK) {
                ota_dl_error(dl, "invalid redirect URL");
                return ESP_FAIL;
            }
            continue;
        }
        ota_dl_error(dl, "HTTP status %d", status);
        esp_http_client_close(client);
        return ESP_FAIL;
    }
    ota_dl_error(dl, "too many redirects");
    return ESP_FAIL;
}

static bool ota_valid_sha256(const char *s)
{
    if (!s || strlen(s) != 64) {
        return false;
    }
    for (int i = 0; i < 64; i++) {
        if (!isxdigit((unsigned char)s[i])) {
            return false;
        }
    }
    return true;
}

static bool ota_valid_filename(const char *s)
{
    if (!s) {
        return false;
    }
    size_t len = strlen(s);
    if (len < 5 || len > 63 || strstr(s, "..")) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!(isalnum((unsigned char)c) || c == '.' || c == '_' || c == '-')) {
            return false;
        }
    }
    const char *dot = strrchr(s, '.');
    return dot && strcasecmp(dot, ".bin") == 0;
}

static void ota_hex_encode(const uint8_t *in, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static esp_err_t ota_fetch_manifest(char *sha_out, size_t sha_sz,
                                    char *file_out, size_t file_sz,
                                    char *err, size_t errsz)
{
    ota_dl_t dl = {0};
    dl.kind = OTA_DL_MANIFEST;
    dl.mem_cap = OTA_MANIFEST_MAX;
    dl.mem = calloc(1, dl.mem_cap + 1);
    if (!dl.mem) {
        ota_str_copy(err, errsz, "out of memory for manifest");
        return ESP_ERR_NO_MEM;
    }

    esp_http_client_handle_t client = ota_http_init(PWN_OTA_MANIFEST_URL, &dl);
    if (!client) {
        free(dl.mem);
        ota_str_copy(err, errsz, "cannot create HTTP client");
        return ESP_ERR_NO_MEM;
    }

    esp_err_t rc = ota_http_open(client, &dl);
    if (rc == ESP_OK && dl.total > (int64_t)dl.mem_cap) {
        ota_dl_error(&dl, "manifest too large");
        rc = ESP_FAIL;
    }
    while (rc == ESP_OK) {
        size_t space = dl.mem_cap - dl.mem_len;
        if (space == 0) {
            char extra;
            int n = esp_http_client_read(client, &extra, 1);
            if (n != 0) {
                ota_dl_error(&dl, "manifest too large");
                rc = ESP_FAIL;
            }
            break;
        }
        int n = esp_http_client_read(client, dl.mem + dl.mem_len, (int)space);
        if (n < 0) {
            ota_dl_error(&dl, "manifest read failed");
            rc = ESP_FAIL;
            break;
        }
        if (n == 0) {
            break;
        }
        dl.mem_len += n;
    }
    if (rc == ESP_OK && dl.total > 0 && dl.mem_len != (size_t)dl.total) {
        ota_dl_error(&dl, "manifest truncated");
        rc = ESP_FAIL;
    }
    esp_http_client_close(client);
    esp_http_client_cleanup(client);

    if (rc == ESP_OK) {
        dl.mem[dl.mem_len] = '\0';
        cJSON *root = cJSON_Parse((const char *)dl.mem);
        if (!root) {
            ota_dl_error(&dl, "manifest JSON parse failed");
            rc = ESP_FAIL;
        } else {
            const char *sha = cJSON_GetStringValue(
                cJSON_GetObjectItemCaseSensitive(root, "sha256"));
            const char *file = cJSON_GetStringValue(
                cJSON_GetObjectItemCaseSensitive(root, "file"));
            if (!ota_valid_sha256(sha)) {
                ota_dl_error(&dl, "manifest sha256 is missing or invalid");
                rc = ESP_FAIL;
            } else if (!ota_valid_filename(file)) {
                ota_dl_error(&dl, "manifest file name is invalid");
                rc = ESP_FAIL;
            } else {
                ota_str_copy(sha_out, sha_sz, sha);
                ota_str_copy(file_out, file_sz, file);
            }
            cJSON_Delete(root);
        }
    }
    free(dl.mem);

    if (rc != ESP_OK) {
        ota_str_copy(err, errsz, dl.err[0] ? dl.err : "manifest download failed");
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t ota_download_image(const char *url, const char *path,
                                    uint64_t max_size, uint64_t *size_out,
                                    char *sha_hex_out, size_t sha_hex_sz,
                                    char *err, size_t errsz)
{
    ota_dl_t dl = {0};
    dl.kind = OTA_DL_IMAGE;
    dl.total = -1;

    FILE *fp = NULL;
    uint8_t *buf = NULL;
    mbedtls_sha256_context sha;
    bool sha_started = false;
    esp_http_client_handle_t client = NULL;
    esp_err_t rc = ESP_FAIL;
    uint64_t written = 0;
    uint8_t digest[32];

    client = ota_http_init(url, &dl);
    if (!client) {
        ota_str_copy(err, errsz, "cannot create HTTP client");
        return ESP_ERR_NO_MEM;
    }
    rc = ota_http_open(client, &dl);
    if (rc == ESP_OK && dl.total <= 0) {
        ota_dl_error(&dl, "firmware size unavailable");
        rc = ESP_FAIL;
    }
    if (rc == ESP_OK && (uint64_t)dl.total < OTA_MIN_IMAGE) {
        ota_dl_error(&dl, "firmware size is too small");
        rc = ESP_FAIL;
    }
    if (rc == ESP_OK && (uint64_t)dl.total > max_size) {
        ota_dl_error(&dl, "firmware does not fit the OTA partition");
        rc = ESP_FAIL;
    }
    if (rc == ESP_OK) {
        pwn_sd_info_t sd;
        if (!capture_sd_info(&sd) || !sd.ready || !sd.writable) {
            ota_dl_error(&dl, "SD card is missing or not writable");
            rc = ESP_FAIL;
        } else if (sd.free_bytes < (uint64_t)dl.total + OTA_SD_RESERVE) {
            ota_dl_error(&dl, "not enough SD space (need %llu bytes, %llu free)",
                         (unsigned long long)((uint64_t)dl.total + OTA_SD_RESERVE),
                         (unsigned long long)sd.free_bytes);
            rc = ESP_FAIL;
        }
    }
    if (rc == ESP_OK) {
        fp = fopen(path, "wb");
        if (!fp) {
            ota_dl_error(&dl, "cannot create %s (errno %d)", path, errno);
            rc = ESP_FAIL;
        }
    }
    if (rc == ESP_OK) {
        buf = heap_caps_malloc(4096, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        if (!buf) {
            buf = malloc(4096);
        }
        if (!buf) {
            ota_dl_error(&dl, "out of memory for download buffer");
            rc = ESP_FAIL;
        }
    }
    if (rc == ESP_OK) {
        mbedtls_sha256_init(&sha);
        sha_started = true;
        if (mbedtls_sha256_starts(&sha, 0) != 0) {
            ota_dl_error(&dl, "SHA-256 init failed");
            rc = ESP_FAIL;
        }
    }
    while (rc == ESP_OK && written < (uint64_t)dl.total) {
        size_t want = 4096;
        if ((uint64_t)want > (uint64_t)dl.total - written) {
            want = (size_t)((uint64_t)dl.total - written);
        }
        int n = esp_http_client_read(client, (char *)buf, (int)want);
        if (n < 0) {
            ota_dl_error(&dl, "download read failed");
            rc = ESP_FAIL;
            break;
        }
        if (n == 0) {
            ota_dl_error(&dl, "download ended early");
            rc = ESP_FAIL;
            break;
        }
        mbedtls_sha256_update(&sha, buf, (size_t)n);
        if (!capture_bus_lock(3000)) {
            ota_dl_error(&dl, "display/SD bus lock timeout");
            rc = ESP_FAIL;
            break;
        }
        size_t w = fwrite(buf, 1, (size_t)n, fp);
        int saved_errno = errno;
        capture_bus_unlock();
        if (w != (size_t)n) {
            ota_dl_error(&dl, "SD write failed (errno %d)", saved_errno);
            rc = ESP_FAIL;
            break;
        }
        written += (uint64_t)n;
        int pct = 5 + (int)((written * 85) / (uint64_t)dl.total);
        if (pct > 90) {
            pct = 90;
        }
        ota_progress_set(pct);
    }

    if (fp) {
        if (fclose(fp) != 0 && rc == ESP_OK) {
            ota_dl_error(&dl, "SD close failed (errno %d)", errno);
            rc = ESP_FAIL;
        }
        fp = NULL;
    }
    if (rc == ESP_OK && written != (uint64_t)dl.total) {
        ota_dl_error(&dl, "download incomplete");
        rc = ESP_FAIL;
    }
    if (rc == ESP_OK) {
        if (sha_hex_sz < 65) {
            ota_dl_error(&dl, "SHA-256 output buffer too small");
            rc = ESP_FAIL;
        } else if (mbedtls_sha256_finish(&sha, digest) != 0) {
            ota_dl_error(&dl, "SHA-256 finish failed");
            rc = ESP_FAIL;
        } else {
            ota_hex_encode(digest, sizeof(digest), sha_hex_out);
        }
    }
    if (sha_started) {
        mbedtls_sha256_free(&sha);
    }
    free(buf);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);

    if (rc != ESP_OK) {
        ota_str_copy(err, errsz, dl.err[0] ? dl.err : "firmware download failed");
        return ESP_FAIL;
    }
    *size_out = written;
    return ESP_OK;
}

static esp_err_t ota_flash_image(const char *path, uint64_t size,
                                 const esp_partition_t *part,
                                 char *err, size_t errsz)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        ota_str_copy(err, errsz, "cannot reopen downloaded image");
        return ESP_FAIL;
    }
    uint8_t *buf = heap_caps_malloc(4096, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!buf) {
        buf = malloc(4096);
    }
    if (!buf) {
        fclose(fp);
        ota_str_copy(err, errsz, "out of memory for flash buffer");
        return ESP_ERR_NO_MEM;
    }

    esp_ota_handle_t ota = 0;
    esp_err_t rc = esp_ota_begin(part, (size_t)size, &ota);
    if (rc != ESP_OK) {
        free(buf);
        fclose(fp);
        ota_str_copy(err, errsz, esp_err_to_name(rc));
        return ESP_FAIL;
    }

    uint64_t done = 0;
    while (done < size) {
        size_t want = 4096;
        if ((uint64_t)want > size - done) {
            want = (size_t)(size - done);
        }
        if (!capture_bus_lock(3000)) {
            rc = ESP_FAIL;
            ota_str_copy(err, errsz, "display/SD bus lock timeout");
            break;
        }
        size_t n = fread(buf, 1, want, fp);
        int saved_errno = errno;
        capture_bus_unlock();
        if (n == 0) {
            rc = ESP_FAIL;
            ota_str_copy(err, errsz, "image read failed");
            ESP_LOGE(TAG, "GitHub OTA: image read errno %d", saved_errno);
            break;
        }
        rc = esp_ota_write(ota, buf, n);
        if (rc != ESP_OK) {
            ota_str_copy(err, errsz, esp_err_to_name(rc));
            break;
        }
        done += n;
        ota_progress_set(95 + (int)((done * 5) / size));
    }
    free(buf);
    fclose(fp);

    if (rc == ESP_OK && done != size) {
        rc = ESP_FAIL;
        ota_str_copy(err, errsz, "image read incomplete");
    }
    if (rc != ESP_OK) {
        esp_ota_abort(ota);
        return ESP_FAIL;
    }
    rc = esp_ota_end(ota);
    if (rc != ESP_OK) {
        ota_str_copy(err, errsz, esp_err_to_name(rc));
        return ESP_FAIL;
    }
    return ESP_OK;
}

static void github_ota_task(void *arg)
{
    (void)arg;
    char err[OTA_ERR_MAX] = "";
    char manifest_sha[65] = "";
    char file[64] = "";
    char url[256];
    char image_sha[65] = "";
    uint64_t image_size = 0;
    bool display_paused = false;

    ESP_LOGW(TAG, "GitHub OTA: manifest %s", PWN_OTA_MANIFEST_URL);
    ota_state_set(OTA_ST_DOWNLOADING, NULL);

    if (!ota_sync_time()) {
        ota_fail("NTP time sync failed");
        goto done;
    }

    const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
    if (!part) {
        ota_fail("no inactive OTA partition");
        goto done;
    }

    ota_progress_set(1);
    if (ota_fetch_manifest(manifest_sha, sizeof(manifest_sha),
                           file, sizeof(file), err, sizeof(err)) != ESP_OK) {
        ota_fail("manifest: %s", err);
        goto done;
    }
    if (snprintf(url, sizeof(url), "%s%s", PWN_OTA_BASE_URL, file) >=
        (int)sizeof(url)) {
        ota_fail("manifest file name is too long");
        goto done;
    }

    /* SD and LCD share one SPI bus. Stop the LVGL refresh worker before
     * touching the card so a long download cannot collide with a panel
     * flush; the web dashboard keeps reporting progress via /api/status. */
    if (esp_lv_adapter_pause(5000) != ESP_OK) {
        ota_fail("cannot pause the display for SD download");
        goto done;
    }
    display_paused = true;
    vTaskDelay(pdMS_TO_TICKS(100));

    ESP_LOGW(TAG, "GitHub OTA: %s", url);
    err[0] = '\0';
    ota_progress_set(5);
    if (ota_download_image(url, PWN_OTA_TMP_FILE, part->size,
                           &image_size, image_sha, sizeof(image_sha),
                           err, sizeof(err)) != ESP_OK) {
        ota_fail("download: %s", err);
        goto done;
    }

    ota_state_set(OTA_ST_VERIFYING, NULL);
    ota_progress_set(92);
    ESP_LOGI(TAG, "GitHub OTA: manifest sha256=%s", manifest_sha);
    ESP_LOGI(TAG, "GitHub OTA: download sha256=%s", image_sha);
    if (strcasecmp(manifest_sha, image_sha) != 0) {
        ota_fail("SHA-256 mismatch; refusing to flash");
        goto done;
    }

    ota_state_set(OTA_ST_FLASHING, NULL);
    ota_progress_set(95);
    err[0] = '\0';
    if (ota_flash_image(PWN_OTA_TMP_FILE, image_size, part,
                        err, sizeof(err)) != ESP_OK) {
        ota_fail("flash: %s", err);
        goto done;
    }
    if (esp_ota_set_boot_partition(part) != ESP_OK) {
        ota_fail("cannot select the new boot partition");
        goto done;
    }

    ota_progress_set(100);
    unlink(PWN_OTA_TMP_FILE);
    ESP_LOGW(TAG, "GitHub OTA: SHA-256 verified, %llu bytes written to %s; "
             "rebooting", (unsigned long long)image_size, part->label);
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();

done:
    unlink(PWN_OTA_TMP_FILE);
    if (display_paused) {
        esp_lv_adapter_resume();
    }
    s_github_ota_busy = false;
    vTaskDelete(NULL);
}

esp_err_t web_ota_github_start(void)
{
    if (!pwn_wifi_authorized()) {
        return ESP_ERR_INVALID_STATE;
    }
    taskENTER_CRITICAL(&s_ota_mux);
    bool busy = s_github_ota_busy;
    if (!busy) {
        s_github_ota_busy = true;
    }
    taskEXIT_CRITICAL(&s_ota_mux);
    if (busy) {
        return ESP_ERR_INVALID_STATE;
    }
    ota_state_set(OTA_ST_DOWNLOADING, NULL);
    ota_progress_set(0);
    if (xTaskCreate(github_ota_task, "pwn_gh_ota", 8192, NULL, 5, NULL) != pdPASS) {
        ota_fail("cannot start OTA task");
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

bool web_ota_busy(void)
{
    return s_github_ota_busy;
}

static esp_err_t ota_github_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    if (!pwn_wifi_authorized()) {
        return fail(req, "403 Forbidden", "unlock attacks first");
    }
    if (s_github_ota_busy) {
        return fail(req, "409 Conflict", "OTA already running");
    }
    esp_err_t start_err = web_ota_github_start();
    if (start_err == ESP_ERR_INVALID_STATE) {
        return fail(req, "409 Conflict", "OTA already running");
    }
    if (start_err != ESP_OK) {
        return fail(req, "500 Internal Server Error", "cannot start OTA task");
    }
    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "started", true);
    cJSON_AddStringToObject(r, "url", PWN_OTA_MANIFEST_URL);
    cJSON_AddStringToObject(r, "note",
                            "manifest SHA-256 is verified before flashing; device will reboot");
    return send_json(req, r);
}

static esp_err_t ota_post(httpd_req_t *req)
{
    if (!web_auth(req)) {
        return ESP_OK;
    }
    if (!pwn_wifi_authorized()) {
        return fail(req, "403 Forbidden", "unlock attacks first");
    }
    if (s_github_ota_busy) {
        return fail(req, "409 Conflict", "OTA already running");
    }
    const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
    if (!part) {
        return fail(req, "500 Internal Server Error", "no OTA partition");
    }
    if (req->content_len <= 0 || req->content_len > (int)part->size) {
        return fail(req, "400 Bad Request", "invalid firmware size");
    }

    esp_ota_handle_t ota = 0;
    esp_err_t err = esp_ota_begin(part, OTA_SIZE_UNKNOWN, &ota);
    if (err != ESP_OK) {
        return fail(req, "500 Internal Server Error", esp_err_to_name(err));
    }

    char buf[1024];
    int remaining = req->content_len;
    while (remaining > 0) {
        int want = remaining < (int)sizeof(buf) ? remaining : (int)sizeof(buf);
        int got = httpd_req_recv(req, buf, want);
        if (got == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;
        }
        if (got <= 0) {
            esp_ota_abort(ota);
            return fail(req, "400 Bad Request", "upload interrupted");
        }
        err = esp_ota_write(ota, buf, got);
        if (err != ESP_OK) {
            esp_ota_abort(ota);
            return fail(req, "500 Internal Server Error", esp_err_to_name(err));
        }
        remaining -= got;
    }

    err = esp_ota_end(ota);
    if (err == ESP_OK) {
        err = esp_ota_set_boot_partition(part);
    }
    if (err != ESP_OK) {
        return fail(req, "500 Internal Server Error", esp_err_to_name(err));
    }

    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "ok", true);
    cJSON_AddStringToObject(r, "partition", part->label);
    cJSON_AddBoolToObject(r, "reboot", true);
    esp_err_t sent = send_json(req, r);
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
    return sent;
}

esp_err_t web_start(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port = 80;
    cfg.max_uri_handlers = 48;
    cfg.max_open_sockets = 4;
    cfg.lru_purge_enable = true;
    cfg.stack_size = 8192;

    esp_err_t err = httpd_start(&s_server, &cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "httpd start failed: %s", esp_err_to_name(err));
        return err;
    }

    static const httpd_uri_t uris[] = {
        {.uri = "/",                 .method = HTTP_GET,  .handler = page_get},
        {.uri = "/favicon.ico",      .method = HTTP_GET,  .handler = favicon_get},
        {.uri = "/api/status",       .method = HTTP_GET,  .handler = status_get},
        {.uri = "/api/aps",          .method = HTTP_GET,  .handler = aps_get},
        {.uri = "/api/clients",      .method = HTTP_GET,  .handler = clients_get},
        {.uri = "/api/ble",          .method = HTTP_GET,  .handler = ble_get},
        {.uri = "/api/ble",          .method = HTTP_POST, .handler = ble_post},
        {.uri = "/api/hid",          .method = HTTP_GET,  .handler = hid_get},
        {.uri = "/api/hid",          .method = HTTP_POST, .handler = hid_post},
        {.uri = "/api/hid_payload",  .method = HTTP_POST, .handler = hid_payload_post},
        {.uri = "/api/dns",          .method = HTTP_GET,  .handler = dns_get},
        {.uri = "/api/sni",          .method = HTTP_GET,  .handler = sni_get},
        {.uri = "/api/network",      .method = HTTP_GET,  .handler = network_get},
        {.uri = "/api/watch",        .method = HTTP_GET,  .handler = watch_get},
        {.uri = "/api/watch",        .method = HTTP_POST, .handler = watch_post},
        {.uri = "/api/hs",           .method = HTTP_GET,  .handler = hs_get},
        {.uri = "/api/sd",           .method = HTTP_POST, .handler = sd_post},
        {.uri = "/api/pcap",         .method = HTTP_GET,  .handler = pcap_get},
        {.uri = "/api/hs_meta",      .method = HTTP_GET,  .handler = hs_meta_get},
        {.uri = "/api/pcap_delete",  .method = HTTP_POST, .handler = pcap_delete_post},
        {.uri = "/api/scan",         .method = HTTP_POST, .handler = scan_post},
        {.uri = "/api/connect",      .method = HTTP_POST, .handler = connect_post},
        {.uri = "/api/disconnect",   .method = HTTP_POST, .handler = disconnect_post},
        {.uri = "/api/auth",         .method = HTTP_POST, .handler = auth_post},
        {.uri = "/api/attacks",      .method = HTTP_POST, .handler = attacks_post},
        {.uri = "/api/deauth",       .method = HTTP_POST, .handler = deauth_post},
        {.uri = "/api/hunt",         .method = HTTP_POST, .handler = hunt_post},
        {.uri = "/api/hop",          .method = HTTP_POST, .handler = hop_post},
        {.uri = "/api/hop_ap",       .method = HTTP_POST, .handler = hop_ap_post},
        {.uri = "/api/pause",        .method = HTTP_POST, .handler = pause_post},
        {.uri = "/api/strategy",     .method = HTTP_POST, .handler = strategy_post},
        {.uri = "/api/brightness",   .method = HTTP_POST, .handler = brightness_post},
        {.uri = "/api/autoconnect",  .method = HTTP_POST, .handler = autoconnect_post},
        {.uri = "/api/reset_brain",  .method = HTTP_POST, .handler = reset_brain_post},
        {.uri = "/api/reboot",       .method = HTTP_POST, .handler = reboot_post},
        {.uri = "/api/ota",          .method = HTTP_POST, .handler = ota_post},
        {.uri = "/api/ota_github",   .method = HTTP_POST, .handler = ota_github_post},
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
        err = httpd_register_uri_handler(s_server, &uris[i]);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "register %s failed: %s", uris[i].uri,
                     esp_err_to_name(err));
        }
    }
    ESP_LOGI(TAG, "web UI listening on :80 (%u handlers)",
             (unsigned)(sizeof(uris) / sizeof(uris[0])));
    return ESP_OK;
}

void web_stop(void)
{
    if (s_server) {
        httpd_stop(s_server);
        s_server = NULL;
    }
}
