#include "pwn_web.h"

#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>

#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "esp_ota_ops.h"
#include "esp_https_ota.h"
#include "esp_crt_bundle.h"
#include "esp_sntp.h"
#include <time.h>
#include "cJSON.h"
#include "bsp/esp-bsp.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "pwn_config.h"
#include "pwn_wifi.h"
#include "pwn_capture.h"
#include "pwn_pet.h"
#include "pwn_net.h"
#include "pwn_web_page.h"

static const char *TAG = "web";

/* Large snapshot arrays live in PSRAM so internal RAM stays available for
 * task stacks (the CLI uses a 16 KiB stack). */
static void *big_calloc(size_t n, size_t size)
{
    void *p = heap_caps_calloc(n, size, MALLOC_CAP_SPIRAM);
    return p ? p : calloc(n, size);
}
static httpd_handle_t s_server;

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
    cJSON_AddNumberToObject(r, "frames", st->frames);
    cJSON_AddNumberToObject(r, "eapol", st->eapol);
    cJSON_AddNumberToObject(r, "deauths", st->deauths);
    cJSON_AddNumberToObject(r, "dropped", st->dropped);
    cJSON_AddNumberToObject(r, "channel", st->channel);
    cJSON_AddNumberToObject(r, "band", st->band);
    cJSON_AddBoolToObject(r, "paused", pet.paused);
    cJSON_AddBoolToObject(r, "locked", pwn_wifi_locked());
    cJSON_AddBoolToObject(r, "authorized", pwn_wifi_authorized());
    cJSON_AddBoolToObject(r, "auto_deauth", pwn_wifi_auto_deauth());
    cJSON_AddBoolToObject(r, "deauth_active", pwn_wifi_deauth_active());
    cJSON_AddStringToObject(r, "last_event",
                            st->last_event[0] ? st->last_event : "listening...");
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

    cJSON_AddBoolToObject(r, "connected", net.connected);
    cJSON_AddBoolToObject(r, "connecting", net.connecting);
    cJSON_AddBoolToObject(r, "have_creds", net.have_creds);
    cJSON_AddBoolToObject(r, "autoconnect", net.autoconnect);
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
    pwn_client_t *cls = calloc(PWN_MAX_CLIENTS, sizeof(pwn_client_t));
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
    pwn_client_t *c = calloc(PWN_MAX_CLIENTS, sizeof(pwn_client_t));
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
        cJSON_AddNumberToObject(o, "mask", hs[i].msg_mask);
        cJSON_AddNumberToObject(o, "frames", hs[i].nframes);
        cJSON_AddBoolToObject(o, "complete", hs[i].complete);
        cJSON_AddBoolToObject(o, "pmkid", hs[i].has_pmkid);
        cJSON_AddBoolToObject(o, "saved", hs[i].saved);
        cJSON_AddStringToObject(o, "file", hs[i].file);
        cJSON_AddItemToArray(arr, o);
    }
    free(hs);

    /* The live slot table is RAM-only.  List the PCAPs that survived on the
     * SD card so the dashboard still shows them after a reboot. */
    pwn_pcap_file_t files[24];
    int nf = capture_list_files(files, 24);
    cJSON *fa = cJSON_AddArrayToObject(root, "files");
    for (int i = 0; i < nf; i++) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "name", files[i].name);
        cJSON_AddNumberToObject(o, "size", files[i].size);
        cJSON_AddItemToArray(fa, o);
    }
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
            pwn_client_t *cl = calloc(PWN_MAX_CLIENTS, sizeof(pwn_client_t));
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
        pwn_client_t *cl = calloc(PWN_MAX_CLIENTS, sizeof(pwn_client_t));
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



static volatile bool s_github_ota_busy;

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

static void github_ota_task(void *arg)
{
    (void)arg;
    ESP_LOGW(TAG, "GitHub OTA: %s", PWN_OTA_URL);
    if (!ota_sync_time()) {
        ESP_LOGE(TAG, "GitHub OTA: NTP time sync failed");
        s_github_ota_busy = false;
        vTaskDelete(NULL);
        return;
    }
    esp_http_client_config_t http = {
        .url = PWN_OTA_URL,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 30000,
        .keep_alive_enable = true,
    };
    esp_https_ota_config_t cfg = {
        .http_config = &http,
    };
    esp_err_t err = esp_https_ota(&cfg);
    if (err == ESP_OK) {
        ESP_LOGW(TAG, "GitHub OTA complete; rebooting");
        vTaskDelay(pdMS_TO_TICKS(500));
        esp_restart();
    }
    ESP_LOGE(TAG, "GitHub OTA failed: %s", esp_err_to_name(err));
    s_github_ota_busy = false;
    vTaskDelete(NULL);
}

esp_err_t web_ota_github_start(void)
{
    if (!pwn_wifi_authorized()) {
        return ESP_ERR_INVALID_STATE;
    }
    if (s_github_ota_busy) {
        return ESP_ERR_INVALID_STATE;
    }
    s_github_ota_busy = true;
    if (xTaskCreate(github_ota_task, "pwn_gh_ota", 8192, NULL, 5, NULL) != pdPASS) {
        s_github_ota_busy = false;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
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
    if (start_err != ESP_OK) {
        return fail(req, "500 Internal Server Error", "cannot start OTA task");
    }
    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "started", true);
    cJSON_AddStringToObject(r, "url", PWN_OTA_URL);
    cJSON_AddStringToObject(r, "note", "device will download and reboot; watch serial/dashboard");
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
    cfg.max_uri_handlers = 24;
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
        {.uri = "/api/hs",           .method = HTTP_GET,  .handler = hs_get},
        {.uri = "/api/sd",           .method = HTTP_POST, .handler = sd_post},
        {.uri = "/api/pcap",         .method = HTTP_GET,  .handler = pcap_get},
        {.uri = "/api/scan",         .method = HTTP_POST, .handler = scan_post},
        {.uri = "/api/connect",      .method = HTTP_POST, .handler = connect_post},
        {.uri = "/api/disconnect",   .method = HTTP_POST, .handler = disconnect_post},
        {.uri = "/api/auth",         .method = HTTP_POST, .handler = auth_post},
        {.uri = "/api/attacks",      .method = HTTP_POST, .handler = attacks_post},
        {.uri = "/api/deauth",       .method = HTTP_POST, .handler = deauth_post},
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
