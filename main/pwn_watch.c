#include "pwn_watch.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <strings.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_err.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "pwn_wifi.h"

static const char *TAG = "watch";
#define WATCH_NVS_NS "pwnwatch"
#define WATCH_NVS_KEY "items"
#define WATCH_ALERT_COOLDOWN_MS 60000

typedef struct {
    uint8_t type;
    uint8_t len;
    char    value[PWN_WATCH_VALUE_MAX];
} watch_rec_t;

static pwn_watch_item_t s_items[PWN_WATCH_MAX];
static uint32_t s_alert_ms[PWN_WATCH_MAX];
static int s_count;
static uint32_t s_hits;
static char s_last[96];
static uint32_t s_last_ms;
static SemaphoreHandle_t s_lock;

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

static uint8_t type_from_name(const char *type)
{
    if (!type) {
        return 0xff;
    }
    if (strcasecmp(type, "ssid") == 0) {
        return PWN_WATCH_SSID;
    }
    if (strcasecmp(type, "mac") == 0) {
        return PWN_WATCH_MAC;
    }
    if (strcasecmp(type, "ble") == 0) {
        return PWN_WATCH_BLE;
    }
    return 0xff;
}

const char *watch_type_name(uint8_t type)
{
    switch (type) {
    case PWN_WATCH_SSID: return "ssid";
    case PWN_WATCH_MAC:  return "mac";
    case PWN_WATCH_BLE:  return "ble";
    default:             return "?";
    }
}

/* Parse aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff. */
static bool parse_mac_str(const char *s, uint8_t out[6])
{
    if (!s) {
        return false;
    }
    unsigned v[6];
    int n = sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x",
                   &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);
    if (n != 6) {
        n = sscanf(s, "%2x-%2x-%2x-%2x-%2x-%2x",
                   &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);
    }
    if (n != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        if (v[i] > 0xff) {
            return false;
        }
        out[i] = (uint8_t)v[i];
    }
    return true;
}

static void format_mac(const uint8_t mac[6], char out[18])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static bool value_is_mac(const char *s, char out[18])
{
    uint8_t mac[6];
    if (!parse_mac_str(s, mac)) {
        return false;
    }
    format_mac(mac, out);
    return true;
}

static esp_err_t save_locked(void)
{
    watch_rec_t recs[PWN_WATCH_MAX];
    memset(recs, 0, sizeof(recs));
    for (int i = 0; i < s_count; i++) {
        recs[i].type = s_items[i].type;
        size_t len = strlen(s_items[i].value);
        if (len >= sizeof(recs[i].value)) {
            len = sizeof(recs[i].value) - 1;
        }
        recs[i].len = (uint8_t)len;
        memcpy(recs[i].value, s_items[i].value, len);
    }

    nvs_handle_t h;
    esp_err_t err = nvs_open(WATCH_NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "nvs open: %s", esp_err_to_name(err));
        return err;
    }
    if (s_count == 0) {
        nvs_erase_key(h, WATCH_NVS_KEY);
        err = nvs_commit(h);
    } else {
        err = nvs_set_blob(h, WATCH_NVS_KEY, recs,
                           (size_t)s_count * sizeof(recs[0]));
        if (err == ESP_OK) {
            err = nvs_commit(h);
        }
    }
    nvs_close(h);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "nvs save: %s", esp_err_to_name(err));
    }
    return err;
}

void watch_init(void)
{
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
    }
    if (!s_lock) {
        ESP_LOGE(TAG, "watch lock allocation failed");
        return;
    }
    memset(s_items, 0, sizeof(s_items));
    memset(s_alert_ms, 0, sizeof(s_alert_ms));
    s_count = 0;
    s_hits = 0;
    s_last[0] = 0;
    s_last_ms = 0;

    nvs_handle_t h;
    if (nvs_open(WATCH_NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        size_t sz = sizeof(watch_rec_t) * PWN_WATCH_MAX;
        watch_rec_t recs[PWN_WATCH_MAX];
        if (nvs_get_blob(h, WATCH_NVS_KEY, recs, &sz) == ESP_OK &&
            sz > 0 && sz % sizeof(watch_rec_t) == 0) {
            int n = (int)(sz / sizeof(watch_rec_t));
            if (n > PWN_WATCH_MAX) {
                n = PWN_WATCH_MAX;
            }
            for (int i = 0; i < n; i++) {
                if (recs[i].type > PWN_WATCH_BLE ||
                    recs[i].len == 0 ||
                    recs[i].len >= sizeof(recs[i].value)) {
                    continue;
                }
                recs[i].value[recs[i].len] = 0;
                s_items[s_count].type = recs[i].type;
                memcpy(s_items[s_count].value, recs[i].value,
                       sizeof(s_items[s_count].value) - 1);
                s_items[s_count].value[sizeof(s_items[s_count].value) - 1] = 0;
                s_count++;
            }
        }
        nvs_close(h);
    }
    ESP_LOGI(TAG, "watchlist loaded: %d entr%s", s_count,
             s_count == 1 ? "y" : "ies");
}

int watch_count(void)
{
    int n = 0;
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
        n = s_count;
        xSemaphoreGive(s_lock);
    } else {
        n = s_count;
    }
    return n;
}

int watch_snapshot(pwn_watch_item_t *out, int max)
{
    if (!out || max <= 0) {
        return 0;
    }
    int n = 0;
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    for (int i = 0; i < s_count && n < max; i++) {
        out[n++] = s_items[i];
    }
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }
    return n;
}

esp_err_t watch_add(const char *type, const char *value, char *err, size_t errsz)
{
    if (err && errsz) {
        err[0] = 0;
    }
    uint8_t t = type_from_name(type);
    if (t == 0xff) {
        if (err && errsz) snprintf(err, errsz, "type must be ssid, mac or ble");
        return ESP_ERR_INVALID_ARG;
    }
    if (!value || !value[0]) {
        if (err && errsz) snprintf(err, errsz, "value is required");
        return ESP_ERR_INVALID_ARG;
    }

    char norm[PWN_WATCH_VALUE_MAX];
    memset(norm, 0, sizeof(norm));

    if (t == PWN_WATCH_MAC || t == PWN_WATCH_BLE) {
        char macbuf[18];
        if (value_is_mac(value, macbuf)) {
            snprintf(norm, sizeof(norm), "%s", macbuf);
        } else if (t == PWN_WATCH_MAC) {
            if (err && errsz) snprintf(err, errsz, "mac must be aa:bb:cc:dd:ee:ff");
            return ESP_ERR_INVALID_ARG;
        } else {
            /* BLE entries may be an advertised name instead of an address. */
            size_t len = strlen(value);
            if (len >= sizeof(norm)) {
                if (err && errsz) snprintf(err, errsz, "name is too long");
                return ESP_ERR_INVALID_ARG;
            }
            for (size_t i = 0; i < len; i++) {
                if (!isprint((unsigned char)value[i])) {
                    if (err && errsz) snprintf(err, errsz, "name has invalid characters");
                    return ESP_ERR_INVALID_ARG;
                }
            }
            snprintf(norm, sizeof(norm), "%s", value);
        }
    } else {
        size_t len = strlen(value);
        if (len == 0 || len > 32) {
            if (err && errsz) snprintf(err, errsz, "ssid must be 1-32 bytes");
            return ESP_ERR_INVALID_ARG;
        }
        for (size_t i = 0; i < len; i++) {
            if ((unsigned char)value[i] < 0x20) {
                if (err && errsz) snprintf(err, errsz, "ssid has control characters");
                return ESP_ERR_INVALID_ARG;
            }
        }
        snprintf(norm, sizeof(norm), "%s", value);
    }

    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    for (int i = 0; i < s_count; i++) {
        if (s_items[i].type == t && strcmp(s_items[i].value, norm) == 0) {
            if (s_lock) xSemaphoreGive(s_lock);
            if (err && errsz) snprintf(err, errsz, "already watched");
            return ESP_ERR_INVALID_STATE;
        }
    }
    if (s_count >= PWN_WATCH_MAX) {
        if (s_lock) xSemaphoreGive(s_lock);
        if (err && errsz) snprintf(err, errsz, "watchlist is full");
        return ESP_ERR_NO_MEM;
    }
    int slot = s_count;
    s_items[slot].type = t;
    snprintf(s_items[slot].value, sizeof(s_items[slot].value), "%s", norm);
    s_alert_ms[slot] = 0;
    s_count++;
    esp_err_t save = save_locked();
    if (s_lock) xSemaphoreGive(s_lock);
    if (save != ESP_OK) {
        if (err && errsz) snprintf(err, errsz, "saved in RAM but NVS write failed");
        return save;
    }
    ESP_LOGI(TAG, "watching %s %s", watch_type_name(t), norm);
    return ESP_OK;
}

bool watch_remove(const char *type, const char *value)
{
    uint8_t t = type_from_name(type);
    if (t == 0xff || !value || !value[0]) {
        return false;
    }
    char norm[PWN_WATCH_VALUE_MAX] = {0};
    if (t == PWN_WATCH_MAC || t == PWN_WATCH_BLE) {
        char macbuf[18];
        if (value_is_mac(value, macbuf)) {
            snprintf(norm, sizeof(norm), "%s", macbuf);
        } else {
            snprintf(norm, sizeof(norm), "%s", value);
        }
    } else {
        snprintf(norm, sizeof(norm), "%s", value);
    }

    bool removed = false;
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    for (int i = 0; i < s_count; i++) {
        if (s_items[i].type == t && strcmp(s_items[i].value, norm) == 0) {
            for (int k = i; k + 1 < s_count; k++) {
                s_items[k] = s_items[k + 1];
                s_alert_ms[k] = s_alert_ms[k + 1];
            }
            s_count--;
            memset(&s_items[s_count], 0, sizeof(s_items[0]));
            s_alert_ms[s_count] = 0;
            removed = true;
            break;
        }
    }
    if (removed) {
        save_locked();
    }
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }
    if (removed) {
        ESP_LOGI(TAG, "removed watch %s %s", watch_type_name(t), norm);
    }
    return removed;
}

int watch_clear(void)
{
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    int n = s_count;
    memset(s_items, 0, sizeof(s_items));
    memset(s_alert_ms, 0, sizeof(s_alert_ms));
    s_count = 0;
    save_locked();
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }
    ESP_LOGI(TAG, "watchlist cleared (%d)", n);
    return n;
}

/* Called with s_lock held. Returns the matching slot or -1. */
static int match_ssid_locked(const char *ssid)
{
    if (!ssid || !ssid[0]) {
        return -1;
    }
    for (int i = 0; i < s_count; i++) {
        if (s_items[i].type == PWN_WATCH_SSID &&
            strcmp(s_items[i].value, ssid) == 0) {
            return i;
        }
    }
    return -1;
}

static int match_mac_locked(const uint8_t mac[6])
{
    char buf[18];
    format_mac(mac, buf);
    for (int i = 0; i < s_count; i++) {
        if (s_items[i].type == PWN_WATCH_MAC &&
            strcmp(s_items[i].value, buf) == 0) {
            return i;
        }
    }
    return -1;
}

static int match_ble_locked(const uint8_t addr[6], const char *name)
{
    char buf[18];
    format_mac(addr, buf);
    for (int i = 0; i < s_count; i++) {
        if (s_items[i].type != PWN_WATCH_BLE) {
            continue;
        }
        char macbuf[18];
        if (value_is_mac(s_items[i].value, macbuf)) {
            if (strcmp(macbuf, buf) == 0) {
                return i;
            }
        } else if (name && name[0] &&
                   strcasecmp(s_items[i].value, name) == 0) {
            return i;
        }
    }
    return -1;
}

static bool alert_slot(int slot, const char *kind)
{
    if (slot < 0 || slot >= s_count) {
        return false;
    }
    uint32_t now = now_ms();
    char msg[96];
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    bool fire = (s_alert_ms[slot] == 0 ||
                 (uint32_t)(now - s_alert_ms[slot]) >= WATCH_ALERT_COOLDOWN_MS);
    if (fire) {
        s_alert_ms[slot] = now;
        s_hits++;
        s_last_ms = now;
        snprintf(msg, sizeof(msg), "watch %s: %s", kind, s_items[slot].value);
        snprintf(s_last, sizeof(s_last), "%s", msg);
    }
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }
    if (fire) {
        ESP_LOGW(TAG, "%s", msg);
        pwn_wifi_event("%s", msg);
    }
    return fire;
}

bool watch_check_ssid(const char *ssid)
{
    if (!s_lock) {
        return false;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    int slot = match_ssid_locked(ssid);
    xSemaphoreGive(s_lock);
    return alert_slot(slot, "ssid");
}

bool watch_check_mac(const uint8_t mac[6])
{
    if (!s_lock || !mac) {
        return false;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    int slot = match_mac_locked(mac);
    xSemaphoreGive(s_lock);
    return alert_slot(slot, "mac");
}

bool watch_check_ble(const uint8_t addr[6], const char *name)
{
    if (!s_lock || !addr) {
        return false;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    int slot = match_ble_locked(addr, name);
    xSemaphoreGive(s_lock);
    return alert_slot(slot, "ble");
}

void watch_status(int *count, uint32_t *hits, char *last, size_t lastsz,
                  uint32_t *age_ms)
{
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    if (count) *count = s_count;
    if (hits) *hits = s_hits;
    if (last && lastsz) {
        snprintf(last, lastsz, "%s", s_last);
    }
    if (age_ms) {
        *age_ms = s_last_ms ? (uint32_t)(now_ms() - s_last_ms) : 0;
    }
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }
}
