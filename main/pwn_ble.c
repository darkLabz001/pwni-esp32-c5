#include "pwn_ble.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_coexist.h"

#if __has_include("nimble/nimble_port.h")
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#define PWN_HAVE_NIMBLE 1
#else
#define PWN_HAVE_NIMBLE 0
#endif

#include "pwn_watch.h"
#include "pwn_wifi.h"
#include "pwn_net.h"
#include "pwn_hid.h"

static const char *TAG = "ble";

static pwn_ble_dev_t *s_devs;
static SemaphoreHandle_t s_lock;
static volatile bool s_enabled;      /* user request; default off */
static volatile bool s_scanning;
static volatile bool s_gated;
static volatile bool s_synced;
static volatile bool s_supported;
static volatile bool s_hid_active;
static TaskHandle_t s_supervisor;

void ble_store_config_init(void);

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

const char *ble_addr_type_name(uint8_t type)
{
    switch (type) {
    case 0: return "public";
    case 1: return "random";
    case 2: return "public-id";
    case 3: return "random-id";
    default: return "?";
    }
}

static void format_addr(const uint8_t a[6], char out[18])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             a[0], a[1], a[2], a[3], a[4], a[5]);
}

static pwn_ble_dev_t *dev_slot(const uint8_t addr[6], uint8_t type)
{
    pwn_ble_dev_t *lru = NULL;
    pwn_ble_dev_t *free_slot = NULL;
    for (int i = 0; i < PWN_BLE_MAX; i++) {
        if (s_devs[i].last_seen_ms &&
            s_devs[i].addr_type == type &&
            memcmp(s_devs[i].addr, addr, 6) == 0) {
            return &s_devs[i];
        }
        if (!s_devs[i].last_seen_ms) {
            if (!free_slot) {
                free_slot = &s_devs[i];
            }
        } else if (!lru || s_devs[i].last_seen_ms < lru->last_seen_ms) {
            lru = &s_devs[i];
        }
    }
    return free_slot ? free_slot : lru;
}

#if PWN_HAVE_NIMBLE

static uint8_t s_own_addr_type;

static void adv_copy_name(char *dst, size_t dstsz,
                          const uint8_t *src, size_t srclen)
{
    if (!src || !srclen) {
        return;
    }
    size_t o = 0;
    for (size_t i = 0; i < srclen && o + 1 < dstsz; i++) {
        uint8_t c = src[i];
        if (c >= 0x20 && c < 0x7f) {
            dst[o++] = (char)c;
        }
    }
    dst[o] = 0;
}

/* Scan raw AD structures for well-known beacon formats. */
static void adv_beacon(const uint8_t *data, uint8_t len,
                       char out[16], char services[64])
{
    int i = 0;
    while (i + 2 <= len) {
        uint8_t alen = data[i];
        if (alen == 0 || i + 1 + alen > len) {
            break;
        }
        uint8_t type = data[i + 1];
        const uint8_t *p = &data[i + 2];
        int plen = alen - 1;
        if (type == 0x16 && plen >= 2) {
            uint16_t uuid = (uint16_t)(p[0] | (p[1] << 8));
            if (uuid == 0xfeaa && !out[0]) {
                snprintf(out, 16, "Eddystone");
            } else if (uuid == 0xfd6f && !out[0]) {
                snprintf(out, 16, "Exposure");
            } else if (uuid == 0xfe2c && !out[0]) {
                snprintf(out, 16, "FastPair");
            }
        } else if (type == 0xff && plen >= 4) {
            uint16_t company = (uint16_t)(p[0] | (p[1] << 8));
            if (company == 0x004c && plen >= 5 &&
                p[2] == 0x02 && p[3] == 0x15 && !out[0]) {
                snprintf(out, 16, "iBeacon");
            } else if (company == 0x0118 && p[2] == 0xbe &&
                       p[3] == 0xac && !out[0]) {
                snprintf(out, 16, "AltBeacon");
            }
        } else if (type == 0x24 && plen > 0 && !out[0]) {
            snprintf(out, 16, "URI");
        } else if (type == 0x08 || type == 0x09) {
            (void)services;
        }
        i += 1 + alen;
    }
}

static void adv_services(const struct ble_hs_adv_fields *f, char out[64])
{
    size_t o = 0;
    out[0] = 0;
    for (int i = 0; i < f->num_uuids16 && i < 4; i++) {
        int n = snprintf(out + o, 64 - o, "%s0x%04x",
                         o ? "," : "", f->uuids16[i].value);
        if (n <= 0 || (size_t)n >= 64 - o) {
            break;
        }
        o += (size_t)n;
    }
    if (!out[0] && f->num_uuids128 > 0) {
        snprintf(out, 64, "128-bit uuid");
    }
    if (!out[0] && f->num_uuids32 > 0) {
        snprintf(out, 64, "32-bit uuid");
    }
}

static void ble_store_adv(const struct ble_gap_disc_desc *disc)
{
    uint8_t addr[6];
    for (int i = 0; i < 6; i++) {
        addr[i] = disc->addr.val[5 - i];
    }

    char name[32] = "";
    char services[64] = "";
    char beacon[16] = "";
    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));
    if (ble_hs_adv_parse_fields(&fields, disc->data, disc->length_data) == 0) {
        adv_copy_name(name, sizeof(name), fields.name, fields.name_len);
        adv_services(&fields, services);
    }
    adv_beacon(disc->data, disc->length_data, beacon, services);
    if (!name[0]) {
        /* Some controllers strip the local-name field; fall back to a raw
         * AD-structure walk so the dashboard still has a label. */
        int i = 0;
        while (i + 2 <= disc->length_data) {
            uint8_t alen = disc->data[i];
            if (alen == 0 || i + 1 + alen > disc->length_data) {
                break;
            }
            if ((disc->data[i + 1] == 0x08 || disc->data[i + 1] == 0x09) &&
                alen > 1) {
                adv_copy_name(name, sizeof(name), &disc->data[i + 2], alen - 1);
                break;
            }
            i += 1 + alen;
        }
    }

    uint32_t now = now_ms();
    bool alert = false;
    char watchname[32];
    snprintf(watchname, sizeof(watchname), "%s", name);

    xSemaphoreTake(s_lock, portMAX_DELAY);
    pwn_ble_dev_t *d = dev_slot(addr, disc->addr.type);
    if (d) {
        bool is_new = d->last_seen_ms == 0;
        if (is_new) {
            memset(d, 0, sizeof(*d));
            memcpy(d->addr, addr, 6);
            d->addr_type = disc->addr.type;
            d->first_seen_ms = now;
        }
        d->event_type = disc->event_type;
        d->rssi = disc->rssi;
        d->last_seen_ms = now;
        if (d->count != UINT16_MAX) {
            d->count++;
        }
        if (name[0]) {
            snprintf(d->name, sizeof(d->name), "%s", name);
        }
        if (services[0]) {
            snprintf(d->services, sizeof(d->services), "%s", services);
        }
        if (beacon[0]) {
            snprintf(d->beacon, sizeof(d->beacon), "%s", beacon);
        }
        alert = is_new;
        snprintf(watchname, sizeof(watchname), "%s", d->name);
    }
    xSemaphoreGive(s_lock);

    char addrstr[18];
    format_addr(addr, addrstr);
    /* Check every advertisement so a watch entry added after the device was
     * first seen still alerts. The watchlist applies its own cooldown. */
    watch_check_ble(addr, watchname);
    if (alert) {
        ESP_LOGI(TAG, "new device %s %s rssi=%d%s%s%s%s", addrstr,
                 ble_addr_type_name(disc->addr.type), disc->rssi,
                 name[0] ? " name=" : "", name,
                 beacon[0] ? " beacon=" : "", beacon);
    }
}

static int ble_gap_event_cb(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    switch (event->type) {
    case BLE_GAP_EVENT_DISC:
        ble_store_adv(&event->disc);
        return 0;
    case BLE_GAP_EVENT_DISC_COMPLETE:
        s_scanning = false;
        ESP_LOGI(TAG, "scan complete");
        return 0;
    default:
        return 0;
    }
}

static void ble_on_sync(void)
{
    s_synced = true;
    int rc = ble_hs_id_infer_auto(0, &s_own_addr_type);
    if (rc != 0) {
        ESP_LOGW(TAG, "own address type inference failed: %d", rc);
        s_own_addr_type = BLE_OWN_ADDR_PUBLIC;
    }
    ESP_LOGI(TAG, "NimBLE synced (own addr type %u)", s_own_addr_type);
    hid_on_ble_sync();
}

static void ble_on_reset(int reason)
{
    (void)reason;
    s_synced = false;
    s_scanning = false;
    hid_on_ble_reset();
    ESP_LOGW(TAG, "NimBLE reset (reason %d)", reason);
}

static void ble_host_task(void *param)
{
    (void)param;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

static bool ble_start_scan(void)
{
    if (!s_synced || s_scanning) {
        return s_scanning;
    }
    struct ble_gap_disc_params params;
    memset(&params, 0, sizeof(params));
    /* Low duty cycle: 100 ms interval, 40 ms window. Passive means no scan
     * requests are transmitted; duplicate filtering stays off so RSSI and
     * last-seen stay fresh. */
    params.itvl = 160;
    params.window = 64;
    params.passive = 1;
    params.filter_duplicates = 0;
    params.filter_policy = 0;
    params.limited = 0;
    int rc = ble_gap_disc(s_own_addr_type, BLE_HS_FOREVER, &params,
                          ble_gap_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGW(TAG, "scan start failed: %d", rc);
        s_scanning = false;
        return false;
    }
    s_scanning = true;
    ESP_LOGI(TAG, "passive scan started (duty 40/100 ms)");
    return true;
}

static void ble_stop_scan(void)
{
    if (!s_scanning) {
        return;
    }
    int rc = ble_gap_disc_cancel();
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGW(TAG, "scan cancel: %d", rc);
    }
    s_scanning = false;
    ESP_LOGI(TAG, "passive scan stopped");
}

/* The single 2.4 GHz radio is shared with Wi-Fi. Only scan when the Wi-Fi
 * side is not acting as an AP and no deauth burst is in flight; normal STA
 * operation is allowed with a low BLE duty cycle. */
static bool ble_allowed_now(void)
{
    if (s_hid_active) {
        return false;
    }
    pwn_net_status_t n;
    net_get_status(&n);
    if (n.ap_active || n.setup_mode) {
        return false;
    }
    if (pwn_wifi_deauth_active()) {
        return false;
    }
    return true;
}

static void ble_supervisor(void *arg)
{
    (void)arg;
    for (;;) {
        bool allowed = ble_allowed_now();
        s_gated = !allowed;
        bool want = s_enabled && allowed;
        if (want && !s_scanning) {
            ble_start_scan();
        } else if (!want && s_scanning) {
            ble_stop_scan();
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

#endif /* PWN_HAVE_NIMBLE */

void ble_init(void)
{
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
    }
    if (!s_lock) {
        ESP_LOGE(TAG, "BLE lock allocation failed");
        return;
    }
    s_devs = heap_caps_calloc(PWN_BLE_MAX, sizeof(*s_devs),
                              MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_devs) {
        s_devs = calloc(PWN_BLE_MAX, sizeof(*s_devs));
    }
    if (!s_devs) {
        ESP_LOGE(TAG, "BLE table allocation failed");
        return;
    }
    s_enabled = false;
    s_scanning = false;
    s_gated = false;
    s_synced = false;
    s_supported = false;
    s_hid_active = false;

#if PWN_HAVE_NIMBLE
    esp_err_t err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "NimBLE init failed: %s (BLE scanner disabled)",
                 esp_err_to_name(err));
        return;
    }
    /* Keep Wi-Fi first on the shared radio. BLE is passive and opt-in. */
    esp_coex_preference_set(ESP_COEX_PREFER_WIFI);

#if CONFIG_BT_NIMBLE_SECURITY_ENABLE
    /* Keep SMP available for hosts that want an encrypted HID link. The
     * keyboard has no display or keypad, so use Just Works pairing with
     * bonding and LE Secure Connections. The HID module does not force an
     * early Security Request (BlueZ rejects that before discovery); the
     * passive observer never pairs. */
    ble_hs_cfg.sm_io_cap = BLE_SM_IO_CAP_NO_IO;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 0;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC |
                                 BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC |
                                   BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
#endif
    ble_store_config_init();
    hid_gatt_init();

    ble_hs_cfg.sync_cb = ble_on_sync;
    ble_hs_cfg.reset_cb = ble_on_reset;
    nimble_port_freertos_init(ble_host_task);

    if (xTaskCreate(ble_supervisor, "pwn_ble", 3072, NULL, 3,
                    &s_supervisor) != pdPASS) {
        ESP_LOGW(TAG, "BLE supervisor task create failed");
        return;
    }
    s_supported = true;
    ESP_LOGI(TAG, "NimBLE ready; scanner is off until enabled from the web UI");
#else
    ESP_LOGW(TAG, "NimBLE not available in this build; BLE scanner disabled");
#endif
}

bool ble_supported(void)
{
    return s_supported;
}

bool ble_set_enabled(bool on)
{
    if (on && !s_supported) {
        return false;
    }
    bool changed = (s_enabled != on);
    s_enabled = on;
    if (changed) {
        ESP_LOGW(TAG, "BLE scanner %s", on ? "enabled" : "disabled");
    }
    return true;
}

bool ble_enabled(void)
{
    return s_enabled;
}

bool ble_scanning(void)
{
    return s_scanning;
}

bool ble_gated(void)
{
    return s_gated;
}

bool ble_hid_set_active(bool on)
{
    bool changed = (s_hid_active != on);
    s_hid_active = on;
#if PWN_HAVE_NIMBLE
    if (on && changed) {
        /* Advertising and discovery cannot share the controller. Cancel the
         * observer synchronously before the HID module starts advertising. */
        ble_stop_scan();
    }
#endif
    if (changed) {
        ESP_LOGI(TAG, "HID mode %s; passive scanner %s", on ? "on" : "off",
                 on ? "paused" : "will resume if enabled");
    }
    return true;
}

bool ble_hid_active(void)
{
    return s_hid_active;
}

int ble_device_count(void)
{
    int n = 0;
    if (!s_lock || !s_devs) {
        return 0;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < PWN_BLE_MAX; i++) {
        if (s_devs[i].last_seen_ms) {
            n++;
        }
    }
    xSemaphoreGive(s_lock);
    return n;
}

int ble_snapshot(pwn_ble_dev_t *out, int max)
{
    if (!out || max <= 0 || !s_lock || !s_devs) {
        return 0;
    }
    int n = 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < PWN_BLE_MAX && n < max; i++) {
        if (s_devs[i].last_seen_ms) {
            out[n++] = s_devs[i];
        }
    }
    xSemaphoreGive(s_lock);
    return n;
}
