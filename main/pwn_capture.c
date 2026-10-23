#include "pwn_capture.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "bsp/esp-bsp.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdspi_host.h"
#include "esp_heap_caps.h"

static const char *TAG = "capture";

static pwn_handshake_t *s_slots;
static SemaphoreHandle_t s_lock;
static bool s_sd_ready;
static bool s_sd_mounted;
static bool s_sd_writable;
static bool s_sd_info_valid;
static uint64_t s_sd_total;
static uint64_t s_sd_free;
static uint32_t s_saved;
static uint32_t s_hs_count;
static uint32_t s_pmkid_count;

/* ---- pcap writer ------------------------------------------------------ */

static void pcap_global_header(FILE *f)
{
    uint32_t magic = 0xa1b2c3d4;
    uint16_t vmaj = 2, vmin = 4;
    uint32_t thiszone = 0, sigfigs = 0, snaplen = 65535, network = 127; /* radiotap */
    fwrite(&magic, 4, 1, f);
    fwrite(&vmaj, 2, 1, f);
    fwrite(&vmin, 2, 1, f);
    fwrite(&thiszone, 4, 1, f);
    fwrite(&sigfigs, 4, 1, f);
    fwrite(&snaplen, 4, 1, f);
    fwrite(&network, 4, 1, f);
}

static void pcap_packet(FILE *f, uint64_t ts_us, const uint8_t *data,
                        uint16_t len, uint8_t channel, int8_t rssi)
{
    /* Radiotap with channel and dBm antenna signal. The remaining bytes are
     * padding to a 24-byte header; Wireshark/aircrack ignore it. */
    uint8_t rtap[24] = {0};
    uint16_t freq = 2412;
    uint16_t flags = 0x0080; /* 2 GHz */
    if (channel >= 36) {
        freq = (uint16_t)(5000 + channel * 5);
        flags = 0x0100;      /* 5 GHz */
    } else if (channel >= 1) {
        freq = (uint16_t)(2412 + (channel - 1) * 5);
    }
    rtap[2] = sizeof(rtap);
    rtap[4] = 0x28;          /* present: channel + antenna signal */
    rtap[8] = (uint8_t)(freq & 0xff);
    rtap[9] = (uint8_t)(freq >> 8);
    rtap[10] = (uint8_t)(flags & 0xff);
    rtap[11] = (uint8_t)(flags >> 8);
    rtap[12] = (uint8_t)rssi;

    uint32_t ts_sec = (uint32_t)(ts_us / 1000000ULL);
    uint32_t ts_frac = (uint32_t)(ts_us % 1000000ULL);
    uint32_t incl = len + sizeof(rtap);
    uint32_t orig = incl;

    fwrite(&ts_sec, 4, 1, f);
    fwrite(&ts_frac, 4, 1, f);
    fwrite(&incl, 4, 1, f);
    fwrite(&orig, 4, 1, f);
    fwrite(rtap, 1, sizeof(rtap), f);
    fwrite(data, 1, len, f);
}

static void sanitize(char *dst, size_t dstlen, const char *src)
{
    size_t j = 0;
    for (size_t i = 0; src && src[i] && j + 1 < dstlen; i++) {
        char c = src[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_') {
            dst[j++] = c;
        } else if (c == ' ') {
            dst[j++] = '_';
        }
    }
    if (j == 0) {
        dst[j++] = 'h';
        dst[j++] = 's';
    }
    dst[j] = 0;
}

static void slot_save(pwn_handshake_t *h)
{
    if (!s_sd_ready) {
        return;
    }
    if (h->nframes == 0 || (h->msg_mask == 0 && !h->has_pmkid)) {
        return;
    }

    if (s_sd_info_valid && s_sd_free > 0 && s_sd_free < 1024 * 1024) {
        ESP_LOGW(TAG, "SD almost full (%llu bytes free); not saving %s",
                 (unsigned long long)s_sd_free, h->ssid);
        return;
    }

    char ssid[33];
    sanitize(ssid, sizeof(ssid), h->ssid);

    char name[64];
    snprintf(name, sizeof(name), "%s_%02x%02x%02x%02x%02x%02x.pcap",
             ssid, h->bssid[0], h->bssid[1], h->bssid[2],
             h->bssid[3], h->bssid[4], h->bssid[5]);
    char path[128];
    char tmp[128];
    snprintf(path, sizeof(path), PWN_HS_DIR "/%s", name);
    snprintf(tmp, sizeof(tmp), PWN_HS_DIR "/.tmp_%s", name);

    FILE *f = fopen(tmp, "wb");
    if (!f) {
        ESP_LOGW(TAG, "cannot open %s (errno %d)", tmp, errno);
        s_sd_ready = false;
        return;
    }
    pcap_global_header(f);
    uint64_t beacon_ts = h->nframes ? h->frames[0].ts_us
                                    : (uint64_t)esp_timer_get_time();
    if (h->bcn_len && h->bcn_len <= PWN_BCN_MAX) {
        pcap_packet(f, beacon_ts, h->bcn, h->bcn_len, h->channel, h->rssi);
    }
    for (int i = 0; i < h->nframes; i++) {
        pcap_packet(f, h->frames[i].ts_us, h->frames[i].data,
                    h->frames[i].len, h->channel, h->rssi);
    }
    bool bad = ferror(f) != 0;
    if (fclose(f) != 0) {
        bad = true;
    }
    if (!bad) {
        /* FATFS rename() does not replace an existing destination. */
        remove(path);
        if (rename(tmp, path) != 0) {
            bad = true;
        }
    }
    if (bad) {
        ESP_LOGW(TAG, "SD write/rename failed for %s (errno %d)", name, errno);
        remove(tmp);
        s_sd_ready = false;
        return;
    }

    bool first = !h->saved;
    h->saved = true;
    h->saved_frames = h->nframes;
    snprintf(h->file, sizeof(h->file), "%s", name);
    if (first) {
        s_saved++;
    }
    ESP_LOGI(TAG, "%s %s (%d frames, ch %u, rssi %d, bcn %u, mask 0x%x%s)",
             first ? "saved" : "updated", path, h->nframes, h->channel,
             h->rssi, h->bcn_len, h->msg_mask, h->has_pmkid ? ", pmkid" : "");
}

static void slot_reset(pwn_handshake_t *h)
{
    memset(h, 0, sizeof(*h));
}

static pwn_handshake_t *slot_for(const uint8_t *bssid, const uint8_t *sta)
{
    pwn_handshake_t *victim = NULL;
    pwn_handshake_t *oldest = NULL;

    for (int i = 0; i < PWN_MAX_HS; i++) {
        pwn_handshake_t *h = &s_slots[i];
        if (h->nframes > 0 && memcmp(h->bssid, bssid, 6) == 0 &&
            memcmp(h->sta, sta, 6) == 0) {
            return h;
        }
        if (h->nframes == 0 && !victim) {
            victim = h;
        }
        if (h->nframes > 0 && (!oldest || h->last_seen_ms < oldest->last_seen_ms)) {
            oldest = h;
        }
    }
    if (victim) {
        return victim;
    }
    if (oldest) {
        if (!oldest->saved || oldest->nframes > oldest->saved_frames) {
            slot_save(oldest);
        }
        slot_reset(oldest);
    }
    return oldest;
}

/* ---- SD card ---------------------------------------------------------- */

/* Mount the card ourselves so we can lower the SPI clock. The slot shares a
 * bus with the LCD; 20 MHz is marginal on this board and multi-block writes
 * come back as EIO. 10 MHz is reliable. */
static esp_err_t sd_mount(void)
{
    sdmmc_host_t host;
    bsp_sdcard_get_sdspi_host(SDSPI_DEFAULT_HOST, &host);
    host.max_freq_khz = 10000;

    sdspi_device_config_t *slot = calloc(1, sizeof(*slot));
    if (!slot) {
        return ESP_ERR_NO_MEM;
    }
    bsp_sdcard_sdspi_get_slot(BSP_LCD_SPI_NUM, slot);

    esp_vfs_fat_sdmmc_mount_config_t mcfg = {
        .format_if_mount_failed = false,
        .max_files = 8,
        .allocation_unit_size = 16 * 1024,
    };

    bsp_sdcard_cfg_t cfg = {
        .mount = &mcfg,
        .host = &host,
    };
    cfg.slot.sdspi = slot;

    /* This BSP helper also initialises the shared SPI bus on first use. */
    esp_err_t err = bsp_sdcard_sdspi_mount(&cfg);
    free(slot);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "SD mount failed: %s", esp_err_to_name(err));
        return err;
    }
    s_sd_mounted = true;

    sdmmc_card_t *card = bsp_sdcard_get_handle();
    sdmmc_card_print_info(stdout, card);

    /* Harmless write test: rewrite the card's last sector with its own
     * contents. This proves writes work without corrupting anything. */
    uint8_t *buf = heap_caps_malloc(512, MALLOC_CAP_DMA);
    if (buf && card) {
        uint32_t last = (uint32_t)card->csd.capacity - 1;
        esp_err_t r = sdmmc_read_sectors(card, buf, last, 1);
        esp_err_t w = sdmmc_write_sectors(card, buf, last, 1);
        ESP_LOGI(TAG, "sector %u read=%s write=%s", (unsigned)last,
                 esp_err_to_name(r), esp_err_to_name(w));
        s_sd_writable = (r == ESP_OK && w == ESP_OK);
        free(buf);
    }
    return ESP_OK;
}

static bool sd_prepare(void)
{
    mkdir(PWN_HS_DIR, 0777);
    mkdir(PWN_PCAP_DIR, 0777);

    FILE *probe = fopen(PWN_HS_DIR "/.probe", "wb");
    if (!probe) {
        ESP_LOGE(TAG, "SD probe open failed, errno %d", errno);
        s_sd_ready = false;
        return false;
    }
    size_t w = fwrite("pwni", 1, 4, probe);
    int cr = fclose(probe);
    ESP_LOGI(TAG, "SD probe write=%u close=%d", (unsigned)w, cr);
    s_sd_ready = (w == 4 && cr == 0 && s_sd_writable);
    if (s_sd_ready) {
        if (esp_vfs_fat_info(PWN_SD_MOUNT, &s_sd_total, &s_sd_free) == ESP_OK) {
            s_sd_info_valid = true;
        }
    }
    return s_sd_ready;
}

/* ---- public ----------------------------------------------------------- */

void capture_init(void)
{
    s_lock = xSemaphoreCreateMutex();
    s_slots = heap_caps_calloc(PWN_MAX_HS, sizeof(pwn_handshake_t),
                               MALLOC_CAP_SPIRAM);
    if (!s_slots) {
        s_slots = calloc(PWN_MAX_HS, sizeof(pwn_handshake_t));
    }
    if (!s_slots) {
        ESP_LOGE(TAG, "out of memory for handshake slots");
        return;
    }

    mkdir(PWN_SD_MOUNT, 0777);
    if (sd_mount() == ESP_OK) {
        sd_prepare();
        ESP_LOGI(TAG, "SD card mounted, handshakes -> " PWN_HS_DIR);
    } else {
        ESP_LOGW(TAG, "no SD card; handshakes kept in RAM only");
    }
    ESP_LOGI(TAG, "%d handshake slots, %d bytes each",
             PWN_MAX_HS, (int)sizeof(pwn_handshake_t));
}

void capture_add_eapol(const uint8_t *bssid, const uint8_t *sta,
                       const char *ssid, uint8_t msg,
                       const uint8_t *frame, uint16_t len,
                       const uint8_t *pmkid,
                       uint8_t channel, int8_t rssi,
                       const uint8_t *bcn, uint16_t bcn_len)
{
    if (!s_slots || !s_lock || len == 0 || len > PWN_FRAME_MAX) {
        return;
    }

    uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000);
    uint64_t now_us = (uint64_t)esp_timer_get_time();

    /* SD shares the SPI bus with the LCD. Take the display lock before the
     * capture lock so a save cannot overlap an LCD flush; see pwn_capture.h.
     * If the display is not up yet there is no flush to contend with. */
    bool bus = capture_bus_lock(portMAX_DELAY);

    xSemaphoreTake(s_lock, portMAX_DELAY);
    pwn_handshake_t *h = slot_for(bssid, sta);
    if (!h) {
        xSemaphoreGive(s_lock);
        if (bus) {
            capture_bus_unlock();
        }
        return;
    }

    if (h->nframes == 0) {
        memcpy(h->bssid, bssid, 6);
        memcpy(h->sta, sta, 6);
        h->first_seen_ms = now_ms;
        h->channel = channel;
        h->rssi = rssi;
        if (ssid && ssid[0]) {
            snprintf(h->ssid, sizeof(h->ssid), "%s", ssid);
        }
        if (bcn && bcn_len && bcn_len <= PWN_BCN_MAX) {
            memcpy(h->bcn, bcn, bcn_len);
            h->bcn_len = bcn_len;
        }
    } else {
        if (channel) {
            h->channel = channel;
        }
        h->rssi = rssi;
        if (!h->bcn_len && bcn && bcn_len && bcn_len <= PWN_BCN_MAX) {
            memcpy(h->bcn, bcn, bcn_len);
            h->bcn_len = bcn_len;
        }
    }
    h->last_seen_ms = now_ms;

    if (pmkid && !h->has_pmkid) {
        memcpy(h->pmkid, pmkid, 16);
        h->has_pmkid = true;
        s_pmkid_count++;
    }

    if (msg >= 1 && msg <= 4) {
        h->msg_mask |= (uint8_t)(1u << (msg - 1));
    }

    /* Only keep the first copy of each message; keep the frames small. */
    bool duplicate = false;
    for (int i = 0; i < h->nframes; i++) {
        if (h->frames[i].len == len &&
            memcmp(h->frames[i].data, frame, len) == 0) {
            duplicate = true;
            break;
        }
    }
    if (!duplicate && h->nframes < PWN_HS_FRAMES) {
        h->frames[h->nframes].ts_us = now_us;
        h->frames[h->nframes].len = len;
        memcpy(h->frames[h->nframes].data, frame, len);
        h->nframes++;
    }

    bool useful = h->has_pmkid ||
                  ((h->msg_mask & 0x03) == 0x03) ||
                  (h->msg_mask == 0x0F);

    if (useful && !h->counted) {
        h->counted = true;
        s_hs_count++;
    }
    /* Save once, then refresh the PCAP whenever another EAPOL message
     * lands so complete handshakes contain M2/M4 rather than just M1. */
    /* Only hit the SD card for a PMKID or a complete handshake.  Partial
     * M1+M2 slots stay in RAM until a complete handshake/eviction, which
     * avoids long SPI/SD writes while the display is flushing. */
    bool save_now = h->has_pmkid || (h->msg_mask == 0x0F);
    if (save_now && (!h->saved || h->nframes > h->saved_frames)) {
        slot_save(h);
    }
    if (h->msg_mask == 0x0F) {
        h->complete = true;
    }

    xSemaphoreGive(s_lock);
    if (bus) {
        capture_bus_unlock();
    }
}

uint32_t capture_handshake_count(void) { return s_hs_count; }
uint32_t capture_pmkid_count(void)     { return s_pmkid_count; }
uint32_t capture_saved_count(void)     { return s_saved; }
bool     capture_sd_ready(void)        { return s_sd_ready; }

bool capture_sd_info(pwn_sd_info_t *out)
{
    if (!out) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->ready = s_sd_ready;
    out->writable = s_sd_writable;
    out->total_bytes = s_sd_total;
    out->free_bytes = s_sd_free;
    return s_sd_ready;
}

bool capture_sd_remount(void)
{
    if (!capture_bus_lock(5000)) {
        return false;
    }
    if (s_sd_mounted) {
        sdmmc_card_t *card = bsp_sdcard_get_handle();
        if (card) {
            esp_vfs_fat_sdcard_unmount(PWN_SD_MOUNT, card);
        }
        s_sd_mounted = false;
        s_sd_ready = false;
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    esp_err_t err = sd_mount();
    bool ok = false;
    if (err == ESP_OK) {
        ok = sd_prepare();
        if (ok && esp_vfs_fat_info(PWN_SD_MOUNT, &s_sd_total, &s_sd_free) == ESP_OK) {
            s_sd_info_valid = true;
        }
    } else {
        ESP_LOGW(TAG, "SD remount failed: %s", esp_err_to_name(err));
    }
    if (!ok) {
        s_sd_info_valid = false;
        s_sd_total = 0;
        s_sd_free = 0;
    }
    capture_bus_unlock();
    ESP_LOGW(TAG, "SD remount: %s", ok ? "ready" : "not ready");
    return ok;
}

typedef struct {
    char name[64];
    time_t mtime;
} prune_ent_t;

static int prune_cmp(const void *a, const void *b)
{
    const prune_ent_t *x = (const prune_ent_t *)a;
    const prune_ent_t *y = (const prune_ent_t *)b;
    if (x->mtime < y->mtime) return -1;
    if (x->mtime > y->mtime) return 1;
    return strcmp(x->name, y->name);
}

int capture_sd_prune(int keep)
{
    if (!s_sd_ready || keep < 0) {
        return 0;
    }
    if (!capture_bus_lock(3000)) {
        return 0;
    }
    DIR *d = opendir(PWN_HS_DIR);
    if (!d) {
        capture_bus_unlock();
        return 0;
    }
    prune_ent_t *ents = calloc(256, sizeof(*ents));
    int n = 0;
    struct dirent *e;
    while (ents && n < 256 && (e = readdir(d)) != NULL) {
        size_t len = strlen(e->d_name);
        if (len < 6 || strcasecmp(e->d_name + len - 5, ".pcap") != 0) {
            continue;
        }
        snprintf(ents[n].name, sizeof(ents[n].name), "%s", e->d_name);
        char path[128];
        snprintf(path, sizeof(path), "%s/%s", PWN_HS_DIR, e->d_name);
        struct stat st;
        ents[n].mtime = (stat(path, &st) == 0) ? st.st_mtime : 0;
        n++;
    }
    closedir(d);

    int deleted = 0;
    if (ents && n > keep) {
        qsort(ents, n, sizeof(*ents), prune_cmp);
        for (int i = 0; i < n - keep; i++) {
            char path[128];
            snprintf(path, sizeof(path), "%s/%s", PWN_HS_DIR, ents[i].name);
            if (unlink(path) == 0) {
                deleted++;
                ESP_LOGW(TAG, "pruned %s", ents[i].name);
            }
        }
    }
    free(ents);
    if (deleted && esp_vfs_fat_info(PWN_SD_MOUNT, &s_sd_total, &s_sd_free) == ESP_OK) {
        s_sd_info_valid = true;
    }
    capture_bus_unlock();
    return deleted;
}

bool capture_bus_lock(uint32_t timeout_ms)
{
    return bsp_display_lock(timeout_ms) == ESP_OK;
}

void capture_bus_unlock(void)
{
    bsp_display_unlock();
}

int capture_snapshot(pwn_handshake_t *out, int max)
{
    if (!s_slots || !s_lock || !out) {
        return 0;
    }
    int n = 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < PWN_MAX_HS && n < max; i++) {
        if (s_slots[i].nframes > 0) {
            out[n++] = s_slots[i];
        }
    }
    xSemaphoreGive(s_lock);
    return n;
}

int capture_list_files(pwn_pcap_file_t *out, int max)
{
    if (!s_sd_ready || !out || max <= 0) {
        return 0;
    }
    if (!capture_bus_lock(2000)) {
        return 0;
    }
    DIR *d = opendir(PWN_HS_DIR);
    if (!d) {
        capture_bus_unlock();
        return 0;
    }
    int n = 0;
    struct dirent *e;
    while (n < max && (e = readdir(d)) != NULL) {
        size_t len = strlen(e->d_name);
        if (len < 6 || strcasecmp(e->d_name + len - 5, ".pcap") != 0) {
            continue;
        }
        snprintf(out[n].name, sizeof(out[n].name), "%s", e->d_name);
        char path[128];
        snprintf(path, sizeof(path), "%s/%s", PWN_HS_DIR, e->d_name);
        struct stat st;
        out[n].size = (stat(path, &st) == 0) ? (uint32_t)st.st_size : 0;
        n++;
    }
    closedir(d);
    capture_bus_unlock();
    return n;
}

void capture_flush_all(void)
{
    if (!s_slots || !s_lock) {
        return;
    }
    bool bus = capture_bus_lock(portMAX_DELAY);
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < PWN_MAX_HS; i++) {
        if (s_slots[i].nframes > 0 &&
            (!s_slots[i].saved || s_slots[i].nframes > s_slots[i].saved_frames)) {
            slot_save(&s_slots[i]);
        }
    }
    xSemaphoreGive(s_lock);
    if (bus) {
        capture_bus_unlock();
    }
}
