#include "pwn_hid.h"

#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "pwn_capture.h"
#include "pwn_wifi.h"
#include "pwn_ble.h"
#include "esp_lv_adapter.h"

#if __has_include("nimble/nimble_port.h")
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "host/ble_store.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#define PWN_HAVE_NIMBLE 1
#else
#define PWN_HAVE_NIMBLE 0
#endif

static const char *TAG = "hid";

static void hid_supervisor(void *arg);

/* ---- state ------------------------------------------------------------ */

static SemaphoreHandle_t s_lock;
static TaskHandle_t s_task;
static TaskHandle_t s_supervisor;
static volatile bool s_supported;
static volatile bool s_active;
static volatile bool s_connected;
static volatile bool s_encrypted;
static volatile bool s_boot_mode;
static volatile bool s_executing;
static volatile bool s_abort;
static volatile bool s_display_paused;
static volatile bool s_notify_report;
static volatile bool s_notify_boot;
static volatile bool s_need_adv;
static volatile uint16_t s_conn = 0xffff;
static volatile uint32_t s_active_since_ms;
static volatile uint32_t s_line;
static volatile uint32_t s_lines;
static volatile uint32_t s_chars;
static volatile pwn_hid_state_t s_state = PWN_HID_OFF;
static char s_selected[PWN_HID_PAYLOAD_NAME_MAX];
static char s_error[96];

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

static void hid_event(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void hid_event(const char *fmt, ...)
{
    char msg[76];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    pwn_wifi_event("HID: %s", msg);
}

static void set_error(const char *msg)
{
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    snprintf(s_error, sizeof(s_error), "%.*s",
             (int)sizeof(s_error) - 1, msg ? msg : "");
    s_state = PWN_HID_ERROR;
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }
}

static void clear_error(void)
{
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    s_error[0] = 0;
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }
}

/* ---- payload files ---------------------------------------------------- */

static bool payload_name_ok(const char *name)
{
    if (!name || !name[0]) {
        return false;
    }
    size_t n = strlen(name);
    if (n >= PWN_HID_PAYLOAD_NAME_MAX) {
        return false;
    }
    if (strchr(name, '/') || strchr(name, '\\') ||
        strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        return false;
    }
    /* Keep names shell- and URL-friendly; the dashboard encodes the upload
     * query string, so do not accept '%' or spaces here. */
    for (const char *p = name; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-' && *p != '.') {
            return false;
        }
    }
    size_t slen = strlen(name);
    return slen > 4 && strcasecmp(name + slen - 4, ".txt") == 0;
}

static void payload_path(const char *name, char *out, size_t outlen)
{
    snprintf(out, outlen, "%s/%.*s", PWN_HID_PAYLOAD_DIR,
             PWN_HID_PAYLOAD_NAME_MAX - 1, name);
}

static bool payload_exists(const char *name)
{
    if (!payload_name_ok(name) || !capture_sd_ready()) {
        return false;
    }
    char path[160];
    payload_path(name, path, sizeof(path));
    bool ok = false;
    if (capture_bus_lock(1000)) {
        struct stat st;
        ok = (stat(path, &st) == 0 && S_ISREG(st.st_mode));
        capture_bus_unlock();
    }
    return ok;
}

int hid_list_payloads(pwn_hid_payload_t *out, int max)
{
    if (!out || max <= 0 || !capture_sd_ready()) {
        return 0;
    }
    int n = 0;
    if (!capture_bus_lock(1500)) {
        return 0;
    }
    DIR *d = opendir(PWN_HID_PAYLOAD_DIR);
    if (!d) {
        capture_bus_unlock();
        return 0;
    }
    struct dirent *e;
    while (n < max && (e = readdir(d)) != NULL) {
        if (!payload_name_ok(e->d_name)) {
            continue;
        }
        char path[160];
        payload_path(e->d_name, path, sizeof(path));
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }
        snprintf(out[n].name, sizeof(out[n].name), "%.*s",
                 (int)sizeof(out[n].name) - 1, e->d_name);
        out[n].size = st.st_size > 0 ? (uint32_t)st.st_size : 0;
        n++;
    }
    closedir(d);
    capture_bus_unlock();

    /* Stable alphabetical order for the dashboard. */
    for (int i = 1; i < n; i++) {
        pwn_hid_payload_t tmp = out[i];
        int j = i - 1;
        while (j >= 0 && strcasecmp(out[j].name, tmp.name) > 0) {
            out[j + 1] = out[j];
            j--;
        }
        out[j + 1] = tmp;
    }
    return n;
}

bool hid_write_payload(const char *name, const char *data, size_t len,
                       char *err, size_t errsz)
{
    if (!payload_name_ok(name)) {
        snprintf(err, errsz, "invalid name (use a .txt file name)");
        return false;
    }
    if (!data || len == 0 || len > PWN_HID_PAYLOAD_MAX) {
        snprintf(err, errsz, "payload must be 1..%d bytes", PWN_HID_PAYLOAD_MAX);
        return false;
    }
    if (!capture_sd_ready()) {
        snprintf(err, errsz, "SD card not ready");
        return false;
    }
    char path[160];
    char tmp[176];
    payload_path(name, path, sizeof(path));
    snprintf(tmp, sizeof(tmp), "%s/.upload.tmp", PWN_HID_PAYLOAD_DIR);
    if (!capture_bus_lock(3000)) {
        snprintf(err, errsz, "SD card busy");
        return false;
    }
    mkdir(PWN_HID_PAYLOAD_DIR, 0777);
    FILE *f = fopen(tmp, "wb");
    if (!f) {
        capture_bus_unlock();
        snprintf(err, errsz, "cannot create payload");
        return false;
    }
    size_t wrote = fwrite(data, 1, len, f);
    int cr = fclose(f);
    if (wrote != len || cr != 0) {
        remove(tmp);
        capture_bus_unlock();
        snprintf(err, errsz, "SD write failed");
        return false;
    }
    remove(path);
    if (rename(tmp, path) != 0) {
        remove(tmp);
        capture_bus_unlock();
        snprintf(err, errsz, "cannot finalise payload");
        return false;
    }
    capture_bus_unlock();
    hid_select(name);
    ESP_LOGI(TAG, "saved payload %s (%u bytes)", name, (unsigned)len);
    return true;
}

static char *payload_read(const char *name, size_t *out_len,
                          char *err, size_t errsz)
{
    if (!payload_name_ok(name)) {
        snprintf(err, errsz, "invalid payload name");
        return NULL;
    }
    if (!capture_sd_ready()) {
        snprintf(err, errsz, "SD card not ready");
        return NULL;
    }
    char path[160];
    payload_path(name, path, sizeof(path));
    if (!capture_bus_lock(2000)) {
        snprintf(err, errsz, "SD card busy");
        return NULL;
    }
    FILE *f = fopen(path, "rb");
    if (!f) {
        snprintf(err, errsz, "cannot open payload");
        capture_bus_unlock();
        return NULL;
    }
    long sz = -1;
    if (fseek(f, 0, SEEK_END) == 0) {
        sz = ftell(f);
    }
    if (sz <= 0 || sz > PWN_HID_PAYLOAD_MAX) {
        fclose(f);
        capture_bus_unlock();
        snprintf(err, errsz, sz <= 0 ? "payload is empty" : "payload too large");
        return NULL;
    }
    rewind(f);
    char *buf = heap_caps_malloc((size_t)sz + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!buf) {
        buf = malloc((size_t)sz + 1);
    }
    if (!buf) {
        fclose(f);
        capture_bus_unlock();
        snprintf(err, errsz, "out of memory");
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    capture_bus_unlock();
    if (got == 0) {
        free(buf);
        snprintf(err, errsz, "cannot read payload");
        return NULL;
    }
    buf[got] = 0;
    *out_len = got;
    return buf;
}

bool hid_select(const char *name)
{
    if (!payload_exists(name)) {
        return false;
    }
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    snprintf(s_selected, sizeof(s_selected), "%.*s",
             (int)sizeof(s_selected) - 1, name);
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }
    return true;
}

/* ---- HID report map and GATT ----------------------------------------- */

#if PWN_HAVE_NIMBLE

/* Keyboard-only report descriptor: modifiers, reserved byte, five LED bits,
 * and a six-key array. Report ID 2 keeps it compatible with hosts that use
 * report protocol; the boot input characteristic covers boot protocol. */
static const uint8_t s_report_map[] = {
    0x05, 0x01,       /* Usage Page (Generic Desktop) */
    0x09, 0x06,       /* Usage (Keyboard) */
    0xA1, 0x01,       /* Collection (Application) */
    0x85, 0x02,       /*   Report ID (2) */
    0x05, 0x07,       /*   Usage Page (Key Codes) */
    0x19, 0xE0,       /*   Usage Minimum (224) */
    0x29, 0xE7,       /*   Usage Maximum (231) */
    0x15, 0x00,       /*   Logical Minimum (0) */
    0x25, 0x01,       /*   Logical Maximum (1) */
    0x75, 0x01,       /*   Report Size (1) */
    0x95, 0x08,       /*   Report Count (8) */
    0x81, 0x02,       /*   Input (Data, Variable, Absolute) - modifiers */
    0x95, 0x01,       /*   Report Count (1) */
    0x75, 0x08,       /*   Report Size (8) */
    0x81, 0x01,       /*   Input (Constant) - reserved */
    0x95, 0x05,       /*   Report Count (5) */
    0x75, 0x01,       /*   Report Size (1) */
    0x05, 0x08,       /*   Usage Page (LEDs) */
    0x19, 0x01,       /*   Usage Minimum (1) */
    0x29, 0x05,       /*   Usage Maximum (5) */
    0x91, 0x02,       /*   Output (Data, Variable, Absolute) - LEDs */
    0x95, 0x01,       /*   Report Count (1) */
    0x75, 0x03,       /*   Report Size (3) */
    0x91, 0x01,       /*   Output (Constant) - padding */
    0x95, 0x06,       /*   Report Count (6) */
    0x75, 0x08,       /*   Report Size (8) */
    0x15, 0x00,       /*   Logical Minimum (0) */
    0x25, 0x65,       /*   Logical Maximum (101) */
    0x05, 0x07,       /*   Usage Page (Key Codes) */
    0x19, 0x00,       /*   Usage Minimum (0) */
    0x29, 0x65,       /*   Usage Maximum (101) */
    0x81, 0x00,       /*   Input (Data, Array) - keys */
    0xC0,             /* End Collection */
};

static const uint8_t s_hid_info[4] = { 0x11, 0x01, 0x00, 0x02 };

enum {
    HID_CHR_INFO = 1,
    HID_CHR_REPORT_MAP,
    HID_CHR_CONTROL,
    HID_CHR_PROTO,
    HID_CHR_REPORT_IN,
    HID_CHR_REPORT_OUT,
    HID_CHR_BOOT_IN,
    HID_CHR_BOOT_OUT,
    HID_DSC_EXT_REF,
    HID_DSC_REF_IN,
    HID_DSC_REF_OUT,
};

static uint8_t s_last_report[8];
static uint8_t s_last_boot[8];
static uint8_t s_leds;
static uint8_t s_addr_type;
static volatile bool s_ble_synced;

static uint16_t s_report_in_handle;
static uint16_t s_report_out_handle;
static uint16_t s_boot_in_handle;
static uint16_t s_boot_out_handle;

static int hid_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                         struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)conn_handle;
    (void)attr_handle;
    int id = (int)(intptr_t)arg;
    int rc;

    switch (id) {
    case HID_CHR_INFO:
        if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR) {
            return BLE_ATT_ERR_UNLIKELY;
        }
        rc = os_mbuf_append(ctxt->om, s_hid_info, sizeof(s_hid_info));
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;

    case HID_CHR_REPORT_MAP:
        if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR) {
            return BLE_ATT_ERR_UNLIKELY;
        }
        rc = os_mbuf_append(ctxt->om, s_report_map, sizeof(s_report_map));
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;

    case HID_CHR_CONTROL:
        if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
            return BLE_ATT_ERR_UNLIKELY;
        }
        return 0;

    case HID_CHR_PROTO:
        if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
            uint8_t mode = s_boot_mode ? 0 : 1;
            rc = os_mbuf_append(ctxt->om, &mode, 1);
            return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        }
        if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
            uint8_t mode = 1;
            if (OS_MBUF_PKTLEN(ctxt->om) != 1 ||
                ble_hs_mbuf_to_flat(ctxt->om, &mode, 1, NULL) != 0) {
                return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
            }
            s_boot_mode = (mode == 0);
            return 0;
        }
        return BLE_ATT_ERR_UNLIKELY;

    case HID_CHR_REPORT_IN:
        if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR) {
            return BLE_ATT_ERR_UNLIKELY;
        }
        rc = os_mbuf_append(ctxt->om, s_last_report, sizeof(s_last_report));
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;

    case HID_CHR_REPORT_OUT:
        if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
            rc = os_mbuf_append(ctxt->om, &s_leds, 1);
            return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        }
        if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
            if (OS_MBUF_PKTLEN(ctxt->om) < 1 ||
                ble_hs_mbuf_to_flat(ctxt->om, &s_leds, 1, NULL) != 0) {
                return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
            }
            return 0;
        }
        return BLE_ATT_ERR_UNLIKELY;

    case HID_CHR_BOOT_IN:
        if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR) {
            return BLE_ATT_ERR_UNLIKELY;
        }
        rc = os_mbuf_append(ctxt->om, s_last_boot, sizeof(s_last_boot));
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;

    case HID_CHR_BOOT_OUT:
        if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
            rc = os_mbuf_append(ctxt->om, &s_leds, 1);
            return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        }
        if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
            if (OS_MBUF_PKTLEN(ctxt->om) < 1 ||
                ble_hs_mbuf_to_flat(ctxt->om, &s_leds, 1, NULL) != 0) {
                return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
            }
            return 0;
        }
        return BLE_ATT_ERR_UNLIKELY;

    case HID_DSC_EXT_REF: {
        /* External Report Reference points at the boot keyboard input. */
        uint8_t ref[2] = { 0x22, 0x2A }; /* little-endian 0x2A22 */
        if (ctxt->op != BLE_GATT_ACCESS_OP_READ_DSC) {
            return BLE_ATT_ERR_UNLIKELY;
        }
        rc = os_mbuf_append(ctxt->om, ref, sizeof(ref));
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }

    case HID_DSC_REF_IN: {
        uint8_t ref[2] = { 0x02, 0x01 }; /* report ID 2, input */
        if (ctxt->op != BLE_GATT_ACCESS_OP_READ_DSC) {
            return BLE_ATT_ERR_UNLIKELY;
        }
        rc = os_mbuf_append(ctxt->om, ref, sizeof(ref));
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }

    case HID_DSC_REF_OUT: {
        uint8_t ref[2] = { 0x02, 0x02 }; /* report ID 2, output */
        if (ctxt->op != BLE_GATT_ACCESS_OP_READ_DSC) {
            return BLE_ATT_ERR_UNLIKELY;
        }
        rc = os_mbuf_append(ctxt->om, ref, sizeof(ref));
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }

    default:
        return BLE_ATT_ERR_UNLIKELY;
    }
}

static const struct ble_gatt_dsc_def s_dsc_ext_ref[] = { {
    .uuid = BLE_UUID16_DECLARE(0x2907),
    .att_flags = BLE_ATT_F_READ,
    .access_cb = hid_access_cb,
    .arg = (void *)(intptr_t)HID_DSC_EXT_REF,
}, { 0 } };

static const struct ble_gatt_dsc_def s_dsc_ref_in[] = { {
    .uuid = BLE_UUID16_DECLARE(0x2908),
    .att_flags = BLE_ATT_F_READ,
    .access_cb = hid_access_cb,
    .arg = (void *)(intptr_t)HID_DSC_REF_IN,
}, { 0 } };

static const struct ble_gatt_dsc_def s_dsc_ref_out[] = { {
    .uuid = BLE_UUID16_DECLARE(0x2908),
    .att_flags = BLE_ATT_F_READ,
    .access_cb = hid_access_cb,
    .arg = (void *)(intptr_t)HID_DSC_REF_OUT,
}, { 0 } };

static const struct ble_gatt_svc_def s_hid_svcs[] = { {
    .type = BLE_GATT_SVC_TYPE_PRIMARY,
    .uuid = BLE_UUID16_DECLARE(0x1812), /* HID service */
    .characteristics = (struct ble_gatt_chr_def[]) {
        {
            .uuid = BLE_UUID16_DECLARE(0x2A4A), /* HID Information */
            .access_cb = hid_access_cb,
            .arg = (void *)(intptr_t)HID_CHR_INFO,
            .flags = BLE_GATT_CHR_F_READ,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2A4B), /* Report Map */
            .access_cb = hid_access_cb,
            .arg = (void *)(intptr_t)HID_CHR_REPORT_MAP,
            .flags = BLE_GATT_CHR_F_READ,
            .descriptors = (struct ble_gatt_dsc_def *)s_dsc_ext_ref,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2A4C), /* HID Control Point */
            .access_cb = hid_access_cb,
            .arg = (void *)(intptr_t)HID_CHR_CONTROL,
            .flags = BLE_GATT_CHR_F_WRITE,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2A4E), /* Protocol Mode */
            .access_cb = hid_access_cb,
            .arg = (void *)(intptr_t)HID_CHR_PROTO,
            .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2A4D), /* Report: keyboard input */
            .access_cb = hid_access_cb,
            .arg = (void *)(intptr_t)HID_CHR_REPORT_IN,
            .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
            .val_handle = &s_report_in_handle,
            .descriptors = (struct ble_gatt_dsc_def *)s_dsc_ref_in,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2A4D), /* Report: keyboard LEDs */
            .access_cb = hid_access_cb,
            .arg = (void *)(intptr_t)HID_CHR_REPORT_OUT,
            .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE |
                     BLE_GATT_CHR_F_WRITE_NO_RSP,
            .val_handle = &s_report_out_handle,
            .descriptors = (struct ble_gatt_dsc_def *)s_dsc_ref_out,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2A22), /* Boot Keyboard Input */
            .access_cb = hid_access_cb,
            .arg = (void *)(intptr_t)HID_CHR_BOOT_IN,
            .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
            .val_handle = &s_boot_in_handle,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2A32), /* Boot Keyboard Output */
            .access_cb = hid_access_cb,
            .arg = (void *)(intptr_t)HID_CHR_BOOT_OUT,
            .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE |
                     BLE_GATT_CHR_F_WRITE_NO_RSP,
            .val_handle = &s_boot_out_handle,
        }, {
            0,
        },
    },
}, {
    0,
} };

static bool hid_notify(uint16_t handle, const uint8_t *data, size_t len)
{
    if (!s_active || !s_connected || s_conn == 0xffff || handle == 0) {
        return false;
    }
    struct os_mbuf *om = ble_hs_mbuf_from_flat(data, (uint16_t)len);
    if (!om) {
        return false;
    }
    int rc = ble_gatts_notify_custom(s_conn, handle, om);
    if (rc != 0) {
        ESP_LOGW(TAG, "notify handle %u failed: %d", handle, rc);
        return false;
    }
    return true;
}

static bool hid_send_report(uint8_t modifiers, uint8_t key)
{
    bool boot = s_boot_mode && s_notify_boot;
    uint16_t handle = boot ? s_boot_in_handle :
        (s_notify_report ? s_report_in_handle :
         (s_notify_boot ? s_boot_in_handle : 0));
    if (!handle) {
        return false;
    }
    uint8_t report[8] = { modifiers, 0, key, 0, 0, 0, 0, 0 };
    memcpy(boot ? s_last_boot : s_last_report, report, sizeof(report));
    if (!hid_notify(handle, report, sizeof(report))) {
        return false;
    }
    return true;
}

static bool hid_abortable_delay(uint32_t ms)
{
    uint32_t start = now_ms();
    while ((now_ms() - start) < ms) {
        if (s_abort || !s_active || !s_connected) {
            return false;
        }
        uint32_t left = ms - (now_ms() - start);
        vTaskDelay(pdMS_TO_TICKS(left > 20 ? 20 : (left ? left : 1)));
    }
    return !(s_abort || !s_active || !s_connected);
}

static bool hid_send_key(uint8_t modifiers, uint8_t key, uint32_t after_ms)
{
    if (!hid_send_report(modifiers, key)) {
        return false;
    }
    /* Hold the key long enough to cover a typical BLE connection interval;
     * a 10 ms press can be missed when the host polls every 30 ms. */
    if (!hid_abortable_delay(30)) {
        /* Never leave a key pressed if the run is cancelled. */
        hid_send_report(0, 0);
        return false;
    }
    if (!hid_send_report(0, 0)) {
        return false;
    }
    if (after_ms && !hid_abortable_delay(after_ms)) {
        return false;
    }
    return hid_abortable_delay(12);
}

/* ---- US keyboard layout ---------------------------------------------- */

static bool char_to_key(char c, uint8_t *key, uint8_t *mod)
{
    *mod = 0;
    if (c >= 'a' && c <= 'z') {
        *key = (uint8_t)(0x04 + (c - 'a'));
        return true;
    }
    if (c >= 'A' && c <= 'Z') {
        *key = (uint8_t)(0x04 + (c - 'A'));
        *mod = 0x02;
        return true;
    }
    if (c >= '1' && c <= '9') {
        *key = (uint8_t)(0x1E + (c - '1'));
        return true;
    }
    if (c == '0') {
        *key = 0x27;
        return true;
    }
    switch (c) {
    case ' ':  *key = 0x2C; return true;
    case '\t': *key = 0x2B; return true;
    case '\n': *key = 0x28; return true;
    case '-':  *key = 0x2D; return true;
    case '_':  *key = 0x2D; *mod = 0x02; return true;
    case '=':  *key = 0x2E; return true;
    case '+':  *key = 0x2E; *mod = 0x02; return true;
    case '[':  *key = 0x2F; return true;
    case '{':  *key = 0x2F; *mod = 0x02; return true;
    case ']':  *key = 0x30; return true;
    case '}':  *key = 0x30; *mod = 0x02; return true;
    case '\\': *key = 0x31; return true;
    case '|':  *key = 0x31; *mod = 0x02; return true;
    case ';':  *key = 0x33; return true;
    case ':':  *key = 0x33; *mod = 0x02; return true;
    case '\'': *key = 0x34; return true;
    case '"':  *key = 0x34; *mod = 0x02; return true;
    case '`':  *key = 0x35; return true;
    case '~':  *key = 0x35; *mod = 0x02; return true;
    case ',':  *key = 0x36; return true;
    case '<':  *key = 0x36; *mod = 0x02; return true;
    case '.':  *key = 0x37; return true;
    case '>':  *key = 0x37; *mod = 0x02; return true;
    case '/':  *key = 0x38; return true;
    case '?':  *key = 0x38; *mod = 0x02; return true;
    case '!':  *key = 0x1E; *mod = 0x02; return true;
    case '@':  *key = 0x1F; *mod = 0x02; return true;
    case '#':  *key = 0x20; *mod = 0x02; return true;
    case '$':  *key = 0x21; *mod = 0x02; return true;
    case '%':  *key = 0x22; *mod = 0x02; return true;
    case '^':  *key = 0x23; *mod = 0x02; return true;
    case '&':  *key = 0x24; *mod = 0x02; return true;
    case '*':  *key = 0x25; *mod = 0x02; return true;
    case '(':  *key = 0x26; *mod = 0x02; return true;
    case ')':  *key = 0x27; *mod = 0x02; return true;
    default:
        return false;
    }
}

static int modifier_bit(const char *tok)
{
    if (!strcasecmp(tok, "CTRL") || !strcasecmp(tok, "CONTROL") ||
        !strcasecmp(tok, "LCTRL")) {
        return 0x01;
    }
    if (!strcasecmp(tok, "SHIFT") || !strcasecmp(tok, "LSHIFT")) {
        return 0x02;
    }
    if (!strcasecmp(tok, "ALT") || !strcasecmp(tok, "LALT")) {
        return 0x04;
    }
    if (!strcasecmp(tok, "GUI") || !strcasecmp(tok, "WIN") ||
        !strcasecmp(tok, "WINDOWS") || !strcasecmp(tok, "LGUI") ||
        !strcasecmp(tok, "COMMAND") || !strcasecmp(tok, "CMD") ||
        !strcasecmp(tok, "META")) {
        return 0x08;
    }
    if (!strcasecmp(tok, "RCTRL")) {
        return 0x10;
    }
    if (!strcasecmp(tok, "RSHIFT")) {
        return 0x20;
    }
    if (!strcasecmp(tok, "RALT")) {
        return 0x40;
    }
    if (!strcasecmp(tok, "RGUI")) {
        return 0x80;
    }
    return -1;
}

static bool key_name_usage(const char *tok, uint8_t *key, uint8_t *mod)
{
    if (strlen(tok) == 1) {
        return char_to_key(tok[0], key, mod);
    }
    *mod = 0;
    if (!strcasecmp(tok, "ENTER") || !strcasecmp(tok, "RETURN")) *key = 0x28;
    else if (!strcasecmp(tok, "ESC") || !strcasecmp(tok, "ESCAPE")) *key = 0x29;
    else if (!strcasecmp(tok, "BACKSPACE") || !strcasecmp(tok, "BKSP")) *key = 0x2A;
    else if (!strcasecmp(tok, "TAB")) *key = 0x2B;
    else if (!strcasecmp(tok, "SPACE")) *key = 0x2C;
    else if (!strcasecmp(tok, "CAPSLOCK")) *key = 0x39;
    else if (!strcasecmp(tok, "F1")) *key = 0x3A;
    else if (!strcasecmp(tok, "F2")) *key = 0x3B;
    else if (!strcasecmp(tok, "F3")) *key = 0x3C;
    else if (!strcasecmp(tok, "F4")) *key = 0x3D;
    else if (!strcasecmp(tok, "F5")) *key = 0x3E;
    else if (!strcasecmp(tok, "F6")) *key = 0x3F;
    else if (!strcasecmp(tok, "F7")) *key = 0x40;
    else if (!strcasecmp(tok, "F8")) *key = 0x41;
    else if (!strcasecmp(tok, "F9")) *key = 0x42;
    else if (!strcasecmp(tok, "F10")) *key = 0x43;
    else if (!strcasecmp(tok, "F11")) *key = 0x44;
    else if (!strcasecmp(tok, "F12")) *key = 0x45;
    else if (!strcasecmp(tok, "PRINTSCREEN")) *key = 0x46;
    else if (!strcasecmp(tok, "SCROLLLOCK")) *key = 0x47;
    else if (!strcasecmp(tok, "PAUSE")) *key = 0x48;
    else if (!strcasecmp(tok, "INSERT") || !strcasecmp(tok, "INS")) *key = 0x49;
    else if (!strcasecmp(tok, "HOME")) *key = 0x4A;
    else if (!strcasecmp(tok, "PAGEUP") || !strcasecmp(tok, "PGUP")) *key = 0x4B;
    else if (!strcasecmp(tok, "DELETE") || !strcasecmp(tok, "DEL")) *key = 0x4C;
    else if (!strcasecmp(tok, "END")) *key = 0x4D;
    else if (!strcasecmp(tok, "PAGEDOWN") || !strcasecmp(tok, "PGDN")) *key = 0x4E;
    else if (!strcasecmp(tok, "RIGHT") || !strcasecmp(tok, "RIGHTARROW")) *key = 0x4F;
    else if (!strcasecmp(tok, "LEFT") || !strcasecmp(tok, "LEFTARROW")) *key = 0x50;
    else if (!strcasecmp(tok, "DOWN") || !strcasecmp(tok, "DOWNARROW")) *key = 0x51;
    else if (!strcasecmp(tok, "UP") || !strcasecmp(tok, "UPARROW")) *key = 0x52;
    else if (!strcasecmp(tok, "NUMLOCK")) *key = 0x53;
    else if (!strcasecmp(tok, "MENU") || !strcasecmp(tok, "APP")) *key = 0x65;
    else return false;
    return true;
}

/* ---- payload execution ------------------------------------------------ */

static bool type_text(const char *s, uint32_t default_delay)
{
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (s_abort || !s_active || !s_connected) {
            return false;
        }
        if (*p == '\r') {
            continue;
        }
        if (*p >= 0x80) {
            /* US layout only; skip UTF-8 bytes rather than sending nonsense. */
            while (p[1] >= 0x80 && p[1]) {
                p++;
            }
            continue;
        }
        uint8_t key = 0, mod = 0;
        if (!char_to_key((char)*p, &key, &mod)) {
            continue;
        }
        if (!hid_send_key(mod, key, default_delay)) {
            return false;
        }
        s_chars++;
    }
    return true;
}

static void trim(char *s)
{
    char *p = s;
    while (*p && isspace((unsigned char)*p)) {
        p++;
    }
    if (p != s) {
        memmove(s, p, strlen(p) + 1);
    }
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1])) {
        s[--n] = 0;
    }
}

static bool line_command(const char *line, const char *cmd, const char **rest)
{
    size_t n = strlen(cmd);
    if (strncasecmp(line, cmd, n) != 0) {
        return false;
    }
    if (line[n] != 0 && !isspace((unsigned char)line[n])) {
        return false;
    }
    const char *p = line + n;
    while (*p && isspace((unsigned char)*p)) {
        p++;
    }
    if (rest) {
        *rest = p;
    }
    return true;
}

static uint32_t parse_delay(const char *s, bool *ok)
{
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    *ok = (end && end != s && errno == 0 && *end == 0 && v <= 600000UL);
    return (uint32_t)v;
}

/* Returns 1 when the line was a key command, 0 when it is plain text, and
 * -1 for a malformed key command. */
static int run_key_line(const char *line, uint32_t default_delay)
{
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%.*s", (int)sizeof(tmp) - 1, line);
    for (char *p = tmp; *p; p++) {
        if (*p == '+') {
            *p = ' ';
        }
    }

    uint8_t mod = 0, key = 0;
    bool have_key = false, saw_mod = false;
    char *save = NULL;
    for (char *tok = strtok_r(tmp, " \t", &save);
         tok; tok = strtok_r(NULL, " \t", &save)) {
        int mb = modifier_bit(tok);
        if (mb >= 0) {
            if (have_key) {
                return -1;
            }
            mod |= (uint8_t)mb;
            saw_mod = true;
            continue;
        }
        if (have_key) {
            return -1;
        }
        uint8_t k = 0, km = 0;
        if (!key_name_usage(tok, &k, &km)) {
            if (saw_mod) {
                return -1;
            }
            return 0;
        }
        key = k;
        mod |= km;
        have_key = true;
    }

    if (!saw_mod && !have_key) {
        return 0;
    }
    if (!hid_send_key(mod, have_key ? key : 0, default_delay)) {
        return -1;
    }
    s_chars++;
    return 1;
}

static void run_task(void *arg)
{
    char *data = (char *)arg;
    size_t len = strlen(data);
    size_t pos = 0;
    uint32_t default_delay = 0;
    char err[96] = "";

    uint32_t lines = 1;
    for (size_t i = 0; i < len; i++) {
        if (data[i] == '\n') {
            lines++;
        }
    }
    s_lines = lines;
    s_line = 0;
    s_chars = 0;

    while (pos < len && !s_abort && s_active && s_connected) {
        size_t start = pos;
        while (pos < len && data[pos] != '\n') {
            pos++;
        }
        size_t l = pos - start;
        if (pos < len) {
            pos++;
        }
        if (l >= sizeof(err) * 4) {
            snprintf(err, sizeof(err), "line %u is too long", (unsigned)(s_line + 1));
            break;
        }
        char line[256];
        size_t copy = l < sizeof(line) - 1 ? l : sizeof(line) - 1;
        memcpy(line, data + start, copy);
        line[copy] = 0;
        if (copy < l) {
            snprintf(err, sizeof(err), "line %u is too long", (unsigned)(s_line + 1));
            break;
        }
        trim(line);
        s_line++;
        if (!line[0]) {
            continue;
        }
        if (line_command(line, "REM", NULL)) {
            continue;
        }
        const char *rest = NULL;
        if (line_command(line, "DELAY", &rest)) {
            bool ok = false;
            uint32_t ms = parse_delay(rest, &ok);
            if (!ok) {
                snprintf(err, sizeof(err), "line %u: bad DELAY", (unsigned)s_line);
                break;
            }
            if (!hid_abortable_delay(ms)) {
                break;
            }
            continue;
        }
        if (line_command(line, "DEFAULTDELAY", &rest) ||
            line_command(line, "DEFAULT_DELAY", &rest)) {
            bool ok = false;
            uint32_t ms = parse_delay(rest, &ok);
            if (!ok) {
                snprintf(err, sizeof(err), "line %u: bad DEFAULTDELAY", (unsigned)s_line);
                break;
            }
            default_delay = ms;
            continue;
        }
        if (line_command(line, "STRINGLN", &rest)) {
            if (!type_text(rest, default_delay) ||
                !hid_send_key(0, 0x28, default_delay)) {
                break;
            }
            s_chars++;
            continue;
        }
        if (line_command(line, "STRING", &rest)) {
            if (!type_text(rest, default_delay)) {
                break;
            }
            continue;
        }

        int rc = run_key_line(line, default_delay);
        if (rc < 0) {
            snprintf(err, sizeof(err), "line %u: unknown key command", (unsigned)s_line);
            break;
        }
        if (rc == 0) {
            /* Plain text line: type it in US layout. */
            if (!type_text(line, default_delay)) {
                break;
            }
        }
    }

    bool aborted = s_abort;
    bool still_active = s_active;
    bool still_connected = s_connected;
    free(data);
    if (s_display_paused) {
        s_display_paused = false;
        esp_lv_adapter_resume();
    }

    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    s_executing = false;
    s_task = NULL;
    if (err[0]) {
        snprintf(s_error, sizeof(s_error), "%.*s",
                 (int)sizeof(s_error) - 1, err);
        s_state = PWN_HID_ERROR;
        ESP_LOGE(TAG, "%s", err);
        hid_event("execution error: %s", err);
    } else if (aborted || !still_active || !still_connected) {
        if (still_active) {
            s_state = PWN_HID_ADVERTISING; /* disconnected: keep advertising */
            snprintf(s_error, sizeof(s_error), "host disconnected");
            hid_event("execution stopped: host disconnected");
        } else {
            s_state = PWN_HID_OFF;
            hid_event("execution stopped");
        }
    } else {
        s_state = PWN_HID_DONE;
        s_error[0] = 0;
        hid_event("execution complete (%u chars)", (unsigned)s_chars);
        ESP_LOGI(TAG, "payload complete: %u chars", (unsigned)s_chars);
    }
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }
    vTaskDelete(NULL);
}

/* ---- advertising / GAP ------------------------------------------------ */

static void hid_adv_stop(void)
{
    int rc = ble_gap_adv_stop();
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGW(TAG, "adv stop: %d", rc);
    }
}

static int hid_gap_event(struct ble_gap_event *event, void *arg);

static bool hid_start_adv(void)
{
    static const char name[] = PWN_HID_DEVICE_NAME;
    struct ble_hs_adv_fields fields;
    struct ble_gap_adv_params params;

    if (!s_ble_synced) {
        return false;
    }
    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.uuids16 = (ble_uuid16_t[]) { BLE_UUID16_INIT(0x1812) };
    fields.num_uuids16 = 1;
    fields.uuids16_is_complete = 1;
    fields.appearance = 0x03C1; /* HID keyboard */
    fields.appearance_is_present = 1;
    fields.name = (uint8_t *)name;
    fields.name_len = sizeof(name) - 1;
    fields.name_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGW(TAG, "adv fields: %d", rc);
        return false;
    }
    memset(&params, 0, sizeof(params));
    params.conn_mode = BLE_GAP_CONN_MODE_UND;
    params.disc_mode = BLE_GAP_DISC_MODE_GEN;
    rc = ble_gap_adv_start(s_addr_type, NULL, BLE_HS_FOREVER, &params,
                           hid_gap_event, NULL);
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGW(TAG, "adv start: %d", rc);
        return false;
    }
    s_need_adv = false;
    s_state = PWN_HID_ADVERTISING;
    ESP_LOGI(TAG, "advertising as BLE keyboard '%s'", name);
    return true;
}

static int hid_gap_event(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            s_conn = event->connect.conn_handle;
            s_connected = true;
            s_encrypted = false;
            s_boot_mode = false;
            s_notify_report = false;
            s_notify_boot = false;
            s_abort = false;
            s_state = PWN_HID_CONNECTED;
            hid_event("host connected, waiting for subscription");
            ESP_LOGI(TAG, "host connected (handle %u)", s_conn);
            /* Do not force a security request before service discovery.
             * BlueZ rejects an early Security Request with "pairing not
             * supported", which leaves the CCCD write hanging. SMP stays
             * enabled, so a host that wants an encrypted link can initiate
             * pairing itself; generic GATT clients can subscribe to the
             * unencrypted report attributes and receive notifications. */
        } else {
            s_connected = false;
            s_need_adv = true;
            hid_event("connection failed (%d), re-advertising", event->connect.status);
        }
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        s_connected = false;
        s_conn = 0xffff;
        s_encrypted = false;
        s_notify_report = false;
        s_notify_boot = false;
        s_abort = true;
        s_need_adv = s_active;
        if (s_active) {
            s_state = PWN_HID_ADVERTISING;
        }
        hid_event("host disconnected, waiting for a new connection");
        ESP_LOGI(TAG, "host disconnected (reason %d)", event->disconnect.reason);
        return 0;

    case BLE_GAP_EVENT_ENC_CHANGE:
        if (event->enc_change.status == 0) {
            s_encrypted = true;
            hid_event("host paired (encrypted link)");
            ESP_LOGI(TAG, "link encrypted");
        } else {
            /* The host may refuse pairing; unencrypted HID reports still work
             * on hosts that accept them. Do not tear down the connection. */
            ESP_LOGD(TAG, "encryption change: %d", event->enc_change.status);
        }
        return 0;

    case BLE_GAP_EVENT_SUBSCRIBE:
        if (event->subscribe.attr_handle == s_report_in_handle) {
            s_notify_report = event->subscribe.cur_notify;
        } else if (event->subscribe.attr_handle == s_boot_in_handle) {
            s_notify_boot = event->subscribe.cur_notify;
        }
        if ((event->subscribe.attr_handle == s_report_in_handle ||
             event->subscribe.attr_handle == s_boot_in_handle) &&
            event->subscribe.cur_notify) {
            hid_event("host subscribed to keyboard reports");
        }
        return 0;

    case BLE_GAP_EVENT_ADV_COMPLETE:
        if (s_active) {
            s_need_adv = true;
        }
        return 0;

    case BLE_GAP_EVENT_REPEAT_PAIRING: {
        struct ble_gap_conn_desc desc;
        if (ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc) == 0) {
            ble_store_util_delete_peer(&desc.peer_id_addr);
        }
        return BLE_GAP_REPEAT_PAIRING_RETRY;
    }

    case BLE_GAP_EVENT_PASSKEY_ACTION:
        /* No display/keypad: the stack should choose Just Works. */
        return 0;

    default:
        return 0;
    }
}

void hid_on_ble_sync(void)
{
    s_ble_synced = true;
    if (ble_hs_id_infer_auto(0, &s_addr_type) != 0) {
        s_addr_type = BLE_OWN_ADDR_PUBLIC;
    }
    s_need_adv = s_active;
}

void hid_on_ble_reset(void)
{
    s_ble_synced = false;
    s_connected = false;
    s_conn = 0xffff;
    s_encrypted = false;
    s_notify_report = false;
    s_notify_boot = false;
    s_abort = true;
    s_active = false;
    s_state = PWN_HID_OFF;
    ble_hid_set_active(false);
}

void hid_gatt_init(void)
{
#if defined(CONFIG_BT_NIMBLE_GATT_SERVER) && CONFIG_BT_NIMBLE_GATT_SERVER
    int rc = ble_gatts_count_cfg(s_hid_svcs);
    if (rc == 0) {
        rc = ble_gatts_add_svcs(s_hid_svcs);
    }
    if (rc != 0) {
        ESP_LOGW(TAG, "HID GATT registration failed: %d", rc);
        s_supported = false;
        return;
    }
    rc = ble_svc_gap_device_name_set(PWN_HID_DEVICE_NAME);
    if (rc != 0) {
        ESP_LOGW(TAG, "GAP name set: %d", rc);
    }
    rc = ble_svc_gap_device_appearance_set(0x03C1);
    if (rc != 0) {
        ESP_LOGW(TAG, "GAP appearance set: %d", rc);
    }
    s_supported = true;
    ESP_LOGI(TAG, "HID GATT service registered (keyboard, boot + report mode)");
#else
    s_supported = false;
    ESP_LOGW(TAG, "HID GATT server not compiled in");
#endif
}

#else /* !PWN_HAVE_NIMBLE */

void hid_on_ble_sync(void) {}
void hid_on_ble_reset(void) {}
void hid_gatt_init(void) { s_supported = false; }

#endif /* PWN_HAVE_NIMBLE */

/* ---- public lifecycle ------------------------------------------------- */

void hid_init(void)
{
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
    }
    s_supported = false;
    s_active = false;
    s_connected = false;
    s_encrypted = false;
    s_boot_mode = false;
    s_executing = false;
    s_abort = false;
    s_notify_report = false;
    s_notify_boot = false;
    s_need_adv = false;
    s_conn = 0xffff;
    s_state = PWN_HID_OFF;
    s_error[0] = 0;
    s_selected[0] = 0;

    if (capture_sd_ready()) {
        /* This runs before the display adapter starts, so no SPI transaction
         * can be in flight and the SD/display lock is not required yet. */
        mkdir(PWN_HID_PAYLOAD_DIR, 0777);
    }
    if (!s_supervisor &&
        xTaskCreate(hid_supervisor, "pwn_hid", 3072, NULL, 3,
                    &s_supervisor) != pdPASS) {
        ESP_LOGW(TAG, "HID supervisor task create failed");
    }
    ESP_LOGI(TAG, "BLE HID ready (off; opt-in and authorized only)");
}

bool hid_supported(void)
{
    return s_supported;
}

void hid_status(pwn_hid_status_t *out)
{
    if (!out) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->supported = s_supported;
    out->active = s_active;
    out->authorized = pwn_wifi_authorized();
    out->connected = s_connected;
    out->encrypted = s_encrypted;
    out->boot_mode = s_boot_mode;
    out->executing = s_executing;
    out->subscribed = s_notify_report || s_notify_boot;
    out->state = s_state;
    out->line = s_line;
    out->lines = s_lines;
    out->chars = s_chars;
    out->age_ms = s_active ? (now_ms() - s_active_since_ms) : 0;
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    snprintf(out->selected, sizeof(out->selected), "%.*s",
             (int)sizeof(out->selected) - 1, s_selected);
    snprintf(out->error, sizeof(out->error), "%.*s",
             (int)sizeof(out->error) - 1, s_error);
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }
}

const char *hid_state_name(pwn_hid_state_t state)
{
    switch (state) {
    case PWN_HID_OFF:         return "off";
    case PWN_HID_ADVERTISING: return "advertising";
    case PWN_HID_CONNECTED:   return "connected";
    case PWN_HID_RUNNING:     return "running";
    case PWN_HID_DONE:        return "done";
    case PWN_HID_ERROR:       return "error";
    default:                  return "?";
    }
}

bool hid_start(void)
{
    if (!s_supported) {
        set_error("HID is not available in this build");
        return false;
    }
    if (!pwn_wifi_authorized()) {
        set_error("unlock active features first");
        hid_event("refused: active features are locked");
        return false;
    }
    if (s_active) {
        return true;
    }
    clear_error();
    s_abort = false;
    s_state = PWN_HID_ADVERTISING;
    s_active_since_ms = now_ms();
    s_active = true;
    /* Pause the passive observer for the whole HID session. It resumes
     * automatically after hid_stop() if the user had it enabled. */
    ble_hid_set_active(true);
    vTaskDelay(pdMS_TO_TICKS(30));
    if (!hid_start_adv()) {
        s_active = false;
        s_state = PWN_HID_ERROR;
        set_error("BLE advertising failed (not synced?)");
        ble_hid_set_active(false);
        return false;
    }
    pwn_wifi_event("HID: keyboard advertising (BLE scanner paused)");
    ESP_LOGW(TAG, "HID keyboard mode ON (authorized)");
    return true;
}

void hid_stop(void)
{
    bool was_active = s_active;
    bool was_executing = s_executing;
    if (!was_active && !was_executing) {
        return;
    }
    s_abort = true;

    /* Give the typing task a moment to release keys and exit. */
    for (int i = 0; i < 150 && s_executing; i++) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    if (s_display_paused) {
        s_display_paused = false;
        esp_lv_adapter_resume();
    }

    if (s_connected && s_conn != 0xffff) {
        ble_gap_terminate(s_conn, BLE_ERR_REM_USER_CONN_TERM);
    }
    hid_adv_stop();

    s_connected = false;
    s_encrypted = false;
    s_notify_report = false;
    s_notify_boot = false;
    s_boot_mode = false;
    s_conn = 0xffff;
    s_active = false;
    s_executing = false;
    s_need_adv = false;
    s_state = PWN_HID_OFF;
    s_line = 0;
    s_lines = 0;
    s_chars = 0;
    clear_error();
    ble_hid_set_active(false);
    pwn_wifi_event("HID: stopped, scanner restored");
    ESP_LOGW(TAG, "HID keyboard mode OFF");
}

bool hid_run(const char *name)
{
    if (!s_supported) {
        set_error("HID is not available in this build");
        return false;
    }
    if (!pwn_wifi_authorized()) {
        set_error("unlock active features first");
        return false;
    }
    if (!s_active) {
        set_error("start HID mode first");
        return false;
    }
    if (!s_connected) {
        set_error("waiting for a host connection");
        return false;
    }
    if (s_executing) {
        set_error("a payload is already running");
        return false;
    }
    if (!(s_notify_report || s_notify_boot)) {
        set_error("host has not subscribed to keyboard reports");
        return false;
    }

    const char *use = (name && name[0]) ? name : s_selected;
    if (!payload_name_ok(use)) {
        set_error("select a payload first");
        return false;
    }

    char err[96] = "";
    size_t len = 0;
    char *data = payload_read(use, &len, err, sizeof(err));
    if (!data) {
        set_error(err);
        hid_event("cannot run %s: %s", use, err);
        return false;
    }
    if (!hid_select(use)) {
        free(data);
        set_error("payload disappeared");
        return false;
    }
    s_line = 0;
    s_lines = 0;
    s_chars = 0;
    clear_error();
    /* LVGL flushes the PSRAM draw buffer through an internal DMA bounce
     * buffer. While BLE notifications are saturating the radio, that
     * allocation can fail and LVGL then waits forever for the flush
     * completion callback. Pause rendering for the duration of the payload;
     * the web UI still shows progress and the screen resumes afterwards. */
    esp_err_t perr = esp_lv_adapter_pause(3000);
    if (perr != ESP_OK && perr != ESP_ERR_INVALID_STATE) {
        free(data);
        set_error("display busy; try again");
        return false;
    }
    s_display_paused = (perr == ESP_OK);

    s_abort = false;
    s_executing = true;
    s_state = PWN_HID_RUNNING;
    pwn_wifi_event("HID: typing %s", use);
    ESP_LOGW(TAG, "executing payload %s (%u bytes)", use, (unsigned)len);

    if (xTaskCreate(run_task, "pwn_hid_run", 6144, data, 4, &s_task) != pdPASS) {
        s_executing = false;
        s_state = PWN_HID_ERROR;
        if (s_display_paused) {
            s_display_paused = false;
            esp_lv_adapter_resume();
        }
        free(data);
        set_error("cannot start typist task");
        return false;
    }
    return true;
}

/* ---- supervisor ------------------------------------------------------- */

static void hid_supervisor(void *arg)
{
    (void)arg;
    for (;;) {
        if (s_active && !pwn_wifi_authorized()) {
            hid_event("stopping: authorization revoked");
            hid_stop();
        }
        if (s_active && s_need_adv && !s_connected) {
            vTaskDelay(pdMS_TO_TICKS(120));
            if (s_active && s_need_adv && !s_connected && s_ble_synced) {
                if (!hid_start_adv()) {
                    ESP_LOGW(TAG, "re-advertising failed, retrying");
                }
            }
        } else if (s_active && !s_connected &&
                   (now_ms() - s_active_since_ms) > (5u * 60u * 1000u)) {
            hid_event("stopping: no host connected for 5 minutes");
            hid_stop();
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}
