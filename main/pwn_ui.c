#include "pwn_ui.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdarg.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "bsp/esp-bsp.h"

#include "pwn_config.h"
#include "pwn_pet.h"
#include "pwn_wifi.h"
#include "pwn_capture.h"
#include "pwn_hunt.h"
#include "pwn_net.h"
#include "pwn_web.h"

static const char *TAG = "ui";

/* ---- palette / geometry ------------------------------------------------ */

#define W 320
#define H 480
#define NAV_H 54
#define BODY_H (H - NAV_H)

#define C_BG    0x050806
#define C_PANEL 0x0c120d
#define C_LINE  0x1c2a1e
#define C_FG    0xd6f5d6
#define C_DIM   0x6f8a72
#define C_ACC   0x8cf58c
#define C_ACC2  0x5cffb0
#define C_WARN  0xffcc66
#define C_BAD   0xff6b6b
#define C_EYE   0xf2fff2

enum { TAB_FACE = 0, TAB_SCAN, TAB_LOOT, TAB_SET, TAB_COUNT };

static lv_obj_t *s_screen[TAB_COUNT];
static lv_obj_t *s_nav_btn[TAB_COUNT];
static lv_obj_t *s_nav_lbl[TAB_COUNT];
static int s_tab;
static bool s_ready;

/* face */
static lv_obj_t *s_eye_l, *s_eye_r, *s_pupil_l, *s_pupil_r, *s_mouth;
static lv_obj_t *s_mood, *s_status, *s_stat1, *s_stat2, *s_event, *s_bond;
static lv_obj_t *s_level, *s_z;
static bool s_blink;
static uint32_t s_tick;
static pwn_mood_t s_last_mood;

/* scan */
static pwn_ap_t s_ui_aps[PWN_MAX_APS];
static int s_ui_ap_count;
static lv_obj_t *s_scan_list, *s_scan_hint;
static volatile bool s_scan_running, s_scan_done;
static uint32_t s_scan_last;

/* loot */
static pwn_handshake_t *s_ui_hs;
static int s_ui_hs_count;
static lv_obj_t *s_loot_list, *s_loot_hint;
static uint32_t s_loot_last;

/* settings */
static lv_obj_t *s_set_conn, *s_set_web, *s_set_auth, *s_set_sys, *s_set_deauth;
static lv_obj_t *s_sw_auto, *s_sw_autoconn, *s_slider, *s_sleep_dd;
static bool s_sw_busy;

/* dashboard QR */
static lv_obj_t *s_qr_box, *s_qr_offline;
static lv_obj_t *s_qr;
static char s_qr_url[32];

/* backlight idle management */
#define PWN_UI_NVS_NS       "pwnui"
#define PWN_UI_NVS_SLEEP    "sleep_s"
#define PWN_TIMEOUT_DEFAULT 60

static uint16_t s_timeout_s = PWN_TIMEOUT_DEFAULT;
static int s_user_brightness = 100;
static bool s_dimmed, s_blanked;
static lv_obj_t *s_wake_overlay;

/* modal / keyboard */
static lv_obj_t *s_modal;
static lv_obj_t *s_kb;
static lv_obj_t *s_ta;
static char s_kb_ssid[33];
static int s_kb_mode_kind;   /* 0 = connect, 1 = auth */
static pwn_ap_t s_sel_ap;
static pwn_client_t s_ui_clients[PWN_MAX_CLIENTS];
static int s_ui_client_count;
static lv_obj_t *s_toast, *s_toast_lbl;
static uint32_t s_toast_until;

static void close_modal(void);
static void close_btn_cb(lv_event_t *e);

/* ---- helpers ----------------------------------------------------------- */

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

/* Screen-timeout choices, in seconds. Zero means "never sleep". */
static const uint16_t k_timeouts[] = {30, 60, 120, 300, 0};
static const char *k_timeout_options = "30 s\n60 s\n2 min\n5 min\noff";
static const char *k_timeout_labels[] = {"30 s", "60 s", "2 min", "5 min", "off"};
#define TIMEOUT_CHOICES ((int)(sizeof(k_timeouts) / sizeof(k_timeouts[0])))

static int timeout_index(uint16_t seconds)
{
    for (int i = 0; i < TIMEOUT_CHOICES; i++) {
        if (k_timeouts[i] == seconds) {
            return i;
        }
    }
    return 1;   /* 60 s */
}

static void timeout_load(void)
{
    nvs_handle_t h;
    uint16_t v = PWN_TIMEOUT_DEFAULT;
    if (nvs_open(PWN_UI_NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_u16(h, PWN_UI_NVS_SLEEP, &v) != ESP_OK) {
            v = PWN_TIMEOUT_DEFAULT;
        }
        nvs_close(h);
    }
    if (timeout_index(v) == 1 && v != k_timeouts[1]) {
        v = PWN_TIMEOUT_DEFAULT;
    }
    s_timeout_s = v;
}

static void timeout_save(uint16_t seconds)
{
    nvs_handle_t h;
    if (nvs_open(PWN_UI_NVS_NS, NVS_READWRITE, &h) != ESP_OK) {
        return;
    }
    nvs_set_u16(h, PWN_UI_NVS_SLEEP, seconds);
    nvs_commit(h);
    nvs_close(h);
}

/* Restore the level chosen with the DISPLAY slider. The dim/blank state is
 * deliberately separate so waking up never changes the user's preference. */
static void screen_wake(void)
{
    if (!s_dimmed && !s_blanked) {
        return;
    }
    s_dimmed = false;
    s_blanked = false;
    bsp_display_brightness_set(s_user_brightness);
    if (s_wake_overlay) {
        lv_obj_add_flag(s_wake_overlay, LV_OBJ_FLAG_HIDDEN);
    }
    lv_display_trigger_activity(NULL);
}

static lv_obj_t *box(lv_obj_t *parent, int x, int y, int w, int h, uint32_t bg)
{
    lv_obj_t *o = lv_obj_create(parent);
    lv_obj_remove_style_all(o);
    lv_obj_set_pos(o, x, y);
    lv_obj_set_size(o, w, h);
    lv_obj_set_style_bg_color(o, lv_color_hex(bg), 0);
    lv_obj_set_style_bg_opa(o, LV_OPA_COVER, 0);
    lv_obj_set_style_radius(o, 10, 0);
    lv_obj_set_style_border_width(o, 1, 0);
    lv_obj_set_style_border_color(o, lv_color_hex(C_LINE), 0);
    lv_obj_remove_flag(o, LV_OBJ_FLAG_SCROLLABLE);
    return o;
}

static lv_obj_t *label(lv_obj_t *parent, const lv_font_t *font, uint32_t color,
                       int x, int y, int w)
{
    lv_obj_t *l = lv_label_create(parent);
    lv_obj_set_style_text_font(l, font, 0);
    lv_obj_set_style_text_color(l, lv_color_hex(color), 0);
    lv_obj_set_pos(l, x, y);
    if (w > 0) {
        lv_obj_set_width(l, w);
        /*
         * Dots mode still wraps when the label auto-sizes, so pin the height
         * to exactly one line.  Multi-line labels call label_lines() below.
         */
        lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
        const lv_font_t *f = lv_obj_get_style_text_font(l, LV_PART_MAIN);
        lv_obj_set_height(l, lv_font_get_line_height(f));
    }
    lv_label_set_text(l, "");
    return l;
}

static void label_lines(lv_obj_t *l, int lines)
{
    const lv_font_t *f = lv_obj_get_style_text_font(l, LV_PART_MAIN);
    lv_obj_set_height(l, lv_font_get_line_height(f) * lines);
}

static lv_obj_t *text_btn(lv_obj_t *parent, const char *txt, int x, int y,
                          int w, int h, bool accent)
{
    lv_obj_t *b = lv_button_create(parent);
    lv_obj_set_pos(b, x, y);
    lv_obj_set_size(b, w, h);
    lv_obj_set_style_radius(b, 8, 0);
    lv_obj_set_style_bg_color(b, lv_color_hex(accent ? C_ACC : C_PANEL), 0);
    lv_obj_set_style_bg_opa(b, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(b, 1, 0);
    lv_obj_set_style_border_color(b, lv_color_hex(accent ? C_ACC : C_LINE), 0);
    lv_obj_set_style_shadow_width(b, 0, 0);
    lv_obj_t *l = lv_label_create(b);
    lv_obj_set_style_text_font(l, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(l, lv_color_hex(accent ? C_BG : C_ACC), 0);
    lv_label_set_text(l, txt);
    lv_obj_center(l);
    return b;
}

static void toastf(const char *fmt, ...)
{
    static char buf[96];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (!s_toast) {
        return;
    }
    lv_label_set_text(s_toast_lbl, buf);
    lv_obj_clear_flag(s_toast, LV_OBJ_FLAG_HIDDEN);
    lv_obj_move_foreground(s_toast);
    s_toast_until = now_ms() + 2600;
}

static void screen_show(int idx)
{
    if (idx < 0 || idx >= TAB_COUNT) {
        return;
    }
    s_tab = idx;
    for (int i = 0; i < TAB_COUNT; i++) {
        if (i == idx) {
            lv_obj_clear_flag(s_screen[i], LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(s_screen[i], LV_OBJ_FLAG_HIDDEN);
        }
        lv_obj_set_style_bg_color(s_nav_btn[i],
                                  lv_color_hex(i == idx ? C_ACC : C_PANEL), 0);
        lv_obj_set_style_text_color(s_nav_lbl[i],
                                    lv_color_hex(i == idx ? C_BG : C_DIM), 0);
    }
}

void ui_show_tab(int idx)
{
    screen_show(idx);
    if (idx == TAB_SCAN) {
        s_scan_last = 0;
    } else if (idx == TAB_LOOT) {
        s_loot_last = 0;
    }
}

static void nav_cb(lv_event_t *e)
{
    int idx = (int)(intptr_t)lv_event_get_user_data(e);
    screen_show(idx);
    if (idx == TAB_SCAN) {
        s_scan_last = 0;
    } else if (idx == TAB_LOOT) {
        s_loot_last = 0;
    }
}

/* ---- face ------------------------------------------------------------- */

/*
 * Pwnagotchi-style face geometry.  The face is deliberately large and
 * monochrome: two white eyes with black pupils and a single white mouth arc.
 */
#define FACE_W      300
#define FACE_H      210
#define EYE_W       96
#define EYE_H       96
#define EYE_X       26
#define EYE_Y       16
#define MOUTH_W     110

static void face_apply(pwn_mood_t mood, bool blink)
{
    int ew = EYE_W, eh = EYE_H;
    int pupil = 36, px = 0, py = 0;
    int mw = 8;
    int mouth = MOUTH_W, mouth_y = 65;
    int ma = 30, mb = 150;

    switch (mood) {
    case MOOD_SLEEPING:
        eh = 10; pupil = 0; mw = 5;
        mouth = 90; mouth_y = 85; ma = 50; mb = 130;
        break;
    case MOOD_OBSERVING:
        break;
    case MOOD_HAPPY:
        eh = 90; pupil = 34; py = -8;
        mouth = 116; mouth_y = 60; ma = 10; mb = 170; mw = 10;
        break;
    case MOOD_EXCITED:
        ew = 100; eh = 100; pupil = 32; py = -10;
        mouth = 120; mouth_y = 56; ma = 0; mb = 180; mw = 12;
        break;
    case MOOD_BORED:
        eh = 64; py = 10;
        mouth = 100; mouth_y = 68; ma = 45; mb = 135; mw = 7;
        break;
    case MOOD_SAD:
        eh = 84; py = 12;
        /* 210..330 is a frown (top half of the circle), placed below the eyes. */
        mouth = 100; mouth_y = 110; ma = 210; mb = 330; mw = 8;
        break;
    case MOOD_MOTIVATED:
        ew = 98; eh = 98; pupil = 34; py = -12;
        mouth = 120; mouth_y = 56; ma = 0; mb = 180; mw = 11;
        break;
    case MOOD_DEMOTIVATED:
        eh = 78; py = 12;
        mouth = 100; mouth_y = 112; ma = 210; mb = 330; mw = 7;
        break;
    default:
        break;
    }

    int dy = EYE_Y + (EYE_H - eh) / 2;
    if (blink) {
        eh = 10;
        pupil = 0;
        dy = EYE_Y + (EYE_H - eh) / 2;
    }

    lv_obj_set_size(s_eye_l, ew, eh);
    lv_obj_set_size(s_eye_r, ew, eh);
    lv_obj_set_style_radius(s_eye_l, LV_RADIUS_CIRCLE, 0);
    lv_obj_set_style_radius(s_eye_r, LV_RADIUS_CIRCLE, 0);
    lv_obj_set_style_bg_color(s_eye_l, lv_color_hex(C_EYE), 0);
    lv_obj_set_style_bg_color(s_eye_r, lv_color_hex(C_EYE), 0);
    lv_obj_set_style_shadow_width(s_eye_l, 0, 0);
    lv_obj_set_style_shadow_width(s_eye_r, 0, 0);

    lv_obj_align(s_eye_l, LV_ALIGN_TOP_LEFT, EYE_X, dy);
    lv_obj_align(s_eye_r, LV_ALIGN_TOP_RIGHT, -EYE_X, dy);

    if (pupil) {
        lv_obj_clear_flag(s_pupil_l, LV_OBJ_FLAG_HIDDEN);
        lv_obj_clear_flag(s_pupil_r, LV_OBJ_FLAG_HIDDEN);
        lv_obj_set_size(s_pupil_l, pupil, pupil);
        lv_obj_set_size(s_pupil_r, pupil, pupil);
        lv_obj_set_style_radius(s_pupil_l, LV_RADIUS_CIRCLE, 0);
        lv_obj_set_style_radius(s_pupil_r, LV_RADIUS_CIRCLE, 0);
        lv_obj_align(s_pupil_l, LV_ALIGN_CENTER, px, py);
        lv_obj_align(s_pupil_r, LV_ALIGN_CENTER, px, py);
    } else {
        lv_obj_add_flag(s_pupil_l, LV_OBJ_FLAG_HIDDEN);
        lv_obj_add_flag(s_pupil_r, LV_OBJ_FLAG_HIDDEN);
    }

    lv_obj_set_size(s_mouth, mouth, mouth);
    lv_arc_set_bg_angles(s_mouth, ma, mb);
    lv_arc_set_angles(s_mouth, ma, mb);
    lv_obj_set_style_arc_width(s_mouth, mw, LV_PART_INDICATOR);
    lv_obj_align(s_mouth, LV_ALIGN_TOP_MID, 0, mouth_y);

    lv_obj_set_style_text_color(s_mood, lv_color_hex(C_ACC), 0);
}

static void face_clicked(lv_event_t *e)
{
    (void)e;
    pet_touch();
}

static lv_obj_t *make_face(lv_obj_t *scr)
{
    lv_obj_t *face = lv_obj_create(scr);
    lv_obj_remove_style_all(face);
    lv_obj_set_pos(face, 10, 40);
    lv_obj_set_size(face, FACE_W, FACE_H);
    lv_obj_add_flag(face, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(face, face_clicked, LV_EVENT_CLICKED, NULL);

    s_eye_l = lv_obj_create(face);
    lv_obj_remove_style_all(s_eye_l);
    lv_obj_set_style_bg_opa(s_eye_l, LV_OPA_COVER, 0);
    lv_obj_add_flag(s_eye_l, LV_OBJ_FLAG_IGNORE_LAYOUT);

    s_eye_r = lv_obj_create(face);
    lv_obj_remove_style_all(s_eye_r);
    lv_obj_set_style_bg_opa(s_eye_r, LV_OPA_COVER, 0);
    lv_obj_add_flag(s_eye_r, LV_OBJ_FLAG_IGNORE_LAYOUT);

    s_pupil_l = lv_obj_create(s_eye_l);
    lv_obj_remove_style_all(s_pupil_l);
    lv_obj_set_style_bg_color(s_pupil_l, lv_color_hex(C_BG), 0);
    lv_obj_set_style_bg_opa(s_pupil_l, LV_OPA_COVER, 0);
    lv_obj_remove_flag(s_pupil_l, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_flag(s_pupil_l, LV_OBJ_FLAG_IGNORE_LAYOUT);

    s_pupil_r = lv_obj_create(s_eye_r);
    lv_obj_remove_style_all(s_pupil_r);
    lv_obj_set_style_bg_color(s_pupil_r, lv_color_hex(C_BG), 0);
    lv_obj_set_style_bg_opa(s_pupil_r, LV_OPA_COVER, 0);
    lv_obj_remove_flag(s_pupil_r, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_flag(s_pupil_r, LV_OBJ_FLAG_IGNORE_LAYOUT);

    s_mouth = lv_arc_create(face);
    lv_obj_remove_style_all(s_mouth);
    lv_obj_set_style_arc_color(s_mouth, lv_color_hex(C_EYE), LV_PART_INDICATOR);
    lv_obj_set_style_arc_opa(s_mouth, LV_OPA_COVER, LV_PART_INDICATOR);
    lv_obj_set_style_arc_width(s_mouth, 8, LV_PART_INDICATOR);
    lv_obj_set_style_arc_rounded(s_mouth, true, LV_PART_INDICATOR);
    lv_obj_set_style_arc_opa(s_mouth, LV_OPA_TRANSP, LV_PART_MAIN);
    lv_obj_set_style_bg_opa(s_mouth, LV_OPA_TRANSP, LV_PART_KNOB);
    lv_obj_set_style_border_width(s_mouth, 0, LV_PART_KNOB);
    lv_obj_remove_flag(s_mouth, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_flag(s_mouth, LV_OBJ_FLAG_IGNORE_LAYOUT);

    s_z = lv_label_create(face);
    lv_obj_set_style_text_font(s_z, &lv_font_unscii_16, 0);
    lv_obj_set_style_text_color(s_z, lv_color_hex(C_DIM), 0);
    lv_label_set_text(s_z, "");
    lv_obj_align(s_z, LV_ALIGN_TOP_RIGHT, -8, 2);

    return face;
}

/* ---- scan ------------------------------------------------------------- */

static int ap_cmp(const void *a, const void *b)
{
    const pwn_ap_t *x = a, *y = b;
    return (int)y->rssi - (int)x->rssi;
}

static void ap_clicked(lv_event_t *e);

static void scan_worker(void *arg)
{
    (void)arg;
    pwn_wifi_scan_now();
    s_scan_done = true;
    s_scan_running = false;
    vTaskDelete(NULL);
}

static void start_scan(void)
{
    if (s_scan_running) {
        toastf("scan already running");
        return;
    }
    s_scan_running = true;
    s_scan_done = false;
    if (xTaskCreate(scan_worker, "ui_scan", 4096, NULL, 3, NULL) != pdPASS) {
        s_scan_running = false;
        toastf("scan task failed");
    } else {
        toastf("scanning...");
    }
}

static void scan_refresh(void)
{
    if (!s_scan_list) {
        return;
    }
    s_ui_ap_count = pwn_wifi_ap_snapshot(s_ui_aps, PWN_MAX_APS);
    qsort(s_ui_aps, s_ui_ap_count, sizeof(s_ui_aps[0]), ap_cmp);

    int scroll = lv_obj_get_scroll_y(s_scan_list);
    lv_obj_clean(s_scan_list);

    if (s_ui_ap_count == 0) {
        lv_obj_t *l = label(s_scan_list, &lv_font_montserrat_14, C_DIM, 10, 14, 270);
        label_lines(l, 2);
        lv_label_set_text(l, "no networks yet\nstarting a scan...");
        return;
    }

    int shown = s_ui_ap_count > 40 ? 40 : s_ui_ap_count;
    for (int i = 0; i < shown; i++) {
        pwn_ap_t *a = &s_ui_aps[i];
        lv_obj_t *row = box(s_scan_list, 2, i * 58, 296, 54, C_PANEL);
        lv_obj_add_flag(row, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(row, ap_clicked, LV_EVENT_CLICKED,
                            (void *)(intptr_t)i);
        lv_obj_set_style_bg_opa(row, LV_OPA_COVER, LV_STATE_PRESSED);

        char ssid[33];
        snprintf(ssid, sizeof(ssid), "%.32s", a->ssid[0] ? a->ssid : "<hidden>");
        lv_obj_t *n = label(row, &lv_font_montserrat_14,
                            a->has_handshake ? C_ACC2 : C_FG, 10, 6, 180);
        lv_label_set_long_mode(n, LV_LABEL_LONG_DOT);
        lv_label_set_text(n, ssid);

        static const char *secs[] = {"open", "WEP", "WPA", "WPA2", "WPA3", "?"};
        char sub[64];
        snprintf(sub, sizeof(sub), "ch %u  %s  %d dBm%s", a->channel,
                 secs[a->security <= SEC_UNKNOWN ? a->security : SEC_UNKNOWN],
                 a->rssi, a->wps ? "  WPS" : "");
        lv_obj_t *s = label(row, &lv_font_montserrat_12, C_DIM, 10, 28, 210);
        lv_label_set_text(s, sub);

        /* RSSI bar, 4 px per 10 dBm above -100. */
        int pct = (a->rssi + 100) * 100 / 60;
        if (pct < 6) pct = 6;
        if (pct > 100) pct = 100;
        lv_obj_t *bar = lv_bar_create(row);
        lv_obj_set_size(bar, 46, 7);
        lv_obj_align(bar, LV_ALIGN_TOP_RIGHT, -12, 12);
        lv_bar_set_range(bar, 0, 100);
        lv_bar_set_value(bar, pct, LV_ANIM_OFF);
        lv_obj_set_style_bg_color(bar, lv_color_hex(0x162016), 0);
        lv_obj_set_style_bg_opa(bar, LV_OPA_COVER, 0);
        lv_obj_set_style_bg_color(bar, lv_color_hex(C_ACC), LV_PART_INDICATOR);

        if (a->has_handshake) {
            lv_obj_t *b = label(row, &lv_font_montserrat_12, C_ACC2, 230, 28, 50);
            lv_label_set_text(b, "HS");
        }
        if (a->security == SEC_OPEN) {
            lv_obj_t *b = label(row, &lv_font_montserrat_12, C_WARN, 230, 6, 50);
            lv_label_set_text(b, "OPEN");
        }
    }
    lv_obj_scroll_to_y(s_scan_list, scroll, LV_ANIM_OFF);
}

static void close_modal(void)
{
    if (s_modal) {
        lv_obj_delete(s_modal);
        s_modal = NULL;
        s_kb = NULL;
        s_ta = NULL;
    }
}

static bool phrase_matches(const char *txt)
{
    if (!txt) {
        return false;
    }
    while (*txt == ' ' || *txt == '\t' || *txt == '\r' || *txt == '\n') {
        txt++;
    }
    size_t len = strlen(txt);
    while (len > 0) {
        char c = txt[len - 1];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
            break;
        }
        len--;
    }
    size_t want = strlen(PWN_AUTH_PHRASE);
    return len == want && strncasecmp(txt, PWN_AUTH_PHRASE, len) == 0;
}

static void kb_event_cb(lv_event_t *e)
{
    lv_event_code_t code = lv_event_get_code(e);
    if (code == LV_EVENT_READY) {
        const char *txt = lv_textarea_get_text(s_ta);
        if (s_kb_mode_kind == 1) {
            bool ok = phrase_matches(txt);
            pwn_wifi_set_authorized(ok);
            if (!ok) {
                pwn_wifi_set_auto_deauth(false);
            }
            toastf(ok ? "attacks unlocked" : "wrong phrase");
        } else {
            net_connect(s_kb_ssid, txt, true);
            toastf("connecting to %s", s_kb_ssid);
        }
        close_modal();
    } else if (code == LV_EVENT_CANCEL) {
        close_modal();
    }
}

static void kb_overlay_cb(lv_event_t *e)
{
    if (lv_event_get_target(e) == lv_event_get_current_target(e)) {
        close_modal();
    }
}

static void open_keyboard(const char *title, const char *initial, int mode,
                          const char *ssid)
{
    close_modal();
    s_kb_mode_kind = mode;
    snprintf(s_kb_ssid, sizeof(s_kb_ssid), "%s", ssid ? ssid : "");

    s_modal = lv_obj_create(lv_layer_top());
    lv_obj_remove_style_all(s_modal);
    lv_obj_set_size(s_modal, W, H);
    lv_obj_set_pos(s_modal, 0, 0);
    lv_obj_set_style_bg_color(s_modal, lv_color_hex(0x000000), 0);
    lv_obj_set_style_bg_opa(s_modal, LV_OPA_80, 0);
    lv_obj_add_flag(s_modal, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(s_modal, kb_overlay_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *t = label(s_modal, &lv_font_montserrat_14, C_ACC, 16, 118, 240);
    lv_label_set_text(t, title);

    s_ta = lv_textarea_create(s_modal);
    lv_obj_set_size(s_ta, 288, 44);
    lv_obj_set_pos(s_ta, 16, 142);
    lv_textarea_set_one_line(s_ta, true);
    lv_textarea_set_max_length(s_ta, 63);
    lv_textarea_set_password_mode(s_ta, mode != 1);
    lv_textarea_set_placeholder_text(s_ta, mode == 1 ? "type the phrase"
                                                      : "WiFi password");
    lv_obj_set_style_bg_color(s_ta, lv_color_hex(0x0a0f0b), 0);
    lv_obj_set_style_text_color(s_ta, lv_color_hex(C_FG), 0);
    lv_obj_set_style_border_color(s_ta, lv_color_hex(C_LINE), 0);
    if (initial && initial[0]) {
        lv_textarea_set_text(s_ta, initial);
    }

    lv_obj_t *hint = label(s_modal, &lv_font_montserrat_12, C_DIM, 16, 194, 288);
    lv_label_set_text(hint, mode == 1 ? "case-insensitive; tap the check key to submit"
                                      : "tap the check key to connect");

    s_kb = lv_keyboard_create(s_modal);
    lv_obj_set_size(s_kb, 300, 200);
    lv_obj_align(s_kb, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_keyboard_set_mode(s_kb, mode == 1 ? LV_KEYBOARD_MODE_TEXT_UPPER
                                         : LV_KEYBOARD_MODE_TEXT_LOWER);
    lv_keyboard_set_textarea(s_kb, s_ta);
    lv_obj_add_event_cb(s_kb, kb_event_cb, LV_EVENT_READY, NULL);
    lv_obj_add_event_cb(s_kb, kb_event_cb, LV_EVENT_CANCEL, NULL);

    lv_obj_t *x = text_btn(s_modal, "X", 276, 108, 32, 30, false);
    lv_obj_add_event_cb(x, close_btn_cb, LV_EVENT_CLICKED, NULL);
}

static void ap_connect_cb(lv_event_t *e)
{
    (void)e;
    char ssid[33];
    snprintf(ssid, sizeof(ssid), "%.32s", s_sel_ap.ssid);
    bool open = (s_sel_ap.security == SEC_OPEN);
    close_modal();
    if (open) {
        net_connect(ssid, "", true);
        toastf("connecting to %s", ssid);
    } else {
        open_keyboard("WiFi password", "", 0, ssid);
    }
}

static void ap_exec_hunt(void)
{
    char err[96] = "";
    if (pwn_hunt_start(s_sel_ap.bssid, NULL, PWN_HUNT_DEFAULT_MS,
                       err, sizeof(err)) == ESP_OK) {
        toastf("hunt %us%s: %.12s", (unsigned)(PWN_HUNT_DEFAULT_MS / 1000),
               s_sel_ap.pmf ? " (PMF may ignore)" : "",
               s_sel_ap.ssid[0] ? s_sel_ap.ssid : "<hidden>");
    } else {
        toastf("%.48s", err[0] ? err : "hunt failed");
    }
}

static void ap_hunt_cb(lv_event_t *e)
{
    (void)e;
    close_modal();
    if (!pwn_wifi_authorized()) {
        toastf("unlock attacks first");
        open_keyboard("AUTHORIZATION PHRASE", "", 1, NULL);
        return;
    }
    ap_exec_hunt();
}

static void ap_deauth_cb(lv_event_t *e)
{
    (void)e;
    close_modal();

    if (!pwn_wifi_authorized()) {
        toastf("unlock attacks first");
        open_keyboard("AUTHORIZATION PHRASE", "", 1, NULL);
        return;
    }
    pwn_net_status_t n;
    net_get_status(&n);
    const pwn_wifi_stats_t *st = pwn_wifi_stats();
    if (s_sel_ap.channel && s_sel_ap.channel != st->channel) {
        if (n.connected) {
            toastf("single radio: target on ch %u", s_sel_ap.channel);
            return;
        }
        pwn_wifi_force_channel(s_sel_ap.channel);
    }
    bool self_ap = n.connected && memcmp(n.bssid, s_sel_ap.bssid, 6) == 0;
    uint8_t self[6];
    pwn_wifi_self_mac(self);
    pwn_client_t cl[PWN_MAX_CLIENTS];
    int cn = pwn_wifi_client_snapshot(cl, PWN_MAX_CLIENTS);
    int targets = 0;
    for (int i = 0; i < cn; i++) {
        if (memcmp(cl[i].bssid, s_sel_ap.bssid, 6) == 0 &&
            memcmp(cl[i].mac, self, 6) != 0) {
            targets++;
        }
    }
    if (targets == 0 && self_ap) {
        toastf("no other clients seen");
        return;
    }

    pwn_deauth_job_t job = {0};
    memcpy(job.bssid, s_sel_ap.bssid, 6);
    job.all = true;
    job.target_is_self_ap = self_ap;
    job.duration_ms = 8000;
    job.interval_ms = 50;
    job.reason = 1;
    if (pwn_wifi_deauth_start(&job) == ESP_OK) {
        if (targets > 0) {
            toastf("deauth 8s: %d client%s", targets,
                   targets == 1 ? "" : "s");
        } else {
            toastf("deauth 8s: broadcast");
        }
    } else {
        toastf("deauth failed");
    }
}

static void close_btn_cb(lv_event_t *e)
{
    (void)e;
    close_modal();
}


static void client_deauth_cb(lv_event_t *e)
{
    int idx = (int)(intptr_t)lv_event_get_user_data(e);
    if (idx < 0 || idx >= s_ui_client_count) {
        return;
    }
    pwn_client_t c = s_ui_clients[idx];
    close_modal();
    pwn_deauth_job_t job = {0};
    memcpy(job.bssid, s_sel_ap.bssid, 6);
    memcpy(job.sta, c.mac, 6);
    job.have_sta = true;
    job.duration_ms = 8000;
    job.interval_ms = 50;
    job.reason = 1;
    if (pwn_wifi_deauth_start(&job) == ESP_OK) {
        toastf("deauth 8s: %02x:%02x:%02x:%02x:%02x:%02x",
               c.mac[0], c.mac[1], c.mac[2], c.mac[3], c.mac[4], c.mac[5]);
    } else {
        toastf("deauth failed");
    }
}

static void clients_btn_cb(lv_event_t *e)
{
    (void)e;
    close_modal();
    uint8_t self[6];
    pwn_wifi_self_mac(self);
    pwn_client_t all[PWN_MAX_CLIENTS];
    int n = pwn_wifi_client_snapshot(all, PWN_MAX_CLIENTS);
    s_ui_client_count = 0;
    for (int i = 0; i < n && s_ui_client_count < PWN_MAX_CLIENTS; i++) {
        if (memcmp(all[i].bssid, s_sel_ap.bssid, 6) != 0) continue;
        if (memcmp(all[i].mac, self, 6) == 0) continue;
        s_ui_clients[s_ui_client_count++] = all[i];
    }

    s_modal = lv_obj_create(lv_layer_top());
    lv_obj_remove_style_all(s_modal);
    lv_obj_set_size(s_modal, W, H);
    lv_obj_set_style_bg_color(s_modal, lv_color_hex(0), 0);
    lv_obj_set_style_bg_opa(s_modal, LV_OPA_70, 0);
    lv_obj_add_flag(s_modal, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(s_modal, kb_overlay_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *p = box(s_modal, 12, 90, 296, 300, C_PANEL);
    lv_obj_set_style_bg_opa(p, LV_OPA_COVER, 0);
    lv_obj_t *t = label(p, &lv_font_montserrat_14, C_ACC, 12, 10, 270);
    lv_label_set_text(t, "CLIENTS");
    lv_obj_t *sub = label(p, &lv_font_montserrat_12, C_DIM, 12, 30, 270);
    lv_label_set_text_fmt(sub, "%.32s", s_sel_ap.ssid[0] ? s_sel_ap.ssid : "<hidden>");

    lv_obj_t *list = lv_obj_create(p);
    lv_obj_remove_style_all(list);
    lv_obj_set_pos(list, 12, 52);
    lv_obj_set_size(list, 272, 184);
    lv_obj_set_scroll_dir(list, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(list, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_pad_all(list, 0, 0);

    if (s_ui_client_count == 0) {
        lv_obj_t *none = label(list, &lv_font_montserrat_12, C_DIM, 4, 8, 260);
        lv_label_set_text(none, "no clients seen");
    } else {
        for (int i = 0; i < s_ui_client_count; i++) {
            char text[64];
            snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x  %d dBm",
                     s_ui_clients[i].mac[0], s_ui_clients[i].mac[1],
                     s_ui_clients[i].mac[2], s_ui_clients[i].mac[3],
                     s_ui_clients[i].mac[4], s_ui_clients[i].mac[5],
                     s_ui_clients[i].rssi);
            lv_obj_t *b = text_btn(list, text, 0, i * 38, 260, 34, false);
            lv_obj_add_event_cb(b, client_deauth_cb, LV_EVENT_CLICKED,
                                (void *)(intptr_t)i);
        }
    }

    lv_obj_t *close = text_btn(p, "CLOSE", 12, 248, 272, 34, false);
    lv_obj_add_event_cb(close, close_btn_cb, LV_EVENT_CLICKED, NULL);
}

static void ap_clicked(lv_event_t *e)
{
    int idx = (int)(intptr_t)lv_event_get_user_data(e);
    if (idx < 0 || idx >= s_ui_ap_count) {
        return;
    }
    s_sel_ap = s_ui_aps[idx];
    pwn_ap_t *a = &s_sel_ap;
    close_modal();

    s_modal = lv_obj_create(lv_layer_top());
    lv_obj_remove_style_all(s_modal);
    lv_obj_set_size(s_modal, W, H);
    lv_obj_set_style_bg_color(s_modal, lv_color_hex(0), 0);
    lv_obj_set_style_bg_opa(s_modal, LV_OPA_70, 0);
    lv_obj_add_flag(s_modal, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(s_modal, kb_overlay_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *p = box(s_modal, 12, 112, 296, 250, C_PANEL);
    lv_obj_set_style_bg_opa(p, LV_OPA_COVER, 0);

    char ssid[33];
    snprintf(ssid, sizeof(ssid), "%.32s", a->ssid[0] ? a->ssid : "<hidden>");
    lv_obj_t *t = label(p, &lv_font_montserrat_20, C_ACC, 12, 12, 270);
    lv_label_set_long_mode(t, LV_LABEL_LONG_DOT);
    lv_label_set_text(t, ssid);

    static const char *secs[] = {"open", "WEP", "WPA", "WPA2", "WPA3", "?"};
    char info[128];
    snprintf(info, sizeof(info),
             "%02x:%02x:%02x:%02x:%02x:%02x\nch %u   %s   %d dBm%s%s",
             a->bssid[0], a->bssid[1], a->bssid[2], a->bssid[3],
             a->bssid[4], a->bssid[5], a->channel,
             secs[a->security <= SEC_UNKNOWN ? a->security : SEC_UNKNOWN],
             a->rssi, a->wps ? "   WPS" : "", a->pmf ? "   PMF" : "");
    lv_obj_t *i = label(p, &lv_font_montserrat_12, C_DIM, 12, 48, 270);
    label_lines(i, 2);
    lv_label_set_text(i, info);

    lv_obj_t *b1 = text_btn(p, "CONNECT", 12, 120, 84, 40, true);
    lv_obj_add_event_cb(b1, ap_connect_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *b2 = text_btn(p, "DEAUTH", 100, 120, 84, 40, false);
    lv_obj_add_event_cb(b2, ap_deauth_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *b3 = text_btn(p, "CLIENTS", 188, 120, 96, 40, false);
    lv_obj_add_event_cb(b3, clients_btn_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *bh = text_btn(p, "HUNT (20s)", 12, 166, 272, 32, false);
    lv_obj_add_event_cb(bh, ap_hunt_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *b4 = text_btn(p, "CLOSE", 12, 204, 272, 32, false);
    lv_obj_add_event_cb(b4, close_btn_cb, LV_EVENT_CLICKED, NULL);
}

static void scan_btn_cb(lv_event_t *e)
{
    (void)e;
    start_scan();
}

/* ---- loot ------------------------------------------------------------- */

static void hs_clicked(lv_event_t *e)
{
    int idx = (int)(intptr_t)lv_event_get_user_data(e);
    if (idx < 0 || idx >= s_ui_hs_count) {
        return;
    }
    pwn_handshake_t *h = &s_ui_hs[idx];
    if (h->file[0]) {
        toastf("%s", h->file);
    } else {
        toastf("kept in RAM (no SD)");
    }
}

static void loot_refresh(void)
{
    if (!s_loot_list || !s_ui_hs) {
        return;
    }
    s_ui_hs_count = capture_snapshot(s_ui_hs, PWN_MAX_HS);
    lv_obj_clean(s_loot_list);

    if (s_ui_hs_count == 0) {
        lv_obj_t *l = label(s_loot_list, &lv_font_montserrat_14, C_DIM, 10, 14, 270);
        label_lines(l, 3);
        lv_label_set_text(l, "no handshakes yet.\nkeep listening - M1/M2 or PMKID\nland here as soon as they are seen.");
        return;
    }
    for (int i = 0; i < s_ui_hs_count; i++) {
        pwn_handshake_t *h = &s_ui_hs[i];
        lv_obj_t *row = box(s_loot_list, 2, i * 68, 296, 62, C_PANEL);
        lv_obj_add_flag(row, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(row, hs_clicked, LV_EVENT_CLICKED, (void *)(intptr_t)i);

        lv_obj_t *n = label(row, &lv_font_montserrat_14, C_FG, 10, 5, 190);
        lv_label_set_long_mode(n, LV_LABEL_LONG_DOT);
        lv_label_set_text(n, h->ssid[0] ? h->ssid : "<hidden>");

        char sub[64];
        snprintf(sub, sizeof(sub), "%02x:%02x:%02x:%02x:%02x:%02x",
                 h->bssid[0], h->bssid[1], h->bssid[2],
                 h->bssid[3], h->bssid[4], h->bssid[5]);
        lv_obj_t *s = label(row, &lv_font_unscii_8, C_DIM, 10, 27, 220);
        lv_label_set_text(s, sub);

        char tags[48] = "";
        if (h->has_pmkid) strcat(tags, "PMKID ");
        if (h->complete)  strcat(tags, "4WAY ");
        if (h->saved)     strcat(tags, "SAVED");
        lv_obj_t *tg = label(row, &lv_font_unscii_8, C_ACC2, 10, 45, 220);
        lv_label_set_text(tg, tags);

        char m[16];
        snprintf(m, sizeof(m), "M%x%x%x%x", h->msg_mask & 1,
                 (h->msg_mask >> 1) & 1, (h->msg_mask >> 2) & 1,
                 (h->msg_mask >> 3) & 1);
        lv_obj_t *ml = label(row, &lv_font_unscii_8, C_DIM, 245, 46, 44);
        lv_label_set_text(ml, m);
    }
}

/* ---- settings --------------------------------------------------------- */

static void settings_set_auto(bool on)
{
    s_sw_busy = true;
    if (on) {
        lv_obj_add_state(s_sw_auto, LV_STATE_CHECKED);
    } else {
        lv_obj_remove_state(s_sw_auto, LV_STATE_CHECKED);
    }
    s_sw_busy = false;
}

static void sw_auto_cb(lv_event_t *e)
{
    if (s_sw_busy) {
        return;
    }
    bool on = lv_obj_has_state(lv_event_get_target(e), LV_STATE_CHECKED);
    if (on && !pwn_wifi_authorized()) {
        settings_set_auto(false);
        toastf("unlock attacks first");
        return;
    }
    pwn_wifi_set_auto_deauth(on);
    toastf("auto-deauth %s", on ? "on" : "off");
}

static void sw_auto_conn_cb(lv_event_t *e)
{
    if (s_sw_busy) {
        return;
    }
    bool on = lv_obj_has_state(lv_event_get_target(e), LV_STATE_CHECKED);
    net_set_autoconnect(on);
    toastf("autoconnect %s", on ? "on" : "off");
}

static void btn_scan_cb(lv_event_t *e)
{
    (void)e;
    screen_show(TAB_SCAN);
}

static void btn_disc_cb(lv_event_t *e)
{
    (void)e;
    net_disconnect(false);
    toastf("disconnected");
}

static void btn_forget_cb(lv_event_t *e)
{
    (void)e;
    net_disconnect(true);
    toastf("network forgotten");
}

static void btn_unlock_cb(lv_event_t *e)
{
    (void)e;
    open_keyboard("AUTHORIZATION PHRASE", "", 1, NULL);
}

static void btn_lock_cb(lv_event_t *e)
{
    (void)e;
    pwn_wifi_set_authorized(false);
    pwn_wifi_set_auto_deauth(false);
    pwn_hunt_stop();
    toastf("attacks locked");
}

static void btn_stop_deauth_cb(lv_event_t *e)
{
    (void)e;
    bool hunting = pwn_hunt_active();
    pwn_hunt_stop();
    pwn_wifi_deauth_stop();
    toastf(hunting ? "hunt stopped" : "deauth stopped");
}

static void github_ota_cb(lv_event_t *e)
{
    (void)e;
    if (!pwn_wifi_authorized()) {
        toastf("unlock attacks first");
        return;
    }
    esp_err_t err = web_ota_github_start();
    if (err == ESP_OK) {
        toastf("GitHub OTA started");
    } else {
        toastf("OTA busy or unavailable");
    }
}

static void strat_cb(lv_event_t *e)
{
    int sel = lv_dropdown_get_selected(lv_event_get_target(e));
    pet_set_action(sel - 1);   /* item 0 is "auto" */
    if (sel <= 0) {
        toastf("strategy: auto");
    } else {
        toastf("strategy: %s", pet_action_name((brain_action_t)(sel - 1)));
    }
}

static void slider_cb(lv_event_t *e)
{
    int v = lv_slider_get_value(lv_event_get_target(e));
    s_user_brightness = v;
    /* While dimmed/blanked this only updates the level restored on wake. */
    if (!s_dimmed && !s_blanked) {
        bsp_display_brightness_set(v);
    }
}

static void sleep_cb(lv_event_t *e)
{
    int sel = lv_dropdown_get_selected(lv_event_get_target(e));
    if (sel < 0 || sel >= TIMEOUT_CHOICES) {
        sel = 1;
    }
    s_timeout_s = k_timeouts[sel];
    timeout_save(s_timeout_s);
    if (s_timeout_s == 0) {
        screen_wake();
    }
    toastf("screen sleep: %s", k_timeout_labels[sel]);
}

static void wake_overlay_cb(lv_event_t *e)
{
    (void)e;
    screen_wake();
}

static void reboot_cb(lv_event_t *e)
{
    (void)e;
    toastf("rebooting...");
    vTaskDelay(pdMS_TO_TICKS(300));
    esp_restart();
}

static void reset_brain_cb(lv_event_t *e)
{
    (void)e;
    pet_reset_brain();
    toastf("brain reset");
}

/* ---- screens ---------------------------------------------------------- */

static lv_obj_t *make_screen(void)
{
    lv_obj_t *s = lv_obj_create(lv_screen_active());
    lv_obj_remove_style_all(s);
    lv_obj_set_pos(s, 0, 0);
    lv_obj_set_size(s, W, BODY_H);
    lv_obj_set_style_bg_color(s, lv_color_hex(C_BG), 0);
    lv_obj_set_style_bg_opa(s, LV_OPA_COVER, 0);
    lv_obj_add_flag(s, LV_OBJ_FLAG_CLICKABLE);
    return s;
}

static void build_face(lv_obj_t *s)
{
    lv_obj_t *title = label(s, &lv_font_montserrat_28, C_ACC, 14, 2, 0);
    lv_label_set_text(title, "PWNI");
    s_level = label(s, &lv_font_montserrat_12, C_DIM, 170, 10, 134);
    lv_obj_set_style_text_align(s_level, LV_TEXT_ALIGN_RIGHT, 0);

    make_face(s);

    /* Pixel font and tight single-line stats keep the face screen uncluttered. */
    s_mood = label(s, &lv_font_unscii_16, C_ACC, 10, 270, 300);
    lv_obj_set_style_text_align(s_mood, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_text(s_mood, "observing");

    s_status = label(s, &lv_font_montserrat_12, 0xa0b8a0, 10, 288, 300);
    lv_label_set_long_mode(s_status, LV_LABEL_LONG_DOT);
    lv_obj_set_style_text_align(s_status, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_text(s_status, "booting up");

    s_stat1 = label(s, &lv_font_unscii_8, C_FG, 16, 308, 288);
    lv_obj_set_style_text_align(s_stat1, LV_TEXT_ALIGN_CENTER, 0);
    s_stat2 = label(s, &lv_font_unscii_8, C_DIM, 16, 319, 288);
    lv_obj_set_style_text_align(s_stat2, LV_TEXT_ALIGN_CENTER, 0);

    s_bond = label(s, &lv_font_montserrat_12, C_DIM, 16, 334, 288);
    lv_obj_set_style_text_align(s_bond, LV_TEXT_ALIGN_CENTER, 0);

    lv_obj_t *line = lv_obj_create(s);
    lv_obj_remove_style_all(line);
    lv_obj_set_pos(line, 20, 352);
    lv_obj_set_size(line, 280, 1);
    lv_obj_set_style_bg_color(line, lv_color_hex(C_LINE), 0);
    lv_obj_set_style_bg_opa(line, LV_OPA_COVER, 0);

    s_event = label(s, &lv_font_unscii_8, C_DIM, 16, 358, 288);
    lv_label_set_long_mode(s_event, LV_LABEL_LONG_DOT);
    lv_obj_set_style_text_align(s_event, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_text(s_event, "listening...");

    lv_obj_t *hint = label(s, &lv_font_montserrat_12, 0x39503c, 10, 376, 300);
    lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_text(hint, "tap the face");
}

static void build_scan(lv_obj_t *s)
{
    lv_obj_t *t = label(s, &lv_font_montserrat_20, C_ACC, 14, 6, 0);
    lv_label_set_text(t, "NETWORKS");
    s_scan_hint = label(s, &lv_font_montserrat_12, C_DIM, 14, 32, 210);
    lv_label_set_text(s_scan_hint, "scanning...");

    lv_obj_t *b = text_btn(s, "SCAN", 234, 8, 72, 32, true);
    lv_obj_add_event_cb(b, scan_btn_cb, LV_EVENT_CLICKED, NULL);

    s_scan_list = lv_obj_create(s);
    lv_obj_remove_style_all(s_scan_list);
    lv_obj_set_pos(s_scan_list, 8, 54);
    lv_obj_set_size(s_scan_list, 304, 364);
    lv_obj_set_scroll_dir(s_scan_list, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(s_scan_list, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_pad_all(s_scan_list, 0, 0);
}

static void build_loot(lv_obj_t *s)
{
    lv_obj_t *t = label(s, &lv_font_montserrat_20, C_ACC, 14, 6, 0);
    lv_label_set_text(t, "CAPTURES");
    s_loot_hint = label(s, &lv_font_montserrat_12, C_DIM, 14, 32, 290);
    lv_label_set_text(s_loot_hint, "");
    lv_obj_set_style_text_align(s_loot_hint, LV_TEXT_ALIGN_RIGHT, 0);

    s_loot_list = lv_obj_create(s);
    lv_obj_remove_style_all(s_loot_list);
    lv_obj_set_pos(s_loot_list, 8, 54);
    lv_obj_set_size(s_loot_list, 304, 364);
    lv_obj_set_scroll_dir(s_loot_list, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(s_loot_list, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_pad_all(s_loot_list, 0, 0);
}

static lv_obj_t *set_panel(lv_obj_t *parent, int y, int h, const char *title)
{
    lv_obj_t *p = box(parent, 0, y, 304, h, C_PANEL);
    lv_obj_t *t = label(p, &lv_font_montserrat_12, C_DIM, 12, 8, 280);
    lv_label_set_text(t, title);
    return p;
}

static void build_settings(lv_obj_t *s)
{
    lv_obj_t *list = lv_obj_create(s);
    lv_obj_remove_style_all(list);
    lv_obj_set_pos(list, 8, 4);
    lv_obj_set_size(list, 304, 418);
    lv_obj_set_scroll_dir(list, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(list, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_pad_all(list, 0, 0);

    int y = 0;

    lv_obj_t *p1 = set_panel(list, y, 156, "WIFI CONNECTION");
    s_set_conn = label(p1, &lv_font_montserrat_12, C_FG, 12, 30, 280);
    label_lines(s_set_conn, 2);
    lv_label_set_text(s_set_conn, "not connected");
    lv_obj_t *b = text_btn(p1, "SCAN", 12, 96, 84, 36, true);
    lv_obj_add_event_cb(b, btn_scan_cb, LV_EVENT_CLICKED, NULL);
    b = text_btn(p1, "DISCONNECT", 104, 96, 104, 36, false);
    lv_obj_add_event_cb(b, btn_disc_cb, LV_EVENT_CLICKED, NULL);
    b = text_btn(p1, "FORGET", 216, 96, 76, 36, false);
    lv_obj_add_event_cb(b, btn_forget_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *ac = label(p1, &lv_font_montserrat_12, C_DIM, 12, 136, 160);
    lv_label_set_text(ac, "reconnect at boot");
    s_sw_autoconn = lv_switch_create(p1);
    lv_obj_set_size(s_sw_autoconn, 44, 24);
    lv_obj_set_pos(s_sw_autoconn, 246, 130);
    lv_obj_add_event_cb(s_sw_autoconn, sw_auto_conn_cb, LV_EVENT_VALUE_CHANGED, NULL);
    y += 166;

    lv_obj_t *p2 = set_panel(list, y, 150, "WEB DASHBOARD");
    s_set_web = label(p2, &lv_font_montserrat_12, C_ACC2, 12, 36, 164);
    label_lines(s_set_web, 2);
    lv_label_set_text(s_set_web, "connect to WiFi first");
    lv_obj_t *wh = label(p2, &lv_font_montserrat_12, C_DIM, 12, 90, 164);
    lv_label_set_text(wh, "scan to open");

    /* White quiet-zone box around the QR so it scans reliably on a dark UI. */
    s_qr_box = box(p2, 184, 30, 108, 108, 0xffffff);
    lv_obj_set_style_radius(s_qr_box, 4, 0);
    lv_obj_set_style_border_width(s_qr_box, 0, 0);
    s_qr = lv_qrcode_create(s_qr_box);
    lv_qrcode_set_size(s_qr, 96);
    lv_qrcode_set_dark_color(s_qr, lv_color_hex(0x000000));
    lv_qrcode_set_light_color(s_qr, lv_color_hex(0xffffff));
    lv_obj_set_pos(s_qr, 6, 6);

    s_qr_offline = box(p2, 184, 30, 108, 108, C_PANEL);
    lv_obj_t *ol = lv_label_create(s_qr_offline);
    lv_obj_set_style_text_font(ol, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(ol, lv_color_hex(C_DIM), 0);
    lv_obj_set_style_text_align(ol, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_text(ol, "no\nlink");
    lv_obj_center(ol);
    lv_obj_add_flag(s_qr_box, LV_OBJ_FLAG_HIDDEN);
    y += 160;

    lv_obj_t *p3 = set_panel(list, y, 236, "ACTIVE ATTACKS");
    s_set_auth = label(p3, &lv_font_montserrat_12, C_WARN, 12, 30, 280);
    lv_label_set_text(s_set_auth, "locked - passive only");
    b = text_btn(p3, "UNLOCK", 12, 54, 130, 34, true);
    lv_obj_add_event_cb(b, btn_unlock_cb, LV_EVENT_CLICKED, NULL);
    b = text_btn(p3, "LOCK", 150, 54, 100, 34, false);
    lv_obj_add_event_cb(b, btn_lock_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *al = label(p3, &lv_font_montserrat_12, C_DIM, 12, 98, 180);
    lv_label_set_text(al, "auto-deauth while hunting");
    s_sw_auto = lv_switch_create(p3);
    lv_obj_set_size(s_sw_auto, 44, 24);
    lv_obj_set_pos(s_sw_auto, 246, 92);
    lv_obj_add_event_cb(s_sw_auto, sw_auto_cb, LV_EVENT_VALUE_CHANGED, NULL);

    lv_obj_t *sl = label(p3, &lv_font_montserrat_12, C_DIM, 12, 128, 100);
    lv_label_set_text(sl, "strategy");
    lv_obj_t *dd = lv_dropdown_create(p3);
    lv_obj_set_pos(dd, 100, 122);
    lv_obj_set_size(dd, 192, 36);
    lv_dropdown_set_options(dd,
        "auto (learning)\n"
        "linger 2.4 GHz\n"
        "hop 2.4 GHz\n"
        "5 GHz low\n"
        "5 GHz high\n"
        "hunt\n"
        "rest");
    lv_obj_set_style_bg_color(dd, lv_color_hex(0x0a0f0b), 0);
    lv_obj_set_style_text_color(dd, lv_color_hex(C_FG), 0);
    lv_obj_set_style_border_color(dd, lv_color_hex(C_LINE), 0);
    lv_obj_set_style_text_font(dd, &lv_font_montserrat_12, 0);
    lv_obj_add_event_cb(dd, strat_cb, LV_EVENT_VALUE_CHANGED, NULL);
    b = text_btn(p3, "STOP DEAUTH", 12, 164, 128, 34, false);
    lv_obj_add_event_cb(b, btn_stop_deauth_cb, LV_EVENT_CLICKED, NULL);
    s_set_deauth = label(p3, &lv_font_montserrat_12, C_ACC, 148, 172, 140);
    lv_label_set_text(s_set_deauth, "idle");
    lv_obj_t *ah = label(p3, &lv_font_montserrat_12, 0x6f8a72, 12, 204, 280);
    lv_label_set_text(ah, "Run deauths only on networks you own.");
    y += 246;

    lv_obj_t *p4 = set_panel(list, y, 118, "DISPLAY");
    lv_obj_t *bl = label(p4, &lv_font_montserrat_12, C_DIM, 12, 42, 60);
    lv_label_set_text(bl, "light");
    s_slider = lv_slider_create(p4);
    lv_obj_set_pos(s_slider, 54, 40);
    lv_obj_set_size(s_slider, 220, 16);
    lv_slider_set_range(s_slider, 10, 100);
    lv_slider_set_value(s_slider, s_user_brightness, LV_ANIM_OFF);
    lv_obj_set_style_bg_color(s_slider, lv_color_hex(0x162016), 0);
    lv_obj_set_style_bg_color(s_slider, lv_color_hex(C_ACC), LV_PART_INDICATOR);
    lv_obj_add_event_cb(s_slider, slider_cb, LV_EVENT_VALUE_CHANGED, NULL);

    lv_obj_t *to = label(p4, &lv_font_montserrat_12, C_DIM, 12, 78, 60);
    lv_label_set_text(to, "sleep");
    s_sleep_dd = lv_dropdown_create(p4);
    lv_obj_set_pos(s_sleep_dd, 54, 72);
    lv_obj_set_size(s_sleep_dd, 220, 36);
    lv_dropdown_set_options(s_sleep_dd, k_timeout_options);
    lv_dropdown_set_selected(s_sleep_dd, timeout_index(s_timeout_s));
    lv_obj_set_style_bg_color(s_sleep_dd, lv_color_hex(0x0a0f0b), 0);
    lv_obj_set_style_text_color(s_sleep_dd, lv_color_hex(C_FG), 0);
    lv_obj_set_style_border_color(s_sleep_dd, lv_color_hex(C_LINE), 0);
    lv_obj_set_style_text_font(s_sleep_dd, &lv_font_montserrat_12, 0);
    lv_obj_add_event_cb(s_sleep_dd, sleep_cb, LV_EVENT_VALUE_CHANGED, NULL);
    y += 128;

    lv_obj_t *p5 = set_panel(list, y, 176, "SYSTEM");
    s_set_sys = label(p5, &lv_font_unscii_8, C_DIM, 12, 28, 280);
    label_lines(s_set_sys, 4);
    lv_label_set_text(s_set_sys, "");
    b = text_btn(p5, "GITHUB OTA", 12, 78, 272, 34, false);
    lv_obj_add_event_cb(b, github_ota_cb, LV_EVENT_CLICKED, NULL);
    b = text_btn(p5, "RESET BRAIN", 12, 124, 132, 36, false);
    lv_obj_add_event_cb(b, reset_brain_cb, LV_EVENT_CLICKED, NULL);
    b = text_btn(p5, "REBOOT", 156, 124, 132, 36, false);
    lv_obj_add_event_cb(b, reboot_cb, LV_EVENT_CLICKED, NULL);
}

/* ---- timer ------------------------------------------------------------ */

static void ui_timer_cb(lv_timer_t *t)
{
    (void)t;
    if (!s_ready) {
        return;
    }
    uint32_t now = now_ms();
    s_tick++;

    pwn_pet_t pet;
    pet_snapshot(&pet);
    const pwn_wifi_stats_t *st = pwn_wifi_stats();

    /* Blink every ~4 s for ~400 ms. */
    bool blink = (s_tick % 20) < 2;
    if (blink != s_blink || pet.mood != s_last_mood) {
        s_blink = blink;
        s_last_mood = pet.mood;
        face_apply(pet.mood, blink);
    }
    if (pet.mood == MOOD_SLEEPING) {
        lv_label_set_text(s_z, (s_tick / 5) % 2 ? "z Z" : "Z z");
    } else {
        lv_label_set_text(s_z, "");
    }
    if (!blink && pet.mood != MOOD_SLEEPING) {
        /* idle eye darts */
        int dx = ((int)(s_tick / 13) % 3 - 1) * 9;
        int dy = ((int)(s_tick / 17) % 3 - 1) * 6;
        lv_obj_align(s_pupil_l, LV_ALIGN_CENTER, dx, dy);
        lv_obj_align(s_pupil_r, LV_ALIGN_CENTER, dx, dy);
    }

    lv_label_set_text(s_mood, pet_mood_name(pet.mood));
    lv_label_set_text(s_status, pet.status);
    lv_label_set_text_fmt(s_stat1, "CH %02u  %s  AP %03u  HS %03u",
                          (unsigned)st->channel,
                          st->band == 5 ? "5G  " : "2.4G",
                          (unsigned)st->ap_count, (unsigned)st->hs_count);
    lv_label_set_text_fmt(s_stat2, "PWN %03u  PMK %03u  CLI %03u",
                          (unsigned)st->saved_count,
                          (unsigned)st->pmkid_count,
                          (unsigned)st->client_count);
    lv_label_set_text_fmt(s_bond, "BOND %u%%   LV %u   XP %u",
                          (unsigned)pet.bond, (unsigned)pet.level,
                          (unsigned)pet.xp);
    lv_label_set_text(s_event, st->last_event[0] ? st->last_event : "listening...");
    lv_label_set_text_fmt(s_level, "LV %u  %s", (unsigned)pet.level,
                          pet.paused ? "Zz" : pet_action_name(pet.action));

    /* Settings readouts, once per second. */
    if ((s_tick % 5) == 0) {
    pwn_net_status_t net;
    net_get_status(&net);
    if (s_set_conn) {
        if (net.connected) {
            lv_label_set_text_fmt(s_set_conn,
                "%s  %d dBm\nhttp://%s/", net.ssid, net.rssi, net.ip);
            lv_obj_set_style_text_color(s_set_conn, lv_color_hex(C_ACC), 0);
        } else if ((net.setup_mode || net.ap_active) && !net.connecting) {
            lv_label_set_text_fmt(s_set_conn, "SETUP AP %s\nhttp://%s/",
                                  net.ap_ssid, net.ap_ip);
            lv_obj_set_style_text_color(s_set_conn, lv_color_hex(C_WARN), 0);
        } else if (net.connecting) {
            if (net.setup_mode || net.ap_active) {
                lv_label_set_text_fmt(s_set_conn, "joining %s...\nAP %s",
                                      net.ssid, net.ap_ssid);
            } else {
                lv_label_set_text_fmt(s_set_conn, "connecting to %s...", net.ssid);
            }
            lv_obj_set_style_text_color(s_set_conn, lv_color_hex(C_WARN), 0);
        } else if (net.have_creds) {
            lv_label_set_text_fmt(s_set_conn, "disconnected\nsaved: %s", net.ssid);
            lv_obj_set_style_text_color(s_set_conn, lv_color_hex(C_DIM), 0);
        } else {
            lv_label_set_text(s_set_conn, "no network\nscan to connect");
            lv_obj_set_style_text_color(s_set_conn, lv_color_hex(C_DIM), 0);
        }
        if (s_set_web) {
            const char *web_ip = NULL;
            if (net.connected && net.ip[0]) {
                web_ip = net.ip;
            } else if ((net.setup_mode || net.ap_active) && net.ap_ip[0]) {
                web_ip = net.ap_ip;
            }
            if (web_ip) {
                char url[32];
                snprintf(url, sizeof(url), "http://%s/", web_ip);
                lv_label_set_text(s_set_web, url);
                lv_obj_set_style_text_color(s_set_web,
                    lv_color_hex(net.connected ? C_ACC2 : C_WARN), 0);
                if (strcmp(url, s_qr_url) != 0) {
                    if (lv_qrcode_update(s_qr, url, strlen(url)) == LV_RESULT_OK) {
                        snprintf(s_qr_url, sizeof(s_qr_url), "%s", url);
                        lv_obj_add_flag(s_qr_offline, LV_OBJ_FLAG_HIDDEN);
                        lv_obj_clear_flag(s_qr_box, LV_OBJ_FLAG_HIDDEN);
                    } else {
                        /* Not expected for a short URL, but do not leave a
                         * stale QR pointing at an old address. */
                        s_qr_url[0] = 0;
                        lv_obj_add_flag(s_qr_box, LV_OBJ_FLAG_HIDDEN);
                        lv_obj_clear_flag(s_qr_offline, LV_OBJ_FLAG_HIDDEN);
                    }
                }
            } else {
                lv_label_set_text(s_set_web, "connect to\nWiFi first");
                if (s_qr_url[0]) {
                    s_qr_url[0] = 0;
                }
                lv_obj_add_flag(s_qr_box, LV_OBJ_FLAG_HIDDEN);
                lv_obj_clear_flag(s_qr_offline, LV_OBJ_FLAG_HIDDEN);
            }
        }
        s_sw_busy = true;
        if (net.autoconnect) lv_obj_add_state(s_sw_autoconn, LV_STATE_CHECKED);
        else lv_obj_remove_state(s_sw_autoconn, LV_STATE_CHECKED);
        if (pwn_wifi_authorized()) {
            lv_obj_remove_state(s_sw_auto, LV_STATE_DISABLED);
            if (pwn_wifi_auto_deauth()) lv_obj_add_state(s_sw_auto, LV_STATE_CHECKED);
            else lv_obj_remove_state(s_sw_auto, LV_STATE_CHECKED);
        } else {
            lv_obj_remove_state(s_sw_auto, LV_STATE_CHECKED);
            lv_obj_add_state(s_sw_auto, LV_STATE_DISABLED);
        }
        s_sw_busy = false;

        if (s_set_auth) {
            if (pwn_wifi_authorized()) {
                lv_label_set_text(s_set_auth, "unlocked - use with permission");
                lv_obj_set_style_text_color(s_set_auth, lv_color_hex(C_BAD), 0);
            } else {
                lv_label_set_text(s_set_auth, "locked - passive only");
                lv_obj_set_style_text_color(s_set_auth, lv_color_hex(C_WARN), 0);
            }
        }
        if (s_set_deauth) {
            if (pwn_hunt_active()) {
                lv_label_set_text(s_set_deauth, "hunt active");
            } else {
                lv_label_set_text(s_set_deauth,
                    pwn_wifi_deauth_active() ? "burst active" : "idle");
            }
        }
    }
    }

    if ((s_tick % 10) == 0 && s_set_sys) {
        uint32_t up = now / 1000;
        lv_label_set_text_fmt(s_set_sys,
            "CPU  %d MHz    FLASH %s\n"
            "PSRAM %s %s\n"
            "HEAP %u KB   SD %s\n"
            "UP   %um %us   DROP %u",
            CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ, CONFIG_ESPTOOLPY_FLASHFREQ,
#if CONFIG_SPIRAM_SPEED_120M
            "120",
#else
            "80",
#endif
            "MHz", (unsigned)(esp_get_free_heap_size() / 1024),
            capture_sd_ready() ? "ok" : "none",
            (unsigned)(up / 60), (unsigned)(up % 60),
            (unsigned)st->dropped);
    }

    /* Scan tab refresh. */
    if (s_tab == TAB_SCAN) {
        if (s_scan_done) {
            s_scan_done = false;
            s_scan_last = now;
            scan_refresh();
        } else if (now - s_scan_last > 9000) {
            s_scan_last = now;
            scan_refresh();
        }
        if (s_scan_hint) {
            lv_label_set_text_fmt(s_scan_hint, "%u networks  %s",
                                  (unsigned)s_ui_ap_count,
                                  s_scan_running ? "scanning..." : "tap to connect");
        }
    }

    /* Loot refresh. */
    if (s_tab == TAB_LOOT && now - s_loot_last > 3000) {
        s_loot_last = now;
        loot_refresh();
        if (s_loot_hint) {
            lv_label_set_text_fmt(s_loot_hint, "%d captured", s_ui_hs_count);
        }
    }

    /*
     * Backlight idle management. LVGL tracks touch activity for us, so the
     * same mechanism covers every tab and any widget. Dim at 75% of the
     * timeout, blank at the timeout, and use the slider value on wake.
     * Keep the panel awake while the user is in a modal, while a deauth burst
     * is running, and during GitHub OTA so progress stays visible.
     */
    bool hold_awake = (s_modal != NULL) || web_ota_busy() ||
                      pwn_wifi_deauth_active() || pwn_hunt_active();
    uint32_t idle = lv_display_get_inactive_time(NULL);
    if (hold_awake) {
        if (s_dimmed || s_blanked) {
            screen_wake();
        }
        lv_display_trigger_activity(NULL);
    } else if (s_timeout_s > 0) {
        uint32_t blank_ms = (uint32_t)s_timeout_s * 1000u;
        uint32_t dim_ms = (blank_ms * 3u) / 4u;
        if (!s_blanked && idle >= blank_ms) {
            s_blanked = true;
            s_dimmed = true;
            bsp_display_brightness_set(0);
            if (s_wake_overlay) {
                lv_obj_clear_flag(s_wake_overlay, LV_OBJ_FLAG_HIDDEN);
                lv_obj_move_foreground(s_wake_overlay);
            }
        } else if (!s_dimmed && idle >= dim_ms) {
            int dim = (s_user_brightness * 15) / 100;
            if (dim < 5) {
                dim = 5;
            }
            s_dimmed = true;
            bsp_display_brightness_set(dim);
        } else if ((s_dimmed || s_blanked) && idle < 1000) {
            /* Touch arrived without hitting the wake overlay (for example a
             * modal was open when the screen dimmed). */
            screen_wake();
        }
    }

    /* Toast timeout. */
    if (s_toast && s_toast_until && now > s_toast_until) {
        lv_obj_add_flag(s_toast, LV_OBJ_FLAG_HIDDEN);
        s_toast_until = 0;
    }
}

/* ---- init ------------------------------------------------------------- */

void ui_init(void)
{
    timeout_load();

    if (bsp_display_lock(1000) != ESP_OK) {
        ESP_LOGE(TAG, "could not lock display");
        return;
    }

    lv_obj_t *scr = lv_screen_active();
    lv_obj_set_style_bg_color(scr, lv_color_hex(C_BG), 0);
    lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);

    s_ui_hs = heap_caps_malloc(PWN_MAX_HS * sizeof(pwn_handshake_t),
                               MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_ui_hs) {
        ESP_LOGW(TAG, "no PSRAM for capture snapshot, using internal RAM");
        s_ui_hs = malloc(PWN_MAX_HS * sizeof(pwn_handshake_t));
    }

    for (int i = 0; i < TAB_COUNT; i++) {
        s_screen[i] = make_screen();
    }
    build_face(s_screen[TAB_FACE]);
    build_scan(s_screen[TAB_SCAN]);
    build_loot(s_screen[TAB_LOOT]);
    build_settings(s_screen[TAB_SET]);

    /* Bottom navigation. */
    lv_obj_t *nav = lv_obj_create(scr);
    lv_obj_remove_style_all(nav);
    lv_obj_set_pos(nav, 0, BODY_H);
    lv_obj_set_size(nav, W, NAV_H);
    lv_obj_set_style_bg_color(nav, lv_color_hex(0x080d09), 0);
    lv_obj_set_style_bg_opa(nav, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(nav, 1, 0);
    lv_obj_set_style_border_side(nav, LV_BORDER_SIDE_TOP, 0);
    lv_obj_set_style_border_color(nav, lv_color_hex(C_LINE), 0);
    lv_obj_remove_flag(nav, LV_OBJ_FLAG_SCROLLABLE);

    static const char *names[TAB_COUNT] = {"FACE", "SCAN", "LOOT", "SET"};
    for (int i = 0; i < TAB_COUNT; i++) {
        lv_obj_t *b = lv_button_create(nav);
        lv_obj_set_pos(b, 8 + i * 78, 5);
        lv_obj_set_size(b, 72, 44);
        lv_obj_set_style_radius(b, 9, 0);
        lv_obj_set_style_shadow_width(b, 0, 0);
        lv_obj_set_style_bg_color(b, lv_color_hex(C_PANEL), 0);
        lv_obj_set_style_bg_opa(b, LV_OPA_COVER, 0);
        lv_obj_set_style_border_width(b, 0, 0);
        lv_obj_add_event_cb(b, nav_cb, LV_EVENT_CLICKED, (void *)(intptr_t)i);
        lv_obj_t *l = lv_label_create(b);
        lv_obj_set_style_text_font(l, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(l, lv_color_hex(C_DIM), 0);
        lv_label_set_text(l, names[i]);
        lv_obj_center(l);
        s_nav_btn[i] = b;
        s_nav_lbl[i] = l;
    }

    /* Toast, above the nav bar. */
    s_toast = lv_obj_create(lv_layer_top());
    lv_obj_remove_style_all(s_toast);
    lv_obj_set_size(s_toast, 290, 38);
    lv_obj_align(s_toast, LV_ALIGN_BOTTOM_MID, 0, -(NAV_H + 8));
    lv_obj_set_style_bg_color(s_toast, lv_color_hex(0x102015), 0);
    lv_obj_set_style_bg_opa(s_toast, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(s_toast, 1, 0);
    lv_obj_set_style_border_color(s_toast, lv_color_hex(C_ACC), 0);
    lv_obj_set_style_radius(s_toast, 9, 0);
    lv_obj_set_style_pad_all(s_toast, 6, 0);
    lv_obj_t *tl = lv_label_create(s_toast);
    lv_obj_set_style_text_font(tl, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(tl, lv_color_hex(C_FG), 0);
    lv_label_set_text(tl, "");
    lv_obj_center(tl);
    s_toast_lbl = tl;
    lv_obj_add_flag(s_toast, LV_OBJ_FLAG_HIDDEN);

    /* Transparent wake-catcher above everything. It is only enabled while
     * the backlight is blanked so the first tap cannot press a control that
     * the user cannot see. */
    s_wake_overlay = lv_obj_create(lv_layer_top());
    lv_obj_remove_style_all(s_wake_overlay);
    lv_obj_set_pos(s_wake_overlay, 0, 0);
    lv_obj_set_size(s_wake_overlay, W, H);
    lv_obj_add_flag(s_wake_overlay, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(s_wake_overlay, wake_overlay_cb, LV_EVENT_PRESSED, NULL);
    lv_obj_add_flag(s_wake_overlay, LV_OBJ_FLAG_HIDDEN);

    s_last_mood = (pwn_mood_t)-1;
    s_blink = false;
    screen_show(TAB_FACE);
    face_apply(MOOD_OBSERVING, false);

    s_ready = true;
    lv_timer_create(ui_timer_cb, 200, NULL);

    bsp_display_unlock();
    ESP_LOGI(TAG, "Pwnagotchi UI ready (tabs: face/scan/loot/set)");
}
