#include "pwn_cli.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/usb_serial_jtag.h"

#include "lvgl.h"
#include "bsp/esp-bsp.h"
#include "esp_lcd_touch.h"

#include "pwn_config.h"
#include "pwn_ui.h"
#include "pwn_net.h"
#include "pwn_wifi.h"
#include "pwn_capture.h"
#include "pwn_pet.h"

static const char *TAG = "cli";

static void *big_calloc(size_t n, size_t size)
{
    void *p = heap_caps_calloc(n, size, MALLOC_CAP_SPIRAM);
    return p ? p : calloc(n, size);
}

static bool phrase_matches(const char *phrase)
{
    if (!phrase) {
        return false;
    }
    while (*phrase == ' ' || *phrase == '\t' || *phrase == '\r' || *phrase == '\n') {
        phrase++;
    }
    size_t len = strlen(phrase);
    while (len > 0) {
        char c = phrase[len - 1];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
            break;
        }
        len--;
    }
    size_t want = strlen(PWN_AUTH_PHRASE);
    return len == want && strncasecmp(phrase, PWN_AUTH_PHRASE, len) == 0;
}

static void print_help(void)
{
    printf("\n"
           "  PWNI %s — commands\n"
           "  ------------------------------------------------\n"
           "  status              pet + radio summary\n"
           "  aps [n]             list access points by signal\n"
           "  clients [n]         list stations\n"
           "  hs                  captured handshakes / PMKIDs\n"
           "  scan                force a synchronous scan\n"
           "  plan <name>         force a hop plan (linger-2g, hop-2g,\n"
           "                      scan-5g-low, scan-5g-high, hunt, rest)\n"
           "  hop <ch>            park on one channel\n"
           "  selftest            inject a fake handshake, verify the PCAP\n"
           "  shot                dump a small BMP screenshot over serial\n"
           "  tab <0-3>           show FACE/SCAN/LOOT/SET screen\n"
           "  touchtest           print touch coordinates for 10 seconds\n"
           "  wifi <ssid> <pass>  connect headlessly (saved to NVS)\n"
           "  pause | resume      stop/start channel hopping\n"
           "  auth <phrase>       unlock active attacks (build-gated)\n"
           "  reset-brain         wipe the learned policy\n"
           "  save                flush handshakes to SD\n"
           "  reboot              restart the device\n"
           "  help                this text\n\n",
           PWN_VERSION);
}

static void print_status(void)
{
    pwn_pet_t pet;
    pet_snapshot(&pet);
    const pwn_wifi_stats_t *st = pwn_wifi_stats();

    uint32_t up = (uint32_t)(esp_timer_get_time() / 1000000);

    printf("\n  PWNI %s   up %lus   mood=%s   action=%s\n",
           PWN_VERSION, (unsigned long)up, pet_mood_name(pet.mood),
           pet_action_name(pet.action));
    printf("  level %u  xp %u  bond %u%%  epochs %u\n",
           (unsigned)pet.level, (unsigned)pet.xp, (unsigned)pet.bond,
           (unsigned)pet.epochs);
    printf("  reward %.3f  avg %.3f  best %.3f\n",
           pet.reward, pet.avg_reward, pet.best_reward);
    printf("  aps %u  clients %u  frames %u  dropped %u\n",
           (unsigned)st->ap_count, (unsigned)st->client_count,
           (unsigned)st->frames, (unsigned)st->dropped);
    printf("  channel %u (%s)  hops %u  dwell %s\n",
           (unsigned)st->channel, st->band == 5 ? "5G" : "2.4G",
           (unsigned)st->hops, "policy");
    printf("  handshakes %u  pmkid %u  saved %u  sd %s\n",
           (unsigned)st->hs_count, (unsigned)st->pmkid_count,
           (unsigned)st->saved_count, st->sd_ready ? "ready" : "none");
    printf("  eapol %u  deauth-seen %u  probes %u  beacons %u\n",
           (unsigned)st->eapol, (unsigned)st->deauths,
           (unsigned)st->probes, (unsigned)st->beacons);
    printf("  active attacks: %s\n", st->authorized ? "ENABLED" : "disabled");
    printf("  last: %s\n\n", st->last_event);
}

static void print_aps(int limit)
{
    pwn_ap_t *aps = big_calloc(PWN_MAX_APS, sizeof(pwn_ap_t));
    if (!aps) return;
    int n = pwn_wifi_ap_snapshot(aps, PWN_MAX_APS);

    /* Simple insertion sort by RSSI, descending. */
    for (int i = 1; i < n; i++) {
        pwn_ap_t key = aps[i];
        int j = i - 1;
        while (j >= 0 && aps[j].rssi < key.rssi) {
            aps[j + 1] = aps[j];
            j--;
        }
        aps[j + 1] = key;
    }

    printf("\n  %d access point%s\n", n, n == 1 ? "" : "s");
    if (limit > n) limit = n;
    for (int i = 0; i < limit; i++) {
        printf("  %3d dBm  ch%-3u %-5s %s%s\n",
               aps[i].rssi, aps[i].channel,
               aps[i].security == SEC_OPEN ? "open" :
               aps[i].security == SEC_WEP ? "wep" :
               aps[i].security == SEC_WPA ? "wpa" :
               aps[i].security == SEC_WPA2 ? "wpa2" :
               aps[i].security == SEC_WPA3 ? "wpa3" : "?",
               aps[i].ssid[0] ? aps[i].ssid : "<hidden>",
               aps[i].wps ? " [wps]" : "");
    }
    printf("\n");
    free(aps);
}

static void print_clients(int limit)
{
    pwn_client_t *cs = calloc(PWN_MAX_CLIENTS, sizeof(pwn_client_t));
    if (!cs) return;
    int n = pwn_wifi_client_snapshot(cs, PWN_MAX_CLIENTS);
    printf("\n  %d station%s\n", n, n == 1 ? "" : "s");
    if (limit > n) limit = n;
    for (int i = 0; i < limit; i++) {
        printf("  %02x:%02x:%02x:%02x:%02x:%02x  %4d dBm  %u frames\n",
               cs[i].mac[0], cs[i].mac[1], cs[i].mac[2],
               cs[i].mac[3], cs[i].mac[4], cs[i].mac[5],
               cs[i].rssi, (unsigned)cs[i].frames);
    }
    printf("\n");
    free(cs);
}

static void print_hs(void)
{
    pwn_handshake_t *hs = big_calloc(PWN_MAX_HS, sizeof(pwn_handshake_t));
    if (!hs) return;
    int n = capture_snapshot(hs, PWN_MAX_HS);
    printf("\n  %d handshake slot%s  (sd: %s)\n",
           n, n == 1 ? "" : "s", capture_sd_ready() ? "ready" : "none");
    for (int i = 0; i < n; i++) {
        printf("  %-16s %02x:%02x:%02x:%02x:%02x:%02x  "
               "mask=0x%x%s%s%s\n",
               hs[i].ssid[0] ? hs[i].ssid : "<hidden>",
               hs[i].bssid[0], hs[i].bssid[1], hs[i].bssid[2],
               hs[i].bssid[3], hs[i].bssid[4], hs[i].bssid[5],
               hs[i].msg_mask,
               hs[i].has_pmkid ? " pmkid" : "",
               hs[i].complete ? " complete" : "",
               hs[i].saved ? " saved" : "");
    }
    printf("\n");
    free(hs);
}

static void b64_line(const uint8_t *src, int len, char *dst)
{
    static const char tab[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i = 0, o = 0;
    while (i + 2 < len) {
        uint32_t v = ((uint32_t)src[i] << 16) |
                     ((uint32_t)src[i + 1] << 8) | src[i + 2];
        dst[o++] = tab[(v >> 18) & 63];
        dst[o++] = tab[(v >> 12) & 63];
        dst[o++] = tab[(v >> 6) & 63];
        dst[o++] = tab[v & 63];
        i += 3;
    }
    if (i < len) {
        uint32_t v = (uint32_t)src[i] << 16;
        if (i + 1 < len) {
            v |= (uint32_t)src[i + 1] << 8;
        }
        dst[o++] = tab[(v >> 18) & 63];
        dst[o++] = tab[(v >> 12) & 63];
        dst[o++] = (i + 1 < len) ? tab[(v >> 6) & 63] : '=';
        dst[o++] = '=';
    }
    dst[o] = '\0';
}

static void b64_dump(const uint8_t *data, size_t len)
{
    char line[80];
    size_t off = 0;
    while (off < len) {
        size_t n = len - off;
        if (n > 57) {
            n = 57;
        }
        b64_line(data + off, (int)n, line);
        printf("%s\n", line);
        off += n;
    }
}

/* Debug helper: 160x240 BMP of the active screen, base64 over the console. */
static void cli_shot(void)
{
    if (bsp_display_lock(2000) != ESP_OK) {
        printf("shot: display busy\n");
        return;
    }
    lv_draw_buf_t *snap = lv_snapshot_take(lv_screen_active(),
                                           LV_COLOR_FORMAT_RGB565);
    bsp_display_unlock();
    if (!snap) {
        printf("shot: snapshot failed\n");
        return;
    }

    const int sw = (int)snap->header.w;
    const int sh = (int)snap->header.h;
    const int dw = sw / 2;
    const int dh = sh / 2;
    const int row = (dw * 3 + 3) & ~3;
    const int pixels = row * dh;
    const int file_bytes = 54 + pixels;

    uint8_t *bmp = malloc(file_bytes);
    if (!bmp) {
        lv_draw_buf_destroy(snap);
        printf("shot: out of memory\n");
        return;
    }
    memset(bmp, 0, file_bytes);

#define PUT16(o, v) do { bmp[(o)] = (v) & 0xff; bmp[(o) + 1] = ((v) >> 8) & 0xff; } while (0)
#define PUT32(o, v) do { PUT16((o), (v)); PUT16((o) + 2, (v) >> 16); } while (0)
    bmp[0] = 'B';
    bmp[1] = 'M';
    PUT32(2, file_bytes);
    PUT32(10, 54);
    PUT32(14, 40);
    PUT32(18, dw);
    PUT32(22, dh);
    PUT16(26, 1);
    PUT16(28, 24);
    PUT32(34, pixels);
    PUT32(38, 2835);
    PUT32(42, 2835);

    for (int y = 0; y < dh; y++) {
        uint8_t *dst = bmp + 54 + (dh - 1 - y) * row;
        for (int x = 0; x < dw; x++) {
            unsigned r = 0, g = 0, b = 0;
            for (int yy = 0; yy < 2; yy++) {
                const uint16_t *src = (const uint16_t *)(snap->data +
                    (size_t)(y * 2 + yy) * snap->header.stride);
                for (int xx = 0; xx < 2; xx++) {
                    uint16_t v = src[x * 2 + xx];
                    unsigned r5 = (v >> 11) & 0x1f;
                    unsigned g6 = (v >> 5) & 0x3f;
                    unsigned b5 = v & 0x1f;
                    r += (r5 << 3) | (r5 >> 2);
                    g += (g6 << 2) | (g6 >> 4);
                    b += (b5 << 3) | (b5 >> 2);
                }
            }
            dst[x * 3 + 0] = (uint8_t)(b / 4);
            dst[x * 3 + 1] = (uint8_t)(g / 4);
            dst[x * 3 + 2] = (uint8_t)(r / 4);
        }
    }
#undef PUT16
#undef PUT32

    printf("SHOT-BEGIN %d %d\n", dw, dh);
    b64_dump(bmp, file_bytes);
    printf("SHOT-END\n");
    free(bmp);
    lv_draw_buf_destroy(snap);
}

static void cli_tab(const char *arg)
{
    int idx = arg ? atoi(arg) : 0;
    if (bsp_display_lock(1000) != ESP_OK) {
        printf("tab: display busy\n");
        return;
    }
    ui_show_tab(idx);
    bsp_display_unlock();
    printf("tab %d\n", idx);
}

/* Diagnostic: poll the touch controller directly while LVGL input is paused. */
static void cli_touchtest(void)
{
    esp_lcd_touch_handle_t tp = bsp_display_get_touch_handle();
    lv_indev_t *indev = bsp_display_get_input_dev();
    if (!tp) {
        printf("touchtest: no touch controller\n");
        return;
    }
    if (indev) {
        lv_indev_enable(indev, false);
    }
    printf("touchtest: tap the screen for 10 seconds\n");
    uint32_t end = (uint32_t)(esp_timer_get_time() / 1000) + 10000;
    int last_x = -1, last_y = -1;
    while ((uint32_t)(esp_timer_get_time() / 1000) < end) {
        esp_lcd_touch_read_data(tp);
        esp_lcd_touch_point_data_t pt[1];
        uint8_t n = 0;
        if (esp_lcd_touch_get_data(tp, pt, &n, 1) == ESP_OK && n > 0) {
            if ((int)pt[0].x != last_x || (int)pt[0].y != last_y) {
                printf("touch x=%u y=%u\n",
                       (unsigned)pt[0].x, (unsigned)pt[0].y);
                last_x = (int)pt[0].x;
                last_y = (int)pt[0].y;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(30));
    }
    if (indev) {
        lv_indev_enable(indev, true);
    }
    printf("touchtest: done\n");
}

static void handle_line(char *line)
{
    char *cmd = line;
    while (*cmd == ' ') cmd++;
    char *arg = strchr(cmd, ' ');
    if (arg) {
        *arg++ = 0;
        while (*arg == ' ') arg++;
    }

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
        print_help();
    } else if (strcmp(cmd, "status") == 0) {
        print_status();
    } else if (strcmp(cmd, "aps") == 0) {
        print_aps(arg ? atoi(arg) : 25);
    } else if (strcmp(cmd, "clients") == 0) {
        print_clients(arg ? atoi(arg) : 25);
    } else if (strcmp(cmd, "hs") == 0) {
        print_hs();
    } else if (strcmp(cmd, "scan") == 0) {
        int n = pwn_wifi_scan_now();
        printf("scan: %d APs\n", n);
    } else if (strcmp(cmd, "plan") == 0) {
        if (!arg) {
            printf("usage: plan linger-2g|hop-2g|scan-5g-low|scan-5g-high|hunt|rest\n");
        } else {
            int found = -1;
            for (int a = 0; a < ACT_COUNT; a++) {
                if (strcmp(arg, brain_policy((brain_action_t)a)->name) == 0) {
                    found = a;
                    break;
                }
            }
            if (found < 0) {
                printf("unknown plan\n");
            } else {
                pwn_wifi_apply_policy(brain_policy((brain_action_t)found),
                                      pwn_wifi_authorized());
                printf("plan: %s\n", arg);
            }
        }
    } else if (strcmp(cmd, "hop") == 0) {
        if (!arg) {
            printf("usage: hop <channel>\n");
        } else {
            int ch = atoi(arg);
            if (ch <= 0 || ch > 196) {
                printf("bad channel\n");
            } else if (pwn_wifi_force_channel((uint8_t)ch) == ESP_OK) {
                printf("parked on channel %d\n", ch);
            } else {
                printf("channel %d rejected (country/band)\n", ch);
            }
        }
    } else if (strcmp(cmd, "shot") == 0) {
        cli_shot();
    } else if (strcmp(cmd, "tab") == 0) {
        cli_tab(arg);
    } else if (strcmp(cmd, "touchtest") == 0) {
        cli_touchtest();
    } else if (strcmp(cmd, "wifi") == 0) {
        char *ssid = arg;
        char *pass = ssid ? strchr(ssid, ' ') : NULL;
        if (pass) {
            *pass++ = 0;
            while (*pass == ' ') pass++;
        }
        if (!ssid || !ssid[0]) {
            printf("usage: wifi <ssid> <password>\n");
        } else {
            esp_err_t err = net_connect(ssid, pass ? pass : "", true);
            printf("wifi: %s\n", err == ESP_OK ? "connecting" : esp_err_to_name(err));
        }
    } else if (strcmp(cmd, "selftest") == 0) {
        int rc = pwn_wifi_selftest();
        printf("selftest: %s (%d)\n", rc == 0 ? "OK" : "FAILED", rc);
    } else if (strcmp(cmd, "pause") == 0) {
        pet_set_paused(true);
        printf("paused\n");
    } else if (strcmp(cmd, "resume") == 0) {
        pet_set_paused(false);
        printf("resumed\n");
    } else if (strcmp(cmd, "auth") == 0) {
        if (!arg) {
            printf("usage: auth %s\n", PWN_AUTH_PHRASE);
        } else if (!phrase_matches(arg)) {
            printf("wrong phrase\n");
        } else if (!PWN_ENABLE_DEAUTH) {
            printf("active attacks are compiled out (PWN_ENABLE_DEAUTH=0)\n");
            printf("this build is passive; see docs/LEGAL.md\n");
        } else {
            pwn_wifi_set_authorized(true);
            printf("active attacks enabled for this session\n");
        }
    } else if (strcmp(cmd, "reset-brain") == 0) {
        pet_reset_brain();
        printf("brain reset\n");
    } else if (strcmp(cmd, "save") == 0) {
        capture_flush_all();
        printf("handshakes flushed\n");
    } else if (strcmp(cmd, "reboot") == 0) {
        capture_flush_all();
        printf("rebooting...\n");
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_restart();
    } else if (cmd[0]) {
        printf("unknown: %s (try 'help')\n", cmd);
    }
    printf("pwni> ");
    fflush(stdout);
}

static void cli_task(void *arg)
{
    (void)arg;

    if (!usb_serial_jtag_is_driver_installed()) {
        usb_serial_jtag_driver_config_t cfg =
            USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
        esp_err_t err = usb_serial_jtag_driver_install(&cfg);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "usb serial driver: %s", esp_err_to_name(err));
        }
    }

    printf("\n\nesp32touch / PWNI %s — type 'help'\npwni> ", PWN_VERSION);
    fflush(stdout);

    char line[160];
    int len = 0;

    for (;;) {
        uint8_t c;
        int n = usb_serial_jtag_read_bytes(&c, 1, pdMS_TO_TICKS(200));
        if (n <= 0) {
            continue;
        }
        if (c == '\r') {
            continue;
        }
        if (c == '\n') {
            line[len] = 0;
            if (len > 0) {
                handle_line(line);
            }
            len = 0;
        } else if (c == 8 || c == 127) {
            if (len > 0) len--;
        } else if (len < (int)sizeof(line) - 1) {
            line[len++] = (char)c;
        }
    }
}

void cli_start(void)
{
    /* 16 KiB: the screenshot helper renders LVGL widgets from this task. */
    xTaskCreate(cli_task, "pwn_cli", 16384, NULL, 2, NULL);
}
