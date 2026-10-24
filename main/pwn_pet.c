#include "pwn_pet.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "pwn_config.h"
#include "pwn_wifi.h"
#include "pwn_capture.h"

static const char *TAG = "pet";

static pwn_pet_t s_pet;
static brain_t   s_brain;
static SemaphoreHandle_t s_lock;

static float s_state[BRAIN_IN];
static float s_probs[BRAIN_OUT];
static uint32_t s_epoch_start_ms;

static uint32_t s_prev_aps;
static uint32_t s_prev_hs;
static uint32_t s_prev_pmkid;
static uint32_t s_prev_deauth;
static uint32_t s_prev_hops;
static int      s_force_action = -1;

static const char *MOOD_NAMES[] = {
    "sleeping", "observing", "happy", "excited",
    "bored", "sad", "motivated", "demotivated",
};

const char *pet_mood_name(pwn_mood_t mood)
{
    if (mood < 0 || mood > MOOD_DEMOTIVATED) {
        return "?";
    }
    return MOOD_NAMES[mood];
}

const char *pet_action_name(brain_action_t action)
{
    return brain_policy(action)->name;
}

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

static void set_status(const char *text)
{
    snprintf(s_pet.status, sizeof(s_pet.status), "%s", text);
}

static void set_statusf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(s_pet.status, sizeof(s_pet.status), fmt, ap);
    va_end(ap);
}

static void compute_features(void);

static void pick_action(void)
{
    if (s_force_action >= 0 && s_force_action < ACT_COUNT) {
        s_pet.action = (brain_action_t)s_force_action;
    } else {
        s_pet.action = brain_act(&s_brain, s_state, s_probs);
    }
    const brain_policy_t *p = brain_policy(s_pet.action);
    pwn_wifi_apply_policy(p, pwn_wifi_authorized());
}

void pet_set_action(int action)
{
    if (!s_lock) return;
    if (action < -1 || action >= ACT_COUNT) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_force_action = action;
    compute_features();
    pick_action();
    if (action < 0) {
        set_status("auto strategy restored");
    } else {
        set_statusf("manual strategy: %s", pet_action_name(s_pet.action));
    }
    xSemaphoreGive(s_lock);
}

int pet_action_override(void)
{
    return s_force_action;
}

static void compute_features(void)
{
    const pwn_wifi_stats_t *st = pwn_wifi_stats();
    brain_features(s_state,
                   st->hs_count, st->ap_count, st->client_count,
                   st->deauths, s_pet.blind_epochs, s_pet.inactive_streak,
                   s_pet.active_epochs, s_pet.epochs + 1);
}

void pet_init(void)
{
    s_lock = xSemaphoreCreateMutex();
    memset(&s_pet, 0, sizeof(s_pet));
    s_pet.level = 1;
    s_pet.bond = 50;
    s_pet.mood = MOOD_OBSERVING;
    set_status("booting up");

    brain_load(&s_brain);
    memset(s_state, 0, sizeof(s_state));
    memset(s_probs, 0, sizeof(s_probs));

    s_prev_aps = 0;
    s_prev_hs = 0;
    s_prev_pmkid = 0;
    s_prev_deauth = 0;
    s_prev_hops = 0;
    s_epoch_start_ms = now_ms();

    pick_action();
    ESP_LOGI(TAG, "pet online, action=%s", pet_action_name(s_pet.action));
}

void pet_touch(void)
{
    if (!s_lock) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_pet.bond = (s_pet.bond + 6 > 100) ? 100 : s_pet.bond + 6;
    s_pet.xp += 1;
    if (s_pet.mood == MOOD_SLEEPING) {
        s_pet.mood = MOOD_OBSERVING;
        set_status("mmh... five more minutes");
    } else if (s_pet.mood == MOOD_SAD || s_pet.mood == MOOD_BORED) {
        set_status("thanks, i needed that");
    } else {
        set_status("hehe, that tickles");
    }
    xSemaphoreGive(s_lock);
}

void pet_set_paused(bool paused)
{
    if (!s_lock) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_pet.paused = paused;
    pwn_wifi_set_paused(paused);
    set_status(paused ? "napping. tap to wake" : "back on the prowl");
    xSemaphoreGive(s_lock);
}

bool pet_paused(void)
{
    return s_pet.paused;
}

void pet_snapshot(pwn_pet_t *out)
{
    if (!out) return;
    if (!s_lock) {
        *out = s_pet;
        return;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    *out = s_pet;
    xSemaphoreGive(s_lock);
}

void pet_reset_brain(void)
{
    if (!s_lock) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    brain_init(&s_brain);
    brain_save(&s_brain);
    s_pet.epochs = 0;
    s_pet.avg_reward = 0;
    s_pet.best_reward = 0;
    compute_features();
    pick_action();
    set_status("brain wiped. fresh start");
    xSemaphoreGive(s_lock);
    ESP_LOGW(TAG, "brain reset");
}

/* ---- epoch ------------------------------------------------------------ */

static void epoch_end(void)
{
    const pwn_wifi_stats_t *st = pwn_wifi_stats();

    uint32_t hs_now = st->hs_count;
    uint32_t pmkid_now = st->pmkid_count;
    uint32_t aps_now = st->ap_count;
    uint32_t deauth_now = st->deauths;
    uint32_t hops_now = st->hops;

    uint32_t hs_new = hs_now - s_prev_hs;
    uint32_t pmkid_new = pmkid_now - s_prev_pmkid;
    uint32_t aps_new = aps_now > s_prev_aps ? aps_now - s_prev_aps : 0;
    uint32_t deauth_new = deauth_now - s_prev_deauth;
    uint32_t hops_new = hops_now - s_prev_hops;

    uint32_t total = s_pet.epochs + 1;
    bool active = (hs_new > 0 || pmkid_new > 0 || aps_new > 0 || deauth_new > 0);

    /* Pwnagotchi-style reward. */
    float assoc = (float)deauth_new;
    float hs = (float)(hs_new + pmkid_new);
    float denom = assoc + hs;
    if (denom < hs) denom = hs;
    if (denom < 1.0f) denom = 1.0f;
    float h = hs / denom;

    float a = 0.2f * (float)(s_pet.active_epochs + (active ? 1 : 0)) / (float)total;
    float c = 0.1f * (float)hops_new / (float)(PWN_ALL_COUNT > 0 ? PWN_ALL_COUNT : 1);
    if (c > 0.1f) c = 0.1f;
    float b = -0.3f * (float)s_pet.blind_epochs / (float)total;
    float m = -0.3f * (float)s_pet.misses / (float)total;
    float i2 = -0.2f * (float)s_pet.inactive_streak / (float)total;
    float reward = h + a + c + b + m + i2;

    s_pet.reward = reward;
    s_pet.avg_reward = s_pet.epochs == 0 ? reward
                                         : 0.9f * s_pet.avg_reward + 0.1f * reward;
    if (reward > s_pet.best_reward) {
        s_pet.best_reward = reward;
    }

    brain_learn(&s_brain, s_state, s_pet.action, s_probs, reward);
    if ((s_brain.epochs % 10) == 0) {
        brain_save(&s_brain);
    }

    s_pet.epochs = total;
    if (active) {
        s_pet.active_epochs++;
        s_pet.inactive_streak = 0;
    } else {
        s_pet.inactive_streak++;
    }
    if (aps_now == 0) {
        s_pet.blind_epochs++;
    }
    if (hs_new == 0 && deauth_new > 0) {
        s_pet.misses++;
    }

    s_pet.hs_total += hs_new + pmkid_new;
    s_pet.pmkid_total += pmkid_new;
    s_pet.aps_seen = aps_now;
    s_pet.clients_seen = st->client_count;
    s_pet.hs_epoch = hs_new + pmkid_new;
    s_pet.aps_epoch = aps_new;
    s_pet.deauth_epoch = deauth_new;

    /* XP + level + bond. */
    s_pet.xp += hs_new * 25 + pmkid_new * 40 + aps_new * 2 + (active ? 2 : 0);
    s_pet.level = 1 + s_pet.xp / 150;
    if (hs_new || pmkid_new) {
        s_pet.bond = (s_pet.bond + 10 > 100) ? 100 : s_pet.bond + 10;
    } else if (s_pet.bond > 0) {
        s_pet.bond--;
    }

    /* Mood. */
    if (s_pet.paused) {
        s_pet.mood = MOOD_SLEEPING;
        set_status("napping...");
    } else if (hs_new > 0 || pmkid_new > 0) {
        s_pet.mood = MOOD_EXCITED;
        set_statusf("got %u new handshake%s!", hs_new + pmkid_new,
                    (hs_new + pmkid_new) == 1 ? "" : "s");
    } else if (aps_new > 0) {
        s_pet.mood = MOOD_HAPPY;
        set_statusf("+%u new access point%s", aps_new, aps_new == 1 ? "" : "s");
    } else if (s_pet.inactive_streak >= PWN_SAD_EPOCHS) {
        s_pet.mood = MOOD_SAD;
        set_status("so quiet... nobody is out there");
    } else if (s_pet.inactive_streak >= PWN_BORED_EPOCHS) {
        s_pet.mood = MOOD_BORED;
        set_status("bored. lets try another band");
    } else if (reward > s_pet.avg_reward + 0.25f && total > 2) {
        s_pet.mood = MOOD_MOTIVATED;
        set_status("this strategy is working. keep going");
    } else if (reward < s_pet.avg_reward - 0.25f && total > 2) {
        s_pet.mood = MOOD_DEMOTIVATED;
        set_status("hmm, that was a bad idea");
    } else {
        s_pet.mood = MOOD_OBSERVING;
        set_status("watching the airwaves");
    }

    ESP_LOGI(TAG, "epoch %u: reward %.2f avg %.2f hs+%u ap+%u rssi %d",
             (unsigned)total, reward, s_pet.avg_reward,
             (unsigned)(hs_new + pmkid_new), (unsigned)aps_new,
             (int)st->last_rssi);

    s_prev_aps = aps_now;
    s_prev_hs = hs_now;
    s_prev_pmkid = pmkid_now;
    s_prev_deauth = deauth_now;
    s_prev_hops = hops_now;
    s_epoch_start_ms = now_ms();

    compute_features();
    pick_action();
    ESP_LOGI(TAG, "next action: %s", pet_action_name(s_pet.action));

#if PWN_ENABLE_DEAUTH
    /* Active mode: a hunting epoch may nudge a few clients off their AP to
     * force a fresh 4-way handshake. Runtime-authorized builds only. */
    if (pwn_wifi_authorized() && pwn_wifi_auto_deauth() &&
        brain_policy(s_pet.action)->aggressive) {
        static pwn_client_t clients[16];
        int cn = pwn_wifi_client_snapshot(clients, 16);
        int sent = 0;
        for (int i = 0; i < cn && sent < 3; i++) {
            if (clients[i].bssid[0] == 0 && clients[i].bssid[1] == 0) {
                continue;
            }
            if (pwn_wifi_deauth(clients[i].bssid, clients[i].mac, 1) == ESP_OK) {
                sent++;
            }
        }
        if (sent) {
            ESP_LOGW(TAG, "sent %d deauth frame(s)", sent);
        }
    }
#endif
}

void pet_tick(void)
{
    if (!s_lock) return;
    if (s_pet.paused) {
        s_epoch_start_ms = now_ms();
        return;
    }
    if (now_ms() - s_epoch_start_ms >= PWN_EPOCH_MS) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
        epoch_end();
        xSemaphoreGive(s_lock);
    }
}
