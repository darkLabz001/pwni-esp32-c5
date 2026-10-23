#include "pwn_brain.h"

#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "esp_log.h"
#include "esp_random.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "brain";
static const char *NVS_NS = "pwni";
static const char *NVS_KEY = "brain";

/* Deterministic initial weights: small random values, fixed seed. */
static uint32_t rng_state = 0x12345678u;
static float frand(void)
{
    rng_state = rng_state * 1664525u + 1013904223u;
    return ((rng_state >> 8) & 0xFFFF) / 32768.0f - 1.0f;
}

void brain_init(brain_t *b)
{
    memset(b, 0, sizeof(*b));
    for (int i = 0; i < BRAIN_HID; i++) {
        for (int j = 0; j < BRAIN_IN; j++) {
            b->w1[i][j] = frand() * 0.5f;
        }
        b->b1[i] = 0.0f;
    }
    for (int i = 0; i < BRAIN_OUT; i++) {
        for (int j = 0; j < BRAIN_HID; j++) {
            b->w2[i][j] = frand() * 0.5f;
        }
        b->b2[i] = 0.0f;
    }
    b->baseline = 0.0f;
}

void brain_load(brain_t *b)
{
    brain_init(b);
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) {
        return;
    }
    size_t sz = sizeof(*b);
    if (nvs_get_blob(h, NVS_KEY, b, &sz) != ESP_OK || sz != sizeof(*b)) {
        ESP_LOGW(TAG, "no saved brain, starting fresh");
    } else {
        ESP_LOGI(TAG, "restored brain after %u epochs", (unsigned)b->epochs);
    }
    nvs_close(h);
}

void brain_save(const brain_t *b)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) {
        return;
    }
    nvs_set_blob(h, NVS_KEY, b, sizeof(*b));
    nvs_commit(h);
    nvs_close(h);
}

static void softmax(const float *logits, float *p)
{
    float mx = logits[0];
    for (int i = 1; i < BRAIN_OUT; i++) {
        if (logits[i] > mx) mx = logits[i];
    }
    float sum = 0.0f;
    for (int i = 0; i < BRAIN_OUT; i++) {
        p[i] = expf(logits[i] - mx);
        sum += p[i];
    }
    for (int i = 0; i < BRAIN_OUT; i++) {
        p[i] /= (sum > 0.0f ? sum : 1.0f);
    }
}

static void forward(const brain_t *b, const float *x, float *h, float *logits)
{
    for (int i = 0; i < BRAIN_HID; i++) {
        float v = b->b1[i];
        for (int j = 0; j < BRAIN_IN; j++) {
            v += b->w1[i][j] * x[j];
        }
        h[i] = tanhf(v);
    }
    for (int i = 0; i < BRAIN_OUT; i++) {
        float v = b->b2[i];
        for (int j = 0; j < BRAIN_HID; j++) {
            v += b->w2[i][j] * h[j];
        }
        logits[i] = v;
    }
}

brain_action_t brain_act(const brain_t *b, const float state[BRAIN_IN],
                         float probs[BRAIN_OUT])
{
    float h[BRAIN_HID], logits[BRAIN_OUT];
    forward(b, state, h, logits);
    softmax(logits, probs);

    /* Sample from the policy. A floor keeps every strategy reachable. */
    float r = (esp_random() % 10000) / 10000.0f;
    float acc = 0.0f;
    for (int i = 0; i < BRAIN_OUT; i++) {
        acc += probs[i];
        if (r <= acc) {
            return (brain_action_t)i;
        }
    }
    return ACT_COUNT - 1;
}

void brain_learn(brain_t *b, const float state[BRAIN_IN],
                 brain_action_t action, const float probs[BRAIN_OUT],
                 float reward)
{
    if (action < 0 || action >= BRAIN_OUT) {
        return;
    }

    float h[BRAIN_HID], logits[BRAIN_OUT];
    forward(b, state, h, logits);

    /* Policy gradient for softmax: dlogit_i = 1{i==a} - p_i. */
    float dlogit[BRAIN_OUT];
    for (int i = 0; i < BRAIN_OUT; i++) {
        dlogit[i] = (i == (int)action ? 1.0f : 0.0f) - probs[i];
    }

    /* Update baseline first so the advantage uses the pre-update baseline. */
    float advantage = reward - b->baseline;
    b->baseline = 0.95f * b->baseline + 0.05f * reward;

    const float lr = 0.03f;
    if (advantage > 3.0f) advantage = 3.0f;
    if (advantage < -3.0f) advantage = -3.0f;

    /* Output layer. */
    for (int i = 0; i < BRAIN_OUT; i++) {
        float g = lr * advantage * dlogit[i];
        for (int j = 0; j < BRAIN_HID; j++) {
            b->w2[i][j] += g * h[j];
        }
        b->b2[i] += g;
    }

    /* Hidden layer via chain rule through tanh. */
    float dh[BRAIN_HID];
    for (int j = 0; j < BRAIN_HID; j++) {
        float s = 0.0f;
        for (int i = 0; i < BRAIN_OUT; i++) {
            s += b->w2[i][j] * dlogit[i];
        }
        dh[j] = s * (1.0f - h[j] * h[j]);
    }
    for (int j = 0; j < BRAIN_HID; j++) {
        float g = lr * advantage * dh[j];
        for (int k = 0; k < BRAIN_IN; k++) {
            b->w1[j][k] += g * state[k];
        }
        b->b1[j] += g;
    }

    b->epochs++;
}

/* ---- strategies ------------------------------------------------------- */

static const brain_policy_t POLICIES[ACT_COUNT] = {
    [ACT_LINGER_2G] = {
        .name = "linger-2g", .dwell_ms = 9000, .five_ghz = false,
        .aggressive = false, .channel_count = 3, .channels = {1, 6, 11},
    },
    [ACT_HOP_2G] = {
        .name = "hop-2g", .dwell_ms = 2200, .five_ghz = false,
        .aggressive = false,
        .channel_count = PWN_2G_COUNT,
        .channels = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13},
    },
    /* 5 GHz plans use only non-DFS channels. Tuning to a DFS channel while
     * promiscuous makes the radio run radar detection, which can stall the
     * WiFi task on this chip. */
    [ACT_SCAN_5G_LOW] = {
        .name = "scan-5g-low", .dwell_ms = 4000, .five_ghz = true,
        .aggressive = false, .channel_count = 4,
        .channels = {36, 40, 44, 48},
    },
    [ACT_SCAN_5G_HIGH] = {
        .name = "scan-5g-high", .dwell_ms = 4000, .five_ghz = true,
        .aggressive = false, .channel_count = 5,
        .channels = {149, 153, 157, 161, 165},
    },
    [ACT_HUNT] = {
        .name = "hunt", .dwell_ms = 6000, .five_ghz = true,
        .aggressive = true,
        .channel_count = 12,
        .channels = {1, 6, 11, 36, 40, 44, 48,
                     149, 153, 157, 161, 165},
    },
    [ACT_REST] = {
        .name = "rest", .dwell_ms = 12000, .five_ghz = false,
        .aggressive = false, .channel_count = 3, .channels = {1, 6, 11},
    },
};

const brain_policy_t *brain_policy(brain_action_t action)
{
    if (action < 0 || action >= ACT_COUNT) {
        return &POLICIES[ACT_HOP_2G];
    }
    return &POLICIES[action];
}

void brain_features(float out[BRAIN_IN],
                    uint32_t hs, uint32_t aps, uint32_t clients,
                    uint32_t deauths, uint32_t blind, uint32_t inactive,
                    uint32_t active, uint32_t total)
{
    if (total == 0) total = 1;
    out[0] = fminf(hs / 4.0f, 1.0f);
    out[1] = fminf(aps / 64.0f, 1.0f);
    out[2] = fminf(clients / 64.0f, 1.0f);
    out[3] = fminf(deauths / 16.0f, 1.0f);
    out[4] = fminf(blind / 32.0f, 1.0f);
    out[5] = fminf(inactive / 32.0f, 1.0f);
    out[6] = fminf(active / 64.0f, 1.0f);
    out[7] = fminf((float)total / 200.0f, 1.0f);
}
