#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "pwn_config.h"

#define PWN_ALL_COUNT_MAX 32

/* A compact on-device policy network (8 -> 16 -> 6) trained with
 * REINFORCE. It is *not* the original Pwnagotchi LSTM/A2C stack; it is an
 * honest, tiny reimplementation of the same idea: observe the WiFi
 * environment, pick a strategy, score the epoch, and nudge the policy. */

#define BRAIN_IN   8
#define BRAIN_HID  16
#define BRAIN_OUT  6

typedef enum {
    ACT_LINGER_2G = 0,   /* sit on 1/6/11, long dwell */
    ACT_HOP_2G,          /* fast hop across 2.4 GHz */
    ACT_SCAN_5G_LOW,     /* UNII-1 / UNII-2 (36-64) */
    ACT_SCAN_5G_HIGH,    /* UNII-3 (100-165) */
    ACT_HUNT,            /* wide sweep, aggressive if authorized */
    ACT_REST,            /* few channels, long dwell, save power */
    ACT_COUNT
} brain_action_t;

typedef struct {
    float w1[BRAIN_HID][BRAIN_IN];
    float b1[BRAIN_HID];
    float w2[BRAIN_OUT][BRAIN_HID];
    float b2[BRAIN_OUT];
    float baseline;
    uint32_t epochs;
} brain_t;

/* Strategy parameters decoded from an action. */
typedef struct {
    const char *name;
    uint32_t dwell_ms;
    bool five_ghz;
    bool aggressive;
    uint8_t channel_count;
    uint8_t channels[PWN_ALL_COUNT_MAX];
} brain_policy_t;

void brain_init(brain_t *b);
void brain_load(brain_t *b);
void brain_save(const brain_t *b);

/* Choose an action from the normalized feature vector. */
brain_action_t brain_act(const brain_t *b, const float state[BRAIN_IN],
                         float probs[BRAIN_OUT]);

/* Policy gradient update for the chosen action. */
void brain_learn(brain_t *b, const float state[BRAIN_IN],
                 brain_action_t action, const float probs[BRAIN_OUT],
                 float reward);

const brain_policy_t *brain_policy(brain_action_t action);

/* Fill the 8 normalized features from live counters. */
void brain_features(float out[BRAIN_IN],
                    uint32_t hs, uint32_t aps, uint32_t clients,
                    uint32_t deauths, uint32_t blind, uint32_t inactive,
                    uint32_t active, uint32_t total);
