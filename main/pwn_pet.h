#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "pwn_brain.h"

typedef enum {
    MOOD_SLEEPING = 0,
    MOOD_OBSERVING,
    MOOD_HAPPY,
    MOOD_EXCITED,
    MOOD_BORED,
    MOOD_SAD,
    MOOD_MOTIVATED,
    MOOD_DEMOTIVATED,
} pwn_mood_t;

typedef struct {
    uint32_t xp;
    uint32_t level;
    uint32_t bond;          /* 0..100 */
    uint32_t epochs;
    uint32_t active_epochs;
    uint32_t inactive_streak;
    uint32_t blind_epochs;
    uint32_t misses;

    uint32_t hs_total;
    uint32_t pmkid_total;
    uint32_t aps_seen;
    uint32_t clients_seen;

    uint32_t hs_epoch;
    uint32_t aps_epoch;
    uint32_t deauth_epoch;

    float reward;
    float avg_reward;
    float best_reward;

    pwn_mood_t mood;
    brain_action_t action;
    bool paused;

    char status[64];
} pwn_pet_t;

void pet_init(void);
void pet_tick(void);

void pet_touch(void);
void pet_set_paused(bool paused);
bool pet_paused(void);

void pet_snapshot(pwn_pet_t *out);
const char *pet_mood_name(pwn_mood_t mood);
const char *pet_action_name(brain_action_t action);
void pet_reset_brain(void);

/* Manual strategy override (-1 restores automatic selection). */
void pet_set_action(int action);
int  pet_action_override(void);
