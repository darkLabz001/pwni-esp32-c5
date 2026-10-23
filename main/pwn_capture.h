#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "pwn_config.h"

#ifndef PWN_BCN_MAX
#define PWN_BCN_MAX 512
#endif

/* Captured EAPOL material for one (BSSID, station) pair. A slot is saved
 * to the SD card as soon as it is useful: PMKID present, or M1+M2 seen,
 * or a complete 4-way handshake. */

typedef struct {
    uint8_t bssid[6];
    uint8_t sta[6];
    char    ssid[33];
    uint8_t channel;
    int8_t  rssi;
    uint16_t bcn_len;         /* beacon/probe-response context */
    uint8_t bcn[PWN_BCN_MAX];
    uint8_t msg_mask;         /* bit 0..3 => M1..M4 seen */
    uint8_t nframes;
    uint8_t saved_frames;     /* frames already written to the PCAP */
    bool    counted;          /* already added to the handshake total */
    bool    complete;
    bool    saved;
    bool    has_pmkid;
    uint8_t pmkid[16];
    uint32_t first_seen_ms;
    uint32_t last_seen_ms;
    char    file[64];         /* basename of the saved PCAP (empty if none) */
    struct {
        uint64_t ts_us;
        uint16_t len;
        uint8_t  data[PWN_FRAME_MAX];
    } frames[PWN_HS_FRAMES];
} pwn_handshake_t;

void capture_init(void);

/* Feed one parsed EAPOL frame. msg is 1..4, 0 if unknown. */
void capture_add_eapol(const uint8_t *bssid, const uint8_t *sta,
                       const char *ssid, uint8_t msg,
                       const uint8_t *frame, uint16_t len,
                       const uint8_t *pmkid,
                       uint8_t channel, int8_t rssi,
                       const uint8_t *bcn, uint16_t bcn_len);

uint32_t capture_handshake_count(void);
uint32_t capture_pmkid_count(void);
uint32_t capture_saved_count(void);
bool     capture_sd_ready(void);

typedef struct {
    bool     ready;
    bool     writable;
    uint64_t total_bytes;
    uint64_t free_bytes;
} pwn_sd_info_t;

/* Query FATFS usage. Returns false if the card is not mounted/queryable. */
bool capture_sd_info(pwn_sd_info_t *out);

/* Unmount and mount the card again. Returns true if it becomes usable. */
bool capture_sd_remount(void);

/* Delete the oldest PCAPs until at most keep remain. Returns deleted count. */
int capture_sd_prune(int keep);

/* One saved PCAP on the SD card.  The live slot table is RAM-only and is
 * reset on reboot, so the UI/web use this to list files that survived. */
typedef struct {
    char     name[64];
    uint32_t size;
} pwn_pcap_file_t;

/* Scan /sdcard/handshakes for *.pcap. Returns the number written (<= max). */
int capture_list_files(pwn_pcap_file_t *out, int max);

/* Copy the slot table for the CLI / UI. Returns number written. */
int capture_snapshot(pwn_handshake_t *out, int max);

/* Write any pending slots out (called before reboot / on demand). */
void capture_flush_all(void);

/* The SD card and the LCD share one SPI bus. Any code touching the
 * filesystem outside this module must hold this lock so a long FAT/SD
 * transaction cannot stall an in-progress LCD flush (LVGL busy-waits on
 * the flush and would otherwise trip the task watchdog).
 *
 * Lock order is always display -> capture. Never take the capture lock
 * (capture_snapshot/add_eapol/flush_all) before this one. */
bool capture_bus_lock(uint32_t timeout_ms);
void capture_bus_unlock(void);
