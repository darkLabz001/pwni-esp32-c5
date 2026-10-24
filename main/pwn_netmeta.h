#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Passive network metadata extracted from *unprotected* 802.11 data frames.
 * Only names and counters are kept: DNS question names, TLS ClientHello SNI,
 * HTTP Host headers, and per-source-MAC talker volume. Payloads, URLs, query
 * answers and credentials are never stored. WPA/WPA2 traffic is encrypted and
 * therefore invisible to this parser. */
#define PWN_DNS_MAX     24
#define PWN_HOST_MAX    24
#define PWN_TALKER_MAX  16
#define PWN_NET_NAME    80

typedef struct {
    char     name[PWN_NET_NAME];
    uint16_t qtype;
    uint32_t count;
    uint32_t first_seen_ms;
    uint32_t last_seen_ms;
} pwn_dns_entry_t;

typedef struct {
    char     host[PWN_NET_NAME];
    uint32_t count;
    uint32_t first_seen_ms;
    uint32_t last_seen_ms;
} pwn_host_entry_t;

typedef struct {
    uint8_t  mac[6];
    char     ip[16];
    uint32_t frames;
    uint32_t bytes;
    uint32_t first_seen_ms;
    uint32_t last_seen_ms;
} pwn_talker_t;

typedef struct {
    uint32_t dns_total;
    uint32_t sni_total;
    uint32_t http_total;
    int      dns_count;
    int      sni_count;
    int      http_count;
    int      talker_count;
} pwn_netmeta_counts_t;

void netmeta_init(void);

/* frame points at the 802.11 header, hdr_len is the MAC header length
 * (24/26/30). protected is the 802.11 Protected Frame bit. */
void netmeta_process(const uint8_t *frame, int len, int hdr_len, bool protected);

int netmeta_dns_snapshot(pwn_dns_entry_t *out, int max);
int netmeta_sni_snapshot(pwn_host_entry_t *out, int max);
int netmeta_http_snapshot(pwn_host_entry_t *out, int max);
int netmeta_talker_snapshot(pwn_talker_t *out, int max);
void netmeta_counts(pwn_netmeta_counts_t *out);
