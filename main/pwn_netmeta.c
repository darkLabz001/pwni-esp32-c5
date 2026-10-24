#include "pwn_netmeta.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static pwn_dns_entry_t  s_dns[PWN_DNS_MAX];
static pwn_host_entry_t s_sni[PWN_HOST_MAX];
static pwn_host_entry_t s_http[PWN_HOST_MAX];
static pwn_talker_t     s_talkers[PWN_TALKER_MAX];
static pwn_netmeta_counts_t s_counts;
static SemaphoreHandle_t s_lock;

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

void netmeta_init(void)
{
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
    }
    memset(s_dns, 0, sizeof(s_dns));
    memset(s_sni, 0, sizeof(s_sni));
    memset(s_http, 0, sizeof(s_http));
    memset(s_talkers, 0, sizeof(s_talkers));
    memset(&s_counts, 0, sizeof(s_counts));
}

/* ---- bounded name tables --------------------------------------------- */

static pwn_dns_entry_t *dns_slot(const char *name)
{
    pwn_dns_entry_t *lru = NULL;
    for (int i = 0; i < PWN_DNS_MAX; i++) {
        if (s_dns[i].count && strcmp(s_dns[i].name, name) == 0) {
            return &s_dns[i];
        }
        if (!s_dns[i].count) {
            return &s_dns[i];
        }
        if (!lru || s_dns[i].last_seen_ms < lru->last_seen_ms) {
            lru = &s_dns[i];
        }
    }
    return lru;
}

static pwn_host_entry_t *host_slot(pwn_host_entry_t *tab, const char *host)
{
    pwn_host_entry_t *lru = NULL;
    for (int i = 0; i < PWN_HOST_MAX; i++) {
        if (tab[i].count && strcmp(tab[i].host, host) == 0) {
            return &tab[i];
        }
        if (!tab[i].count) {
            return &tab[i];
        }
        if (!lru || tab[i].last_seen_ms < lru->last_seen_ms) {
            lru = &tab[i];
        }
    }
    return lru;
}

static void add_dns(const char *name, uint16_t qtype)
{
    if (!name || !name[0]) {
        return;
    }
    uint32_t now = now_ms();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    pwn_dns_entry_t *e = dns_slot(name);
    if (e) {
        bool same = e->count && strcmp(e->name, name) == 0;
        if (!same) {
            bool was_empty = e->count == 0;
            memset(e, 0, sizeof(*e));
            snprintf(e->name, sizeof(e->name), "%s", name);
            e->qtype = qtype;
            e->first_seen_ms = now;
            if (was_empty) {
                s_counts.dns_count++;
            }
        }
        if (e->count != UINT32_MAX) {
            e->count++;
        }
        e->last_seen_ms = now;
        s_counts.dns_total++;
    }
    xSemaphoreGive(s_lock);
}

static void add_host(pwn_host_entry_t *tab, const char *host, bool sni)
{
    if (!host || !host[0]) {
        return;
    }
    uint32_t now = now_ms();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    pwn_host_entry_t *e = host_slot(tab, host);
    if (e) {
        bool same = e->count && strcmp(e->host, host) == 0;
        if (!same) {
            bool was_empty = e->count == 0;
            memset(e, 0, sizeof(*e));
            snprintf(e->host, sizeof(e->host), "%s", host);
            e->first_seen_ms = now;
            if (was_empty) {
                if (sni) {
                    s_counts.sni_count++;
                } else {
                    s_counts.http_count++;
                }
            }
        }
        if (e->count != UINT32_MAX) {
            e->count++;
        }
        e->last_seen_ms = now;
        if (sni) {
            s_counts.sni_total++;
        } else {
            s_counts.http_total++;
        }
    }
    xSemaphoreGive(s_lock);
}

static void add_talker(const uint8_t mac[6], const uint8_t *ip, int len)
{
    if (!mac || (mac[0] & 0x01)) {
        return;
    }
    uint32_t now = now_ms();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    pwn_talker_t *lru = NULL;
    pwn_talker_t *slot = NULL;
    for (int i = 0; i < PWN_TALKER_MAX; i++) {
        if (s_talkers[i].last_seen_ms &&
            memcmp(s_talkers[i].mac, mac, 6) == 0) {
            slot = &s_talkers[i];
            break;
        }
        if (!s_talkers[i].last_seen_ms) {
            if (!slot) {
                slot = &s_talkers[i];
            }
        } else if (!lru || s_talkers[i].last_seen_ms < lru->last_seen_ms) {
            lru = &s_talkers[i];
        }
    }
    if (!slot) {
        slot = lru;
    }
    if (slot) {
        if (!slot->last_seen_ms) {
            memset(slot, 0, sizeof(*slot));
            memcpy(slot->mac, mac, 6);
            slot->first_seen_ms = now;
            s_counts.talker_count++;
        }
        slot->last_seen_ms = now;
        if (slot->frames != UINT32_MAX) {
            slot->frames++;
        }
        if (len > 0 && slot->bytes <= UINT32_MAX - (uint32_t)len) {
            slot->bytes += (uint32_t)len;
        }
        if (ip && !slot->ip[0]) {
            snprintf(slot->ip, sizeof(slot->ip), "%u.%u.%u.%u",
                     ip[0], ip[1], ip[2], ip[3]);
        }
    }
    xSemaphoreGive(s_lock);
}

/* ---- parsers ---------------------------------------------------------- */

static bool dns_read_name(const uint8_t *d, int len, int *off,
                          char *out, size_t outsz)
{
    int pos = *off;
    int jumps = 0;
    bool jumped = false;
    size_t o = 0;
    bool have_label = false;

    while (pos >= 0 && pos < len) {
        uint8_t b = d[pos];
        if (b == 0) {
            pos++;
            break;
        }
        if ((b & 0xc0) == 0xc0) {
            if (pos + 1 >= len) {
                return false;
            }
            int ptr = ((b & 0x3f) << 8) | d[pos + 1];
            if (ptr >= len || ++jumps > 8) {
                return false;
            }
            if (!jumped) {
                *off = pos + 2;
                jumped = true;
            }
            pos = ptr;
            continue;
        }
        if (b > 63 || pos + 1 + b > len) {
            return false;
        }
        if (have_label) {
            if (o + 1 >= outsz) {
                return false;
            }
            out[o++] = '.';
        }
        if (o + b >= outsz) {
            return false;
        }
        for (int i = 0; i < b; i++) {
            uint8_t c = d[pos + 1 + i];
            out[o++] = (char)tolower(c);
        }
        have_label = true;
        pos += 1 + b;
    }
    if (!jumped) {
        *off = pos;
    }
    out[o] = 0;
    return o > 0;
}

static void parse_dns(const uint8_t *d, int len)
{
    if (len < 12) {
        return;
    }
    uint16_t flags = (uint16_t)((d[2] << 8) | d[3]);
    if (flags & 0x8000) {   /* responses are not queries */
        return;
    }
    int qd = (d[4] << 8) | d[5];
    if (qd < 1) {
        return;
    }
    int off = 12;
    char name[PWN_NET_NAME];
    if (!dns_read_name(d, len, &off, name, sizeof(name))) {
        return;
    }
    if (off + 4 > len) {
        return;
    }
    uint16_t qtype = (uint16_t)((d[off] << 8) | d[off + 1]);
    add_dns(name, qtype);
}

static void parse_http(const uint8_t *d, int len)
{
    static const char *methods[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "DELETE ", "CONNECT ",
    };
    if (len < 16) {
        return;
    }
    bool method_ok = false;
    for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        size_t n = strlen(methods[i]);
        if (len >= (int)n && memcmp(d, methods[i], n) == 0) {
            method_ok = true;
            break;
        }
    }
    if (!method_ok) {
        return;
    }

    int limit = len < 1024 ? len : 1024;
    for (int i = 0; i + 5 < limit; i++) {
        if (d[i] != '\n') {
            continue;
        }
        int p = i + 1;
        if (p + 5 > limit) {
            break;
        }
        if ((d[p] == 'H' || d[p] == 'h') &&
            (d[p + 1] == 'o' || d[p + 1] == 'O') &&
            (d[p + 2] == 's' || d[p + 2] == 'S') &&
            (d[p + 3] == 't' || d[p + 3] == 'T') && d[p + 4] == ':') {
            p += 5;
            while (p < limit && (d[p] == ' ' || d[p] == '\t')) {
                p++;
            }
            int start = p;
            while (p < limit && d[p] != '\r' && d[p] != '\n' &&
                   p - start < PWN_NET_NAME - 1) {
                p++;
            }
            int n = p - start;
            if (n <= 0) {
                return;
            }
            char host[PWN_NET_NAME];
            int o = 0;
            for (int k = 0; k < n; k++) {
                uint8_t c = d[start + k];
                if (!isprint(c)) {
                    break;
                }
                host[o++] = (char)tolower(c);
            }
            host[o] = 0;
            /* Strip a non-IPv6 port so counts group by hostname. */
            char *colon = strrchr(host, ':');
            if (colon && !strchr(host, '[') && !strchr(colon + 1, ':')) {
                *colon = 0;
            }
            if (host[0]) {
                add_host(s_http, host, false);
            }
            return;
        }
        if (d[p] == '\r' || d[p] == '\n') {
            return;     /* end of headers, no Host */
        }
    }
}

static void parse_sni(const uint8_t *d, int len)
{
    if (len < 5 + 4 + 2 + 32) {
        return;
    }
    if (d[0] != 0x16) {             /* TLS handshake record */
        return;
    }
    int rec_len = (d[3] << 8) | d[4];
    if (rec_len <= 0 || 5 + rec_len > len) {
        rec_len = len - 5;          /* segment may be truncated; parse what we have */
    }
    const uint8_t *hs = d + 5;
    int hn = rec_len;
    if (hn < 4 || hs[0] != 0x01) {  /* ClientHello */
        return;
    }
    int hs_len = (hs[1] << 16) | (hs[2] << 8) | hs[3];
    if (hs_len <= 0) {
        return;
    }
    int end = 4 + hs_len;
    if (end > hn) {
        end = hn;
    }
    int p = 4;
    if (p + 2 + 32 > end) {
        return;
    }
    p += 2 + 32;                    /* legacy_version + random */
    if (p >= end) {
        return;
    }
    int sid = hs[p++];
    if (p + sid > end) {
        return;
    }
    p += sid;
    if (p + 2 > end) {
        return;
    }
    int cs = (hs[p] << 8) | hs[p + 1];
    p += 2;
    if (p + cs > end) {
        return;
    }
    p += cs;
    if (p >= end) {
        return;
    }
    int comp = hs[p++];
    if (p + comp > end) {
        return;
    }
    p += comp;
    if (p + 2 > end) {
        return;
    }
    int ext_total = (hs[p] << 8) | hs[p + 1];
    p += 2;
    int ext_end = p + ext_total;
    if (ext_end > end) {
        ext_end = end;
    }

    while (p + 4 <= ext_end) {
        int type = (hs[p] << 8) | hs[p + 1];
        int elen = (hs[p + 2] << 8) | hs[p + 3];
        p += 4;
        if (p + elen > ext_end) {
            return;
        }
        if (type == 0x0000 && elen >= 5) {  /* server_name */
            int q = p;
            int list_len = (hs[q] << 8) | hs[q + 1];
            q += 2;
            int list_end = q + list_len;
            if (list_end > p + elen) {
                list_end = p + elen;
            }
            while (q + 3 <= list_end) {
                int ntype = hs[q++];
                int nlen = (hs[q] << 8) | hs[q + 1];
                q += 2;
                if (q + nlen > list_end) {
                    return;
                }
                if (ntype == 0 && nlen > 0) {
                    char host[PWN_NET_NAME];
                    int o = 0;
                    for (int i = 0; i < nlen && o < PWN_NET_NAME - 1; i++) {
                        uint8_t c = hs[q + i];
                        if (!isprint(c)) {
                            return;
                        }
                        host[o++] = (char)tolower(c);
                    }
                    host[o] = 0;
                    if (host[0]) {
                        add_host(s_sni, host, true);
                    }
                    return;
                }
                q += nlen;
            }
        }
        p += elen;
    }
}

static const uint8_t *ipv4_parse(const uint8_t *ip, int len,
                                 int *l4_off, int *l4_len,
                                 uint8_t *proto, const uint8_t **src_ip)
{
    if (len < 20 || (ip[0] >> 4) != 4) {
        return NULL;
    }
    int ihl = (ip[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > len) {
        return NULL;
    }
    int total = (ip[2] << 8) | ip[3];
    if (total < ihl) {
        return NULL;
    }
    if (total > len) {
        total = len;
    }
    uint16_t frag = (uint16_t)((ip[6] << 8) | ip[7]);
    if (frag & 0x1fff) {        /* non-first fragment */
        return NULL;
    }
    *proto = ip[9];
    *src_ip = ip + 12;
    *l4_off = ihl;
    *l4_len = total - ihl;
    return ip;
}

static void process_ipv4(const uint8_t *ip, int len)
{
    int l4_off = 0, l4_len = 0;
    uint8_t proto = 0;
    const uint8_t *src_ip = NULL;
    if (!ipv4_parse(ip, len, &l4_off, &l4_len, &proto, &src_ip)) {
        return;
    }
    const uint8_t *l4 = ip + l4_off;

    if (proto == 17 && l4_len >= 8) {           /* UDP */
        int sport = (l4[0] << 8) | l4[1];
        int dport = (l4[2] << 8) | l4[3];
        if (sport == 53 || dport == 53) {
            parse_dns(l4 + 8, l4_len - 8);
        }
    } else if (proto == 6 && l4_len >= 20) {    /* TCP */
        int sport = (l4[0] << 8) | l4[1];
        int dport = (l4[2] << 8) | l4[3];
        int thl = (l4[12] >> 4) * 4;
        if (thl < 20 || thl > l4_len) {
            return;
        }
        const uint8_t *pay = l4 + thl;
        int plen = l4_len - thl;
        if (plen <= 0) {
            return;
        }
        if (dport == 80 || dport == 8000 || dport == 8080 || dport == 8888) {
            parse_http(pay, plen);
        }
        if (dport == 443 || dport == 8443 || dport == 993 || dport == 995 ||
            dport == 465) {
            parse_sni(pay, plen);
        }
        (void)sport;
    }
}

void netmeta_process(const uint8_t *frame, int len, int hdr_len, bool protected)
{
    if (!s_lock || !frame || len < hdr_len || hdr_len < 24) {
        return;
    }

    bool tods = frame[1] & 0x01;
    bool fromds = frame[1] & 0x02;
    const uint8_t *src = NULL;
    if (tods && !fromds) {
        src = frame + 10;       /* addr2 */
    } else if (!tods && fromds) {
        src = frame + 16;       /* addr3 */
    } else if (!tods && !fromds) {
        src = frame + 10;       /* addr2 */
    }

    /* Talker volume includes encrypted frames (header metadata only). */
    if (protected) {
        if (src) {
            add_talker(src, NULL, len);
        }
        return;
    }
    if (len < hdr_len + 8) {
        if (src) {
            add_talker(src, NULL, len);
        }
        return;
    }
    const uint8_t *llc = frame + hdr_len;
    if (llc[0] != 0xaa || llc[1] != 0xaa || llc[2] != 0x03) {
        if (src) {
            add_talker(src, NULL, len);
        }
        return;
    }
    uint16_t ethertype = (uint16_t)((llc[6] << 8) | llc[7]);
    if (ethertype != 0x0800) {
        if (src) {
            add_talker(src, NULL, len);
        }
        return;
    }
    const uint8_t *ip = llc + 8;
    int iplen = len - (hdr_len + 8);
    if (iplen < 20) {
        if (src) {
            add_talker(src, NULL, len);
        }
        return;
    }
    /* Decode the source IP for the talker table before the deeper parse. */
    int l4_off = 0, l4_len = 0;
    uint8_t proto = 0;
    const uint8_t *src_ip = NULL;
    if (ipv4_parse(ip, iplen, &l4_off, &l4_len, &proto, &src_ip) && src) {
        add_talker(src, src_ip, len);
    } else if (src) {
        add_talker(src, NULL, len);
    }
    process_ipv4(ip, iplen);
}

int netmeta_dns_snapshot(pwn_dns_entry_t *out, int max)
{
    if (!out || max <= 0 || !s_lock) {
        return 0;
    }
    int n = 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < PWN_DNS_MAX && n < max; i++) {
        if (s_dns[i].count) {
            out[n++] = s_dns[i];
        }
    }
    xSemaphoreGive(s_lock);
    return n;
}

int netmeta_sni_snapshot(pwn_host_entry_t *out, int max)
{
    if (!out || max <= 0 || !s_lock) {
        return 0;
    }
    int n = 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < PWN_HOST_MAX && n < max; i++) {
        if (s_sni[i].count) {
            out[n++] = s_sni[i];
        }
    }
    xSemaphoreGive(s_lock);
    return n;
}

int netmeta_http_snapshot(pwn_host_entry_t *out, int max)
{
    if (!out || max <= 0 || !s_lock) {
        return 0;
    }
    int n = 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < PWN_HOST_MAX && n < max; i++) {
        if (s_http[i].count) {
            out[n++] = s_http[i];
        }
    }
    xSemaphoreGive(s_lock);
    return n;
}

int netmeta_talker_snapshot(pwn_talker_t *out, int max)
{
    if (!out || max <= 0 || !s_lock) {
        return 0;
    }
    int n = 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < PWN_TALKER_MAX && n < max; i++) {
        if (s_talkers[i].last_seen_ms) {
            out[n++] = s_talkers[i];
        }
    }
    xSemaphoreGive(s_lock);
    return n;
}

void netmeta_counts(pwn_netmeta_counts_t *out)
{
    if (!out || !s_lock) {
        return;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    *out = s_counts;
    xSemaphoreGive(s_lock);
}
