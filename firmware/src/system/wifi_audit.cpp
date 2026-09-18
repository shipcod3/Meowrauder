/**
 * @file wifi_audit.cpp
 * @brief See wifi_audit.h.
 */
#include "wifi_audit.h"
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <cstring>
#include "mk_psram_buf.h"
#include <cstdio>
#include "mk_psram_buf.h"

namespace {

/* In PSRAM, not internal .bss: raising these caps in internal RAM starved the
 * Bluetooth controller once already. pcap_capture's ring is PSRAM and is
 * written from the same promiscuous critical sections, so the pattern is
 * proven on this hardware. */
static AuditAp*     s_ap = nullptr;
static bool ensure_aps()
{
    static void* slot = nullptr;
    if (!s_ap) s_ap = (AuditAp*)mk_psram_buf(&slot, sizeof(AuditAp) * WifiAudit::MAX_APS);
    return s_ap != nullptr;
}
static int          s_n = 0;
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

/* RSN/WPA suite selectors are OUI(3) + type(1); we only care about the type
 * once the OUI is the standard 00-0F-AC (or 00-50-F2 for WPA1). */
static inline uint16_t ciph_bit(uint8_t t) { return (t < 16) ? (uint16_t)(1u << t) : 0; }
static inline uint32_t akm_bit(uint8_t t)  { return (t < 32) ? (1u << t) : 0; }

static AuditAp* slot_for(const uint8_t* bssid, uint32_t now)
{
    if (!s_ap) return nullptr;      /* never allocate from a callback path */
    for (int i = 0; i < s_n; i++)
        if (!memcmp(s_ap[i].bssid, bssid, 6)) return &s_ap[i];
    if (s_n < WifiAudit::MAX_APS) {
        AuditAp* a = &s_ap[s_n++];
        *a = AuditAp{};
        memcpy(a->bssid, bssid, 6);
        a->wps_locked = 0xFF;
        a->first_seen_unused_ = 0;
        (void)now;
        return a;
    }
    AuditAp* oldest = &s_ap[0];
    for (int i = 1; i < s_n; i++)
        if ((int32_t)(s_ap[i].last_ms - oldest->last_ms) < 0) oldest = &s_ap[i];
    *oldest = AuditAp{};
    memcpy(oldest->bssid, bssid, 6);
    oldest->wps_locked = 0xFF;
    return oldest;
}

/* WPS TLVs are big-endian type(2) len(2) value(len). */
static void parse_wps(const uint8_t* p, int len, AuditAp* a)
{
    a->flags |= WA_WPS_ENABLED;
    int i = 0;
    while (i + 4 <= len) {
        const uint16_t t = (uint16_t)((p[i] << 8) | p[i + 1]);
        const uint16_t l = (uint16_t)((p[i + 2] << 8) | p[i + 3]);
        if (i + 4 + l > len) break;
        if (t == 0x1044 && l >= 1) a->wps_state  = p[i + 4];   /* setup state   */
        if (t == 0x1057 && l >= 1) a->wps_locked = p[i + 4];   /* AP setup lock */
        i += 4 + l;
    }
    /* Configured registrar that is not locked: the Pixie-Dust candidate. */
    if (a->wps_state == 2 && a->wps_locked == 0) a->flags |= WA_WPS_UNLOCKED;
}

static void parse_rsn(const uint8_t* p, int len, AuditAp* a)
{
    if (len < 8) return;
    int i = 2;                                   /* skip version */

    if (i + 4 > len) return;
    a->group |= ciph_bit(p[i + 3]); i += 4;      /* group cipher */

    if (i + 2 > len) return;
    int np = p[i] | (p[i + 1] << 8); i += 2;
    for (int k = 0; k < np && i + 4 <= len; k++, i += 4)
        a->pairwise |= ciph_bit(p[i + 3]);

    if (i + 2 > len) return;
    int na = p[i] | (p[i + 1] << 8); i += 2;
    for (int k = 0; k < na && i + 4 <= len; k++, i += 4)
        a->akm |= akm_bit(p[i + 3]);

    if (i + 2 <= len) {
        const uint16_t caps = (uint16_t)(p[i] | (p[i + 1] << 8));
        const bool mfpr = caps & 0x0040;         /* required */
        const bool mfpc = caps & 0x0080;         /* capable  */
        if (mfpr)       a->flags |= WA_PMF_REQUIRED;
        else if (mfpc)  a->flags |= WA_PMF_OPTIONAL;
        else            a->flags |= WA_NO_PMF;
    } else {
        a->flags |= WA_NO_PMF;
    }
}

static void finalise(AuditAp* a, bool privacy, bool have_rsn, bool have_wpa1)
{
    if (!privacy && !have_rsn && !have_wpa1) a->flags |= WA_OPEN;
    /* privacy bit but no RSN and no WPA1 element == WEP */
    if (privacy && !have_rsn && !have_wpa1)  a->flags |= WA_WEP;
    if (have_wpa1)                            a->flags |= WA_WPA1;

    if ((a->pairwise | a->group) & WA_CIPH_TKIP)              a->flags |= WA_TKIP;
    if ((a->pairwise | a->group) & (WA_CIPH_WEP40 | WA_CIPH_WEP104)) a->flags |= WA_WEP;

    const bool sae = a->akm & (akm_bit(8) | akm_bit(9));
    const bool psk = a->akm & (akm_bit(2) | akm_bit(6) | akm_bit(4));
    if (sae)              a->flags |= WA_SAE;
    if (sae && psk)       a->flags |= WA_WPA3_TRANSITION;
    if (a->akm & akm_bit(18)) a->flags |= WA_OWE;

    uint32_t serious = WA_OPEN | WA_WEP | WA_WPA1 | WA_TKIP | WA_WPS_UNLOCKED |
                       WA_NO_PMF | WA_WPA3_TRANSITION;
    uint8_t n = 0;
    for (int b = 0; b < 16; b++) if ((a->flags & serious) & (1u << b)) n++;
    a->findings = n;
}

void promisc_cb(void* buf, wifi_promiscuous_pkt_type_t type)
{
    (void)type;
    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    const uint8_t* fr = pkt->payload;
    const int len = pkt->rx_ctrl.sig_len;
    if (len < 38) return;

    const uint8_t ftype = (fr[0] >> 2) & 0x3;
    const uint8_t fsub  = (fr[0] >> 4) & 0xF;

    /* ── hidden-SSID resolution ────────────────────────────────────────
     * A beacon from a hidden AP carries an empty SSID element, but a client
     * associating with it must name it. Association (0) and reassociation (2)
     * requests are addressed to the BSSID and carry the real SSID, so they
     * resolve the name authoritatively — unlike a probe request, which only
     * shows what some client is looking for. */
    if (ftype == 0 && (fsub == 0 || fsub == 2) && len >= 28) {
        const int fixed = (fsub == 0) ? 4 : 10;   /* reassoc adds current AP */
        int p2 = 24 + fixed;
        char found[33] = {0};
        while (p2 + 2 <= len) {
            const uint8_t tag = fr[p2], tl = fr[p2 + 1];
            if (p2 + 2 + tl > len) break;
            if (tag == 0 && tl > 0) {
                int n = tl > 32 ? 32 : tl;
                memcpy(found, fr + p2 + 2, n);
                found[n] = '\0';
                break;
            }
            p2 += 2 + tl;
        }
        if (found[0]) {
            portENTER_CRITICAL_ISR(&s_mux);
            for (int i = 0; i < s_n; i++)
                if (!memcmp(s_ap[i].bssid, fr + 4 /*addr1 = BSSID*/, 6) &&
                    (s_ap[i].flags & WA_HIDDEN) && !s_ap[i].ssid[0]) {
                    snprintf(s_ap[i].ssid, sizeof(s_ap[i].ssid), "%s", found);
                    s_ap[i].flags |= WA_HIDDEN_RESOLVED;
                    break;
                }
            portEXIT_CRITICAL_ISR(&s_mux);
        }
        return;
    }

    if (ftype != 0 || (fsub != 8 && fsub != 5)) return;   /* beacon / probe-resp */

    /* fixed params: timestamp(8) interval(2) capability(2) at offset 24 */
    const uint16_t cap = (uint16_t)(fr[34] | (fr[35] << 8));
    const bool privacy = cap & 0x0010;

    const uint32_t now = millis();

    portENTER_CRITICAL_ISR(&s_mux);
    AuditAp* a = slot_for(fr + 10, now);
    if (!a) { portEXIT_CRITICAL_ISR(&s_mux); return; }

    /* Re-derive from scratch each beacon so a reconfigured AP updates cleanly.
     * Keep the identity fields. */
    const uint32_t keep = a->flags & WA_HIDDEN_RESOLVED;   /* survives a rebuild */
    a->flags = keep; a->pairwise = 0; a->group = 0; a->akm = 0;
    a->wps_state = 0; a->wps_locked = 0xFF;
    a->ie_count = 0; a->ie_vendor = 0; a->ie_mask = 0;

    bool have_rsn = false, have_wpa1 = false;

    int p = 36;
    while (p + 2 <= len) {
        const uint8_t tag = fr[p], tl = fr[p + 1];
        if (p + 2 + tl > len) break;
        const uint8_t* v = fr + p + 2;

        if (a->ie_count < 255) a->ie_count++;
        switch (tag) {
            case 7:   a->ie_mask |= WA_IE_COUNTRY; break;
            case 45:  a->ie_mask |= WA_IE_HT;      break;
            case 61:  a->ie_mask |= WA_IE_HTOP;    break;
            case 191: a->ie_mask |= WA_IE_VHT;     break;
            case 127: a->ie_mask |= WA_IE_EXTCAP;  break;
            case 70:  a->ie_mask |= WA_IE_RM;      break;
            case 32: case 33: a->ie_mask |= WA_IE_POWER; break;
            case 54:  a->ie_mask |= WA_IE_MOBDOM;  break;
            default: break;
        }

        if (tag == 1 && tl > 0) {                        /* Supported Rates */
            /* Rate bytes are in 500 kbit/s units with the high bit marking a
             * basic rate, so 1 Mbit/s is 0x82. Commercial APs list the basic
             * set as 1, 2, 5.5, 11; ESP-IDF's SoftAP starts at 5.5.
             *
             * Measured against 27 real 2.4 GHz APs: "first rate is not 1 Mbit"
             * flagged exactly one — the rogue portal. An earlier version
             * tested for a non-ascending sequence and flagged 21 of 27,
             * because the common list 1,2,5.5,11,9,18,36,54 drops from 11 to
             * 9. Do not "simplify" this back to an ordering test. */
            if ((v[0] & 0x7F) != 2) a->flags |= WA_SOFTAP_RATES;
        }

        if (tag == 0) {                                  /* SSID */
            if (tl == 0) a->flags |= WA_HIDDEN;            /* keeps any resolved name */
            else {
                int n = tl > 32 ? 32 : tl;
                memcpy(a->ssid, v, n);
                a->ssid[n] = '\0';
            }
        } else if (tag == 48) {                          /* RSN */
            have_rsn = true;
            parse_rsn(v, tl, a);
        } else if (tag == 221 && tl >= 4) {              /* vendor specific */
            if (a->ie_vendor < 255) a->ie_vendor++;
            if (v[0] == 0x00 && v[1] == 0x50 && v[2] == 0xF2) {
                if (v[3] == 0x01)      have_wpa1 = true;             /* WPA1 */
                else if (v[3] == 0x02) a->ie_mask |= WA_IE_WMM;      /* WMM  */
                else if (v[3] == 0x04) { a->ie_mask |= WA_IE_WPS;
                                         parse_wps(v + 4, tl - 4, a); }
            }
        }
        p += 2 + tl;
    }

    a->channel = (uint8_t)pkt->rx_ctrl.channel;
    a->rssi    = (int8_t)pkt->rx_ctrl.rssi;
    a->last_ms = now;
    finalise(a, privacy, have_rsn, have_wpa1);
    portEXIT_CRITICAL_ISR(&s_mux);
}

} // namespace

void WifiAudit::begin()
{
    ensure_aps();
    portENTER_CRITICAL(&s_mux);
    s_n = 0;
    portEXIT_CRITICAL(&s_mux);

    _stats = AuditStats{};
    _stats.running = true;
    _stats.hopping = true;
    _stats.channel = 1;
    _running   = true;
    _last_hop  = millis();
    _last_tick = millis();

    /* A SoftAP (Evil Twin) or a half-torn-down BLE session can leave the radio
     * in a state where promiscuous mode is refused. Put WiFi back to station
     * mode first so a capture does not fail for a reason nobody can see. */
    WiFi.mode(WIFI_STA);
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(&promisc_cb);
    if (esp_wifi_set_promiscuous(true) != ESP_OK) {
        /* The comment above is only worth anything if the result is checked.
         * One retry after a settle: the refusal is usually a radio still
         * being released by the previous screen. AuditStats has no error
         * field to report a second failure through, but `aps` staying at 0
         * is at least visible on screen. */
        delay(100);
        esp_wifi_set_promiscuous(true);
    }
    esp_wifi_set_channel(_stats.channel, WIFI_SECOND_CHAN_NONE);
}

void WifiAudit::stop()
{
    _running = false;
    _stats.running = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
}

void WifiAudit::pause()
{
    if (!_running) return;
    _running = false;
    _stats.running = false;
    esp_wifi_set_promiscuous(false);
}

void WifiAudit::resume()
{
    if (_running) return;
    _running = true;
    _stats.running = true;
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(_stats.channel, WIFI_SECOND_CHAN_NONE);
}

void WifiAudit::set_channel(uint8_t channel)
{
    if (channel == 0) { _stats.hopping = true; return; }
    if (channel > 14) return;
    _stats.hopping = false;
    _stats.channel = channel;
    if (_running) esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

void WifiAudit::_hop()
{
    uint8_t ch = _stats.channel + 1;
    if (ch > 13) ch = 1;
    _stats.channel = ch;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

void WifiAudit::loop()
{
    if (!_running || !s_ap) return;
    const uint32_t now = millis();

    /* Dwell longer than the other monitors: a beacon interval is ~100 ms and we
     * want a full set of IEs per channel. */
    if (_stats.hopping && now - _last_hop >= 500) { _last_hop = now; _hop(); }

    if (now - _last_tick >= 1000) {
        _last_tick = now;
        uint16_t risk = 0, wps = 0, nopmf = 0, n = 0;
        portENTER_CRITICAL(&s_mux);
        n = (uint16_t)s_n;
        for (int i = 0; i < s_n; i++) {
            if (s_ap[i].findings)                  risk++;
            if (s_ap[i].flags & WA_WPS_UNLOCKED)   wps++;
            if (s_ap[i].flags & WA_NO_PMF)         nopmf++;
        }
        portEXIT_CRITICAL(&s_mux);
        _stats.aps      = n;
        _stats.at_risk  = risk;
        _stats.wps_open = wps;
        _stats.no_pmf   = nopmf;
    }
}

int WifiAudit::list(AuditAp* out, int max) const
{
    if (!out || max <= 0 || !s_ap) return 0;
    static void* s_wal_buf = nullptr;
    AuditAp* snap = (AuditAp*)mk_psram_buf(&s_wal_buf, sizeof(AuditAp) * (MAX_APS));
    if (!snap) return 0;
    int n;
    portENTER_CRITICAL(&s_mux);
    n = s_n;
    for (int i = 0; i < n; i++) snap[i] = s_ap[i];
    portEXIT_CRITICAL(&s_mux);

    /* most findings first, then strongest signal */
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (snap[j].findings > snap[i].findings ||
                (snap[j].findings == snap[i].findings && snap[j].rssi > snap[i].rssi)) {
                AuditAp t = snap[i]; snap[i] = snap[j]; snap[j] = t;
            }
    if (n > max) n = max;
    for (int i = 0; i < n; i++) out[i] = snap[i];
    return n;
}
