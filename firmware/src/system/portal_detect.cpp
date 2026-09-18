/**
 * @file portal_detect.cpp
 * @brief See portal_detect.h.
 */
#include "portal_detect.h"
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <HTTPClient.h>
#include <cstring>
#include "mk_psram_buf.h"
#include <cstdio>
#include <SD_MMC.h>

namespace {

/* A plain-HTTP endpoint that answers 204 with no body. Anything else on the
 * path means something is rewriting our traffic. Deliberately not HTTPS: a
 * portal cannot transparently intercept TLS without a certificate error, so
 * only cleartext reveals it. */
static const char* PROBE_URL = "http://connectivitycheck.gstatic.com/generate_204";
static constexpr uint32_t PROBE_JOIN_MS = 12000;
static constexpr uint32_t PROBE_HTTP_MS = 6000;

/* In PSRAM, not internal .bss: raising these caps in internal RAM starved the
 * Bluetooth controller once already. pcap_capture's ring is PSRAM and is
 * written from the same promiscuous critical sections, so the pattern is
 * proven on this hardware. */
static PortalSsidInfo* s_ssid = nullptr;
static int             s_n = 0;
static bool ensure_table()
{
    static void* slot = nullptr;
    if (!s_ssid) s_ssid = (PortalSsidInfo*)mk_psram_buf(
        &slot, sizeof(PortalSsidInfo) * PortalDetect::MAX_SSIDS);
    return s_ssid != nullptr;
}

/* Write what the radio actually saw to /portal/scan.log.
 *
 * The device is normally untethered and its USB CDC stays silent unless
 * something writes to it, so on-screen counters were the only channel back —
 * which meant a person reading numbers off a 320x240 panel and retyping them.
 * The SD card already round-trips on every firmware update, so it is the
 * cheapest telemetry path there is. Truncated each session, not appended, so
 * it cannot grow without bound. */
static bool s_log_started = false;
static int  s_scan_src    = 0;   /* 0 none, 1 IDF, 2 Arduino store */

static void log_scan(esp_err_t err, int num, const wifi_ap_record_t* recs,
                     const PortalStats& st)
{
    SD_MMC.mkdir("/portal");
    File f = SD_MMC.open("/portal/scan.log",
                         s_log_started ? FILE_APPEND : FILE_WRITE);
    if (!f) return;
    s_log_started = true;

    /* Both channels: the card is the reliable one (the device is normally
     * untethered), Serial is the immediate one when it happens to be
     * plugged in. Neither is load-bearing for the feature. */
    #define PD_LOG(...) do { f.printf(__VA_ARGS__); Serial.printf(__VA_ARGS__); } while (0)

    PD_LOG("[pd] scan t=%lu esp_err=0x%04X num=%d src=%d raw=%u ok=%u hid=%u full=%u tbl=%d\n",
           (unsigned long)millis(), (unsigned)err, num, s_scan_src,
           st.raw_seen, st.accepted, st.rej_hidden, st.rej_full,
           st.table_ok ? 1 : 0);
    for (int i = 0; i < num && recs; i++) {
        char ss[33];
        memcpy(ss, recs[i].ssid, 32);
        ss[32] = '\0';
        PD_LOG("[pd]   %02X:%02X:%02X:%02X:%02X:%02X ch%-3u %4d  auth%-2u  %s\n",
               recs[i].bssid[0], recs[i].bssid[1], recs[i].bssid[2],
               recs[i].bssid[3], recs[i].bssid[4], recs[i].bssid[5],
               recs[i].primary, recs[i].rssi, (unsigned)recs[i].authmode,
               ss[0] ? ss : "<hidden>");
    }
    #undef PD_LOG
    f.close();
}

/* "http://192.168.4.1/" -> true, "https://wifi.marriott.com/x" -> false.
 * Only the host part matters; a host made entirely of digits and dots is an
 * address, not a name. */
static bool redirect_is_bare_ip(const char* url)
{
    if (!url) return false;
    const char* p = strstr(url, "://");
    p = p ? p + 3 : url;
    bool any = false;
    for (; *p && *p != '/' && *p != ':' && *p != '?'; p++) {
        if (*p == '.') continue;
        if (*p < '0' || *p > '9') return false;
        any = true;
    }
    return any;
}

static bool same_oui(const uint8_t* a, const uint8_t* b)
{
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2];
}

/* Higher = stronger. Mirrors mk_ap_t.auth ordering closely enough to spot a
 * downgrade; the exact ranking between WPA2 variants does not matter here. */
static int auth_rank(uint8_t a)
{
    switch (a) {
        case 0:  return 0;   /* open     */
        case 1:  return 1;   /* WEP      */
        case 2:  return 2;   /* WPA      */
        case 3:  return 3;   /* WPA2     */
        case 4:  return 3;   /* WPA/2    */
        case 5:  return 4;   /* WPA2-EAP */
        case 6:  return 5;   /* WPA3     */
        case 7:  return 5;   /* WPA2/3   */
        default: return 3;
    }
}

static PortalSsidInfo* find_or_add(const char* ssid)
{
    if (!s_ssid) return nullptr;      /* never allocate from a callback path */
    for (int i = 0; i < s_n; i++)
        if (!strcmp(s_ssid[i].ssid, ssid)) return &s_ssid[i];
    if (s_n >= PortalDetect::MAX_SSIDS) return nullptr;
    PortalSsidInfo* e = &s_ssid[s_n++];
    *e = PortalSsidInfo{};
    snprintf(e->ssid, sizeof(e->ssid), "%s", ssid);
    e->best_rssi  = -127;
    e->first_auth = 0xFF;          /* "unset" */
    return e;
}

} // namespace

void PortalDetect::begin()
{
    s_log_started = false;                   /* truncate the log per session */
    Serial.println("[pd] begin");
    const bool tbl = ensure_table();
    s_n = 0;
    _stats = PortalStats{};
    _stats.table_ok = tbl;
    _stats.running = true;
    _probe = PortalProbeResult{};
    _running    = true;
    _last_scan  = 0;              /* scan immediately */
    /* Every other Meowrauder screen puts the radio in promiscuous mode, and
     * an STA scan cannot run while it is claimed. Portal Check is normally
     * reached by navigating away from one of those screens, so clear it here
     * rather than trusting each of them to have cleaned up. */
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);

    WiFi.mode(WIFI_STA);
    WiFi.disconnect(false, false);
}

void PortalDetect::stop()
{
    _running = false;
    _stats.running  = false;
    _stats.scanning = false;
    WiFi.scanDelete();
    probe_stop();
}

/* Fold one completed scan into the SSID table. */
void PortalDetect::_harvest(const wifi_ap_record_t* recs, int n)
{
    if (n < 0 || (n > 0 && !recs)) n = 0;
    _stats.raw_seen   = (uint16_t)n;
    _stats.accepted   = 0;
    _stats.rej_hidden = 0;
    _stats.rej_full   = 0;
    _stats.rej_bssid  = 0;

    for (int i = 0; i < n; i++) {
        const wifi_ap_record_t* ap = &recs[i];

        char ss[33];
        memcpy(ss, ap->ssid, 32);
        ss[32] = '\0';
        if (!ss[0]) { _stats.rej_hidden++; continue; }          /* hidden */
        PortalSsidInfo* e = find_or_add(ss);
        if (!e) { _stats.rej_full++; continue; }

        const uint8_t* bs = ap->bssid;
        _stats.accepted++;
        const int8_t  rs = (int8_t)ap->rssi;
        const uint8_t ch = ap->primary;
        uint8_t au;
        switch (ap->authmode) {
            case WIFI_AUTH_OPEN:            au = 0; break;
            case WIFI_AUTH_WEP:             au = 1; break;
            case WIFI_AUTH_WPA_PSK:         au = 2; break;
            case WIFI_AUTH_WPA2_PSK:        au = 3; break;
            case WIFI_AUTH_WPA_WPA2_PSK:    au = 4; break;
            case WIFI_AUTH_WPA2_ENTERPRISE: au = 5; break;
#ifdef WIFI_AUTH_WPA3_PSK
            case WIFI_AUTH_WPA3_PSK:        au = 6; break;
#endif
#ifdef WIFI_AUTH_WPA2_WPA3_PSK
            case WIFI_AUTH_WPA2_WPA3_PSK:   au = 7; break;
#endif
            default:                        au = 3; break;
        }

        /* strongest auth ever advertised under this name */
        if (e->first_auth == 0xFF || auth_rank(au) > auth_rank(e->first_auth))
            e->first_auth = au;
        if (rs > e->best_rssi) e->best_rssi = rs;

        /* update or append this BSSID */
        int slot = -1;
        for (int k = 0; k < e->n_bssid; k++)
            if (!memcmp(e->ap[k].bssid, bs, 6)) { slot = k; break; }
        if (slot < 0) {
            if (e->n_bssid < MAX_PER) slot = e->n_bssid++;
            else {                                   /* replace the weakest */
                slot = 0;
                for (int k = 1; k < e->n_bssid; k++)
                    if (e->ap[k].rssi < e->ap[slot].rssi) slot = k;
                if (rs <= e->ap[slot].rssi) continue;
            }
            memcpy(e->ap[slot].bssid, bs, 6);
        }
        e->ap[slot].channel = ch;
        e->ap[slot].rssi    = rs;
        e->ap[slot].auth    = au;
    }

}

void PortalDetect::_analyse()
{
    if (!s_ssid) return;
    uint16_t flagged = 0;

    for (int i = 0; i < s_n; i++) {
        PortalSsidInfo* e = &s_ssid[i];
        e->flags = 0;
        if (e->n_bssid == 0) continue;

        bool any_open = false, any_secure = false;
        int  min_ch = 99, max_ch = 0;
        int8_t strongest = -127, strongest_open = -127;

        for (int k = 0; k < e->n_bssid; k++) {
            const PortalBssid& a = e->ap[k];
            if (a.auth == 0) { any_open = true; if (a.rssi > strongest_open) strongest_open = a.rssi; }
            else               any_secure = true;
            if (a.channel && a.channel < min_ch) min_ch = a.channel;
            if (a.channel > max_ch)              max_ch = a.channel;
            if (a.rssi > strongest)              strongest = a.rssi;

            /* vendor mismatch against the first BSSID we recorded */
            if (k > 0 && !same_oui(e->ap[0].bssid, a.bssid))
                e->flags |= PD_MULTI_OUI;

            /* weaker than the strongest security this name ever advertised */
            if (e->first_auth != 0xFF && auth_rank(a.auth) < auth_rank(e->first_auth))
                e->flags |= PD_AUTH_DOWNGRADE;
        }

        /* An open copy of a secured network is the classic evil twin. */
        if (any_open && any_secure) e->flags |= PD_OPEN_CLONE;

        /* Legitimate multi-AP deployments do use different channels, so this is
         * only interesting alongside another flag — it is left informational. */
        if (e->n_bssid > 1 && max_ch - min_ch >= 5) e->flags |= PD_MULTI_CHANNEL;

        /* An open clone louder than everything else nearby: someone in the room. */
        if (any_open && any_secure && strongest_open >= strongest - 3)
            e->flags |= PD_SIGNAL_JUMP;

        if (e->flags & (PD_OPEN_CLONE | PD_MULTI_OUI | PD_AUTH_DOWNGRADE | PD_SIGNAL_JUMP))
            flagged++;
    }

    _stats.ssids   = (uint16_t)s_n;
    _stats.flagged = flagged;
}

void PortalDetect::loop()
{
    if (!_running) return;

    /* the active probe owns the radio while it runs */
    if (_probe.state == PD_PROBE_CONNECTING || _probe.state == PD_PROBE_CHECKING) {
        probe_loop();
        return;
    }

    const uint32_t now = millis();
    if (now - _last_scan < SCAN_GAP_MS) return;
    _last_scan = now;

    /* Scan through esp_wifi directly rather than WiFi.scanNetworks().
     *
     * Arduino's wrapper opens with
     *
     *     if (getStatusBits() & WIFI_SCANNING_BIT) return WIFI_SCAN_RUNNING;
     *
     * and sets WIFI_SCANNING_BIT once esp_wifi_scan_start() succeeds. Only
     * _scanDone() (on SCAN_DONE) or scanComplete() (past _scanTimeout) clears
     * it. A scan started while the radio is claimed for promiscuous capture
     * can finish without raising SCAN_DONE, and a blocking scanNetworks()
     * that gives up waiting returns WIFI_SCAN_FAILED with the bit still set.
     * One such attempt latches it for the rest of the boot and every later
     * scan returns -1 without reaching the driver — which is exactly what
     * this screen reported on hardware. Clearing promiscuous afterwards does
     * not unstick it; only scanComplete() does.
     *
     * esp_wifi_scan_start has no such wrapper state, and its esp_err_t says
     * what actually went wrong instead of collapsing to -1. */
    esp_wifi_set_promiscuous(false);         /* a claimed radio cannot scan */
    esp_wifi_scan_stop();                    /* drop anything still pending */

    wifi_scan_config_t cfg = {};
    cfg.show_hidden          = false;
    cfg.scan_type            = WIFI_SCAN_TYPE_ACTIVE;
    cfg.scan_time.active.min = 100;
    cfg.scan_time.active.max = 300;

    _stats.scanning = true;
    const esp_err_t err = esp_wifi_scan_start(&cfg, true /*block*/);
    _stats.scanning = false;
    _stats.scan_rc  = (int16_t)err;          /* 0 == ESP_OK */
    if (err != ESP_OK) { log_scan(err, 0, nullptr, _stats); return; }

    /* Where the results actually are.
     *
     * Arduino registers a WIFI_EVENT_SCAN_DONE handler that runs
     * WiFiScanClass::_scanDone() -> esp_wifi_scan_get_ap_records(), and that
     * call FREES the driver's internal list. It fires before this code is
     * reached, so asking the IDF for the records returns ESP_OK and a count
     * of zero — which is precisely what the device logged:
     *
     *     [pd] scan t=140464 esp_err=0x0000 num=0 raw=0 ...
     *
     * The records are in Arduino's store by then. So: scan through the IDF
     * (which sidesteps the WIFI_SCANNING_BIT guard that was returning -1 before
     * the driver was ever reached), then read from whichever store actually
     * has them. Do not assume either one — the handler's registration is not
     * ours to depend on. */
    static void* slot = nullptr;
    wifi_ap_record_t* recs = (wifi_ap_record_t*)mk_psram_buf(
        &slot, sizeof(wifi_ap_record_t) * MAX_SSIDS);
    if (!recs) { log_scan(err, 0, nullptr, _stats); return; }

    uint16_t num = 0;
    if (esp_wifi_scan_get_ap_num(&num) != ESP_OK) num = 0;
    if (num > MAX_SSIDS) num = MAX_SSIDS;
    if (num && esp_wifi_scan_get_ap_records(&num, recs) != ESP_OK) num = 0;
    s_scan_src = num ? 1 : 0;              /* 1 = IDF still had them */

    if (!num) {                            /* Arduino drained them first */
        int an = WiFi.scanComplete();
        if (an > MAX_SSIDS) an = MAX_SSIDS;
        for (int i = 0; i < an; i++) {
            wifi_ap_record_t* r = &recs[num];
            memset(r, 0, sizeof(*r));
            String ss = WiFi.SSID(i);
            strncpy((char*)r->ssid, ss.c_str(), sizeof(r->ssid) - 1);
            const uint8_t* bs = WiFi.BSSID(i);
            if (bs) memcpy(r->bssid, bs, 6);
            r->rssi     = (int8_t)WiFi.RSSI(i);
            r->primary  = (uint8_t)WiFi.channel(i);
            r->authmode = WiFi.encryptionType(i);
            num++;
        }
        if (num) s_scan_src = 2;            /* 2 = came from Arduino's store */
    }

    _stats.scans++;
    _stats.complete_rc = (int16_t)num;
    _harvest(recs, (int)num);
    _analyse();
    log_scan(err, (int)num, recs, _stats);
    WiFi.scanDelete();
}

int PortalDetect::list(PortalSsidInfo* out, int max) const
{
    if (!out || max <= 0 || !s_ssid) return 0;
    static void* s_pdl_buf = nullptr;
    PortalSsidInfo* snap = (PortalSsidInfo*)mk_psram_buf(&s_pdl_buf, sizeof(PortalSsidInfo) * (MAX_SSIDS));
    if (!snap) return 0;
    int n = s_n;
    for (int i = 0; i < n; i++) snap[i] = s_ssid[i];

    /* flagged first, then strongest */
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++) {
            const bool fi = snap[i].flags != 0, fj = snap[j].flags != 0;
            if ((fj && !fi) || (fj == fi && snap[j].best_rssi > snap[i].best_rssi)) {
                PortalSsidInfo t = snap[i]; snap[i] = snap[j]; snap[j] = t;
            }
        }
    if (n > max) n = max;
    for (int i = 0; i < n; i++) out[i] = snap[i];
    return n;
}

/* ── active probe ────────────────────────────────────────────────────── */

bool PortalDetect::probe_begin(const char* ssid)
{
    if (!ssid || !ssid[0]) return false;

    /* Open networks only: we never offer a passphrase to an unknown AP. */
    const PortalSsidInfo* e = nullptr;
    for (int i = 0; i < s_n; i++)
        if (!strcmp(s_ssid[i].ssid, ssid)) { e = &s_ssid[i]; break; }
    if (!e) return false;
    bool open = false;
    for (int k = 0; k < e->n_bssid; k++) if (e->ap[k].auth == 0) open = true;
    if (!open) return false;

    WiFi.scanDelete();
    _stats.scanning = false;

    _probe = PortalProbeResult{};
    snprintf(_probe.ssid, sizeof(_probe.ssid), "%s", ssid);
    _probe.state = PD_PROBE_CONNECTING;
    _probe_started = millis();

    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid);            /* open network: no passphrase */
    return true;
}

void PortalDetect::probe_stop()
{
    if (_probe.state == PD_PROBE_CONNECTING || _probe.state == PD_PROBE_CHECKING) {
        WiFi.disconnect(false, true);
        _probe.state = PD_PROBE_IDLE;
    }
}

/* Fold the passive per-SSID flags in with what the probe saw, and weight the
 * result.
 *
 * No single signal here is proof. A legitimate cafe portal will trip
 * DNS_WILDCARD and often NO_SERVER, and lands around 20. An ESP32 evil
 * portal cloning a known network trips SOFTAP_GW + IP_REDIRECT + OPEN_CLONE
 * and lands well past 75. The weights say which evidence is load-bearing:
 * the gateway address and the open clone do most of the work, because those
 * are the two a real venue has no reason to produce. */
void PortalDetect::_score_rogue()
{
    /* carry over what repeated scans already established about this SSID */
    if (s_ssid) {
        for (int i = 0; i < s_n; i++) {
            if (strcmp(s_ssid[i].ssid, _probe.ssid)) continue;
            const uint16_t f = s_ssid[i].flags;
            if (f & PD_OPEN_CLONE)  _probe.rogue_flags |= PD_RG_OPEN_CLONE;
            if (f & PD_SIGNAL_JUMP) _probe.rogue_flags |= PD_RG_SIGNAL_JUMP;
            if (f & PD_MULTI_OUI)   _probe.rogue_flags |= PD_RG_MULTI_OUI;
            break;
        }
    }

    const uint16_t f = _probe.rogue_flags;
    int score = 0;
    if (f & PD_RG_SOFTAP_GW)    score += 40;
    if (f & PD_RG_OPEN_CLONE)   score += 35;
    if (f & PD_RG_IP_REDIRECT)  score += 20;
    if (f & PD_RG_MULTI_OUI)    score += 15;
    if (f & PD_RG_DNS_WILDCARD) score += 10;
    if (f & PD_RG_NO_SERVER)    score += 10;
    if (f & PD_RG_SIGNAL_JUMP)  score += 10;
    if (f & PD_RG_FAST_LOCAL)   score += 5;

    /* A network that does not intercept anything is not a rogue portal,
     * whatever else it trips. */
    if (_probe.verdict == PD_VERDICT_CLEAR || _probe.verdict == PD_VERDICT_NONET)
        score = 0;

    _probe.rogue_conf = (uint8_t)(score > 100 ? 100 : score);
}

void PortalDetect::probe_loop()
{
    const uint32_t now = millis();

    if (_probe.state == PD_PROBE_CONNECTING) {
        if (WiFi.status() == WL_CONNECTED) {
            _probe.state = PD_PROBE_CHECKING;
            return;
        }
        if (now - _probe_started > PROBE_JOIN_MS) {
            _probe.state      = PD_PROBE_FAILED;
            _probe.verdict    = PD_VERDICT_NONET;
            _probe.elapsed_ms = now - _probe_started;
            WiFi.disconnect(false, true);
        }
        return;
    }

    if (_probe.state != PD_PROBE_CHECKING) return;

    /* ── rogue evidence, gathered while we hold the lease ─────────────── */

    /* The gateway address. Arduino's SoftAP defaults to 192.168.4.1 and
     * neither Marauder, Bruce nor the Flipper portals change it, so this is
     * the single most characteristic tell of an ESP32-class evil portal. A
     * real venue runs its gateway on its own LAN numbering. */
    const IPAddress gw = WiFi.gatewayIP();
    snprintf(_probe.gateway, sizeof(_probe.gateway), "%u.%u.%u.%u",
             gw[0], gw[1], gw[2], gw[3]);
    if (gw[0] == 192 && gw[1] == 168 && gw[2] == 4 && gw[3] == 1)
        _probe.rogue_flags |= PD_RG_SOFTAP_GW;

    /* A name that cannot exist. If it resolves, DNS is being answered
     * locally for everything. Legitimate portals do this too, which is why
     * it is weighted low on its own. */
    {
        IPAddress dummy;
        if (WiFi.hostByName("wpad-nx-7f3a2b91.invalid", dummy) == 1)
            _probe.rogue_flags |= PD_RG_DNS_WILDCARD;
    }

    /* One cleartext request to a known-204 endpoint. Redirects are NOT
     * followed — the Location header is the interesting part. */
    WiFiClient client;
    HTTPClient http;
    http.setTimeout(PROBE_HTTP_MS);
    http.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS);

    if (!http.begin(client, PROBE_URL)) {
        _probe.state   = PD_PROBE_FAILED;
        _probe.verdict = PD_VERDICT_NONET;
    } else {
        const char* hdrs[] = { "Location", "Server" };
        http.collectHeaders(hdrs, 2);
        const uint32_t t0 = millis();
        const int code = http.GET();
        _probe.rtt_ms    = (uint16_t)(millis() - t0);
        _probe.http_code = (int16_t)code;

        if (code == 204) {
            _probe.verdict = PD_VERDICT_CLEAR;
        } else if (code >= 300 && code < 400) {
            _probe.verdict = PD_VERDICT_PORTAL;
            String loc = http.header("Location");
            if (loc.length()) {
                snprintf(_probe.redirect, sizeof(_probe.redirect), "%s", loc.c_str());
                /* A venue portal redirects to a branded hostname it owns.
                 * An ESP32 portal has no name to redirect to, so it sends
                 * its own address. */
                if (redirect_is_bare_ip(loc.c_str()))
                    _probe.rogue_flags |= PD_RG_IP_REDIRECT;
            }
        } else if (code == 200) {
            /* a body where a 204 belongs: something answered for the endpoint */
            _probe.verdict = PD_VERDICT_INTERCEPT;
        } else if (code > 0) {
            _probe.verdict = PD_VERDICT_INTERCEPT;
        } else {
            _probe.verdict = PD_VERDICT_NONET;
        }
        String srv = http.header("Server");
        if (srv.length()) snprintf(_probe.server, sizeof(_probe.server), "%s", srv.c_str());
        else if (code > 0) _probe.rogue_flags |= PD_RG_NO_SERVER;

        /* An answer inside ~15 ms never left the room. A venue portal sits
         * behind at least one upstream hop. */
        if (code > 0 && _probe.rtt_ms <= 15) _probe.rogue_flags |= PD_RG_FAST_LOCAL;

        http.end();
        _probe.state = PD_PROBE_DONE;
    }

    _score_rogue();

    _probe.elapsed_ms = millis() - _probe_started;
    WiFi.disconnect(false, true);       /* never linger on an unknown network */
}
