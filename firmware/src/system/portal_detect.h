/**
 * @file  portal_detect.h
 * @brief Evil-twin and captive-portal detection — the defensive inverse of a
 *        rogue-AP attack.
 *
 * Two halves:
 *
 *  1. PASSIVE. Repeated scans are grouped by SSID. An SSID advertised by more
 *     than one BSSID is normal (roaming, mesh), so the flags below look for the
 *     patterns that are not: the same name offered both open and secured, BSSIDs
 *     from unrelated vendors, a security downgrade over time, or a clone that is
 *     suddenly far louder than the AP you know. Nothing is transmitted and
 *     nothing is joined.
 *
 *  2. ACTIVE PROBE, one network at a time and only when asked. Joins a chosen
 *     OPEN network and fetches a known 204 endpoint — exactly the connectivity
 *     check every phone and laptop performs automatically. A 204 means the path
 *     is clear; a redirect or a page body means something is intercepting HTTP,
 *     which is what a captive portal does. The redirect host is reported so you
 *     can see where a portal is sending you.
 *
 * This finds portals and impersonated networks. It does not create either.
 */
#pragma once
#include <cstdint>
#include <esp_wifi_types.h>   /* wifi_ap_record_t */

/* Anomaly flags on an SSID group. */
enum {
    PD_OPEN_CLONE     = 1u << 0,  /* same SSID offered open AND secured      */
    PD_MULTI_OUI      = 1u << 1,  /* BSSIDs from unrelated vendor OUIs       */
    PD_AUTH_DOWNGRADE = 1u << 2,  /* security got weaker than first seen     */
    PD_MULTI_CHANNEL  = 1u << 3,  /* same SSID on widely separated channels  */
    PD_SIGNAL_JUMP    = 1u << 4,  /* a clone much louder than the known AP   */
};

/* Active-probe lifecycle. */
enum { PD_PROBE_IDLE = 0, PD_PROBE_CONNECTING, PD_PROBE_CHECKING,
       PD_PROBE_DONE, PD_PROBE_FAILED };

/* Active-probe verdict: what the network DOES. Deliberately separate from
 * the rogue evidence below, which is whether it looks HOSTILE. Every hotel,
 * airport and cafe network on earth returns PD_VERDICT_PORTAL, so a portal
 * verdict on its own is not a finding. */
enum { PD_VERDICT_NONE = 0,
       PD_VERDICT_CLEAR,      /* 204, no interception                     */
       PD_VERDICT_PORTAL,     /* redirected — captive portal              */
       PD_VERDICT_INTERCEPT,  /* 200 with a body instead of 204           */
       PD_VERDICT_NONET };    /* joined but no usable path, or join failed */

/* Rogue evidence gathered while joined. Weighted, because no single one of
 * these proves anything: a legitimate cafe portal will trip two or three. */
enum {
    PD_RG_SOFTAP_GW    = 1u << 0,  /* gateway is 192.168.4.1               */
    PD_RG_IP_REDIRECT  = 1u << 1,  /* redirected to a bare IP, not a host  */
    PD_RG_DNS_WILDCARD = 1u << 2,  /* invented hostname still resolves     */
    PD_RG_NO_SERVER    = 1u << 3,  /* no Server: header at all             */
    PD_RG_FAST_LOCAL   = 1u << 4,  /* answered too fast for an upstream hop*/
    PD_RG_OPEN_CLONE   = 1u << 5,  /* SSID also exists secured  (passive)  */
    PD_RG_SIGNAL_JUMP  = 1u << 6,  /* clone much louder than the real AP   */
    PD_RG_MULTI_OUI    = 1u << 7,  /* same SSID across vendor OUIs         */
};

struct PortalBssid {
    uint8_t bssid[6];
    uint8_t channel;
    int8_t  rssi;
    uint8_t auth;      /* same encoding as mk_ap_t.auth */
};

struct PortalSsidInfo {
    char        ssid[33];
    uint8_t     n_bssid;
    uint16_t    flags;         /* PD_* */
    int8_t      best_rssi;
    uint8_t     first_auth;    /* strongest auth ever seen for this SSID */
    PortalBssid ap[4];
};

struct PortalStats {
    uint16_t ssids    = 0;
    uint16_t flagged  = 0;
    uint16_t scans    = 0;
    bool     scanning = false;
    bool     running  = false;

    /* Diagnostics. "Portal Check sees no SSIDs" has three very different
     * causes — the scan never starts, the scan starts and fails, or the scan
     * succeeds and the table drops everything — and they are indistinguishable
     * from a count of zero. These separate them on screen. */
    int16_t  scan_rc     = 0;    /* last scanNetworks() return   */
    int16_t  complete_rc = 0;    /* last scanComplete() return   */
    uint16_t raw_seen    = 0;    /* entries the last scan returned */
    uint16_t accepted    = 0;    /* entries folded into the table  */
    uint16_t rej_hidden  = 0;    /* dropped: blank SSID            */
    uint16_t rej_full    = 0;    /* dropped: table at MAX_SSIDS    */
    uint16_t rej_bssid   = 0;    /* unused since the IDF scan: a
                                  * wifi_ap_record_t always has a BSSID */
    bool     table_ok    = false;/* PSRAM table allocated          */
};

struct PortalProbeResult {
    char     ssid[33] = {0};
    uint8_t  state    = PD_PROBE_IDLE;
    uint8_t  verdict  = PD_VERDICT_NONE;
    int16_t  http_code = 0;
    char     redirect[64] = {0};   /* host a portal redirected us to */
    uint32_t elapsed_ms = 0;

    uint16_t rogue_flags = 0;      /* PD_RG_*                             */
    uint8_t  rogue_conf  = 0;      /* 0-100, weighted sum of the above    */
    char     gateway[16] = {0};    /* dotted quad, for the operator to see */
    char     server[24]  = {0};    /* Server: header, "" if absent        */
    uint16_t rtt_ms      = 0;      /* time for the probe request alone    */
};

class PortalDetect {
public:
    /* Sized against a real survey: 41 BSSIDs / 24 unique SSIDs in one room,
     * and the old cap of 24 sat exactly on that boundary, so an AP could be
     * dropped purely by scan order. The table lives in PSRAM, so headroom is
     * cheap. */
    static constexpr int MAX_SSIDS   = 96;
    static constexpr int MAX_PER     = 4;    /* BSSIDs kept per SSID */
    static constexpr int SCAN_GAP_MS = 4000;

    void begin();
    void stop();
    void loop();                 /* drives the async scan + analysis */
    bool running() const { return _running; }

    const PortalStats& stats() const { return _stats; }
    int  list(PortalSsidInfo* out, int max) const;   /* flagged first */

    /* Active probe. Open networks only — this never sends a passphrase.
     * Returns false if the SSID is unknown or is not open. */
    bool probe_begin(const char* ssid);
    void probe_loop();
    void probe_stop();
    const PortalProbeResult& probe() const { return _probe; }

private:
    bool        _running   = false;
    uint32_t    _last_scan = 0;
    PortalStats _stats;
    PortalProbeResult _probe;
    uint32_t    _probe_started = 0;

    void _harvest(const wifi_ap_record_t* recs, int n);
    void _score_rogue();
    void _analyse();
};
