/**
 * @file  wifi_audit.h
 * @brief Per-AP WiFi security audit from beacon information elements.
 *
 * FeralCat's AP list shows a coarse label ("WPA2", "Open") because that is all
 * esp_wifi's scan gives back. The interesting facts for an assessment live in
 * the IEs that label is derived from, and nothing on the device reads them:
 *
 *   RSN (tag 48)   pairwise/group ciphers, AKM suites, and the RSN capability
 *                  bits that say whether 802.11w management-frame protection is
 *                  REQUIRED, merely capable, or absent
 *   WPA1 (221/1)   the deprecated pre-RSN element
 *   WPS  (221/4)   setup state and whether AP Setup Locked is set — an
 *                  unlocked, configured WPS registrar is the Pixie-Dust case
 *
 * From those we report findings rather than a label: TKIP still enabled, WPA3
 * running in transition mode (and therefore downgradable), PMF not required (so
 * deauthentication still works against it), WPS left open, hidden SSIDs.
 *
 * Entirely passive — it reads frames that are already in the air.
 */
#pragma once
#include <cstdint>

/* Findings. Roughly ordered by how much they matter. */
enum {
    WA_OPEN            = 1u << 0,  /* no encryption at all              */
    WA_WEP             = 1u << 1,  /* WEP                               */
    WA_WPA1            = 1u << 2,  /* pre-RSN WPA1 element present      */
    WA_TKIP            = 1u << 3,  /* TKIP in pairwise or group cipher  */
    WA_WPS_ENABLED     = 1u << 4,  /* WPS advertised                    */
    WA_WPS_UNLOCKED    = 1u << 5,  /* WPS configured and NOT locked     */
    WA_NO_PMF          = 1u << 6,  /* RSN present but MFPC=0            */
    WA_PMF_OPTIONAL    = 1u << 7,  /* MFPC=1, MFPR=0 — downgradable     */
    WA_WPA3_TRANSITION = 1u << 8,  /* SAE and PSK both offered          */
    WA_HIDDEN          = 1u << 9,  /* SSID withheld in beacons          */
    WA_OWE             = 1u << 10, /* Enhanced Open (informational)     */
    WA_PMF_REQUIRED    = 1u << 11, /* MFPR=1 — good, informational      */
    WA_SAE             = 1u << 12, /* SAE offered (informational)       */
    WA_HIDDEN_RESOLVED = 1u << 13, /* hidden name recovered from an assoc */
    WA_SOFTAP_RATES    = 1u << 14, /* first basic rate is not 1 Mbit/s — the
                                    * signature of an ESP-IDF SoftAP. Measured
                                    * over 27 real 2.4 GHz APs: flags exactly
                                    * one, the rogue portal. */
};

/* Notable beacon IE tags, for fingerprinting an AP's radio stack. */
enum { WA_IE_COUNTRY = 1u << 0,  /* tag 7   — commercial APs nearly always   */
       WA_IE_HT      = 1u << 1,  /* tag 45  — 802.11n capabilities           */
       WA_IE_HTOP    = 1u << 2,  /* tag 61  — 802.11n operation              */
       WA_IE_VHT     = 1u << 3,  /* tag 191 — 802.11ac                       */
       WA_IE_EXTCAP  = 1u << 4,  /* tag 127 — extended capabilities          */
       WA_IE_RM      = 1u << 5,  /* tag 70  — RM enabled capabilities        */
       WA_IE_POWER   = 1u << 6,  /* tag 32/33 — power constraint/capability  */
       WA_IE_WMM     = 1u << 7,  /* WMM vendor IE                            */
       WA_IE_WPS     = 1u << 8,  /* WPS vendor IE                            */
       WA_IE_MOBDOM  = 1u << 9 };/* tag 54  — 802.11r mobility domain        */

/* cipher / akm bitmasks (bit index = suite selector's last byte) */
enum { WA_CIPH_WEP40 = 1u << 1, WA_CIPH_TKIP = 1u << 2, WA_CIPH_CCMP = 1u << 4,
       WA_CIPH_WEP104 = 1u << 5, WA_CIPH_GCMP = 1u << 8 };

struct AuditAp {
    uint8_t  bssid[6];
    char     ssid[33];
    uint8_t  channel;
    int8_t   rssi;
    uint32_t flags;        /* WA_* */
    uint16_t pairwise;     /* WA_CIPH_* bitmask */
    uint16_t group;        /* WA_CIPH_* bitmask */
    uint32_t akm;          /* bit per AKM selector last byte */
    uint8_t  wps_state;    /* 0 none, 1 unconfigured, 2 configured */
    uint8_t  wps_locked;   /* 0 no, 1 yes, 0xFF unknown */
    uint8_t  findings;     /* count of serious flags */
    /* Beacon fingerprint. A bare ESP32/SoftAP beacon carries far fewer
     * information elements than a commercial router's — no country info, no
     * HT/VHT capabilities, few or no vendor IEs. Recorded rather than judged:
     * the discriminator should come from comparing real APs, not guesswork. */
    uint8_t  ie_count;     /* how many IEs the beacon carried      */
    uint8_t  ie_vendor;    /* how many tag-221 vendor IEs          */
    uint16_t ie_mask;      /* notable tags present, see WA_IE_*    */
    uint32_t last_ms;
    uint32_t first_seen_unused_;  /* reserved */
};

struct AuditStats {
    uint16_t aps      = 0;
    uint16_t at_risk  = 0;   /* at least one serious finding */
    uint16_t wps_open = 0;
    uint16_t no_pmf   = 0;
    uint8_t  channel  = 1;
    bool     hopping  = true;
    bool     running  = false;
};

class WifiAudit {
public:
    /* 41 BSSIDs were present in a single real survey; 32 overflowed. PSRAM. */
    static constexpr int MAX_APS = 96;

    void begin();
    void stop();
    void loop();                    /* channel hop + recount */
    void pause();
    void resume();
    bool running() const { return _running; }

    const AuditStats& stats() const { return _stats; }
    int  list(AuditAp* out, int max) const;   /* worst findings first */
    void set_channel(uint8_t channel);        /* 0 = resume hopping */

private:
    bool       _running   = false;
    uint32_t   _last_hop  = 0;
    uint32_t   _last_tick = 0;
    AuditStats _stats;

    void _hop();
};
