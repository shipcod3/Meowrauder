/**
 * @file  evil_twin.h
 * @brief Evil-twin access point with a captive portal, for authorised
 *        social-engineering assessments.
 *
 * Brings up an OPEN SoftAP under a chosen SSID (typically cloned from a target
 * network), hijacks DNS so every lookup resolves to the device, and answers the
 * OS captive-portal probes so the "Sign in to network" sheet appears. The
 * portal page itself is an HTML template read from /portal on the SD card, so
 * the pretext is yours and is not baked into the firmware.
 *
 * Associations, requests and form submissions are logged to
 * /portal/captures.csv with the submitting client's MAC and a timestamp.
 *
 * ── Scope ────────────────────────────────────────────────────────────────
 * This impersonates a network and collects what people type into it. Run it
 * only under a signed engagement that covers social-engineering testing of the
 * site and population you are testing, on the SSIDs named in that scope.
 *
 * Operational hygiene: the capture file is plaintext client credential
 * material. Treat it as the most sensitive artefact of the engagement — pull it
 * off the card, store it as you would any credential dump, and destroy it once
 * the report is delivered.
 */
#pragma once
#include <cstdint>

struct TwinClient {
    uint8_t  mac[6];
    uint32_t joined_ms;
    uint8_t  submitted;     /* 0/1 — has posted the form */
};

struct TwinCapture {
    uint8_t  mac[6];
    uint32_t ms;
    char     field1[48];    /* first form field, usually the identity */
    char     field2[48];    /* second form field, usually the secret  */
};

struct TwinStats {
    char     ssid[33]   = {0};
    char     portal[32] = {0};   /* template file in use */
    uint16_t clients    = 0;     /* currently associated */
    uint16_t seen       = 0;     /* distinct clients since start */
    uint16_t submits    = 0;     /* form submissions */
    uint32_t requests   = 0;     /* HTTP requests served */
    uint8_t  channel    = 1;
    bool     running    = false;
    bool     sd_ok      = false; /* capture log is writable */
};

class EvilTwin {
public:
    static constexpr int MAX_CLIENTS  = 16;
    static constexpr int MAX_CAPTURES = 16;

    /* ssid: the name to advertise. portal: template basename under /portal
     * (e.g. "default" -> /portal/default.html); falls back to a built-in page.
     * channel: 1..13. Returns false if the AP could not start. */
    bool begin(const char* ssid, const char* portal, uint8_t channel);
    void stop();
    void loop();                 /* services DNS + HTTP; call every loop */
    bool running() const { return _running; }

    const TwinStats& stats() const { return _stats; }
    int  clients(TwinClient* out, int max) const;
    int  captures(TwinCapture* out, int max) const;   /* newest first */

    /* Wipe the in-memory capture list and truncate the on-card log. */
    void clear_captures();

private:
    bool      _running = false;
    uint32_t  _last_tick = 0;
    TwinStats _stats;

    void _refresh_clients();
};
