/**
 * @file  eapol_capture.h
 * @brief WPA/WPA2 EAPOL and PMKID capture.
 *
 * Watches for EAPOL-Key frames (the 4-way handshake) in promiscuous mode,
 * classifies them M1..M4, and pulls the PMKID out of the RSN KDE in M1 when
 * the AP offers one. EAPOL frames are written to /pcap/eapol_NNN.pcap for
 * offline analysis, and any PMKID found is appended to /pcap/pmkid.22000 in
 * hashcat's WPA*01 form.
 *
 * WPA3 is also covered: SAE authentication frames (auth algorithm 3) are
 * matched and classified commit/confirm, so a WPA3 exchange shows up alongside
 * the WPA2 ones rather than looking like silence.
 *
 * This is for auditing passphrase strength on networks you are permitted to
 * test. Receive-only: it never transmits, so it cannot force a handshake — it
 * only records the ones that happen.
 */
#pragma once
#include <cstdint>

/* message bitmask. M1..M4 are the WPA2 4-way handshake; the SAE bits are the
 * WPA3 authentication exchange, which is management frames rather than EAPOL
 * and so is matched separately. */
enum { EAPOL_M1 = 1, EAPOL_M2 = 2, EAPOL_M3 = 4, EAPOL_M4 = 8,
       EAPOL_SAE_COMMIT = 16, EAPOL_SAE_CONFIRM = 32 };

struct EapolTarget {
    uint8_t  bssid[6];
    uint8_t  sta[6];
    uint8_t  msgs;          /* EAPOL_M* bitmask seen for this pair */
    uint8_t  have_pmkid;    /* 0/1 */
    uint8_t  pmkid[16];
    int8_t   rssi;
    uint8_t  channel;
    uint32_t last_ms;
};

/* Why a start attempt failed. Silence is the worst diagnostic: begin() has
 * five failure paths and reporting none of them makes any of them look like
 * "the button does nothing". */
enum { EAPOL_ERR_NONE = 0, EAPOL_ERR_MEM, EAPOL_ERR_DIR, EAPOL_ERR_FULL,
       EAPOL_ERR_OPEN, EAPOL_ERR_WRITE, EAPOL_ERR_PROMISC };

struct EapolStats {
    uint32_t frames     = 0;   /* EAPOL-Key frames seen              */
    uint16_t targets    = 0;   /* AP/STA pairs tracked               */
    uint16_t pmkids     = 0;   /* distinct PMKIDs written            */
    uint16_t handshakes = 0;   /* pairs with at least M1+M2          */
    uint16_t sae        = 0;   /* pairs with an SAE commit+confirm   */
    uint16_t dropped    = 0;   /* frames lost because the ring filled*/
    uint8_t  channel    = 1;
    bool     hopping    = true;
    bool     running    = false;
    char     path[40]   = {0}; /* "/pcap/eapol_002.pcap"             */
    uint8_t  error      = EAPOL_ERR_NONE;  /* last begin() failure     */
};

class EapolCapture {
public:
    /* AP/STA pairs seen exchanging EAPOL. 16 is thin in a busy building where
     * many clients reconnect; the table is PSRAM-backed so it costs nothing. */
    static constexpr int MAX_TARGETS = 48;
    static constexpr int SNAPLEN     = 512;   /* EAPOL frames are small */
    static constexpr int RING_SIZE   = 8 * 1024;

    bool begin(bool hop, uint8_t channel);
    void stop();
    void loop();                  /* drain ring -> SD, hop, recount */
    void pause();
    void resume();
    bool running() const { return _running; }

    const EapolStats& stats() const { return _stats; }
    int  list(EapolTarget* out, int max) const;   /* newest first */
    void set_channel(uint8_t channel);            /* 0 = resume hopping */

private:
    bool      _running   = false;
    bool      _opened    = false;
    uint32_t  _last_hop  = 0;
    uint32_t  _last_tick = 0;
    EapolStats _stats;

    void _hop();
    void _drain();
};
