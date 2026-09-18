/**
 * @file  wifi_fox.h
 * @brief WiFi Fox Hunt — follow one 802.11 target by signal strength.
 *
 * Promiscuous capture builds a target list: APs (from beacons and probe
 * responses, so they carry an SSID) and stations (from data/probe-request
 * frames). RSSI is smoothed with the same median+EWMA filter the BLE tracker
 * store uses, then one selected target is followed through TrackerFinder — the
 * same tested state machine behind the BLE tracker radar, so Live/Waiting/Lost,
 * trend and relative strength behave identically on both radios.
 *
 * Receive-only: it listens and never transmits.
 */
#pragma once
#include <cstdint>
#include "tracker_monitor.h"   /* TrackerEntry — the finder's input type */
#include "tracker_finder.h"

enum { FOX_KIND_AP = 0, FOX_KIND_STA = 1 };

struct FoxTarget {
    uint8_t  mac[6];
    char     ssid[33];        /* APs only; "" for stations        */
    uint8_t  kind;            /* FOX_KIND_*                       */
    uint8_t  channel;
    int8_t   rssi;            /* last raw sample                  */
    int16_t  filtered_rssi;   /* median + EWMA, dBm               */
    uint16_t count;
    uint32_t first_ms;
    uint32_t last_ms;
    uint32_t id;              /* stable, nonzero within a session */
    uint32_t sequence;        /* bumps only on a real new sample  */
    bool     scan_fresh;
};

struct FoxStats {
    uint16_t targets = 0;     /* entries currently held  */
    uint16_t aps     = 0;
    uint16_t stations = 0;
    uint8_t  channel = 1;
    bool     hopping = true;
    bool     running = false;
};

class WifiFox {
public:
    /* Tracks APs and stations, so it fills fastest of all: 41 BSSIDs plus
     * every client seen. 32 was far too small. PSRAM. */
    static constexpr int MAX_TARGETS = 160;
    static constexpr int SAMPLES     = 5;    /* median window */

    void begin();
    void stop();
    void loop();                      /* channel hop + finder update */
    void pause();
    void resume();
    bool running() const { return _running; }

    const FoxStats& stats() const { return _stats; }

    /* Copy up to max targets, strongest filtered RSSI first. */
    int  list(FoxTarget* out, int max) const;

    /* 0 releases the current target. Returns 1 if the id is present. */
    int  select(uint32_t id);
    const TrackerFinder& finder() const { return _finder; }
    bool finder_target(FoxTarget& out) const;

    void set_channel(uint8_t channel);   /* 0 = resume hopping */

private:
    bool      _running   = false;
    uint32_t  _last_hop  = 0;
    uint32_t  _sel       = 0;
    FoxStats  _stats;
    TrackerFinder _finder;

    void _hop();
};
