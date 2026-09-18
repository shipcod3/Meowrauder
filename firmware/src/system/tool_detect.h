/**
 * @file  tool_detect.h
 * @brief Detect other people's hacking hardware in the area.
 *
 * The defensive counterpart to the rest of this app: find the Flipper Zeros,
 * Pwnagotchis, WiFi Pineapples, deauthers and ESP32 tool firmwares (Bruce,
 * Marauder) operating nearby. Entirely passive on both radios.
 *
 * Evidence is reported, not asserted. Each hit carries the specific signals
 * that produced it and a confidence derived from how many independent signals
 * agree, because most single signals are weak:
 *
 *   - An Espressif OUI proves nothing on its own. Every ESP32 in the world
 *     shares those prefixes, including the device you are holding. It only
 *     counts as corroboration.
 *   - A name match is suggestive but trivially changed.
 *   - Behaviour is the strong signal: one BSSID advertising many SSIDs is
 *     Karma/Pineapple behaviour, and a station emitting deauthentication
 *     frames is actively attacking regardless of what it calls itself.
 *
 * Only behaviour or a name match can raise a hit. OUI alone never does.
 *
 * WiFi and BLE are separate modes: the two radios contend, and the existing
 * FeralCat monitors take the same one-at-a-time approach.
 */
#pragma once
#include <cstdint>

/* What we think it is. */
enum {
    TD_UNKNOWN = 0,
    TD_PINEAPPLE,    /* many SSIDs from one BSSID / Karma answering everything */
    TD_PWNAGOTCHI,   /* advertises with a JSON payload in the SSID field       */
    TD_DEAUTHER,     /* observed transmitting deauth/disassoc                  */
    TD_MARAUDER,     /* ESP32 Marauder                                        */
    TD_BRUCE,        /* Bruce firmware                                        */
    TD_FLIPPER,      /* Flipper Zero (BLE)                                    */
    TD_ESP_TOOL,     /* an ESP32 running some tool firmware as an AP           */
};

/* Why we think it. */
enum {
    TD_EV_NAME      = 1u << 0,  /* SSID or BLE name matched a signature   */
    TD_EV_OUI       = 1u << 1,  /* vendor prefix is a known tool platform */
    TD_EV_MULTISSID = 1u << 2,  /* one BSSID, many distinct SSIDs         */
    TD_EV_DEAUTH_TX = 1u << 3,  /* seen transmitting deauth/disassoc      */
    TD_EV_BEACON_TX = 1u << 4,  /* seen beaconing (is an AP)              */
    TD_EV_JSON_SSID = 1u << 5,  /* SSID is a JSON blob (Pwnagotchi)       */
    TD_EV_SVC_UUID  = 1u << 6,  /* BLE service UUID matched               */
    TD_EV_MFG       = 1u << 7,  /* BLE manufacturer data matched          */
    TD_EV_SOFTAP    = 1u << 8,  /* OPEN network whose Supported Rates are
                                 * not ascending — an ESP-IDF SoftAP, not a
                                 * commercial AP. This is what catches a
                                 * rogue portal, which is otherwise
                                 * indistinguishable from an ordinary open
                                 * network. Measured, not assumed: beacon IE
                                 * counts and locally-administered MACs both
                                 * failed to separate it.                   */
};

enum { TD_MODE_WIFI = 0, TD_MODE_BLE = 1 };

struct ToolHit {
    uint8_t  mac[6];
    uint8_t  kind;         /* TD_* */
    uint8_t  radio;        /* TD_MODE_* it was seen on */
    uint8_t  confidence;   /* 0..100 */
    int8_t   rssi;
    uint8_t  channel;      /* WiFi only */
    char     label[33];    /* SSID or BLE name, when we have one */
    uint16_t ssid_count;   /* distinct SSIDs seen from this BSSID */
    uint16_t count;        /* sightings */
    uint16_t ad_mask;      /* BLE: AD types present in the advertisement */
    uint16_t mfg_id;       /* BLE: manufacturer company id, 0 if none    */
    uint16_t uuid16;       /* BLE: first 16-bit service UUID, 0 if none  */
    uint32_t evidence;     /* TD_EV_* */
    uint32_t first_ms;
    uint32_t last_ms;
};

struct ToolStats {
    uint16_t hits      = 0;
    uint16_t high_conf = 0;   /* confidence >= 70 */
    uint16_t tracked   = 0;   /* devices under observation */
    uint8_t  mode      = TD_MODE_WIFI;
    uint8_t  channel   = 1;
    bool     hopping   = true;
    bool     running   = false;
    bool     ble_error = false;
};

class ToolDetect {
public:
    /* Sized against a real survey: 41 BSSIDs in one room, plus every station
     * seen in a data frame. The old 40 overflowed constantly, evicting devices
     * before they accumulated evidence. Tables live in PSRAM. */
    static constexpr int MAX_HITS  = 64;
    static constexpr int MAX_TRACK = 192;
    /* A legitimate AP can carry a couple of SSIDs per radio; this many from one
     * BSSID is Karma/Pineapple territory. */
    static constexpr int MULTISSID_THRESHOLD = 5;

    bool begin(uint8_t mode);
    void stop();
    void loop();
    bool running() const { return _running; }

    const ToolStats& stats() const { return _stats; }
    int  list(ToolHit* out, int max) const;   /* highest confidence first */
    void set_channel(uint8_t channel);        /* 0 = resume hopping, WiFi mode */

private:
    bool      _running    = false;
    bool      _ble_inited = false;   /* we brought Bluedroid up ourselves */
    uint32_t  _last_hop   = 0;
    uint32_t  _last_tick = 0;
    ToolStats _stats;

    void _hop();
    bool _begin_wifi();
    bool _begin_ble();
};
