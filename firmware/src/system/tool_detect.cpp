/**
 * @file tool_detect.cpp
 * @brief See tool_detect.h.
 */
#include "tool_detect.h"
#include "mk_crumb.h"
#include <Arduino.h>
#include <esp_wifi.h>
#include <BLEDevice.h>
#include <cstring>
#include "mk_psram_buf.h"
#include <cstdio>
#include "mk_psram_buf.h"

namespace {

/* ── tracked device table ────────────────────────────────────────────── */
struct Track {
    uint8_t  mac[6];
    uint8_t  radio;
    uint8_t  kind;
    int8_t   rssi;
    uint8_t  channel;
    char     label[33];
    uint16_t ad_mask;          /* BLE: which AD types the advert carried */
    uint16_t mfg_id;           /* BLE: manufacturer company id           */
    uint16_t uuid16;           /* BLE: first 16-bit service UUID         */
    char     ssids[4][33];     /* distinct SSIDs seen from this BSSID */
    uint8_t  n_ssids;
    uint16_t ssid_count;       /* may exceed the 4 we keep names for */
    uint16_t count;
    uint32_t evidence;
    uint32_t first_ms;
    uint32_t last_ms;
    bool     used;
};

/* In PSRAM, not internal .bss: raising these caps in internal RAM starved the
 * Bluetooth controller once already. pcap_capture's ring is PSRAM and is
 * written from the same promiscuous critical sections, so the pattern is
 * proven on this hardware. */
static Track*        s_tr = nullptr;
static bool ensure_tracks()
{
    static void* slot = nullptr;
    if (!s_tr) s_tr = (Track*)mk_psram_buf(&slot, sizeof(Track) * ToolDetect::MAX_TRACK);
    return s_tr != nullptr;
}
static portMUX_TYPE  s_mux = portMUX_INITIALIZER_UNLOCKED;
static volatile bool s_ble_err = false;

/* ── helpers ─────────────────────────────────────────────────────────── */

static bool ieq(const char* a, const char* b)          /* case-insensitive == */
{
    while (*a && *b) {
        char ca = *a >= 'A' && *a <= 'Z' ? (char)(*a + 32) : *a;
        char cb = *b >= 'A' && *b <= 'Z' ? (char)(*b + 32) : *b;
        if (ca != cb) return false;
        a++; b++;
    }
    return *a == *b;
}

static bool icontains(const char* hay, const char* needle)
{
    for (int i = 0; hay[i]; i++) {
        int k = 0;
        while (needle[k]) {
            char ch = hay[i + k], cn = needle[k];
            if (!ch) return false;
            if (ch >= 'A' && ch <= 'Z') ch = (char)(ch + 32);
            if (cn >= 'A' && cn <= 'Z') cn = (char)(cn + 32);
            if (ch != cn) break;
            k++;
        }
        if (!needle[k]) return true;
    }
    return false;
}

/* Espressif and M5Stack prefixes. Corroborating evidence ONLY — this device
 * matches them too. */
static bool known_tool_oui(const uint8_t* m)
{
    static const uint8_t OUI[][3] = {
        {0x24,0x0A,0xC4},{0x30,0xAE,0xA4},{0x3C,0x71,0xBF},{0x7C,0xDF,0xA1},
        {0x84,0x0D,0x8E},{0x8C,0xAA,0xB5},{0xA4,0xCF,0x12},{0xB4,0xE6,0x2D},
        {0xBC,0xDD,0xC2},{0xC4,0x4F,0x33},{0xCC,0x50,0xE3},{0xD8,0xA0,0x1D},
        {0xDC,0x4F,0x22},{0xE8,0xDB,0x84},{0xEC,0xFA,0xBC},{0xF0,0x08,0xD1},
        {0x4C,0x75,0x25},{0x58,0xBF,0x25},{0x0C,0xB8,0x15},{0x34,0x85,0x18},
    };
    for (unsigned i = 0; i < sizeof(OUI) / sizeof(OUI[0]); i++)
        if (!memcmp(m, OUI[i], 3)) return true;
    return false;
}

/* Name signatures. Returns the kind, or TD_UNKNOWN. */
static uint8_t kind_from_name(const char* n)
{
    if (!n || !n[0]) return TD_UNKNOWN;
    if (icontains(n, "flipper"))                      return TD_FLIPPER;
    if (icontains(n, "marauder"))                     return TD_MARAUDER;
    if (icontains(n, "bruce"))                        return TD_BRUCE;
    if (icontains(n, "pwnagotchi"))                   return TD_PWNAGOTCHI;
    if (icontains(n, "deauth") || ieq(n, "pwned"))    return TD_DEAUTHER;
    if (icontains(n, "pineapple") || icontains(n, "wifipineapple")) return TD_PINEAPPLE;
    /* ESP8266 Deauther's stock APs */
    if (ieq(n, "esp8266") || ieq(n, "deauther"))      return TD_DEAUTHER;
    return TD_UNKNOWN;
}

/* SSIDs that ESP32 attack firmwares use by default. On their own these are
 * worthless — a cafe really does call its network "Free WiFi" — so they count
 * only alongside the SoftAP rate signature, i.e. an open network that is also
 * demonstrably not a commercial AP. Taken from the tools' own sources:
 * Bruce uses "Free Wifi" as its evil-portal default (evil_portal.cpp) and
 * "BruceAttack"/"BruceBeacon" for its attack APs (wifi_atks.cpp). */
static bool default_tool_ssid(const char* n)
{
    if (!n || !n[0]) return false;
    static const char* const NAMES[] = {
        "free wifi", "free wi-fi", "freewifi",
        "bruceattack", "brucebeacon",
        "esp32-ap", "esp_ap", "airport free wifi", "free public wifi",
    };
    for (unsigned i = 0; i < sizeof(NAMES) / sizeof(NAMES[0]); i++)
        if (ieq(n, NAMES[i])) return true;
    return false;
}

/* Pwnagotchi advertises by stuffing a JSON blob into the SSID field. */
static bool looks_like_json(const char* s)
{
    return s && s[0] == '{' && (s[1] == '"' || s[1] == '\'');
}

/* Callers may be inside portENTER_CRITICAL_ISR (the promiscuous path) where
 * heap_caps_malloc is not callable, so this must never allocate: begin()
 * warms the table up front and a missing table here is simply "no room". */
static Track* track_for(const uint8_t* mac, uint8_t radio, uint32_t now)
{
    if (!s_tr) return nullptr;
    for (int i = 0; i < ToolDetect::MAX_TRACK; i++)
        if (s_tr[i].used && s_tr[i].radio == radio && !memcmp(s_tr[i].mac, mac, 6))
            return &s_tr[i];
    for (int i = 0; i < ToolDetect::MAX_TRACK; i++)
        if (!s_tr[i].used) {
            Track* t = &s_tr[i];
            *t = Track{};
            t->used = true;
            memcpy(t->mac, mac, 6);
            t->radio = radio;
            t->first_ms = now;
            return t;
        }
    /* full: evict the stalest with no evidence, else the stalest */
    Track* victim = nullptr;
    for (int i = 0; i < ToolDetect::MAX_TRACK; i++) {
        Track* t = &s_tr[i];
        if (!victim) { victim = t; continue; }
        const bool t_weak = t->evidence == 0, v_weak = victim->evidence == 0;
        if (t_weak && !v_weak) victim = t;
        else if (t_weak == v_weak && (int32_t)(t->last_ms - victim->last_ms) < 0) victim = t;
    }
    if (!victim) return nullptr;
    *victim = Track{};
    victim->used = true;
    memcpy(victim->mac, mac, 6);
    victim->radio = radio;
    victim->first_ms = now;
    return victim;
}

static void note_ssid(Track* t, const char* ssid)
{
    if (!ssid || !ssid[0]) return;
    for (int i = 0; i < t->n_ssids; i++)
        if (!strcmp(t->ssids[i], ssid)) return;
    if (t->n_ssids < 4) {
        snprintf(t->ssids[t->n_ssids], 33, "%s", ssid);
        t->n_ssids++;
    }
    if (t->ssid_count < 0xFFFF) t->ssid_count++;
    if (t->ssid_count >= ToolDetect::MULTISSID_THRESHOLD)
        t->evidence |= TD_EV_MULTISSID;
}

/* ── WiFi promiscuous ────────────────────────────────────────────────── */

void promisc_cb(void* buf, wifi_promiscuous_pkt_type_t type)
{
    (void)type;
    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    const uint8_t* fr = pkt->payload;
    const int len = pkt->rx_ctrl.sig_len;
    if (len < 24) return;

    const uint8_t ftype = (fr[0] >> 2) & 0x3;
    const uint8_t fsub  = (fr[0] >> 4) & 0xF;
    const uint32_t now  = millis();

    portENTER_CRITICAL_ISR(&s_mux);

    /* deauth / disassoc from addr2 = an actively attacking station */
    if (ftype == 0 && (fsub == 12 || fsub == 10)) {
        Track* t = track_for(fr + 10, TD_MODE_WIFI, now);
        if (t) {
            t->evidence |= TD_EV_DEAUTH_TX;
            if (t->kind == TD_UNKNOWN) t->kind = TD_DEAUTHER;
            t->rssi = (int8_t)pkt->rx_ctrl.rssi;
            t->channel = (uint8_t)pkt->rx_ctrl.channel;
            if (t->count < 0xFFFF) t->count++;
            t->last_ms = now;
            if (known_tool_oui(fr + 10)) t->evidence |= TD_EV_OUI;
        }
        portEXIT_CRITICAL_ISR(&s_mux);
        return;
    }

    /* beacon / probe-response: read the SSID and judge the name */
    if (ftype == 0 && (fsub == 8 || fsub == 5) && len >= 38) {
        char ssid[33] = {0};
        bool unordered = false, have_rsn = false;
        /* capability bits sit at offset 34; bit 4 is Privacy */
        const bool privacy = (len >= 36) && ((fr[34] | (fr[35] << 8)) & 0x0010);
        int p = 36;
        while (p + 2 <= len) {
            const uint8_t tag = fr[p], tl = fr[p + 1];
            if (p + 2 + tl > len) break;
            const uint8_t* v = fr + p + 2;
            if (tag == 0 && !ssid[0]) {
                int n = tl > 32 ? 32 : tl;
                memcpy(ssid, v, n);
                ssid[n] = '\0';
            } else if (tag == 1 && tl > 0) {
                /* First basic rate is not 1 Mbit/s (0x82 masked to 2). See the
                 * note in wifi_audit.cpp: an ordering test flags 21 of 27 real
                 * APs; this flags one, and it is the rogue. */
                if ((v[0] & 0x7F) != 2) unordered = true;
            } else if (tag == 48) {
                have_rsn = true;
            }
            p += 2 + tl;
        }
        const bool open_net = !have_rsn && !privacy;

        Track* t = track_for(fr + 10, TD_MODE_WIFI, now);
        if (t) {
            t->evidence |= TD_EV_BEACON_TX;
            t->rssi    = (int8_t)pkt->rx_ctrl.rssi;
            t->channel = (uint8_t)pkt->rx_ctrl.channel;
            if (t->count < 0xFFFF) t->count++;
            t->last_ms = now;
            if (known_tool_oui(fr + 10)) t->evidence |= TD_EV_OUI;

            note_ssid(t, ssid);
            if (!t->label[0] && ssid[0]) snprintf(t->label, sizeof(t->label), "%s", ssid);

            if (looks_like_json(ssid)) {
                t->evidence |= TD_EV_JSON_SSID;
                t->kind = TD_PWNAGOTCHI;
            } else {
                const uint8_t k = kind_from_name(ssid);
                if (k != TD_UNKNOWN) { t->kind = k; t->evidence |= TD_EV_NAME; }
            }
            /* An OPEN network whose rate list is not ascending is a software
             * AP pretending to be a hotspot — the shape of a rogue portal.
             * Only together: an ESP32 IoT device with WPA2 is unremarkable,
             * and plenty of legitimate hotspots are open. */
            if (open_net && unordered) {
                t->evidence |= TD_EV_SOFTAP;
                if (t->kind == TD_UNKNOWN) t->kind = TD_ESP_TOOL;
                /* A tool's stock portal name on top of that is a strong tell,
                 * but only on top of it — never on the name alone. */
                if (default_tool_ssid(ssid)) {
                    t->evidence |= TD_EV_NAME;
                    if (t->kind == TD_ESP_TOOL) t->kind = TD_BRUCE;
                }
            }
            if ((t->evidence & TD_EV_MULTISSID) && t->kind == TD_UNKNOWN)
                t->kind = TD_PINEAPPLE;
        }
    }
    portEXIT_CRITICAL_ISR(&s_mux);
}

/* ── BLE scan ────────────────────────────────────────────────────────── */

/* Walk the AD structures for a local name (0x08/0x09), 128-bit service UUIDs
 * (0x06/0x07) and manufacturer data (0xFF). */
/* Map an AD type onto a bit, so a hit can report what the advertisement
 * actually contained. Guessing at another device's advertising layout from
 * memory does not work — the first Flipper we saw matched on its name alone
 * because the UUID compare below was written in the wrong byte order and
 * could never have fired. Report the structure; match on facts. */
static uint16_t ad_bit(uint8_t t)
{
    switch (t) {
        case 0x01: return 1u << 0;   /* flags                  */
        case 0x02: case 0x03: return 1u << 1;   /* 16-bit UUIDs  */
        case 0x04: case 0x05: return 1u << 2;   /* 32-bit UUIDs  */
        case 0x06: case 0x07: return 1u << 3;   /* 128-bit UUIDs */
        case 0x08: case 0x09: return 1u << 4;   /* local name    */
        case 0x0A: return 1u << 5;   /* tx power               */
        case 0x16: return 1u << 6;   /* service data, 16-bit   */
        case 0x20: case 0x21: return 1u << 7;   /* service data, 32/128  */
        case 0xFF: return 1u << 8;   /* manufacturer specific  */
        default:   return 1u << 15;  /* something else         */
    }
}

static void parse_adv(const uint8_t* d, int len, char* name, int name_n,
                      bool* svc_flipper, uint16_t* mfg,
                      uint16_t* ad_mask, uint16_t* uuid16)
{
    name[0] = '\0';
    *svc_flipper = false;
    *mfg = 0;
    *ad_mask = 0;
    *uuid16 = 0;
    int i = 0;
    while (i + 1 < len) {
        const uint8_t l = d[i];
        if (l == 0 || i + 1 + l > len) break;
        const uint8_t t = d[i + 1];
        const uint8_t* v = d + i + 2;
        const int vl = l - 1;
        *ad_mask |= ad_bit(t);

        if ((t == 0x08 || t == 0x09) && vl > 0) {
            int n = vl < name_n - 1 ? vl : name_n - 1;
            memcpy(name, v, n);
            name[n] = '\0';
        } else if ((t == 0x02 || t == 0x03) && vl >= 2) {
            if (!*uuid16) *uuid16 = (uint16_t)(v[0] | (v[1] << 8));
        } else if ((t == 0x06 || t == 0x07) && vl >= 16) {
            /* Flipper Zero's serial service is 8fe5b3d5-2e7f-4a98-2a48-7acc60fe...
             * A 128-bit UUID goes out least-significant-byte first, so the
             * display order is reversed on the wire. Check both orders rather
             * than assume: some stacks get this wrong too. */
            static const uint8_t FWD[] = {0x2e,0x7f,0x4a,0x98,0x2a,0x48};
            static const uint8_t REV[] = {0x48,0x2a,0x98,0x4a,0x7f,0x2e};
            for (int k = 0; k + 6 <= vl; k++)
                if (!memcmp(v + k, FWD, 6) || !memcmp(v + k, REV, 6)) {
                    *svc_flipper = true;
                    break;
                }
        } else if (t == 0xFF && vl >= 2) {
            *mfg = (uint16_t)(v[0] | (v[1] << 8));
        }
        i += 1 + l;
    }
}

void gap_cb(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t* p)
{
    if (event == ESP_GAP_BLE_SCAN_PARAM_SET_COMPLETE_EVT) {
        mk_crumb_set(MKC_TD_GAP_PARAM_CPL);
        if (esp_ble_gap_start_scanning(0) != ESP_OK) s_ble_err = true;
        mk_crumb_set(MKC_TD_GAP_START_CPL);
        return;
    }
    if (event == ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT) {
        mk_crumb_set(MKC_TD_GAP_STOP_CPL);
        return;
    }
    if (event != ESP_GAP_BLE_SCAN_RESULT_EVT) return;
    if (p->scan_rst.search_evt != ESP_GAP_SEARCH_INQ_RES_EVT) return;
    mk_crumb_set(MKC_TD_GAP_RESULT);

    char name[33];
    bool svc = false;
    uint16_t mfg = 0, admask = 0, uuid16 = 0;
    mk_crumb_set(MKC_TD_GAP_PARSE);
    parse_adv(p->scan_rst.ble_adv, p->scan_rst.adv_data_len + p->scan_rst.scan_rsp_len,
              name, sizeof(name), &svc, &mfg, &admask, &uuid16);

    const uint8_t k = kind_from_name(name);
    /* Only record something we have a reason to record. */
    if (k == TD_UNKNOWN && !svc) return;

    const uint32_t now = millis();
    mk_crumb_set(MKC_TD_GAP_TRACK);
    portENTER_CRITICAL(&s_mux);
    Track* t = track_for(p->scan_rst.bda, TD_MODE_BLE, now);
    if (t) {
        t->rssi = (int8_t)p->scan_rst.rssi;
        if (t->count < 0xFFFF) t->count++;
        t->last_ms = now;
        if (name[0] && !t->label[0]) snprintf(t->label, sizeof(t->label), "%s", name);
        if (k != TD_UNKNOWN) { t->kind = k; t->evidence |= TD_EV_NAME; }
        if (svc)             { t->kind = TD_FLIPPER; t->evidence |= TD_EV_SVC_UUID; }
        if (mfg)               t->evidence |= TD_EV_MFG;
        t->ad_mask = admask;
        t->mfg_id  = mfg;
        t->uuid16  = uuid16;
    }
    portEXIT_CRITICAL(&s_mux);
}

static esp_ble_scan_params_t s_scan_params = [] {
    esp_ble_scan_params_t s{};
    s.scan_type          = BLE_SCAN_TYPE_PASSIVE;
    s.own_addr_type      = BLE_ADDR_TYPE_PUBLIC;
    s.scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL;
    s.scan_interval      = 0x50;
    s.scan_window        = 0x50;
    s.scan_duplicate     = BLE_SCAN_DUPLICATE_DISABLE;
    return s;
}();

/* Confidence from how many independent signals agree. OUI alone is worth
 * nothing on its own and cannot raise a hit. */
static uint8_t confidence_of(const Track* t)
{
    uint8_t c = 0;
    if (t->evidence & TD_EV_DEAUTH_TX) c += 60;   /* actively attacking */
    if (t->evidence & TD_EV_MULTISSID) c += 50;   /* Karma behaviour    */
    if (t->evidence & TD_EV_JSON_SSID) c += 55;
    if (t->evidence & TD_EV_SVC_UUID)  c += 50;
    if (t->evidence & TD_EV_NAME)      c += 30;
    if (t->evidence & TD_EV_OUI)       c += 10;   /* corroboration only */
    if (t->evidence & TD_EV_SOFTAP)    c += 45;   /* open + non-standard rates */
    if (t->evidence & TD_EV_MFG)       c += 5;
    if (t->count > 5)                  c += 5;
    return c > 100 ? 100 : c;
}

static bool reportable(const Track* t)
{
    /* Behaviour or a name. Never OUI/beaconing alone. */
    return (t->evidence & (TD_EV_NAME | TD_EV_MULTISSID | TD_EV_DEAUTH_TX |
                           TD_EV_JSON_SSID | TD_EV_SVC_UUID | TD_EV_SOFTAP)) != 0;
}

} // namespace

/* ── lifecycle ───────────────────────────────────────────────────────── */

bool ToolDetect::_begin_wifi()
{
    mk_crumb_set(MKC_TD_WIFI_BEGIN);
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(&promisc_cb);
    if (esp_wifi_set_promiscuous(true) != ESP_OK) return false;
    esp_wifi_set_channel(_stats.channel, WIFI_SECOND_CHAN_NONE);
    return true;
}

bool ToolDetect::_begin_ble()
{
    s_ble_err = false;

    /* Same lifecycle TrackerMonitor uses, which is the one proven to work from
     * an SD app: tear the stack fully down, let it settle, then bring it up
     * fresh. Reusing an already-initialised Bluedroid across a mode toggle —
     * which is what "init only if not initialised" did here — leaves a stale
     * GAP registration behind and hard-resets the device. */
    mk_crumb_set(MKC_TD_BLE_DEINIT);
    BLEDevice::deinit(false);
    mk_crumb_set(MKC_TD_BLE_SETTLE);
    delay(50);
    mk_crumb_set(MKC_TD_BLE_INIT);
    BLEDevice::init("");
    _ble_inited = BLEDevice::getInitialized();
    if (!_ble_inited) { s_ble_err = true; return false; }

    mk_crumb_set(MKC_TD_BLE_REGCB);
    if (esp_ble_gap_register_callback(&gap_cb) != ESP_OK) { s_ble_err = true; return false; }
    mk_crumb_set(MKC_TD_BLE_SCANPARAMS);
    if (esp_ble_gap_set_scan_params(&s_scan_params) != ESP_OK) { s_ble_err = true; return false; }
    mk_crumb_set(MKC_TD_BLE_READY);
    return true;    /* scanning starts on the param-set-complete event */
}

bool ToolDetect::begin(uint8_t mode)
{
    mk_crumb_set(MKC_TD_BEGIN);
    stop();                          /* release whichever radio the last mode held */
    mk_crumb_set(MKC_TD_TRACKS);
    if (!ensure_tracks()) return false;

    portENTER_CRITICAL(&s_mux);
    if (s_tr) for (int i = 0; i < MAX_TRACK; i++) s_tr[i] = Track{};
    portEXIT_CRITICAL(&s_mux);

    _stats = ToolStats{};
    _stats.mode    = (mode == TD_MODE_BLE) ? TD_MODE_BLE : TD_MODE_WIFI;
    _stats.channel = 1;
    _stats.hopping = _stats.mode == TD_MODE_WIFI;
    _last_hop = _last_tick = millis();

    const bool ok = (_stats.mode == TD_MODE_WIFI) ? _begin_wifi() : _begin_ble();
    _running = ok;
    _stats.running = ok;
    return ok;
}

void ToolDetect::stop()
{
    /* Always clear the WiFi side — leaving promiscuous claimed after a BLE
     * session was the bug that needed a reboot to cure.
     *
     * But only touch BLE if the stack is actually up. Calling Bluedroid GAP
     * functions against an uninitialised controller panics the device, which
     * is exactly what an unconditional teardown did here: in WiFi mode
     * BLEDevice::init() has never run, so esp_ble_gap_* is not safe to call.
     * There is also no way to deregister a GAP callback — passing nullptr is
     * not valid; _begin_ble() simply replaces it. */
    mk_crumb_set(MKC_TD_STOP_ENTER);
    if (_ble_inited) {
        mk_crumb_set(MKC_TD_STOP_SCAN_STOP);
        esp_ble_gap_stop_scanning();
        mk_crumb_set(MKC_TD_STOP_BLE_DEINIT);
        BLEDevice::deinit(false);     /* actually release the stack */
        _ble_inited = false;
    }
    mk_crumb_set(MKC_TD_STOP_PROMISC);
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);

    _running = false;
    _stats.running = false;
    mk_crumb_set(MKC_TD_STOP_DONE);
}

void ToolDetect::set_channel(uint8_t channel)
{
    if (_stats.mode != TD_MODE_WIFI) return;
    if (channel == 0) { _stats.hopping = true; return; }
    if (channel > 14) return;
    _stats.hopping = false;
    _stats.channel = channel;
    if (_running) esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

void ToolDetect::_hop()
{
    uint8_t ch = _stats.channel + 1;
    if (ch > 13) ch = 1;
    _stats.channel = ch;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

void ToolDetect::loop()
{
    if (!_running || !s_tr) return;
    const uint32_t now = millis();

    if (_stats.mode == TD_MODE_WIFI && _stats.hopping && now - _last_hop >= 400) {
        _last_hop = now;
        _hop();
    }

    if (now - _last_tick >= 1000) {
        _last_tick = now;
        uint16_t hits = 0, high = 0, tracked = 0;
        portENTER_CRITICAL(&s_mux);
        for (int i = 0; i < MAX_TRACK; i++) {
            if (!s_tr[i].used) continue;
            tracked++;
            if (!reportable(&s_tr[i])) continue;
            hits++;
            if (confidence_of(&s_tr[i]) >= 70) high++;
        }
        portEXIT_CRITICAL(&s_mux);
        _stats.hits      = hits;
        _stats.high_conf = high;
        _stats.tracked   = tracked;
        _stats.ble_error = s_ble_err;
    }
}

int ToolDetect::list(ToolHit* out, int max) const
{
    if (!out || max <= 0 || !s_tr) return 0;

    static void* s_tdl_buf = nullptr;
    ToolHit* tmp = (ToolHit*)mk_psram_buf(&s_tdl_buf, sizeof(ToolHit) * (MAX_TRACK));
    if (!tmp) return 0;
    int n = 0;
    portENTER_CRITICAL(&s_mux);
    for (int i = 0; i < MAX_TRACK && n < MAX_TRACK; i++) {
        const Track* t = &s_tr[i];
        if (!t->used || !reportable(t)) continue;
        ToolHit& h = tmp[n++];
        memset(&h, 0, sizeof(h));
        memcpy(h.mac, t->mac, 6);
        h.kind       = t->kind;
        h.radio      = t->radio;
        h.confidence = confidence_of(t);
        h.rssi       = t->rssi;
        h.channel    = t->channel;
        snprintf(h.label, sizeof(h.label), "%s", t->label);
        h.ssid_count = t->ssid_count;
        h.count      = t->count;
        h.ad_mask    = t->ad_mask;
        h.mfg_id     = t->mfg_id;
        h.uuid16     = t->uuid16;
        h.evidence   = t->evidence;
        h.first_ms   = t->first_ms;
        h.last_ms    = t->last_ms;
    }
    portEXIT_CRITICAL(&s_mux);

    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (tmp[j].confidence > tmp[i].confidence ||
                (tmp[j].confidence == tmp[i].confidence && tmp[j].rssi > tmp[i].rssi)) {
                ToolHit t = tmp[i]; tmp[i] = tmp[j]; tmp[j] = t;
            }

    if (n > max) n = max;
    for (int i = 0; i < n; i++) out[i] = tmp[i];
    return n;
}
