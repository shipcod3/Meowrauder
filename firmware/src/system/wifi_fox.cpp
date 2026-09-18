/**
 * @file wifi_fox.cpp
 * @brief See wifi_fox.h.
 */
#include "wifi_fox.h"
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <cstring>
#include "mk_psram_buf.h"
#include "mk_psram_buf.h"

namespace {

/* ── target table, written from the WiFi task ─────────────────────────── */
struct Slot {
    FoxTarget t{};
    int8_t    samples[WifiFox::SAMPLES]{};
    uint8_t   nsamples = 0;
    int32_t   filtered_q8 = 0;
    bool      used = false;
};

/* In PSRAM, not internal .bss: raising these caps in internal RAM starved the
 * Bluetooth controller once already. pcap_capture's ring is PSRAM and is
 * written from the same promiscuous critical sections, so the pattern is
 * proven on this hardware. */
static Slot*         s_slots = nullptr;
static bool ensure_slots()
{
    static void* slot = nullptr;
    if (!s_slots) s_slots = (Slot*)mk_psram_buf(&slot, sizeof(Slot) * WifiFox::MAX_TARGETS);
    return s_slots != nullptr;
}
static uint32_t      s_next_id = 1;
static portMUX_TYPE  s_mux = portMUX_INITIALIZER_UNLOCKED;

static bool mac_eq(const uint8_t* a, const uint8_t* b) { return memcmp(a, b, 6) == 0; }

static bool mac_meaningful(const uint8_t* m)
{
    /* skip broadcast and the all-zero address */
    static const uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    if (mac_eq(m, bcast)) return false;
    for (int i = 0; i < 6; i++) if (m[i]) return true;
    return false;
}

/* Find or allocate a slot; evicts the weakest/stalest when full. */
static Slot* slot_for(const uint8_t* mac, uint32_t now)
{
    if (!s_slots) return nullptr;      /* never allocate from a callback path */
    for (int i = 0; i < WifiFox::MAX_TARGETS; i++)
        if (s_slots[i].used && mac_eq(s_slots[i].t.mac, mac)) return &s_slots[i];

    for (int i = 0; i < WifiFox::MAX_TARGETS; i++)
        if (!s_slots[i].used) {
            Slot* s = &s_slots[i];
            *s = Slot{};
            s->used = true;
            memcpy(s->t.mac, mac, 6);
            s->t.id       = s_next_id++;
            if (s_next_id == 0) s_next_id = 1;
            s->t.first_ms = now;
            s->t.filtered_rssi = -127;
            return s;
        }

    /* full: drop the oldest-seen entry that is not the current pick */
    Slot* oldest = nullptr;
    for (int i = 0; i < WifiFox::MAX_TARGETS; i++) {
        Slot* s = &s_slots[i];
        if (!oldest || (int32_t)(s->t.last_ms - oldest->t.last_ms) < 0) oldest = s;
    }
    if (!oldest) return nullptr;
    uint32_t keep_id = oldest->t.id;
    (void)keep_id;
    *oldest = Slot{};
    oldest->used = true;
    memcpy(oldest->t.mac, mac, 6);
    oldest->t.id       = s_next_id++;
    if (s_next_id == 0) s_next_id = 1;
    oldest->t.first_ms = now;
    oldest->t.filtered_rssi = -127;
    return oldest;
}

/* Same median+EWMA shape as the BLE tracker store, so both radios agree. */
static void record(const uint8_t* mac, uint8_t kind, const char* ssid,
                   int8_t rssi, uint8_t channel, uint32_t now)
{
    if (!mac_meaningful(mac)) return;
    Slot* s = slot_for(mac, now);
    if (!s) return;

    if (s->nsamples < WifiFox::SAMPLES) s->samples[s->nsamples++] = rssi;
    else {
        for (int i = 1; i < WifiFox::SAMPLES; i++) s->samples[i - 1] = s->samples[i];
        s->samples[WifiFox::SAMPLES - 1] = rssi;
    }
    int8_t sorted[WifiFox::SAMPLES];
    for (uint8_t i = 0; i < s->nsamples; i++) {
        int8_t v = s->samples[i]; int j = i;
        while (j && sorted[j - 1] > v) { sorted[j] = sorted[j - 1]; --j; }
        sorted[j] = v;
    }
    const int32_t median_q8 = (int32_t)sorted[s->nsamples / 2] * 256;
    if (s->t.count == 0) s->filtered_q8 = median_q8;
    else                 s->filtered_q8 += (median_q8 - s->filtered_q8) / 4;

    s->t.filtered_rssi = (int16_t)(s->filtered_q8 / 256);
    s->t.rssi    = rssi;
    s->t.channel = channel;
    /* An AP sighting upgrades a slot first seen as a station. */
    if (kind == FOX_KIND_AP) s->t.kind = FOX_KIND_AP;
    if (ssid && ssid[0] && !s->t.ssid[0])
        snprintf(s->t.ssid, sizeof(s->t.ssid), "%s", ssid);
    if (s->t.count < UINT16_MAX) s->t.count++;
    if (++s->t.sequence == 0) s->t.sequence = 1;
    s->t.last_ms    = now;
    s->t.scan_fresh = true;
}

void promisc_cb(void* buf, wifi_promiscuous_pkt_type_t type)
{
    (void)type;
    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    const uint8_t* fr = pkt->payload;
    if (pkt->rx_ctrl.sig_len < 24) return;

    const uint8_t ftype = (fr[0] >> 2) & 0x3;
    const uint8_t fsub  = (fr[0] >> 4) & 0xF;
    const int8_t  rssi  = (int8_t)pkt->rx_ctrl.rssi;
    const uint8_t ch    = (uint8_t)pkt->rx_ctrl.channel;
    const uint32_t now  = millis();

    portENTER_CRITICAL_ISR(&s_mux);
    if (ftype == 0 && (fsub == 8 /*beacon*/ || fsub == 5 /*probe resp*/)) {
        /* addr2 = BSSID; tagged params start at 36 (12 B fixed after the header) */
        char ssid[33] = {0};
        const int len = pkt->rx_ctrl.sig_len;
        int p = 36;
        while (p + 2 <= len) {
            const uint8_t tag = fr[p], tlen = fr[p + 1];
            if (p + 2 + tlen > len) break;
            if (tag == 0) {                                  /* SSID */
                int n = tlen > 32 ? 32 : tlen;
                memcpy(ssid, fr + p + 2, n);
                ssid[n] = '\0';
                break;
            }
            p += 2 + tlen;
        }
        record(fr + 10, FOX_KIND_AP, ssid, rssi, ch, now);
    } else if (ftype == 2 || (ftype == 0 && fsub == 4 /*probe req*/)) {
        record(fr + 10, FOX_KIND_STA, nullptr, rssi, ch, now);
    }
    portEXIT_CRITICAL_ISR(&s_mux);
}

/* Project a FoxTarget onto the finder's input type so TrackerFinder can drive
 * it. Only the fields the finder reads are meaningful here. */
static TrackerEntry as_entry(const FoxTarget& t)
{
    TrackerEntry e{};
    memcpy(e.mac, t.mac, 6);
    e.type          = t.kind;
    e.rssi          = t.rssi;
    e.count         = t.count;
    e.first_ms      = t.first_ms;
    e.last_ms       = t.last_ms;
    e.id            = t.id;
    e.sequence      = t.sequence;
    e.filtered_rssi = t.filtered_rssi;
    e.scan_fresh    = t.scan_fresh;
    return e;
}

} // namespace

/* ── lifecycle ───────────────────────────────────────────────────────── */

void WifiFox::begin()
{
    ensure_slots();
    portENTER_CRITICAL(&s_mux);
    if (s_slots) for (int i = 0; i < MAX_TARGETS; i++) s_slots[i] = Slot{};
    s_next_id = 1;
    portEXIT_CRITICAL(&s_mux);

    _stats = FoxStats{};
    _stats.running = true;
    _stats.hopping = true;
    _stats.channel = 1;
    _sel = 0;
    _finder.reset();
    _running  = true;
    _last_hop = millis();

    /* A SoftAP (Evil Twin) or a half-torn-down BLE session can leave the radio
     * in a state where promiscuous mode is refused. Put WiFi back to station
     * mode first so a capture does not fail for a reason nobody can see. */
    WiFi.mode(WIFI_STA);
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(&promisc_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(_stats.channel, WIFI_SECOND_CHAN_NONE);
}

void WifiFox::stop()
{
    _running = false;
    _stats.running = false;
    _sel = 0;
    _finder.reset();
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
}

void WifiFox::pause()
{
    if (!_running) return;
    _running = false;
    _stats.running = false;
    esp_wifi_set_promiscuous(false);
    portENTER_CRITICAL(&s_mux);
    for (int i = 0; i < MAX_TARGETS; i++)
        if (s_slots[i].used) s_slots[i].t.scan_fresh = false;
    portEXIT_CRITICAL(&s_mux);
}

void WifiFox::resume()
{
    if (_running) return;
    _running = true;
    _stats.running = true;
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(_stats.channel, WIFI_SECOND_CHAN_NONE);
}

void WifiFox::set_channel(uint8_t channel)
{
    if (channel == 0) { _stats.hopping = true; return; }
    if (channel > 14) return;
    _stats.hopping = false;
    _stats.channel = channel;
    if (_running) esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

void WifiFox::_hop()
{
    uint8_t ch = _stats.channel + 1;
    if (ch > 13) ch = 1;
    _stats.channel = ch;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

void WifiFox::loop()
{
    const uint32_t now = millis();

    if (_running && _stats.hopping && now - _last_hop >= 300) { _last_hop = now; _hop(); }

    /* recount + push the selected target's newest sample into the finder */
    uint16_t aps = 0, stas = 0, n = 0;
    FoxTarget sel{};
    bool have_sel = false;

    portENTER_CRITICAL(&s_mux);
    for (int i = 0; i < MAX_TARGETS; i++) {
        if (!s_slots[i].used) continue;
        n++;
        if (s_slots[i].t.kind == FOX_KIND_AP) aps++; else stas++;
        if (_sel && s_slots[i].t.id == _sel) { sel = s_slots[i].t; have_sel = true; }
    }
    portEXIT_CRITICAL(&s_mux);

    _stats.targets  = n;
    _stats.aps      = aps;
    _stats.stations = stas;

    if (_sel) {
        const TrackerEntry e = have_sel ? as_entry(sel) : TrackerEntry{};
        _finder.update(have_sel ? &e : nullptr, now, _running);
    }
}

/* ── queries ─────────────────────────────────────────────────────────── */

int WifiFox::list(FoxTarget* out, int max) const
{
    if (!out || max <= 0 || !s_slots) return 0;
    static void* s_foxl_buf = nullptr;
    FoxTarget* snap = (FoxTarget*)mk_psram_buf(&s_foxl_buf, sizeof(FoxTarget) * (MAX_TARGETS));
    if (!snap) return 0;
    int n = 0;

    portENTER_CRITICAL(&s_mux);
    for (int i = 0; i < MAX_TARGETS; i++)
        if (s_slots[i].used) snap[n++] = s_slots[i].t;
    portEXIT_CRITICAL(&s_mux);

    /* strongest filtered RSSI first; id breaks ties so order is stable */
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (snap[j].filtered_rssi > snap[i].filtered_rssi ||
                (snap[j].filtered_rssi == snap[i].filtered_rssi && snap[j].id < snap[i].id)) {
                FoxTarget t = snap[i]; snap[i] = snap[j]; snap[j] = t;
            }

    if (n > max) n = max;
    for (int i = 0; i < n; i++) out[i] = snap[i];
    return n;
}

int WifiFox::select(uint32_t id)
{
    if (id == 0) { _sel = 0; _finder.reset(); return 1; }

    FoxTarget found{};
    bool ok = false;
    portENTER_CRITICAL(&s_mux);
    for (int i = 0; i < MAX_TARGETS; i++)
        if (s_slots[i].used && s_slots[i].t.id == id) { found = s_slots[i].t; ok = true; break; }
    portEXIT_CRITICAL(&s_mux);
    if (!ok) return 0;

    _sel = id;
    const TrackerEntry e = as_entry(found);
    _finder.select(e, millis(), _running);
    return 1;
}

bool WifiFox::finder_target(FoxTarget& out) const
{
    if (!_sel) return false;
    portENTER_CRITICAL(&s_mux);
    for (int i = 0; i < MAX_TARGETS; i++)
        if (s_slots[i].used && s_slots[i].t.id == _sel) {
            out = s_slots[i].t;
            portEXIT_CRITICAL(&s_mux);
            return true;
        }
    portEXIT_CRITICAL(&s_mux);
    return false;
}
