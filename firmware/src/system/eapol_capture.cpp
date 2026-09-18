/**
 * @file eapol_capture.cpp
 * @brief See eapol_capture.h.
 */
#include "eapol_capture.h"
#include <Arduino.h>
#include <SD_MMC.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_heap_caps.h>
#include <sys/time.h>
#include <cstring>
#include "mk_psram_buf.h"
#include <cstdio>

namespace {

/* ── ring buffer (WiFi task -> loop), same shape as pcap_capture ──────── */
struct __attribute__((packed)) RecHdr {
    uint16_t caplen;
    uint32_t ts_sec, ts_usec;
    int8_t   rssi;
    uint8_t  channel;
};
static constexpr uint16_t WRAP   = 0xFFFF;
static constexpr int      HDR_SZ = sizeof(RecHdr);

static uint8_t*          s_ring = nullptr;
static volatile uint32_t s_head = 0, s_tail = 0;
static volatile uint32_t s_frames = 0;
static volatile uint16_t s_dropped = 0;
static portMUX_TYPE      s_mux = portMUX_INITIALIZER_UNLOCKED;

/* ── target table ────────────────────────────────────────────────────── */
/* PSRAM, matching the other modules — see mk_psram_buf.h for why neither the
 * stack nor internal .bss is the right home for these. */
static EapolTarget* s_tgt = nullptr;
static int          s_tgt_n = 0;
static bool ensure_targets()
{
    static void* slot = nullptr;
    if (!s_tgt) s_tgt = (EapolTarget*)mk_psram_buf(
        &slot, sizeof(EapolTarget) * EapolCapture::MAX_TARGETS);
    return s_tgt != nullptr;
}

/* ── key_info bits (IEEE 802.11 EAPOL-Key) ───────────────────────────── */
static constexpr uint16_t KI_PAIRWISE = 0x0008;
static constexpr uint16_t KI_INSTALL  = 0x0040;
static constexpr uint16_t KI_ACK      = 0x0080;
static constexpr uint16_t KI_MIC      = 0x0100;
static constexpr uint16_t KI_SECURE   = 0x0200;

static uint8_t classify(uint16_t ki, uint16_t kdlen)
{
    if (!(ki & KI_PAIRWISE)) return 0;
    const bool mic = ki & KI_MIC, ack = ki & KI_ACK;
    const bool ins = ki & KI_INSTALL, sec = ki & KI_SECURE;
    if (!mic && ack)            return EAPOL_M1;
    if (mic && !ack && !sec)    return EAPOL_M2;
    if (mic && ack && ins)      return EAPOL_M3;
    if (mic && !ack && sec && kdlen == 0) return EAPOL_M4;
    if (mic && ack)             return EAPOL_M3;
    return EAPOL_M2;
}

/* RSN PMKID KDE: DD <len> 00 0F AC 04 <16 B>. */
static bool find_pmkid(const uint8_t* kd, int kdlen, uint8_t out[16])
{
    int p = 0;
    while (p + 2 <= kdlen) {
        const uint8_t tag = kd[p], len = kd[p + 1];
        if (p + 2 + len > kdlen) break;
        if (tag == 0xDD && len >= 20 &&
            kd[p + 2] == 0x00 && kd[p + 3] == 0x0F &&
            kd[p + 4] == 0xAC && kd[p + 5] == 0x04) {
            memcpy(out, kd + p + 6, 16);
            return true;
        }
        p += 2 + len;
    }
    return false;
}

static EapolTarget* target_for(const uint8_t* bssid, const uint8_t* sta)
{
    if (!s_tgt) return nullptr;      /* never allocate from a callback path */
    for (int i = 0; i < s_tgt_n; i++)
        if (!memcmp(s_tgt[i].bssid, bssid, 6) && !memcmp(s_tgt[i].sta, sta, 6))
            return &s_tgt[i];
    if (s_tgt_n < EapolCapture::MAX_TARGETS) {
        EapolTarget* t = &s_tgt[s_tgt_n++];
        *t = EapolTarget{};
        memcpy(t->bssid, bssid, 6);
        memcpy(t->sta, sta, 6);
        return t;
    }
    /* full: reuse the stalest row */
    EapolTarget* oldest = &s_tgt[0];
    for (int i = 1; i < s_tgt_n; i++)
        if ((int32_t)(s_tgt[i].last_ms - oldest->last_ms) < 0) oldest = &s_tgt[i];
    *oldest = EapolTarget{};
    memcpy(oldest->bssid, bssid, 6);
    memcpy(oldest->sta, sta, 6);
    return oldest;
}

void promisc_cb(void* buf, wifi_promiscuous_pkt_type_t type)
{
    (void)type;
    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    const uint8_t* fr = pkt->payload;
    const int len = pkt->rx_ctrl.sig_len;
    if (len < 32 || !s_ring) return;

    const uint8_t ftype = (fr[0] >> 2) & 0x3;
    const uint8_t fsub  = (fr[0] >> 4) & 0xF;

    /* ── WPA3: SAE authentication (management subtype 11) ──────────────
     * Fixed params at offset 24: auth algorithm (2), transaction seq (2),
     * status (2). Algorithm 3 is SAE; seq 1 is commit, seq 2 is confirm. */
    if (ftype == 0 && fsub == 11 && len >= 30) {
        const uint16_t alg = (uint16_t)(fr[24] | (fr[25] << 8));
        if (alg != 3) return;
        const uint16_t seq = (uint16_t)(fr[26] | (fr[27] << 8));
        const uint8_t* bssid = fr + 16;           /* addr3 */
        const uint8_t* sta   = memcmp(fr + 10, bssid, 6) ? fr + 10 : fr + 4;

        struct timeval tv; gettimeofday(&tv, nullptr);
        int cap = len; if (cap > EapolCapture::SNAPLEN) cap = EapolCapture::SNAPLEN;

        portENTER_CRITICAL_ISR(&s_mux);
        EapolTarget* t = target_for(bssid, sta);
        if (t) {
            t->msgs   |= (seq == 1) ? EAPOL_SAE_COMMIT
                       : (seq == 2) ? EAPOL_SAE_CONFIRM : 0;
            t->rssi    = (int8_t)pkt->rx_ctrl.rssi;
            t->channel = (uint8_t)pkt->rx_ctrl.channel;
            t->last_ms = millis();
        }
        /* queue the frame too — an SAE exchange is worth keeping */
        uint32_t head = s_head, tail = s_tail;
        const uint32_t need = HDR_SZ + (uint32_t)cap;
        const uint32_t freeb = (tail > head) ? (tail - head - 1)
                                            : (EapolCapture::RING_SIZE - head + tail - 1);
        if (head + need <= (uint32_t)EapolCapture::RING_SIZE && freeb >= need) {
            RecHdr h{};
            h.caplen = (uint16_t)cap;
            h.ts_sec = (uint32_t)tv.tv_sec; h.ts_usec = (uint32_t)tv.tv_usec;
            h.rssi = (int8_t)pkt->rx_ctrl.rssi; h.channel = (uint8_t)pkt->rx_ctrl.channel;
            memcpy(s_ring + head, &h, HDR_SZ);
            memcpy(s_ring + head + HDR_SZ, fr, cap);
            s_head = head + need;
            s_frames++;
        } else {
            s_dropped++;
        }
        portEXIT_CRITICAL_ISR(&s_mux);
        return;
    }

    if (ftype != 2) return;                       /* otherwise data frames only */

    int hlen = 24;
    if (fsub & 0x08) hlen += 2;                   /* QoS control */
    const uint8_t tods = fr[1] & 0x01, fromds = (fr[1] >> 1) & 0x01;
    if (tods && fromds) return;                   /* skip 4-address WDS */

    /* LLC/SNAP then EtherType 0x888E */
    if (hlen + 8 > len) return;
    const uint8_t* llc = fr + hlen;
    if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
          llc[6] == 0x88 && llc[7] == 0x8E)) return;

    const uint8_t* eap = llc + 8;
    const int eaplen = len - (hlen + 8);
    if (eaplen < 99 || eap[1] != 3) return;       /* 3 = EAPOL-Key */

    const uint16_t ki    = (uint16_t)((eap[5] << 8) | eap[6]);
    const uint16_t kdlen = (uint16_t)((eap[97] << 8) | eap[98]);
    const uint8_t  msg   = classify(ki, kdlen);
    if (!msg) return;

    const uint8_t* bssid = tods ? fr + 4  : fr + 10;
    const uint8_t* sta   = tods ? fr + 10 : fr + 4;

    struct timeval tv; gettimeofday(&tv, nullptr);
    int cap = len; if (cap > EapolCapture::SNAPLEN) cap = EapolCapture::SNAPLEN;

    portENTER_CRITICAL_ISR(&s_mux);
    /* record the pair */
    EapolTarget* t = target_for(bssid, sta);
    if (t) {
        t->msgs   |= msg;
        t->rssi    = (int8_t)pkt->rx_ctrl.rssi;
        t->channel = (uint8_t)pkt->rx_ctrl.channel;
        t->last_ms = millis();
        if (msg == EAPOL_M1 && !t->have_pmkid && kdlen > 0 &&
            99 + kdlen <= eaplen) {
            uint8_t pm[16];
            if (find_pmkid(eap + 99, kdlen, pm)) {
                memcpy(t->pmkid, pm, 16);
                t->have_pmkid = 1;
            }
        }
    }
    /* queue the frame for the file */
    uint32_t head = s_head, tail = s_tail;
    const uint32_t need = HDR_SZ + (uint32_t)cap;
    const uint32_t freeb = (tail > head) ? (tail - head - 1)
                                        : (EapolCapture::RING_SIZE - head + tail - 1);
    if (head + need > (uint32_t)EapolCapture::RING_SIZE) {
        if (freeb > (uint32_t)(EapolCapture::RING_SIZE - head) + need) {
            RecHdr w{}; w.caplen = WRAP;
            memcpy(s_ring + head, &w, HDR_SZ);
            head = 0;
        } else { s_dropped++; portEXIT_CRITICAL_ISR(&s_mux); return; }
    }
    if (freeb < need) { s_dropped++; portEXIT_CRITICAL_ISR(&s_mux); return; }

    RecHdr h{};
    h.caplen = (uint16_t)cap;
    h.ts_sec = (uint32_t)tv.tv_sec; h.ts_usec = (uint32_t)tv.tv_usec;
    h.rssi = (int8_t)pkt->rx_ctrl.rssi; h.channel = (uint8_t)pkt->rx_ctrl.channel;
    memcpy(s_ring + head, &h, HDR_SZ);
    memcpy(s_ring + head + HDR_SZ, fr, cap);
    s_head = head + need;
    s_frames++;
    portEXIT_CRITICAL_ISR(&s_mux);
}

/* ── file writers (same radiotap/pcap layout as pcap_capture) ─────────── */
static File s_file;
static constexpr uint32_t LINKTYPE_RADIOTAP = 127;

struct __attribute__((packed)) Radiotap {
    uint8_t version, pad; uint16_t len; uint32_t present;
    uint16_t freq, chan_flags; int8_t antsignal;
};
static uint16_t chan_to_freq(uint8_t ch)
{
    if (ch == 14) return 2484;
    if (ch >= 1 && ch <= 13) return (uint16_t)(2407 + ch * 5);
    return 2412;
}

} // namespace

bool EapolCapture::begin(bool hop, uint8_t channel)
{
    _stats.error = EAPOL_ERR_NONE;
    if (!ensure_targets()) { _stats.error = EAPOL_ERR_MEM; return false; }
    if (!s_ring) {
        s_ring = (uint8_t*)heap_caps_malloc(RING_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!s_ring) s_ring = (uint8_t*)malloc(RING_SIZE);
        if (!s_ring) { _stats.error = EAPOL_ERR_MEM; return false; }
    }
    /* Do NOT gate on SD_MMC.exists() for a directory — it is unreliable there,
     * and when it wrongly said "/pcap" was missing the mkdir() fallback failed
     * precisely BECAUSE the directory already existed, reporting "cannot
     * create /pcap" about a directory that was present all along.
     * Create unconditionally and ignore the result; the file open is the real
     * test of whether the card is usable. */
    SD_MMC.mkdir("/pcap");

    char path[40]; int n = 0;
    for (; n < 1000; n++) {
        snprintf(path, sizeof(path), "/pcap/eapol_%03d.pcap", n);
        if (!SD_MMC.exists(path)) break;
    }
    if (n >= 1000) { _stats.error = EAPOL_ERR_FULL; return false; }

    s_file = SD_MMC.open(path, FILE_WRITE);
    if (!s_file) {
        SD_MMC.mkdir("/pcap");                       /* one retry */
        s_file = SD_MMC.open(path, FILE_WRITE);
    }
    if (!s_file) { _stats.error = EAPOL_ERR_OPEN; return false; }

    struct __attribute__((packed)) {
        uint32_t magic; uint16_t vmaj, vmin;
        int32_t thiszone; uint32_t sigfigs, snaplen, network;
    } gh = { 0xa1b2c3d4u, 2, 4, 0, 0, SNAPLEN + 16, LINKTYPE_RADIOTAP };
    if (s_file.write((const uint8_t*)&gh, sizeof(gh)) != sizeof(gh)) {
        s_file.close();
        _stats.error = EAPOL_ERR_WRITE;
        return false;
    }

    const uint8_t keep_err = _stats.error;
    _stats = EapolStats{};
    _stats.error = keep_err;
    snprintf(_stats.path, sizeof(_stats.path), "%s", path);
    _stats.hopping = hop;
    _stats.channel = (channel >= 1 && channel <= 14) ? channel : 1;
    _stats.running = true;

    portENTER_CRITICAL(&s_mux);
    s_head = s_tail = 0; s_frames = 0; s_dropped = 0; s_tgt_n = 0;
    portEXIT_CRITICAL(&s_mux);

    _opened = true; _running = true;
    _last_hop = _last_tick = millis();

    /* A SoftAP (Evil Twin) or a half-torn-down BLE session can leave the radio
     * in a state where promiscuous mode is refused. Put WiFi back to station
     * mode first so a capture does not fail for a reason nobody can see. */
    WiFi.mode(WIFI_STA);
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(&promisc_cb);
    if (esp_wifi_set_promiscuous(true) != ESP_OK) {
        /* Something else owns the radio — a SoftAP, or another monitor that
         * was not stopped. Undo the file so we do not leave a stub behind. */
        s_file.close();
        _opened = false; _running = false;
        _stats.running = false;
        _stats.error = EAPOL_ERR_PROMISC;
        SD_MMC.remove(path);
        return false;
    }
    esp_wifi_set_channel(_stats.channel, WIFI_SECOND_CHAN_NONE);
    return true;
}

void EapolCapture::stop()
{
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    _running = false; _stats.running = false;
    if (_opened) {
        _drain();
        s_file.flush();
        const size_t sz = s_file.size();
        s_file.close();
        _opened = false;
        /* Nothing but the 24-byte global header: a run that saw no EAPOL. Do
         * not litter the card with empty captures. */
        if (sz <= 24 && _stats.path[0]) SD_MMC.remove(_stats.path);
    }
}

void EapolCapture::pause()
{
    if (!_running) return;
    _running = false; _stats.running = false;
    esp_wifi_set_promiscuous(false);
    _drain();
    if (_opened) s_file.flush();
}

void EapolCapture::resume()
{
    if (_running || !_opened) return;
    if (esp_wifi_set_promiscuous(true) != ESP_OK) {
        /* Resuming into a radio someone else has claimed would capture
         * nothing and say it was running. */
        _stats.error = EAPOL_ERR_PROMISC;
        return;
    }
    _running = true; _stats.running = true;
    esp_wifi_set_channel(_stats.channel, WIFI_SECOND_CHAN_NONE);
}

void EapolCapture::set_channel(uint8_t channel)
{
    if (channel == 0) { _stats.hopping = true; return; }
    if (channel > 14) return;
    _stats.hopping = false; _stats.channel = channel;
    if (_running) esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

void EapolCapture::_hop()
{
    uint8_t ch = _stats.channel + 1;
    if (ch > 13) ch = 1;
    _stats.channel = ch;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

void EapolCapture::_drain()
{
    if (!_opened) return;
    for (;;) {
        portENTER_CRITICAL(&s_mux);
        uint32_t head = s_head, tail = s_tail;
        portEXIT_CRITICAL(&s_mux);
        if (tail == head) break;

        RecHdr h; memcpy(&h, s_ring + tail, HDR_SZ);
        if (h.caplen == WRAP) {
            portENTER_CRITICAL(&s_mux); s_tail = 0; portEXIT_CRITICAL(&s_mux);
            continue;
        }
        if (h.caplen == 0 || h.caplen > SNAPLEN) {
            portENTER_CRITICAL(&s_mux); s_tail = s_head; portEXIT_CRITICAL(&s_mux);
            break;
        }

        Radiotap rt{};
        rt.len = sizeof(Radiotap);
        rt.present = (1u << 3) | (1u << 5);
        rt.freq = chan_to_freq(h.channel);
        rt.chan_flags = 0x00a0;
        rt.antsignal = h.rssi;

        const uint32_t total = sizeof(Radiotap) + h.caplen;
        struct __attribute__((packed)) {
            uint32_t ts_sec, ts_usec, incl_len, orig_len;
        } ph = { h.ts_sec, h.ts_usec, total, total };

        s_file.write((const uint8_t*)&ph, sizeof(ph));
        s_file.write((const uint8_t*)&rt, sizeof(rt));
        s_file.write(s_ring + tail + HDR_SZ, h.caplen);

        portENTER_CRITICAL(&s_mux);
        s_tail = tail + HDR_SZ + h.caplen;
        portEXIT_CRITICAL(&s_mux);
    }
}

/* Append any new PMKID in hashcat WPA*01 form. ESSID is left empty when we have
 * not seen a beacon for the BSSID — hcxtools can fill it in from a capture. */
static void write_pmkid_line(const EapolTarget& t)
{
    File f = SD_MMC.open("/pcap/pmkid.22000", FILE_APPEND);
    if (!f) return;
    char line[160];
    int n = snprintf(line, sizeof(line), "WPA*01*");
    for (int i = 0; i < 16; i++) n += snprintf(line + n, sizeof(line) - n, "%02x", t.pmkid[i]);
    n += snprintf(line + n, sizeof(line) - n, "*");
    for (int i = 0; i < 6; i++)  n += snprintf(line + n, sizeof(line) - n, "%02x", t.bssid[i]);
    n += snprintf(line + n, sizeof(line) - n, "*");
    for (int i = 0; i < 6; i++)  n += snprintf(line + n, sizeof(line) - n, "%02x", t.sta[i]);
    n += snprintf(line + n, sizeof(line) - n, "****\n");
    f.write((const uint8_t*)line, n);
    f.close();
}

void EapolCapture::loop()
{
    if (!_running) return;
    _drain();

    const uint32_t now = millis();
    if (_stats.hopping && now - _last_hop >= 300) { _last_hop = now; _hop(); }

    if (now - _last_tick >= 1000) {
        _last_tick = now;

        uint16_t pm = 0, hs = 0, sae = 0, n = 0;
        static uint8_t written[MAX_TARGETS] = {0};
        portENTER_CRITICAL(&s_mux);
        n = (uint16_t)s_tgt_n;
        _stats.frames  = s_frames;
        _stats.dropped = s_dropped;
        portEXIT_CRITICAL(&s_mux);

        for (int i = 0; i < n && i < MAX_TARGETS; i++) {
            if (s_tgt[i].have_pmkid) {
                pm++;
                if (!written[i]) { write_pmkid_line(s_tgt[i]); written[i] = 1; }
            }
            if ((s_tgt[i].msgs & (EAPOL_M1 | EAPOL_M2)) == (EAPOL_M1 | EAPOL_M2)) hs++;
            if ((s_tgt[i].msgs & (EAPOL_SAE_COMMIT | EAPOL_SAE_CONFIRM)) ==
                (EAPOL_SAE_COMMIT | EAPOL_SAE_CONFIRM)) sae++;
        }
        _stats.targets    = n;
        _stats.pmkids     = pm;
        _stats.handshakes = hs;
        _stats.sae        = sae;
        s_file.flush();
    }
}

int EapolCapture::list(EapolTarget* out, int max) const
{
    if (!out || max <= 0 || !s_tgt) return 0;
    static void* s_eapl_buf = nullptr;
    EapolTarget* snap = (EapolTarget*)mk_psram_buf(&s_eapl_buf, sizeof(EapolTarget) * (MAX_TARGETS));
    if (!snap) return 0;
    int n = 0;
    portENTER_CRITICAL(&s_mux);
    n = s_tgt_n;
    for (int i = 0; i < n; i++) snap[i] = s_tgt[i];
    portEXIT_CRITICAL(&s_mux);

    for (int i = 0; i < n; i++)          /* newest first */
        for (int j = i + 1; j < n; j++)
            if ((int32_t)(snap[j].last_ms - snap[i].last_ms) > 0) {
                EapolTarget t = snap[i]; snap[i] = snap[j]; snap[j] = t;
            }
    if (n > max) n = max;
    for (int i = 0; i < n; i++) out[i] = snap[i];
    return n;
}
