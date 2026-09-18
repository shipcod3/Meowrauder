/**
 * @file pcap_capture.cpp
 * @brief See pcap_capture.h.
 */
#include "pcap_capture.h"
#include <Arduino.h>
#include <SD_MMC.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_heap_caps.h>
#include <sys/time.h>
#include <cstring>
#include <cstdio>

namespace {

/* ── ring buffer, written from the WiFi task, drained from loop() ─────────
 * Record layout: RecHdr then caplen payload bytes. A caplen of WRAP means
 * "nothing more before the end of the buffer, restart at 0". */
struct __attribute__((packed)) RecHdr {
    uint16_t caplen;
    uint32_t ts_sec;
    uint32_t ts_usec;
    int8_t   rssi;
    uint8_t  channel;
};
static constexpr uint16_t WRAP    = 0xFFFF;
static constexpr int      HDR_SZ  = sizeof(RecHdr);

static uint8_t*         s_ring = nullptr;
static volatile uint32_t s_head = 0;    /* producer (WiFi task) */
static volatile uint32_t s_tail = 0;    /* consumer (loop)      */
static volatile uint32_t s_dropped = 0;
static volatile uint32_t s_cur = 0;     /* frames this second   */
static portMUX_TYPE     s_mux = portMUX_INITIALIZER_UNLOCKED;

static inline uint32_t ring_free(uint32_t head, uint32_t tail)
{
    return (tail > head) ? (tail - head - 1)
                         : (PcapCapture::RING_SIZE - head + tail - 1);
}

void promisc_cb(void* buf, wifi_promiscuous_pkt_type_t type)
{
    (void)type;
    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    int len = pkt->rx_ctrl.sig_len;
    if (len <= 0 || !s_ring) return;
    if (len > PcapCapture::SNAPLEN) len = PcapCapture::SNAPLEN;

    struct timeval tv;
    gettimeofday(&tv, nullptr);

    portENTER_CRITICAL_ISR(&s_mux);
    uint32_t head = s_head, tail = s_tail;
    uint32_t need = HDR_SZ + (uint32_t)len;

    /* If the record cannot sit contiguously before the end, mark a wrap. */
    if (head + need > (uint32_t)PcapCapture::RING_SIZE) {
        if (head + HDR_SZ <= (uint32_t)PcapCapture::RING_SIZE &&
            ring_free(head, tail) >= (uint32_t)(PcapCapture::RING_SIZE - head) + need) {
            RecHdr w{}; w.caplen = WRAP;
            memcpy(s_ring + head, &w, HDR_SZ);
            head = 0;
        } else {
            s_dropped++;
            portEXIT_CRITICAL_ISR(&s_mux);
            return;
        }
    }
    if (ring_free(head, tail) < need) {
        s_dropped++;
        portEXIT_CRITICAL_ISR(&s_mux);
        return;
    }

    RecHdr h{};
    h.caplen  = (uint16_t)len;
    h.ts_sec  = (uint32_t)tv.tv_sec;
    h.ts_usec = (uint32_t)tv.tv_usec;
    h.rssi    = (int8_t)pkt->rx_ctrl.rssi;
    h.channel = (uint8_t)pkt->rx_ctrl.channel;
    memcpy(s_ring + head, &h, HDR_SZ);
    memcpy(s_ring + head + HDR_SZ, pkt->payload, len);
    s_head = head + need;
    s_cur++;
    portEXIT_CRITICAL_ISR(&s_mux);
}

/* ── pcap / radiotap ─────────────────────────────────────────────────── */
static File s_file;

/* LINKTYPE_IEEE802_11_RADIOTAP — lets Wireshark show per-frame RSSI. */
static constexpr uint32_t LINKTYPE_RADIOTAP = 127;

static bool write_global_header()
{
    struct __attribute__((packed)) {
        uint32_t magic; uint16_t vmaj, vmin;
        int32_t  thiszone; uint32_t sigfigs, snaplen, network;
    } gh = { 0xa1b2c3d4u, 2, 4, 0, 0, PcapCapture::SNAPLEN + 16, LINKTYPE_RADIOTAP };
    return s_file.write((const uint8_t*)&gh, sizeof(gh)) == sizeof(gh);
}

/* Minimal radiotap: channel (freq+flags) and antenna signal. */
struct __attribute__((packed)) Radiotap {
    uint8_t  version;      /* 0 */
    uint8_t  pad;
    uint16_t len;          /* 13 */
    uint32_t present;      /* CHANNEL(3) | ANTSIGNAL(5) */
    uint16_t freq;
    uint16_t chan_flags;
    int8_t   antsignal;
};

static uint16_t chan_to_freq(uint8_t ch)
{
    if (ch == 14) return 2484;
    if (ch >= 1 && ch <= 13) return (uint16_t)(2407 + ch * 5);
    return 2412;
}

} // namespace

/* ── lifecycle ───────────────────────────────────────────────────────── */

bool PcapCapture::begin(bool hop, uint8_t channel)
{
    if (!s_ring) {
        s_ring = (uint8_t*)heap_caps_malloc(RING_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!s_ring) s_ring = (uint8_t*)malloc(RING_SIZE);
        if (!s_ring) return false;
    }

    /* Same trap as eapol_capture: exists() on a directory is unreliable, and
     * mkdir() then fails because the directory is already there. Just create
     * it and let the file open decide. */
    SD_MMC.mkdir("/pcap");

    /* Pick the next free cap_NNN.pcap rather than clobbering a capture. */
    char path[40];
    int n = 0;
    for (; n < 1000; n++) {
        snprintf(path, sizeof(path), "/pcap/cap_%03d.pcap", n);
        if (!SD_MMC.exists(path)) break;
    }
    if (n >= 1000) return false;

    s_file = SD_MMC.open(path, FILE_WRITE);
    if (!s_file) {
        SD_MMC.mkdir("/pcap");                       /* one retry */
        s_file = SD_MMC.open(path, FILE_WRITE);
    }
    if (!s_file) return false;

    _stats = PcapStats{};
    snprintf(_stats.path, sizeof(_stats.path), "%s", path);
    _stats.hopping = hop;
    _stats.channel = (channel >= 1 && channel <= 14) ? channel : 1;

    if (!write_global_header()) { s_file.close(); return false; }
    _stats.bytes = (uint32_t)s_file.size();

    for (int i = 0; i < HIST; i++) _hist[i] = 0;
    _hidx = 0;
    _accum_ms  = 0;
    _run_since = millis();
    _last_tick = millis();
    _last_hop  = millis();
    _opened    = true;
    _running   = true;
    _stats.running = true;

    portENTER_CRITICAL(&s_mux);
    s_head = s_tail = 0; s_dropped = 0; s_cur = 0;
    portEXIT_CRITICAL(&s_mux);

    /* A SoftAP (Evil Twin) or a half-torn-down BLE session can leave the radio
     * in a state where promiscuous mode is refused. Put WiFi back to station
     * mode first so a capture does not fail for a reason nobody can see. */
    WiFi.mode(WIFI_STA);
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(&promisc_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(_stats.channel, WIFI_SECOND_CHAN_NONE);
    return true;
}

void PcapCapture::stop()
{
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    _running = false;
    _stats.running = false;
    if (_opened) {
        _drain();                /* flush whatever the ring still holds */
        s_file.flush();
        s_file.close();
        _opened = false;
    }
}

void PcapCapture::pause()
{
    if (!_running) return;
    _accum_ms += millis() - _run_since;
    _running = false;
    _stats.running = false;
    esp_wifi_set_promiscuous(false);
    _drain();
    if (_opened) s_file.flush();
}

void PcapCapture::resume()
{
    if (_running || !_opened) return;
    _run_since = millis();
    _last_tick = millis();
    _running = true;
    _stats.running = true;
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(_stats.channel, WIFI_SECOND_CHAN_NONE);
}

void PcapCapture::set_channel(uint8_t channel)
{
    if (channel == 0) { _stats.hopping = true; return; }
    if (channel > 14) return;
    _stats.hopping = false;
    _stats.channel = channel;
    if (_running) esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

/* ── drain + tick ────────────────────────────────────────────────────── */

void PcapCapture::_drain()
{
    if (!_opened) return;

    for (;;) {
        portENTER_CRITICAL(&s_mux);
        uint32_t head = s_head, tail = s_tail;
        portEXIT_CRITICAL(&s_mux);
        if (tail == head) break;

        RecHdr h;
        memcpy(&h, s_ring + tail, HDR_SZ);
        if (h.caplen == WRAP) {
            portENTER_CRITICAL(&s_mux); s_tail = 0; portEXIT_CRITICAL(&s_mux);
            continue;
        }
        if (h.caplen == 0 || h.caplen > SNAPLEN) {   /* corrupt — resync */
            portENTER_CRITICAL(&s_mux); s_tail = s_head; portEXIT_CRITICAL(&s_mux);
            break;
        }

        Radiotap rt{};
        rt.version    = 0;
        rt.len        = sizeof(Radiotap);
        rt.present    = (1u << 3) | (1u << 5);       /* CHANNEL | ANTSIGNAL */
        rt.freq       = chan_to_freq(h.channel);
        rt.chan_flags = 0x00a0;                      /* 2 GHz, dynamic CCK-OFDM */
        rt.antsignal  = h.rssi;

        const uint32_t total = sizeof(Radiotap) + h.caplen;
        struct __attribute__((packed)) {
            uint32_t ts_sec, ts_usec, incl_len, orig_len;
        } ph = { h.ts_sec, h.ts_usec, total, total };

        s_file.write((const uint8_t*)&ph, sizeof(ph));
        s_file.write((const uint8_t*)&rt, sizeof(rt));
        s_file.write(s_ring + tail + HDR_SZ, h.caplen);

        _stats.frames++;
        _stats.bytes += sizeof(ph) + total;

        portENTER_CRITICAL(&s_mux);
        s_tail = tail + HDR_SZ + h.caplen;
        portEXIT_CRITICAL(&s_mux);
    }
}

void PcapCapture::_hop()
{
    uint8_t ch = _stats.channel + 1;
    if (ch > 13) ch = 1;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);

    /* Read the channel back rather than trusting the request. If something
     * else owns the radio — a SoftAP pins it to its own channel — the hop is
     * silently ignored, and reporting the intended channel would make the UI
     * claim it was sweeping when every frame lands on one channel. */
    uint8_t actual = ch;
    wifi_second_chan_t sec;
    if (esp_wifi_get_channel(&actual, &sec) != ESP_OK || actual == 0) actual = ch;
    _stats.channel = actual;
    _stats.pinned  = (actual != ch);
}

void PcapCapture::loop()
{
    if (!_running) return;
    _drain();

    const uint32_t now = millis();

    if (_stats.hopping && now - _last_hop >= 250) { _last_hop = now; _hop(); }

    if (now - _last_tick >= 1000) {
        _last_tick += 1000;
        portENTER_CRITICAL(&s_mux);
        uint16_t c = (uint16_t)s_cur; s_cur = 0;
        _stats.dropped = s_dropped;
        portEXIT_CRITICAL(&s_mux);

        _stats.rate = c;
        if (c > _stats.peak) _stats.peak = c;
        _hist[_hidx] = c;
        _hidx = (_hidx + 1) % HIST;
        s_file.flush();          /* keep the file valid if power is pulled */
    }
}

void PcapCapture::history(uint16_t* out) const
{
    for (int i = 0; i < HIST; i++) out[i] = _hist[(_hidx + i) % HIST];
}

uint32_t PcapCapture::uptime_s() const
{
    uint32_t ms = _accum_ms + (_running ? millis() - _run_since : 0);
    return ms / 1000;
}
