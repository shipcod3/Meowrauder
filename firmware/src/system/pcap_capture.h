/**
 * @file  pcap_capture.h
 * @brief Raw 802.11 frame capture to a libpcap file on the SD card.
 *
 * Promiscuous RX runs in the WiFi task and must not touch the SD there, so
 * frames are length-prefixed into a PSRAM ring buffer and drained to the file
 * from loop() on the caller's task. Frames are written with a minimal radiotap
 * header (channel + signal), so Wireshark shows per-frame RSSI.
 *
 * Receive-only: it listens and writes a file, and never transmits.
 */
#pragma once
#include <cstdint>

struct PcapStats {
    uint32_t frames  = 0;   /* frames written to the file               */
    uint32_t dropped = 0;   /* frames lost because the ring was full    */
    uint32_t bytes   = 0;   /* file size so far                         */
    uint16_t rate    = 0;   /* frames in the last completed second      */
    uint16_t peak    = 0;   /* highest per-second rate seen             */
    uint8_t  channel = 1;
    bool     hopping = true;
    bool     running = false;
    bool     pinned  = false;  /* a hop was requested but the radio ignored it,
                                * e.g. a SoftAP is holding the channel */
    char     path[40] = {0}; /* "/pcap/cap_007.pcap"                    */
};

class PcapCapture {
public:
    static constexpr int HIST      = 30;    /* seconds shown in the graph */
    static constexpr int SNAPLEN   = 1600;  /* per-frame cap              */
    static constexpr int RING_SIZE = 64 * 1024;

    /* Open the next /pcap/cap_NNN.pcap and start capturing.
     * hop = sweep channels 1..13; channel = fixed channel when hop is false.
     * Returns false if the SD or the ring buffer is unavailable. */
    bool begin(bool hop, uint8_t channel);
    void stop();                 /* drain, close the file, drop promiscuous */
    void loop();                 /* drain ring -> SD, 1 Hz tick, channel hop */

    void pause();
    void resume();
    bool running() const { return _running; }

    const PcapStats& stats() const { return _stats; }
    void history(uint16_t* out) const;      /* HIST counts, oldest..newest */
    uint32_t uptime_s() const;

    /* Fix on one channel, or pass 0 to resume hopping. */
    void set_channel(uint8_t channel);

private:
    bool     _running   = false;
    bool     _opened    = false;
    uint32_t _last_hop  = 0;
    uint32_t _last_tick = 0;
    uint32_t _accum_ms  = 0;
    uint32_t _run_since = 0;
    PcapStats _stats;

    uint16_t _hist[HIST] = {0};
    int      _hidx = 0;

    void _hop();
    void _drain();
};
