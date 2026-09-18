/*
 * Meowrauder — the RF reconnaissance FeralCat does not already have.
 *
 * Scope rule: this app deliberately implements only what FeralCat's own apps
 * do NOT. AP scanning, probe sniffing, deauth detection, evil-twin twins,
 * BLE-spam detection, tracker detection and the BLE proximity radar all ship
 * as FeralCat apps already (wifianalyzer, probesniffer, deauthdetect,
 * rogueradar, blespamdetect, trackerdetect), and MeowGotchi already captures
 * EAPOL handshakes to pcap and can transmit deauth. None of that is duplicated
 * here. What remains is what was missing:
 *
 *   Channel Map    2.4 GHz occupancy histogram — no channel view exists
 *   PCAP Capture   raw ALL-frame capture to SD (MeowGotchi saves EAPOL only)
 *   PMKID Harvest  RSN PMKID -> hashcat WPA*01, which nothing else extracts
 *   Fox Hunt WiFi  follow an AP or station by signal (the radar is BLE-only)
 *   Portal Check   captive-portal probe + temporal evil-twin flags; nothing in
 *                  FeralCat associates, so nothing can detect a portal
 *
 * Pure C against the mk_app ABI (mk_app_abi.h) — no LVGL / LovyanGFX / drivers
 * linked in. Everything here is receive-only; the app never transmits.
 * Use it on networks you own or are permitted to assess.
 *
 * Controls — menu: Up/Down select · A open · hold B exit
 *            modes: B back · A per-screen action · hold B exit
 */
#include "mk_app_abi.h"

#define MAXAPS 40

enum {
    S_MENU = 0,
    S_CHAN,
    S_PCAP,
    S_PMKID,
    S_AUDIT, S_AUDITDETAIL,
    S_TWIN,
    S_TOOLS, S_TOOLDETAIL,
    S_WFOX, S_WFOXHUNT,
    S_PORTAL, S_PORTALPROBE
};

static const char* const MENU_NAME[] = {
    "Channel Map", "PCAP Capture", "PMKID Harvest", "AP Audit",
    "Fox Hunt (WiFi)", "Portal Check", "Rogue Tools"
};
static const int MENU_SCREEN[] = {
    S_CHAN, S_PCAP, S_PMKID, S_AUDIT, S_WFOX, S_PORTAL, S_TOOLS
};
#define MENU_N ((int)(sizeof(MENU_SCREEN) / sizeof(MENU_SCREEN[0])))

/* ── state ────────────────────────────────────────────────────────────── */
static mk_ap_t      g_aps[MAXAPS];       /* Channel Map input only */
static int          g_apn = 0;
static uint16_t     g_hist[MK_PCAP_HIST];
static mk_pd_ssid_t g_pd[MK_PD_MAX];
static mk_wa_ap_t   g_wa[MK_WA_MAX];
static int          g_wa_n = 0;
static mk_td_hit_t  g_td[MK_TD_MAX];
static int          g_td_n = 0;
static int          g_pd_n   = 0;
static int          g_screen = S_MENU;
static int          g_active = 0;        /* which service is running */

/* ── helpers ──────────────────────────────────────────────────────────── */

static int clampi(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }

static void fmt_mac(char* buf, int n, const uint8_t* m)
{
    mk_snprintf(buf, n, "%02X:%02X:%02X:%02X:%02X:%02X",
                m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void fmt_bytes(char* buf, int n, uint32_t b)
{
    if (b >= 1048576u)   mk_snprintf(buf, n, "%lu.%lu MB", (unsigned long)(b >> 20),
                                     (unsigned long)(((b >> 10) % 1024) * 10 / 1024));
    else if (b >= 1024u) mk_snprintf(buf, n, "%lu KB", (unsigned long)(b >> 10));
    else                 mk_snprintf(buf, n, "%lu B", (unsigned long)b);
}

/* Bar-graph sparkline, oldest→newest, auto-scaled to its own peak. */
static void draw_spark(int x, int y, int w, int h, const uint16_t* v, int n, uint32_t col)
{
    if (n <= 0) return;
    int peak = 1;
    for (int i = 0; i < n; i++) if (v[i] > peak) peak = v[i];
    int bw = w / n;
    if (bw < 1) bw = 1;
    mk_gfx_rect(x, y, w, h, MK_COL_BORDER);
    for (int i = 0; i < n; i++) {
        int bh = (int)(((long)v[i] * (h - 2)) / peak);
        if (bh < 1 && v[i] > 0) bh = 1;
        if (bh > 0) mk_gfx_fill_rect(x + i * bw + 1, y + h - 1 - bh,
                                     bw > 2 ? bw - 1 : 1, bh, col);
    }
}

static void stat_row(int y, const char* label, const char* value, uint32_t col)
{
    mk_gfx_text(MK_PAD, y, label, MK_COL_MUTED);
    mk_gfx_text(120, y, value, col);
}

static void banner(int y, const char* s, uint32_t col)
{
    mk_gfx_fill_rect(0, y, MK_SCREEN_W, 22,
                     col == MK_COL_ERR ? MK_COL_ACCENT_DARK : MK_COL_ITEM_BG);
    mk_gfx_text(MK_PAD, y + 5, s, col);
}

/* ── service lifecycle ────────────────────────────────────────────────── */

static void services_stop(void)
{
    if (g_active == S_PCAP)   mk_pcap_stop();
    if (g_active == S_PMKID)  mk_eapol_stop();
    if (g_active == S_WFOX)   mk_fox_stop();
    if (g_active == S_PORTAL) { mk_pd_probe_stop(); mk_pd_stop(); }
    if (g_active == S_AUDIT)  mk_wa_stop();
    if (g_active == S_TWIN)   mk_twin_stop();
    if (g_active == S_TOOLS)  mk_td_stop();
    g_active = 0;
}

/* Only one service may own the receiver at a time. PCAP and PMKID write files,
 * so the user starts those explicitly rather than on screen entry. */
static void service_start(int screen)
{
    services_stop();
    if (screen == S_WFOX)   mk_fox_begin();
    if (screen == S_PORTAL) mk_pd_begin();
    if (screen == S_AUDIT)  mk_wa_begin();
    if (screen == S_TOOLS)  mk_td_begin(MK_TD_MODE_WIFI);
    g_active = screen;
}

static void service_pump(void)
{
    if (g_active == S_PCAP)   mk_pcap_loop();
    if (g_active == S_PMKID)  mk_eapol_loop();
    if (g_active == S_WFOX)   mk_fox_loop();
    if (g_active == S_PORTAL) mk_pd_loop();
    if (g_active == S_AUDIT)  mk_wa_loop();
    /* the portal must be serviced every loop or clients time out */
    if (g_active == S_TWIN)   mk_twin_loop();
    if (g_active == S_TOOLS)  mk_td_loop();
}

/* ── menu ─────────────────────────────────────────────────────────────── */

static void draw_menu(int sel, int scroll)
{
    mk_gfx_clear();
    mk_gfx_header("Meowrauder");
    int vis = mk_content_rows();
    for (int i = 0; i < vis; i++) {
        int idx = scroll + i;
        if (idx >= MENU_N) break;
        mk_gfx_menu_item(i, MENU_NAME[idx], "", idx == sel);
    }
    mk_gfx_footer("Open", "Exit");
    mk_gfx_present();
}

/* ── Channel Map ──────────────────────────────────────────────────────── */

static void do_scan(void)
{
    mk_gfx_clear();
    mk_gfx_header("Channel Map");
    mk_gfx_text(MK_PAD, 110, "Scanning 2.4GHz...", MK_COL_ACCENT);
    mk_gfx_footer("", "");
    mk_gfx_present();

    int n = mk_wifi_scan(g_aps, MAXAPS);
    g_apn = n < 0 ? 0 : n;
}

static void draw_chan_map(void)
{
    int count[15];
    int busiest = 0, peak = 1;
    for (int c = 0; c <= 14; c++) count[c] = 0;
    for (int i = 0; i < g_apn; i++) {
        int c = g_aps[i].channel;
        if (c >= 1 && c <= 14) count[c]++;
    }
    for (int c = 1; c <= 14; c++) {
        if (count[c] > peak) peak = count[c];
        if (count[c] > count[busiest ? busiest : 1]) busiest = c;
    }

    mk_gfx_clear();
    mk_gfx_header("Channel Map");

    /* base + labels + summary must clear the footer (starts at H-FTR_H = 220) */
    const int base = 172, maxh = 112, bw = 20;
    for (int c = 1; c <= 14; c++) {
        int x  = 10 + (c - 1) * bw;
        int bh = (int)(((long)count[c] * maxh) / peak);
        uint32_t col = (c == 1 || c == 6 || c == 11) ? MK_COL_ACCENT : MK_COL_ACCENT_DIM;
        if (count[c] > 0) mk_gfx_fill_rect(x, base - bh, bw - 4, bh, col);
        mk_gfx_rect(x, base - maxh, bw - 4, maxh, MK_COL_BORDER);
        char lbl[4];
        mk_snprintf(lbl, sizeof(lbl), "%d", c);
        mk_gfx_text(x + (c < 10 ? 4 : 1), base + 4, lbl, MK_COL_MUTED);
    }

    char buf[48];
    mk_snprintf(buf, sizeof(buf), "%d APs   busiest ch %d (%d)",
                g_apn, busiest ? busiest : 0, busiest ? count[busiest] : 0);
    mk_gfx_text(MK_PAD, base + 22, buf, MK_COL_TEXT);

    mk_gfx_footer("Rescan", "Back");
    mk_gfx_present();
}

/* ── PCAP capture ─────────────────────────────────────────────────────── */

static void draw_pcap(void)
{
    mk_pcap_stats_t st;
    mk_pcap_stats(&st);

    mk_gfx_clear();
    mk_gfx_header("PCAP Capture");

    if (!st.running && st.frames == 0) {
        mk_gfx_text(MK_PAD, 46,  "Raw 802.11 capture to SD", MK_COL_TEXT);
        mk_gfx_text(MK_PAD, 70,  "every frame, not just EAPOL", MK_COL_MUTED);
        mk_gfx_text(MK_PAD, 92,  "radiotap: channel + RSSI", MK_COL_MUTED);
        mk_gfx_text(MK_PAD, 114, "/pcap/cap_NNN.pcap", MK_COL_MUTED);
        mk_gfx_text(MK_PAD, 148, "Receive-only. Capture only", MK_COL_ACCENT);
        mk_gfx_text(MK_PAD, 168, "traffic you are allowed to.", MK_COL_ACCENT);
        mk_gfx_footer("Start", "Back");
        mk_gfx_present();
        return;
    }

    if (st.running) banner(28, " CAPTURING", MK_COL_ERR);
    else            banner(28, " STOPPED", MK_COL_MUTED);

    mk_gfx_text(MK_PAD, 54, st.path, MK_COL_ACCENT);

    int hn = mk_pcap_history(g_hist, MK_PCAP_HIST);
    draw_spark(MK_PAD, 74, MK_SCREEN_W - 2 * MK_PAD, 30, g_hist, hn,
               st.running ? MK_COL_ACCENT : MK_COL_MUTED);

    char buf[48];
    int y = 112;
    mk_snprintf(buf, sizeof(buf), "%lu  (%u/s, peak %u)",
                (unsigned long)st.frames, st.rate, st.peak);
    stat_row(y, "Frames", buf, MK_COL_TEXT); y += 22;
    fmt_bytes(buf, sizeof(buf), st.bytes);
    stat_row(y, "File size", buf, MK_COL_TEXT); y += 22;
    mk_snprintf(buf, sizeof(buf), "%lu", (unsigned long)st.dropped);
    stat_row(y, "Dropped", buf, st.dropped ? MK_COL_WARN : MK_COL_MUTED); y += 22;
    if (st.pinned)       mk_snprintf(buf, sizeof(buf), "PINNED to %u", st.channel);
    else if (st.hopping) mk_snprintf(buf, sizeof(buf), "hopping (now %u)", st.channel);
    else                 mk_snprintf(buf, sizeof(buf), "fixed %u", st.channel);
    stat_row(y, "Channel", buf, st.pinned ? MK_COL_ERR : MK_COL_TEXT); y += 22;
    mk_snprintf(buf, sizeof(buf), "%lus", (unsigned long)st.uptime_s);
    stat_row(y, "Elapsed", buf, MK_COL_MUTED);

    mk_gfx_footer(st.running ? "Stop" : "Start", "Back");
    mk_gfx_present();
}

/* ── PMKID harvest ────────────────────────────────────────────────────────
 * MeowGotchi already writes EAPOL handshake pcaps, so this does the part
 * nothing else does: pull the PMKID out of the RSN KDE in M1 and write it as a
 * hashcat WPA*01 line. Passive — it cannot force a handshake. */

static const char* eapol_err_str(unsigned e)
{
    if (e == MK_EAPOL_ERR_MEM)     return "out of memory (ring)";
    if (e == MK_EAPOL_ERR_DIR)     return "cannot create /pcap";
    if (e == MK_EAPOL_ERR_FULL)    return "/pcap full (1000 files)";
    if (e == MK_EAPOL_ERR_OPEN)    return "cannot open capture file";
    if (e == MK_EAPOL_ERR_WRITE)   return "SD write failed";
    if (e == MK_EAPOL_ERR_PROMISC) return "radio busy - stop other scans";
    return "unknown";
}

static void draw_pmkid(void)
{
    mk_eapol_stats_t st;
    static mk_eapol_target_t tg[MK_EAPOL_MAX];
    mk_eapol_stats(&st);

    mk_gfx_clear();
    mk_gfx_header("PMKID Harvest");

    if (!st.running && st.error) {
        banner(28, " FAILED TO START", MK_COL_ERR);
        mk_gfx_text(MK_PAD, 62, eapol_err_str(st.error), MK_COL_ERR);
        if (st.error == MK_EAPOL_ERR_PROMISC) {
            mk_gfx_text(MK_PAD, 96,  "Another capture still owns", MK_COL_MUTED);
            mk_gfx_text(MK_PAD, 116, "the radio. Leave PCAP, Fox", MK_COL_MUTED);
            mk_gfx_text(MK_PAD, 136, "Hunt, Rogue Tools or the", MK_COL_MUTED);
            mk_gfx_text(MK_PAD, 156, "Evil Twin first.", MK_COL_MUTED);
        } else {
            mk_gfx_text(MK_PAD, 96, "Check the SD card.", MK_COL_MUTED);
        }
        mk_gfx_footer("Retry", "Back");
        mk_gfx_present();
        return;
    }

    if (!st.running && st.frames == 0) {
        mk_gfx_text(MK_PAD, 46,  "RSN PMKID -> hashcat", MK_COL_TEXT);
        mk_gfx_text(MK_PAD, 70,  "appends WPA*01 lines to", MK_COL_MUTED);
        mk_gfx_text(MK_PAD, 90,  "/pcap/pmkid.22000", MK_COL_MUTED);
        mk_gfx_text(MK_PAD, 116, "(handshake pcaps: MeowGotchi)", MK_COL_MUTED);
        mk_gfx_text(MK_PAD, 148, "Passive: cannot force a", MK_COL_ACCENT);
        mk_gfx_text(MK_PAD, 168, "handshake. Own networks only.", MK_COL_ACCENT);
        mk_gfx_footer("Start", "Back");
        mk_gfx_present();
        return;
    }

    if (st.running) banner(28, " LISTENING", MK_COL_OK);
    else            banner(28, " STOPPED", MK_COL_MUTED);

    char buf[52];
    mk_snprintf(buf, sizeof(buf), "%lu frames %u pair %u PMKID %u SAE",
                (unsigned long)st.frames, st.targets, st.pmkids, st.sae);
    mk_gfx_text(MK_PAD, 54, buf, MK_COL_TEXT);

    int n = mk_eapol_list(tg, MK_EAPOL_MAX);
    if (n <= 0) {
        mk_gfx_text(MK_PAD, 100, "No EAPOL seen yet", MK_COL_MUTED);
        mk_gfx_text(MK_PAD, 122, "PMKID appears on M1 from", MK_COL_MUTED);
        mk_gfx_text(MK_PAD, 142, "APs that offer one", MK_COL_MUTED);
    } else {
        mk_gfx_text(MK_PAD, 78, "BSSID", MK_COL_MUTED);
        mk_gfx_text(200, 78, "msgs", MK_COL_MUTED);
        for (int i = 0; i < n && i < 4; i++) {
            int y = 98 + i * 26;
            fmt_mac(buf, sizeof(buf), tg[i].bssid);
            mk_gfx_text(MK_PAD, y, buf, tg[i].have_pmkid ? MK_COL_WARN : MK_COL_TEXT);
            char m[16];
            const int sae = (tg[i].msgs & (MK_EAPOL_SAE_COMMIT | MK_EAPOL_SAE_CONFIRM)) != 0;
            if (sae)
                mk_snprintf(m, sizeof(m), "SAE %c%c",
                            (tg[i].msgs & MK_EAPOL_SAE_COMMIT)  ? 'c' : '-',
                            (tg[i].msgs & MK_EAPOL_SAE_CONFIRM) ? 'f' : '-');
            else
                mk_snprintf(m, sizeof(m), "%c%c%c%c%s",
                            (tg[i].msgs & MK_EAPOL_M1) ? '1' : '-',
                            (tg[i].msgs & MK_EAPOL_M2) ? '2' : '-',
                            (tg[i].msgs & MK_EAPOL_M3) ? '3' : '-',
                            (tg[i].msgs & MK_EAPOL_M4) ? '4' : '-',
                            tg[i].have_pmkid ? " PMKID" : "");
            mk_gfx_text(200, y, m, tg[i].have_pmkid ? MK_COL_WARN : MK_COL_MUTED);
        }
    }

    mk_gfx_footer(st.running ? "Stop" : "Start", "Back");
    mk_gfx_present();
}

/* ── AP security audit ────────────────────────────────────────────────── */

static void draw_audit_list(int sel, int scroll)
{
    mk_wa_stats_t st;
    mk_wa_stats(&st);
    g_wa_n = mk_wa_list(g_wa, MK_WA_MAX);

    mk_gfx_clear();
    mk_gfx_header("AP Audit");

    char buf[52];
    mk_snprintf(buf, sizeof(buf), "%u APs  %u at risk  ch%u",
                st.aps, st.at_risk, st.channel);
    mk_gfx_text(MK_PAD, 30, buf, st.at_risk ? MK_COL_WARN : MK_COL_MUTED);

    if (g_wa_n <= 0) {
        mk_gfx_text(MK_PAD, 110, "Reading beacons...", MK_COL_ACCENT);
        mk_gfx_footer("", "Back");
        mk_gfx_present();
        return;
    }

    for (int i = 0; i < 5; i++) {
        int idx = scroll + i;
        if (idx >= g_wa_n) break;
        int y = 50 + i * 30;
        mk_wa_ap_t* a = &g_wa[idx];
        uint32_t fg = (idx == sel) ? MK_COL_ACCENT
                    : a->findings >= 2 ? MK_COL_ERR
                    : a->findings ? MK_COL_WARN : MK_COL_TEXT;

        if (a->flags & MK_WA_HIDDEN_RESOLVED)
            mk_snprintf(buf, sizeof(buf), "(%s)", a->ssid);   /* recovered */
        else if (a->flags & MK_WA_HIDDEN)
            mk_snprintf(buf, sizeof(buf), "<hidden>");
        else
            mk_snprintf(buf, sizeof(buf), "%s", a->ssid);
        mk_gfx_text(MK_PAD, y, buf, fg);

        /* worst finding as a short tag */
        const char* tag = "-";
        if      (a->flags & MK_WA_OPEN)            tag = "OPEN";
        else if (a->flags & MK_WA_WEP)             tag = "WEP";
        else if (a->flags & MK_WA_WPS_UNLOCKED)    tag = "WPS OPEN";
        else if (a->flags & MK_WA_TKIP)            tag = "TKIP";
        else if (a->flags & MK_WA_WPA1)            tag = "WPA1";
        else if (a->flags & MK_WA_WPA3_TRANSITION) tag = "WPA3 TRANS";
        else if (a->flags & MK_WA_NO_PMF)          tag = "NO PMF";
        else if (a->flags & MK_WA_SOFTAP_RATES) tag = "SOFT AP";
        else if (a->flags & MK_WA_PMF_REQUIRED)    tag = "PMF req";
        mk_snprintf(buf, sizeof(buf), "C%-2d %ddBm %s", a->channel, a->rssi, tag);
        mk_gfx_text(140, y + 13, buf, a->findings ? MK_COL_ERR : MK_COL_MUTED);
    }
    mk_gfx_footer("Findings", "Back");
    mk_gfx_present();
}

/* One finding row per line, worst first. */
static void draw_audit_detail(const mk_wa_ap_t* a)
{
    mk_gfx_clear();
    mk_gfx_header((a->flags & MK_WA_HIDDEN) && !a->ssid[0] ? "<hidden>" : a->ssid);

    char buf[56];
    fmt_mac(buf, sizeof(buf), a->bssid);
    mk_gfx_text(MK_PAD, 30, buf, MK_COL_MUTED);
    mk_snprintf(buf, sizeof(buf), "ch%d  %ddBm", a->channel, a->rssi);
    mk_gfx_text(215, 30, buf, MK_COL_MUTED);

    int y = 52;
    struct { uint32_t f; const char* txt; uint32_t col; } R[] = {
        { MK_WA_OPEN,            "No encryption",            MK_COL_ERR   },
        { MK_WA_WEP,             "WEP in use",               MK_COL_ERR   },
        { MK_WA_WPA1,            "WPA1 (pre-RSN) offered",   MK_COL_ERR   },
        { MK_WA_TKIP,            "TKIP cipher enabled",      MK_COL_ERR   },
        { MK_WA_WPS_UNLOCKED,    "WPS configured, unlocked", MK_COL_ERR   },
        { MK_WA_WPA3_TRANSITION, "WPA3 transition mode",     MK_COL_WARN  },
        { MK_WA_NO_PMF,          "No PMF (802.11w absent)",  MK_COL_WARN  },
        { MK_WA_PMF_OPTIONAL,    "PMF capable, not required",MK_COL_WARN  },
        { MK_WA_WPS_ENABLED,     "WPS advertised",           MK_COL_WARN  },
        { MK_WA_SOFTAP_RATES, "software AP (rate order)",  MK_COL_WARN  },
        { MK_WA_HIDDEN_RESOLVED, "hidden name recovered",    MK_COL_WARN  },
        { MK_WA_HIDDEN,          "SSID withheld",            MK_COL_MUTED },
        { MK_WA_PMF_REQUIRED,    "PMF required",             MK_COL_OK    },
        { MK_WA_SAE,             "SAE (WPA3) offered",       MK_COL_OK    },
        { MK_WA_OWE,             "Enhanced Open (OWE)",      MK_COL_OK    },
    };
    int shown = 0;
    for (unsigned i = 0; i < sizeof(R) / sizeof(R[0]) && shown < 7; i++) {
        if (!(a->flags & R[i].f)) continue;
        mk_gfx_text(MK_PAD, y, R[i].txt, R[i].col);
        y += 20;
        shown++;
    }
    if (!shown) mk_gfx_text(MK_PAD, y, "No findings", MK_COL_OK);

    /* Beacon fingerprint. A commercial router shows country/HT/VHT/extcap and
     * several vendor IEs; a bare ESP32 SoftAP — an evil portal, a hobby tool —
     * shows very few. Displayed so the difference can be read off two real
     * APs rather than guessed at. */
    {
        char fp[44];
        mk_snprintf(fp, sizeof(fp), "IEs %u (%u vnd)%s%s%s%s",
                    a->ie_count, a->ie_vendor,
                    (a->ie_mask & MK_WA_IE_COUNTRY) ? " ctry" : "",
                    (a->ie_mask & MK_WA_IE_HT)      ? " ht"   : "",
                    (a->ie_mask & MK_WA_IE_VHT)     ? " vht"  : "",
                    (a->ie_mask & MK_WA_IE_WMM)     ? " wmm"  : "");
        mk_gfx_text(MK_PAD, 182, fp, MK_COL_MUTED);
    }
    if (a->wps_state) {
        mk_snprintf(buf, sizeof(buf), "WPS state %u, locked %s", a->wps_state,
                    a->wps_locked == 0xFF ? "?" : (a->wps_locked ? "yes" : "no"));
        mk_gfx_text(MK_PAD, 200, buf, MK_COL_MUTED);
    }

    /* Only offer the clone when we actually have a name to impersonate. A
     * hidden AP whose name was recovered from an association still carries
     * MK_WA_HIDDEN, so key off the name itself, not the flag. */
    const int clonable = a->ssid[0] && !mk_twin_running();
    mk_gfx_footer(clonable ? "Clone AP" : "", "Back");
    mk_gfx_present();
}

/* ── Evil twin + portal ───────────────────────────────────────────────── */

static void draw_twin(void)
{
    mk_twin_stats_t st;
    static mk_twin_cap_t caps[MK_TWIN_CAPS];
    mk_twin_stats(&st);

    mk_gfx_clear();
    mk_gfx_header("Evil Twin");

    if (!st.running) {
        mk_gfx_text(MK_PAD, 46,  "Clones the selected SSID as", MK_COL_TEXT);
        mk_gfx_text(MK_PAD, 66,  "an open AP with a portal from", MK_COL_MUTED);
        mk_gfx_text(MK_PAD, 86,  "/portal/<name>.html", MK_COL_MUTED);
        mk_gfx_text(MK_PAD, 112, "Submissions -> captures.csv", MK_COL_MUTED);
        mk_gfx_text(MK_PAD, 144, "Authorised engagements only.", MK_COL_ERR);
        mk_gfx_text(MK_PAD, 164, "Captures are plaintext creds:", MK_COL_ERR);
        mk_gfx_text(MK_PAD, 184, "destroy after reporting.", MK_COL_ERR);
        mk_gfx_footer("Start", "Back");
        mk_gfx_present();
        return;
    }

    banner(28, " AP UP - TRANSMITTING", MK_COL_ERR);
    mk_gfx_text(MK_PAD, 54, st.ssid, MK_COL_ACCENT);

    char buf[56];
    mk_snprintf(buf, sizeof(buf), "ch%u  portal:%s%s", st.channel, st.portal,
                st.sd_ok ? "" : "  [SD!]");
    mk_gfx_text(MK_PAD, 74, buf, st.sd_ok ? MK_COL_MUTED : MK_COL_ERR);

    int y = 96;
    mk_snprintf(buf, sizeof(buf), "%u now, %u seen", st.clients, st.seen);
    stat_row(y, "Clients", buf, MK_COL_TEXT); y += 22;
    mk_snprintf(buf, sizeof(buf), "%lu", (unsigned long)st.requests);
    stat_row(y, "Requests", buf, MK_COL_TEXT); y += 22;
    mk_snprintf(buf, sizeof(buf), "%u", st.submits);
    stat_row(y, "Submitted", buf, st.submits ? MK_COL_ERR : MK_COL_MUTED); y += 24;

    int n = mk_twin_captures(caps, MK_TWIN_CAPS);
    if (n > 0) {
        mk_gfx_text(MK_PAD, y, "Latest captures", MK_COL_MUTED); y += 18;
        for (int i = 0; i < n && i < 2; i++) {
            mk_snprintf(buf, sizeof(buf), "%s / %s", caps[i].field1, caps[i].field2);
            mk_gfx_text(MK_PAD + 4, y, buf, MK_COL_ERR);
            y += 18;
        }
    }

    mk_gfx_footer("Stop", "Back");
    mk_gfx_present();
}

/* ── Rogue-tool detection ─────────────────────────────────────────────── */

static const char* td_kind_str(unsigned k)
{
    if (k == MK_TD_PINEAPPLE)  return "Pineapple/Karma";
    if (k == MK_TD_PWNAGOTCHI) return "Pwnagotchi";
    if (k == MK_TD_DEAUTHER)   return "Deauther";
    if (k == MK_TD_MARAUDER)   return "Marauder";
    if (k == MK_TD_BRUCE)      return "Bruce";
    if (k == MK_TD_FLIPPER)    return "Flipper Zero";
    if (k == MK_TD_ESP_TOOL)   return "ESP32 tool";
    return "unidentified";
}

/* What the last unexpected reset was, and the last breadcrumb set before it.
 * Only shown when the previous boot actually died — a clean start prints
 * nothing, so this costs the user nothing in normal use. */
static void draw_crumb(int y)
{
    unsigned r = mk_crumb_reset_id();
    if (r != 4 /*PANIC*/ && r != 5 /*INT_WDT*/ && r != 6 /*TASK_WDT*/ &&
        r != 7 /*WDT*/  && r != 9 /*BROWNOUT*/) return;

    char b[56];
    mk_snprintf(b, sizeof(b), "last reset: %s at %s",
                mk_crumb_reset_str(), mk_crumb_last_name());
    mk_gfx_text(MK_PAD, y, b, MK_COL_ERR);
}

static void draw_tools(int sel, int scroll)
{
    mk_td_stats_t st;
    mk_td_stats(&st);
    g_td_n = mk_td_list(g_td, MK_TD_MAX);

    mk_gfx_clear();
    mk_gfx_header("Rogue Tools");

    char buf[56];
    mk_snprintf(buf, sizeof(buf), "%s  %u hits  %u strong  %u seen",
                st.mode == MK_TD_MODE_BLE ? "BLE" : "WiFi",
                st.hits, st.high_conf, st.tracked);
    mk_gfx_text(MK_PAD, 30, buf, st.high_conf ? MK_COL_ERR : MK_COL_MUTED);

    if (st.ble_error) {
        mk_gfx_text(MK_PAD, 110, "BLE scan failed to start", MK_COL_ERR);
        mk_gfx_footer("WiFi/BLE", "Back");
        mk_gfx_present();
        return;
    }

    if (g_td_n <= 0) {
        mk_gfx_text(MK_PAD, 86,  "Nothing matched yet.", MK_COL_MUTED);
        mk_gfx_text(MK_PAD, 112, "A toggles WiFi / BLE.", MK_COL_MUTED);
        mk_gfx_text(MK_PAD, 138, "Evidence, not guesses:", MK_COL_ACCENT);
        mk_gfx_text(MK_PAD, 158, "OUI alone never flags.", MK_COL_ACCENT);
        draw_crumb(182);
        mk_gfx_footer("WiFi/BLE", "Back");
        mk_gfx_present();
        return;
    }

    for (int i = 0; i < 5; i++) {
        int idx = scroll + i;
        if (idx >= g_td_n) break;
        int y = 50 + i * 30;
        mk_td_hit_t* h = &g_td[idx];
        uint32_t fg = (idx == sel) ? MK_COL_ACCENT
                    : h->confidence >= 70 ? MK_COL_ERR
                    : h->confidence >= 40 ? MK_COL_WARN : MK_COL_TEXT;

        mk_gfx_text(MK_PAD, y, td_kind_str(h->kind), fg);
        mk_snprintf(buf, sizeof(buf), "%u%%  %ddBm", h->confidence, h->rssi);
        mk_gfx_text(210, y, buf, fg);

        if (h->label[0]) mk_snprintf(buf, sizeof(buf), "%s", h->label);
        else             fmt_mac(buf, sizeof(buf), h->mac);
        mk_gfx_text(MK_PAD + 6, y + 13, buf, MK_COL_MUTED);
    }
    mk_gfx_footer("Evidence", "Back");
    mk_gfx_present();
}

static void draw_tool_detail(const mk_td_hit_t* h)
{
    mk_gfx_clear();
    mk_gfx_header(td_kind_str(h->kind));

    char buf[56];
    fmt_mac(buf, sizeof(buf), h->mac);
    mk_gfx_text(MK_PAD, 30, buf, MK_COL_TEXT);
    mk_snprintf(buf, sizeof(buf), "%s %ddBm", h->radio == MK_TD_MODE_BLE ? "BLE" : "WiFi",
                h->rssi);
    mk_gfx_text(215, 30, buf, MK_COL_MUTED);

    if (h->label[0]) mk_gfx_text(MK_PAD, 50, h->label, MK_COL_ACCENT);

    mk_snprintf(buf, sizeof(buf), "confidence %u%%", h->confidence);
    mk_gfx_text(MK_PAD, 72, buf,
                h->confidence >= 70 ? MK_COL_ERR
              : h->confidence >= 40 ? MK_COL_WARN : MK_COL_MUTED);

    mk_gfx_text(MK_PAD, 96, "Evidence", MK_COL_MUTED);
    int y = 114;
    struct { uint32_t f; const char* txt; uint32_t col; } E[] = {
        { MK_TD_EV_DEAUTH_TX, "sending deauth frames",    MK_COL_ERR   },
        { MK_TD_EV_MULTISSID, "many SSIDs, one BSSID",    MK_COL_ERR   },
        { MK_TD_EV_JSON_SSID, "JSON payload in SSID",     MK_COL_ERR   },
        { MK_TD_EV_SVC_UUID,  "BLE service UUID match",   MK_COL_ERR   },
        { MK_TD_EV_SOFTAP,    "open + software-AP rates",  MK_COL_ERR   },
        { MK_TD_EV_NAME,      "name signature match",     MK_COL_WARN  },
        { MK_TD_EV_MFG,       "BLE vendor data",          MK_COL_MUTED },
        { MK_TD_EV_BEACON_TX, "beaconing (is an AP)",     MK_COL_MUTED },
        { MK_TD_EV_OUI,       "tool-platform OUI (weak)", MK_COL_MUTED },
    };
    for (unsigned i = 0; i < sizeof(E) / sizeof(E[0]) && y < 196; i++) {
        if (!(h->evidence & E[i].f)) continue;
        mk_gfx_text(MK_PAD + 4, y, E[i].txt, E[i].col);
        y += 19;
    }

    if (h->radio == MK_TD_MODE_BLE) {
        /* What the advertisement actually carried. Diagnostic: if a signature
         * is not matching, this says whether the field is even present. */
        char ad[40];
        mk_snprintf(ad, sizeof(ad), "adv:%s%s%s%s%s",
                    (h->ad_mask & (1u << 4)) ? " name" : "",
                    (h->ad_mask & (1u << 1)) ? " u16"  : "",
                    (h->ad_mask & (1u << 3)) ? " u128" : "",
                    (h->ad_mask & (1u << 8)) ? " mfg"  : "",
                    (h->ad_mask & (1u << 6)) ? " svcd" : "");
        mk_gfx_text(MK_PAD, 182, ad, MK_COL_MUTED);
        mk_snprintf(buf, sizeof(buf), "mfg %04X  uuid %04X  x%u",
                    h->mfg_id, h->uuid16, h->count);
        mk_gfx_text(MK_PAD, 200, buf, MK_COL_MUTED);
    } else if (h->ssid_count > 1) {
        mk_snprintf(buf, sizeof(buf), "%u SSIDs, %u sightings", h->ssid_count, h->count);
        mk_gfx_text(MK_PAD, 200, buf, MK_COL_MUTED);
    } else {
        mk_snprintf(buf, sizeof(buf), "%u sightings", h->count);
        mk_gfx_text(MK_PAD, 200, buf, MK_COL_MUTED);
    }

    mk_gfx_footer("", "Back");
    mk_gfx_present();
}

/* ── Fox Hunt (WiFi) ──────────────────────────────────────────────────── */

static void draw_wfox_list(int sel, int scroll)
{
    static mk_fox_target_t list[MK_FOX_MAX];
    mk_fox_stats_t st;
    mk_fox_stats(&st);
    int n = mk_fox_list(list, MK_FOX_MAX);

    mk_gfx_clear();
    mk_gfx_header("Fox Hunt - WiFi");

    char buf[52];
    mk_snprintf(buf, sizeof(buf), "%u targets  %u AP  %u sta  ch%u",
                st.targets, st.aps, st.stations, st.channel);
    mk_gfx_text(MK_PAD, 30, buf, MK_COL_MUTED);

    if (n <= 0) {
        mk_gfx_text(MK_PAD, 110, "Listening for targets...", MK_COL_MUTED);
        mk_gfx_footer("", "Back");
        mk_gfx_present();
        return;
    }

    for (int i = 0; i < 5; i++) {
        int idx = scroll + i;
        if (idx >= n) break;
        int y = 50 + i * 30;
        uint32_t fg = (idx == sel) ? MK_COL_ACCENT : MK_COL_TEXT;
        if (list[idx].kind == MK_FOX_AP && list[idx].ssid[0])
            mk_snprintf(buf, sizeof(buf), "%s", list[idx].ssid);
        else
            fmt_mac(buf, sizeof(buf), list[idx].mac);
        mk_gfx_text(MK_PAD, y, buf, fg);
        mk_snprintf(buf, sizeof(buf), "%s C%-2d %ddBm",
                    list[idx].kind == MK_FOX_AP ? "AP " : "sta",
                    list[idx].channel, list[idx].filtered_rssi);
        mk_gfx_text(150, y + 13, buf, MK_COL_MUTED);
    }
    mk_gfx_footer("Hunt", "Back");
    mk_gfx_present();
}

static const char* fox_state_str(unsigned st)
{
    if (st == MK_TRK_LIVE)    return "LIVE";
    if (st == MK_TRK_WAITING) return "WAITING";
    if (st == MK_TRK_LOST)    return "LOST";
    return "PAUSED";
}

static void draw_fox_hunt(void)
{
    mk_tracker_finder_t f;
    mk_fox_finder(&f);

    mk_gfx_clear();
    mk_gfx_header("Fox Hunt - WiFi");

    if (!f.has_target) {
        mk_gfx_text(MK_PAD, 110, "No target selected", MK_COL_MUTED);
        mk_gfx_footer("", "Back");
        mk_gfx_present();
        return;
    }

    char buf[48];
    fmt_mac(buf, sizeof(buf), f.mac);
    mk_gfx_text(MK_PAD, 32, buf, MK_COL_TEXT);
    mk_gfx_text(230, 32, f.type == MK_FOX_AP ? "AP" : "station", MK_COL_MUTED);

    uint32_t scol = (f.state == MK_TRK_LIVE) ? MK_COL_OK
                  : (f.state == MK_TRK_LOST) ? MK_COL_ERR : MK_COL_WARN;
    mk_gfx_text(MK_PAD, 52, fox_state_str(f.state), scol);

    int pct = clampi(f.strength, 0, 100);
    mk_gfx_rect(MK_PAD, 72, MK_SCREEN_W - 2 * MK_PAD, 26, MK_COL_BORDER);
    mk_gfx_fill_rect(MK_PAD + 2, 74, (MK_SCREEN_W - 2 * MK_PAD - 4) * pct / 100, 22,
                     pct >= 60 ? MK_COL_ACCENT : pct >= 30 ? MK_COL_WARN : MK_COL_ACCENT_DIM);
    mk_snprintf(buf, sizeof(buf), "%d%%  %ddBm", pct, f.filtered_rssi);
    mk_gfx_text(MK_PAD, 104, buf, MK_COL_TEXT);

    if (f.trend_ready) {
        const char* t = f.trend > 0 ? "STRONGER" : f.trend < 0 ? "WEAKER" : "STEADY";
        uint32_t tc = f.trend > 0 ? MK_COL_OK : f.trend < 0 ? MK_COL_ERR : MK_COL_MUTED;
        mk_gfx_text(200, 104, t, tc);
        if (f.trend != 0) {
            int yb = 112;
            if (f.trend > 0) mk_gfx_fill_triangle(300, yb - 8, 292, yb + 4, 308, yb + 4, MK_COL_OK);
            else             mk_gfx_fill_triangle(300, yb + 4, 292, yb - 8, 308, yb - 8, MK_COL_ERR);
        }
    }

    const int gx = MK_PAD, gy = 128, gw = MK_SCREEN_W - 2 * MK_PAD, gh = 56;
    mk_gfx_rect(gx, gy, gw, gh, MK_COL_BORDER);
    int hc = f.history_count;
    if (hc > MK_TRK_HISTORY) hc = MK_TRK_HISTORY;
    if (hc > 1) {
        for (int i = 1; i < hc; i++) {
            int p0 = clampi((f.history[i - 1] + 95) * (gh - 4) / 60, 0, gh - 4);
            int p1 = clampi((f.history[i]     + 95) * (gh - 4) / 60, 0, gh - 4);
            int x0 = gx + 2 + (i - 1) * (gw - 4) / (hc - 1);
            int x1 = gx + 2 + i * (gw - 4) / (hc - 1);
            mk_gfx_line(x0, gy + gh - 2 - p0, x1, gy + gh - 2 - p1, MK_COL_ACCENT);
        }
    } else {
        mk_gfx_text(gx + 6, gy + 20, "collecting samples...", MK_COL_MUTED);
    }

    mk_snprintf(buf, sizeof(buf), "age %lums", (unsigned long)f.age_ms);
    mk_gfx_text(MK_PAD, 190, buf, MK_COL_MUTED);
    mk_gfx_text(150, 190, "relative signal only", MK_COL_MUTED);

    mk_gfx_footer("", "Back");
    mk_gfx_present();
}

/* ── Portal Check ─────────────────────────────────────────────────────── */

static void pd_flag_str(char* buf, int n, uint16_t f)
{
    if      (f & MK_PD_OPEN_CLONE)     mk_snprintf(buf, n, "OPEN TWIN");
    else if (f & MK_PD_MULTI_OUI)      mk_snprintf(buf, n, "VENDOR MIX");
    else if (f & MK_PD_AUTH_DOWNGRADE) mk_snprintf(buf, n, "DOWNGRADE");
    else if (f & MK_PD_SIGNAL_JUMP)    mk_snprintf(buf, n, "LOUD CLONE");
    else if (f & MK_PD_MULTI_CHANNEL)  mk_snprintf(buf, n, "multi-ch");
    else                               mk_snprintf(buf, n, "-");
}

static int pd_is_serious(uint16_t f)
{
    return (f & (MK_PD_OPEN_CLONE | MK_PD_MULTI_OUI |
                 MK_PD_AUTH_DOWNGRADE | MK_PD_SIGNAL_JUMP)) != 0;
}

static void draw_portal_list(int sel, int scroll)
{
    mk_pd_stats_t st;
    mk_pd_stats(&st);
    g_pd_n = mk_pd_list(g_pd, MK_PD_MAX);

    mk_gfx_clear();
    mk_gfx_header("Portal Check");

    char buf[52];
    mk_snprintf(buf, sizeof(buf), "%u SSID (raw %u) %u flag s%u%s",
                st.ssids, st.raw_seen, st.flagged, st.scans,
                st.scanning ? ".." : "");
    mk_gfx_text(MK_PAD, 30, buf, st.flagged ? MK_COL_WARN : MK_COL_MUTED);

    if (g_pd_n <= 0) {
        mk_gfx_text(MK_PAD, 86, "Scanning for networks...", MK_COL_ACCENT);

        /* An empty list has three unrelated causes and they look identical
         * from a count of zero, so show which one this is. */
        if (!st.table_ok) {
            mk_gfx_text(MK_PAD, 112, "PSRAM table alloc FAILED", MK_COL_ERR);
        } else if (st.scan_rc != 0) {
            /* esp_err_t now, not an Arduino scan code: 0x300x is the esp_wifi
             * family (0x3002 = not started, 0x3006 = bad state). Checked
             * before the scans counter, which a failed scan never advances. */
            mk_snprintf(buf, sizeof(buf), "scan failed: esp_err 0x%04X",
                        (unsigned)(st.scan_rc & 0xFFFF));
            mk_gfx_text(MK_PAD, 112, buf, MK_COL_ERR);
        } else if (st.scans == 0) {
            mk_gfx_text(MK_PAD, 112, "no sweep finished yet", MK_COL_MUTED);
        } else if (st.raw_seen == 0) {
            mk_gfx_text(MK_PAD, 112, "scan OK, 0 APs in range", MK_COL_ERR);
        } else {
            mk_snprintf(buf, sizeof(buf), "raw %u  ok %u  hid %u full %u",
                        st.raw_seen, st.accepted, st.rej_hidden, st.rej_full);
            mk_gfx_text(MK_PAD, 112, buf, MK_COL_ERR);
        }
        mk_gfx_text(MK_PAD, 138, "A on an open net = probe", MK_COL_MUTED);
        mk_gfx_footer("", "Back");
        mk_gfx_present();
        return;
    }

    for (int i = 0; i < 5; i++) {
        int idx = scroll + i;
        if (idx >= g_pd_n) break;
        int y = 50 + i * 30;
        mk_pd_ssid_t* e = &g_pd[idx];
        uint32_t fg = (idx == sel) ? MK_COL_ACCENT
                    : pd_is_serious(e->flags) ? MK_COL_ERR : MK_COL_TEXT;
        mk_gfx_text(MK_PAD, y, e->ssid[0] ? e->ssid : "<hidden>", fg);
        char fl[16];
        pd_flag_str(fl, sizeof(fl), e->flags);
        mk_snprintf(buf, sizeof(buf), "%dx %ddBm %s", e->n_bssid, e->best_rssi, fl);
        mk_gfx_text(150, y + 13, buf,
                    pd_is_serious(e->flags) ? MK_COL_ERR : MK_COL_MUTED);
    }
    mk_gfx_footer("Probe", "Back");
    mk_gfx_present();
}

static const char* pd_verdict_str(unsigned v)
{
    if (v == MK_PD_VERDICT_CLEAR)     return "NO PORTAL";
    if (v == MK_PD_VERDICT_PORTAL)    return "CAPTIVE PORTAL";
    if (v == MK_PD_VERDICT_INTERCEPT) return "HTTP INTERCEPTED";
    if (v == MK_PD_VERDICT_NONET)     return "NO USABLE PATH";
    return "-";
}

/* Short tag per evidence bit, strongest first so a truncated list still
 * shows the load-bearing ones. */
static int pd_slen(const char* s) { int n = 0; while (s && s[n]) n++; return n; }

static int pd_rogue_tags(unsigned f, const char** out, int max)
{
    static const struct { unsigned bit; const char* tag; } T[] = {
        { MK_PD_RG_SOFTAP_GW,    "softap-gw"   },
        { MK_PD_RG_OPEN_CLONE,   "open-clone"  },
        { MK_PD_RG_IP_REDIRECT,  "ip-redirect" },
        { MK_PD_RG_MULTI_OUI,    "multi-oui"   },
        { MK_PD_RG_DNS_WILDCARD, "dns-wild"    },
        { MK_PD_RG_NO_SERVER,    "no-server"   },
        { MK_PD_RG_SIGNAL_JUMP,  "signal-jump" },
        { MK_PD_RG_FAST_LOCAL,   "local-rtt"   },
    };
    int n = 0;
    for (unsigned i = 0; i < sizeof(T) / sizeof(T[0]) && n < max; i++)
        if (f & T[i].bit) out[n++] = T[i].tag;
    return n;
}

static void draw_portal_probe(void)
{
    mk_pd_probe_t p;
    mk_pd_probe(&p);

    mk_gfx_clear();
    mk_gfx_header("Portal Probe");
    mk_gfx_text(MK_PAD, 32, p.ssid[0] ? p.ssid : "-", MK_COL_TEXT);

    if (p.state == MK_PD_PROBE_CONNECTING) {
        banner(56, " joining (open network)", MK_COL_WARN);
        mk_gfx_text(MK_PAD, 100, "No passphrase is sent.", MK_COL_MUTED);
        mk_gfx_text(MK_PAD, 122, "Disconnects when done.", MK_COL_MUTED);
        mk_gfx_footer("", "Cancel");
        mk_gfx_present();
        return;
    }
    if (p.state == MK_PD_PROBE_CHECKING) {
        banner(56, " checking HTTP path", MK_COL_WARN);
        mk_gfx_text(MK_PAD, 100, "GET generate_204 (cleartext)", MK_COL_MUTED);
        mk_gfx_footer("", "Cancel");
        mk_gfx_present();
        return;
    }
    if (p.state == MK_PD_PROBE_IDLE) {
        mk_gfx_text(MK_PAD, 100, "Select an open network", MK_COL_MUTED);
        mk_gfx_footer("", "Back");
        mk_gfx_present();
        return;
    }

    /* Lead with hostility, not with "a portal exists". Every hotel and cafe
     * network returns PD_VERDICT_PORTAL; that on its own is not a finding,
     * and heading the screen with it was misreporting benign networks. */
    char buf[64];
    const int conf = p.rogue_conf;
    uint32_t vc; const char* head;

    if (p.verdict == MK_PD_VERDICT_CLEAR)      { vc = MK_COL_OK;    head = " NO PORTAL"; }
    else if (p.verdict == MK_PD_VERDICT_NONET) { vc = MK_COL_MUTED; head = " NO USABLE PATH"; }
    else if (conf >= 70)                       { vc = MK_COL_ERR;   head = " LIKELY ROGUE PORTAL"; }
    else if (conf >= 40)                       { vc = MK_COL_WARN;  head = " SUSPICIOUS PORTAL"; }
    else                                       { vc = MK_COL_TEXT;  head = " PORTAL (looks normal)"; }
    banner(56, head, vc);

    if (p.verdict == MK_PD_VERDICT_CLEAR || p.verdict == MK_PD_VERDICT_NONET) {
        mk_gfx_text(MK_PAD, 92, pd_verdict_str(p.verdict), vc);
        mk_snprintf(buf, sizeof(buf), "%d", p.http_code);
        stat_row(120, "HTTP", p.http_code ? buf : "none", MK_COL_TEXT);
        mk_snprintf(buf, sizeof(buf), "%lums", (unsigned long)p.elapsed_ms);
        stat_row(142, "Took", buf, MK_COL_MUTED);
        mk_gfx_footer("Re-probe", "Back");
        mk_gfx_present();
        return;
    }

    mk_snprintf(buf, sizeof(buf), "%s  rogue %d%%  %d/%ums",
                pd_verdict_str(p.verdict), conf, p.http_code, p.rtt_ms);
    mk_gfx_text(MK_PAD, 88, buf, vc);

    /* The evidence, so the number can be argued with rather than trusted. */
    const char* tags[8];
    const int nt = pd_rogue_tags(p.rogue_flags, tags, 8);
    int y = 110;
    if (nt == 0) {
        mk_gfx_text(MK_PAD, y, "no rogue indicators", MK_COL_MUTED);
        y += 20;
    } else {
        char line[44];
        int col = 0;
        line[0] = 0;
        for (int i = 0; i < nt; i++) {
            const int len = pd_slen(tags[i]);
            if (col && col + len + 1 > 38) {
                mk_gfx_text(MK_PAD, y, line, MK_COL_ERR);
                y += 18; col = 0; line[0] = 0;
            }
            if (col) { line[col++] = ' '; line[col] = 0; }
            for (int k = 0; k < len; k++) line[col + k] = tags[i][k];
            col += len; line[col] = 0;
        }
        if (col) { mk_gfx_text(MK_PAD, y, line, MK_COL_ERR); y += 18; }
        y += 4;
    }

    mk_snprintf(buf, sizeof(buf), "%s", p.gateway[0] ? p.gateway : "-");
    stat_row(y, "Gateway", buf, (p.rogue_flags & MK_PD_RG_SOFTAP_GW) ? MK_COL_ERR
                                                                     : MK_COL_TEXT);
    y += 20;
    mk_snprintf(buf, sizeof(buf), "%s", p.server[0] ? p.server : "(none)");
    stat_row(y, "Server", buf, MK_COL_MUTED); y += 20;

    if (p.redirect[0]) {
        /* stat_row's value column runs from x=120 to the right edge: about
         * 24 glyphs. Anything longer wrapped into the footer. */
        char l1[25];
        int i = 0; for (; i < 24 && p.redirect[i]; i++) l1[i] = p.redirect[i];
        l1[i] = 0;
        stat_row(y, "Redirect", l1, MK_COL_ERR);
    }

    mk_gfx_footer("Re-probe", "Back");
    mk_gfx_present();
}

/* ── main ─────────────────────────────────────────────────────────────── */

int app_main(int argc, char** argv)
{
    (void)argc; (void)argv;

    /* The app and the firmware ship separately — app.elf lives on the SD card.
     * If they were built against different revisions of mk_app_abi.h, struct
     * offsets no longer line up and screens read the wrong bytes with no
     * crash to point at it. Fail loudly instead. */
    const uint32_t fw_abi = mk_abi_version();
    if (fw_abi != MK_ABI_VERSION) {
        for (int i = 0; i < 400; i++) {
            mk_input_poll();
            if (mk_btn(MK_BTN_B) || mk_btn_long(MK_BTN_B) || mk_btn(MK_BTN_A)) break;
            if (i == 0) {
                char b[48];
                mk_gfx_clear();
                mk_gfx_header("Version mismatch");
                mk_gfx_text(MK_PAD, 50, "Firmware and app disagree", MK_COL_ERR);
                mk_gfx_text(MK_PAD, 70, "about the app ABI.", MK_COL_ERR);
                mk_snprintf(b, sizeof(b), "firmware ABI: %lu", (unsigned long)fw_abi);
                mk_gfx_text(MK_PAD, 102, b, MK_COL_TEXT);
                mk_snprintf(b, sizeof(b), "this app:     %lu", (unsigned long)MK_ABI_VERSION);
                mk_gfx_text(MK_PAD, 122, b, MK_COL_TEXT);
                mk_gfx_text(MK_PAD, 154, "Update both: firmware.bin", MK_COL_MUTED);
                mk_gfx_text(MK_PAD, 174, "and /apps/meowrauder/app.elf", MK_COL_MUTED);
                mk_gfx_footer("", "Exit");
                mk_gfx_present();
            }
            mk_delay(20);
        }
        return -1;
    }

    mk_wifi_begin();

    int sel = 0, scroll = 0;
    int isel = 0, iscroll = 0;
    int dirty = 1;
    uint32_t last_refresh = 0;

    for (;;) {
        mk_input_poll();
        service_pump();

        if (mk_btn_long(MK_BTN_B)) break;          /* hold B → exit anywhere */

        if (g_screen == S_MENU) {
            int vis = mk_content_rows();
            if (mk_btn(MK_BTN_UP) && sel > 0) {
                sel--; if (sel < scroll) scroll = sel; dirty = 1;
            }
            if (mk_btn(MK_BTN_DOWN) && sel < MENU_N - 1) {
                sel++; if (sel >= scroll + vis) scroll = sel - vis + 1; dirty = 1;
            }
            if (mk_btn(MK_BTN_A)) {
                g_screen = MENU_SCREEN[sel];
                isel = 0; iscroll = 0;
                if (g_screen == S_CHAN) do_scan();
                else                    service_start(g_screen);
                dirty = 1;
            }
        }
        else if (g_screen == S_CHAN) {
            if (mk_btn(MK_BTN_A)) { do_scan(); dirty = 1; }
            if (mk_btn(MK_BTN_B)) { g_screen = S_MENU; dirty = 1; }
        }
        else if (g_screen == S_PCAP) {
            mk_pcap_stats_t st; mk_pcap_stats(&st);
            if (mk_btn(MK_BTN_A)) {
                if (st.running) mk_pcap_stop();
                else          { mk_pcap_begin(1, 1); g_active = S_PCAP; }
                dirty = 1;
            }
            if (mk_btn(MK_BTN_UP))    { mk_pcap_set_channel(0); dirty = 1; }
            if (mk_btn(MK_BTN_LEFT))  { int c = st.channel > 1  ? st.channel - 1 : 13;
                                        mk_pcap_set_channel(c); dirty = 1; }
            if (mk_btn(MK_BTN_RIGHT)) { int c = st.channel < 13 ? st.channel + 1 : 1;
                                        mk_pcap_set_channel(c); dirty = 1; }
            if (mk_btn(MK_BTN_B)) { services_stop(); g_screen = S_MENU; dirty = 1; }
            uint32_t now = mk_millis();
            if (now - last_refresh >= 250) { last_refresh = now; dirty = 1; }
        }
        else if (g_screen == S_PMKID) {
            mk_eapol_stats_t es; mk_eapol_stats(&es);
            if (mk_btn(MK_BTN_A)) {
                if (es.running) mk_eapol_stop();
                else          { mk_eapol_begin(1, 1); g_active = S_PMKID; }
                dirty = 1;
            }
            if (mk_btn(MK_BTN_B)) { services_stop(); g_screen = S_MENU; dirty = 1; }
            uint32_t now = mk_millis();
            if (now - last_refresh >= 400) { last_refresh = now; dirty = 1; }
        }
        else if (g_screen == S_AUDIT) {
            if (mk_btn(MK_BTN_UP) && isel > 0) {
                isel--; if (isel < iscroll) iscroll = isel; dirty = 1;
            }
            if (mk_btn(MK_BTN_DOWN) && isel < g_wa_n - 1) {
                isel++; if (isel >= iscroll + 5) iscroll = isel - 4; dirty = 1;
            }
            if (mk_btn(MK_BTN_A) && g_wa_n > 0) { g_screen = S_AUDITDETAIL; dirty = 1; }
            if (mk_btn(MK_BTN_B)) { services_stop(); g_screen = S_MENU; dirty = 1; }
            uint32_t now = mk_millis();
            if (now - last_refresh >= 600) { last_refresh = now; dirty = 1; }
        }
        else if (g_screen == S_AUDITDETAIL) {
            /* The twin is only reachable from a selected AP, so the SSID it
             * clones is always one the operator picked deliberately. */
            if (mk_btn(MK_BTN_A) && g_wa_n > 0 && isel < g_wa_n &&
                g_wa[isel].ssid[0]) {          /* need a name to impersonate */
                services_stop();
                g_active = S_TWIN;
                g_screen = S_TWIN;
                dirty = 1;
            }
            if (mk_btn(MK_BTN_B)) { g_screen = S_AUDIT; dirty = 1; }
        }
        else if (g_screen == S_TWIN) {
            mk_twin_stats_t ts; mk_twin_stats(&ts);
            if (mk_btn(MK_BTN_A)) {
                if (ts.running) mk_twin_stop();
                else if (g_wa_n > 0 && isel < g_wa_n)
                    mk_twin_begin(g_wa[isel].ssid, "default", g_wa[isel].channel);
                dirty = 1;
            }
            if (mk_btn(MK_BTN_B)) {
                mk_twin_stop();
                g_active = 0;
                g_screen = S_AUDITDETAIL;
                dirty = 1;
            }
            uint32_t now = mk_millis();
            if (now - last_refresh >= 300) { last_refresh = now; dirty = 1; }
        }
        else if (g_screen == S_TOOLS) {
            mk_td_stats_t ts; mk_td_stats(&ts);
            if (mk_btn(MK_BTN_UP) && isel > 0) {
                isel--; if (isel < iscroll) iscroll = isel; dirty = 1;
            }
            if (mk_btn(MK_BTN_DOWN) && isel < g_td_n - 1) {
                isel++; if (isel >= iscroll + 5) iscroll = isel - 4; dirty = 1;
            }
            if (mk_btn(MK_BTN_A)) {
                if (g_td_n > 0 && isel < g_td_n) { g_screen = S_TOOLDETAIL; }
                else {
                    /* nothing listed yet: A swaps radio, since the two contend */
                    mk_td_stop();
                    mk_td_begin(ts.mode == MK_TD_MODE_WIFI ? MK_TD_MODE_BLE
                                                           : MK_TD_MODE_WIFI);
                    g_active = S_TOOLS;
                }
                dirty = 1;
            }
            if (mk_btn(MK_BTN_LEFT) || mk_btn(MK_BTN_RIGHT)) {
                mk_td_stop();
                mk_td_begin(ts.mode == MK_TD_MODE_WIFI ? MK_TD_MODE_BLE
                                                       : MK_TD_MODE_WIFI);
                g_active = S_TOOLS;
                isel = 0; iscroll = 0;
                dirty = 1;
            }
            if (mk_btn(MK_BTN_B)) { services_stop(); g_screen = S_MENU; dirty = 1; }
            uint32_t now = mk_millis();
            if (now - last_refresh >= 500) { last_refresh = now; dirty = 1; }
        }
        else if (g_screen == S_TOOLDETAIL) {
            if (mk_btn(MK_BTN_B)) { g_screen = S_TOOLS; dirty = 1; }
            uint32_t now = mk_millis();
            if (now - last_refresh >= 500) { last_refresh = now; dirty = 1; }
        }
        else if (g_screen == S_WFOX) {
            static mk_fox_target_t wl[MK_FOX_MAX];
            int n = mk_fox_list(wl, MK_FOX_MAX);
            if (mk_btn(MK_BTN_UP) && isel > 0) {
                isel--; if (isel < iscroll) iscroll = isel; dirty = 1;
            }
            if (mk_btn(MK_BTN_DOWN) && isel < n - 1) {
                isel++; if (isel >= iscroll + 5) iscroll = isel - 4; dirty = 1;
            }
            if (mk_btn(MK_BTN_A) && n > 0 && isel < n) {
                if (mk_fox_select(wl[isel].id)) { g_screen = S_WFOXHUNT; dirty = 1; }
            }
            if (mk_btn(MK_BTN_B)) { services_stop(); g_screen = S_MENU; dirty = 1; }
            uint32_t now = mk_millis();
            if (now - last_refresh >= 400) { last_refresh = now; dirty = 1; }
        }
        else if (g_screen == S_WFOXHUNT) {
            mk_fox_loop();
            if (mk_btn(MK_BTN_B)) { mk_fox_select(0); g_screen = S_WFOX; dirty = 1; }
            uint32_t now = mk_millis();
            if (now - last_refresh >= 200) { last_refresh = now; dirty = 1; }
        }
        else if (g_screen == S_PORTAL) {
            if (mk_btn(MK_BTN_UP) && isel > 0) {
                isel--; if (isel < iscroll) iscroll = isel; dirty = 1;
            }
            if (mk_btn(MK_BTN_DOWN) && isel < g_pd_n - 1) {
                isel++; if (isel >= iscroll + 5) iscroll = isel - 4; dirty = 1;
            }
            if (mk_btn(MK_BTN_A) && g_pd_n > 0 && isel < g_pd_n) {
                /* probe_begin refuses anything that is not open */
                if (mk_pd_probe_begin(g_pd[isel].ssid)) { g_screen = S_PORTALPROBE; dirty = 1; }
            }
            if (mk_btn(MK_BTN_B)) { services_stop(); g_screen = S_MENU; dirty = 1; }
            uint32_t now = mk_millis();
            if (now - last_refresh >= 500) { last_refresh = now; dirty = 1; }
        }
        else if (g_screen == S_PORTALPROBE) {
            mk_pd_loop();
            mk_pd_probe_t pp; mk_pd_probe(&pp);
            if (mk_btn(MK_BTN_A) && (pp.state == MK_PD_PROBE_DONE ||
                                     pp.state == MK_PD_PROBE_FAILED)) {
                mk_pd_probe_begin(g_pd[isel].ssid); dirty = 1;
            }
            if (mk_btn(MK_BTN_B)) { mk_pd_probe_stop(); g_screen = S_PORTAL; dirty = 1; }
            uint32_t now = mk_millis();
            if (now - last_refresh >= 250) { last_refresh = now; dirty = 1; }
        }

        if (dirty) {
            if      (g_screen == S_MENU)        draw_menu(sel, scroll);
            else if (g_screen == S_CHAN)        draw_chan_map();
            else if (g_screen == S_PCAP)        draw_pcap();
            else if (g_screen == S_PMKID)       draw_pmkid();
            else if (g_screen == S_AUDIT)       draw_audit_list(isel, iscroll);
            else if (g_screen == S_AUDITDETAIL) draw_audit_detail(&g_wa[isel]);
            else if (g_screen == S_TWIN)        draw_twin();
            else if (g_screen == S_TOOLS)       draw_tools(isel, iscroll);
            else if (g_screen == S_TOOLDETAIL)  draw_tool_detail(&g_td[isel]);
            else if (g_screen == S_WFOX)        draw_wfox_list(isel, iscroll);
            else if (g_screen == S_WFOXHUNT)    draw_fox_hunt();
            else if (g_screen == S_PORTAL)      draw_portal_list(isel, iscroll);
            else if (g_screen == S_PORTALPROBE) draw_portal_probe();
            dirty = 0;
        }
        mk_delay(20);
    }

    services_stop();
    return 0;
}
