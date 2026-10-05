/* Headless simulator for MeowKit **native ELF apps**.
 *
 * The two existing sims cover built-in screens: sim/ renders LVGL system
 * screens, sim/tui/ renders MK_TUI app screens. Neither can see a native SD
 * app, because those draw through the flat mk_app ABI (mk_app_abi.h) rather
 * than calling MK_TUI directly.
 *
 * This runs an app's real app_main() on the desktop: every mk_* symbol is
 * implemented here against an off-screen LGFX_Sprite, exactly the way
 * src/system/app_sdk.cpp implements them on device (same MK_TUI helpers, same
 * efontCN_16 font), so the pixels match. Radio calls return scripted sample
 * data; buttons come from a --keys script.
 *
 *   cmake -S sim/app -B sim/app/build -DAPP_SRC="sd files/apps/meowrauder/app_main.c"
 *   cmake --build sim/app/build
 *   sim/app/build/meowkit-app --keys "A" --out shot.bmp
 */
#define LGFX_USE_V1
#include <LovyanGFX.hpp>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

#include "mk_tui.h"
extern "C" {
#include "mk_app_abi.h"
}

/* ── canvas ──────────────────────────────────────────────────────────── */
static lgfx::LGFX_Sprite canvas;
static std::string  g_out   = "app.bmp";
static int          g_frame = 0;
static bool         g_all   = false;   /* --frames: write every present() */

/* Write an RGB565 sprite as a 24-bit BMP (bottom-up BGR). */
static int save_bmp565(const char* path, const uint16_t* fb, int W, int H)
{
    FILE* f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "open %s failed\n", path); return 1; }
    const int row = W * 3, pad = (4 - (row % 4)) % 4, img = (row + pad) * H, off = 54;
    uint8_t hdr[54] = {0};
    hdr[0] = 'B'; hdr[1] = 'M';
    uint32_t fsz = off + img;              memcpy(&hdr[2],  &fsz, 4);
    uint32_t o   = off;                    memcpy(&hdr[10], &o,   4);
    uint32_t ih  = 40;                     memcpy(&hdr[14], &ih,  4);
    int32_t  w = W, h = H;                 memcpy(&hdr[18], &w, 4); memcpy(&hdr[22], &h, 4);
    uint16_t planes = 1, bpp = 24;         memcpy(&hdr[26], &planes, 2); memcpy(&hdr[28], &bpp, 2);
    fwrite(hdr, 1, 54, f);
    std::vector<uint8_t> line(row + pad, 0);
    for (int y = H - 1; y >= 0; y--) {
        for (int x = 0; x < W; x++) {
            uint16_t p = fb[y * W + x];
            p = (uint16_t)((p >> 8) | (p << 8));    /* sprite stores byte-swapped */
            line[x * 3 + 0] = (uint8_t)((p & 0x1F) << 3);          /* B */
            line[x * 3 + 1] = (uint8_t)(((p >> 5) & 0x3F) << 2);   /* G */
            line[x * 3 + 2] = (uint8_t)(((p >> 11) & 0x1F) << 3);  /* R */
        }
        fwrite(line.data(), 1, row + pad, f);
    }
    fclose(f);
    return 0;
}

/* ── scripted input ──────────────────────────────────────────────────
 * One script step is consumed per mk_input_poll(). Once the script runs out
 * we let a few frames render, then report a long-B so app_main() returns. */
static std::vector<int> g_keys;      /* button id, or -1 = idle, -2 = long B */
static size_t g_step   = 0;
static int    g_cur    = -1;
static int    g_curLong= 0;
static int    g_tail   = 0;
static int    g_tailMax= 3;

static int key_of(const std::string& s)
{
    if (s == "U" || s == "u") return MK_BTN_UP;
    if (s == "D" || s == "d") return MK_BTN_DOWN;
    if (s == "L" || s == "l") return MK_BTN_LEFT;
    if (s == "R" || s == "r") return MK_BTN_RIGHT;
    if (s == "A" || s == "a") return MK_BTN_A;
    if (s == "B")             return MK_BTN_B;
    if (s == "b")             return -2;          /* hold B (exit) */
    return -1;                                    /* "." = idle frame */
}

/* ── sample radio data ───────────────────────────────────────────────── */
static const struct { const char* ssid; int8_t rssi; uint8_t ch, enc, auth; uint8_t b[6]; } APS[] = {
    {"HomeNet-5G",      -42, 6,  1, 4, {0xA4,0x2B,0xB0,0x11,0x22,0x33}},
    {"CafeGuest",       -58, 1,  0, 0, {0x00,0x1A,0x2B,0x44,0x55,0x66}},
    {"Lobby Guest",     -61, 11, 1, 6, {0xDE,0xAD,0xBE,0xEF,0x01,0x02}},
    {"linksys",         -70, 6,  1, 1, {0x00,0x25,0x9C,0xAA,0xBB,0xCC}},
    {"",                -74, 3,  1, 3, {0x12,0x34,0x56,0x78,0x9A,0xBC}},
    {"Pixel_1234",      -79, 11, 1, 7, {0x3C,0x5A,0xB4,0x00,0x11,0x22}},
    {"printer-setup",   -83, 1,  0, 0, {0x9C,0x93,0x4E,0x77,0x88,0x99}},
    {"ATT-Fiber-8821",  -88, 6,  1, 4, {0x7C,0xD9,0x5C,0x12,0x34,0x56}},
};
static const int NAPS = (int)(sizeof(APS) / sizeof(APS[0]));

static uint32_t g_ms = 0;

/* ── display ABI ─────────────────────────────────────────────────────── */
void mk_gfx_clear(void)                                  { MK_TUI::clearScreen(canvas); }
void mk_gfx_header(const char* t)                        { MK_TUI::drawHeader(canvas, t); }
void mk_gfx_footer(const char* l, const char* r)         { MK_TUI::drawFooter(canvas, l, r); }
void mk_gfx_menu_item(int row, const char* n, const char* v, int sel)
                                                         { MK_TUI::drawMenuItem(canvas, row, n, v, sel != 0); }
static void draw_text(int x, int y, const char* s, uint32_t c, int size)
{
    canvas.setFont(&fonts::efontCN_16);
    canvas.setTextColor(c);
    canvas.setTextSize(size < 1 ? 1 : size);
    canvas.setCursor(x, y);
    canvas.print(s);
    canvas.setTextSize(1);
}
void mk_gfx_text(int x, int y, const char* s, uint32_t c)            { draw_text(x, y, s, c, 1); }
void mk_gfx_text_sz(int x, int y, const char* s, uint32_t c, int sz) { draw_text(x, y, s, c, sz); }
void mk_gfx_fill_rect(int x,int y,int w,int h,uint32_t c)            { canvas.fillRect(x,y,w,h,c); }
void mk_gfx_rect(int x,int y,int w,int h,uint32_t c)                 { canvas.drawRect(x,y,w,h,c); }
void mk_gfx_fill_round_rect(int x,int y,int w,int h,int r,uint32_t c){ canvas.fillRoundRect(x,y,w,h,r,c); }
void mk_gfx_circle(int x,int y,int r,uint32_t c)                     { canvas.drawCircle(x,y,r,c); }
void mk_gfx_fill_circle(int x,int y,int r,uint32_t c)                { canvas.fillCircle(x,y,r,c); }
void mk_gfx_fill_triangle(int a,int b,int c2,int d,int e,int f,uint32_t c){ canvas.fillTriangle(a,b,c2,d,e,f,c); }
void mk_gfx_line(int x0,int y0,int x1,int y1,uint32_t c)             { canvas.drawLine(x0,y0,x1,y1,c); }
int  mk_content_rows(void)                                           { return MK_LAYOUT::CONTENT_ROWS; }

void mk_gfx_present(void)
{
    const uint16_t* fb = (const uint16_t*)canvas.getBuffer();
    char path[512];
    if (g_all) snprintf(path, sizeof(path), "%s.%03d.bmp", g_out.c_str(), g_frame);
    else       snprintf(path, sizeof(path), "%s", g_out.c_str());
    save_bmp565(path, fb, MK_LAYOUT::W, MK_LAYOUT::H);
    g_frame++;
}

/* ── WiFi ────────────────────────────────────────────────────────────── */
void mk_wifi_begin(void) {}
int  mk_wifi_scan(mk_ap_t* out, int max)
{
    int n = NAPS < max ? NAPS : max;
    for (int i = 0; i < n; i++) {
        memset(&out[i], 0, sizeof(out[i]));
        snprintf(out[i].ssid, sizeof(out[i].ssid), "%s", APS[i].ssid);
        out[i].rssi = APS[i].rssi; out[i].channel = APS[i].ch;
        out[i].encrypted = APS[i].enc; out[i].auth = APS[i].auth;
        memcpy(out[i].bssid, APS[i].b, 6);
    }
    return n;
}

/* ── deauth monitor ──────────────────────────────────────────────────── */
static int s_deauth_on = 0;
void mk_deauth_begin(void){ s_deauth_on=1; } void mk_deauth_loop(void){}
void mk_deauth_pause(void){} void mk_deauth_resume(void){}
void mk_deauth_stop(void){ s_deauth_on=0; } int mk_deauth_running(void){ return s_deauth_on; }
void mk_deauth_stats(mk_deauth_stats_t* o)
{ *o = mk_deauth_stats_t{ 1843, 12, 41, 6, 1, 96, (uint8_t)s_deauth_on }; }
int  mk_deauth_history(uint16_t* o, int max)
{
    static const uint16_t H[]={0,0,1,0,2,1,0,4,9,14,22,31,41,38,29,18,11,7,4,2,1,0,0,1,0,0,2,1,0,0};
    int n=(int)(sizeof(H)/sizeof(H[0])); if(n>max)n=max; memcpy(o,H,n*sizeof(uint16_t)); return n;
}
int  mk_deauth_attackers(mk_attacker_t* o, int max)
{
    static const mk_attacker_t A[]={
        {{0xDE,0xAD,0xBE,0xEF,0x01,0x02},{0xA4,0x2B,0xB0,0x11,0x22,0x33},412,-38,6},
        {{0x00,0x1A,0x2B,0x44,0x55,0x66},{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},197,-57,6},
        {{0x12,0x34,0x56,0x78,0x9A,0xBC},{0x7C,0xD9,0x5C,0x12,0x34,0x56}, 63,-71,6},
    };
    int n=3; if(n>max)n=max; memcpy(o,A,n*sizeof(mk_attacker_t)); return n;
}

/* ── beacon-flood monitor ────────────────────────────────────────────── */
static int s_flood_on=0;
void mk_flood_begin(void){ s_flood_on=1; } void mk_flood_loop(void){}
void mk_flood_pause(void){} void mk_flood_resume(void){}
void mk_flood_stop(void){ s_flood_on=0; } int mk_flood_running(void){ return s_flood_on; }
void mk_flood_stats(mk_flood_stats_t* o)
{ *o = mk_flood_stats_t{ 9421, 188, 37, 54, 44, 1, 6, 143, (uint8_t)s_flood_on }; }
int  mk_flood_history(uint16_t* o, int max)
{
    static const uint16_t H[]={4,6,5,9,12,18,31,52,88,121,165,188,174,151,132,119,101,94,88,76,64,55,41,33,27,19,14,11,8,6};
    int n=(int)(sizeof(H)/sizeof(H[0])); if(n>max)n=max; memcpy(o,H,n*sizeof(uint16_t)); return n;
}

/* ── BLE-spam monitor ────────────────────────────────────────────────── */
static int s_ble_on=0;
void mk_blespam_begin(void){ s_ble_on=1; } void mk_blespam_loop(void){}
void mk_blespam_pause(void){} void mk_blespam_resume(void){}
void mk_blespam_stop(void){ s_ble_on=0; } int mk_blespam_running(void){ return s_ble_on; }
void mk_blespam_stats(mk_blespam_stats_t* o)
{ *o = mk_blespam_stats_t{ 2764, 46, 71, 1, 38, 12, 4, 9, 71, (uint8_t)s_ble_on }; }
int  mk_blespam_history(uint16_t* o, int max)
{
    static const uint16_t H[]={1,0,2,3,8,14,23,37,46,41,33,29,24,18,14,11,9,7,6,4,3,2,2,1,1,0,0,1,0,0};
    int n=(int)(sizeof(H)/sizeof(H[0])); if(n>max)n=max; memcpy(o,H,n*sizeof(uint16_t)); return n;
}

/* ── probe sniffer ───────────────────────────────────────────────────── */
static int s_probe_on=0;
void mk_probe_begin(void){ s_probe_on=1; } void mk_probe_loop(void){}
void mk_probe_pause(void){} void mk_probe_resume(void){}
void mk_probe_stop(void){ s_probe_on=0; } int mk_probe_running(void){ return s_probe_on; }
void mk_probe_stats(mk_probe_stats_t* o)
{ *o = mk_probe_stats_t{ 612, 9, 24, 7, 6, 74, (uint8_t)s_probe_on }; }
int  mk_probe_history(uint16_t* o, int max)
{
    static const uint16_t H[]={1,2,1,3,4,2,6,9,7,5,8,11,9,6,4,3,5,7,6,4,3,2,4,3,2,1,2,1,1,0};
    int n=(int)(sizeof(H)/sizeof(H[0])); if(n>max)n=max; memcpy(o,H,n*sizeof(uint16_t)); return n;
}
int  mk_probe_devices(mk_probe_dev_t* o, int max)
{
    static const mk_probe_dev_t D[]={
        {{0x3C,0x5A,0xB4,0x00,0x11,0x22},"HomeNet-5G",   58,-44,6},
        {{0x9C,0x93,0x4E,0x77,0x88,0x99},"CafeGuest",    31,-63,1},
        {{0x7C,0xD9,0x5C,0x12,0x34,0x56},"",            22,-71,6},
        {{0xA4,0x2B,0xB0,0x11,0x22,0x33},"Pixel_1234",  14,-78,11},
        {{0x00,0x25,0x9C,0xAA,0xBB,0xCC},"eduroam",      9,-84,6},
    };
    int n=5; if(n>max)n=max; memcpy(o,D,n*sizeof(mk_probe_dev_t)); return n;
}

/* ── tracker detector ────────────────────────────────────────────────── */
static int s_trk_on=0;
static uint32_t s_trk_sel=0;
void mk_tracker_begin(void){ s_trk_on=1; } void mk_tracker_loop(void){}
void mk_tracker_pause(void){} void mk_tracker_resume(void){}
void mk_tracker_stop(void){ s_trk_on=0; } int mk_tracker_running(void){ return s_trk_on; }
int  mk_tracker_starting(void){ return 0; }
int  mk_tracker_error(char* o, int max){ (void)o;(void)max; return 0; }
void mk_tracker_stats(mk_tracker_stats_t* o)
{ *o = mk_tracker_stats_t{ 3, 2, 1, (uint8_t)s_trk_on }; }   /* 2 exceed MK_TRK_PERSIST_MS */
int  mk_tracker_list(mk_tracker_t* o, int max)
{
    static const mk_tracker_t T[]={
        {{0x4C,0x8D,0x3B,0x11,0x22,0x33},MK_TRK_APPLE,  -47,318,  1000,121000,1,-46,1},
        {{0x88,0x4A,0xEA,0x44,0x55,0x66},MK_TRK_TILE,   -68, 94, 52000,120400,2,-69,1},
        {{0x6C,0x2F,0x2C,0x77,0x88,0x99},MK_TRK_SAMSUNG,-81, 21,104000,119800,3,-80,1},
    };
    int n=3; if(n>max)n=max; memcpy(o,T,n*sizeof(mk_tracker_t)); return n;
}
int  mk_tracker_select(uint32_t id){ s_trk_sel = id; return 1; }
void mk_tracker_finder(mk_tracker_finder_t* o)
{
    memset(o, 0, sizeof(*o));
    if (!s_trk_sel) return;
    o->has_target    = 1;
    o->state         = MK_TRK_LIVE;
    o->trend_ready   = 1;
    o->trend         = 1;                     /* closing in */
    o->filtered_rssi = -46;
    o->strength      = (o->filtered_rssi + 95) * 100 / 60;
    o->age_ms        = 340;
    o->target_id     = s_trk_sel;
    o->type          = MK_TRK_APPLE;
    const uint8_t mac[6] = {0x4C,0x8D,0x3B,0x11,0x22,0x33};
    memcpy(o->mac, mac, 6);
    /* a rising-then-noisy approach curve */
    static const int16_t H[] = {-82,-80,-81,-78,-76,-77,-74,-71,-72,-69,-66,-67,
                                -63,-61,-62,-58,-56,-57,-53,-51,-52,-49,-47,-46};
    o->history_count = (uint16_t)(sizeof(H)/sizeof(H[0]));
    memcpy(o->history, H, sizeof(H));
}

/* ── media (unused by recon apps, stubbed for completeness) ──────────── */
int  mk_media_begin(void){ return 1; }
void mk_media_end(void){}
void mk_media_cmd(int a,int v){ (void)a;(void)v; }
void mk_media_status(mk_media_status_t* o){ memset(o,0,sizeof(*o)); snprintf(o->state,sizeof(o->state),"idle"); }
int  mk_media_tracks(int off, mk_track_t* o, int max){ (void)off;(void)o;(void)max; return 0; }
void mk_media_set_output(int spk){ (void)spk; }

/* ── PCAP capture ────────────────────────────────────────────────────── */
static int      s_pcap_on = 0;
static uint32_t s_pcap_frames = 0;
void mk_pcap_loop(void)   { if (s_pcap_on) s_pcap_frames += 7; }
void mk_pcap_pause(void)  {}
void mk_pcap_resume(void) { s_pcap_on = 1; }
void mk_pcap_stop(void)   { s_pcap_on = 0; }
int  mk_pcap_running(void){ return s_pcap_on; }
static uint8_t s_pcap_ch = 1; static uint8_t s_pcap_hop = 1;
int  mk_pcap_begin(int hop, int channel)
{
    s_pcap_on = 1; s_pcap_hop = (uint8_t)(hop != 0);
    s_pcap_ch = (uint8_t)((channel >= 1 && channel <= 14) ? channel : 6);
    s_pcap_frames = 4193;                    /* mid-capture, so the screen is full */
    return 1;
}
void mk_pcap_set_channel(int channel)
{
    if (channel == 0) { s_pcap_hop = 1; return; }
    s_pcap_hop = 0; s_pcap_ch = (uint8_t)channel;
}
void mk_pcap_stats(mk_pcap_stats_t* o)
{
    memset(o, 0, sizeof(*o));
    o->frames  = s_pcap_frames;
    o->dropped = 12;
    o->bytes   = 24u + s_pcap_frames * 214u;
    o->rate    = 63; o->peak = 142;
    o->channel = s_pcap_hop ? 6 : s_pcap_ch;
    o->hopping = s_pcap_hop;
    o->running = (uint8_t)s_pcap_on;
    o->uptime_s = 67;
    snprintf(o->path, sizeof(o->path), "/pcap/cap_003.pcap");
}
int mk_pcap_history(uint16_t* o, int max)
{
    static const uint16_t H[]={12,18,24,31,44,58,71,63,55,49,61,74,88,102,
                               142,121,98,84,76,69,63,58,51,47,44,39,35,31,27,24};
    int n=(int)(sizeof(H)/sizeof(H[0])); if(n>max)n=max;
    memcpy(o,H,n*sizeof(uint16_t)); return n;
}

/* ── WiFi Fox Hunt ───────────────────────────────────────────────────── */
static int      s_fox_on = 0;
static uint32_t s_fox_sel = 0;
static const struct { const char* ssid; uint8_t kind, ch; int16_t f; uint8_t m[6]; } FOX[] = {
    {"HomeNet-5G",   MK_FOX_AP,  6, -41, {0xA4,0x2B,0xB0,0x11,0x22,0x33}},
    {"",             MK_FOX_STA, 6, -52, {0x3C,0x5A,0xB4,0x00,0x11,0x22}},
    {"CafeGuest",    MK_FOX_AP,  1, -59, {0x00,0x1A,0x2B,0x44,0x55,0x66}},
    {"Lobby Guest",  MK_FOX_AP, 11, -64, {0xDE,0xAD,0xBE,0xEF,0x01,0x02}},
    {"",             MK_FOX_STA,11, -73, {0x9C,0x93,0x4E,0x77,0x88,0x99}},
    {"linksys",      MK_FOX_AP,  6, -81, {0x00,0x25,0x9C,0xAA,0xBB,0xCC}},
};
static const int NFOX = (int)(sizeof(FOX)/sizeof(FOX[0]));

void mk_fox_begin(void) { s_fox_on = 1; }
void mk_fox_loop(void)  {}
void mk_fox_pause(void) {}
void mk_fox_resume(void){ s_fox_on = 1; }
void mk_fox_stop(void)  { s_fox_on = 0; s_fox_sel = 0; }
int  mk_fox_running(void){ return s_fox_on; }
void mk_fox_stats(mk_fox_stats_t* o)
{
    memset(o, 0, sizeof(*o));
    o->targets = NFOX; o->aps = 4; o->stations = 2;
    o->channel = 6; o->hopping = 1; o->running = (uint8_t)s_fox_on;
}
int mk_fox_list(mk_fox_target_t* o, int max)
{
    int n = NFOX < max ? NFOX : max;
    for (int i = 0; i < n; i++) {
        memset(&o[i], 0, sizeof(o[i]));
        snprintf(o[i].ssid, sizeof(o[i].ssid), "%s", FOX[i].ssid);
        memcpy(o[i].mac, FOX[i].m, 6);
        o[i].kind = FOX[i].kind; o[i].channel = FOX[i].ch;
        o[i].filtered_rssi = FOX[i].f; o[i].rssi = (int8_t)FOX[i].f;
        o[i].count = (uint16_t)(120 - i * 14);
        o[i].id = (uint32_t)(i + 1);
    }
    return n;
}
int  mk_fox_select(uint32_t id){ s_fox_sel = id; return 1; }
void mk_fox_set_channel(int c) { (void)c; }
void mk_fox_finder(mk_tracker_finder_t* o)
{
    memset(o, 0, sizeof(*o));
    if (!s_fox_sel) return;
    int i = (int)s_fox_sel - 1; if (i < 0 || i >= NFOX) i = 0;
    o->has_target = 1; o->state = MK_TRK_LIVE;
    o->trend_ready = 1; o->trend = -1;              /* drifting away */
    o->filtered_rssi = FOX[i].f;
    o->strength = (int16_t)((FOX[i].f + 95) * 100 / 60);
    o->age_ms = 120; o->target_id = s_fox_sel;
    o->type = FOX[i].kind;
    memcpy(o->mac, FOX[i].m, 6);
    static const int16_t H[] = {-38,-39,-37,-40,-42,-41,-44,-43,-46,-45,-48,-47,
                                -50,-49,-52,-51,-54,-53,-56,-55,-58,-57,-60,-59};
    o->history_count = (uint16_t)(sizeof(H)/sizeof(H[0]));
    memcpy(o->history, H, sizeof(H));
}

/* ── EAPOL / PMKID ───────────────────────────────────────────────────── */
static int s_eap_on = 0;
int  mk_eapol_begin(int hop, int ch){ (void)hop;(void)ch; s_eap_on = 1; return 1; }
void mk_eapol_loop(void)  {}
void mk_eapol_pause(void) {}
void mk_eapol_resume(void){ s_eap_on = 1; }
void mk_eapol_stop(void)  { s_eap_on = 0; }
int  mk_eapol_running(void){ return s_eap_on; }
void mk_eapol_set_channel(int c){ (void)c; }
void mk_eapol_stats(mk_eapol_stats_t* o)
{
    memset(o, 0, sizeof(*o));
    o->frames = 31; o->targets = 4; o->handshakes = 2; o->pmkids = 1; o->sae = 1;
    o->channel = 6; o->hopping = 1; o->running = (uint8_t)s_eap_on;
    snprintf(o->path, sizeof(o->path), "/pcap/eapol_001.pcap");
}
int mk_eapol_list(mk_eapol_target_t* o, int max)
{
    static const mk_eapol_target_t T[] = {
        {{0xA4,0x2B,0xB0,0x11,0x22,0x33},{0x3C,0x5A,0xB4,0x00,0x11,0x22},
          MK_EAPOL_M1|MK_EAPOL_M2|MK_EAPOL_M3|MK_EAPOL_M4, 1,
          {0xb2,0x7c,0x11,0x9f,0x4a,0x02,0xde,0xad,0x5e,0x6f,0x70,0x81,0x92,0xa3,0xb4,0xc5},
          -44, 6},
        {{0x00,0x1A,0x2B,0x44,0x55,0x66},{0x9C,0x93,0x4E,0x77,0x88,0x99},
          MK_EAPOL_M1|MK_EAPOL_M2, 0, {0}, -61, 1},
        {{0xDE,0xAD,0xBE,0xEF,0x01,0x02},{0x7C,0xD9,0x5C,0x12,0x34,0x56},
          MK_EAPOL_M1, 0, {0}, -72, 11},
        {{0x88,0x4A,0xEA,0x11,0x22,0x33},{0x6C,0x2F,0x2C,0x44,0x55,0x66},
          MK_EAPOL_SAE_COMMIT|MK_EAPOL_SAE_CONFIRM, 0, {0}, -49, 6},
    };
    int n = 4; if (n > max) n = max;
    memcpy(o, T, (size_t)n * sizeof(mk_eapol_target_t));
    return n;
}

/* ── portal / evil-twin detection ────────────────────────────────────── */
static int s_pd_on = 0;
static mk_pd_probe_t s_pp;
static int s_pd_verdict = MK_PD_VERDICT_PORTAL;   /* --clear flips to CLEAR */

void mk_pd_begin(void){ s_pd_on = 1; memset(&s_pp, 0, sizeof(s_pp)); }
void mk_pd_loop(void) {}
void mk_pd_stop(void) { s_pd_on = 0; }
int  mk_pd_running(void){ return s_pd_on; }
void mk_pd_stats(mk_pd_stats_t* o)
{
    memset(o, 0, sizeof(*o));
    o->ssids = 6; o->flagged = 3; o->scans = 4;
    o->scanning = 0; o->running = (uint8_t)s_pd_on;
    o->scan_rc = -1; o->complete_rc = 6;
    o->raw_seen = 8; o->accepted = 6; o->rej_hidden = 2;
    o->table_ok = 1;
}
int mk_pd_list(mk_pd_ssid_t* o, int max)
{
    struct Row { const char* ssid; uint8_t n; uint16_t f; int8_t r; uint8_t fa; };
    static const Row R[] = {
        {"CorpNet",        2, MK_PD_OPEN_CLONE|MK_PD_SIGNAL_JUMP|MK_PD_MULTI_OUI, -38, 3},
        {"FreeCoffeeWiFi", 1, MK_PD_OPEN_CLONE,                                   -44, 0},
        {"HomeNet-5G",     2, MK_PD_AUTH_DOWNGRADE,                               -51, 6},
        {"CafeGuest",      1, 0,                                                  -59, 0},
        {"eduroam",        3, MK_PD_MULTI_CHANNEL,                                -66, 5},
        {"linksys",        1, 0,                                                  -81, 1},
    };
    int n = (int)(sizeof(R)/sizeof(R[0])); if (n > max) n = max;
    for (int i = 0; i < n; i++) {
        memset(&o[i], 0, sizeof(o[i]));
        snprintf(o[i].ssid, sizeof(o[i].ssid), "%s", R[i].ssid);
        o[i].n_bssid = R[i].n; o[i].flags = R[i].f;
        o[i].best_rssi = R[i].r; o[i].first_auth = R[i].fa;
        for (int k = 0; k < R[i].n && k < MK_PD_PER; k++) {
            o[i].ap[k].bssid[0] = (uint8_t)(0xA4 + k * 0x30);
            o[i].ap[k].bssid[5] = (uint8_t)(0x10 + i);
            o[i].ap[k].channel = (uint8_t)(1 + (i + k * 5) % 11);
            o[i].ap[k].rssi = (int8_t)(R[i].r - k * 6);
            o[i].ap[k].auth = (uint8_t)((R[i].f & MK_PD_OPEN_CLONE) && k ? 0 : R[i].fa);
        }
    }
    return n;
}
int mk_pd_probe_begin(const char* ssid)
{
    memset(&s_pp, 0, sizeof(s_pp));
    snprintf(s_pp.ssid, sizeof(s_pp.ssid), "%s", ssid ? ssid : "");
    s_pp.state = MK_PD_PROBE_DONE;
    s_pp.verdict = (uint8_t)s_pd_verdict;
    if (s_pd_verdict == MK_PD_VERDICT_PORTAL) {
        s_pp.http_code = 302;
        snprintf(s_pp.redirect, sizeof(s_pp.redirect),
                 "http://192.168.4.1/login?ap=CorpNet");
        /* The densest case on purpose: a high-confidence rogue with most of
         * the evidence set, so the layout is checked at its worst. */
        s_pp.rogue_flags = MK_PD_RG_SOFTAP_GW | MK_PD_RG_OPEN_CLONE |
                           MK_PD_RG_IP_REDIRECT | MK_PD_RG_MULTI_OUI |
                           MK_PD_RG_DNS_WILDCARD | MK_PD_RG_NO_SERVER |
                           MK_PD_RG_FAST_LOCAL;
        s_pp.rogue_conf = 100;
        snprintf(s_pp.gateway, sizeof(s_pp.gateway), "192.168.4.1");
        s_pp.server[0] = 0;
        s_pp.rtt_ms = 8;
    } else { s_pp.http_code = 204; }
    s_pp.elapsed_ms = 2840;
    return 1;
}
void mk_pd_probe_stop(void){ s_pp.state = MK_PD_PROBE_IDLE; }
void mk_pd_probe(mk_pd_probe_t* o){ *o = s_pp; }

/* ── AP security audit ───────────────────────────────────────────────── */
static int s_wa_on = 0;
void mk_wa_begin(void)  { s_wa_on = 1; }
void mk_wa_loop(void)   {}
void mk_wa_pause(void)  {}
void mk_wa_resume(void) { s_wa_on = 1; }
void mk_wa_stop(void)   { s_wa_on = 0; }
int  mk_wa_running(void){ return s_wa_on; }
void mk_wa_set_channel(int c) { (void)c; }
void mk_wa_stats(mk_wa_stats_t* o)
{
    memset(o, 0, sizeof(*o));
    o->aps = 6; o->at_risk = 4; o->wps_open = 1; o->no_pmf = 3;
    o->channel = 6; o->hopping = 1; o->running = (uint8_t)s_wa_on;
}
int mk_wa_list(mk_wa_ap_t* o, int max)
{
    struct Row { const char* ssid; uint8_t ch; int8_t rssi; uint32_t f;
                 uint8_t wst, wlk; uint8_t nf; };
    static const Row R[] = {
        {"linksys",     6, -71, MK_WA_WEP|MK_WA_WPS_ENABLED|MK_WA_WPS_UNLOCKED|MK_WA_NO_PMF, 2, 0, 3},
        {"CorpGuest",   1, -48, MK_WA_TKIP|MK_WA_WPA1|MK_WA_NO_PMF,                          0, 0xFF, 3},
        {"CorpNet",    11, -44, MK_WA_WPA3_TRANSITION|MK_WA_PMF_OPTIONAL|MK_WA_SAE,          0, 0xFF, 1},
        {"FreeCoffee",  1, -55, MK_WA_OPEN,                                                  0, 0xFF, 1},
        {"HomeNet-5G",  6, -41, MK_WA_PMF_REQUIRED|MK_WA_SAE,                                0, 0xFF, 0},
        {"StaffOnly",   3, -78, MK_WA_HIDDEN|MK_WA_HIDDEN_RESOLVED|MK_WA_NO_PMF,             0, 0xFF, 1},
    };
    int n = (int)(sizeof(R)/sizeof(R[0])); if (n > max) n = max;
    for (int i = 0; i < n; i++) {
        memset(&o[i], 0, sizeof(o[i]));
        snprintf(o[i].ssid, sizeof(o[i].ssid), "%s", R[i].ssid);
        for (int k = 0; k < 6; k++) o[i].bssid[k] = (uint8_t)(0xA4 + i * 7 + k);
        o[i].channel = R[i].ch; o[i].rssi = R[i].rssi; o[i].flags = R[i].f;
        o[i].wps_state = R[i].wst; o[i].wps_locked = R[i].wlk;
        o[i].findings = R[i].nf;
    }
    return n;
}

/* ── evil twin ───────────────────────────────────────────────────────── */
static int  s_tw_on = 0;
static char s_tw_ssid[33] = {0};
int mk_twin_begin(const char* ssid, const char* portal, int channel)
{
    (void)portal; (void)channel;
    snprintf(s_tw_ssid, sizeof(s_tw_ssid), "%s", ssid ? ssid : "");
    s_tw_on = 1; return 1;
}
void mk_twin_loop(void)   {}
void mk_twin_stop(void)   { s_tw_on = 0; }
int  mk_twin_running(void){ return s_tw_on; }
void mk_twin_clear(void)  {}
void mk_twin_stats(mk_twin_stats_t* o)
{
    memset(o, 0, sizeof(*o));
    snprintf(o->ssid, sizeof(o->ssid), "%s", s_tw_ssid);
    snprintf(o->portal, sizeof(o->portal), "default");
    o->running = (uint8_t)s_tw_on;
    if (s_tw_on) { o->clients = 2; o->seen = 5; o->submits = 2;
                   o->requests = 47; o->channel = 11; o->sd_ok = 1; }
}
int mk_twin_clients(mk_twin_client_t* o, int max)
{
    if (!s_tw_on || max <= 0) return 0;
    int n = 2 < max ? 2 : max;
    for (int i = 0; i < n; i++) {
        memset(&o[i], 0, sizeof(o[i]));
        for (int k = 0; k < 6; k++) o[i].mac[k] = (uint8_t)(0x3C + i * 9 + k);
        o[i].joined_ms = 1000u * (i + 1); o[i].submitted = (uint8_t)(i == 0);
    }
    return n;
}
int mk_twin_captures(mk_twin_cap_t* o, int max)
{
    if (!s_tw_on || max <= 0) return 0;
    static const char* U[] = {"a.user", "b.user"};
    static const char* P[] = {"Summer2026!", "Welcome123"};
    int n = 2 < max ? 2 : max;
    for (int i = 0; i < n; i++) {
        memset(&o[i], 0, sizeof(o[i]));
        for (int k = 0; k < 6; k++) o[i].mac[k] = (uint8_t)(0x3C + i * 9 + k);
        o[i].ms = 12000u + i * 4000u;
        snprintf(o[i].field1, sizeof(o[i].field1), "%s", U[i]);
        snprintf(o[i].field2, sizeof(o[i].field2), "%s", P[i]);
    }
    return n;
}

/* ── rogue-tool detection ────────────────────────────────────────────── */
static int s_td_on = 0;
static uint8_t s_td_mode = MK_TD_MODE_WIFI;

int mk_td_begin(int mode)
{
    s_td_on = 1;
    s_td_mode = (uint8_t)((mode == MK_TD_MODE_BLE) ? MK_TD_MODE_BLE : MK_TD_MODE_WIFI);
    return 1;
}
void mk_td_loop(void)   {}
void mk_td_stop(void)   { s_td_on = 0; }
int  mk_td_running(void){ return s_td_on; }
void mk_td_set_channel(int c) { (void)c; }

/* Report a panic so the crumb line is actually exercised in the simulator —
 * the on-device path only shows it after a real crash. */
/* The app refuses to run against a mismatched ABI, so report the version it
 * was compiled against. */
unsigned mk_abi_version(void) { return MK_ABI_VERSION; }

unsigned    mk_crumb_last_id(void)   { return 0x100A; }
const char* mk_crumb_last_name(void) { return "ble_init"; }
unsigned    mk_crumb_reset_id(void)  { return 4; }
const char* mk_crumb_reset_str(void) { return "PANIC"; }

void mk_td_stats(mk_td_stats_t* o)
{
    memset(o, 0, sizeof(*o));
    o->mode = s_td_mode; o->running = (uint8_t)s_td_on;
    o->channel = 6; o->hopping = (uint8_t)(s_td_mode == MK_TD_MODE_WIFI);
    if (s_td_mode == MK_TD_MODE_WIFI) { o->hits = 4; o->high_conf = 3; o->tracked = 31; }
    else                              { o->hits = 2; o->high_conf = 2; o->tracked = 18; }
}

int mk_td_list(mk_td_hit_t* o, int max)
{
    struct Row { uint8_t kind; uint8_t radio; const char* label;
                 int8_t rssi; uint8_t ch; uint32_t ev; uint16_t nssid, cnt; };
    static const Row W[] = {
        { MK_TD_PINEAPPLE,  MK_TD_MODE_WIFI, "FreeWiFi",   -39, 6,
          MK_TD_EV_MULTISSID|MK_TD_EV_BEACON_TX|MK_TD_EV_OUI,            17, 214 },
        { MK_TD_DEAUTHER,   MK_TD_MODE_WIFI, "",           -52, 6,
          MK_TD_EV_DEAUTH_TX|MK_TD_EV_OUI,                                0,  88 },
        { MK_TD_PWNAGOTCHI, MK_TD_MODE_WIFI, "{\"name\":\"p", -64, 1,
          MK_TD_EV_JSON_SSID|MK_TD_EV_BEACON_TX,                          1,  31 },
        { MK_TD_MARAUDER,   MK_TD_MODE_WIFI, "ESP32 Marauder", -71, 11,
          MK_TD_EV_NAME|MK_TD_EV_BEACON_TX|MK_TD_EV_OUI,                  1,  12 },
    };
    static const Row B[] = {
        { MK_TD_FLIPPER, MK_TD_MODE_BLE, "Flipper Zuko", -41, 0,
          MK_TD_EV_NAME|MK_TD_EV_SVC_UUID|MK_TD_EV_MFG,                   0, 143 },
        { MK_TD_BRUCE,   MK_TD_MODE_BLE, "Bruce",        -67, 0,
          MK_TD_EV_NAME|MK_TD_EV_MFG,                                     0,  22 },
    };
    const Row* R = (s_td_mode == MK_TD_MODE_BLE) ? B : W;
    int n = (s_td_mode == MK_TD_MODE_BLE) ? 2 : 4;
    if (n > max) n = max;

    /* mirror the firmware's additive confidence so the screen is faithful */
    for (int i = 0; i < n; i++) {
        memset(&o[i], 0, sizeof(o[i]));
        for (int k = 0; k < 6; k++) o[i].mac[k] = (uint8_t)(0x24 + i * 11 + k);
        o[i].kind = R[i].kind; o[i].radio = R[i].radio;
        snprintf(o[i].label, sizeof(o[i].label), "%s", R[i].label);
        o[i].rssi = R[i].rssi; o[i].channel = R[i].ch;
        o[i].evidence = R[i].ev; o[i].ssid_count = R[i].nssid; o[i].count = R[i].cnt;
        int c = 0;
        if (R[i].ev & MK_TD_EV_DEAUTH_TX) c += 60;
        if (R[i].ev & MK_TD_EV_MULTISSID) c += 50;
        if (R[i].ev & MK_TD_EV_JSON_SSID) c += 55;
        if (R[i].ev & MK_TD_EV_SVC_UUID)  c += 50;
        if (R[i].ev & MK_TD_EV_NAME)      c += 30;
        if (R[i].ev & MK_TD_EV_OUI)       c += 10;
        if (R[i].ev & MK_TD_EV_MFG)       c += 5;
        if (R[i].cnt > 5)                 c += 5;
        o[i].confidence = (uint8_t)(c > 100 ? 100 : c);
        o[i].first_ms = 1000; o[i].last_ms = 90000;
    }
    return n;
}

/* ── input / misc ────────────────────────────────────────────────────── */
void mk_input_poll(void)
{
    g_cur = -1; g_curLong = 0;
    if (g_step < g_keys.size()) {
        int k = g_keys[g_step++];
        if (k == -2) g_curLong = 1;
        else         g_cur = k;
    } else if (++g_tail > g_tailMax) {
        g_curLong = 1;          /* script done → hold B so app_main returns */
    }
    g_ms += 40;
}
int  mk_btn(int id)      { return (g_cur == id) ? 1 : 0; }
int  mk_btn_long(int id) { return (g_curLong && id == MK_BTN_B) ? 1 : 0; }

/* Touch. Reported as unavailable so the app exercises its button paths here;
 * the zone arithmetic is pure and can be checked without a panel, and the
 * app is required to work with touch absent anyway. A future scripted-tap
 * mode would feed up_x/up_y from the --keys string. */
int  mk_touch_available(void) { return 0; }
void mk_touch_get(mk_touch_t* o)
{
    if (!o) return;
    o->x = o->y = -1;
    o->pressed = o->tapped = 0;
    o->up_x = o->up_y = -1;
}
void mk_delay(uint32_t ms){ g_ms += ms; }
uint32_t mk_millis(void)  { return g_ms; }
int  mk_snprintf(char* b, size_t n, const char* fmt, ...)
{ va_list ap; va_start(ap, fmt); int r = vsnprintf(b, n, fmt, ap); va_end(ap); return r; }

/* ── entry ───────────────────────────────────────────────────────────── */
extern "C" int app_main(int argc, char** argv);

int main(int argc, char** argv)
{
    const char* keys = "";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--out")    && i + 1 < argc) g_out = argv[++i];
        else if (!strcmp(argv[i], "--keys") && i + 1 < argc) keys = argv[++i];
        else if (!strcmp(argv[i], "--frames")) g_all = true;
        else if (!strcmp(argv[i], "--clear")) s_pd_verdict = MK_PD_VERDICT_CLEAR;
        else if (!strcmp(argv[i], "--ble")) s_td_mode = MK_TD_MODE_BLE;
        else if (!strcmp(argv[i], "--idle") && i + 1 < argc) g_tailMax = atoi(argv[++i]);
        else { fprintf(stderr,
                "usage: meowkit-app [--keys U,D,A,B,b,.] [--out f.bmp] [--frames] [--idle N]\n"
                "  U/D/L/R/A/B = button tap, b = hold B (exit), . = idle frame\n"); return 2; }
    }
    /* parse comma/space separated key script */
    { std::string s(keys), tok;
      for (size_t i = 0; i <= s.size(); i++) {
          if (i == s.size() || s[i] == ',' || s[i] == ' ') {
              if (!tok.empty()) g_keys.push_back(key_of(tok));
              tok.clear();
          } else tok += s[i];
      } }

    canvas.setColorDepth(16);
    if (!canvas.createSprite(MK_LAYOUT::W, MK_LAYOUT::H)) {
        fprintf(stderr, "createSprite failed\n"); return 1;
    }
    int rc = app_main(0, nullptr);
    printf("app_main returned %d; %d frame(s); last -> %s\n", rc, g_frame, g_out.c_str());
    return rc == 0 ? 0 : 1;
}
