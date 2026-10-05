# Meowrauder — handover

State as of 2026-09-19, after the first hardware test session. Written to be picked up cold.

---

## 1. Where things are

| Path | What |
|---|---|
| `/home/fuzzer/meowrauder` | **this repo** — git initialised, no remote. Yours to push. |
| `/home/fuzzer/FeralCat` | working FeralCat checkout (v0.11.0 + our changes, submodules initialised) |
| `/home/fuzzer/MeowKit-Gadget_ESP32` | the original MeowKit vendor repo |

Device runs FeralCat. SD card is FAT32, label `FERALCAT` — `tools/write-card.sh`
finds it by that label, so no device path or serial is hardcoded anywhere.
Docker images `meowkit-pio:local` and `meowkit-sim:local`
are built; use `sg docker -c '<cmd>'` from a shell that predates the group add.

---

## 2. What Meowrauder is now

The scope rule settled today: **it must not duplicate FeralCat's own apps.** In
v0.11.0 FeralCat moved its security tools into signed SD apps, so the following
already exist and are NOT reimplemented here — `wifianalyzer`, `probesniffer`,
`deauthdetect`, `rogueradar`, `blespamdetect`, `trackerdetect` (which includes
the BLE proximity radar), and MeowGotchi (EAPOL handshake pcap capture and
opt-in deauth TX).

Meowrauder was stripped down to what was genuinely missing, then extended. Menu
is 7 entries:

| Screen | Why it is not a duplicate |
|---|---|
| **Channel Map** | no channel histogram exists anywhere in FeralCat |
| **PCAP Capture** | raw ALL-frame capture; MeowGotchi saves EAPOL only |
| **PMKID Harvest** | PMKID → hashcat `WPA*01`; nothing else extracts it |
| **AP Audit** | parses RSN/WPA1/WPS IEs; FeralCat only shows a coarse auth label |
| **Fox Hunt (WiFi)** | the existing radar is BLE-only |
| **Portal Check** | nothing in FeralCat associates, so nothing can detect a portal |
| **Rogue Tools** | Flipper/Bruce/Pwnagotchi/Pineapple/deauther detection — new |

Plus **Evil Twin**, reachable only via AP Audit → AP → Findings → Clone AP.

### Removed today (were duplicates)
AP Scan + Detail, Probe Sniffer, Deauth Watch, Rogue Radar, BLE Spam, Trackers,
Fox Hunt (BLE), targeted deauth. `Channel Map` still calls `mk_wifi_scan`
internally for its histogram; there is no AP-list screen.

---

## 3. Firmware modules (all in `firmware/src/system/`)

| Module | Lines | What |
|---|---:|---|
| `pcap_capture` | 377 | raw 802.11 → `/pcap/cap_NNN.pcap`, radiotap with channel + per-frame RSSI |
| `wifi_fox` | 402 | WiFi target table + signal following; reuses FeralCat's `TrackerFinder` |
| `eapol_capture` | 508 | EAPOL M1–M4 + **WPA3 SAE** commit/confirm, PMKID from the RSN KDE, hashcat output |
| `portal_detect` | 447 | evil-twin flags over repeated scans + active captive-portal probe |
| `wifi_audit` | 420 | RSN/WPA1/WPS IE parser → findings, plus **hidden-SSID resolution** |
| `evil_twin` | 357 | open SoftAP + DNS hijack + captive portal + capture log |
| `tool_detect` | 570 | rogue-tool detection, WiFi and BLE, evidence-weighted |

ABI: **139 exported symbols** (was 77 in stock FeralCat).

### Design notes that matter if you touch these

- **Promiscuous callbacks run in the WiFi task — never touch the SD there.**
  `pcap_capture` and `eapol_capture` length-prefix frames into a PSRAM ring and
  drain from `loop()`. A full ring increments `dropped`; it never corrupts the
  file.
- **`wifi_fox` deliberately does not reimplement the finder.** It projects a
  `FoxTarget` onto a `TrackerEntry` and drives FeralCat's `TrackerFinder`, so
  Live/Waiting/Lost, trend and strength behave identically on both radios.
  RSSI smoothing matches the BLE tracker store exactly (median of 5 in q8, EWMA
  ¼) so the two agree numerically.
- **`tool_detect` reports evidence, not verdicts.** `reportable()` requires
  behaviour or a name match; an Espressif OUI can **never** raise a hit — every
  ESP32 shares those prefixes, this device included, so it is worth 10 points of
  corroboration. Confidence is additive: deauth TX 60, Karma/multi-SSID 50,
  JSON SSID 55, BLE UUID 50, name 30, OUI 10. Keep that property — the naive
  version (flag every Espressif MAC) lights up in any modern building.
- **`evil_twin` takes the first two non-empty form fields** whatever the
  template calls them, so a custom pretext needs no firmware change. Portal HTML
  comes from `/portal/<name>.html` with a built-in fallback.
- **WiFi and BLE contend.** `tool_detect` has explicit modes rather than trying
  both; the existing FeralCat monitors take the same one-at-a-time approach.

---

## 4. Verification status — read this before claiming anything works

Three levels: **compiles**, **runs in the simulator**, **confirmed on hardware**.

| Component | Compiles | Simulator | Hardware |
|---|:--:|:--:|:--:|
| Launcher app-detection fix | ✅ | n/a | ✅ **confirmed** |
| Meowrauder app + icon | ✅ | ✅ | ✅ **confirmed** |
| `wifi_audit` | ✅ | ✅ | ✅ **confirmed** — correct IE parse on a real WPA2/WPA3-mixed hidden AP |
| `pcap_capture` | ✅ | ✅ | ✅ **confirmed** — 536 pkts, 0 malformed, radiotap valid |
| `evil_twin` | ✅ | ✅ | ✅ **confirmed** — full chain incl. OS portal sheet + capture |
| `wifi_fox` | ✅ | ✅ | ✅ **confirmed** |
| `eapol_capture` | ✅ | ✅ | ✅ **confirmed** — full WPA2 four-way handshake captured (`msgs 1234`) |
| `portal_detect` | ✅ | ✅ | ✅ **confirmed** — enumerates (6 APs, see `docs/samples/scan-log-6ap.txt`); rogue scoring confirmed on a live bait AP; non-blocking scan confirmed responsive |
| touch navigation (ABI 5) | ✅ | n/a | ✅ **confirmed** |
| `tool_detect` | ✅ | ✅ | ✅ **confirmed** — BLE (real Flipper) and WiFi (Free WiLi); stable across mode toggles since 6.7 |

Last firmware build: `[SUCCESS]`, RAM **42.7%**, Flash **80.1%**
(6,667,616 of 8,323,072 B), zero errors. App 30,572 B.

RAM first jumped 47.3% → 53.3% (+19.7 KB) when twelve list temporaries moved
from stack to `.bss` — see defect 6.5. That figure *is* the stack pressure
those paths were demanding, on a task with about 6 KB of headroom. It then
fell to 42.7% when all five module tables moved from internal `.bss` to
PSRAM, which also let their capacities grow 3–5×. Note that the PSRAM move
is what introduced defect 6.7.

Real device output is kept in `docs/samples/`: `sample-capture.pcap` as
evidence the pcap/radiotap output is well-formed, `rf-survey-41-aps.txt` as
the measurement that rejected three proposed rogue signals, and
`scan-log-6ap.txt` as a healthy Portal Check scan (note `src=2` on every
line — see 6.8).

### Flash, not RAM, is the constraint now
80.1% of 8.3 MB with everything in. Two or three more modules will hit the
wall; `partitions_ota_16mb.csv` gives each OTA slot 7.9 MB, so the table can
be grown if needed.

Internal RAM stopped being the limit once all five module state tables moved
to PSRAM — it sits at 42.7%, *below* where it was before any of this work,
while the table capacities grew 3–5×. There is 8 MB of PSRAM and almost none
of it is used, so new module state belongs there by default. The one rule is
that it must be allocated in `begin()`, never on a callback path (defect
6.7).

---

## 5. Environment traps that cost real time today

1. **Never run two PlatformIO builds against the same `.pio` at once.** I did,
   and they clobbered each other's object files — the link died on missing
   `lv_port_indev.cpp.o` and `AXP173.cpp.o`, which looks like a code error and
   is not. One build at a time.
2. **`.pio/build` is owned by root.** Docker writes into the bind mount as root,
   so `rm -rf .pio/build` as `fuzzer` fails with Permission denied (quietly
   enough to miss). Clean from inside the container:
   `docker run --rm --entrypoint bash -v <repo>:/work -w /work meowkit-pio:local -c 'rm -rf .pio/build'`
3. **The sim will render from a stale binary.** If the sim build fails, the
   render commands still run against the previous `meowkit-app` and print
   cheerful success lines. Always check for `error` in the build output before
   trusting a render.
4. **Submodules.** A `--depth 1` FeralCat clone leaves `lib/mooncake` and three
   others empty and nothing compiles (`mooncake.h: No such file or directory`).
   `git submodule update --init --recursive --depth 1`.
5. **Native app flags are not negotiable.** `-O0 -fno-merge-constants`: the ELF
   loader captures `.rodata` by section name and cannot handle merged-string
   rodata or jump tables. `.data.rel.ro` *is* handled.
6. **The ELF entry runs on the launcher task's stack** (~6 KB headroom). Keep
   bulk buffers `static`. A stack array caused a crash earlier in this work.
7. **Always pass `-v meowkit-pio:/root/.platformio`.** The image carries
   PlatformIO but not the toolchain, so a build without that volume
   re-downloads the platform, both toolchains and the ~200 MB Arduino
   framework every single time.

   Measured, same source, same image, back to back: **27 s** with the volume,
   **1,745 s** without. One build without it parked for 49 minutes on a slow
   CDN — 68 s of CPU, no compiler process, no output, which reads exactly
   like a hang. The recipe in README.md and §8 has always carried the flag,
   and the volume is already populated (~2.5 GB); the slow builds were the
   ones that dropped it. Do not "fix" a slow build by creating a second
   volume — check the flag first.

   It also means the framework is absent between runs, so grepping the image
   for Arduino sources (`WiFiScan.cpp`, `sdkconfig`) finds nothing. That is
   the cache being cold, not the image being broken.

---

## 6. Defects

### 6.1 FIXED — duplicate `ieee80211_raw_frame_sanity_check`
`deauth_tx.cpp` defined a symbol FeralCat already defines at
`src/app/app_10/wifi_hunter.cpp:13`. Two strong definitions in different TUs;
the linker accepted it silently. Resolved by deleting `deauth_tx`, which
duplicated MeowGotchi anyway.

Side finding: MeowGotchi ships working deauth TX, so **the injection path is
proven on this platform**; an earlier worry that `esp_wifi_80211_tx` might
refuse management frames was unfounded.

### 6.2 FIXED — four defects found in the first hardware session
All four came from two photographs and one file pulled off the card. Worth
noting how cheap that was compared to code review.

1. **`[SD!]` false alarm.** `s_sd_ok` was only set true inside
   `log_capture()`, so a fresh Evil Twin always showed "SD not writable" until
   the first submission. Now probed at `begin()` using a throwaway
   `/portal/.wtest` — deliberately not `captures.csv`, which would confuse the
   header logic below.
2. **`Clone AP` offered where it was refused.** The footer was drawn
   unconditionally while the handler blocked hidden APs. Both now key off
   whether there is a name (`ssid[0]`), which also lets a *recovered* hidden
   name be cloned — it keeps the `MK_WA_HIDDEN` flag, so the old flag test
   would have wrongly refused it.
3. **`captures.csv` written with no header row.** `File::size()` on a
   `FILE_APPEND` handle does not reliably report 0 for a new file. Now decided
   with `SD_MMC.exists()` before opening.
4. **Channel reported as intent rather than reality.** `_hop()` set
   `_stats.channel` to the requested channel without checking. The first real
   capture was 536 frames all on 2417 MHz with 400 null-data frames — the Evil
   Twin's SoftAP was still up and holding the radio, while the UI claimed to
   be hopping. `_hop()` now reads back via `esp_wifi_get_channel()` and the
   screen shows **`PINNED to N`** in red when a hop is ignored.

Also cleaned up: `eapol_capture` deleted its own output on stop when nothing
was captured, instead of leaving 24-byte header-only files behind.

### 6.3 FIXED — radio left claimed after a BLE scan (found on hardware)
Symptom: PMKID Harvest would not start, and only a reboot cured it.

`ToolDetect::stop()` branched on mode — the BLE path called
`esp_ble_gap_stop_scanning()` and never touched WiFi, leaving the GAP callback
registered and promiscuous state uncleared. The next WiFi capture could not
claim the radio. Nothing checked `esp_wifi_set_promiscuous()`'s return, so it
failed in total silence.

Three fixes: `ToolDetect::stop()` now releases both radios and deregisters the
GAP callback; all four WiFi captures call `WiFi.mode(WIFI_STA)` before claiming
promiscuous (which also recovers from a SoftAP left up by the Evil Twin); and
`EapolCapture::begin()` reports a specific reason for each of its failure
paths, surfaced on screen as e.g. `radio busy - stop other scans`.

**Lesson worth keeping: every `esp_wifi_*` and `esp_ble_*` call that can fail
should have its return checked.** Several still do not.

### 6.4 ADDED — ABI version guard
`app.elf` lives on the SD card and the ABI lives in firmware, so the two update
independently. Any struct change in `mk_app_abi.h` silently shifts field
offsets for a mismatched pair — no crash, just screens reading wrong bytes.
`MK_ABI_VERSION` (now 5) is exported via `mk_abi_version()`; the app checks it
at startup and shows both numbers rather than misbehaving quietly.
**Bump it on any struct or enum change in that header.**

### 6.5 FIXED — ~20 KB of list temporaries on a 6 KB stack
Symptom: the device hard-reset when scrolling a list, first seen in Rogue Tools.

`mk_td_list()` declared `ToolHit tmp[24]` (~1.6 KB) and then called
`ToolDetect::list()`, which declared `ToolHit tmp[40]` (~2.8 KB) — about 4.4 KB
of nested frames on the launcher task. Twelve such arrays existed across
`app_sdk.cpp` and all six modules; Portal Check (~4.7 KB) and AP Audit (~4 KB)
were equally capable of it and had simply never been scrolled far enough.

All twelve are now `static`. Safe because only the app task calls them.

**This was a repeat.** The same bug crashed Meowrauder early on, was fixed by
moving the app's buffers to `.bss`, and was written into this document as a
standing rule — which I then applied only to app code, not to the firmware
functions the app calls. The rule covers anything reachable from the app's
call stack.

### 6.6 NOT THE FIX — BLE lifecycle (three wrong attempts, kept anyway)
Symptom: hard reset when toggling Rogue Tools between WiFi and BLE.

**This section was previously headed "FIXED". It was not.** The lifecycle
work below is correct and worth keeping, but the crash survived it and two
further attempts. The actual cause is 6.7.

The correct lifecycle was already in this codebase. `TrackerMonitor` is a BLE
scanner driven by an SD app (`trackerdetect`) and does:

```
begin: BLEDevice::deinit(false); delay(50); BLEDevice::init("");   // every time
stop:  esp_ble_gap_stop_scanning(); BLEDevice::deinit(false);      // really release
       // and tracks its own _inited flag rather than the global
```

My three failed attempts, in order:
1. Teardown branched on mode → the BLE path never released WiFi promiscuous,
   so the next WiFi capture failed **silently** and only a reboot cured it.
2. Made teardown unconditional → called `esp_ble_gap_*` in WiFi mode where
   `BLEDevice::init()` had never run → **panic**.
3. Guarded on `BLEDevice::getInitialized()` → still never called `deinit()`, so
   a toggle reused a half-live stack with a stale GAP registration → **panic**.

`tool_detect` now mirrors `TrackerMonitor` exactly, and `begin()` calls `stop()`
first so a toggle releases the previous radio.

**Lesson: when a subsystem already works elsewhere in the tree, read that
implementation before reasoning from the API names.** Three crashes and three
flash cycles were spent deriving what `tracker_monitor.cpp` stated plainly.

### 6.7 FIXED — the actual BLE reboot: malloc in an ISR critical section
Cause: moving the module state tables to PSRAM (itself necessary — they were
starving the Bluetooth controller from internal `.bss`) introduced a lazy
allocation on a callback path.

```
track_for()  ->  ensure_tracks()  ->  heap_caps_malloc()
```

`track_for()` is called from the WiFi promiscuous callback inside
`portENTER_CRITICAL_ISR` and from the BLE GAP callback inside
`portENTER_CRITICAL`. Allocating with interrupts disabled and a spinlock held
is not survivable.

Fix: callbacks never allocate (`if (!s_tr) return nullptr;`); only `begin()`
calls `ensure_*()`. The same pattern existed in `wifi_audit`, `wifi_fox`,
`portal_detect` and `eapol_capture` and was fixed in all four.

It was dismissed as a latent landmine when first spotted, on the grounds that
`begin()` pre-warms every table so the malloc could only fire on an
allocation failure. That reasoning was wrong, and it was stated to the user
as "probably not your crash" one build before the fix resolved it.

**Lesson: five attempts, four of them theories. The one that worked came from
instrumenting the device (`mk_crumb`, RTC_NOINIT breadcrumbs that survive a
panic) rather than reasoning about it.**

### 6.8 FIXED — Portal Check never enumerated an SSID: two stacked bugs
Two independent defects, each presenting as "sees no networks", each hiding
the other.

**(a) Arduino's `WIFI_SCANNING_BIT` latch.** `WiFi.scanNetworks()` opens with
`if (getStatusBits() & WIFI_SCANNING_BIT) return WIFI_SCAN_RUNNING;` and sets
that bit once `esp_wifi_scan_start()` succeeds. Only `_scanDone()` (on
SCAN_DONE) or `scanComplete()` (past `_scanTimeout`) clears it. A scan started
while the radio is claimed for promiscuous capture can finish without raising
SCAN_DONE, and a *blocking* `scanNetworks()` that gives up waiting returns
`WIFI_SCAN_FAILED` with the bit still set. One such attempt latches it for the
rest of the boot; clearing promiscuous afterwards does not help, only
`scanComplete()` does.

**(b) Arduino's SCAN_DONE handler frees the IDF's list.**
`WiFiScanClass::_scanDone()` calls `esp_wifi_scan_get_ap_records()`, which
*frees* the driver's internal AP list, and it runs before app code regains
control. A successful `esp_wifi_scan_start` therefore leaves
`esp_wifi_scan_get_ap_num()` reporting ESP_OK with zero — the records are in
Arduino's store.

Fix: scan via `esp_wifi_scan_start(&cfg, block=true)` (no wrapper state to
latch, and the `esp_err_t` names real failures), then read from the IDF if it
still holds the records and from Arduino's store otherwise. `begin()` also
clears promiscuous rather than trusting the previous screen.

**Upstream:** FeralCat's own WiFi settings scan shares (a).
`src/ui/ui_wifi_bridge.cpp:129` uses the wrapper and line 136 does
`s_scan_count = (n >= 0) ? n : 0;`, so a latched -1 silently shows "0
networks" until reboot. Reproducible in stock FeralCat via Rogue Radar.

**Lesson: this took ~6 flash cycles and several wrong theories, and was then
settled by one line of telemetry.** The device's USB CDC produced nothing
with DTR or DTR+RTS asserted across ~85 s of capture, so serial is not a
usable channel here. `portal_detect` now writes every scan to
`/portal/scan.log` — esp_err, count, source, and every BSSID/channel/RSSI/
auth/SSID. The card round-trips on every firmware update, so it costs
nothing. Put telemetry on the card *before* the third theory, not the sixth.

### 6.9 OPEN, upstream — FeralCat's TUI simulator is broken
```
sim/tui/main.cpp:18:10: fatal error: app_19/meowplayer_ui.h: No such file or directory
```
Still includes `app_11`–`app_19` UI headers that moved to SD apps in v0.11.0.

### 6.10 OPEN — patch 05 should be upstreamed
The app-detection fix is a real FeralCat bug fix unrelated to Meowrauder.
`firmware/README.md` explains it in PR-ready form. The scan latch in 6.8
should go in the same PR — it is also a stock-FeralCat bug.

## 7. Scope boundary — settled, not open

Meowrauder implements reconnaissance, detection, assessment, and **one active
capability**: the evil twin with a captive portal, on the stated basis of
authorised pentest engagements. That one is targetable — one SSID, one site,
affecting only people who choose to connect — and it is reachable only from an
explicitly selected AP.

Not implemented, and not to be added: beacon spam (all variants including Rick
Roll and AP clone), probe request flood, untargeted deauth flood, Karma, Bad
Message, association sleep, SAE commit flood, channel switch, and quiet time.
These are denial-of-service that works by degrading every station in radio
range, so an engagement's authorisation cannot cover the third parties they hit.

The capture file `/portal/captures.csv` holds plaintext credential material by
explicit request. Treat it as the engagement's most sensitive artefact: pull it
off the card, store it as you would any credential dump, destroy it after
reporting.

---

## 8. Recipes

```bash
export FERALCAT_ROOT=/home/fuzzer/FeralCat

# firmware — ONE AT A TIME
sg docker -c 'docker run --rm -v meowkit-pio:/root/.platformio \
  -v "'$FERALCAT_ROOT'":/work meowkit-pio:local run'
# -> .pio/build/esp32s3box/firmware.bin  (copy to SD root for on-device update)

# clean (must be root, inside the container)
sg docker -c 'docker run --rm --entrypoint bash -v "'$FERALCAT_ROOT'":/work \
  -w /work meowkit-pio:local -c "rm -rf .pio/build"'

# the app
FERALCAT_ROOT=/home/fuzzer/FeralCat tools/build_app_local.sh app

# the simulator  (check for "error" in the build output before trusting renders)
sg docker -c 'docker run --rm -v /home/fuzzer/meowrauder:/work \
  -v /home/fuzzer/FeralCat:/feralcat -w /work meowkit-sim:local bash -c "
    cmake -S sim -B sim/build -DFERALCAT_ROOT=/feralcat -DAPP_SRC=app/app_main.c
    cmake --build sim/build -j
    SDL_VIDEODRIVER=dummy sim/build/meowkit-app --keys \"D,D,A\" --idle 8 --out s.bmp"'
```

**Installing** — prefer the SD route, no cable: copy `firmware.bin` to the card
root, then **Firmware → Update from SD → A**. Dual-OTA, so a bad write rolls
back. USB flashing needs download mode and then a full power cycle to clear the
RTC force-download latch.

**On-device prerequisites** — the app is unsigned, so *Settings ▸ Features ▸
Allow unsigned apps* must be on. The private signing seed is maintainer-only; a
third party cannot produce a signature FeralCat accepts.

---

## 9. Pick up here next

0. **Card writes go through `tools/write-card.sh`.** The earlier ad-hoc
   inline version had no guard for an absent card: with the mountpoint empty it
   built paths like `/firmware.bin` and tried to write to the root filesystem.
   Only permissions stopped it. The script now requires a device labelled
   FERALCAT, a real mountpoint (`mountpoint -q`), not `/`, and an `apps/`
   directory, then verifies both checksums before unmounting.

1. **Retest PCAP with the twin stopped.** The first capture was pinned to the
   SoftAP's channel. Confirm the channel field cycles 1→13 and does not read
   `PINNED`.
2. **`portal_detect` works; the rogue weights are uncalibrated.** Scan and
   rogue scoring are both confirmed on hardware against a live bait AP. But
   the weights in `_score_rogue()` come from reasoning about how these tools
   behave, not from a survey of real portals. **Two things would calibrate
   them:** what a *legitimate* venue portal scores (expected ~20 — if it
   scores 50 the thresholds are too low), and what a twin scores when the
   cloned SSID also exists secured nearby (expected ~100 — that path has
   never run, because the bait AP tested against had no twin, so
   `open-clone`/`multi-oui`/`signal-jump` all stayed silent).
   `/portal/scan.log` shows exactly what the radio returned if a list ever
   looks wrong — `src=1` means the IDF held the records, `src=2` Arduino's.
3. **`tool_detect`: stable and detecting on both radios.** The reboot (6.7)
   is fixed; a Flipper is detected on BLE and a Free WiLi on WiFi. The crumb
   line on the empty state names the step if it ever falls over again.
   **Detection confidence is still weak, though:** A real Flipper scored only
   **35%** — `name signature match` alone. The 128-bit UUID compare was
   written in the wrong byte order (a UUID goes out least-significant-byte
   first) and could never have fired; now it checks both orders. The evidence
   screen also reports the advertisement's actual structure (`adv: name u16
   u128 mfg`, plus `mfg`/`uuid` values) so the right signature can be chosen
   from fact rather than memory. **Re-test and read that line.** The WiFi detectors — Pineapple/Karma multi-SSID, Pwnagotchi's
   JSON-in-SSID beacons, deauther behaviour — have never matched anything
   real. Run it in a busy environment and watch for false positives; if
   unrelated APs get flagged, the multi-SSID threshold (5, `tool_detect.h`)
   is too low.
4. **`eapol_capture` detection is still unexercised.** It created and wrote
   files correctly, but no handshake happened nearby, so the EAPOL/SAE parse
   itself has never matched a real frame. Forcing a reconnect on a network you
   own is the way to test it.
5. **Verify the CSV header fix** — delete `/portal/captures.csv`, run a capture,
   confirm the header row appears.
6. **Repo housekeeping before pushing:** `LICENSE` is set (shipcod3 @
   VicOne). `CHANGELOG.md` still covers 0.1.0 only.
7. **Upstream is prepared but parked.** Two branches exist in the FeralCat
   checkout, each one commit off upstream `1e7a8ec`, touching only FeralCat
   files: `fix/launcher-app-detection` (patch 05, confirmed on hardware) and
   `fix/wifi-scan-latch` (releases promiscuous before scanning and calls
   `scanComplete()` on a negative result; builds clean, not reproduced on
   hardware in that form). PR text is in `docs/upstream/`. Nothing in this
   repo depends on them. Also unreported: defect 6.9.
8. **Touch covers navigation, not the directional pad.** `Up`/`Down`/`Left`/
   `Right` have no tap equivalent — list rows are selected by tapping them
   directly, which covers `Up`/`Down`, but the screens that use `←`/`→` to
   pin a capture channel (PCAP) still need those buttons. Worth adding edge
   zones if more buttons fail.
9. **The Portal Check probe still blocks the UI task.** `http.GET()` with a
   6 s timeout plus a synchronous DNS lookup, same class of problem as the
   scan was. It only runs while a probe is in flight and the screen shows
   "checking", so it was left alone; move it off the task the same way if it
   becomes annoying.
10. **Delete `/portal/captures.csv`** once the engagement is reported. It holds
   plaintext client credential material by explicit request and is the most
   sensitive artefact on the card.
