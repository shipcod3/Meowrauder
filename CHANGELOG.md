# Changelog

## 0.3.0 — the two bugs that survived 0.2.0

0.2.0 shipped with two faults it believed were fixed or unimportant: Rogue
Tools still hard-reset on a BLE toggle, and Portal Check had never enumerated
a single SSID on hardware. Both are now fixed, and both took more attempts
than they should have.

### Fixed — BLE reboot: `malloc` reachable from an ISR critical section

Moving the module state tables to PSRAM in 0.2.0 (item 8 there) fixed a real
problem and introduced this one: a lazy allocation on a callback path.

```
track_for()  ->  ensure_tracks()  ->  heap_caps_malloc()
```

`track_for()` is called from the WiFi promiscuous callback inside
`portENTER_CRITICAL_ISR` and from the BLE GAP callback inside
`portENTER_CRITICAL`. Allocating with interrupts disabled and a spinlock held
is not survivable. Callbacks now never allocate; only `begin()` calls
`ensure_*()`. The same pattern was removed from `wifi_audit`, `wifi_fox`,
`portal_detect` and `eapol_capture`.

This was the fifth attempt at this crash. The first four were theories — UUID
byte order, radio teardown, GAP lifecycle, table capacity — and none was the
bug. It was found by adding **`mk_crumb`**: breadcrumbs in `RTC_NOINIT`
memory, which the startup code does not clear on a software reset, so the
device names its own crash site after a panic. Serial was not an option:
panic output over TinyUSB CDC does not reliably escape the chip, and the
device is normally untethered.

### Fixed — Portal Check: two stacked scan bugs

Each presented as "sees no networks", and the first hid the second.

**(a) Arduino's `WIFI_SCANNING_BIT` latch.** `WiFi.scanNetworks()` opens
with `if (getStatusBits() & WIFI_SCANNING_BIT) return WIFI_SCAN_RUNNING;` and
sets that bit once `esp_wifi_scan_start()` succeeds. Only `_scanDone()` (on
SCAN_DONE) or `scanComplete()` (past `_scanTimeout`) clears it, and a
*blocking* `scanNetworks()` that gives up waiting for SCAN_DONE returns
`WIFI_SCAN_FAILED` with the bit still set. One such attempt latches it for
the rest of the boot; the call never reaches the driver.

**(b) Arduino's SCAN_DONE handler frees the IDF's list.**
`WiFiScanClass::_scanDone()` calls `esp_wifi_scan_get_ap_records()`, which
frees the driver's internal AP list, and it runs before app code regains
control. A successful `esp_wifi_scan_start` therefore leaves
`esp_wifi_scan_get_ap_num()` honestly reporting zero.

Scanning now goes through `esp_wifi_scan_start(&cfg, block=true)` — no
wrapper state to latch, and the `esp_err_t` names real failures — and results
are read from the IDF if it still holds them and from Arduino's store
otherwise. On hardware it is always the latter (`src=2`, see
`docs/samples/scan-log-6ap.txt`). `begin()` also clears promiscuous rather
than trusting the previous screen to have done so.

**Upstream:** FeralCat's own WiFi settings scan shares (a).
`src/ui/ui_wifi_bridge.cpp:136` turns a latched `-1` into a silent "0
networks" until reboot, reachable in stock FeralCat via Rogue Radar.

### Added — rogue scoring, separated from the portal verdict

Portal Check reported `PORTAL DETECTED` for anything intercepting HTTP, which
is every hotel, airport and cafe network. That is a fact about the network,
not a finding.

The verdict now stays as *what the network does*, and a separate weighted
score says *whether it looks hostile*: `softap-gw` (gateway 192.168.4.1, the
Arduino SoftAP default that Marauder, Bruce and the Flipper portals all leave
alone) 40, `open-clone` 35, `ip-redirect` 20, `multi-oui` 15, `dns-wild` 10,
`no-server` 10, `signal-jump` 10, `local-rtt` 5. The passive per-SSID flags
were already being computed across repeated scans and the probe had been
discarding them; they now fold in. A network that intercepts nothing scores
zero regardless. The screen lists the evidence tags so the number can be
argued with rather than trusted.

**The weights are reasoned, not measured.** They have been confirmed against
a live standalone bait AP, but that AP had no secured twin, so `open-clone`,
`multi-oui` and `signal-jump` never fired and the evil-twin path remains
unexercised. See HANDOVER §9.2 for the two measurements that would calibrate
them.

### Added — telemetry on the SD card

`portal_detect` writes every scan to `/portal/scan.log`: `esp_err`, count,
which store supplied the records, and every BSSID / channel / RSSI / authmode
/ SSID. The card round-trips on every firmware update, so it costs nothing
and needs no cable.

This is what actually solved the Portal Check bug, and it should have been
added at the third attempt rather than the sixth. The device's USB CDC
produced nothing across ~85 s of capture with DTR and then DTR+RTS asserted;
serial is not a usable channel on this board.

### Also

- **Rogue SoftAP rate signature** in `wifi_audit`: first basic rate not
  1 Mbit/s flagged exactly one AP out of 27 real ones — the rogue portal. An
  earlier version tested for a non-ascending rate sequence and flagged 21 of
  27, because the common list drops from 11 to 9. Measured, not assumed.
- **Bruce stock device names** added to `tool_detect`.
- **Evil Twin accepts `/get`** as well as `/login`: the FreeWili portal
  templates submit there, so a twin using them would have captured nothing.
- **IR library installer** (`tools/install-ir-library.sh`), per-category
  batched with a sync between each — an unbatched write corrupted the FAT
  when USB passthrough dropped mid-transfer.
- **ABI 2 -> 4.** `mk_pd_stats_t` and `mk_pd_probe_t` both gained fields, and
  a stale `app.elf` must be rejected rather than handed a short buffer.
- **Two unchecked returns**, both the silent-failure class that caused more
  than one bug in 0.2.0. `EapolCapture::resume()` enabled promiscuous mode
  without checking, so resuming into a radio another screen held would
  capture nothing while reporting *running*; it sets `EAPOL_ERR_PROMISC` now.
  `WifiAudit::begin()` carried a comment about not failing "for a reason
  nobody can see" directly above an unchecked call, and retries after a
  settle. `AuditStats` has no error field to report a second failure through
  and adding one means another ABI bump, so that is a known gap rather than a
  silent fix.
- **`tools/check-sync.sh`** diffs every repo copy against the FeralCat working
  tree and exits non-zero on a mismatch. It has already caught two real
  problems: four stale headers whose capacity raises would have been lost
  (restoring the silent-drop bug), and firmware built and verified from
  sources the repo did not yet have.
- **`tools/redact-samples.py`** replaces addresses and SSIDs in
  `docs/samples/`, preserving the properties those samples are cited for.

### Notes for anyone continuing

Both headline bugs were found by instrumentation and neither by reasoning,
after nine attempts between them. The lesson is not "add logging" in the
abstract — it is that on a device with no usable console, the debug channel
has to be built deliberately and early, and on this hardware the SD card is
that channel because it already moves between the device and the workstation
on every update.

`LICENSE` is set and the repo has been swept for personal identifiers:
addresses, SSIDs, a name in a simulator mock, a hardware serial, and the
commit metadata itself. `portal_detect` and `tool_detect` are both confirmed
on hardware, so the verification table in HANDOVER §4 no longer has gaps.

Still not established: the rogue weights are reasoned rather than measured,
and the evil-twin scoring path has never run — the bait AP it was tested
against had no secured twin, so `open-clone`, `multi-oui` and `signal-jump`
all stayed silent. HANDOVER §9.2 names the two measurements that would
calibrate them.

## 0.2.0 — hardware-validated

Meowrauder was rescoped and extended, then tested on a real MeowKit-S3. Most of
the work in this release was finding out which parts did not actually work.

### Scope rule: no duplication of FeralCat

FeralCat v0.11.0 moved its security tools into signed SD apps, so these already
exist and were **removed** from Meowrauder: AP Scan and detail (`wifianalyzer`),
Probe Sniffer (`probesniffer`), Deauth Watch (`deauthdetect`), Rogue Radar
(`rogueradar`), BLE Spam (`blespamdetect`), Trackers and BLE Fox Hunt
(`trackerdetect`'s proximity radar), and targeted deauth (MeowGotchi already
transmits it). The app dropped from 29,456 to 17,140 bytes before regrowing
with new work.

`deauth_tx` was deleted outright: it duplicated MeowGotchi *and* redefined
`ieee80211_raw_frame_sanity_check`, which FeralCat already defines in
`wifi_hunter.cpp` — two strong definitions the linker had been accepting
silently.

### Added

| Screen | What it adds |
|---|---|
| **Channel Map** | 2.4 GHz occupancy histogram; no channel view existed |
| **PCAP Capture** | raw all-frame capture with radiotap channel + per-frame RSSI |
| **PMKID Harvest** | RSN PMKID → hashcat `WPA*01`, plus WPA3 SAE commit/confirm |
| **AP Audit** | parses the RSN/WPA1/WPS IEs the scan API discards |
| **Fox Hunt (WiFi)** | follow an AP or station by filtered signal |
| **Portal Check** | evil-twin flags over repeated scans + active captive-portal probe |
| **Rogue Tools** | Flipper / Bruce / Pwnagotchi / Pineapple / deauther detection |
| **Evil Twin** | open SoftAP + DNS hijack + captive portal, for authorised assessments |

Plus hidden-SSID resolution from association requests, and an ABI version
guard (`mk_abi_version()`), since `app.elf` ships on the SD card while the ABI
lives in firmware and a mismatched pair silently reads wrong struct offsets.

### Confirmed on hardware

- **`wifi_audit`** — correct IE parse on a real WPA2/WPA3-mixed hidden AP:
  transition mode, PMF capable-not-required, SAE offered, SSID withheld.
- **`pcap_capture`** — 536 packets, **zero malformed**, radiotap present-mask
  valid on every frame, RSSI −68..−58. A sample is in `docs/samples/`.
- **`eapol_capture`** — a complete WPA2 four-way handshake. Verified off-card:
  M3's ANonce is byte-identical to M1's and M4's nonce is all zeros, exactly as
  the protocol requires.
- **`evil_twin`** — full chain: SoftAP, DNS hijack, the OS opening its own
  captive-portal sheet, form capture, plaintext log, post-submit page.
- **`wifi_fox`**, the app, the icon, and the launcher app-detection fix.
- **`tool_detect`** — BLE side detected a real Flipper Zero.

**Not yet run against a radio: `portal_detect`.** `tool_detect`'s WiFi
detectors (Pineapple/Karma, Pwnagotchi, deauther) have also never matched
anything real.

### Fixed — all found on hardware, none findable in the simulator

1. **`[SD!]` false alarm** — the flag was only set inside `log_capture()`, so a
   fresh Evil Twin always claimed the card was unwritable until the first
   submission. Now probed at `begin()`.
2. **`Clone AP` offered where it was refused** — the footer was drawn
   unconditionally while the handler blocked hidden APs. Both now key off
   having a name, which also permits cloning a *recovered* hidden SSID.
3. **`captures.csv` written with no header** — `File::size()` on a
   `FILE_APPEND` handle does not reliably report 0. Uses `SD_MMC.exists()`.
4. **Channel reported as intent, not reality** — `_hop()` set the channel
   without checking. A real capture was 536 frames on one channel while the UI
   claimed to be sweeping, because the Evil Twin's SoftAP held the radio. Now
   reads back with `esp_wifi_get_channel()` and shows `PINNED`.
5. **`cannot create /pcap`** — `SD_MMC.exists()` is unreliable on
   *directories*, and the `mkdir()` fallback then failed *because the directory
   already existed*. The file open is now the only test.
6. **Flipper scored 30% on its name alone** — the 128-bit UUID compare was
   written in display byte order when a UUID is transmitted
   least-significant-byte first, so it could never have matched. Now checks
   both orders, and the evidence screen reports the advertisement's actual
   structure so signatures can be chosen from observation.
7. **Hard reset when scrolling a list** — `mk_td_list()` declared
   `ToolHit tmp[24]` then called `ToolDetect::list()`, which declared
   `ToolHit tmp[40]`: ~4.4 KB of nested frames on a task with ~6 KB of
   headroom. Twelve such arrays existed; Portal Check and AP Audit were
   equally capable of it and had merely never been scrolled far enough.
8. **Hard reset when toggling Rogue Tools to BLE** — caused by the fix for (7).
   Moving ~20 KB into internal `.bss` starved the Bluetooth controller, which
   needs *internal* heap specifically. All twelve buffers now come from PSRAM
   (`mk_psram_buf.h`), returning internal RAM to 47.3% and letting both fixes
   hold at once.
9. **BLE lifecycle** — `tool_detect` never called `BLEDevice::deinit()`, so a
   mode toggle reused a half-live stack with a stale GAP registration. Now
   mirrors `TrackerMonitor`, the BLE scanner already proven from an SD app.
   **This did not fix the reboot.** The lifecycle work is correct and was
   kept, but the crash survived it; see 0.3.0 for the actual cause.

### Notes for anyone continuing

Two of these were self-inflicted: (8) was caused by the fix for (7), and the
BLE teardown took four attempts. The pattern in both cases was reasoning from
API names instead of either reading a working implementation in the same tree
(`tracker_monitor.cpp` stated the correct lifecycle plainly) or asking what had
changed between working and broken.

The single most useful change was not a feature — it was making `begin()`
report *why* it failed. That turned the next fault from a reboot-and-guess into
a one-line diagnosis.

## 0.1.0 — first release

Initial app and firmware engines: `pcap_capture`, `wifi_fox`, `eapol_capture`,
`deauth_tx` (since removed), the launcher app-detection fix, and the native-app
simulator in `sim/`.
