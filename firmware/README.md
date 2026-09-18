# Firmware side

Meowrauder reaches the radio through FeralCat's `mk_app` ABI, which is
receive-only in stock FeralCat and has no capture-to-file or transmit surface.
These four engines add that, and the patches expose them to native apps.

Apply with [`../tools/install.sh`](../tools/install.sh).

## New modules (`src/system/`)

| Module | What it does |
|---|---|
| `pcap_capture` | Raw 802.11 → `/pcap/cap_NNN.pcap`, radiotap header (channel + RSSI) |
| `wifi_fox` | WiFi target table + signal following for Fox Hunt |
| `eapol_capture` | EAPOL-Key M1–M4 detection, PMKID extraction, hashcat output, WPA3 SAE commit/confirm |
| `wifi_audit` | Parses the RSN / WPA1 / WPS elements the scan API discards; beacon fingerprint |
| `portal_detect` | Evil-twin flags across repeated scans, active captive-portal probe, weighted rogue score; logs each scan to `/portal/scan.log` |
| `tool_detect` | Flipper / Bruce / Pwnagotchi / Pineapple / deauther detection on both radios |
| `evil_twin` | Open SoftAP + DNS hijack + captive portal from `/portal/<name>.html` |
| `mk_psram_buf.h` | Header-only: one-shot PSRAM allocation for module state tables |
| `mk_crumb` | Breadcrumbs in `RTC_NOINIT` memory that survive a panic reboot |

`deauth_tx` was in this list and has been **deleted** — it duplicated
MeowGotchi and redefined a symbol FeralCat already defines (see the notes
below).

`src/ui/images/ui_img_ic_meowrauder.c` is the app icon as an LVGL
`TRUE_COLOR_ALPHA` asset (70×70, 3 bytes/px: RGB565 little-endian + alpha).

## Patches (existing files)

| Patch | File(s) | Why |
|---|---|---|
| `01-abi-declarations` | `src/system/mk_app_abi.h` | declares `mk_pcap_*`, `mk_fox_*`, `mk_eapol_*`, `mk_wa_*`, `mk_pd_*`, `mk_td_*`, `mk_et_*`, `mk_crumb_*`, and `MK_ABI_VERSION` (currently **4**) |
| `02-sdk-implement-and-export` | `src/system/app_sdk.cpp` | implements them and adds them to the ELF-loader symbol table |
| `03-launcher-icon-mapping` | `src/app/app.h` | maps `icon=meowrauder` to the new asset |
| `04-persist-tx-gate` | `src/system/persist.h` | adds `PKEY_TX_EN`, the active-TX gate |
| `05-fix-app-detection` | `src/app/launcher/launcher.{cpp,h}` | **bug fix, independent of Meowrauder** |

### About patch 05

Stock FeralCat scans `/apps` **once per boot**, and only on the Home →
joystick-Left transition. If that scan runs while the SD is unavailable — which
is exactly what a USB MSC session causes, since `usb_msc_enable()` calls
`SD_MMC.end()` — it latches an empty catalogue and **every app tile stays
hidden until the next reboot**.

The patch scans from `onLoop()` as soon as the card is ready (250 ms settle
window, off the boot path), invalidates the catalogue when MSC releases the SD
(mirroring the existing `_luaUsbWasActive` pattern), and makes the Home→Left
path a fallback that never latches while the card is absent.

This is useful to FeralCat with or without Meowrauder and is worth upstreaming.

## Notes for anyone extending this

- **Promiscuous callbacks run in the WiFi task.** Do not touch the SD there.
  Both capture engines length-prefix frames into a PSRAM ring and drain from
  `loop()`; a full ring increments a `dropped` counter rather than corrupting
  the file.
- **Native app ELFs must be built `-O0 -fno-merge-constants`.** FeralCat's ELF
  loader captures `.rodata` by section name and cannot handle the
  `SHF_MERGE|SHF_STRINGS` merged-string rodata that `-O1+` produces, nor the
  jump tables it emits. `.data.rel.ro` *is* handled (allocated, copied,
  relocated in `esp_elf.c`).
- **Memory has three homes and only one is right for bulk buffers.** The ELF
  entry runs on the launcher task's stack (~6 KB headroom), so multi-KB arrays
  cannot live there — ~4.4 KB of nested frames hard-reset the device when
  scrolling a list. But internal `.bss` is the wrong answer too: moving ~20 KB
  there starved the Bluetooth controller, which needs *internal* heap
  specifically, and BLE init then reset the device on a mode toggle. Use
  `mk_psram_buf.h`, which allocates once from the 8 MB of otherwise idle PSRAM.
  These are UI-rate buffers; the slower access does not matter.

- **Check the return of every `esp_wifi_*` / `esp_ble_*` call that can fail.**
  An unchecked `esp_wifi_set_promiscuous()` turned a real radio-contention bug
  into a dead button that took a reboot and a wrong theory to diagnose.

- **`SD_MMC.exists()` is unreliable on directories.** Do not gate on it — a
  `mkdir()` fallback will then fail *because the directory already exists*.
  Create unconditionally and let the file open be the test.

- **BLE lifecycle: copy `TrackerMonitor`.** `deinit(false)` → `delay(50)` →
  `init("")` on every start, a real `deinit()` on stop, and track your own
  inited flag. Reusing an already-initialised stack across a mode toggle leaves
  a stale GAP registration and hard-resets the device.
- **Never allocate on a callback path.** `heap_caps_malloc` from inside
  `portENTER_CRITICAL_ISR` (the promiscuous callback) or `portENTER_CRITICAL`
  (the BLE GAP callback) is not survivable. Every module's state table is
  warmed in `begin()`; the lookups bail on a null table rather than allocate.
  A lazy `mk_psram_buf` call on that path was the real cause of a reboot that
  four earlier theories failed to explain.
- **Scanning for APs is not `WiFi.scanNetworks()`.** Arduino's wrapper opens
  with `if (getStatusBits() & WIFI_SCANNING_BIT) return WIFI_SCAN_RUNNING;`,
  and that bit latches for the whole boot if a scan is started while the
  radio is claimed for promiscuous capture — only `scanComplete()` clears it,
  and the blocking path never calls it. Use
  `esp_wifi_scan_start(&cfg, block=true)`, and read the results from
  *Arduino's* store: its `SCAN_DONE` handler calls
  `esp_wifi_scan_get_ap_records()`, which frees the driver's list before app
  code regains control. `portal_detect::loop()` documents both.
- **There is no usable serial console.** This board's USB CDC produced nothing
  across ~85 s of capture with DTR and then DTR+RTS asserted, and panic output
  over TinyUSB does not reliably escape the chip. Log to the SD card, which
  round-trips to the workstation on every firmware update anyway, and use
  `mk_crumb` for anything that ends in a reset.
