# fix(wifi): scanner wedges after a promiscuous capture, showing no networks

**Branch:** `fix/wifi-scan-latch` (one commit off `1e7a8ec`)
**Files:** `src/ui/ui_wifi_bridge.cpp`, `src/bsp/wifi/WiFi_Class.cpp`

## Reproduce

Run **Rogue Radar** (or the tracker radar), then open the WiFi network list.
It shows no networks, with no error, until the device is restarted.

## Cause

`WiFiScanClass::scanNetworks()` opens with

```cpp
if (WiFiGenericClass::getStatusBits() & WIFI_SCANNING_BIT) return WIFI_SCAN_RUNNING;
```

and sets `WIFI_SCANNING_BIT` as soon as `esp_wifi_scan_start()` succeeds. The
bit is cleared in `_scanDone()` when SCAN_DONE arrives, or by
`scanComplete()` once the scan has outlived `_scanTimeout`.

The blocking form this project uses does neither. When its 10 s wait for
SCAN_DONE expires it returns `WIFI_SCAN_FAILED` and leaves the bit set, and
nothing on the path calls `scanComplete()`. One scan that never completes
therefore latches the bit for the whole boot, and every later scan returns
`-1` without reaching the driver.

Both call sites fold a negative result to "0 APs" —
`ui_wifi_bridge.cpp:136` is `s_scan_count = (n >= 0) ? n : 0;` — which is why
this presents as an empty list rather than as a failure.

A scan started while the radio is claimed for promiscuous capture is the way
to reach that state, and Rogue Radar and the tracker radar both claim it.

## Fix

At both call sites:

1. **Release promiscuous mode before scanning.** This prevents the condition
   instead of recovering from it, and is correct regardless — an STA scan
   cannot run on a radio held for capture.
2. **Call `scanComplete()` if the scan returns negative.** It is the only
   public call that clears `WIFI_SCANNING_BIT`, and by that point the scan has
   certainly outlived `_scanTimeout` (`max_ms_per_chan * 20` = 8 s, against a
   10 s wait), so one call is enough.

## Testing

Verified against arduino-esp32 framework `3.20006.221224`
(`libraries/WiFi/src/WiFiScan.cpp`). Builds clean for `esp32s3box`; no RAM
change, +80 bytes flash.

**Not yet verified on hardware in this exact form.** The mechanism was
diagnosed from a third-party app that hit the same latch — there, the symptom
was `scan failed: rc=-1` on screen and the fix was to bypass the Arduino
wrapper entirely and call `esp_wifi_scan_start()` directly, which is not an
appropriate change for FeralCat's own call sites. The two changes here follow
from the framework source rather than from a reproduction of the fixed
behaviour, so they are worth a maintainer's eye on that point.

## Suggested follow-up (not in this PR)

`ui_wifi_bridge.cpp` folding `WIFI_SCAN_FAILED` to `0` is what turned this
into a silent failure. Surfacing scan errors distinctly from "no networks
found" would have made it self-diagnosing.
