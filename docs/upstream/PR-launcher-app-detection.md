# fix(launcher): native /apps tiles disappear until a reboot

**Branch:** `fix/launcher-app-detection` (one commit off `1e7a8ec`)
**Files:** `src/app/launcher/launcher.cpp`, `src/app/launcher/launcher.h`

## The bug

Native app tiles are scanned lazily, the first time the Apps menu is opened,
and `_nativeScanned` is then set unconditionally:

```cpp
if (!_nativeScanned) {
    native_apps_scan();
    _nativeScanned = true;
    loadAppsMenu();
}
```

If that scan runs while the SD card is unavailable it latches an empty
catalog for the rest of the boot, and every native tile stays hidden until
the device is restarted. The card being unavailable is not an edge case — it
is the window right after an insert, and the whole time a USB MSC session
holds `SD_MMC`.

## The fix

* Scan from `onLoop()` as soon as the card is ready, rather than waiting for
  the user to open the Apps menu, with a 250 ms settle window so a freshly
  mounted card is not scanned mid-mount. It stays off the boot path, which is
  why it was lazy to begin with.
* Invalidate the catalog when a USB MSC session ends — `SD_MMC` is remounted
  underneath it, so the previous listing no longer describes the card.
* The lazy path in `processNavEvents()` becomes a fallback and refuses to
  latch while `_sd_ready` is false. That is the actual defect.

The grid rebuild reuses the guard the Lua catalog rebuild already uses (only
between animations, only with no pending selection), so it cannot fire during
a screen load.

## Testing

Confirmed on MeowKit-S3 hardware: tiles appear without a restart, survive a
card removal and re-insert, and survive a USB MSC session. Builds clean for
`esp32s3box`.

## Notes

Found while developing a third-party SD app, but the bug and the fix are
entirely in FeralCat and independent of it.
