# The app

| File | |
|---|---|
| `app_main.c` | the whole app — pure C against `mk_app_abi.h` |
| `manifest.ini` | name, icon, entry point |
| `app.elf` | prebuilt, **unsigned** (see the root README) |

Install: copy this directory to `/apps/meowrauder` on the SD card, then restart
the device. `app.elf` and `manifest.ini` are the only files the launcher needs.

Rebuild:

```bash
FERALCAT_ROOT=/path/to/FeralCat ../tools/build_app_local.sh .
```

## Controls

Buttons and touch both work; a tap synthesises the press it stands for, so
nothing is touch-only and nothing is button-only.

Menu — `Up`/`Down` select, `A` open, hold `B` exit.
In a screen — `B` back, hold `B` exit, `A` is the per-screen action:

| Screen | `A` | other |
|---|---|---|
| Channel Map | rescan | |
| PCAP Capture | start/stop | `←`/`→` fix channel, `↑` resume hopping |
| PMKID Harvest | start/stop | |
| AP Audit | AP detail | `Up`/`Down` pick |
| AP Detail | clone AP → Evil Twin (needs an SSID) | |
| Fox Hunt (WiFi) | hunt selected target | `Up`/`Down` pick |
| Portal Check | probe the selected open network | `Up`/`Down` pick |
| Rogue Tools | evidence detail | `A` also toggles WiFi/BLE on the list |
| Evil Twin | start/stop | captures land in `/portal/captures.csv` |

### Touch

Added in 0.4.0. The panel is the same FT6336 LVGL drives for the launcher,
reached through `mk_touch_get()` (ABI 5) — FeralCat v0.11.2's tap navigation
is LVGL-side and a native app has no LVGL indev, so it could not be reused.

| Tap | Does |
|---|---|
| header strip, full width (`y < 24`) | **back** |
| footer right (`x >= 150`, `y >= 217`) | **back** |
| footer left (`x < 150`, `y >= 217`) | `A` |
| either back zone on the menu | **exit the app** |
| a tool on the menu | select **and open** it |
| a row on any list | select it |

Back is deliberately reachable from two zones, and the menu's back zones exit
the app. Before this, only a long press on `B` could leave Meowrauder, which
is no use on a unit with a failed `B` button — the reason touch was added.

The footer zone starts at `y >= 217` rather than the drawn footer's 220 to
give a slightly larger target. It cannot start lower: the menu's sixth
visible row occupies `y 185..216`, so a zone at 212 would swallow the bottom
of a selectable row.
