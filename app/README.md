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

Menu — `Up`/`Down` select, `A` open, hold `B` exit.
In a screen — `B` back, hold `B` exit, `A` is the per-screen action:

| Screen | `A` | other |
|---|---|---|
| AP Scan | details | `B` back |
| AP Detail | targeted deauth (if TX enabled) | |
| Channel Map | rescan | |
| PCAP Capture | start/stop | `←`/`→` fix channel, `↑` resume hopping |
| EAPOL / PMKID | start/stop | |
| Fox Hunt (either) | hunt selected target | `Up`/`Down` pick |
| Targeted deauth | start/stop | self-stops after 30 s |
