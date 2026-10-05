# Native-app simulator

Runs a native MeowKit app's real `app_main()` on a PC and writes each frame as
a BMP. No hardware, no flashing, no signing.

FeralCat ships two simulators, but neither can see a native app: `sim/` renders
LVGL system screens and `sim/tui/` renders `MK_TUI` built-in app screens, while
a native SD app draws through the flat `mk_app` ABI instead.

This implements every `mk_*` symbol over an off-screen `LGFX_Sprite`, using the
same `MK_TUI` helpers and `efontCN_16` font that `app_sdk.cpp` uses on device —
so the pixels match the hardware rather than approximating it. Radio calls
return fixed sample data; buttons come from a script.

## Build and run

```bash
docker build -t meowkit-sim:local -f ../docker/Dockerfile.sim ../docker
docker run --rm -v "$PWD/..":/work -v "$FERALCAT_ROOT":/feralcat -w /work \
  meowkit-sim:local bash -c '
    cmake -S sim -B sim/build -DFERALCAT_ROOT=/feralcat -DAPP_SRC=app/app_main.c
    cmake --build sim/build -j
    SDL_VIDEODRIVER=dummy sim/build/meowkit-app --keys "D,D,A" --idle 8 --out shot.bmp'
```

`APP_SRC` is a CMake parameter, so this works for any native app, not just
Meowrauder.

## Options

| Flag | Meaning |
|---|---|
| `--keys "D,D,A"` | button script: `U D L R A B` tap, `b` hold-B (exits), `.` idle frame |
| `--out f.bmp` | output path; rewritten on every `mk_gfx_present()` |
| `--frames` | write every frame as `f.bmp.000.bmp`, `…001.bmp`, … |
| `--idle N` | idle polls after the script before a synthetic hold-B (default 3) |
| `--unarmed` | report the active-TX gate as disabled |

The script is consumed one step per `mk_input_poll()`. When it runs out the
harness idles a few frames then reports a long-B, so `app_main()` returns
normally and you see its exit code.

## Worth knowing

It is a real test, not just a screenshot tool — it caught a footer-collision
layout bug in Meowrauder's Channel Map on the first run, and any crash or
non-zero return from `app_main()` shows up immediately.

What it does **not** model: real radio behaviour, SD timing, the ELF loader, or
stack limits on device. An app that renders perfectly here can still fail to
load on hardware.
