#!/usr/bin/env bash
# Build/run the headless simulators in Docker. Linux paths (the docs assume macOS).
#
#   tools/sim.sh build                     # build the meowkit-sim image
#   tools/sim.sh tui  <scene>  [out.bmp]   # LovyanGFX MK_TUI app screens
#   tools/sim.sh lvgl <screen> [out.bmp]   # LVGL system screens
#   tools/sim.sh list                      # list available scenes/screens
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMG=meowkit-sim:local
cd "$ROOT"
mkdir -p sim/shots

run() { docker run --rm -v "$ROOT":/work -w /work "$IMG" bash -c "$1"; }

case "${1:-}" in
  build) docker build -t "$IMG" -f docker/Dockerfile.sim docker/ ;;
  tui)   run "cmake -S sim/tui -B sim/tui/build >/dev/null && cmake --build sim/tui/build -j >/dev/null
              SDL_VIDEODRIVER=dummy sim/tui/build/meowkit-tui --scene '${2:?scene}' --out '/work/sim/shots/${3:-${2}.bmp}'" ;;
  lvgl)  run "cmake -S sim -B sim/build >/dev/null && cmake --build sim/build -j >/dev/null
              SDL_VIDEODRIVER=dummy sim/build/meowkit-sim --screen '${2:?screen}' --shot '/work/sim/shots/${3:-${2}.bmp}'" ;;
  list)  run "cmake -S sim/tui -B sim/tui/build >/dev/null && cmake --build sim/tui/build -j >/dev/null
              sim/tui/build/meowkit-tui --list" ;;
  *) sed -n '2,9p' "$0"; exit 2 ;;
esac
