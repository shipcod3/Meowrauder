#!/usr/bin/env bash
# Build a native MeowKit ELF app with the locally-installed xtensa toolchain.
#
# Same compile/strip recipe as "sd files/apps/build_app.sh", minus Docker —
# that script hardcodes a macOS Docker path. Keep the two in sync.
#
# Usage: FERALCAT_ROOT=/path/to/FeralCat tools/build_app_local.sh <app-dir>
set -euo pipefail
DIR="${1:?usage: build_app_local.sh <app-dir>}"
DIR="$(cd "$DIR" && pwd)"
[ -f "$DIR/app_main.c" ] || { echo "no app_main.c in $DIR"; exit 1; }

# mk_app_abi.h lives with the firmware. Point FERALCAT_ROOT at a checkout.
: "${FERALCAT_ROOT:?set FERALCAT_ROOT=/path/to/FeralCat}"
SDK="$(cd "$FERALCAT_ROOT/src/system" && pwd)"
BIN="$HOME/.espressif/tools/xtensa-esp32s3-elf/esp-2021r2-patch5-8.4.0/xtensa-esp32s3-elf/bin"
GCC="$BIN/xtensa-esp32s3-elf-gcc"
STRIP="$BIN/xtensa-esp32s3-elf-strip"

# -O0 + -fno-merge-constants: the elf_loader captures .rodata by name only and
# cannot handle SHF_MERGE|SHF_STRINGS merged-string rodata (ES=1) that -O1+
# produces; -O0 also avoids jump tables, which need relocation the loader lacks.
"$GCC" -mlongcalls -nostartfiles -nostdlib -fPIC -shared -e app_main \
     -fdata-sections -ffunction-sections -Wl,--gc-sections \
     -fvisibility=hidden -O0 -fno-merge-constants -I"$SDK" \
     -Wall -Wextra \
     -o "$DIR/app.elf" "$DIR/app_main.c"

"$STRIP" --strip-unneeded \
  --remove-section=.comment --remove-section=.got.loc \
  --remove-section=.dynamic --remove-section=.xt.lit \
  --remove-section=.xt.prop --remove-section=.xtensa.info \
  "$DIR/app.elf"

echo "built $DIR/app.elf ($(stat -c%s "$DIR/app.elf") bytes)"
