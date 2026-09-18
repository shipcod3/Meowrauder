#!/usr/bin/env bash
# Apply the Meowrauder firmware overlay to a FeralCat checkout.
#
#   FERALCAT_ROOT=/path/to/FeralCat tools/install.sh [--dry-run]
#
# Copies the new modules, then applies the patches that touch existing files.
# Safe to re-run: already-applied patches are detected and skipped.
set -euo pipefail

: "${FERALCAT_ROOT:?set FERALCAT_ROOT=/path/to/FeralCat}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

[ -f "$FERALCAT_ROOT/src/system/mk_app_abi.h" ] || {
  echo "error: $FERALCAT_ROOT does not look like a FeralCat checkout" >&2
  exit 1; }

run() { if [ "$DRY" = 1 ]; then echo "  would: $*"; else "$@"; fi; }

echo "FeralCat root: $FERALCAT_ROOT"
echo
echo "== new files =="
while IFS= read -r rel; do
  src="$HERE/firmware/$rel"
  dst="$FERALCAT_ROOT/${rel}"
  echo "  $rel"
  run mkdir -p "$(dirname "$dst")"
  run cp -f "$src" "$dst"
done < <(cd "$HERE/firmware" && find src -type f | sort)

echo
echo "== patches =="
for p in "$HERE"/firmware/patches/*.patch; do
  name="$(basename "$p")"
  if git -C "$FERALCAT_ROOT" apply --reverse --check "$p" >/dev/null 2>&1; then
    echo "  $name — already applied, skipping"
    continue
  fi
  if ! git -C "$FERALCAT_ROOT" apply --check "$p" >/dev/null 2>&1; then
    echo "  $name — DOES NOT APPLY (FeralCat may have moved on)" >&2
    echo "    try: git -C '$FERALCAT_ROOT' apply --3way '$p'" >&2
    continue
  fi
  echo "  $name"
  run git -C "$FERALCAT_ROOT" apply "$p"
done

echo
echo "== app =="
echo "  copy app/ to /apps/meowrauder on the SD card (app.elf + manifest.ini)"
echo
echo "Next:"
echo "  cd '$FERALCAT_ROOT'"
echo "  git submodule update --init --recursive --depth 1"
echo "  docker build -t meowkit-pio:local docker/"
echo "  docker run --rm -v meowkit-pio:/root/.platformio -v \"\$PWD\":/work meowkit-pio:local run"
