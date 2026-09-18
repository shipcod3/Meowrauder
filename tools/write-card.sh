#!/usr/bin/env bash
# Write firmware.bin + app.elf to the MeowKit SD card, preserving device state.
#
#   FERALCAT_ROOT=/path/to/FeralCat tools/write-card.sh
#
# Refuses to run unless the card is actually mounted. An earlier ad-hoc version
# of this had no such guard: with the card absent the mountpoint was empty and
# it built paths like "/firmware.bin", attempting to write to the root
# filesystem. Only permissions stopped it.
set -euo pipefail

: "${FERALCAT_ROOT:?set FERALCAT_ROOT=/path/to/FeralCat}"
LABEL="${LABEL:-FERALCAT}"

DEV="$(lsblk -rno NAME,LABEL | awk -v l="$LABEL" '$2==l {print "/dev/"$1; exit}')"
[ -n "$DEV" ] || { echo "error: no block device labelled $LABEL — is the card in the reader?" >&2; exit 1; }

MP="$(lsblk -no MOUNTPOINT "$DEV" | head -1)"
[ -n "$MP" ] || MP="$(udisksctl mount -b "$DEV" | sed 's/.* at //;s/\.$//')"

# The guard that was missing: a plausible, mounted, writable directory.
[ -n "$MP" ] && [ -d "$MP" ] && mountpoint -q "$MP" \
  || { echo "error: $DEV is not mounted at a usable path (got '${MP:-}')" >&2; exit 1; }
[ "$MP" != "/" ] || { echo "error: refusing to write to /" >&2; exit 1; }
[ -d "$MP/apps" ] || { echo "error: $MP has no apps/ — that is not the MeowKit card" >&2; exit 1; }

FW="$FERALCAT_ROOT/.pio/build/esp32s3box/firmware.bin"
APP="$FERALCAT_ROOT/sd files/apps/meowrauder"
[ -f "$FW" ] && [ -f "$APP/app.elf" ] || { echo "error: build artefacts missing — build first" >&2; exit 1; }

echo "card: $DEV at $MP"
mkdir -p "$MP/apps/meowrauder"
cp -f "$FW"                "$MP/firmware.bin"
cp -f "$APP/app.elf"       "$MP/apps/meowrauder/app.elf"
cp -f "$APP/manifest.ini"  "$MP/apps/meowrauder/manifest.ini"
sync

ok=1
for pair in "$FW:$MP/firmware.bin" "$APP/app.elf:$MP/apps/meowrauder/app.elf"; do
  src="${pair%%:*}"; dst="${pair##*:}"
  if [ "$(sha256sum "$src" | cut -d' ' -f1)" = "$(sha256sum "$dst" | cut -d' ' -f1)" ]; then
    printf "  OK        %-28s %s B\n" "$(basename "$dst")" "$(stat -c%s "$dst")"
  else
    printf "  MISMATCH  %s\n" "$(basename "$dst")"; ok=0
  fi
done
[ -f "$MP/system/xp.txt" ] && echo "  $(grep '^xp=' "$MP/system/xp.txt") preserved"
sync
udisksctl unmount -b "$DEV" >/dev/null && echo "  unmounted — safe to remove"
[ "$ok" = 1 ] || exit 1
