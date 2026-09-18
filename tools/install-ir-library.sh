#!/usr/bin/env bash
# Install a Flipper-format IR library onto the MeowKit SD card.
#
#   IR_SRC=/path/to/Flipper-IRDB tools/install-ir-library.sh
#   INCLUDE_CONVERTED=1 ...      also install the _Converted_ tree
#
# FeralCat's Infrared app reads the Flipper .ir format natively
# (src/app/app_09/infrared.cpp), so the files are a drop-in. Measured limits:
#
#   * path buffers are char[128]; the worst curated path is well inside that.
#   * _listIrFiles() builds an unbounded std::vector<String> per directory, so
#     a directory of thousands of entries would exhaust the heap. The worst
#     curated directory is 314 files (TVs); nothing approaches 500.
#
# _Converted_ is skipped by default. It is 6,944 of 8,461 files — machine
# converted Pronto dumps with names like
# "PMD500U_(EVEN)_(SERIAL-_RCA_MALE_TIP_=_S)_STEREO_DOUBLE_CASS.ir", unreadable
# on a 320x240 screen, and it contains the only directory near the parser's
# per-directory limit (_Converted_/Pronto/S/Sony, 342 files). The 1,517 curated
# files are the useful ones.
#
# Copying is done per category with a sync between each, because this card is
# on a USB passthrough that has dropped mid-write: the block device
# re-enumerated under a mounted filesystem, which corrupted the FAT and needed
# fsck. Per-category batches mean a drop costs one category, not the lot.
set -euo pipefail

: "${IR_SRC:?set IR_SRC=/path/to/an/IR/library}"
LABEL="${LABEL:-FERALCAT}"
INCLUDE_CONVERTED="${INCLUDE_CONVERTED:-0}"

DEV="$(lsblk -rno NAME,LABEL | awk -v l="$LABEL" '$2==l {print "/dev/"$1; exit}')"
[ -n "$DEV" ] || { echo "error: no block device labelled $LABEL" >&2; exit 1; }
MP="$(lsblk -no MOUNTPOINT "$DEV" | head -1)"
[ -n "$MP" ] || MP="$(udisksctl mount -b "$DEV" | sed 's/.* at //;s/\.$//')"
[ -n "$MP" ] && mountpoint -q "$MP" && [ "$MP" != "/" ] && [ -d "$MP/apps" ] \
  || { echo "error: $DEV is not the MeowKit card" >&2; exit 1; }

echo "source: $IR_SRC"
echo "card:   $DEV at $MP"
mkdir -p "$MP/infrared"

copied=0; failed=""
for dir in "$IR_SRC"/*/; do
  cat="$(basename "$dir")"
  if [ "$cat" = "_Converted_" ] && [ "$INCLUDE_CONVERTED" != "1" ]; then
    echo "  skip  _Converted_ (set INCLUDE_CONVERTED=1 to include)"
    continue
  fi
  n=$(find "$dir" -name '*.ir' | wc -l)
  [ "$n" -gt 0 ] || continue
  if rsync -a --include='*/' --include='*.ir' --include='*.IR' --exclude='*' \
        "$dir" "$MP/infrared/$cat/" 2>/dev/null; then
    sync
    got=$(find "$MP/infrared/$cat" -name '*.ir' 2>/dev/null | wc -l)
    printf "  ok    %-28s %s/%s\n" "$cat" "$got" "$n"
    copied=$((copied + got))
  else
    printf "  FAIL  %-28s (USB drop? re-run to resume)\n" "$cat"
    failed="$failed $cat"
  fi
done

# loose .ir files at the top level
rsync -a --include='*.ir' --include='*.IR' --exclude='*' "$IR_SRC/" "$MP/infrared/" 2>/dev/null || true
sync

echo "  total on card: $(find "$MP/infrared" -name '*.ir' | wc -l) .ir files"
[ -z "$failed" ] || echo "  incomplete:$failed"
sync
udisksctl unmount -b "$DEV" >/dev/null 2>&1 && echo "  unmounted — safe to remove"
[ -z "$failed" ]
