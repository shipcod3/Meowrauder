#!/usr/bin/env bash
# Verify this repo's copies match the FeralCat working tree they were taken from.
#
#   FERALCAT_ROOT=/path/to/FeralCat tools/check-sync.sh
#
# Written because four headers silently fell out of sync: the capacity raises
# (MAX_APS 32->96 and friends) lived in .h files while several sync passes
# copied only the .cpp. Anyone building from the repo would have got the
# undersized tables back, which drop entries with no error — exactly the bug
# those raises fixed. Exit 1 on any mismatch so CI or a pre-push hook catches it.
set -euo pipefail

: "${FERALCAT_ROOT:?set FERALCAT_ROOT=/path/to/FeralCat}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
F="$FERALCAT_ROOT"
[ -d "$F/src/system" ] || { echo "error: $F does not look like FeralCat" >&2; exit 1; }

bad=0
report() { echo "  OUT OF SYNC  $1"; bad=1; }

for f in "$ROOT"/firmware/src/system/*; do
    b="$(basename "$f")"
    if [ ! -f "$F/src/system/$b" ]; then
        echo "  only in repo  $b"          # new module not yet upstreamed: fine
        continue
    fi
    cmp -s "$f" "$F/src/system/$b" || report "firmware/src/system/$b"
done

cmp -s "$ROOT/app/app_main.c" "$F/sd files/apps/meowrauder/app_main.c" \
    || report "app/app_main.c"
cmp -s "$ROOT/app/app.elf" "$F/sd files/apps/meowrauder/app.elf" \
    || report "app/app.elf  (rebuild, then re-copy)"

if [ "$bad" -eq 0 ]; then echo "in sync with $F"; else
    echo; echo "Re-copy the files above from $F before committing." >&2
fi
exit "$bad"
