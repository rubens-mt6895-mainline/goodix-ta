#!/bin/bash
# goodix-fp-restore -- put a backed-up fingerprint store back in place.
#
#   goodix-fp-restore                 # list the available backups
#   goodix-fp-restore <dir>           # restore that backup
#   goodix-fp-restore --last          # restore the most recent one
#
# The trustlet reads /var/lib/goodixta at init, so nothing may be running while
# we swap the files.  Every restore first snapshots what is there now.
set -eu

STORE=/var/lib/goodixta
ROOTS=(/root/fprintd-deleted /root /home/k50)

usage() {
	echo "usage: goodix-fp-restore [--last | <backup-dir>]"
	echo
	echo "backups:"
	find "${ROOTS[@]}" -maxdepth 2 -type d \
		\( -name 'fp_*' -o -name 'fprintd-deleted*' -o -name 'fp_store_*' \) \
		-printf '  %T@ %p\n' 2>/dev/null | sort -rn | cut -d' ' -f2- | sed 's/^/  /'
}

if [ $# -eq 0 ]; then
	usage
	exit 0
fi

if [ "$1" = "--last" ]; then
	SRC=$(find "${ROOTS[@]}" -maxdepth 2 -type d \
		\( -name 'fp_*' -o -name 'fprintd-deleted*' \) -printf '%T@ %p\n' 2>/dev/null \
		| sort -rn | head -1 | cut -d' ' -f2-)
	[ -n "$SRC" ] || { echo "no backup found"; exit 1; }
else
	SRC=$1
fi

# a backup dir may either be the store itself or contain a goodixta/ subdir
if [ -d "$SRC/goodixta" ]; then
	SRC="$SRC/goodixta"
fi
[ -f "$SRC/finger_0_0.so" ] || { echo "$SRC does not look like a store (no finger_0_0.so)"; exit 1; }

pgrep -x ta_host >/dev/null && { echo "ta_host is running -- stop it first"; exit 1; }

NOW=$(date +%Y%m%d-%H%M%S)
mkdir -p "$STORE" "/root/fp_store_replaced_$NOW"
for f in "$STORE"/finger_*.so* "$STORE"/asp_template_* "$STORE"/fprint_names.json; do
	[ -e "$f" ] || continue
	mv "$f" "/root/fp_store_replaced_$NOW/"
done

cp -a "$SRC"/. "$STORE"/
chown -R k50:k50 "$STORE" 2>/dev/null || true

echo "restored $SRC -> $STORE (previous store saved in /root/fp_store_replaced_$NOW)"
ls -l "$STORE" | grep -E 'finger|asp' | sed 's/^/  /'
