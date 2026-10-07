#!/bin/sh
# goodix-fp-syncslots -- make the Goodix TA's persistent template store loadable.
#
# Root cause found 2026-10-06 22:45 (K50 rubens / mt6895, ta_host v86b port):
# the trustlet's gf_ta_load_finger walks EVERY per-user template slot
# (max_fingers_per_user = 5, as printed by gf_algo_common_init) and returns
# GF_ERROR_READ_SECURE_OBJECT_FAILED (errno 1034) as soon as one
# /var/lib/goodixta/finger_0_<i>.so is missing.  That 1034 aborts the whole
# load, so the TA is left with an EMPTY fingerlist and every auth press ends in
# GF_ERROR_NOT_MATCH (1006) -- the 2026-10-06 22:36 run had 6/6 presses
# "no match" for exactly this reason (the template itself was read fine).
#
# Enrollment only ever writes slot 0 (finger_0_0.so), so slots 1..4 have to be
# replicated from it.  The TA then writes its own *_bak.so backup objects while
# loading ("sync data to backup object"), so those need not be created here.
#
# Second mismatch, same session: the auth path asks for the ASP feature object
# asp_template_features_0_1.so (fid 1) while the enroll-time save wrote
# asp_template_features_0_-1.so (poisoned fid), which made
# gf_algo_asp_load_templates_features fail and break the load as well.
#
# Verified: with this in place gf_ta_load_finger exits cleanly
# ("load so(finger_0_4.so) success", "sync data to backup object ... success")
# and the only remaining 1034 comes from the benign first-boot
# asp_last_asplevel.so miss.
#
# 2026-10-07: the fid-1 ASP copy is now FORCED (not only when missing), because a
# re-enrollment rewrites asp_template_*_0_-1.so and would otherwise leave the
# previous enrollment's stale _0_1.so in place.
#
# Usage: goodix-fp-syncslots     (idempotent; run after every enrollment)
set -e
D=/var/lib/goodixta
[ -f "$D/finger_0_0.so" ] || { echo "goodix-fp-syncslots: $D/finger_0_0.so missing" >&2; exit 1; }
for i in 1 2 3 4; do
	cp -f "$D/finger_0_0.so" "$D/finger_0_$i.so"
done
if [ -f "$D/asp_template_features_0_-1.so" ]; then
	cp -f "$D/asp_template_features_0_-1.so" "$D/asp_template_features_0_1.so"
	[ -f "$D/asp_template_score_0_-1.so" ] && cp -f "$D/asp_template_score_0_-1.so" "$D/asp_template_score_0_1.so"
fi
chown k50:k50 "$D"/finger_0_*.so "$D"/asp_template_*.so 2>/dev/null || true
ls -l "$D"/finger_0_*.so "$D"/asp_template_*.so
echo "slot sizes: $(stat -c %s "$D"/finger_0_0.so) (Oct-1 proven template was 57719)"
