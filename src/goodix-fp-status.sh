#!/bin/bash
# goodix-fp-status -- one-shot health report of the K50 fingerprint chain.
# Read-only.  Run as root: goodix-fp-status
set -u

STORE=/var/lib/goodixta
HOST=/opt/goodixta/bin/ta_host
PROVEN=d723e2269b201ba9fa8b32fdac2da483

hr() { printf '%s\n' "------------------------------------------------------------"; }

hr
echo "K50 fingerprint chain status   $(date '+%F %T')"
hr

echo "[host binary]"
if [ -x "$HOST" ]; then
	md5=$(md5sum "$HOST" | awk '{print $1}')
	echo "  $HOST"
	echo "  md5=$md5  size=$(stat -c %s "$HOST")"
	if [ "$md5" = "$PROVEN" ]; then
		echo "  ✓ this is the 10-01 proven host (real-press MATCH verified)"
	else
		echo "  ! NOT the proven host -- expect bad templates / no matches"
	fi
else
	echo "  ✗ missing $HOST"
fi

echo
echo "[enrolled store] $STORE"
n=$(ls -1 "$STORE"/finger_*_*.so 2>/dev/null | grep -vc '_bak')
echo "  finger slot files (non-bak): $n"
if [ -f "$STORE/finger_0_0.so" ]; then
	echo "  finger_0_0.so: $(stat -c %s "$STORE/finger_0_0.so") bytes  md5=$(md5sum "$STORE/finger_0_0.so" | awk '{print $1}')"
	echo "  (a healthy 10-sample template is 57687 bytes; 55172 = the v66 sizeof-NOP corruption)"
fi
[ -f "$STORE/finger_0_0_bak.so" ] && echo "  finger_0_0_bak.so: $(stat -c %s "$STORE/finger_0_0_bak.so") bytes"
ls -1 "$STORE"/asp_template_* 2>/dev/null | sed 's/^/  /'

echo
echo "[PAM]"
grep -v '^#' /etc/pam.d/common-auth | grep -v '^$' | sed 's/^/  /'
echo "  whitelist /etc/goodix-fp-pam.users:"
sed 's/^/    /' /etc/goodix-fp-pam.users
for u in k50; do
	grep -qx "$u" /etc/goodix-fp-pam.users \
		&& echo "  ✓ $u is allowed to unlock with the sensor" \
		|| echo "  ✗ $u is NOT whitelisted"
done
uniq_line=$(grep -n '^[^#]*pam_unix\.so' /etc/pam.d/common-auth | head -1 | cut -d: -f1)
fp_line=$(grep -n '^[^#]*pam_exec\.so.*goodix-fp-pam' /etc/pam.d/common-auth | head -1 | cut -d: -f1)
if [ -n "$uniq_line" ] && [ -n "$fp_line" ] && [ "$uniq_line" -lt "$fp_line" ]; then
	echo "  ✓ pam_unix (line $uniq_line) runs BEFORE the sensor (line $fp_line):"
	echo "    a correct password unlocks instantly, the sensor is only tried"
	echo "    when the password step failed (empty field = use the fingerprint)"
else
	echo "  ! sensor step is not after pam_unix -- passwords would be delayed"
fi
if grep -q '"FP_PAM_SINGLE", "1"' /usr/local/bin/goodix-fp-pam 2>/dev/null; then
	echo "  ✓ helper is in single-shot mode (one Enter at the lock screen = one capture)"
else
	echo "  ! helper is NOT in single-shot mode (multi-press, unsynced rhythm)"
fi

echo
echo "[system settings integration]"
echo "  goodix-fprintd.service: $(systemctl is-active goodix-fprintd 2>/dev/null)/$(systemctl is-enabled goodix-fprintd 2>/dev/null)"
if busctl --system list 2>/dev/null | grep -q 'net.reactivated.Fprint'; then
	echo "  ✓ net.reactivated.Fprint is owned on the system bus (KCM can enroll)"
else
	echo "  ! nobody owns net.reactivated.Fprint -- System Settings cannot enroll"
fi
[ -f /var/lib/goodixta/fprint_names.json ] \
	&& echo "  enrolled finger names: $(cat /var/lib/goodixta/fprint_names.json)"

echo
echo "[screen lock / DPMS]"
echo "  k50-dpms.service: $(systemctl is-active k50-dpms 2>/dev/null)/$(systemctl is-enabled k50-dpms 2>/dev/null)"
echo "  card0-DSI-1 dpms: $(cat /sys/class/drm/card0-DSI-1/dpms 2>/dev/null || echo '?')"
grep -q 'HandlePowerKey=lock' /etc/systemd/logind.conf.d/10-k50-powerkey.conf 2>/dev/null \
	&& echo "  ✓ power key = lock (logind drop-in present)" \
	|| echo "  ! logind power-key drop-in missing"

echo
echo "[sensor]"
for f in finger powered reset_level vdd_microvolts; do
	printf '  spi0.0/%s = %s\n' "$f" "$(cat /sys/bus/spi/devices/spi0.0/$f 2>/dev/null || echo '?')"
done
echo "  running ta_host: $(pgrep -x ta_host || echo none)"

echo
echo "[last capture attempts]  /run/goodix-fp-pam.log (root-only; /run, not /tmp)"
tail -6 /run/goodix-fp-pam.log 2>/dev/null | sed 's/^/  /' || echo "  (no log yet)"
if [ -e /tmp/goodix-fp-pam.tail ] || [ -e /tmp/goodix-fp-pam.log ]; then
	echo "  ! legacy /tmp fingerprint files present -- they are unused now and can be removed:"
	ls -l /tmp/goodix-fp-pam.tail /tmp/goodix-fp-pam.log /tmp/goodix-fp.state 2>/dev/null | sed 's/^/    /'
fi
hr
