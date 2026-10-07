#!/bin/bash
# goodix-fp-pam-daemon -- PAM auth step backed by the resident fingerprint daemon.
#
# Design (2026-10-07): the vendor sensor reports finger down/up itself (its FDT
# engine, read over SPI by the trustlet's IRQ command).  The v87 ta_host daemon
# keeps that capture loop resident, so a PAM client does not have to pace
# anything and the user never presses Enter: touch the sensor, the daemon
# matches, stamps /run/goodix-fp.state ("<epoch> <count>"), and this script
# sees the counter move and returns Success.
#
# Falls through to the password (exit 1) if nobody touches the sensor within
# FP_PAM_WAIT seconds -- pam_unix runs before this step, so a typed password is
# verified in ~50 ms and never reaches here at all.
#
# Env:  FP_PAM_WAIT   seconds to watch for a match (default 15)
#       FP_PAM_STATE  state file written by the daemon (default /run/goodix-fp.state)
#       FP_PAM_LOG    log file (default /run/goodix-fp-pam.log)
set -u

U="${PAM_USER:-}"
STATE="${FP_PAM_STATE:-/run/goodix-fp.state}"
LOG="${FP_PAM_LOG:-/run/goodix-fp-pam.log}"
WAIT="${FP_PAM_WAIT:-15}"
USERS=/etc/goodix-fp-pam.users

say() { printf '%s %s\n' "$(date '+%H:%M:%S')" "$*" >>"$LOG" 2>/dev/null || true; }

[ -n "$U" ] || exit 1

# Only whitelisted accounts may authenticate by fingerprint.
if [ ! -r "$USERS" ] || ! grep -qxF "$U" "$USERS" 2>/dev/null; then
	say "user=$U not whitelisted -- password path"
	exit 1
fi

base=0
if [ -r "$STATE" ]; then
	base=$(awk 'NR==1{print $2+0}' "$STATE" 2>/dev/null)
	base=${base:-0}
fi

T0=$(date +%s)
end=$((T0 + WAIT))
say "start user=$U wait=${WAIT}s base=$base"

started=0
while [ "$(date +%s)" -lt "$end" ]; do
	if [ -r "$STATE" ]; then
		read -r mt cnt <"$STATE" 2>/dev/null || true
		if [ -n "${cnt:-}" ] && [ "$cnt" -gt "$base" ] 2>/dev/null; then
			say "MATCH user=$U stamp=${mt:-?} count=$cnt"
			exit 0
		fi
	fi

	# systemd keeps it alive normally; start it by hand if it is missing so a
	# single touch still gets a chance.
	if ! pgrep -x ta_host.v87 >/dev/null 2>&1 && ! pgrep -x ta_host >/dev/null 2>&1; then
		if [ "$started" = 0 ]; then
			started=1
			say "daemon not running -- starting (bringup costs ~10s, extending wait)"
			systemctl start goodix-fprintd.service 2>/dev/null
			if ! pgrep -x ta_host.v87 >/dev/null 2>&1 && ! pgrep -x ta_host >/dev/null 2>&1; then
				setsid nohup env TA_STATE_FILE="$STATE" GOODIXTA_QUIET=1 \
					/opt/goodixta/bin/ta_host.v87 /opt/goodixta/ta/goodixfp.ta d \
					>>/run/goodix-fp-fpd.log 2>&1 &
			fi
			end=$((end + 12))
		fi
	fi
	sleep 0.25
done

say "no-match user=$U (waited ${WAIT}s)"
exit 1
