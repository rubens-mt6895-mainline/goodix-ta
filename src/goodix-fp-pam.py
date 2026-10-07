#!/usr/bin/env python3
# goodix-fp-pam -- pam_exec step that unlocks the K50 with the Goodix sensor.
#
# WHY THIS SHAPE (forensics, 2026-10-06):
#   * Only the operator-paced TA_PRESS capture has ever matched on this
#     device (session C2: 2/8 real presses).  Capturing when the finger
#     ARRIVES (GOODIX_FP_IOC_WAIT_FINGER edge, or the resident daemon loop)
#     yields either a GF_FDT_NAV base image (garbage finger_id 3435973835)
#     or a TOO_FAST (1094) reject -- 0 matches in every free-running run.
#   * Presence detection is unavailable: /sys/bus/spi/devices/spi0.0/finger,
#     gpio-136 in /sys/kernel/debug/gpio and GOODIX_FP_IOC_FINGER_STATE all
#     stayed constant while a finger was pressed, so the driver cannot tell
#     us "a finger is on the sensor".
#   * What DOES correlate: the capture status.  `final status=1094` means the
#     frame was empty/rejected (no finger), `final status=0` or `1064` means a
#     real finger image was taken.  So this wrapper uses the status to decide
#     whether the user is even trying to use the fingerprint, and bails out
#     quickly (cheap password fallback) when they are not.
#
# Flow: keep the trustlet resident in TA_PRESS mode and feed its Enter
# keystrokes on the proven rhythm -- prompt -> finger placed -> ~2.5 s ->
# capture (Enter) -> "lift finger" -> CYCLE -> lift (Enter) -> next press.
#
# PAM ORDER (2026-10-07): /etc/pam.d/common-auth runs pam_unix BEFORE this
# module, so a correct password unlocks instantly and this capture only ever
# runs when the password failed (empty field / wrong password / fingerprint
# attempt).  A user who wants the fingerprint just presses Enter with the
# password field empty -- pam_unix fails in milliseconds, then this module
# gets the sensor for up to FP_PAM_BUDGET seconds.
#
# SINGLE-SHOT MODE (default, FP_PAM_SINGLE=1): take exactly ONE capture per
# PAM invocation.  The greeter's "press Enter" then IS the rhythm: the user
# puts the finger on the sensor, presses Enter, we capture after a short
# settle; on a failure the greeter asks again and he lifts/re-places and
# presses Enter again.  Every capture is therefore synced to an intentionally
# placed, settled finger -- the only condition that has ever matched here --
# instead of guessing a hold/lift rhythm the user cannot see.  Set
# FP_PAM_SINGLE=0 to get the old multi-press behaviour.
#
# Env knobs: FP_PAM_PRESSES, FP_PAM_BUDGET, FP_PAM_SETTLE, FP_PAM_CYCLE,
#            FP_PAM_FIRST_SETTLE, FP_PAM_PROBE_SETTLE, FP_PAM_PROBE_CYCLE,
#            FP_PAM_ABSENT_PRESSES, FP_PAM_SINGLE, FP_PAM_VERBOSE,
#            FP_PAM_KEEP
import fcntl
import os
import subprocess
import sys
import time

GOODIX = "/opt/goodixta"
WHITELIST = "/etc/goodix-fp-pam.users"
# Runtime files live in /run: it is root-only, so the PAM step (which runs as
# root) can always rewrite them.  /tmp was the original location and it is a
# trap -- it is world-writable + sticky, so a file that a k50-owned process
# created there can no longer be opened by the root helper (kernel
# fs.protected_regular => EACCES) and k50 could even pre-plant a symlink.
# Callers may override these for per-user diagnostics.
LOG = os.environ.get("FP_PAM_LOG", "/run/goodix-fp-pam.log")
TAIL = os.environ.get("FP_PAM_TAIL", "/run/goodix-fp-pam.tail")
STATE = os.environ.get("FP_PAM_STATE", "/run/goodix-fp.state")
LOCK = os.environ.get("FP_PAM_LOCK", "/run/goodix-fp-pam.lock")

PRESSES = int(os.environ.get("FP_PAM_PRESSES", "8"))
BUDGET = float(os.environ.get("FP_PAM_BUDGET", "40"))
# Prompt -> Enter when a finger has already been seen (comfortable rhythm).
SETTLE = float(os.environ.get("FP_PAM_SETTLE", "2.5"))
# "lift finger" -> Enter.
CYCLE = float(os.environ.get("FP_PAM_CYCLE", "1.5"))
# Grace before the very first capture: the lock screen has just shown the
# hint and the user has to get the finger onto the sensor.  In single-shot
# mode the finger is normally already placed when he presses Enter.
FIRST_SETTLE = float(os.environ.get("FP_PAM_FIRST_SETTLE", "2.0"))
# One capture per PAM invocation (see the header comment).
SINGLE = os.environ.get("FP_PAM_SINGLE", "1") == "1"
# After the frame status line, drain this long so that a "MATCH" line printed
# right behind it is still seen before we stop reading.
DRAIN = float(os.environ.get("FP_PAM_DRAIN", "0.8"))
# While no finger has been seen yet, answer prompts quickly so that an
# unlock attempt without a fingerprint falls through fast.
PROBE_SETTLE = float(os.environ.get("FP_PAM_PROBE_SETTLE", "0.3"))
# Shorter lift->next-press cycle while still probing (nothing on the sensor
# to settle, so there is no reason to wait a full CYCLE).
PROBE_CYCLE = float(os.environ.get("FP_PAM_PROBE_CYCLE", "1.0"))
# That many consecutive empty frames (status 1094) => the user is not using
# the fingerprint: give up and let pam_unix ask for the password.
ABSENT_N = int(os.environ.get("FP_PAM_ABSENT_PRESSES", "3"))
KEEP = os.environ.get("FP_PAM_KEEP") == "1"
VERBOSE = os.environ.get("FP_PAM_VERBOSE") == "1"

# Capture statuses that mean "a real finger image was taken".
EMPTY_STATUS = "1094"


class _Sink:
    """No-op sink returned whenever a best-effort file cannot be opened."""

    def write(self, data):
        return len(data)

    def flush(self):
        pass

    def close(self):
        pass


def open_sink(path, mode="ab", perm=0o644):
    """Best-effort open that never raises and never follows a symlink.

    Diagnostics (log, frame tail, state stamp) and the advisory lock must not
    be able to change the PAM verdict: on any failure we hand back a no-op
    sink instead of crashing the unlock path.  2026-10-07 forensics: the old
    /tmp paths could not even be created by the root-run helper once a k50
    process owned them.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
    flags |= os.O_APPEND if "a" in mode else os.O_TRUNC
    try:
        fd = os.open(path, flags, perm)
    except OSError:
        return _Sink()
    try:
        return os.fdopen(fd, mode)
    except (OSError, ValueError):
        try:
            os.close(fd)
        except OSError:
            pass
        return _Sink()


def write_file(path, text):
    """Best-effort whole-file write (state stamp); never raises."""
    fh = open_sink(path, "wb")
    try:
        fh.write(text.encode())
    except OSError:
        pass
    finally:
        fh.close()


def log(msg):
    line = "%s [pam] %s\n" % (time.strftime("%H:%M:%S"), msg)
    fh = open_sink(LOG, "a")
    try:
        fh.write(line)
    except OSError:
        pass
    finally:
        fh.close()
    if VERBOSE:
        sys.stderr.write(line)
        sys.stderr.flush()


def whitelisted(user):
    if not user:
        return False
    try:
        with open(WHITELIST) as fh:
            for raw in fh:
                if raw.strip() == user:
                    return True
    except OSError:
        return False
    return False


def run(user):
    cmd = ["./bin/ta_host", "ta/goodixfp.ta", "auth", str(PRESSES)]
    env = dict(os.environ)
    env.update({
        "TA_PRESS": "1",
        "TA_MIN_TPL": "10",
        "TA_LOG_LEVEL": "3",
        "GOODIXTA_QUIET": "1",
    })
    env.pop("FP_VERIFY", None)

    t0 = time.time()
    log("start user=%s presses=%d budget=%ss single=%s (put the finger on the "
        "sensor; rhythm: press ~2s, lift, repeat)"
        % (user, PRESSES, BUDGET, SINGLE))
    tail = open_sink(TAIL, "wb")
    if not KEEP:
        write_file(STATE, "0 0\n")            # invalidate stale stamps

    proc = subprocess.Popen(cmd, cwd=GOODIX, env=env, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, bufsize=0)
    os.set_blocking(proc.stdout.fileno(), False)

    matched = 0
    presses = 0
    absent = 0
    seen_finger = False
    shot_at = 0.0
    buf = b""
    try:
        while True:
            if time.time() - t0 > BUDGET:
                log("budget %.0fs reached (matched=%d)" % (BUDGET, matched))
                break
            chunk = proc.stdout.read(4096)
            if not chunk:
                if proc.poll() is not None and not buf:
                    break
                time.sleep(0.03)
                # fall through: the stop conditions at the end of the loop
                # must still be evaluated while the capture is quiet
                chunk = b""
            buf += chunk
            tail.write(chunk)
            tail.flush()
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                text = line.decode("utf-8", "replace")
                if VERBOSE and ("press " in text or "then press Enter" in text
                                or "frame=" in text or "MATCH" in text):
                    sys.stderr.write("  | %s\n" % text.strip())
                    sys.stderr.flush()
                if "MATCH! finger recognised" in text:
                    matched += 1
                    log("MATCH (%d) at %.1fs" % (matched, time.time() - t0))
                elif "final status=" in text:
                    status = text.rsplit("final status=", 1)[1].split()[0]
                    if shot_at == 0.0:
                        shot_at = time.time()
                    if status == EMPTY_STATUS:
                        absent += 1
                    else:
                        seen_finger = True
                        absent = 0
                        if VERBOSE:
                            log("finger image taken (status=%s)" % status)
                elif "lift the finger FULLY" in text:
                    presses += 1
                    if SINGLE:
                        pass          # one capture per invocation; do not cycle
                    else:
                        time.sleep(CYCLE if seen_finger else PROBE_CYCLE)
                        try:
                            proc.stdin.write(b"\n")
                            proc.stdin.flush()
                        except (OSError, ValueError):
                            pass
                elif "then press Enter" in text:
                    if presses == 0:
                        wait = FIRST_SETTLE
                    elif seen_finger:
                        wait = SETTLE
                    else:
                        wait = PROBE_SETTLE
                    time.sleep(wait)
                    try:
                        proc.stdin.write(b"\n")
                        proc.stdin.flush()
                    except (OSError, ValueError):
                        pass
            if matched:
                break
            if SINGLE and shot_at and (time.time() - shot_at) >= DRAIN:
                break
            if not seen_finger and absent >= ABSENT_N:
                log("no finger after %d empty frames -- falling through to "
                    "the password" % absent)
                break
    except KeyboardInterrupt:
        pass
    finally:
        tail.close()
        # Ask the host to leave by closing its stdin (fgets -> EOF), then
        # escalate quickly: PAM is holding the user at the lock screen, so
        # every extra second here is a second he waits.
        try:
            proc.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            proc.wait(timeout=0.6)
        except Exception:
            try:
                proc.terminate()
                proc.wait(timeout=0.4)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=1)
                except Exception:
                    pass

    if matched:
        write_file(STATE, "%d %d\n" % (int(time.time()), matched))
        log("RESULT match user=%s matched=%d presses=%d elapsed=%.1fs"
            % (user, matched, presses, time.time() - t0))
        return 0
    log("RESULT no-match user=%s presses=%d finger_seen=%s elapsed=%.1fs"
        % (user, presses, seen_finger, time.time() - t0))
    return 1


def main():
    user = os.environ.get("PAM_USER", "")
    if not whitelisted(user):
        log("skip: user %r not in %s" % (user, WHITELIST))
        return 1

    # One capture at a time: a second PAM attempt while the first is still
    # waiting for a finger would just fight over the sensor.
    lf = open_sink(LOCK, "ab")
    if isinstance(lf, _Sink):
        # Cannot even open the lock: a lock is advisory here, so run anyway
        # rather than failing a legitimate unlock attempt.
        log("warning: cannot use lock %s -- continuing unlocked" % LOCK)
    else:
        try:
            fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            log("skip: another capture is already in flight")
            lf.close()
            return 1

    try:
        return run(user)
    finally:
        try:
            lf.close()
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
