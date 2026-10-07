#!/usr/bin/env python3
"""goodix-fprintd -- a net.reactivated.Fprint (fprintd) compatible D-Bus service
for the K50 (mt6895 / Goodix gf-spi) fingerprint reader.

Why this exists: there is no libfprint driver for this sensor, and the vendor
ta_host binary cannot report finger presence (GPIO136 floats; the driver's
FINGER_STATE ioctl stays 0 even while a finger rests on the sensor -- both were
measured).  So we drive ta_host in its *interactive* (TA_PRESS) mode, on a timed
rhythm, which is the only mode that has ever produced a successful capture on
this hardware.  Everything fprintd's clients expect is emulated on top:

  Manager  net.reactivated.Fprint.Manager @ /net/reactivated/Fprint/Manager
  Device   net.reactivated.Fprint.Device  @ /net/reactivated/Fprint/Device/0
           Claim/Release/ListEnrolledFingers/DeleteEnrolledFinger(s[2])
           EnrollStart/EnrollStop/VerifyStart/VerifyStop
           properties name/scan-type/num-enroll-stages/finger-present/finger-needed
           signals   EnrollStatus/VerifyStatus/VerifyFingerSelected/VerifyFingerMatched

Enrolment from Plasma's System Settings -> Users talks exactly this protocol.

Run as root:  goodix-fprintd            (system bus, foreground)
"""
import glob
import json
import os
import pwd
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib

SERVICE = "net.reactivated.Fprint"
MGR_PATH = "/net/reactivated/Fprint/Manager"
DEV_PATH = "/net/reactivated/Fprint/Device/0"
MGR_IFACE = SERVICE + ".Manager"
DEV_IFACE = SERVICE + ".Device"
ERR = SERVICE + ".Error."
DBUS_PROP_IFACE = "org.freedesktop.DBus.Properties"

STORE = "/var/lib/goodixta"
NAMES = os.path.join(STORE, "fprint_names.json")
HOST_DIR = "/opt/goodixta"
HOST = os.path.join(HOST_DIR, "bin/ta_host")
TA = os.path.join(HOST_DIR, "ta/goodixfp.ta")
DELETED_DIR = "/root/fprintd-deleted"
LOG = "/var/log/goodix-fprintd.log"

NUM_STAGES = 10                 # == the successful enrolment (min_templates=10)

# Pacing: the sensor only yields a usable frame when the finger is placed and
# then *triggered*; a continuously held finger is rejected as a duplicate frame.
SETTLE = 3.0                    # wait after "put finger ... press Enter"
SETTLE_FIRST = 4.5              # first press: give the user time to place it
CYCLE = 1.5                     # wait after "lift finger FULLY ... press Enter"
PROBE = 0.6                     # probe rhythm once a real finger has been seen
ABSENT_N = 3                    # stop early when N frames in a row are empty

FINGERS = [
    "left-thumb", "left-index-finger", "left-middle-finger",
    "left-ring-finger", "left-little-finger",
    "right-thumb", "right-index-finger", "right-middle-finger",
    "right-ring-finger", "right-little-finger",
]

_logf = None
_loglock = threading.Lock()


def log(msg):
    global _logf
    line = "%s %s\n" % (time.strftime("%H:%M:%S"), msg)
    with _loglock:
        sys.stderr.write(line)
        sys.stderr.flush()
        if _logf:
            try:
                _logf.write(line)
                _logf.flush()
            except Exception:
                pass


def store_files():
    """Every file that belongs to the enrolled-template store."""
    out = []
    for pat in ("finger_*.so*", "asp_template_*"):
        out += sorted(glob.glob(os.path.join(STORE, pat)))
    return out


def real_slots():
    """Number of finger slots the trustlet will count (its per-user limit is 5)."""
    n = 0
    for f in glob.glob(os.path.join(STORE, "finger_*.so")):
        if f.endswith("_bak.so"):
            continue
        n += 1
    return n


def stash_store(reason):
    """Move the entire template store aside (never deleted).  Returns the dir."""
    files = store_files()
    if not files:
        return None
    dest = os.path.join("/root/fprintd-replaced",
                        time.strftime("%Y%m%d-%H%M%S") + "-" + reason)
    try:
        os.makedirs(dest, exist_ok=True)
        for f in files:
            shutil.move(f, os.path.join(dest, os.path.basename(f)))
    except Exception as exc:
        log("[store] stash failed: %s" % exc)
        return None
    log("[store] stashed %d file(s) -> %s (slots now %d)"
        % (len(files), dest, real_slots()))
    return dest


def restore_store(dest):
    """Put a stashed store back (used when an enrolment did not succeed)."""
    if not dest:
        return
    n = 0
    for f in sorted(glob.glob(os.path.join(dest, "*"))):
        try:
            shutil.move(f, os.path.join(STORE, os.path.basename(f)))
            n += 1
        except Exception as exc:
            log("[store] cannot restore %s: %s" % (f, exc))
    try:
        subprocess.run(["chown", "-R", "k50:k50", STORE], timeout=30)
    except Exception:
        pass
    log("[store] restored %d file(s) from %s (slots now %d)" % (n, dest, real_slots()))


def load_names():
    try:
        with open(NAMES) as fh:
            data = json.load(fh)
        return [str(x.get("finger")) for x in data.get("prints", [])]
    except FileNotFoundError:
        # A store that predates this service: one physical print, replicated
        # into the remaining slots by goodix-fp-syncslots.
        if os.path.exists(os.path.join(STORE, "finger_0_0.so")):
            return ["right-index-finger"]
        return []
    except Exception as exc:
        log("[names] unreadable (%s) -- treating store as unmanaged" % exc)
        return ["right-index-finger"] if real_slots() else []


def save_names(fingers):
    tmp = NAMES + ".tmp"
    try:
        with open(tmp, "w") as fh:
            json.dump({"prints": [{"finger": f, "added": time.time()} for f in fingers]},
                      fh, indent=1)
        os.replace(tmp, NAMES)
    except Exception as exc:
        log("[names] cannot write %s: %s" % (NAMES, exc))


def whitelist_users():
    try:
        with open("/etc/goodix-fp-pam.users") as fh:
            return [l.strip() for l in fh if l.strip()]
    except Exception:
        return []


def sender_username(sender):
    """Resolve a D-Bus sender unique name to its local user name."""
    try:
        bus = dbus.SystemBus()
        uid = bus.get_unix_user(sender)
        return pwd.getpwuid(uid).pw_name
    except Exception as exc:
        log("[dbus] cannot resolve sender %s: %s" % (sender, exc))
        return None


DAEMON_UNIT = "goodix-fp-capture.service"
DAEMON_BIN = "/opt/goodixta/bin/ta_host.v87"


def daemon_running():
    """True when the resident capture daemon holds the sensor right now."""
    for name in ("ta_host.v87", "ta_host"):
        try:
            if subprocess.run(["pgrep", "-x", name], capture_output=True,
                              text=True).returncode == 0:
                return True
        except Exception:
            pass
    return False


def daemon_stop():
    """Free the SPI device before spawning our own ta_host.

    Only one trustlet host may own the sensor: the resident capture daemon
    (goodix-fp-capture.service) polls it continuously, so the D-Bus provider has
    to park it for the duration of an enroll/verify session.  Returns True when
    we actually stopped something and therefore owe the daemon a restart.
    """
    if not daemon_running():
        return False
    log("[ta] stopping the resident capture daemon to free the sensor")
    try:
        subprocess.run(["systemctl", "stop", DAEMON_UNIT], capture_output=True,
                       text=True, timeout=15)
    except Exception:
        pass
    if daemon_running():
        try:
            subprocess.run(["pkill", "-x", "ta_host.v87"], capture_output=True)
            subprocess.run(["pkill", "-x", "ta_host"], capture_output=True)
        except Exception:
            pass
    for _ in range(30):
        if not daemon_running():
            return True
        time.sleep(0.1)
    log("[ta] warning: the capture daemon is still alive after 3s")
    return True


def daemon_start():
    """Give the sensor back to the resident capture daemon."""
    log("[ta] restarting the resident capture daemon")
    try:
        if subprocess.run(["systemctl", "start", DAEMON_UNIT],
                          capture_output=True, text=True).returncode == 0:
            return
    except Exception:
        pass
    env = dict(os.environ)
    env.setdefault("GOODIXTA_QUIET", "1")
    env.setdefault("TA_STATE_FILE", "/run/goodix-fp.state")
    try:
        out = open("/run/goodix-fp-fpd.log", "ab")
    except Exception:
        out = subprocess.DEVNULL
    subprocess.Popen([DAEMON_BIN, TA, "d"], cwd=HOST_DIR, stdout=out,
                     stderr=subprocess.STDOUT, env=env, start_new_session=True)


class TaRunner:
    """Drives one ta_host process in interactive (TA_PRESS) mode."""

    def __init__(self, mode, iterations, on_line, logpath=None):
        self.mode = mode
        self.iterations = iterations
        self.on_line = on_line
        self.logpath = logpath
        self.proc = None
        self.queue = queue.Queue()
        self.stop_flag = False
        self.seen_finger = False
        self.progress = 0
        self.enter_at = None
        self.presses = 0
        self.restore_daemon = False
        self.status = None          # 'match' / 'nomatch' / 'completed' / 'failed'
        self._log = None
        if logpath:
            self._log = open(logpath, "a", buffering=1)

    # -- plumbing ---------------------------------------------------------
    def _reader(self):
        try:
            for raw in self.proc.stdout:
                line = raw.rstrip("\n")
                if self._log:
                    self._log.write(line + "\n")
                self.queue.put(line)
        except Exception:
            pass
        self.queue.put(None)

    def start(self):
        # Only one trustlet host may own the sensor: park the resident capture
        # daemon (if any) for the duration of this session.
        self.restore_daemon = daemon_stop()
        env = dict(os.environ)
        env.update({
            "TA_PRESS": "1",
            "GOODIXTA_QUIET": "1",
            "TA_LOG_LEVEL": "3",
            "TA_MIN_TPL": str(NUM_STAGES),
        })
        self.proc = subprocess.Popen(
            [HOST, TA, self.mode, str(self.iterations)],
            cwd=HOST_DIR, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env=env, text=True, bufsize=1)
        threading.Thread(target=self._reader, daemon=True).start()

    def send_enter(self):
        try:
            self.proc.stdin.write("\n")
            self.proc.stdin.flush()
        except Exception as exc:
            log("[ta] stdin write failed: %s" % exc)

    def schedule(self, delay):
        self.enter_at = time.monotonic() + delay

    def pump(self):
        """Consume host output; returns False when the host is gone."""
        try:
            line = self.queue.get(timeout=0.15)
        except queue.Empty:
            line = ""
        if line is None:
            return False
        if line:
            try:
                self.on_line(line)
            except Exception as exc:
                log("[ta] on_line error: %s" % exc)
        if self.enter_at is not None and time.monotonic() >= self.enter_at:
            self.enter_at = None
            self.send_enter()
        return self.proc.poll() is None

    def stop(self, why="stop"):
        self.stop_flag = True
        if self.proc and self.proc.poll() is None:
            log("[ta] killing %s (%s)" % (self.mode, why))
            try:
                self.proc.terminate()
            except Exception:
                pass
            try:
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        if self._log:
            try:
                self._log.close()
            except Exception:
                pass
        # hand the sensor back to the resident capture daemon
        if self.restore_daemon:
            self.restore_daemon = False
            daemon_start()


class FprintDevice(dbus.service.Object):
    def __init__(self, bus_name):
        dbus.service.Object.__init__(self, bus_name, DEV_PATH)
        self.lock = threading.RLock()
        self.claimed_by = None       # username
        self.claimed_sender = None
        self.runner = None
        self.action = None           # 'enroll' / 'verify' / None
        self.finger = None
        self._present = False
        self._needed = False
        self.sessions = []           # enrolled finger names, cache

    # -- helpers ----------------------------------------------------------
    def emit(self, signal, *args):
        GLib.idle_add(lambda: (self._emit(signal, *args), False)[1])

    def _emit(self, signal, *args):
        try:
            getattr(self, signal)(*args)
        except Exception as exc:
            log("[dbus] emit %s failed: %s" % (signal, exc))

    def _notify(self, **kw):
        """Emit PropertiesChanged for the device properties (dashed names)."""
        types = {"num-enroll-stages": dbus.Int32, "finger-present": dbus.Boolean,
                 "finger-needed": dbus.Boolean, "name": dbus.String,
                 "scan-type": dbus.String}
        changed = {}
        for name, val in kw.items():
            changed[name] = types.get(name, lambda v: v)(val)
        if changed:
            try:
                self.PropertiesChanged(DEV_IFACE,
                                       dbus.Dictionary(changed, signature="sv"), [])
            except Exception as exc:
                log("[dbus] PropertiesChanged failed: %s" % exc)

    # -- properties -------------------------------------------------------
    # dbus-python has no property decorator (dbus.service.property does not
    # exist in 1.3.2), so the org.freedesktop.DBus.Properties interface is
    # implemented by hand.
    def _prop_values(self):
        return {
            "name": dbus.String("Goodix Fingerprint Sensor (K50)"),
            "scan-type": dbus.String("press"),
            "num-enroll-stages": dbus.Int32(NUM_STAGES if self.claimed_by else -1),
            "finger-present": dbus.Boolean(self._present),
            "finger-needed": dbus.Boolean(self._needed),
        }

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="ss", out_signature="v")
    def Get(self, interface, prop):
        vals = self._prop_values()
        if interface not in (DEV_IFACE, "") or prop not in vals:
            raise dbus.exceptions.DBusException(
                "Unknown property %s.%s" % (interface, prop),
                name="org.freedesktop.DBus.Error.UnknownProperty")
        return vals[prop]

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        return dbus.Dictionary(self._prop_values(), signature="sv")

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="ssv")
    def Set(self, interface, prop, value):
        raise dbus.exceptions.DBusException(
            "Property %s is read-only" % prop,
            name="org.freedesktop.DBus.Error.PropertyReadOnly")

    @dbus.service.signal(DBUS_PROP_IFACE, signature="sa{sv}as")
    def PropertiesChanged(self, interface, changed, invalidated):
        pass

    def set_props(self, **kw):
        """Update cached property values and tell clients about the changes."""
        for key, val in kw.items():
            setattr(self, "_" + key, val)
        self._notify(**{k.replace("_", "-"): v for k, v in kw.items()})

    # -- signals ----------------------------------------------------------
    @dbus.service.signal(DEV_IFACE, signature="sb")
    def EnrollStatus(self, result, done):
        pass

    @dbus.service.signal(DEV_IFACE, signature="sb")
    def VerifyStatus(self, result, done):
        pass

    @dbus.service.signal(DEV_IFACE, signature="s")
    def VerifyFingerSelected(self, finger_name):
        pass

    @dbus.service.signal(DEV_IFACE, signature="s")
    def VerifyFingerMatched(self, finger_name):
        pass

    @dbus.service.signal(DEV_IFACE, signature="s")
    def EnrollComplete(self, finger_name):
        pass

    # -- claim / release --------------------------------------------------
    @dbus.service.method(DEV_IFACE, in_signature="s", sender_keyword="sender")
    def Claim(self, username, sender=None):
        user = str(username)
        if not user:
            user = sender_username(sender) or ""
        if not user:
            raise dbus.exceptions.DBusException(
                "cannot determine the calling user", name=ERR + "Internal")
        with self.lock:
            if self.claimed_by and self.claimed_by != user:
                raise dbus.exceptions.DBusException(
                    "Device already claimed by %s" % self.claimed_by,
                    name=ERR + "AlreadyInUse")
            if self.action:
                raise dbus.exceptions.DBusException(
                    "Device already in use", name=ERR + "AlreadyInUse")
            self.claimed_by = user
            self.claimed_sender = sender
        log("[dbus] Claim(%s) by sender=%s" % (user, sender))
        self._notify(**{"num-enroll-stages": NUM_STAGES})

    @dbus.service.method(DEV_IFACE, in_signature="", sender_keyword="sender")
    def Release(self, sender=None):
        with self.lock:
            if not self.claimed_by:
                raise dbus.exceptions.DBusException(
                    "Device not claimed", name=ERR + "ClaimDevice")
            self._stop_action("release")
            self.claimed_by = None
            self.claimed_sender = None
        log("[dbus] Release()")
        self._notify(**{"num-enroll-stages": -1})

    def _require_claim(self, sender):
        with self.lock:
            if not self.claimed_by:
                raise dbus.exceptions.DBusException(
                    "Device not claimed", name=ERR + "ClaimDevice")

    # -- listing / deleting ----------------------------------------------
    def _resolve_user(self, username, sender):
        user = str(username)
        if user:
            return user
        with self.lock:
            if self.claimed_by:
                return self.claimed_by
        return sender_username(sender) or ""

    @dbus.service.method(DEV_IFACE, in_signature="s", out_signature="as",
                         sender_keyword="sender")
    def ListEnrolledFingers(self, username, sender=None):
        user = self._resolve_user(username, sender)
        fingers = load_names() if real_slots() else []
        log("[dbus] ListEnrolledFingers(%s) -> %s" % (username, fingers))
        if not fingers:
            raise dbus.exceptions.DBusException(
                "No prints enrolled for %s" % user, name=ERR + "NoEnrolledPrints")
        return dbus.Array([dbus.String(f) for f in fingers], signature="s")

    def _wipe_store(self, what):
        if not os.path.isdir(STORE):
            return
        stamp = time.strftime("%Y%m%d-%H%M%S")
        dest = os.path.join(DELETED_DIR, "%s-%s" % (stamp, what))
        os.makedirs(dest, exist_ok=True)
        moved = 0
        for f in store_files() + ([NAMES] if os.path.exists(NAMES) else []):
            try:
                shutil.move(f, os.path.join(dest, os.path.basename(f)))
                moved += 1
            except Exception as exc:
                log("[store] cannot move %s: %s" % (f, exc))
        left = real_slots()
        log("[store] deleted %d file(s) -> %s (slots left: %d)" % (moved, dest, left))
        if left:
            raise dbus.exceptions.DBusException(
                "fingerprints not deleted from storage", name=ERR + "PrintsNotDeleted")

    @dbus.service.method(DEV_IFACE, in_signature="s", sender_keyword="sender")
    def DeleteEnrolledFingers(self, username, sender=None):
        self._resolve_user(username, sender)
        self._stop_action("delete")
        self._wipe_store("DeleteEnrolledFingers")

    @dbus.service.method(DEV_IFACE, in_signature="", sender_keyword="sender")
    def DeleteEnrolledFingers2(self, sender=None):
        self._require_claim(sender)
        self._stop_action("delete")
        self._wipe_store("DeleteEnrolledFingers2")

    @dbus.service.method(DEV_IFACE, in_signature="s", sender_keyword="sender")
    def DeleteEnrolledFinger(self, finger_name, sender=None):
        self._require_claim(sender)
        name = str(finger_name)
        if name not in FINGERS:
            raise dbus.exceptions.DBusException(
                "Invalid finger name %s" % name, name=ERR + "InvalidFingername")
        fingers = load_names()
        if name not in fingers:
            raise dbus.exceptions.DBusException(
                "No print enrolled for %s" % name, name=ERR + "NoEnrolledPrints")
        # The trustlet stores prints anonymously (finger_<group>_<id>.so), so a
        # named deletion can only drop the whole enrolled set.
        self._stop_action("delete")
        self._wipe_store("DeleteEnrolledFinger-" + name)

    # -- actions ----------------------------------------------------------
    def _stop_action(self, why):
        r = self.runner
        if r:
            r.stop(why)
        self.runner = None
        self.action = None
        self.set_props(finger_present=False, finger_needed=False)

    def _finish(self):
        cmd = "/usr/local/bin/goodix-fp-syncslots"
        if os.path.exists(cmd):
            try:
                out = subprocess.run([cmd], capture_output=True, text=True,
                                     timeout=60)
                log("[syncslots] rc=%d %s" % (out.returncode,
                                              (out.stdout or out.stderr).strip()[:200]))
            except Exception as exc:
                log("[syncslots] failed: %s" % exc)
        self.set_props(finger_present=False, finger_needed=False)

    @dbus.service.method(DEV_IFACE, in_signature="s", sender_keyword="sender")
    def EnrollStart(self, finger_name, sender=None):
        self._require_claim(sender)
        name = str(finger_name)
        if name not in FINGERS:
            raise dbus.exceptions.DBusException(
                "Invalid finger name %s" % name, name=ERR + "InvalidFingername")
        with self.lock:
            if self.action:
                raise dbus.exceptions.DBusException(
                    "Device already in use", name=ERR + "AlreadyInUse")
            if name in load_names():
                raise dbus.exceptions.DBusException(
                    "%s is already enrolled" % name,
                    name=ERR + "FingerAlreadyEnrolled")
            self.action = "enroll"
            self.finger = name
        log("[dbus] EnrollStart(%s) slots=%d" % (name, real_slots()))
        threading.Thread(target=self._enroll_worker, daemon=True).start()

    @dbus.service.method(DEV_IFACE, in_signature="", sender_keyword="sender")
    def EnrollStop(self, sender=None):
        self._require_claim(sender)
        log("[dbus] EnrollStop()")
        self._stop_action("EnrollStop")

    @dbus.service.method(DEV_IFACE, in_signature="s", sender_keyword="sender")
    def VerifyStart(self, finger_name, sender=None):
        self._require_claim(sender)
        name = str(finger_name)
        if name != "any" and name not in FINGERS:
            raise dbus.exceptions.DBusException(
                "Invalid finger name %s" % name, name=ERR + "InvalidFingername")
        if not real_slots():
            raise dbus.exceptions.DBusException(
                "No enrolled prints", name=ERR + "NoEnrolledPrints")
        with self.lock:
            if self.action:
                raise dbus.exceptions.DBusException(
                    "Device already in use", name=ERR + "AlreadyInUse")
            self.action = "verify"
            self.finger = name
        log("[dbus] VerifyStart(%s)" % name)
        self.emit("VerifyFingerSelected", dbus.String(name))
        threading.Thread(target=self._verify_worker, daemon=True).start()

    @dbus.service.method(DEV_IFACE, in_signature="", sender_keyword="sender")
    def VerifyStop(self, sender=None):
        self._require_claim(sender)
        log("[dbus] VerifyStop()")
        self._stop_action("VerifyStop")

    # -- worker: enrolment ------------------------------------------------
    def _enroll_worker(self):
        # The trustlet refuses a new enrolment while 5 slots are populated, and
        # goodix-fp-syncslots fills 4 of them with replicas of the single enrolled
        # print -- so "add fingerprint" would always hit GF_ERROR_REACH_FINGERS_UPLIMIT.
        # This device therefore keeps exactly one enrolled print: stash the old
        # store (backed up, restored if the new enrolment fails) and start clean.
        old_names = load_names()
        backup = stash_store("enroll-" + self.finger)
        self.set_props(finger_present=True, finger_needed=True)
        self.emit("EnrollStatus", dbus.String("enroll-retry-scan"), dbus.Boolean(False))
        state = {"press": 0, "first": True, "last_tpl": 0, "retry_sent": False}

        def on_line(line):
            if "REACH_FINGERS_UPLIMIT" in line or "errno=1005" in line:
                state["full"] = True
                log("[enroll] trustlet says the finger store is full")
            if "press finger (" in line:
                m = re.search(r"press finger \((\d+)/", line)
                if m:
                    state["press"] = int(m.group(1))
            elif "TA_PRESS: put finger on sensor" in line:
                r.schedule(SETTLE_FIRST if state["first"] else SETTLE)
                state["first"] = False
                self.set_props(finger_needed=True)
            elif "lift finger FULLY, then press Enter" in line:
                r.schedule(CYCLE)
            else:
                m = re.search(r"g_fpTemplateNum=(\d+)", line)
                if m:
                    val = int(m.group(1))
                    if val > state["last_tpl"]:
                        state["last_tpl"] = val
                        self.emit("EnrollStatus", dbus.String("enroll-stage-passed"),
                                  dbus.Boolean(False))
                        self.set_props(finger_present=True)
                if "template saved" in line:
                    state["completed"] = True
                if re.search(r"tplcheck prev=(\d+) tpl=(\d+)", line):
                    mm = re.search(r"tplcheck prev=(\d+) tpl=(\d+)", line)
                    if int(mm.group(1)) >= NUM_STAGES - 2 and int(mm.group(2)) == 0:
                        state["completed"] = True

        r = TaRunner("enroll", 40, on_line,
                     logpath="/var/log/goodix-fprintd-enroll.log")
        self.runner = r
        r.start()
        full = False
        try:
            while not r.stop_flag and r.pump():
                if state.get("full"):
                    full = True
                    break
                if state.get("completed"):
                    break
        finally:
            ok = state.get("completed") and not r.stop_flag
            r.stop("enrolment finished" if ok else "enrolment ended")
            self.runner = None
            with self.lock:
                self.action = None
            if ok:
                save_names([self.finger])
                self._finish()
                log("[enroll] completed finger=%s" % self.finger)
                self.emit("EnrollStatus", dbus.String("enroll-completed"),
                          dbus.Boolean(True))
                self.emit("EnrollComplete", dbus.String(self.finger))
            else:
                # Never lose the previous print because of a failed attempt.
                if real_slots():
                    stash_store("failed-enroll-" + self.finger)
                restore_store(backup)
                if old_names:
                    save_names(old_names)
                self.set_props(finger_present=False, finger_needed=False)
                if full or real_slots() >= 5:
                    self.emit("EnrollStatus", dbus.String("enroll-data-full"),
                              dbus.Boolean(True))
                elif r.stop_flag:
                    pass
                else:
                    self.emit("EnrollStatus", dbus.String("enroll-failed"),
                              dbus.Boolean(True))

    # -- worker: verification ---------------------------------------------
    def _verify_worker(self):
        self.set_props(finger_present=True, finger_needed=True)
        state = {"first": True, "absent": 0, "last_tpl": 0}

        def on_line(line):
            if "TA_PRESS: put finger on sensor" in line or \
               "put the ENROLLED finger on the sensor" in line:
                r.schedule(SETTLE_FIRST if state["first"] else SETTLE)
                state["first"] = False
            elif "lift finger FULLY" in line or "lift the finger FULLY" in line:
                r.schedule(CYCLE)
            elif "MATCH! finger recognised" in line:
                state["match"] = True
            else:
                m = re.search(r"final status=(\d+)", line)
                if m:
                    st = m.group(1)
                    if st == "1094":
                        state["absent"] += 1
                        self.emit("VerifyStatus",
                                  dbus.String("verify-retry-scan"), dbus.Boolean(False))
                    else:
                        state["absent"] = 0
                    self.set_props(finger_present=True)
                m = re.search(r"g_fpTemplateNum=(\d+)", line)
                if m and int(m.group(1)) > state["last_tpl"]:
                    state["last_tpl"] = int(m.group(1))

        r = TaRunner("auth", 16, on_line,
                     logpath="/var/log/goodix-fprintd-verify.log")
        self.runner = r
        r.start()
        try:
            while not r.stop_flag and r.pump():
                if state.get("match"):
                    break
                if state["absent"] >= ABSENT_N and "match" not in state:
                    break
        finally:
            matched = bool(state.get("match")) and not r.stop_flag
            r.stop("verify finished")
            self.runner = None
            with self.lock:
                self.action = None
            self.set_props(finger_present=False, finger_needed=False)
            if matched:
                self.emit("VerifyFingerMatched", dbus.String(self.finger or "any"))
                self.emit("VerifyStatus", dbus.String("verify-match"), dbus.Boolean(True))
            else:
                self.emit("VerifyStatus", dbus.String("verify-no-match"),
                          dbus.Boolean(True))


class FprintManager(dbus.service.Object):
    def __init__(self, bus_name):
        dbus.service.Object.__init__(self, bus_name, MGR_PATH)

    @dbus.service.method(MGR_IFACE, in_signature="", out_signature="ao")
    def GetDevices(self):
        return dbus.Array([dbus.ObjectPath(DEV_PATH)], signature="o")

    @dbus.service.method(MGR_IFACE, in_signature="", out_signature="o")
    def GetDefaultDevice(self):
        return dbus.ObjectPath(DEV_PATH)

    # fprintd's manager also carries a Devices property; some clients read it
    # instead of calling GetDevices(), so serve both.
    def _prop_values(self):
        return {
            "Devices": dbus.Array([dbus.ObjectPath(DEV_PATH)], signature="o"),
            "Version": dbus.String("1.94.2 (goodix-fprintd emulation)"),
        }

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="ss", out_signature="v")
    def Get(self, interface, prop):
        vals = self._prop_values()
        if prop not in vals:
            raise dbus.exceptions.DBusException(
                "Unknown property %s.%s" % (interface, prop),
                name="org.freedesktop.DBus.Error.UnknownProperty")
        return vals[prop]

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        return dbus.Dictionary(self._prop_values(), signature="sv")

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="ssv")
    def Set(self, interface, prop, value):
        raise dbus.exceptions.DBusException(
            "Property %s is read-only" % prop,
            name="org.freedesktop.DBus.Error.PropertyReadOnly")

    @dbus.service.signal(DBUS_PROP_IFACE, signature="sa{sv}as")
    def PropertiesChanged(self, interface, changed, invalidated):
        pass


def main():
    global _logf
    os.makedirs(STORE, exist_ok=True)
    os.makedirs(DELETED_DIR, exist_ok=True)
    _logf = open(LOG, "a", buffering=1)
    log("[fprintd] starting (pid %d)" % os.getpid())

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    name = dbus.service.BusName(SERVICE, bus)
    mgr = FprintManager(name)
    dev = FprintDevice(name)
    log("[fprintd] claimed %s, device at %s (%d slots enrolled)"
        % (SERVICE, DEV_PATH, real_slots()))

    loop = GLib.MainLoop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, sig,
                             lambda: (loop.quit(), False)[1])
    try:
        loop.run()
    finally:
        if dev.runner:
            dev.runner.stop("shutdown")
        log("[fprintd] stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
