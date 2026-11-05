#!/usr/bin/env python3
"""edge/flash-device.sh mpy_cp, offline (5 Nov 2026): a copy to the board is tried three
times, and on the last failure mpremote's own error reaches the run's log, since the
wizard discards the run's stderr. The functions are taken from the script itself and run
against a fake mpremote that fails a set number of times."""
import os
import re
import stat
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "edge", "flash-device.sh")


def read(path):
    with open(path) as f:
        return f.read()


def function(src, name):
    """The text of one top-level function: a one-liner, or up to the first line that is '}'."""
    m = re.search(r"(?m)^%s\(\) *\{.*\}$" % re.escape(name), src)
    if m:
        return m.group(0)
    m = re.search(r"(?ms)^%s\(\) *\{\n.*?^\}$" % re.escape(name), src)
    if not m:
        raise AssertionError("no function %s in flash-device.sh" % name)
    return m.group(0)


FAKE = r"""#!/bin/bash
# fake mpremote: connect PORT fs cp SRC DST; fails while the counter is below FAIL_TIMES
n=$(cat "$COUNT" 2>/dev/null || echo 0); echo $((n + 1)) > "$COUNT"
if [ "$n" -lt "$FAIL_TIMES" ]; then
  echo "Traceback (most recent call last):" >&2
  echo "" >&2
  echo "mpremote.transport.TransportError: could not enter raw repl" >&2
  exit 1
fi
echo "cp $5 $6"
"""


class MpyCpTest(unittest.TestCase):
    def run_cp(self, fail_times):
        src = read(SCRIPT)
        tmp = tempfile.mkdtemp()
        self.addCleanup(subprocess.run, ["rm", "-rf", tmp])
        fake = os.path.join(tmp, "mpremote")
        with open(fake, "w") as f:
            f.write(FAKE)
        os.chmod(fake, stat.S_IRWXU)
        log = os.path.join(tmp, "uilog")
        body = "\n".join(function(src, n) for n in ("info", "warn", "mpy", "mpy_cp"))
        script = ('set -uo pipefail\nui_append() { printf "%s\\n" "$*" >> "$UILOG"; }\nsleep() { :; }\n'
                  + body + '\nmpy_cp /x/boot.py :boot.py; echo "rc=$?"')
        env = dict(os.environ, MPREMOTE=fake, PORT="/dev/null", SUDO="", COUNT=os.path.join(tmp, "n"),
                   FAIL_TIMES=str(fail_times), UILOG=log, YEL="", RED="", N="")
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
        ui = read(log) if os.path.exists(log) else ""
        tries = int(read(os.path.join(tmp, "n")))
        return r.stdout, ui, tries

    def test_first_try(self):
        out, ui, tries = self.run_cp(0)
        self.assertIn("rc=0", out)
        self.assertEqual((tries, ui), (1, ""))

    def test_a_retry_succeeds_and_says_so(self):
        out, ui, tries = self.run_cp(2)
        self.assertIn("rc=0", out)
        self.assertEqual(tries, 3)
        self.assertIn("copied boot.py on attempt 3", ui)

    def test_last_failure_shows_mpremote_error(self):
        out, ui, tries = self.run_cp(3)
        self.assertIn("rc=1", out)
        self.assertEqual(tries, 3)
        self.assertIn("mpremote: Traceback (most recent call last): "
                      "mpremote.transport.TransportError: could not enter raw repl", ui)

    def test_every_copy_uses_it(self):
        src = read(SCRIPT)
        self.assertEqual(re.findall(r"mpy fs cp", src), ["mpy fs cp"])   # only inside mpy_cp
        self.assertIn('mpy fs cp "$src" "$dst"', function(src, "mpy_cp"))
        self.assertEqual(src.count("mpy_cp \"$f\""), 4)

    def test_boot_and_main_go_last(self):
        """boot.py runs at every mpremote connect (soft reset) and joins WiFi once its modules
        are there; copied first, every later copy cut a WiFi handshake off (5 Nov 2026)."""
        src = read(SCRIPT)
        skip = src.index('boot.py|main.py) continue')
        last = src.index('for f in "$APP_DIR"/main.py "$APP_DIR"/boot.py; do')   # boot.py the very last
        pkgs = src.index('for pkg in umqtt sensor_pack_2; do')
        verify = src.index('step "Verifying"')
        self.assertLess(skip, pkgs)
        self.assertLess(pkgs, last)
        self.assertLess(last, verify)


BOARD = os.path.join(ROOT, "edge", "src", "bootstrap", "wifi_try.py")

FAKE_NETWORK = r"""
import os
STAT_IDLE, STAT_CONNECTING, STAT_GOT_IP = 1000, 1001, 1010
STAT_WRONG_PASSWORD, STAT_NO_AP_FOUND, STAT_HANDSHAKE_TIMEOUT, STAT_ASSOC_FAIL = 202, 201, 204, 203
STA_IF = 0
PLAN = os.environ["PLAN"].split(",")   # status per poll: an int, or 'ip:<addr>'
class WLAN:
    def __init__(self, i): self.n = 0; self.on = False; self.joined = None
    def active(self, v=None):
        if v is not None: self.on = v
        return self.on
    def disconnect(self): pass
    def config(self, **k): print("CONFIG", k)
    def connect(self, ssid, psk): self.joined = (ssid, psk); print("JOIN", repr(ssid), len(psk))
    def _step(self):
        p = PLAN[min(self.n, len(PLAN) - 1)]; self.n += 1; return p
    def isconnected(self):
        p = PLAN[min(self.n, len(PLAN) - 1)]
        if p.startswith("ip:"): self.n += 1; return True
        return False
    def ifconfig(self): return (PLAN[min(self.n - 1, len(PLAN) - 1)][3:], "", "", "")
    def status(self): return int(self._step())
"""

FAKE_TIME = r"""
_now = [0]
def ticks_ms(): return _now[0]
def ticks_diff(a, b): return a - b
def sleep_ms(ms): _now[0] += ms
"""


class WifiTryBoardTest(unittest.TestCase):
    """edge/src/bootstrap/wifi_try.py under CPython, with fake network and time modules."""

    def run_board(self, plan, ssid="Vieira", psk="p'w\\\"x"):
        tmp = tempfile.mkdtemp()
        self.addCleanup(subprocess.run, ["rm", "-rf", tmp])
        with open(os.path.join(tmp, "network.py"), "w") as f:
            f.write(FAKE_NETWORK)
        # CPython's time is built in, so MicroPython's ticks_ms/sleep_ms come in through sys.modules
        shim = ("import sys, types\n_t = types.ModuleType('time')\nexec(%r, _t.__dict__)\n"
                "sys.modules['time'] = _t\n" % FAKE_TIME)
        script = os.path.join(tmp, "run.py")
        with open(script, "w") as f:
            f.write(shim + "SSID = %r\nPSK = %r\n" % (ssid, psk) + read(BOARD))
        r = subprocess.run(["python3", "-S", script], capture_output=True, text=True, cwd=tmp,
                           env={"PLAN": plan, "PYTHONPATH": tmp, "PATH": os.environ["PATH"]})
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_outcomes(self):
        for plan, want in (("1001,1001,ip:192.168.1.9", "WIFI\tGOT_IP\t192.168.1.9"),
                           ("1001,202", "WIFI\tREFUSED\t-"),
                           ("1001,15", "WIFI\tREFUSED\t-"),      # a wrong WPA2 passphrase, raw IDF reason
                           ("201", "WIFI\tNO_AP_FOUND\t-"),
                           ("1001,211", "WIFI\tNO_AP_FOUND\t-"),
                           ("1001,7", "WIFI\tREASON_7\t-"),
                           # a failure that does not last 3 s is the driver still retrying
                           ("202,202,202,1001,1001,ip:10.0.0.7", "WIFI\tGOT_IP\t10.0.0.7"),
                           ("1001", "WIFI\tTIMEOUT\t-"),
                           ("ip:0.0.0.0,1001,ip:10.0.0.5", "WIFI\tGOT_IP\t10.0.0.5")):
            out = self.run_board(plan)
            self.assertEqual(out.strip().splitlines()[-1], want, plan)
            self.assertIn("CONFIG {'reconnects': 2}", out)

    def test_the_literals_reach_the_board_intact(self):
        out = self.run_board("ip:1.2.3.4", ssid="Café 2.4", psk="a'b\"c\\d$e")
        self.assertIn("JOIN 'Café 2.4' 9", out)


FAKE_RUN = r"""#!/bin/bash
# fake mpremote: connect PORT run FILE -> the board's answer, from the file's own literals
echo "$*" >> "$ARGV_LOG"
[ "$3" = run ] || exit 2
n=$(wc -l < "$ARGV_LOG")
if [ "$n" -le "${SILENT_RUNS:-0}" ]; then echo "could not enter raw repl" >&2; exit 1; fi
python3 - "$4" <<'PY'
import sys
src = open(sys.argv[1]).read()
ns = {}
exec(src.split("import network")[0], ns)
print("noise")
print("WIFI\t%s\t%s" % (("GOT_IP", "192.168.1.9") if ns["PSK"] == "right one" else ("REFUSED", "-")))
PY
"""


class WifiTryShellTest(unittest.TestCase):
    def run_shell(self, psk, silent=0):
        src = read(SCRIPT)
        tmp = tempfile.mkdtemp()
        self.addCleanup(subprocess.run, ["rm", "-rf", tmp])
        fake = os.path.join(tmp, "mpremote")
        with open(fake, "w") as f:
            f.write(FAKE_RUN)
        os.chmod(fake, stat.S_IRWXU)
        body = "\n".join(function(src, n) for n in ("mpy", "wifi_try"))
        script = 'set -euo pipefail\n' + body + '\nwifi_try; echo "res=$WIFI_RES ip=$WIFI_IP"'
        env = dict(os.environ, MPREMOTE=fake, PORT="/dev/null", SUDO="", SSID="Vieira", PSK=psk,
                   SRC_DIR=os.path.dirname(BOARD), ARGV_LOG=os.path.join(tmp, "argv"), TMPDIR=tmp,
                   SILENT_RUNS=str(silent))
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        left = [n for n in os.listdir(tmp) if n.startswith("cea-wifi.")]
        return r.stdout.strip(), read(os.path.join(tmp, "argv")), left

    def test_joined_and_refused(self):
        out, argv, left = self.run_shell("right one")
        self.assertEqual(out, "res=GOT_IP ip=192.168.1.9")
        self.assertNotIn("right one", argv)      # never in argv
        self.assertEqual(left, [])               # the file with the passphrase is gone
        out, _, _ = self.run_shell("wrong")
        self.assertEqual(out, "res=REFUSED ip=-")

    def test_no_answer_is_tried_once_more(self):
        out, argv, left = self.run_shell("right one", silent=1)
        self.assertEqual(out, "res=GOT_IP ip=192.168.1.9")
        self.assertEqual(len(argv.splitlines()), 2)
        out, argv, left = self.run_shell("right one", silent=2)
        self.assertEqual(out, "res= ip=")          # "no answer from the board": the stage asks what next
        self.assertEqual(len(argv.splitlines()), 2)
        self.assertEqual(left, [])

    def test_the_stage_checks_before_writing(self):
        src = read(SCRIPT)
        stage = src[src.index('step "WiFi"'):src.index('step "WebREPL credential"')]
        self.assertIn("wifi_try", stage)
        self.assertIn('GOT_IP) info', stage)
        self.assertIn('[ "$WIFI_RES" = REFUSED ]', stage)     # --yes without a terminal stops there
        cleanup = function(src, "cleanup")
        self.assertIn('rm -rf "$WIFI_TRY_DIR"', cleanup)       # the passphrase file, on a signal
        for opt in ("Type the passphrase again", "Choose another network", "Continue anyway"):
            self.assertIn(opt, stage)
        self.assertLess(src.index('step "WiFi"'), src.index('step "Writing the board\'s files"'))


if __name__ == "__main__":
    unittest.main()
