#!/usr/bin/env python3
"""edge/flash-device.sh's Back and Cancel (5 Nov 2026), offline: the real planning functions
(plan_role, plan_slot, plan_wiring) and their loop, taken from the script and run with the
browser's answers scripted; the prompt helpers; cancel at a question. The server side
(/api/cancel, Back only where offered) is in tests/test_edge_auth.py WizardTests."""
import json
import os
import re
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "edge", "flash-device.sh")
BACK = "\x1bback"


def read(path):
    with open(path) as f:
        return f.read()


def function(src, name):
    m = re.search(r"(?m)^%s\(\) *\{.*\}$" % re.escape(name), src)
    if m:
        return m.group(0)
    m = re.search(r"(?ms)^%s\(\) *\{[^\n]*\n.*?^\}$" % re.escape(name), src)
    if not m:
        raise AssertionError("no function %s in flash-device.sh" % name)
    return m.group(0)


HELPERS = ("step", "info", "warn", "die", "cancel_check", "cancelled", "is_back", "term_back",
           "ui_on", "ui_wait_answer", "ui_prompt_json", "prompt_text", "prompt_confirm",
           "prompt_choice", "prompt_secret", "menu_reset", "menu_add", "menu_head", "menu_count",
           "menu_ask", "ask_param", "driver_chosen", "chosen_count", "plan_role", "plan_slot",
           "plan_wiring", "prompt_wiring", "sense_questions", "sense_wiring_take", "wiring_findings",
           "sense_wiring_check", "sense_wiring_ui", "sense_save_template")

# The browser: answers the prompts in order from ANSWERS (one per line; "BACK" is Back)
# and logs each prompt it saw. A stand-in for the page + wizard_server.
FAKE_BROWSER = r'''
ui_wait_answer() {
  local json="$1" a
  cancel_check
  printf '%s\n' "$json" >> "$PROMPTS"
  [ -s "$ANSWERS" ] || { echo "OUT-OF-ANSWERS at: $json" >&2; exit 99; }
  a="$(sed -n 1p "$ANSWERS")"; sed -i 1d "$ANSWERS"
  [ "$a" = BACK ] && a="$BACK_TOKEN"
  ANSWER="$a"
}
ui_waiting() { :; }
ui_append() { printf '%s\n' "$*" >> "$UILOG"; }
ui_phase() { :; }
'''

SLOTS = ("SLOT\tUNIT01\tZONE01\t1\tCONTROL\tfree\tunit01-c-zone01\t\t\t\t\n"
         "SLOT\tUNIT02\tZONE01\t2\tCONTROL\tfree\tunit02-c-zone01\t\t\t\t\n"
         "SLOT\tUNIT01\tZONE01\t1\tSENSE\tfree\tunit01-s-zone01\t\t\t\t\n")


class PlanningBack(unittest.TestCase):
    def run_plan(self, answers, role="", tool=None, extra=None, after=""):
        src = read(SCRIPT)
        tmp = tempfile.mkdtemp()
        self.addCleanup(subprocess.run, ["rm", "-rf", tmp])
        with open(os.path.join(tmp, "answers"), "w") as f:
            f.write("\n".join(answers) + "\n")
        loop = src[src.index("  ROLE_ASKED=0; SLOT_ASKED=0; PLAN_STAGE=role"):src.index("  BACK_OK=0\n", src.index("PLAN_STAGE=role"))]
        defs = "\n".join(function(src, n) for n in HELPERS if n not in ("ui_wait_answer",))
        consts = "\n".join(l for l in src.splitlines()
                           if l.startswith(("BACK_TOKEN=", "SENSORS_TSV=\"\"; CONTROL_PINS_TSV", "BOARD_TOUCHED=0",
                                          "CANCEL_CLOSED=0")))
        script = "\n".join([
            "set -uo pipefail", "B=''; N=''; DIM=''; RED=''; YEL=''; GRN=''",
            consts, "ASK_ADVANCED=0; UI=1; UNREGISTERED=0; MENU=(); CHOICES=(); ANSWER=''; BACK_OK=0; PARAMS=()",
            "UNIT_WANTED=''; ZONE_WANTED=''; OUT_DIR=\"${T_OUT_DIR:-$UI_DIR/provisioned}\"",
            "WIRING_FILE=\"${T_WIRING_FILE:-}\"; BOARD_TEMPLATE=\"${T_BOARD_TEMPLATE:-}\"",
            "SENSE_WIRING_JSON=''; SENSE_VARIANT=''; SENSE_SAVE_AS=''; EDGE_USER=\"${T_EDGE_USER:-}\"",
            defs, FAKE_BROWSER,
            'set -e',
            loop,
            '  BACK_OK=0',
            after,
            'echo "WIRING variant=$SENSE_VARIANT doc=$SENSE_WIRING_JSON"',
            'echo "SENSORS $(awk -F\'\\t\' \'NF && !s[$1]++{printf "%s,", $1}\' <<<"$SENSORS_TSV")"',
            'echo "RESULT role=$ROLE unit=$UNIT_CODE zone=$ZONE_CODE dns=$SLOT_DNS pins=$(grep -c . <<<"$CONTROL_PINS_TSV" || true)"',
        ])
        env = dict(os.environ, UI_DIR=tmp, ANSWERS=os.path.join(tmp, "answers"),
                   PROMPTS=os.path.join(tmp, "prompts"), UILOG=os.path.join(tmp, "uilog"),
                   TEMPLATE_TOOL=tool or os.path.join(ROOT, "edge", "src", "host", "device_template.py"),
                   SLOTS=SLOTS, ROLE=role, **(extra or {}))
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, cwd=ROOT,
                           timeout=120)
        prompts = [json.loads(l) for l in read(env["PROMPTS"]).splitlines()] if os.path.exists(env["PROMPTS"]) else []
        return r, prompts

    def test_back_from_slot_and_from_wiring(self):
        # role CONTROL; slot: Back -> role again; CONTROL; slot 1; wiring: Back -> slot; slot 2;
        # reference wiring yes.
        r, prompts = self.run_plan(["2", "BACK", "2", "1", "BACK", "2", "y"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("RESULT role=CONTROL unit=UNIT02 zone=ZONE01 dns=unit02-c-zone01 pins=", r.stdout)
        self.assertNotIn("pins=0", r.stdout)
        labels = [(p["label"].split(" [")[0], p["back"]) for p in prompts]
        self.assertEqual(labels, [
            ("What is this board for?", False),                       # the first question: no Back
            ("Which unit and zone is this board going into?", True),
            ("What is this board for?", False),
            ("Which unit and zone is this board going into?", True),
            ("Use this reference wiring?", True),
            ("Which unit and zone is this board going into?", True),
            ("Use this reference wiring?", True),
        ])

    def test_no_back_where_nothing_was_asked_before(self):
        """--role given and one free slot: the wiring question is the first, so no Back."""
        r, prompts = self.run_plan([], role="SENSE", tool=SenseWiring.stub(self))
        # SENSE's first question in the browser is how the board is wired (the run then
        # stops: no answers left)
        self.assertEqual(r.returncode, 99, r.stderr)
        self.assertTrue(prompts, r.stderr)
        self.assertEqual(prompts[0]["label"].split(" [")[0], "How is this board wired?")
        self.assertFalse(prompts[0]["back"])


# A stand-in for device_template.py on the SENSE side (contract §4), so these tests
# follow the shell and not the template's driver list: fixed drivers and params, two
# board templates (one invalid), a validator that refuses a document with "bad", and
# a save that refuses the slug "taken". Every call is logged to $CALLS.
STUB_TOOL = r'''
import json, os, sys
a = sys.argv[1:]
with open(os.environ.get("CALLS", os.devnull), "a") as f:
    f.write(json.dumps(a) + "\n")
DOC = {"version": 1, "board": {"variant": "esp32s3", "part": "esp32-s3-devkitc-1"},
       "buses": [{"id": "i2c0", "kind": "i2c", "sda": 8, "scl": 9}],
       "sensors": [{"id": "sht45_1", "driver": "sht4x", "bus": "i2c0", "addr": 68,
                    "tags": [{"q": "temperature", "tag": "air_temperature"}]}]}
cmd = a[0]
if cmd == "drivers":
    print("ROLE\tSENSE\tSENSE\tmulti")
    print("DRIVER\tground_temperature\tDS18B20 substrate probe\t1-Wire\tground_temperature")
    print("DRIVER\tscd30\tSensirion SCD30\tI2C\tco2")
    print("DEVPARAM\tmessage_interval\tint\t30\tPublish interval (seconds)\thint\t0")
elif cmd == "params":
    if a[2] == "ground_temperature":
        print("PARAM\tdata_pin\tpin\t17\t1-Wire data pin\thint\t0")
elif cmd == "board-templates":
    print("sense-hub\tHub board\tesp32s3\tshipped\t1\t-")
    print("broken\tBroken board\tesp32\tsaved\t0\tbuses.i2c0.sda - GPIO8 is a flash pin")
elif cmd == "board-template":
    if a[1] != "sense-hub":
        sys.exit("no board template " + a[1])
    print(json.dumps(DOC))
elif cmd == "wiring-spec":
    init = None
    if "--initial" in a:
        with open(a[a.index("--initial") + 1]) as f:
            init = json.load(f)
    print(json.dumps({"role": "SENSE", "variant": a[2], "templates": [], "initial": init}))
elif cmd == "validate-wiring":
    doc = json.load(sys.stdin)
    if doc.get("bad"):
        print(json.dumps({"findings": [{"level": "error", "code": "E_ADDR_CLASH",
                                        "where": "sensors.lux_1.addr",
                                        "message": "0x44 answers twice on mux0 ch0"}],
                          "errors": 1, "warnings": 0}))
        sys.exit(1)
    print(json.dumps({"findings": [{"level": "warn", "code": "W_PULLUPS", "where": "buses.i2c0",
                                    "message": "fit 2.2 kOhm pull-ups"}], "errors": 0, "warnings": 1}))
elif cmd == "save-board-template":
    sys.stdin.read()
    if a[1] == "taken":
        sys.exit("board template taken exists: tick replace")
    print("edge/board-templates/%s.json" % a[1])
else:
    sys.exit("stub: unexpected " + cmd)
'''


class SenseWiring(unittest.TestCase):
    """The SENSE wiring question (6 Nov 2026): the screen, a board template or the old
    questions, Back between them, the check before the erase, --wiring FILE."""

    @staticmethod
    def stub(test):
        tmp = tempfile.mkdtemp()
        test.addCleanup(subprocess.run, ["rm", "-rf", tmp])
        path = os.path.join(tmp, "device_template.py")
        with open(path, "w") as f:
            f.write(STUB_TOOL)
        test.calls_file = os.path.join(tmp, "calls")
        return path

    def run_sense(self, answers, extra=None, after=""):
        tool = self.stub(self)
        env = dict(extra or {}, CALLS=self.calls_file)
        r, prompts = PlanningBack.run_plan(self, answers, role="SENSE", tool=tool, extra=env, after=after)
        calls = [json.loads(l) for l in read(self.calls_file).splitlines()] if os.path.exists(self.calls_file) else []
        return r, prompts, calls

    ANSWER = json.dumps({"wiring": {"version": 1, "board": {"variant": "esp32s3"}, "sensors": [
        {"id": "sht45_1", "driver": "sht4x"}]}, "variant": "esp32s3", "save_as": None})

    def labels(self, prompts):
        return [(p["label"].split(" [")[0], p["back"]) for p in prompts]

    def test_screen_offered_with_the_three_kinds_of_option(self):
        r, prompts, calls = self.run_sense(["1", self.ANSWER, "30"])
        self.assertEqual(r.returncode, 0, r.stderr)
        how = prompts[0]
        self.assertEqual(how["kind"], "choice")
        self.assertEqual(how["label"].split(" [")[0], "How is this board wired?")
        opts = [o.split("|")[0] for o in how["options"]]
        self.assertEqual(opts, ["Wire the sensors on screen", "Start from a saved board: Hub board",
                                "Answer one sensor at a time (questions)"])   # the invalid one is left out
        self.assertIn("not offered: board template broken", r.stdout)
        screen = prompts[1]
        self.assertEqual(screen["kind"], "wiring")
        self.assertTrue(screen["back"])
        self.assertEqual(screen["options"], [])
        self.assertEqual(screen["spec"]["variant"], "esp32s3")
        self.assertIsNone(screen["spec"]["initial"])
        self.assertIn(["wiring-spec", "SENSE", "esp32s3"], calls)
        self.assertIn(["validate-wiring", "SENSE", "esp32s3"], calls)
        self.assertIn('WIRING variant=esp32s3 doc={"version":1,', r.stdout)
        self.assertIn("SENSORS \n", r.stdout)          # no questions answered
        self.assertIn("fit 2.2 kOhm pull-ups", r.stderr)  # a warning is shown, not refused

    def test_the_screen_starts_from_the_slots_last_record(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(subprocess.run, ["rm", "-rf", tmp])
        rec = os.path.join(tmp, "unit01-s-zone01.json")
        with open(rec, "w") as f:
            json.dump({"hostname": "unit01-s-zone01", "wiring": {"version": 1, "sensors": []}}, f)
        r, prompts, calls = self.run_sense(["1", self.ANSWER, "30"], extra={"T_OUT_DIR": tmp})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(["wiring-spec", "SENSE", "esp32s3", "--initial", rec], calls)
        self.assertEqual(prompts[1]["spec"]["initial"]["wiring"], {"version": 1, "sensors": []})

    def test_back_from_the_screen_returns_to_how(self):
        r, prompts, calls = self.run_sense(["2", "BACK", "2", self.ANSWER, "30"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.labels(prompts), [
            ("How is this board wired?", False),
            ("Wire the sensors to the board", True),
            ("How is this board wired?", False),
            ("Wire the sensors to the board", True),
            ("Publish interval (seconds)", False),
        ])
        # a board template opens the screen with it as the starting point
        self.assertEqual(prompts[1]["spec"]["initial"]["sensors"][0]["id"], "sht45_1")
        self.assertEqual([c[:2] for c in calls if c[0] == "board-template"], [["board-template", "sense-hub"]] * 2)
        self.assertTrue(any(c[0] == "wiring-spec" and "--initial" in c for c in calls))

    def test_an_invalid_wiring_dies_before_the_erase(self):
        bad = json.dumps({"wiring": {"version": 1, "bad": True}, "variant": "esp32s3"})
        r, prompts, _ = self.run_sense(["1", bad, "30"])
        self.assertEqual(r.returncode, 1)
        self.assertIn("the wiring has errors and was not accepted", r.stderr)
        self.assertIn("sensors.lux_1.addr - 0x44 answers twice on mux0 ch0", r.stderr)
        self.assertEqual(len(prompts), 2)       # nothing asked after it
        self.assertNotIn("RESULT", r.stdout)
        src = read(SCRIPT)
        # planning (and so this check) ends before the board is first touched
        self.assertLess(src.index("PLAN_STAGE=role\n"), src.index("BOARD_TOUCHED=1   #"))

    def test_questions_run_the_old_loop_and_back_returns_to_how(self):
        r, prompts, _ = self.run_sense(["3", "BACK", "3", "1", "17", "2", "30"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.labels(prompts), [
            ("How is this board wired?", False),
            ("Which sensor is wired to this board?", True),
            ("How is this board wired?", False),
            ("Which sensor is wired to this board?", True),
            ("1-Wire data pin", True),
            ("Which sensor is wired to this board?", True),
            ("Publish interval (seconds)", False),
        ])
        self.assertIn("SENSORS ground_temperature,\n", r.stdout)
        self.assertIn("WIRING variant= doc=\n", r.stdout)

    def test_wiring_file_skips_the_prompts(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(subprocess.run, ["rm", "-rf", tmp])
        wf = os.path.join(tmp, "board.json")
        with open(wf, "w") as f:
            json.dump({"version": 1, "board": {"variant": "esp32"}, "sensors": []}, f)
        r, prompts, calls = self.run_sense(["30"], extra={"T_WIRING_FILE": wf})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.labels(prompts), [("Publish interval (seconds)", False)])
        self.assertIn(["validate-wiring", "SENSE", "esp32"], calls)
        self.assertIn('WIRING variant=esp32 doc={"version":1,', r.stdout)
        # and a bad one dies before anything else is asked
        with open(wf, "w") as f:
            json.dump({"version": 1, "bad": True}, f)
        r, prompts, _ = self.run_sense(["30"], extra={"T_WIRING_FILE": wf})
        self.assertEqual(r.returncode, 1)
        self.assertEqual(prompts, [])

    def test_board_template_option(self):
        r, prompts, calls = self.run_sense(["30"], extra={"T_BOARD_TEMPLATE": "sense-hub"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(prompts), 1)
        self.assertIn(["board-template", "sense-hub"], calls)
        r, _, _ = self.run_sense(["30"], extra={"T_BOARD_TEMPLATE": "nope"})
        self.assertEqual(r.returncode, 1)
        self.assertIn("no board template nope", r.stderr)

    SAVE = '[ "$ROLE" != SENSE ] || sense_save_template'

    def answer_saving(self, slug):
        return json.dumps({"wiring": {"version": 1}, "variant": "esp32s3",
                           "save_as": {"slug": slug, "title": "-Two hubs", "description": "", "replace": True}})

    def test_save_as_records_the_signed_in_person(self):
        self.assertIn("  " + self.SAVE, read(SCRIPT))
        r, _, calls = self.run_sense(["1", self.answer_saving("two-hubs"), "30"],
                                     extra={"T_EDGE_USER": "eng"}, after=self.SAVE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(["save-board-template", "two-hubs", "--title", "-Two hubs", "--by", "eng", "--replace"], calls)
        self.assertIn("saved board template two-hubs", r.stdout)

    def test_a_failed_save_is_a_warning(self):
        r, _, _ = self.run_sense(["1", self.answer_saving("taken"), "30"],
                                 extra={"T_EDGE_USER": "eng"}, after=self.SAVE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("the board template taken was not saved", r.stderr)
        self.assertIn("RESULT", r.stdout)
        r, _, calls = self.run_sense(["1", self.answer_saving("two-hubs"), "30"], after=self.SAVE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("nobody is signed in", r.stderr)
        self.assertFalse(any(c[0] == "save-board-template" for c in calls))

    def test_chip_recheck_and_spec_cover_sense(self):
        src = read(SCRIPT)
        self.assertIn('if [ "$ROLE" = SENSE ] && [ -n "$SENSE_WIRING_JSON" ] && [ -n "$SENSE_VARIANT" ]', src)
        self.assertIn('sense_wiring_check "$CHIP" || die', src)
        # The screen offers the S3 board alone, so its advice names what works.
        line = [x for x in src.splitlines() if 'sense_wiring_check "$CHIP" || die' in x][0]
        self.assertNotIn("pick $CHIP as the board", line)
        self.assertIn("Answer one sensor at a time (questions)", line)
        self.assertIn("--wiring FILE", line)
        self.assertIn('spec["wiring"] = json.loads(e["SENSE_WIRING_JSON"])', src)
        self.assertIn('"wiring": json.loads(e["SENSE_WIRING_JSON"])', src)


class CancelAtAQuestion(unittest.TestCase):
    def run_cancel(self, touched, registered=""):
        src = read(SCRIPT)
        tmp = tempfile.mkdtemp()
        self.addCleanup(subprocess.run, ["rm", "-rf", tmp])
        with open(os.path.join(tmp, "cancel"), "w") as f:
            f.write("eng")
        defs = "\n".join(function(src, n) for n in ("info", "warn", "die", "cancel_check", "cancelled",
                                                   "ui_on", "ui_wait_answer", "ui_prompt_json",
                                                   "prompt_text"))
        script = "\n".join([
            "set -uo pipefail", "RED=''; N=''; UI=1; UI_PID=''; BACK_OK=0; CHOICES=()",
            "BOARD_TOUCHED=%d; REGISTERED_ID='%s'; CANCEL_CLOSED=0" % (touched, registered),
            "ui_append() { printf '%s\\n' \"$*\" >> \"$UI_DIR/log\"; }",
            defs,
            'prompt_text "SSID" "" "hint"; echo "not reached"',
        ])
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                           env=dict(os.environ, UI_DIR=tmp))
        return r, read(os.path.join(tmp, "log")), os.listdir(tmp)

    def test_before_the_erase(self):
        r, log, left = self.run_cancel(0)
        self.assertEqual(r.returncode, 130)
        self.assertNotIn("not reached", r.stdout)
        self.assertIn("cancelled by eng in the browser: nothing was changed on the board; nothing was registered", log)
        self.assertNotIn("cancel", left)          # consumed
        self.assertNotIn("prompt.json", left)     # no question left on the page

    def test_after_the_erase(self):
        _, log, _ = self.run_cancel(1)
        self.assertIn("the board was erased or partly written: onboard it again before it is used", log)

    def test_every_step_checks(self):
        src = read(SCRIPT)
        self.assertIn("cancel_check;", function(src, "step"))
        self.assertIn("BOARD_TOUCHED=1", function(src, "flash_at"))
        self.assertIn("cancel_check", function(src, "ui_wait_answer"))


class ReviewFixes(unittest.TestCase):
    def test_each_wiring_pass_starts_clean(self):
        """Back from CONTROL wiring to the role and on to SENSE must not keep the channel map."""
        f = function(read(SCRIPT), "plan_wiring")
        head = f[:f.index('if [ "$ROLE" = "SENSE" ]')]
        for v in ("SENSORS_TSV", "CONTROL_PINS_TSV", "CONTROL_ACTUATOR_JSON", "CONTROL_VARIANT",
                  "SENSE_WIRING_JSON", "SENSE_VARIANT", "SENSE_SAVE_AS"):
            self.assertIn('%s=""' % v, head)
        self.assertIn('if [ "$ROLE" = CONTROL ] && [ -n "$CONTROL_ACTUATOR_JSON" ]', read(SCRIPT))

    def test_cancel_closes_from_verifying_on(self):
        src = read(SCRIPT)
        close = src.index("CANCEL_CLOSED=1\n")
        self.assertLess(close, src.index('step "Verifying"'))
        self.assertGreater(close, src.index('step "Writing the board\'s files"'))
        self.assertIn('"$UI_DIR/nocancel"', src[close:src.index('step "Verifying"')])
        defs = "\n".join(function(src, n) for n in ("cancel_check",))
        tmp = tempfile.mkdtemp()
        self.addCleanup(subprocess.run, ["rm", "-rf", tmp])
        open(os.path.join(tmp, "cancel"), "w").close()
        r = subprocess.run(["bash", "-c", "CANCEL_CLOSED=1\n%s\ncancel_check; echo went-on" % defs],
                           capture_output=True, text=True, env=dict(os.environ, UI_DIR=tmp))
        self.assertEqual(r.stdout.strip(), "went-on")


class TerminalBack(unittest.TestCase):
    def test_lt_is_back_only_where_offered(self):
        src = read(SCRIPT)
        defs = "\n".join(function(src, n) for n in ("is_back", "term_back"))
        token = [l for l in src.splitlines() if l.startswith("BACK_TOKEN=")][0]
        for ok, want in (("1", "back"), ("0", "plain")):
            script = "%s\n%s\nBACK_OK=%s; ANSWER='<'; term_back; is_back && echo back || echo plain" % (token, defs, ok)
            r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
            self.assertEqual(r.stdout.strip(), want)


# A stand-in for edge/src/host/mqtt_test.py: records its argv and environment, prints the
# one JSON line the real one prints, exits STUB_RC.
STUB_MQTT_TEST = r'''import json, os, sys
with open(os.environ["T_ARGV"], "w") as f:
    json.dump({"argv": sys.argv[1:], "stdin_tty": sys.stdin.isatty()}, f)
rc = int(os.environ.get("STUB_RC", "0"))
print(json.dumps({"ok": True, "topic": "medcea/UNIT01/ZONE01/sense/_test", "msg_type": "TS"}
                 if rc == 0 else {"ok": False, "error": "stub said no"}))
sys.exit(rc)
'''


class SendTest(unittest.TestCase):
    """--send-test DNS: one TS message through mqtt_test.py, out before USB, sign-in or venv."""
    DNS = "unit01-s-zone01"

    def tree(self, config="DOMAIN=medcea\n_LAN_IP=10.0.0.5\nPROJECT_NAME=medcea\n", ca=True, record=True):
        tmp = tempfile.mkdtemp()
        self.addCleanup(subprocess.run, ["rm", "-rf", tmp])
        host = os.path.join(tmp, "edge", "src", "host")
        os.makedirs(host)
        os.makedirs(os.path.join(tmp, "edge", "provisioned"))
        with open(SCRIPT) as f, open(os.path.join(tmp, "edge", "flash-device.sh"), "w") as g:
            g.write(f.read())
        with open(os.path.join(host, "mqtt_test.py"), "w") as f:
            f.write(STUB_MQTT_TEST)
        # A tripwire: the toolchain is never built for a test message.
        with open(os.path.join(tmp, "edge", "lib-venv.sh"), "w") as f:
            f.write('touch "$T_VENV"\nensure_edge_venv() { return 1; }\n')
        with open(os.path.join(tmp, "config.env"), "w") as f:
            f.write(config)
        if ca:
            os.makedirs(os.path.join(tmp, ".ca"))
            open(os.path.join(tmp, ".ca", "ca.crt"), "w").close()
        if record:
            with open(os.path.join(tmp, "edge", "provisioned", self.DNS + ".json"), "w") as f:
                json.dump({"hostname": self.DNS, "mqtt": {"username": self.DNS}}, f)
        return tmp

    def run_send(self, args, tmp=None, rc=0):
        tmp = tmp or self.tree()
        env = dict(os.environ, T_ARGV=os.path.join(tmp, "argv.json"), T_VENV=os.path.join(tmp, "venv"),
                   STUB_RC=str(rc))
        r = subprocess.run(["bash", os.path.join(tmp, "edge", "flash-device.sh")] + args,
                           capture_output=True, text=True, env=env, cwd=tmp, stdin=subprocess.DEVNULL,
                           timeout=60)
        argv = None
        if os.path.exists(env["T_ARGV"]):
            with open(env["T_ARGV"]) as f:
                argv = json.load(f)["argv"]
        self.assertFalse(os.path.exists(env["T_VENV"]), "--send-test sourced lib-venv.sh")
        return r, argv, tmp

    def test_runs_mqtt_test_with_the_onboarding_broker_values(self):
        r, argv, tmp = self.run_send(["--send-test", self.DNS])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(argv, ["--record", os.path.join(tmp, "edge", "provisioned", self.DNS + ".json"),
                                "--host", "10.0.0.5", "--port", "31884", "--tls-name", "mqtt.medcea",
                                "--ca", os.path.join(tmp, ".ca", "ca.crt"), "--source", "cli"])
        self.assertEqual(json.loads(r.stdout.strip().splitlines()[-1])["msg_type"], "TS")
        self.assertIn("look for tag _test", r.stderr)

    def test_broker_options_override(self):
        r, argv, _ = self.run_send(["--mqtt-host", "192.0.2.7", "--send-test", self.DNS,
                                    "--mqtt-port", "8883", "--mqtt-tls-name", "mqtt.other"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(argv[argv.index("--host") + 1], "192.0.2.7")
        self.assertEqual(argv[argv.index("--port") + 1], "8883")
        self.assertEqual(argv[argv.index("--tls-name") + 1], "mqtt.other")

    def test_exits_with_mqtt_tests_code(self):
        for rc in (1, 2):
            r, argv, _ = self.run_send(["--send-test", self.DNS], rc=rc)
            self.assertEqual(r.returncode, rc)
            self.assertIsNotNone(argv)
            self.assertEqual(json.loads(r.stdout.strip().splitlines()[-1])["ok"], False)
            self.assertNotIn("look for tag _test", r.stderr)

    def assertRefused(self, args, msg, tmp=None):
        r, argv, _ = self.run_send(args, tmp=tmp)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIsNone(argv, "mqtt_test.py ran for %r" % (args,))
        self.assertIn(msg, r.stderr)
        return r

    def test_bad_names_are_refused(self):
        for name in ("-y", "--role", "Unit01-s-zone01", "../config", "unit01_s", "a" * 33, ""):
            self.assertRefused(["--send-test", name], "not a board name")
        self.assertRefused(["--send-test"], "not a board name")

    def test_flashing_options_are_refused(self):
        for extra in (["--role", "SENSE"], ["--ui"], ["-y"], ["--no-erase"], ["--unregistered"],
                      ["-p", "/dev/ttyUSB0"], ["--wiring", "x.json"], ["--topic-root", "other"],
                      ["--offline"], ["--ui-spool", "/tmp/x"]):
            self.assertRefused(["--send-test", self.DNS] + extra, "--send-test flashes nothing: not with %s" % extra[0])
        r = self.assertRefused(["--psk", "hunter2-secret", "--send-test", self.DNS], "not with --psk")
        self.assertNotIn("hunter2-secret", r.stderr + r.stdout)

    def test_missing_record_ca_or_domain(self):
        self.assertRefused(["--send-test", self.DNS], "no readable record", tmp=self.tree(record=False))
        self.assertRefused(["--send-test", self.DNS], "the platform CA", tmp=self.tree(ca=False))
        self.assertRefused(["--send-test", self.DNS], "no broker certificate name",
                           tmp=self.tree(config="_LAN_IP=10.0.0.5\n"))

    def test_help_names_it(self):
        r = subprocess.run(["bash", SCRIPT, "--help"], capture_output=True, text=True)
        self.assertIn("--send-test DNS", r.stdout)
        self.assertIn("Only --mqtt-host, --mqtt-port and", r.stdout)


if __name__ == "__main__":
    unittest.main()
