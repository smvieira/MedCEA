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
           "plan_wiring")

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
    def run_plan(self, answers, role=""):
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
            "UNIT_WANTED=''; ZONE_WANTED=''",
            defs, FAKE_BROWSER,
            'set -e',
            loop,
            '  BACK_OK=0',
            'echo "RESULT role=$ROLE unit=$UNIT_CODE zone=$ZONE_CODE dns=$SLOT_DNS pins=$(grep -c . <<<"$CONTROL_PINS_TSV" || true)"',
        ])
        env = dict(os.environ, UI_DIR=tmp, ANSWERS=os.path.join(tmp, "answers"),
                   PROMPTS=os.path.join(tmp, "prompts"), UILOG=os.path.join(tmp, "uilog"),
                   TEMPLATE_TOOL=os.path.join(ROOT, "edge", "src", "host", "device_template.py"),
                   SLOTS=SLOTS, ROLE=role)
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
        r, prompts = self.run_plan([], role="SENSE")
        # SENSE's first question is its sensor menu (the run then stops: no answers left)
        self.assertEqual(r.returncode, 99, r.stderr)
        self.assertTrue(prompts, r.stderr)
        self.assertEqual(prompts[0]["label"].split(" [")[0], "Which sensor is wired to this board?")
        self.assertFalse(prompts[0]["back"])


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
        for v in ("SENSORS_TSV", "CONTROL_PINS_TSV", "CONTROL_ACTUATOR_JSON", "CONTROL_VARIANT"):
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


if __name__ == "__main__":
    unittest.main()
