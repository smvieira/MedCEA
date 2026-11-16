#!/usr/bin/env python3
"""tests/test_health_controlloops.py — health-check.sh's controlloops check (feedback control, Q11/Q20).

Offline, with test_health_phase5.py's scratch tree and fake kubectl (read-only verbs only,
every call logged with its stdin). Nothing reaches a cluster or the repository's state/.

  ControlLoops  one read-only psql as postgres in rdbms-postgresql-0: SKIP before migration
                010, OK when every zone with actuators has valid loop rows, WARN on zones on
                the default map, on such zones with several sensors on a tag (no_data +
                ALARM ambiguous_source) or with _zone_inventory sensor problems, and on
                active loops _loop_problems() rejects, WARN
                when unreadable; never FAIL
  Wiring        the conf line after Scheduler UI, the dispatch and the help line

    python3 tests/test_health_controlloops.py
"""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from test_health_phase5 import Base, body, rule  # noqa: E402

PG = r"exec -i -n medcea rdbms-postgresql-0 -- env PGOPTIONS=-c default_transaction_read_only=on"
NAME = "Control loops"


def loops_out(zones=2, loops=6, n_def=0, defs="", n_amb=0, amb="", n_bad=0, bad="", n_sp=0, sp=""):
    return (f"zones|{zones}|{loops}\ndefault|{n_def}|{defs}\nambiguous|{n_amb}|{amb}\n"
            f"sensors|{n_sp}|{sp}\nproblems|{n_bad}|{bad}\n")


class ControlLoops(Base):
    def run_check(self, out=None, rc=0, err=""):
        self.t.scenario([rule(PG, loops_out() if out is None else out, rc, err, stdin="medcea.control_loop")])
        return self.t.fn("check_controlloops", f'check_controlloops "{NAME}" medcea_db', helpers=())

    def test_skip_before_migration_010(self):
        self.assertEqual(self.run_check("state|unbuilt\n"),
                         f"SKIP|{NAME}|no medcea.control_loop table yet (./apps/database/deploy.sh, migration 010)")
        self.assertReadOnly()

    def test_ok(self):
        self.assertEqual(self.run_check(), f"OK|{NAME}|2 zone(s) with actuators, all on valid control_loop rows "
                         "(6 active loop(s))")
        self.assertEqual(self.run_check(loops_out(zones=0, loops=0)), f"OK|{NAME}|no active zone has actuators")
        c = self.t.calls()
        self.assertEqual(len(c), 1)
        self.assertIn("PGOPTIONS=-c default_transaction_read_only=on -c client_min_messages=warning", c[0]["argv"])
        self.assertEqual(c[0]["argv"][-1], "medcea_db")
        self.assertIn("-U postgres", " ".join(c[0]["argv"]))
        self.assertReadOnly()

    def test_warn_default_map(self):
        r = self.run_check(loops_out(n_def=2, defs="U1/Z1 U2/Z1"))
        self.assertEqual(r, f"WARN|{NAME}|2 zone(s) run on the default map (no control_loop rows; Q20): U1/Z1 U2/Z1")
        r = self.run_check(loops_out(n_def=7, defs="A/1 A/2 A/3 A/4 A/5"))
        self.assertTrue(r.endswith("A/1 A/2 A/3 A/4 A/5 ..."), r)
        self.assertReadOnly()

    def test_warn_ambiguous(self):
        r = self.run_check(loops_out(n_def=1, defs="U1/Z1", n_amb=1, amb="U1/Z1 air_temperature: scd30,sht45"))
        self.assertTrue(r.startswith("WARN|"), r)
        self.assertIn("1 zone(s) run on the default map (no control_loop rows; Q20): U1/Z1; 1 of them with several "
                      "sensors on a tag (no_data + ALARM ambiguous_source: choose the reference in onboarding): "
                      "U1/Z1 air_temperature: scd30,sht45", r)
        r = self.run_check(loops_out(n_def=4, defs="a b c d", n_amb=4, amb="a co2: x,y; b co2: x,y; c co2: x,y"))
        self.assertTrue(r.endswith("c co2: x,y; ..."), r)

    def test_warn_problems(self):
        r = self.run_check(loops_out(n_bad=1, bad="U1/Z1 co2: output.command_map must be exactly "
                                                  '{"UP": "OFF", "OFF": "OFF", "DOWN": "UP"}'))
        self.assertEqual(r, f"WARN|{NAME}|1 active loop(s) break the loop rules (the loop picker rejects them; the runner "
                         "refuses rule errors and gets no_data or no actuator for the rest; re-save in "
                         'onboarding): U1/Z1 co2: output.command_map must be exactly {"UP": "OFF", "OFF": "OFF", "DOWN": "UP"}')
        r = self.run_check(loops_out(n_def=1, defs="U2/Z1", n_bad=1, bad="U1/Z1 co2: x"))
        self.assertIn("(no control_loop rows; Q20): U2/Z1; 1 active loop(s) break", r)

    def test_warn_sensor_problems(self):
        r = self.run_check(loops_out(n_def=1, defs="U1/Z1", n_sp=1,
                                     sp="U1/Z1 component 7 publishes air_temperature as sensor default, a reserved name"))
        self.assertEqual(r, f"WARN|{NAME}|1 zone(s) run on the default map (no control_loop rows; Q20): U1/Z1; "
                         "1 of them with sensor problems (their readings still count on the default map: "
                         "re-onboard): U1/Z1 component 7 publishes air_temperature as sensor default, a reserved name")
        r = self.run_check(loops_out(n_def=4, defs="a b c d", n_sp=4, sp="a x; b x; c x"))
        self.assertTrue(r.endswith("c x; ..."), r)
        # an answer without the sensors line is unreadable, never OK
        self.assertTrue(self.run_check("zones|1|0\ndefault|0|\nambiguous|0|\nproblems|0|\n")
                        .startswith(f"WARN|{NAME}|cannot read"))

    def test_never_fails(self):
        for out in (loops_out(n_def=9, defs="a", n_amb=9, amb="a", n_bad=9, bad="a"), "state|partial\n", ""):
            self.assertFalse(self.run_check(out).startswith("FAIL|"), out)
        self.assertNotIn("_record FAIL", body("check_controlloops"))

    def test_unreadable_warns(self):
        self.assertTrue(self.run_check("state|partial\n").startswith(f"WARN|{NAME}|medcea.control_loop exists without"))
        for out, rc in (("", 2), ("zones|1|0\n", 0), ("psql:<stdin>:9: ERROR:  permission denied for table x\n", 3),
                        ("state|unbuilt\n", 2)):
            r = self.run_check(out, rc)
            self.assertTrue(r.startswith(f"WARN|{NAME}|cannot read the control loops of medcea_db"), (out, rc, r))
        r = self.run_check("psql:<stdin>:9: ERROR:  permission denied for table x\n", 3)
        self.assertIn("ERROR:  permission denied", r)


class Wiring(unittest.TestCase):
    def test_conf_dispatch_help_and_sql(self):
        with open(os.path.join(REPO, "health-checks.conf")) as f:
            lines = [l for l in f.read().splitlines() if l.strip() and not l.startswith("#")]
        names = [l.split("|")[0].strip() for l in lines]
        i = names.index("Scheduler UI")
        self.assertEqual([x.strip() for x in lines[i + 1].split("|")[:3]], [NAME, "controlloops", "$POSTGRES_DB"])
        self.assertEqual([l.split("|")[1].strip() for l in lines].count("controlloops"), 1)
        with open(os.path.join(REPO, "health-check.sh")) as f:
            src = f.read()
        self.assertRegex(src, r'(?m)^        controlloops\) check_controlloops "\$name" "\$target" ;;$')
        self.assertIn("${CYAN}controlloops${NC}", src)
        fn = body("check_controlloops", src)
        self.assertIn('timeout "$TIMEOUT" $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0', fn)
        self.assertIn("default_transaction_read_only=on", fn)
        self.assertIn("ON_ERROR_STOP=1", fn)
        self.assertIn('PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")"', fn)
        # the signatures the check calls are the migration's
        with open(os.path.join(REPO, "apps", "database", "medcea_db_migrations.sql")) as f:
            mig = f.read()
        for sig, call in (("medcea._loop_problems(p_loop jsonb, p_zone_code text, p_sensors jsonb, p_actuators jsonb)",
                           "medcea._loop_problems(jsonb,text,jsonb,jsonb)"),
                          ("medcea._zone_inventory(p_zone_id integer, OUT sensors jsonb", "medcea._zone_inventory(integer)"),
                          ("medcea._loop_quantities() RETURNS jsonb", "medcea._loop_quantities()")):
            self.assertIn("FUNCTION " + sig, mig)
            self.assertIn(call, fn)
        # the runner's zone selection: an active ACTUATOR component in an active zone of an active unit
        self.assertIn("c.component_type = 'ACTUATOR' AND c.is_active = 'Y'", fn)
        self.assertIn("coalesce(d.is_active, 'Y') = 'Y'", fn)
        self.assertIn("u.is_active = 'Y' AND z.is_active = 'Y'", fn)
        runner_py = os.path.join(REPO, "schd", "cea", "get_control_loops.py")
        if os.path.exists(runner_py):   # the runner's default-map selection (commit C4)
            with open(runner_py) as f:
                runner = " ".join(f.read().split())
            for cond in ("u.is_active = 'Y' AND z.is_active = 'Y'", "coalesce(d.is_active, 'Y') = 'Y'",
                         "c.component_type = 'ACTUATOR' AND c.is_active = 'Y'"):
                self.assertIn(cond, runner)
        # ambiguity: two or more distinct sensors on a tag, an old board's readings being sensor 'default'
        self.assertRegex(fn, r"HAVING count\(DISTINCT s\.sensor\) >= 2")
        self.assertIn("SELECT 'default', b -> 'tags' FROM jsonb_array_elements(dm.old_boards) b", fn)
        # the inventory's problems of a default-map zone are reported (its readings still count there)
        self.assertIn("i.problems", fn)
        self.assertRegex(fn, r"FROM dm WHERE jsonb_typeof\(dm\.problems\) = 'array' AND jsonb_array_length\(dm\.problems\) > 0")
        self.assertNotRegex(fn, r"(?i)\b(insert|update|delete|create|alter|drop|grant)\b\s")


if __name__ == "__main__":
    unittest.main()
