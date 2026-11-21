"""tests/test_scheduler_cancel.py: the Scheduler page cancels a queued run (21 Nov 2026), offline.

A queued run (S) gets ■ Cancel beside ▶ Execute; it calls the stop route, which sets S -> F
through medcea.set_run_status (level O). A running run (R) keeps ■ Stop.

    python3 tests/test_scheduler_cancel.py
"""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


class Cancel(unittest.TestCase):
    def setUp(self):
        self.page = read("apps", "scheduler", "html", "scheduler.html")

    def branch(self, status):
        m = re.search(r"if \(r\.recipe_run_status === '%s'\) \{(.*?)\n    \}" % status, self.page, re.S)
        self.assertIsNotNone(m, status)
        return m.group(1)

    def test_a_queued_run_has_execute_and_cancel(self):
        s = self.branch("S")
        self.assertIn("executeRun(${r.recipe_run_id})", s)
        self.assertIn("stopRun(${r.recipe_run_id}, true)", s)
        self.assertIn("■ Cancel", s)

    def test_a_running_run_keeps_stop(self):
        r = self.branch("R")
        self.assertIn("stopRun(${r.recipe_run_id})", r)
        self.assertIn("■ Stop", r)

    def test_the_stop_route_accepts_a_queued_run(self):
        api = read("apps", "scheduler", "scheduler-api.py")
        self.assertIn('"""R or S: medcea.set_run_status(F) as the person', api)

    def test_the_manual_names_it(self):
        self.assertIn("<strong>■ Cancel</strong>", read("docs", "manual", "chapters", "apps.html"))


class RunNow(unittest.TestCase):
    """Run Now: only an R or S run blocks the unit (as the API's _active_run); with
    IAM_DB_ROLES=true it sends an approved parameter set and no inline algorithm."""

    def setUp(self):
        self.page = read("apps", "scheduler", "html", "scheduler.html")

    def fn(self, name):
        i = self.page.index("async function %s(" % name)
        j = self.page.index("\nasync function ", i + 1)
        return self.page[i:j]

    def test_only_running_or_queued_runs_block(self):
        f = self.fn("loadRnUnits")
        self.assertIn("r.recipe_run_status === 'R' || r.recipe_run_status === 'S'", f)
        api = read("apps", "scheduler", "scheduler-api.py")
        self.assertIn("recipe_run_status IN ('S','R')", api)

    def test_a_parameter_set_under_iam_db_roles(self):
        f = self.fn("submitRunNow")
        self.assertIn("if (_iamDbRoles)", f)
        self.assertIn("JSON.stringify({unit_id, recipe_id, params_id})", f)
        enforced = f[f.index("if (_iamDbRoles)"):f.index("return;\n  }")]
        self.assertNotIn("control_algorithm", enforced)
        self.assertIn("x.status === 'approved'", self.fn("loadRnParamSets"))
        self.assertIn('id="rn-params-id"', self.page)


class Decommission(unittest.TestCase):
    """Rerun (a new run) and Decommission (F -> is_active 'N', confirmed by the run's number)."""

    def setUp(self):
        self.page = read("apps", "scheduler", "html", "scheduler.html")
        self.api = read("apps", "scheduler", "scheduler-api.py")
        self.mig = read("apps", "database", "medcea_db_migrations.sql")

    def body(self, head):
        i = self.mig.index(head)
        return self.mig[i:self.mig.index("END $$;", i)]

    def test_the_database_transition(self):
        srs = self.body("FUNCTION medcea.set_run_status(")
        self.assertIn("('F', 'D')", srs)
        self.assertIn("UPDATE medcea.recipe_run SET is_active = 'N'", srs)
        # a decommissioned run refuses everything, before the transition check
        self.assertLess(srs.index("IF r.is_active = 'N' THEN"), srs.index("is not a transition"))
        self.assertLess(srs.index("_check_assigned_run"), srs.index("IF r.is_active = 'N' THEN"))
        # the D write sits inside the owner-write window, after _unit_schedulable (test_policy pins the order)
        self.assertLess(srs.index("_owner_write(true)"), srs.index("IF p_status = 'D' THEN"))
        self.assertLess(srs.index("IF p_status = 'D' THEN"), srs.index("_owner_write(false)"))
        sr = self.body("FUNCTION medcea.start_run(")
        self.assertLess(sr.index("IF r.is_active = 'N' THEN"), sr.index("IF r.recipe_run_status <> 'S' THEN"))
        self.assertIn("is decommissioned", sr)

    def test_the_api_needs_the_number_and_a_failed_run(self):
        i = self.api.index("def set_run_status(run_id):")
        fn = self.api[i:self.api.index("@app.route", i)]
        self.assertIn("if current['is_active'] == 'N':", fn)
        self.assertIn("str(d.get('confirm', '')).strip() != str(run_id)", fn)
        self.assertIn("if st != 'F':", fn)
        self.assertLess(fn.index("str(d.get('confirm'"), fn.index("SELECT medcea.set_run_status(%s, 'D')"))
        self.assertIn("rr.recipe_run_status != 'C' AND rr.is_active = 'Y'", self.api)
        self.assertIn("(rr.recipe_run_status = 'C' OR rr.is_active = 'N')", self.api)
        self.assertIn("rr.recipe_run_status <> 'C' AND rr.is_active = 'Y'", read("apps", "monitor", "monitor-api.py"))

    def test_the_page(self):
        f = self.page[self.page.index("if (r.recipe_run_status === 'F') {"):]
        f = f[:f.index("// Log button")]
        self.assertIn("openDecomModal(${r.recipe_run_id})", f)
        self.assertIn("rerunRun(${r.unit_id}, ${r.recipe_id})", f)
        self.assertIn("if (!_iamDbRoles || r.params_id)", f)
        sub = self.page[self.page.index("async function submitDecom("):self.page.index("async function openRetryModal(")]
        self.assertIn("if (typed !== String(runId)) return;", sub)
        self.assertIn("JSON.stringify({status: 'D', confirm: typed})", sub)
        self.assertIn('id="decom-submit" onclick="submitDecom()" disabled', self.page)
        self.assertIn("r.is_active === 'N' ? 'D'", self.page)


if __name__ == "__main__":
    unittest.main()
