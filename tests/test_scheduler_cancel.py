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


if __name__ == "__main__":
    unittest.main()
