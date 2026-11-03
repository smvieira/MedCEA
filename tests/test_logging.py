#!/usr/bin/env python3
"""tests/test_logging.py — every deploy, uninstall, health check and live test writes
its own log in logs/ (infra/lib-log.sh), so its output can be read back without being
copied from a terminal.

Offline. Checks that each entry script calls medcea_log, before medcea_lock (tee must
not inherit the lock's fd 9), that the parents export MEDCEA_LOG_FILE so their children
log once, and runs the helper: exit code kept, mode 600, quiet under a parent.
"""
import glob
import os
import stat
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


ENTRY = (sorted(glob.glob("apps/*/deploy.sh", root_dir=ROOT)) + sorted(glob.glob("apps/*/uninstall.sh", root_dir=ROOT))
         + ["apps/iam/units.sh", "apps/iam/apply.sh", "apps/backup/backups.sh", "infra/deploy-workbench.sh", "infra/publish-manual.sh", "health-check.sh",
            "tests/iam-db-fixture.sh"]
         + [f"tests/iam-{n}.sh" for n in ("signin", "workbench", "mqtt", "access", "network", "hosts", "check",
                                          "schema", "runner", "postgrest", "db")])


class EntryScriptsLog(unittest.TestCase):
    def test_every_entry_script_logs_before_the_lock(self):
        for rel in ENTRY:
            with self.subTest(rel):
                s = "\n".join(l for l in read(rel).splitlines() if not l.lstrip().startswith("#"))
                self.assertIn("medcea_log ", s)
                if "medcea_lock" in s:
                    self.assertLess(s.index("medcea_log "), s.index("medcea_lock"))

    def test_parents_export_their_log(self):
        self.assertIn('export MEDCEA_LOG_FILE="$LOG_FILE"', read("deploy-infra.sh"))
        self.assertEqual(read("deploy-apps.sh").count('export MEDCEA_LOG_FILE="$LOG_FILE"'), 2)


class Helper(unittest.TestCase):
    def run_script(self, env_extra=None):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "infra"))
        with open(os.path.join(ROOT, "infra", "lib-log.sh")) as src, open(os.path.join(d, "infra", "lib-log.sh"), "w") as dst:
            dst.write(src.read())
        with open(os.path.join(d, "s.sh"), "w") as fh:
            fh.write('REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"; source "$REPO_ROOT/infra/lib-log.sh"; medcea_log t\n'
                     'echo out; echo err >&2; exit 3\n')
        env = {k: v for k, v in os.environ.items() if k not in ("MEDCEA_LOG_FILE", "MEDCEA_NO_LOG")}
        env.update(env_extra or {})
        p = subprocess.run(["bash", os.path.join(d, "s.sh")], capture_output=True, text=True, env=env)
        return d, p

    def test_logs_and_keeps_the_exit_code(self):
        d, p = self.run_script()
        self.assertEqual(p.returncode, 3)
        logs = glob.glob(os.path.join(d, "logs", "t-*.log"))
        self.assertEqual(len(logs), 1)
        self.assertEqual(stat.S_IMODE(os.stat(logs[0]).st_mode), 0o600)
        with open(logs[0]) as fh:
            body = fh.read()
        self.assertIn("out", body)
        self.assertIn("err", body)

    def test_quiet_under_a_parent_or_when_off(self):
        for extra in ({"MEDCEA_LOG_FILE": "/nonexistent/parent.log"}, {"MEDCEA_NO_LOG": "1"}):
            with self.subTest(extra):
                d, p = self.run_script(extra)
                self.assertEqual(p.returncode, 3)
                self.assertFalse(os.path.exists(os.path.join(d, "logs")))


if __name__ == "__main__":
    unittest.main()
