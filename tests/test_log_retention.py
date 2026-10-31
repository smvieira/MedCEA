#!/usr/bin/env python3
"""tests/test_log_retention.py — the scheduler's run-log job (apps/scheduler/log_retention.py, IAM 2.6).

Run logs are compressed, never deleted; nothing but run_recipe_*.log is touched (the
deploy logs share the directory); a run in S or R, or one running now, keeps its log.

Run from the repository root:  python3 tests/test_log_retention.py
Offline, stdlib only.
"""
import gzip
import importlib.util
import logging
import os
import stat
import sys
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("log_retention", os.path.join(REPO, "apps/scheduler/log_retention.py"))
lr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lr)

log = logging.getLogger("test_log_retention")
NOW = time.time()
DAY = 86400


class LogRetentionTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        for f in os.listdir(self.dir):
            os.chmod(os.path.join(self.dir, f), stat.S_IRUSR | stat.S_IWUSR)
        os.chmod(self.dir, stat.S_IRWXU)
        self._tmp.cleanup()

    def put(self, name, days, content=b"line\n"):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as f:
            f.write(content)
        t = NOW - days * DAY
        os.utime(path, (t, t))
        return path

    def entries(self):
        return [(f, os.stat(os.path.join(self.dir, f)).st_mtime) for f in sorted(os.listdir(self.dir))]

    def run_job(self, compress_days, runs, active=()):
        actions = lr.plan(self.entries(), NOW, compress_days, runs, set(active))
        return actions, lr.apply(self.dir, actions, log)

    @staticmethod
    def runs(rid, status, unit="U1", recipe="R"):
        return {rid: {"status": status, "basename": f"run_recipe_{unit}_{recipe}_{rid}.log"}}

    def test_foreign_files_never_touched(self):
        for n in ("deploy-infra-20250101.log", "deploy-apps-x.log", "foo.log", "foo.log.gz"):
            self.put(n, 400)
        actions, res = self.run_job(1, {})
        self.assertEqual(actions, [])
        self.assertEqual(sorted(os.listdir(self.dir)),
                         ["deploy-apps-x.log", "deploy-infra-20250101.log", "foo.log", "foo.log.gz"])

    def test_finished_run_compressed(self):
        p = self.put("run_recipe_U1_R_7.log", 10, b"hello\nworld\n")
        mtime = os.stat(p).st_mtime
        _, res = self.run_job(7, self.runs(7, "C"))
        self.assertEqual(res["compressed"], 1)
        self.assertFalse(os.path.exists(p))
        self.assertFalse(os.path.exists(p + ".gz.tmp"))
        with gzip.open(p + ".gz", "rb") as f:
            self.assertEqual(f.read(), b"hello\nworld\n")
        self.assertEqual(os.stat(p + ".gz").st_mtime, mtime)

    def test_failed_run_compressed(self):
        self.put("run_recipe_U1_R_8.log", 10)
        _, res = self.run_job(7, self.runs(8, "F"))
        self.assertEqual(res["compressed"], 1)

    def test_running_run_kept(self):
        runs = {**self.runs(1, "S"), **self.runs(2, "R"), **self.runs(3, "C")}
        for rid in (1, 2, 3):
            self.put(f"run_recipe_U1_R_{rid}.log", 400)
        _, res = self.run_job(1, runs, active={3})
        self.assertEqual(res["compressed"], 0)
        self.assertEqual(len([f for f in os.listdir(self.dir) if f.endswith(".log")]), 3)

    def test_young_log_kept(self):
        self.put("run_recipe_U1_R_7.log", 3)
        _, res = self.run_job(7, self.runs(7, "C"))
        self.assertEqual(res["compressed"], 0)

    def test_never_deletes(self):
        self.put("run_recipe_U1_R_7.log.gz", 4000)
        self.put("run_recipe_U1_R_9.log", 4000)
        actions, res = self.run_job(1, {**self.runs(7, "C"), **self.runs(9, "C")})
        self.assertEqual({a for a, _, _ in actions}, {"keep", "compress"})
        self.assertEqual(sorted(os.listdir(self.dir)), ["run_recipe_U1_R_7.log.gz", "run_recipe_U1_R_9.log.gz"])

    def test_minimum_clamped(self):
        self.put("run_recipe_U1_R_7.log", 0.5)
        _, res = self.run_job(0, self.runs(7, "C"))
        self.assertEqual(res["compressed"], 0)
        self.put("run_recipe_U1_R_8.log", 1.5)
        _, res = self.run_job(0, self.runs(8, "C"))
        self.assertEqual(res["compressed"], 1)

    def test_legacy_and_mismatched_names(self):
        self.put("run_recipe_U1_Old.log", 30)                 # no run id
        self.put("run_recipe_U1_Batch_12.log", 30)            # a recipe called Batch_12, legacy name
        runs = {12: {"status": "R", "basename": "run_recipe_U2_X_12.log"}}
        _, res = self.run_job(7, runs)
        self.assertEqual(res["compressed"], 2)
        # ... unless a run with that id is running here
        self.put("run_recipe_U1_Batch_13.log", 30)
        _, res = self.run_job(7, {}, active={13})
        self.assertEqual(res["compressed"], 0)

    def test_existing_gz_appended(self):
        p = self.put("run_recipe_U1_R_7.log", 10, b"first attempt\n")
        self.run_job(7, self.runs(7, "F"))
        self.put("run_recipe_U1_R_7.log", 10, b"retry\n")       # F -> S -> R appends a new .log
        self.run_job(7, self.runs(7, "C"))
        self.assertEqual(os.listdir(self.dir), ["run_recipe_U1_R_7.log.gz"])
        with gzip.open(p + ".gz", "rb") as f:
            self.assertEqual(f.read(), b"first attempt\nretry\n")

    def test_changed_or_restarted_since_plan_kept(self):
        self.put("run_recipe_U1_R_7.log", 10)
        actions = lr.plan(self.entries(), NOW, 7, self.runs(7, "C"), set())
        res = lr.apply(self.dir, actions, log, still_idle=lambda rid: False)
        self.assertEqual((res["compressed"], res["kept"]), (0, 1))
        res = lr.apply(self.dir, actions, log, stats={"run_recipe_U1_R_7.log": (0, 0)})
        self.assertEqual((res["compressed"], res["kept"]), (0, 1))
        self.assertTrue(os.path.exists(os.path.join(self.dir, "run_recipe_U1_R_7.log")))

    def test_stale_tmp_removed(self):
        self.put("run_recipe_U1_R_7.log.gz.tmp", 2)
        self.put("run_recipe_U1_R_8.log.gz.tmp", 0.1)
        self.put("deploy-infra.log.gz.tmp", 2)
        self.run_job(7, {})
        self.assertEqual(sorted(os.listdir(self.dir)), ["deploy-infra.log.gz.tmp", "run_recipe_U1_R_8.log.gz.tmp"])

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root ignores permissions")
    def test_apply_never_raises(self):
        self.put("run_recipe_U1_R_7.log", 10)
        os.chmod(self.dir, stat.S_IRUSR | stat.S_IXUSR)       # cannot create the .gz
        try:
            _, res = self.run_job(7, self.runs(7, "C"))
        finally:
            os.chmod(self.dir, stat.S_IRWXU)
        self.assertEqual((res["compressed"], res["errors"]), (0, 1))
        self.assertTrue(os.path.exists(os.path.join(self.dir, "run_recipe_U1_R_7.log")))

    def test_run_id_of(self):
        self.assertEqual(lr.run_id_of("run_recipe_U1_R_42.log.gz"), 42)
        self.assertIsNone(lr.run_id_of("run_recipe_U1_R.log"))


if __name__ == "__main__":
    logging.basicConfig(level=logging.CRITICAL)
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
