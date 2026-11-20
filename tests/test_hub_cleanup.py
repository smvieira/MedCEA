"""tests/lib-hub-cleanup.sh: the live tests remove their throwaway hub users (owner decision
of 20 Nov 2026), offline.

hub_sweep_test_users runs against a fake kubectl (logs argv, answers the list from the
environment, "deletes" what it is given) and a stub _kc_get; the list query runs on a real
sqlite file shaped like the hub's. Only test-<role>-<hex> names without a realm account and
without a running workspace are deleted, and the hub restarts only when one was.
"""
import os
import pathlib
import sqlite3
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent
LIB = REPO / "tests" / "lib-hub-cleanup.sh"

FAKE_KUBECTL = r"""#!/bin/sh
{ printf '%s' "$*" | tr '\n' '~'; echo; } >> "$LOG"   # one line per call
case "$*" in
  "get pods "*) [ -n "$FAKE_POD" ] && printf '%s' "$FAKE_POD"; exit 0 ;;
  "exec "*)
    case "$*" in
      *new_session_factory*)
        found=""
        for a in "$@"; do
          if [ -n "$found" ]; then echo "deleted|$a"; fi
          case "$a" in *new_session_factory*) found=1 ;; esac
        done
        echo "end|"; exit 0 ;;
      *) printf '%b' "$FAKE_LIST"; echo "end|"; exit 0 ;;
    esac ;;
  "rollout "*) exit 0 ;;
esac
exit 1
"""

DRIVER = r"""
set -u
source "$LIB"
_kc_get() {
    local u="${1#*username=}"; u="${u%%&*}"
    case " $KC_ERROR " in *" $u "*) return 22 ;; esac
    case " $KC_PRESENT " in *" $u "*) echo '[{"id": "x"}]'; return 0 ;; esac
    echo '[ ]'
}
hub_sweep_test_users medcea-research medcea
"""


class Sweep(unittest.TestCase):
    def run_sweep(self, listing, pod="hub-1", present="", error=""):
        with tempfile.TemporaryDirectory() as d:
            kubectl = pathlib.Path(d) / "kubectl"
            kubectl.write_text(FAKE_KUBECTL)
            kubectl.chmod(0o755)
            log = pathlib.Path(d) / "log"
            env = dict(os.environ, KUBECTL=str(kubectl), LOG=str(log), LIB=str(LIB),
                       FAKE_POD=pod, FAKE_LIST=listing, KC_PRESENT=present, KC_ERROR=error)
            p = subprocess.run(["bash", "-c", DRIVER], env=env, capture_output=True, text=True, timeout=30)
            calls = log.read_text().splitlines() if log.exists() else []
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout + p.stderr, calls

    @staticmethod
    def deletes(calls):
        return [c for c in calls if "new_session_factory" in c]

    @staticmethod
    def restarts(calls):
        return [c for c in calls if c.startswith("rollout restart")]

    def test_removes_a_leftover_admin_and_restarts_the_hub(self):
        out, calls = self.run_sweep("test-admin-a92659|0\\n")
        [d] = self.deletes(calls)
        self.assertTrue(d.endswith(" test-admin-a92659"), d)
        self.assertIn("-c hub", d)
        self.assertEqual(self.restarts(calls), ["rollout restart deployment/hub -n medcea-research"])
        self.assertIn("rollout status deployment/hub -n medcea-research --timeout=5m", calls)
        self.assertIn("removed test-admin-a92659", out)

    def test_keeps_an_account_keycloak_still_has(self):
        out, calls = self.run_sweep("test-viewer-abcdef|0\\n", present="test-viewer-abcdef")
        self.assertEqual(self.deletes(calls), [])
        self.assertEqual(self.restarts(calls), [])
        self.assertIn("still an account in realm medcea", out)

    def test_keeps_a_name_keycloak_did_not_answer_for(self):
        out, calls = self.run_sweep("test-admin-123456|0\\n", error="test-admin-123456")
        self.assertEqual(self.deletes(calls), [])
        self.assertIn("Keycloak did not answer", out)

    def test_keeps_a_running_workspace(self):
        out, calls = self.run_sweep("test-bio-scientist-0a0b0c|1\\n")
        self.assertEqual(self.deletes(calls), [])
        self.assertIn("a workspace is running", out)

    def test_never_passes_another_name(self):
        # the list query already filters; a name off the pattern from a broken list is still dropped
        out, calls = self.run_sweep("admin|0\\nbio_user|0\\ntest-admin-XYZ123|0\\ntest-admin-a1b2c3|0\\n")
        [d] = self.deletes(calls)
        self.assertNotIn(" admin ", d + " ")
        self.assertNotIn("bio_user", d)
        self.assertNotIn("XYZ123", d)
        self.assertTrue(d.endswith(" test-admin-a1b2c3"), d)

    def test_nothing_left_no_restart(self):
        out, calls = self.run_sweep("")
        self.assertEqual(self.deletes(calls), [])
        self.assertEqual(self.restarts(calls), [])
        self.assertIn("no throwaway test user left", out)

    def test_no_running_hub(self):
        out, calls = self.run_sweep("test-admin-a92659|0\\n", pod="")
        self.assertFalse([c for c in calls if c.startswith("exec")])
        self.assertIn("no running hub", out)


class ListQuery(unittest.TestCase):
    """HUB_LIST_PY on a sqlite file with the hub's users and spawners columns."""

    def test_query(self):
        script = subprocess.run(["bash", "-c", f'source "{LIB}"; printf %s "$HUB_LIST_PY"'],
                                capture_output=True, text=True, check=True).stdout
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "jupyterhub.sqlite")
            db = sqlite3.connect(path)
            db.executescript("""
                CREATE TABLE users (id INTEGER PRIMARY KEY, name VARCHAR(255));
                CREATE TABLE spawners (id INTEGER PRIMARY KEY, user_id INTEGER, server_id INTEGER, name VARCHAR(255));
                INSERT INTO users VALUES (1, 'admin'), (2, 'bio_user'), (3, 'test-admin-a92659'),
                                         (4, 'test-control-scientist-0a0b0c'), (5, 'test-admin-NOTHEX');
                INSERT INTO spawners VALUES (1, 1, NULL, ''), (2, 2, 7, ''), (3, 3, NULL, ''), (4, 4, 9, '');
            """)
            db.commit()
            db.close()
            script = script.replace("/srv/jupyterhub/jupyterhub.sqlite", path)
            out = subprocess.run(["python3", "-c", script], capture_output=True, text=True, check=True).stdout
        self.assertEqual(out.split(), ["test-admin-a92659|0", "test-control-scientist-0a0b0c|1", "end|"])


class Wiring(unittest.TestCase):
    def test_both_live_tests_sweep_after_deleting_their_accounts(self):
        for name in ("iam-workbench.sh", "iam-signin.sh"):
            text = (REPO / "tests" / name).read_text()
            body = text[text.index("cleanup() {"):text.index("trap cleanup EXIT")]
            self.assertIn("source tests/lib-hub-cleanup.sh", text, name)
            self.assertIn("hub_sweep_test_users", body, name)
            self.assertLess(body.index("_kc_send DELETE"), body.index("hub_sweep_test_users"), name)
            self.assertLess(body.index("hub_sweep_test_users"), body.index("kc_admin_done"), name)


if __name__ == "__main__":
    unittest.main()
