#!/usr/bin/env python3
"""IAM Phase 4, slice 4.2a (design §14.4.8, §14.4.2 item 5): apps/database/lib-db-apply.sh
after the extraction of dba_compiled_functions, dba_mode_live, dba_service_logins and
dba_policy_bundle, and dba_record_event's routing to iam_policy._record.

Offline: every psql call goes to a fake _dba_psql that records its arguments and stdin
and answers the few questions db_apply asks; nothing reaches a cluster. The grants are
compiled for real (`cli.py --defaults`, namespace medcea-iamtest), the same compiler on
both sides of the byte comparison, so only the library differs.
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(REPO, "apps", "database", "lib-db-apply.sh")
PRE_42A = "08fab15"   # the library before the extraction

# the isolation assert dba_policy_bundle adds right after the actor (F-24): the one
# difference of db_apply's psql stdin before and after the extraction
ISOLATION = """DO $iso$
BEGIN
    IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'the policy bundle needs READ COMMITTED (is %)', pg_catalog.current_setting('transaction_isolation');
    END IF;
END $iso$;
"""

HARNESS = r'''
set -uo pipefail
LIB="$1"; OUT="$2"; shift 2
export PROJECT_NAME=medcea CEA_DB=medcea_db KUBECTL=false
source "$LIB"
_dba_psql() {
    local n f a
    n=$(( $(cat "$OUT/n" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$OUT/n"
    f="$OUT/$(printf %03d "$n")"
    printf '%s\n' "$@" > "$f.args"
    cat > "$f.in"
    case "$*" in
        *"FROM pg_database"*) echo 1 ;;
        *deploy_nonce=*) for a in "$@"; do [[ "$a" == deploy_nonce=* ]] && echo "${a#deploy_nonce=}" > "$OUT/nonce"; done ;;
        *last_nonce*) cat "$OUT/nonce" ;;
        *"to_regnamespace('iam')"*) echo "${FAKE_IAM:-f|f|f|f}" ;;
        *"WHERE s.key = 'iam_db_roles'"*) echo "${FAKE_LIVE:-false}" ;;
    esac
    [[ -n "${FAKE_FAIL:-}" && "$(cat "$f.in")" == *"$FAKE_FAIL"* ]] && return 3
    return 0
}
_dba_scram() { case "$1" in mqtt_auth|svc_monitor) echo "SCRAM-$1" ;; esac; return 0; }
db_clients_live() { echo "monitor svc_monitor"; echo "scheduler postgres"; }
db_client_role() { echo "svc_$1"; }
db_role_can_login() { return 1; }
"$@"
'''


def run(lib, *cmd, env=None):
    out = tempfile.mkdtemp(prefix="dba-")
    e = {k: v for k, v in os.environ.items() if not k.startswith(("MEDCEA_POLICY", "DBA_", "IAM_"))}
    e["REPO_ROOT"] = REPO
    e.update(env or {})
    p = subprocess.run(["bash", "-c", HARNESS, "harness", lib, out, *cmd], env=e, capture_output=True, stdin=subprocess.DEVNULL,
                       text=True, timeout=300)
    calls = []
    for f in sorted(os.listdir(out)):
        if f.endswith(".args"):
            base = os.path.join(out, f[:-5])
            with open(base + ".args") as a, open(base + ".in") as i:
                calls.append((a.read().split("\n")[:-1], i.read()))
    shutil.rmtree(out)
    return p, calls


def pre_42a_lib():
    try:
        text = subprocess.run(["git", "-C", REPO, "show", f"{PRE_42A}:apps/database/lib-db-apply.sh"],
                              capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    d = tempfile.mkdtemp(prefix="dba-old-")
    path = os.path.join(d, "lib-db-apply.sh")
    with open(path, "w") as f:
        f.write(text)
    return path


def bundle(calls):
    """The one psql call whose stdin carries the mode bundle."""
    found = [c for c in calls if "_set_internal_actor('system:" in c[1] and "SET log_statement = 'none';" in c[1]
             and "--part" not in c[1]]
    return found[-1]


class DbApplyExtraction(unittest.TestCase):
    """db_apply's psql stdin is byte-identical before and after the extraction, but for the
    READ COMMITTED assert (design §14.4.8: db_apply calls dba_policy_bundle with /dev/null)."""

    @classmethod
    def setUpClass(cls):
        cls.old = pre_42a_lib()

    def compare(self, mode, env):
        if not self.old:
            self.skipTest(f"git show {PRE_42A} unavailable")
        p_old, old = run(self.old, "db_apply", "medcea-iamtest", "pod", mode, env=env)
        p_new, new = run(LIB, "db_apply", "medcea-iamtest", "pod", mode, env=env)
        self.assertEqual(p_old.returncode, 0, p_old.stderr[-2000:])
        self.assertEqual(p_new.returncode, 0, p_new.stderr[-2000:])
        self.assertEqual(len(old), len(new))
        nonce = re.compile(r"deploy_nonce=[0-9a-f]+")
        for (a_old, i_old), (a_new, i_new) in zip(old, new):
            self.assertEqual([nonce.sub("deploy_nonce=N", x) for x in a_old],
                             [nonce.sub("deploy_nonce=N", x) for x in a_new])
            if ISOLATION in i_new and ISOLATION not in i_old:
                self.assertEqual(i_new.count(ISOLATION), 1)
                actor = "SELECT medcea_auth._set_internal_actor('system:deploy');\n"
                self.assertIn(actor + ISOLATION, i_new)
                i_new = i_new.replace(ISOLATION, "", 1)
            self.assertEqual(i_old, i_new)
        b = bundle(new)[1]
        self.assertIn(ISOLATION, b)
        return new

    def test_false_without_iam(self):
        calls = self.compare("false", {"DBA_SERVICE_LOGINS": "svc_monitor,iam_svc"})
        b = bundle(calls)[1]
        self.assertIn("\\set pw_svc_monitor 'SCRAM-svc_monitor'", b)

    def test_true_with_iam(self):
        self.compare("true", {"FAKE_IAM": "t|t|t|t"})

    def test_false_no_service_logins(self):
        # DBA_SERVICE_LOGINS unset: db_apply keeps today's "none", it never asks dba_service_logins
        calls = self.compare("false", {})
        self.assertFalse(any("db_clients_live" in c[1] for c in calls))


class PolicyBundle(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="dba-sql-")
        self.pre = os.path.join(self.d, "pre.sql")
        self.post = os.path.join(self.d, "post.sql")
        with open(self.pre, "w") as f:
            f.write("SELECT 'PRE-MARK';\n")
        with open(self.post, "w") as f:
            f.write("SELECT 'POST-MARK';\n")

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_auto_refuses_a_mismatch(self):
        p, calls = run(LIB, "dba_policy_bundle", "medcea", "pod", "auto", self.pre, self.post,
                       env={"FAKE_LIVE": "true", "IAM_DB_ROLES": "false"})
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("config.env says IAM_DB_ROLES=false, the database records true: run ./apps/database/deploy.sh first",
                      p.stderr)
        self.assertEqual(len(calls), 1)                  # only the mode was read
        self.assertNotIn("PRE-MARK", "".join(c[1] for c in calls))

    def test_auto_unset_is_3(self):
        p, calls = run(LIB, "dba_policy_bundle", "medcea", "pod", "auto", self.pre, self.post,
                       env={"FAKE_LIVE": "unset"})
        self.assertEqual(p.returncode, 3)
        self.assertIn("migration 008b not applied", p.stderr)

    def test_mode_live(self):
        for live, rc in (("true", 0), ("false", 0), ("unset", 3), ("maybe", 1)):
            p, _ = run(LIB, "dba_mode_live", "medcea", "pod", "medcea_db", env={"FAKE_LIVE": live})
            self.assertEqual(p.returncode, rc, live)
            if rc == 0:
                self.assertEqual(p.stdout.strip(), live)

    def test_order_actor_and_functions(self):
        p, calls = run(LIB, "dba_policy_bundle", "medcea-iamtest", "pod", "auto", self.pre, self.post,
                       "--with-functions",
                       env={"FAKE_LIVE": "false", "IAM_DB_ROLES": "false", "DBA_ACTOR": "system:apply",
                            "DBA_SERVICE_LOGINS": ""})
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        b = bundle(calls)
        self.assertIn("-1", b[0])
        sql = b[1]
        with open(os.path.join(REPO, "apps/database/medcea_db_migrations_down_008b.sql")) as f:
            down = f.read()
        marks = ["SET log_statement = 'none';", "\\set root 'medcea'", "\\set mode 'false'",
                 "SELECT medcea_auth._set_internal_actor('system:apply');", ISOLATION, "PRE-MARK",
                 "FUNCTION medcea_auth.pre_request()", down[:200], "INSERT INTO medcea.platform_setting (key, value) VALUES ('mqtt_topic_root'",
                 "POST-MARK"]
        pos = [sql.index(m) for m in marks]
        self.assertEqual(pos, sorted(pos))
        # the asserts come last: after POST
        self.assertGreater(sql.rindex("ASSERT") if "ASSERT" in sql else sql.rindex("RAISE"), sql.index("POST-MARK"))
        self.assertNotIn("system:deploy", sql[:sql.index("PRE-MARK")])

    def test_rollback_message(self):
        p, _ = run(LIB, "dba_policy_bundle", "medcea-iamtest", "pod", "false", self.pre, self.post,
                   env={"FAKE_FAIL": "PRE-MARK", "DBA_SERVICE_LOGINS": ""})
        self.assertEqual(p.returncode, 1)
        self.assertIn("policy bundle was rolled back (nothing in it was applied)", p.stderr)

    def test_usage(self):
        p, _ = run(LIB, "dba_policy_bundle", "medcea", "pod", "maybe", self.pre, self.post)
        self.assertEqual(p.returncode, 2)
        p, _ = run(LIB, "dba_policy_bundle", "medcea", "pod", "false", self.pre, self.post,
                   env={"DBA_ACTOR": "someone"})
        self.assertEqual(p.returncode, 2)

    def test_service_logins(self):
        # IAM_DB_SERVICE_ROLES=true: presence of the config.env variable only
        p, _ = run(LIB, "dba_service_logins", "medcea",
                   env={"IAM_DB_SERVICE_ROLES": "true", "SVC_MONITOR_DB_PASS": "x", "IAM_SVC_DB_PASS": "y",
                        "AUTHENTICATOR_DB_PASS": "z"})
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), "svc_monitor,iam_svc")
        # false: the roles a live client still uses
        p, _ = run(LIB, "dba_service_logins", "medcea", env={"IAM_DB_SERVICE_ROLES": "false"})
        self.assertEqual(p.stdout.strip(), "svc_monitor")
        self.assertIn("monitor still logs in as svc_monitor", p.stderr)
        # IAM_DB_ROLES=true: nothing
        p, _ = run(LIB, "dba_service_logins", "medcea", env={"IAM_DB_ROLES": "true", "IAM_DB_SERVICE_ROLES": "true",
                                                             "SVC_MONITOR_DB_PASS": "x"})
        self.assertEqual(p.stdout.strip(), "")


def simulate_record_event(sql, ev, state):
    """psql's \\gset/\\if flow of dba_record_event for one catalog state: the branch taken."""
    first = {
        "actor_ok": state != "none",
        "policy_event": ev in ("break_glass_seen", "break_glass_ended", "account_seeded"),
        "seed_event": ev == "account_seeded",
        "system_as": state == "42a",
        "record_41": state in ("41", "42a"),
        "writer": state != "none",
    }
    # the second SELECT's expressions, evaluated over the first's values
    m = re.search(r"\\gset\nSELECT (.*?) \\gset", sql, flags=re.S)
    second = {}
    for expr in re.split(r",\s*\n\s*", m.group(1)):
        e, name = expr.rsplit(" AS ", 1)
        py = re.sub(r":'(\w+)'::boolean", lambda x: repr(first[x.group(1)]), e)
        py = py.replace("AND", "and").replace("NOT", "not")
        second[name.strip()] = eval(py)
    vals = {**first, **second}
    branches = re.split(r"(?m)^\\(if|elif|else|endif)\b ?(:\w+)?\n", sql[m.end():])
    # branches: ['', 'if', ':x', body, 'elif', ':y', body, ..., 'else', None, body, 'endif', None, rest]
    i = 1
    while i < len(branches):
        kw, var, body = branches[i], branches[i + 1], branches[i + 2]
        if kw == "endif":
            return ""
        if kw == "else" or vals[var[1:]]:
            return body
        i += 3
    return ""


class RecordEventRouting(unittest.TestCase):
    """dba_record_event (critique ops-3): _record once _system_as exists, skip-4.1 with the
    4.1 _record alone, append_history (break_glass_seen) or a queue (account_seeded) before 008c."""

    @classmethod
    def setUpClass(cls):
        p, calls = run(LIB, "dba_record_event", "medcea", "pod", "medcea_db", "break_glass_seen",
                       '{"identity": "node-red NR_ADMIN_AUTH=off"}', "Node-RED ran without its sign-in")
        assert p.returncode == 0, p.stderr
        cls.args, cls.sql = calls[0]

    def test_variables(self):
        self.assertIn("ev=break_glass_seen", self.args)
        self.assertIn("-1", self.args)
        self.assertIn("ON_ERROR_STOP=1", self.args)

    def test_routes(self):
        cases = {
            ("break_glass_seen", "42a"): "iam_policy._record(",
            ("break_glass_ended", "42a"): "iam_policy._record(",
            ("account_seeded", "42a"): "iam_policy._record(",
            ("break_glass_seen", "41"): "\\echo skip-4.1",
            ("account_seeded", "41"): "\\echo skip-4.1",
            ("break_glass_seen", "008b"): "iam_policy.append_history(",
            ("account_seeded", "008b"): "\\echo skip\n",
            ("enforcement_enabled", "42a"): "iam_policy.append_history(",
            ("break_glass_seen", "none"): "\\echo skip\n",
        }
        for (ev, state), want in cases.items():
            body = simulate_record_event(self.sql, ev, state)
            self.assertIn(want, body, (ev, state))
            if "_record(" in want or "append_history(" in want:
                self.assertIn("_set_internal_actor('system:deploy')", body)
            if want == "\\echo skip\n":
                self.assertNotIn("skip-4.1", body)

    def test_reason_into_payload(self):
        body = simulate_record_event(self.sql, "break_glass_seen", "42a")
        self.assertIn("p ? 'reason'", body)
        self.assertIn("jsonb_build_object('reason', :'why')", body)


if __name__ == "__main__":
    unittest.main(verbosity=1)
