#!/usr/bin/env python3
"""IAM Phase 2.5 (IAM_DB_SERVICE_ROLES), offline: no cluster, no database.

- infra/lib-db-roles.sh against a fake kubectl and a fake psql: db_client picks the
  service's own role only when the flag is on, its password is set, its Secret exists
  and the role may log in, and stays on postgres otherwise; db_clients_live reads each
  client's user (and says "?" when it cannot); everything survives set -euo pipefail.
- The wiring: every client renders its user through db_client, every template
  variable is in its render call, the manifests read the password from a Secret, the
  database deploy's guard and login list, the scheduler's and dbmgmt's fixes.

Run: python3 tests/test_db_roles.py
"""
import base64
import json
import os
import re
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*p):
    with open(os.path.join(ROOT, *p)) as f:
        return f.read()


# FAKE_* variables are the cluster: FAKE_LOGIN = roles that may log in, FAKE_SECRETS
# = Secrets that exist, FAKE_DEPLOY_<name> = a deployment's PG_USER (set = deployed),
# FAKE_FLOWS / FAKE_GRAFANA_B64 / FAKE_SERVERS = Node-RED's flows, Grafana's
# datasources.yaml (base64) and pgAdmin's servers.json.
FAKE = r"""
fake_kubectl() {
    [[ -n "${FAKE_FAIL:-}" ]] && return 1
    local a="$*" v
    case "$a" in
        "get pod -n "*"postgresql"*) echo rdbms-postgresql-0 ;;
        "get secret grafana-datasource -n "*"-o jsonpath"*) printf '%s' "${FAKE_GRAFANA_B64:-}" ;;
        "get secret grafana-datasource -n "*) [[ -n "${FAKE_GRAFANA_B64+x}" ]] ;;
        "get secret "*) [[ " ${FAKE_SECRETS:-} " == *" $3 "* ]] ;;
        "get configmap pgadmin-servers -n "*"-o jsonpath"*) printf '%s' "${FAKE_SERVERS:-}" ;;
        "get configmap pgadmin-servers -n "*) [[ -n "${FAKE_SERVERS+x}" ]] ;;
        "get deployment node-red -n "*) [[ -n "${FAKE_FLOWS+x}" ]] ;;
        "exec -n "*"deployment/node-red -- cat /data/flows.json") printf '%s' "${FAKE_FLOWS:-}" ;;
        "get deployment "*"-o jsonpath"*)
            v="FAKE_DEPLOY_$3"; [[ -n "${!v+x}" ]] || return 1; printf '%s\n' "${!v}" ;;
        "get deployment "*) v="FAKE_DEPLOY_$3"; [[ -n "${!v+x}" ]] ;;
        *) echo "fake_kubectl: unexpected: $a" >&2; return 1 ;;
    esac
}
KUBECTL=fake_kubectl
REPO_ROOT="$1"
_dba_psql() {   # db -tAq -c "SELECT rolcanlogin ... rolname = 'ROLE'"
    [[ -n "${FAKE_PSQL_FAIL:-}" ]] && return 1
    local q="${*: -1}" r
    r="$(sed -E "s/.*rolname = '([^']*)'.*/\1/" <<<"$q")"
    if [[ " ${FAKE_LOGIN:-} " == *" $r "* ]]; then echo t; else echo f; fi
}
source "$REPO_ROOT/infra/lib-db-roles.sh"
"""


def lib(script, strict=False, **env):
    pre = "set -euo pipefail\n" if strict else ""
    base = {k: v for k, v in os.environ.items() if not k.startswith(("FAKE_", "IAM_DB_", "SVC_", "POSTGRES_"))}
    p = subprocess.run(["bash", "-c", pre + FAKE + script, "t", ROOT], env=dict(base, **env),
                       capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr


SHOW = 'db_client medcea-x {role}; echo "$DBC_USER $DBC_SECRET $DBC_SECRET_KEY ${{#DBC_PASS}}"'
ON = {"IAM_DB_SERVICE_ROLES": "true", "POSTGRES_PASS": "pg-super", "SVC_SCHEDULER_DB_PASS": "s3cret-sched",
      "RR_ADMIN_LOGIN_DB_PASS": "s3cret-admin", "FAKE_LOGIN": "svc_scheduler rr_admin_login",
      "FAKE_SECRETS": "db-svc-scheduler db-rr-admin-login"}


class DbClient(unittest.TestCase):
    def test_flag_off_is_postgres_and_asks_nothing(self):
        rc, out, err = lib(SHOW.format(role="svc_scheduler"), FAKE_FAIL="1", POSTGRES_PASS="pg-super")
        self.assertEqual((rc, out), (0, "postgres rdbms-postgresql postgres-password 8"))
        self.assertEqual(err, "")

    def test_flag_on_role_ready_is_own_role(self):
        rc, out, _ = lib(SHOW.format(role="svc_scheduler"), **ON)
        self.assertEqual(out, "svc_scheduler db-svc-scheduler password 12")
        rc, out, _ = lib(SHOW.format(role="rr_admin_login"), **ON)
        self.assertEqual(out, "rr_admin_login db-rr-admin-login password 12")

    def test_flag_on_but_not_ready_stays_postgres_and_says_why(self):
        cases = {
            "cannot log in yet": dict(ON, FAKE_LOGIN=""),
            "does not exist yet": dict(ON, FAKE_SECRETS=""),
            "SVC_SCHEDULER_DB_PASS is empty": dict(ON, SVC_SCHEDULER_DB_PASS=""),
            "could not be asked": dict(ON, FAKE_PSQL_FAIL="1"),
        }
        for why, env in cases.items():
            with self.subTest(why):
                rc, out, err = lib(SHOW.format(role="svc_scheduler"), **env)
                self.assertEqual((rc, out), (0, "postgres rdbms-postgresql postgres-password 8"))
                self.assertIn("stays on postgres", err)
                self.assertIn(why, err)
                self.assertNotIn("s3cret", out + err)

    def test_survives_set_e(self):
        rc, out, _ = lib(SHOW.format(role="svc_scheduler") + "; echo end", strict=True, **dict(ON, FAKE_LOGIN=""))
        self.assertEqual(rc, 0)
        self.assertTrue(out.endswith("end"))

    def test_secret_names(self):
        rc, out, _ = lib('for r in svc_scheduler svc_dbexport iam_svc rr_admin_login authenticator; do db_role_secret $r; done')
        self.assertEqual(out.split(), ["db-svc-scheduler", "db-svc-dbexport", "db-iam-svc", "db-rr-admin-login", "db-authenticator"])


class ClientsLive(unittest.TestCase):
    FLOWS = json.dumps([{"id": "a", "type": "tab"}, {"id": "b", "type": "postgreSQLConfig", "user": "svc_ingest"}])
    GRAFANA = base64.b64encode(b"apiVersion: 1\ndatasources:\n- name: IoT Postgres\n  user: svc_grafana\n").decode()
    SERVERS = json.dumps({"Servers": {"1": {"Name": "IoT Postgres", "Username": "postgres"}}})

    def test_reads_every_client(self):
        rc, out, _ = lib("db_clients_live medcea-x", strict=True, FAKE_DEPLOY_scheduler="svc_scheduler",
                         FAKE_DEPLOY_monitor="postgres", FAKE_FLOWS=self.FLOWS, FAKE_GRAFANA_B64=self.GRAFANA,
                         FAKE_SERVERS=self.SERVERS)
        self.assertEqual(rc, 0)
        self.assertEqual(out.splitlines(), ["scheduler svc_scheduler", "monitor postgres", "node-red svc_ingest",
                                            "grafana svc_grafana", "pgadmin postgres"])

    def test_not_deployed_is_skipped_unreadable_is_question_mark(self):
        rc, out, _ = lib("db_clients_live medcea-x", strict=True, FAKE_DEPLOY_dbmgmt="", FAKE_FLOWS="not json",
                         FAKE_SERVERS="{}")
        self.assertEqual(rc, 0)
        self.assertEqual(out.splitlines(), ["dbmgmt ?", "node-red ?", "pgadmin ?"])

    def test_kubectl_down_prints_nothing(self):
        rc, out, _ = lib("db_clients_live medcea-x; echo end", strict=True, FAKE_FAIL="1")
        self.assertEqual((rc, out), (0, "end"))

    def test_roles(self):
        rc, out, _ = lib("for c in scheduler monitor dbmgmt node-red grafana pgadmin; do db_client_role $c; done")
        self.assertEqual(out.split(), ["svc_scheduler", "svc_monitor", "svc_dbexport", "svc_ingest",
                                       "svc_grafana", "rr_admin_login"])


# ── the wiring ────────────────────────────────────────────────────────────────────
CLIENTS = [  # deploy script, template, the role db_client is asked for
    ("apps/scheduler/deploy.sh", "apps/scheduler/k8s/scheduler.yaml", "svc_scheduler"),
    ("apps/monitor/deploy.sh", "apps/monitor/k8s/monitor.yaml", "svc_monitor"),
    ("apps/frontend/deploy.sh", "apps/frontend/k8s/dbmgmt.yaml", "svc_dbexport"),
    ("deploy-infra.sh", "k8s/grafana/datasource-secret.yaml", "svc_grafana"),
    ("deploy-infra.sh", "k8s/pgadmin/pgadmin.yaml", "rr_admin_login"),
]


class Wiring(unittest.TestCase):
    def test_every_client_asks_db_client(self):
        for script, tpl, role in CLIENTS + [("apps/node-red/deploy.sh", None, "svc_ingest")]:
            with self.subTest(script=script, role=role):
                sh = read(script)
                self.assertRegex(sh, r'db_client "\$NAMESPACE" %s\b' % role)
                self.assertIn("infra/lib-db-roles.sh", sh)

    def test_templates_rendered_with_every_variable(self):
        # an unlisted ${VAR} is left as literal text by render (CLAUDE.md, lib-render.sh)
        for script, tpl, _role in CLIENTS:
            with self.subTest(tpl=tpl):
                body = "\n".join(l for l in read(tpl).splitlines() if not l.lstrip().startswith("#"))
                used = set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*)\}", body))
                rel = tpl.split("/", 2)[2] if script.startswith("apps/") else tpl   # $SCRIPT_DIR is the app's dir
                call = re.search(r'render "\$(?:SCRIPT_DIR|REPO_ROOT)/%s"(.*?)[|>]' % re.escape(rel), read(script), re.S)
                self.assertIsNotNone(call, f"no render call for {tpl} in {script}")
                listed = set(call.group(1).replace("\\", " ").split())
                self.assertEqual(used - listed, set(), f"{tpl}: not in the render call")
                self.assertNotIn("POSTGRES_PASS", used)
                self.assertNotIn("POSTGRES_USER", used)

    def test_manifests_read_the_password_from_a_secret(self):
        for _s, tpl, _r in CLIENTS[:3]:
            with self.subTest(tpl=tpl):
                y = read(tpl)
                self.assertIn('value: "${PG_USER}"', y)
                self.assertRegex(y, r"- name: PG_PASSWORD\n\s+valueFrom:\n\s+secretKeyRef:\n\s+name: \$\{PG_SECRET\}\n\s+key: \$\{PG_SECRET_KEY\}")

    def test_restarts_on_a_new_login(self):
        self.assertIn('medcea/db-user: "${PGA_DB_USER}"', read("k8s/pgadmin/pgadmin.yaml"))
        infra = read("deploy-infra.sh")
        self.assertIn('"$_GF_PREV_USER" != "$DS_USER"', infra)
        self.assertLess(infra.index("_GF_PREV_USER=\"$(db_clients_live"), infra.index("db_client \"$NAMESPACE\" svc_grafana"))

    def test_database_deploy(self):
        db = read("apps/database/deploy.sh")
        guard = db[db.index('if [[ "$IAM_DB_ROLES" == "true" ]]; then'):db.index("# ── Passwords")]
        self.assertIn('"${IAM_DB_SERVICE_ROLES:-false}" == "true" ]] || refuse+=', guard)
        self.assertIn("db_clients_live", guard)
        # never `while read … < <(db_clients_live …)`: kubectl exec -i in the body eats the list
        self.assertNotRegex(db, r"done < <\(db_clients_live")
        logins = db[db.index("# ── Service logins"):db.index("# ── Apply")]
        self.assertIn("db-roles --logins", logins)
        self.assertIn("db_role_can_login", logins)
        self.assertIn('db_role_secret "$_role"', db)
        self.assertNotIn("_secret_for", db)
        lib_apply = read("apps/database/lib-db-apply.sh")
        self.assertIn('--service-logins "$DBA_SERVICE_LOGINS"', lib_apply)
        self.assertIn('[[ "$grants_mode" == additive', lib_apply)

    def test_flag_documented(self):
        self.assertIn('IAM_DB_SERVICE_ROLES="false"', read("config.env.example"))
        conf = read("health-checks.conf")
        self.assertRegex(conf, r"\|\s*dbclients\s*\|")

    def test_scheduler_takes_the_function_path_off_superuser(self):
        api = read("apps/scheduler/scheduler-api.py")
        self.assertIn("return _enforcing(cur) or not _superuser(cur)", api)
        self.assertNotIn("DELETE FROM medcea.algorithm_state", api)   # IAM 2.6: retired, never deleted
        for anchor in ("a completed run is not reopened", "SELECT medcea.propose_setting"):
            i = api.index(anchor)
            self.assertIn("_functions_only(cur)", api[api.rindex("\n    with tx()", 0, i) if "propose" in anchor else i - 400:i],
                          anchor)

    def test_dbmgmt(self):
        api = read("apps/frontend/html/dbmgmt-api.py")
        self.assertNotIn("information_schema.sequences", api)
        self.assertIn("pg_catalog.pg_sequence", api)
        self.assertIn("c.relkind = 'S'", api)
        # IAM 2.6: the person's X groups narrow the listing, and the export is logged
        # (set_actor -> reads -> log_export) before it commits
        exp = api[api.index("def run_export"):api.index("# ── Access policy check")]
        self.assertLess(exp.index("exportable_objects("), exp.index("get_data_inserts("))
        self.assertIn("not in allowed", exp)
        self.assertLess(exp.index("SELECT medcea_auth.set_actor"), exp.index("SELECT iam_policy.log_export"))
        self.assertLess(exp.index("SELECT iam_policy.log_export"), exp.index("con.commit()"))


if __name__ == "__main__":
    unittest.main()
