#!/usr/bin/env python3
"""tests/test_research_export.py — the research export (apps/research-export/, research sandbox
Phase 2a), offline: no cluster, no database.

- The CronJob as deploy.sh renders it: every ${VAR} in the template is in the render list (and the
  header's "Render list:"); label app: research-export on the CronJob, its job template and its pod;
  daily 03:00 UTC (after the backup's 02:30), Forbid, no retry, a deadline; no service account token,
  no service links, non-root, read-only root, every capability dropped, an emptyDir /tmp, resources;
  both passwords only through secretKeyRef (a sentinel in the environment never reaches the manifest),
  no host path, no other Secret.
- export-job.sh under dash with a fake psql: the research side's latest cut first, then the
  operational cut and contract version, then every medcea.research_*() function \\copy'd TO a file in
  one REPEATABLE READ READ ONLY transaction, then ONE research psql -1 run that \\copy-loads every
  lake.stage_* and calls lake.close_snapshot(cut, previous, contract) last; the summary line; the
  refusal when the cut is not after the latest one (nothing loaded); a failed load; an answer that is
  not a timestamp; each password only in its own psql's environment, never in an argument, the
  output or a file; the work folder removed. Both sides name the same columns, and they are the ones
  migration 013's functions and the research DDL's stage tables declare, when those are in the tree.
- deploy.sh against a fake microk8s, a stub cli.py and a stub policy source: an unknown option exits
  2 before the log; each skip (switch off, no research zone, no applied version, no research
  database, IAM_DB_SERVICE_ROLES off) is one line, exit 0, ends with policy_source_finish and removes
  a CronJob already there; a broken policy, a missing writer Secret and a postgres fallback die; the
  full path applies the ConfigMap and the CronJob with research-postgresql's image and
  svc_research_export, and no password anywhere in an argument or the applied manifests.
- uninstall.sh removes the CronJob, the Jobs by label and the ConfigMap, nothing else.
- lib-research-export.sh rsexport_age_status: SKIP, OK, WARN at 26 h, FAIL at 72 h.

Run: python3 tests/test_research_export.py
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "apps", "research-export")
JOB = os.path.join(APP, "export-job.sh")
SH = shutil.which("dash") or "/bin/sh"
OP_SENTINEL = "s3ntinel-OP-pass"
RS_SENTINEL = "s3ntinel-RS-pass"
PG_SENTINEL = "s3ntinel-POSTGRES-pass"

# INTERFACES.md (Phase 2a): each function's columns = its stage table's columns
COLUMNS = {
    "measurements": ["ingested_at", "measured_at", "unit_code", "zone_code", "tag", "sensor", "value", "uom"],
    "units": ["unit_code", "recipe_type", "area", "height", "is_active"],
    "zones": ["unit_code", "zone_code", "is_active"],
    "recipes": ["recipe_id", "recipe_type", "status"],
    "recipe_lines": ["recipe_id", "seq", "cycle_number", "light_type", "light_on_minutes", "light_off_minutes",
                     "setpoints"],
    "runs": ["run_id", "recipe_id", "unit_code", "started_at", "ended_at", "status"],
    "cycles": ["run_id", "seq", "cycle_num", "started_at", "ended_at", "status", "algorithm_code",
               "algorithm_params", "control_loops"],
    "control_loops": ["unit_code", "zone_code", "loop_code", "input", "output"],
    "param_sets": ["params_id", "algorithm_code", "unit_code", "params"],
    "catalogue": ["kind", "code", "doc"],
}


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def write(path, text, mode=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)
    if mode is not None:
        os.chmod(path, mode)


def code(text):
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


# ── the CronJob ─────────────────────────────────────────────────────────────────
class CronJobRender(unittest.TestCase):
    VALUES = {"NAMESPACE": "medcea", "RESEARCH_NAMESPACE": "medcea-research",
              "EXPORT_IMAGE": "docker.io/bitnami/postgresql:18.0.0", "POSTGRES_DB": "medcea_db",
              "OP_DB_USER": "svc_research_export", "OP_SECRET": "db-svc-research-export", "OP_SECRET_KEY": "password"}

    @classmethod
    def setUpClass(cls):
        deploy = read("apps/research-export/deploy.sh")
        m = re.search(r'render "\$SCRIPT_DIR/k8s/cronjob.yaml" ((?:[A-Z_]+ |\\\n\s*)+)\\?\n?\s*\|', deploy)
        cls.render_list = re.findall(r"[A-Z_]+", m.group(1))
        env = dict(os.environ, POSTGRES_PASS=PG_SENTINEL, SVC_RESEARCH_EXPORT_DB_PASS=OP_SENTINEL,
                   RS_EXPORT_WRITER_DB_PASS=RS_SENTINEL, **cls.VALUES)
        cls.text = subprocess.run(
            ["bash", "-c", 'source "$1/infra/lib-render.sh"; shift; render "$@"', "-", ROOT,
             os.path.join(APP, "k8s", "cronjob.yaml"), *cls.render_list],
            capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env, check=True).stdout
        cls.cj = yaml.safe_load(cls.text)
        cls.job = cls.cj["spec"]["jobTemplate"]
        cls.pod = cls.job["spec"]["template"]["spec"]
        cls.c = cls.pod["containers"][0]
        cls.env = {e["name"]: e for e in cls.c["env"]}

    def test_render_list_covers_the_template(self):
        tpl = read("apps/research-export/k8s/cronjob.yaml")
        used = set(re.findall(r"\$\{([A-Z_]+)\}", code(tpl)))
        self.assertEqual(used, set(self.render_list))
        header = re.search(r"# Render list: ([A-Z_ ]+)\n", tpl).group(1).split()
        self.assertEqual(header, self.render_list)
        self.assertNotRegex(self.text, r"\$\{[A-Z_]+\}")

    def test_labels(self):
        self.assertEqual(self.cj["metadata"]["name"], "research-export")
        self.assertEqual(self.cj["metadata"]["namespace"], "medcea")
        for meta in (self.cj["metadata"], self.job["metadata"], self.job["spec"]["template"]["metadata"]):
            self.assertEqual(meta["labels"], {"app": "research-export"})

    def test_schedule(self):
        s = self.cj["spec"]
        self.assertEqual(s["schedule"], "0 3 * * *")
        self.assertEqual(s["timeZone"], "Etc/UTC")
        self.assertEqual(s["concurrencyPolicy"], "Forbid")
        self.assertIs(s["suspend"], False)
        self.assertEqual(self.job["spec"]["backoffLimit"], 0)
        self.assertGreater(self.job["spec"]["activeDeadlineSeconds"], 0)
        self.assertEqual(self.pod["restartPolicy"], "Never")
        # after the nightly backup (02:30 UTC)
        self.assertEqual(yaml.safe_load(read("apps/backup/k8s/backup-cronjob.yaml").replace("${", "_{"))
                         ["spec"]["schedule"], "30 2 * * *")

    def test_hardening(self):
        self.assertIs(self.pod["automountServiceAccountToken"], False)
        self.assertIs(self.pod["enableServiceLinks"], False)
        self.assertIs(self.pod["securityContext"]["runAsNonRoot"], True)
        sc = self.c["securityContext"]
        self.assertIs(sc["allowPrivilegeEscalation"], False)
        self.assertIs(sc["readOnlyRootFilesystem"], True)
        self.assertEqual(sc["capabilities"], {"drop": ["ALL"]})
        self.assertNotIn("privileged", sc)
        self.assertIn("requests", self.c["resources"])
        self.assertIn("memory", self.c["resources"]["limits"])
        vols = {v["name"]: v for v in self.pod["volumes"]}
        mounts = {m["mountPath"]: m for m in self.c["volumeMounts"]}
        self.assertIn("emptyDir", vols[mounts["/tmp"]["name"]])
        self.assertTrue(mounts["/scripts"]["readOnly"])
        self.assertEqual(vols["script"]["configMap"]["name"], "research-export-script")
        self.assertFalse([v for v in self.pod["volumes"] if "hostPath" in v or "secret" in v])
        self.assertEqual(self.c["image"], self.VALUES["EXPORT_IMAGE"])
        self.assertEqual(self.c["command"], ["/bin/sh", "/scripts/export-job.sh"])

    def test_passwords_only_by_secret_ref(self):
        for s in (PG_SENTINEL, OP_SENTINEL, RS_SENTINEL):
            self.assertNotIn(s, self.text)
        self.assertEqual(self.env["OP_PASSWORD"]["valueFrom"]["secretKeyRef"],
                         {"name": "db-svc-research-export", "key": "password"})
        self.assertEqual(self.env["RS_PASSWORD"]["valueFrom"]["secretKeyRef"],
                         {"name": "research-export-writer", "key": "password"})
        refs = [e for e in self.c["env"] if "valueFrom" in e]
        self.assertEqual(sorted(e["name"] for e in refs), ["OP_PASSWORD", "RS_PASSWORD"])
        for e in self.c["env"]:
            if "value" in e:
                self.assertNotRegex(e["name"], r"(?i)pass|secret|token", e["name"])
        self.assertNotIn("envFrom", self.c)
        self.assertNotRegex(" ".join(self.c["command"]), r"(?i)pass")

    def test_connection_values(self):
        v = {n: e.get("value") for n, e in self.env.items()}
        self.assertEqual(v["PGHOST_OP"], "rdbms-postgresql")
        self.assertEqual(v["OP_DB"], "medcea_db")
        self.assertEqual(v["OP_USER"], "svc_research_export")
        self.assertEqual(v["RS_HOST"], "research-postgresql.medcea-research")
        self.assertEqual(v["RS_DB"], "medcea_research")
        self.assertEqual(v["RS_USER"], "rs_export_writer")


# ── export-job.sh ───────────────────────────────────────────────────────────────
FAKE_PSQL = r'''#!/bin/sh
# fake psql: the operational server is rdbms-postgresql, the research one research-postgresql.*
host=""; single=no; file=""
for a in "$@"; do
    case "$a" in --host=*) host="${a#--host=}" ;; -1) single=yes ;; esac
done
prev=""; for a in "$@"; do [ "$prev" = "-f" ] && file="$a"; prev="$a"; done
n=$(cat "$FAKE_DIR/n" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$FAKE_DIR/n"
printf '%s\n' "$*" > "$FAKE_DIR/argv.$n"
printf '%s\n' "${PGPASSWORD:-}" > "$FAKE_DIR/pw.$n"
if [ -n "$file" ]; then cp "$file" "$FAKE_DIR/sql.$n"; else cat > "$FAKE_DIR/sql.$n"; fi
case "$host" in
  research-postgresql.*)
    if [ "$single" = yes ]; then
        echo "research-load" > "$FAKE_DIR/kind.$n"
        # the stage files must exist when the load runs
        for f in $(sed -n "s/.* FROM '\(.*\)'$/\1/p" "$FAKE_DIR/sql.$n"); do
            [ -f "$f" ] || { echo "psql: $f: No such file" >&2; exit 1; }
        done
        [ -n "${FAKE_LOAD_FAIL:-}" ] && { echo "ERROR:  close_snapshot: previous cut differs" >&2; exit 3; }
        echo "snapshot=${FAKE_SNAP:-7}"
    else
        echo "research-cut" > "$FAKE_DIR/kind.$n"
        echo "${FAKE_PREV:-none}"
    fi ;;
  rdbms-postgresql)
    if [ -n "$file" ]; then
        echo "op-dump" > "$FAKE_DIR/kind.$n"
        [ -n "${FAKE_DUMP_FAIL:-}" ] && { echo "ERROR: permission denied for function research_runs" >&2; exit 3; }
        sed -n "s/.* TO '\(.*\)'$/\1/p" "$FAKE_DIR/sql.$n" | while read -r f; do
            case "$f" in
              */measurements.copy) i=0; while [ $i -lt "${FAKE_ROWS:-3}" ]; do echo "row $i"; i=$((i+1)); done > "$f" ;;
              *) echo "x" > "$f" ;;
            esac
        done
    else
        echo "op-cut" > "$FAKE_DIR/kind.$n"
        echo "${FAKE_CUT:-2026-11-18 02:58:00.123456+00}|${FAKE_CONTRACT:-1}|${FAKE_VERDICT:-ok}"
    fi ;;
  *) echo "fake psql: unknown host $host" >&2; exit 2 ;;
esac
'''


class ExportJob(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bin = os.path.join(self.tmp, "bin")
        self.fake = os.path.join(self.tmp, "fake")
        self.work = os.path.join(self.tmp, "work")
        os.makedirs(self.fake)
        os.makedirs(self.work)
        write(os.path.join(self.bin, "psql"), FAKE_PSQL, 0o755)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_job(self, **extra):
        env = {"PATH": self.bin + ":/usr/bin:/bin", "FAKE_DIR": self.fake, "TMPDIR": self.work,
               "PGHOST_OP": "rdbms-postgresql", "OP_PORT": "5432", "OP_DB": "medcea_db",
               "OP_USER": "svc_research_export", "OP_PASSWORD": OP_SENTINEL,
               "RS_HOST": "research-postgresql.medcea-research", "RS_PORT": "5432", "RS_DB": "medcea_research",
               "RS_USER": "rs_export_writer", "RS_PASSWORD": RS_SENTINEL}
        env.update(extra)
        return subprocess.run([SH, JOB], capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env, cwd=self.tmp)

    def calls(self):
        out = []
        n = 1
        while os.path.exists(os.path.join(self.fake, f"argv.{n}")):
            def r(k):
                with open(os.path.join(self.fake, f"{k}.{n}")) as fh:
                    return fh.read()
            out.append({"argv": r("argv").strip(), "pw": r("pw").strip(), "sql": r("sql"), "kind": r("kind").strip()})
            n += 1
        return out

    def test_a_first_snapshot(self):
        p = self.run_job()
        self.assertEqual(p.returncode, 0, p.stderr)
        c = self.calls()
        self.assertEqual([x["kind"] for x in c], ["research-cut", "op-cut", "op-dump", "research-load"])
        self.assertIn("lake.latest_cut()", c[0]["sql"])
        self.assertIn("now() - interval '2 minutes'", c[1]["sql"])
        self.assertIn("medcea.research_contract_version()", c[1]["sql"])
        self.assertTrue(p.stdout.rstrip().endswith(
            "research-export: snapshot 7 cut 2026-11-18 02:58:00.123456+00 measurements 3"), p.stdout)
        self.assertEqual(p.stdout.count("research-export: snapshot "), 1)
        # no snapshot yet: from the beginning (NULL) up to the cut
        cut = "'2026-11-18 02:58:00.123456+00'::timestamptz"
        self.assertIn(f"medcea.research_measurements(NULL::timestamptz, {cut})", c[2]["sql"])
        self.assertIn(f"lake.close_snapshot({cut}, NULL::timestamptz, 1)", c[3]["sql"])
        # the work folder is gone
        self.assertEqual(os.listdir(self.work), [])

    def test_the_dump_is_one_read_only_snapshot_of_every_function(self):
        self.assertEqual(self.run_job(FAKE_PREV="2026-11-17 02:58:00.5+00").returncode, 0)
        dump = self.calls()[2]
        lines = [l for l in dump["sql"].splitlines() if l.strip()]
        self.assertEqual(lines[0], "SET TIME ZONE 'UTC';")
        self.assertEqual(lines[1], "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;")
        self.assertEqual(lines[-1], "COMMIT;")
        copies = lines[2:-1]
        self.assertEqual(len(copies), len(COLUMNS))
        seen = {}
        for l in copies:
            m = re.fullmatch(r"\\copy \(SELECT (.+) FROM medcea\.research_([a-z_]+)\((.*)\)\) TO '(/[^']+)'", l)
            self.assertIsNotNone(m, l)
            seen[m.group(2)] = (m.group(1).split(", "), m.group(3), m.group(4))
        self.assertEqual(set(seen), set(COLUMNS))
        for t, (cols, args, path) in seen.items():
            self.assertEqual(cols, COLUMNS[t], t)
            self.assertTrue(path.startswith(self.work + "/research-export."), path)
            self.assertTrue(path.endswith(f"/{t}.copy"), path)
            self.assertEqual(args, "'2026-11-17 02:58:00.5+00'::timestamptz, '2026-11-18 02:58:00.123456+00'::timestamptz"
                             if t == "measurements" else "", t)
        self.assertIn("--host=rdbms-postgresql", dump["argv"])
        self.assertIn("--username=svc_research_export", dump["argv"])
        self.assertIn("--dbname=medcea_db", dump["argv"])

    def test_one_research_transaction_loads_every_stage_then_closes(self):
        self.assertEqual(self.run_job(FAKE_PREV="2026-11-17 02:58:00.5+00", FAKE_SNAP="12").returncode, 0)
        load = self.calls()[3]
        self.assertRegex(load["argv"], r"(^| )-1( |$)")
        self.assertIn("-v ON_ERROR_STOP=1", load["argv"])
        self.assertIn("--host=research-postgresql.medcea-research", load["argv"])
        self.assertIn("--username=rs_export_writer", load["argv"])
        self.assertIn("--dbname=medcea_research", load["argv"])
        lines = [l for l in load["sql"].splitlines() if l.strip()]
        self.assertEqual(lines[0], "SET TIME ZONE 'UTC';")
        self.assertNotIn("BEGIN", load["sql"])      # psql -1 is the transaction
        self.assertNotIn("COMMIT", load["sql"])
        self.assertEqual(lines[-1], "SELECT 'snapshot=' || lake.close_snapshot("
                         "'2026-11-18 02:58:00.123456+00'::timestamptz, '2026-11-17 02:58:00.5+00'::timestamptz, 1);")
        stages = lines[1:-1]
        self.assertEqual(len(stages), len(COLUMNS))
        for l in stages:
            m = re.fullmatch(r"\\copy lake\.stage_([a-z_]+) \((.+)\) FROM '(/[^']+)'", l)
            self.assertIsNotNone(m, l)
            self.assertEqual(m.group(2).split(", "), COLUMNS[m.group(1)], l)
            self.assertTrue(m.group(3).endswith(f"/{m.group(1)}.copy"))
        # the research side writes nothing but staging and close_snapshot
        self.assertNotRegex(load["sql"], r"(?i)\b(insert|update|delete|truncate)\b")

    def test_passwords_only_in_their_own_psql_environment(self):
        p = self.run_job()
        self.assertEqual(p.returncode, 0, p.stderr)
        for x in self.calls():
            want = RS_SENTINEL if x["kind"].startswith("research") else OP_SENTINEL
            self.assertEqual(x["pw"], want, x["kind"])
            for s in (OP_SENTINEL, RS_SENTINEL):
                self.assertNotIn(s, x["argv"] + x["sql"], x["kind"])
            self.assertIn("--no-password", x["argv"])
        self.assertNotIn(OP_SENTINEL, p.stdout + p.stderr)
        self.assertNotIn(RS_SENTINEL, p.stdout + p.stderr)

    def test_a_cut_not_after_the_latest_is_refused(self):
        p = self.run_job(FAKE_PREV="2026-11-18 02:58:00.123456+00", FAKE_VERDICT="stale")
        self.assertEqual(p.returncode, 1)
        self.assertIn("refused: the cut 2026-11-18 02:58:00.123456+00 is not after the latest snapshot's cut", p.stderr)
        kinds = [x["kind"] for x in self.calls()]
        self.assertEqual(kinds, ["research-cut", "op-cut"])     # nothing dumped, nothing loaded
        # the check is the database's: the previous cut is compared in SQL
        self.assertIn("now() - interval '2 minutes' <= '2026-11-18 02:58:00.123456+00'::timestamptz",
                      self.calls()[1]["sql"])
        self.assertEqual(os.listdir(self.work), [])

    def test_unexpected_answers_are_refused(self):
        for env, msg in (({"FAKE_PREV": "2026-11-18'); DROP TABLE x; --"}, "lake.latest_cut() gave an unexpected answer"),
                         ({"FAKE_CUT": "yesterday"}, "unexpected cut"),
                         ({"FAKE_CONTRACT": "one"}, "research_contract_version() gave an unexpected answer"),
                         ({"FAKE_VERDICT": "maybe"}, "unexpected answer"),
                         ({"FAKE_SNAP": "x"}, "close_snapshot() gave an unexpected answer")):
            with self.subTest(env=env):
                shutil.rmtree(self.fake)
                os.makedirs(self.fake)
                p = self.run_job(**env)
                self.assertEqual(p.returncode, 1, p.stdout)
                self.assertIn(msg, p.stderr)
                self.assertNotIn("DROP TABLE", "".join(x["sql"] for x in self.calls()))

    def test_failures_write_nothing_further(self):
        p = self.run_job(FAKE_DUMP_FAIL="1")
        self.assertEqual(p.returncode, 1)
        self.assertIn("reading the medcea.research_*() functions failed; nothing was written", p.stderr)
        self.assertNotIn("research-load", [x["kind"] for x in self.calls()])
        shutil.rmtree(self.fake)
        os.makedirs(self.fake)
        p = self.run_job(FAKE_LOAD_FAIL="1")
        self.assertEqual(p.returncode, 1)
        self.assertIn("the research transaction was rolled back, nothing was written", p.stderr)
        self.assertNotIn("research-export: snapshot", p.stdout)
        self.assertEqual(os.listdir(self.work), [])

    def test_missing_password_refused(self):
        p = self.run_job(RS_PASSWORD="")
        self.assertEqual(p.returncode, 1)
        self.assertIn("RS_PASSWORD is empty", p.stderr)
        self.assertEqual(self.calls(), [])

    def test_posix(self):
        self.assertEqual(subprocess.run([SH, "-n", JOB], stdin=subprocess.DEVNULL).returncode, 0)
        src = code(read("apps/research-export/export-job.sh"))
        self.assertTrue(read("apps/research-export/export-job.sh").startswith("#!/bin/sh\n"))
        # dash's echo would end "\copy" at "\c"
        self.assertNotRegex(src, r"echo [^\n]*\\\\copy")
        self.assertNotRegex(src, r"\[\[ |\bpipefail\b|\blocal\b")

    # Interfaces 013 and the research DDL, when they are in this tree (other parts of commit A).
    def test_columns_match_migration_013(self):
        mig = read("apps/database/medcea_db_migrations.sql")
        if "medcea.research_measurements" not in mig:
            self.skipTest("migration 013 is not in this tree yet")
        for t, cols in COLUMNS.items():
            with self.subTest(t=t):
                m = re.findall(r"FUNCTION medcea\.research_%s\([^)]*\)\s*RETURNS TABLE\s*\((.*?)\)\s*(?:LANGUAGE|SECURITY|STABLE|SET|AS)"
                               % t, mig, re.S | re.I)
                self.assertTrue(m, t)
                names = [c.strip().split()[0] for c in re.split(r",(?![^(]*\))", m[-1]) if c.strip()]
                self.assertEqual(names, cols, t)

    def test_columns_match_the_stage_tables(self):
        d = os.path.join(ROOT, "apps", "research", "db")
        sql = ""
        if os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                if f.endswith(".sql"):
                    with open(os.path.join(d, f)) as fh:
                        sql += fh.read()
        if "lake.stage_measurements" not in sql:
            self.skipTest("the research DDL is not in this tree yet")
        for t, cols in COLUMNS.items():
            with self.subTest(t=t):
                m = re.search(r"CREATE TABLE (?:IF NOT EXISTS )?lake\.stage_%s\s*\((.*?)\)\s*;" % t, sql, re.S | re.I)
                self.assertIsNotNone(m, t)
                names = [c.strip().split()[0] for c in m.group(1).split(",") if c.strip()]
                self.assertEqual(names, cols, t)


# ── deploy.sh and uninstall.sh ──────────────────────────────────────────────────
FAKE_MICROK8S = r'''#!/bin/bash
# fake microk8s: status ok; kubectl answers from FAKE_* and logs every argv
[[ "$1" == status ]] && exit 0
shift   # kubectl
printf '%s\n' "$*" >> "$FAKE_DIR/kubectl.log"
a="$*"
case "$a" in
  "get cronjob research-export -n "*) [[ -n "${FAKE_CRON:-}" ]] ;;
  "delete "*) exit 0 ;;
  "get statefulset research-postgresql -n "*)
      [[ "$a" == *" -n ${FAKE_RNS:-medcea-research} "* ]] || exit 1
      [[ -n "${FAKE_IMAGE:-}" ]] || exit 1; printf '%s' "$FAKE_IMAGE" ;;
  "get secret research-export-writer -n medcea -o name") [[ -n "${FAKE_WRITER:-}" ]] && echo secret/research-export-writer ;;
  "get secret db-svc-research-export -n medcea"*) [[ -n "${FAKE_OPSECRET:-}" ]] ;;
  "get pod -n medcea -l "*) echo rdbms-postgresql-0 ;;
  "exec -i -n medcea rdbms-postgresql-0 "*) cat >/dev/null; [[ -n "${FAKE_CAN_LOGIN:-}" ]] && echo t || echo f ;;
  "create configmap research-export-script "*) printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: research-export-script\n' ;;
  "apply -f -") { cat; echo "---"; } >> "$FAKE_DIR/applied.yaml" ;;
  *) echo "fake kubectl: unexpected: $a" >&2; exit 1 ;;
esac
'''
FAKE_CLI = r'''import os, sys
a = sys.argv[1:]
with open(os.path.join(os.environ["FAKE_DIR"], "cli.log"), "a") as fh:
    fh.write(" ".join(a) + "\n")
if a[:2] == ["has-zone", "research"]:
    sys.exit(int(os.environ.get("FAKE_ZONE", "0")))
if a[:2] == ["db-roles", "--passwords"]:
    print("svc_research_export SVC_RESEARCH_EXPORT_DB_PASS")
    sys.exit(0)
sys.exit(9)
'''
FAKE_SOURCE = r'''# stub of infra/lib-policy-source.sh
policy_source_init() { echo "init $*" >> "$FAKE_DIR/policy.log"; return "${FAKE_INIT_RC:-0}"; }
policy_source_finish() { echo "finish $*" >> "$FAKE_DIR/policy.log"; }
policy_db_state() { echo "state $*" >> "$FAKE_DIR/policy.log"; [[ "${FAKE_STATE:-}" == unreadable ]] && return 1; echo "${FAKE_STATE:-version-3}"; }
'''


class Deploy(unittest.TestCase):
    CONFIG = {"NAMESPACE": "medcea", "RESEARCH_ENABLED": "true", "RESEARCH_NAMESPACE": "${NAMESPACE}-research",
              "POSTGRES_DB": "medcea_db", "POSTGRES_PASS": PG_SENTINEL, "IAM_DB_SERVICE_ROLES": "true",
              "SVC_RESEARCH_EXPORT_DB_PASS": OP_SENTINEL, "RS_EXPORT_WRITER_DB_PASS": RS_SENTINEL}
    READY = {"FAKE_IMAGE": "docker.io/bitnami/postgresql:18.0.0@sha256:" + "a" * 64, "FAKE_WRITER": "1",
             "FAKE_OPSECRET": "1", "FAKE_CAN_LOGIN": "1"}

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="medcea-rsexport-")
        shutil.copytree(APP, os.path.join(self.root, "apps", "research-export"))
        for f in ("lib-log.sh", "lib-lock.sh", "lib-mk8s.sh", "lib-render.sh", "lib-db-roles.sh"):
            write(os.path.join(self.root, "infra", f), read(f"infra/{f}"))
        write(os.path.join(self.root, "apps", "database", "lib-db-apply.sh"), read("apps/database/lib-db-apply.sh"))
        write(os.path.join(self.root, "infra", "lib-policy-source.sh"), FAKE_SOURCE)
        write(os.path.join(self.root, "apps", "iam", "compiler", "cli.py"), FAKE_CLI)
        self.bin = os.path.join(self.root, "bin")
        self.fake = os.path.join(self.root, "fake")
        os.makedirs(self.fake)
        write(os.path.join(self.bin, "microk8s"), FAKE_MICROK8S, 0o755)

    def tearDown(self):
        shutil.rmtree(self.root)

    def run_(self, script="deploy.sh", args=(), config=None, **extra):
        cfg = dict(self.CONFIG, **(config or {}))
        write(os.path.join(self.root, "config.env"), "".join(f'{k}="{v}"\n' for k, v in cfg.items()))
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("MEDCEA_", "FAKE_", "IAM_", "RESEARCH_", "SVC_", "POSTGRES_", "NAMESPACE"))}
        env.update({"PATH": self.bin + ":" + os.environ["PATH"], "FAKE_DIR": self.fake, "MEDCEA_NO_LOG": "1"})
        env.update(extra)
        return subprocess.run(["bash", os.path.join(self.root, "apps", "research-export", script), *args],
                              capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env, cwd=self.root)

    def log(self, name):
        p = os.path.join(self.fake, name)
        if not os.path.exists(p):
            return ""
        with open(p) as fh:
            return fh.read()

    def assert_skip(self, p, line):
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(f"skipped: {line}", p.stdout)
        self.assertTrue(self.log("policy.log").rstrip().endswith("finish medcea research-export"))
        self.assertEqual(self.log("applied.yaml"), "")

    def test_unknown_option_before_the_log(self):
        p = self.run_(args=("--gate-only",), MEDCEA_NO_LOG="")
        self.assertEqual(p.returncode, 2)
        self.assertIn("unknown arguments: --gate-only", p.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.root, "logs")))
        self.assertEqual(self.log("kubectl.log") + self.log("policy.log"), "")
        p = self.run_(script="uninstall.sh", args=("--purge-data",), MEDCEA_NO_LOG="")
        self.assertEqual(p.returncode, 2)
        self.assertFalse(os.path.exists(os.path.join(self.root, "logs")))
        p = self.run_(args=("--help",))
        self.assertEqual(p.returncode, 0)
        self.assertIn("usage: ./apps/research-export/deploy.sh", p.stdout)
        self.assertEqual(self.log("kubectl.log"), "")

    def test_switch_off(self):
        p = self.run_(config={"RESEARCH_ENABLED": "false"}, **self.READY)
        self.assert_skip(p, "RESEARCH_ENABLED is not true")
        self.assertEqual(self.log("cli.log"), "")
        self.assertNotIn("delete", self.log("kubectl.log"))

    def test_a_skip_removes_a_running_export(self):
        p = self.run_(config={"RESEARCH_ENABLED": "false"}, FAKE_CRON="1", **self.READY)
        self.assert_skip(p, "RESEARCH_ENABLED is not true")
        k = self.log("kubectl.log")
        self.assertIn("delete cronjob research-export -n medcea --ignore-not-found", k)
        self.assertIn("delete job -n medcea -l app=research-export --ignore-not-found", k)
        self.assertIn("delete configmap research-export-script -n medcea --ignore-not-found", k)
        self.assertIn("the research database keeps its snapshots", p.stderr)

    def test_no_research_zone(self):
        p = self.run_(FAKE_ZONE="1", **self.READY)
        self.assert_skip(p, "the applied access policy has no research zone yet")
        self.assertEqual(self.log("cli.log"), "has-zone research\n")
        p = self.run_(FAKE_ZONE="2", **self.READY)
        self.assertEqual(p.returncode, 1)
        self.assertIn("cannot read the research zone", p.stderr)

    def test_no_applied_version(self):
        for st in ("none", "empty"):
            p = self.run_(FAKE_STATE=st, **self.READY)
            self.assert_skip(p, f"no version of the access policy is applied yet (state {st})")
        p = self.run_(FAKE_STATE="partial", **self.READY)
        self.assertEqual(p.returncode, 1)
        p = self.run_(FAKE_STATE="unreadable", **self.READY)
        self.assertEqual(p.returncode, 1)
        self.assertIn("cannot read the policy versions", p.stderr)

    def test_no_research_database(self):
        p = self.run_(**dict(self.READY, FAKE_IMAGE=""))
        self.assert_skip(p, "./apps/research/deploy.sh has not run")
        # asked in RESEARCH_NAMESPACE (config.env's expression)
        self.assertIn("get statefulset research-postgresql -n medcea-research", self.log("kubectl.log"))

    def test_service_roles_off(self):
        p = self.run_(config={"IAM_DB_SERVICE_ROLES": "false"}, **self.READY)
        self.assert_skip(p, "the research export needs IAM_DB_SERVICE_ROLES=true")

    def test_refusals(self):
        p = self.run_(**dict(self.READY, FAKE_WRITER=""))
        self.assertEqual(p.returncode, 1)
        self.assertIn("no Secret research-export-writer in medcea: run ./apps/research/deploy.sh", p.stderr)
        # a fallback to postgres (the role cannot log in yet) is refused
        p = self.run_(**dict(self.READY, FAKE_CAN_LOGIN=""))
        self.assertEqual(p.returncode, 1)
        self.assertIn("would log in as postgres, not svc_research_export", p.stderr)
        self.assertEqual(self.log("applied.yaml"), "")
        p = self.run_(FAKE_INIT_RC="2", **self.READY)
        self.assertEqual(p.returncode, 2)

    def test_full_path(self):
        p = self.run_(**self.READY)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(self.log("policy.log").startswith("init medcea\n"))
        self.assertTrue(self.log("policy.log").rstrip().endswith("finish medcea research-export"))
        docs = [d for d in yaml.safe_load_all(self.log("applied.yaml")) if d]
        self.assertEqual([d["kind"] for d in docs], ["ConfigMap", "CronJob"])
        cj = docs[1]
        c = cj["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(c["image"], self.READY["FAKE_IMAGE"])
        env = {e["name"]: e for e in c["env"]}
        self.assertEqual(env["OP_USER"]["value"], "svc_research_export")
        self.assertEqual(env["OP_PASSWORD"]["valueFrom"]["secretKeyRef"],
                         {"name": "db-svc-research-export", "key": "password"})
        self.assertEqual(env["RS_HOST"]["value"], "research-postgresql.medcea-research")
        k = self.log("kubectl.log")
        self.assertIn("create configmap research-export-script -n medcea --from-file=export-job.sh=", k)
        everything = k + self.log("applied.yaml") + self.log("cli.log") + p.stdout + p.stderr
        for s in (OP_SENTINEL, RS_SENTINEL, PG_SENTINEL):
            self.assertNotIn(s, everything)

    def test_uninstall(self):
        p = self.run_(script="uninstall.sh")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.log("kubectl.log").splitlines(), [
            "delete cronjob research-export -n medcea --ignore-not-found",
            "delete job -n medcea -l app=research-export --ignore-not-found",
            "delete configmap research-export-script -n medcea --ignore-not-found"])

    def test_wiring(self):
        d = code(read("apps/research-export/deploy.sh"))
        self.assertLess(d.index("medcea_log app-research-export-deploy"), d.index("medcea_lock"))
        self.assertLess(d.index("exit 2"), d.index("medcea_log "))
        self.assertIn('policy_source_init "$NAMESPACE" || exit $?', d)
        self.assertTrue(d.rstrip().endswith('policy_source_finish "$NAMESPACE" research-export'))
        u = code(read("apps/research-export/uninstall.sh"))
        self.assertLess(u.index("medcea_log app-research-export-uninstall"), u.index("medcea_lock"))
        for f in ("deploy.sh", "uninstall.sh"):
            self.assertTrue(os.access(os.path.join(APP, f), os.X_OK), f)


# ── lib-research-export.sh ──────────────────────────────────────────────────────
class AgeStatus(unittest.TestCase):
    def status(self, now, last, created, snap=""):
        p = subprocess.run(["bash", "-c", 'source "$1"; shift; rsexport_age_status "$@"', "-",
                            os.path.join(APP, "lib-research-export.sh"), str(now), last, str(created), snap],
                           capture_output=True, text=True, stdin=subprocess.DEVNULL, check=True)
        return p.stdout.strip()

    def test_thresholds(self):
        now = 1_800_000_000
        h = 3600
        self.assertTrue(self.status(now, "", now - 2 * h).startswith("SKIP|no snapshot yet"))
        self.assertTrue(self.status(now, "", now - 30 * h).startswith("WARN|no snapshot since"))
        self.assertTrue(self.status(now, "", now - 80 * h).startswith("FAIL|"))
        self.assertEqual(self.status(now, str(now - 5 * h), 0, "4"), "OK|newest snapshot 4, 5 h old")
        self.assertTrue(self.status(now, str(now - 27 * h), 0, "4").startswith("WARN|newest snapshot 4 is 27 h old (over 26 h"))
        self.assertTrue(self.status(now, str(now - 73 * h), 0, "4").startswith("FAIL|newest snapshot 4 is 73 h old (over 72 h"))
        self.assertTrue(self.status(now, str(now + 60), 0, "4").startswith("OK|"))


if __name__ == "__main__":
    unittest.main()
