#!/usr/bin/env python3
"""tests/test_backup.py — the nightly backups (apps/backup/), offline.

- The CronJob as apps/backup/deploy.sh renders it: every ${VAR} in the template is in the
  render list; daily 02:30 UTC (not the scheduler's 03:15), Forbid, no retry; the postgres
  password only through secretKeyRef (a sentinel in the environment never reaches the
  manifest); the volumes' directory mounted read-only, BACKUP_DIR read-write; no service
  account token; no capability beyond CHOWN, DAC_OVERRIDE, FOWNER.
- backup-job.sh under dash with a fake pg_dump/pg_dumpall and a fake PV directory: one dated
  folder with both dumps, the roles without passwords, a tar of each workbench home,
  Node-RED and Grafana and of nothing else (not PostgreSQL's, the broker's, the hub's or
  another namespace's volume); SHA256SUMS that sha256sum -c accepts; MANIFEST with sizes;
  OK last; the password in no argument, output or file. A failing pg_dump: exit 1, no OK,
  nothing deleted. MANIFEST names the access policy's chain head (IAM 4.5), read with a
  fake psql before the first dump; unavailable without the schema or when psql fails, and
  the backup still completes.
- Retention (backup-job.sh prune): only folders named like 20261102-023000Z and older than
  KEEP_DAYS go; never the newest complete one, never a symbolic link, never another name;
  a bad KEEP_DAYS deletes nothing.
- apps/backup/lib-backup.sh: the newest OK marker, and OK/WARN/FAIL/SKIP at 26 h and 72 h.
- health-check.sh check_backupage with a fake kubectl: SKIP without the CronJob, then the
  ages above, FAIL when BACKUP_DIR cannot be read.
- apps/backup/backups.sh in a scratch tree: list, verify (a changed or an added file fails),
  restore-help (runs no kubectl, names every part), now (a Job from the CronJob, its log),
  an unknown command.
- uninstall.sh leaves BACKUP_DIR; config.env.example and health-checks.conf carry it.

Run: python3 tests/test_backup.py
"""
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "apps", "backup")
JOB = os.path.join(APP, "backup-job.sh")
LIB = os.path.join(APP, "lib-backup.sh")
SENTINEL = "s3ntinel-PG-pass-do-not-print"
UID = "0123abcd-0000-1111-2222-333344445555"
SH = shutil.which("dash") or "/bin/sh"


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def stamp(epoch):
    return time.strftime("%Y%m%d-%H%M%SZ", time.gmtime(epoch))


def write(path, text, mode=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)
    if mode is not None:
        os.chmod(path, mode)


class CronJobRender(unittest.TestCase):
    VALUES = {"NAMESPACE": "medcea", "BACKUP_DIR": "/var/backups/medcea", "BACKUP_KEEP_DAYS": "14",
              "BACKUP_IMAGE": "docker.io/bitnami/postgresql:18.0.0", "BACKUP_UID": "1000", "BACKUP_GID": "1000",
              "STORAGE_DIR": "/var/snap/microk8s/common/default-storage", "POSTGRES_DB": "medcea_db"}

    @classmethod
    def setUpClass(cls):
        deploy = read("apps/backup/deploy.sh")
        m = re.search(r'render "\$SCRIPT_DIR/k8s/backup-cronjob.yaml" ((?:[A-Z_]+ |\\\n\s*)+)\\?\n?\s*\|', deploy)
        cls.render_list = re.findall(r"[A-Z_]+", m.group(1))
        env = dict(os.environ, POSTGRES_PASS=SENTINEL, PGPASSWORD=SENTINEL, **cls.VALUES)
        cls.text = subprocess.run(
            ["bash", "-c", 'source "$1/infra/lib-render.sh"; shift; render "$@"', "-", ROOT,
             os.path.join(APP, "k8s", "backup-cronjob.yaml"), *cls.render_list],
            capture_output=True, text=True, env=env, check=True).stdout
        cls.cj = yaml.safe_load(cls.text)
        cls.pod = cls.cj["spec"]["jobTemplate"]["spec"]["template"]["spec"]
        cls.c = cls.pod["containers"][0]

    def test_render_list_covers_the_template(self):
        used = set(re.findall(r"\$\{([A-Z_]+)\}", read("apps/backup/k8s/backup-cronjob.yaml")))
        self.assertEqual(used, set(self.render_list))
        self.assertNotRegex(self.text, r"\$\{[A-Z_]+\}")

    def test_schedule(self):
        s = self.cj["spec"]
        self.assertEqual(s["schedule"], "30 2 * * *")      # 02:30, not sys_log_retention's 03:15
        self.assertEqual(s["timeZone"], "Etc/UTC")
        self.assertEqual(s["concurrencyPolicy"], "Forbid")
        self.assertEqual(s["jobTemplate"]["spec"]["backoffLimit"], 0)
        self.assertIn("daily 03:15 UTC", read("apps/scheduler/scheduler-api.py"))

    def test_password_only_by_secret_ref(self):
        self.assertNotIn(SENTINEL, self.text)
        env = {e["name"]: e for e in self.c["env"]}
        self.assertEqual(env["PGPASSWORD"]["valueFrom"]["secretKeyRef"],
                         {"name": "rdbms-postgresql", "key": "postgres-password"})
        self.assertNotIn("value", env["PGPASSWORD"])
        self.assertNotRegex(" ".join(self.c["command"]), r"(?i)pass")
        self.assertEqual(env["DATABASES"]["value"], "medcea_db keycloak")
        self.assertEqual(env["OPTIONAL_DATABASES"]["value"], "superset")
        self.assertEqual(env["VOLUMES"]["value"], "claim-* node-red grafana")

    def test_mounts(self):
        mounts = {m["name"]: m for m in self.c["volumeMounts"]}
        vols = {v["name"]: v for v in self.pod["volumes"]}
        self.assertTrue(mounts["storage"].get("readOnly"))
        self.assertTrue(mounts["script"].get("readOnly"))
        self.assertFalse(mounts["out"].get("readOnly", False))
        self.assertEqual(vols["storage"]["hostPath"], {"path": self.VALUES["STORAGE_DIR"], "type": "Directory"})
        self.assertEqual(vols["out"]["hostPath"], {"path": self.VALUES["BACKUP_DIR"], "type": "Directory"})
        hostpaths = [v for v in self.pod["volumes"] if "hostPath" in v]
        self.assertEqual(len(hostpaths), 2)

    def test_pod_hardening(self):
        self.assertIs(self.pod["automountServiceAccountToken"], False)
        sc = self.c["securityContext"]
        self.assertIs(sc["allowPrivilegeEscalation"], False)
        self.assertIs(sc["readOnlyRootFilesystem"], True)
        self.assertEqual(sc["capabilities"]["drop"], ["ALL"])
        self.assertEqual(set(sc["capabilities"]["add"]), {"CHOWN", "DAC_OVERRIDE", "FOWNER"})
        self.assertNotIn("privileged", sc)


class JobRun(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bin = os.path.join(self.tmp, "bin")
        self.out = os.path.join(self.tmp, "out")
        self.st = os.path.join(self.tmp, "storage")
        self.log = os.path.join(self.tmp, "fake.log")
        os.makedirs(self.out)
        fake = ('#!/bin/sh\necho "$(basename "$0") $*" >> "$FAKE_LOG"\n'
                '[ -n "${FAKE_FAIL:-}" ] && case "$*" in *"$FAKE_FAIL"*) echo "fake: connection refused" >&2; exit 1 ;; esac\n'
                'for a in "$@"; do case "$a" in --file=*) f="${a#--file=}" ;; esac; done\n'
                'printf "PGDMP %s\\n" "$*" > "$f"\n')
        for n in ("pg_dump", "pg_dumpall"):
            write(os.path.join(self.bin, n), fake, 0o755)
        # psql answers the chain-head query (stdin, kept for the test) as FAKE_PSQL says
        write(os.path.join(self.bin, "psql"),
              '#!/bin/sh\necho "psql $*" >> "$FAKE_LOG"\ncat > "$FAKE_LOG.in"\n'
              # the existence question of OPTIONAL_DATABASES: answered from FAKE_EXISTS
              'if grep -q pg_database "$FAKE_LOG.in"; then cat "$FAKE_LOG.in" >> "$FAKE_LOG.exists.sql"\n'
              '  case "${FAKE_EXISTS:-t}" in t|f) echo "${FAKE_EXISTS:-t}"; exit 0 ;; *) echo "psql: error" >&2; exit 2 ;; esac\n'
              'fi\nmv "$FAKE_LOG.in" "$FAKE_LOG.sql"\n'
              'case "${FAKE_PSQL:-head}" in\n'
              '  head) echo "head 41 ' + "ab" * 32 + ' t" ;;\n'
              '  broken) echo "head 41 ' + "ab" * 32 + ' f" ;;\n'
              '  empty) echo "head none - t" ;;\n'
              '  noschema) echo "no-schema" ;;\n'
              '  garbage) echo "head 41 not-a-hash t" ;;\n'
              '  fail) echo "psql: error: connection to server failed: Connection refused" >&2; exit 2 ;;\n'
              'esac\n', 0o755)
        for claim in ("claim-alice", "claim-bob-2esmith", "node-red", "grafana",
                      "data-rdbms-postgresql-0", "mosquitto-data", "hub-db-dir"):
            write(os.path.join(self.st, f"medcea-{claim}-pvc-{UID}", "file.txt"), f"data of {claim}\n")
        write(os.path.join(self.st, f"medcea-iamtest-grafana-pvc-{UID}", "x"), "other namespace\n")
        write(os.path.join(self.st, "medcea-grafana-notapv", "x"), "no pv suffix\n")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_job(self, cmd="run", **extra):
        env = {"PATH": self.bin + ":/usr/bin:/bin", "FAKE_LOG": self.log, "BACKUP_OUT": self.out,
               "STORAGE": self.st, "NAMESPACE": "medcea", "DATABASES": "medcea_db keycloak",
               "VOLUMES": "claim-* node-red grafana", "KEEP_DAYS": "14",
               "OWNER_UID": str(os.getuid()), "OWNER_GID": str(os.getgid()), "PGPASSWORD": SENTINEL}
        env.update(extra)
        return subprocess.run([SH, JOB, cmd], capture_output=True, text=True, env=env, cwd=self.tmp)

    def test_a_complete_run(self):
        now = 1793586600   # 2026-11-02 02:30:00 UTC
        p = self.run_job(BACKUP_NOW=str(now))
        self.assertEqual(p.returncode, 0, p.stderr)
        d = os.path.join(self.out, "20261102-023000Z")
        files = sorted(os.path.relpath(os.path.join(r, f), d) for r, _, fs in os.walk(d) for f in fs)
        self.assertEqual(files, ["MANIFEST", "OK", "SHA256SUMS", "db/globals.sql", "db/keycloak.dump",
                                 "db/medcea_db.dump", "volumes/claim-alice.tar.gz",
                                 "volumes/claim-bob-2esmith.tar.gz", "volumes/grafana.tar.gz",
                                 "volumes/node-red.tar.gz"])
        with open(os.path.join(d, "OK")) as fh:
            self.assertEqual(fh.read().split()[0], str(now))
        v = subprocess.run(["sha256sum", "--strict", "-c", "SHA256SUMS"], cwd=d, capture_output=True, text=True)
        self.assertEqual(v.returncode, 0, v.stdout + v.stderr)
        with open(os.path.join(d, "MANIFEST")) as fh:
            rows = [l.split("\t") for l in fh.read().splitlines() if not l.startswith("#")]
        self.assertEqual(len(rows), 7)
        for size, _, path in rows:
            self.assertEqual(int(size), os.path.getsize(os.path.join(d, path)))
        t = subprocess.run(["tar", "-tzf", os.path.join(d, "volumes", "node-red.tar.gz")], capture_output=True, text=True)
        self.assertIn("./file.txt", t.stdout.split())
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700)
        with open(self.log) as fh:
            calls = fh.read()
        self.assertIn("pg_dump --no-password --format=custom", calls)
        self.assertIn("--dbname=keycloak", calls)
        self.assertIn("pg_dumpall --no-password --globals-only --no-role-passwords", calls)
        # the password: in no argument, no output, no file
        self.assertNotIn(SENTINEL, calls + p.stdout + p.stderr)
        for r, _, fs in os.walk(d):
            for f in fs:
                with open(os.path.join(r, f), "rb") as fh:
                    self.assertNotIn(SENTINEL.encode(), fh.read(), f)

    def manifest_head(self, **extra):
        p = self.run_job(BACKUP_NOW="1793586600", **extra)
        self.assertEqual(p.returncode, 0, p.stderr)
        d = os.path.join(self.out, "20261102-023000Z")
        with open(os.path.join(d, "MANIFEST")) as fh:
            heads = [l for l in fh.read().splitlines() if l.startswith("# policy chain head")]
        self.assertTrue(os.path.exists(os.path.join(d, "OK")))
        shutil.rmtree(d)
        self.assertEqual(len(heads), 1)
        return heads[0], p

    def test_the_policy_chain_head_is_read_before_the_dump(self):
        # IAM 4.5 (design §14.8.10, owner decision 10): read first, so the dump holds at least it
        head, p = self.manifest_head()
        self.assertEqual(head, "# policy chain head (read before the dump): 41 " + "ab" * 32 + " verify_chain=t")
        self.assertIn("backup: policy chain head (read before the dump): 41", p.stdout)
        with open(self.log) as fh:
            calls = fh.read().splitlines()
        first = [i for i, c in enumerate(calls) if c.startswith(("psql", "pg_dump "))]
        self.assertTrue(calls[first[0]].startswith("psql --no-password"), calls)
        self.assertIn("--dbname=medcea_db", calls[first[0]])
        self.assertNotIn(SENTINEL, calls[first[0]])
        with open(self.log + ".sql") as fh:
            sql = fh.read()
        self.assertIn("BEGIN TRANSACTION READ ONLY;", sql)
        self.assertIn("iam_policy.history h ORDER BY h.event_id DESC LIMIT 1", sql)
        self.assertIn("\\if :has_chain", sql)
        self.assertIn("iam_policy.verify_chain()", sql)
        # POLICY_DB names another database
        head, _ = self.manifest_head(POLICY_DB="other_db")
        with open(self.log) as fh:
            self.assertIn("--dbname=other_db", [c for c in fh.read().splitlines() if c.startswith("psql")][-1])
        self.assertTrue(self.manifest_head(FAKE_PSQL="broken")[0].endswith(" verify_chain=f"))

    def test_an_unavailable_head_does_not_stop_the_backup(self):
        for mode, why in (("noschema", "no iam_policy schema in medcea_db"),
                          ("empty", "iam_policy.history is empty"),
                          ("garbage", "unexpected answer from psql"),
                          ("fail", "psql exit 2: psql: error: connection to server failed: Connection refused")):
            head, _ = self.manifest_head(FAKE_PSQL=mode)
            self.assertEqual(head, f"# policy chain head: unavailable ({why})", mode)

    def optional_run(self, **extra):
        p = self.run_job(**dict({"BACKUP_NOW": "1793586600", "OPTIONAL_DATABASES": "superset"}, **extra))
        d = os.path.join(self.out, "20261102-023000Z")
        manifest = ""
        if os.path.exists(os.path.join(d, "MANIFEST")):
            with open(os.path.join(d, "MANIFEST")) as fh:
                manifest = fh.read()
        with open(self.log) as fh:
            calls = fh.read()
        return p, d, manifest, calls

    def test_an_absent_optional_database_is_skipped(self):
        # Superset (stage B): database superset exists only on installs with Superset
        p, d, manifest, calls = self.optional_run(FAKE_EXISTS="f")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(os.path.exists(os.path.join(d, "OK")))
        self.assertFalse(os.path.exists(os.path.join(d, "db", "superset.dump")))
        self.assertNotIn("--dbname=superset", calls)
        self.assertIn("backup: skipped superset (no such database on this install)", p.stdout)
        self.assertIn("# databases: medcea_db keycloak\n", manifest)
        self.assertIn("# databases skipped (absent): superset\n", manifest)
        with open(self.log + ".exists.sql") as fh:
            sql = fh.read()
        self.assertIn("pg_catalog.pg_database WHERE datname = :'name'", sql)
        self.assertIn("psql --no-password --no-psqlrc -X -q -tA -v ON_ERROR_STOP=1 --dbname=postgres -v name=superset", calls)

    def test_a_present_optional_database_is_dumped(self):
        p, d, manifest, calls = self.optional_run(FAKE_EXISTS="t")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(os.path.exists(os.path.join(d, "OK")))
        self.assertTrue(os.path.exists(os.path.join(d, "db", "superset.dump")))
        self.assertIn("--dbname=superset", calls)
        self.assertIn("# databases: medcea_db keycloak superset\n", manifest)
        self.assertNotIn("skipped", manifest)
        self.assertIn("\tdb/superset.dump\n", manifest)
        v = subprocess.run(["sha256sum", "--strict", "-c", "SHA256SUMS"], cwd=d, capture_output=True, text=True)
        self.assertEqual(v.returncode, 0, v.stdout + v.stderr)
        self.assertNotIn(SENTINEL, calls + p.stdout + p.stderr)

    def test_an_optional_database_that_cannot_be_asked_fails(self):
        p, d, _, _ = self.optional_run(FAKE_EXISTS="error")
        self.assertEqual(p.returncode, 1)
        self.assertIn("could not ask PostgreSQL whether database superset exists", p.stderr)
        self.assertFalse(os.path.exists(os.path.join(d, "OK")))
        # and a failed dump of a present one fails like any dump
        shutil.rmtree(d)
        p, d, _, _ = self.optional_run(FAKE_EXISTS="t", FAKE_FAIL="--dbname=superset")
        self.assertEqual(p.returncode, 1)
        self.assertIn("pg_dump of superset failed", p.stderr)
        self.assertFalse(os.path.exists(os.path.join(d, "OK")))

    def test_an_optional_database_name_is_checked(self):
        p, d, _, calls = self.optional_run(OPTIONAL_DATABASES="x';drop")
        self.assertEqual(p.returncode, 1)
        self.assertIn("is not a plain database name", p.stderr)

    def test_a_failed_dump_leaves_no_ok_and_deletes_nothing(self):
        old = os.path.join(self.out, "20200101-023000Z")
        write(os.path.join(old, "OK"), "1577845800 x\n")
        write(os.path.join(self.out, "20200102-023000Z", "OK"), "1577932200 x\n")
        p = self.run_job(FAKE_FAIL="keycloak", BACKUP_NOW="1793586600")
        self.assertEqual(p.returncode, 1)
        self.assertIn("pg_dump of keycloak failed", p.stderr)
        self.assertIn("has no OK marker", p.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.out, "20261102-023000Z", "OK")))
        self.assertTrue(os.path.isdir(old))

    def test_a_second_run_in_the_same_second_refuses(self):
        self.assertEqual(self.run_job(BACKUP_NOW="1793586600").returncode, 0)
        p = self.run_job(BACKUP_NOW="1793586600")
        self.assertEqual(p.returncode, 1)
        self.assertIn("exists already", p.stderr)

    # --- retention -----------------------------------------------------------
    def make(self, epoch, ok=True):
        d = os.path.join(self.out, stamp(epoch))
        os.makedirs(d)
        if ok:
            write(os.path.join(d, "OK"), f"{epoch} x\n")
        return d

    def test_prune(self):
        now = 1793586600
        day = 86400
        old_ok = self.make(now - 20 * day)
        old_bad = self.make(now - 15 * day, ok=False)
        edge = self.make(now - 14 * day + 60)
        recent = self.make(now - 2 * day)
        recent_bad = self.make(now - 1 * day, ok=False)
        other = os.path.join(self.out, "keep-me")
        os.makedirs(other)
        target = os.path.join(self.tmp, "elsewhere")
        os.makedirs(target)
        link = os.path.join(self.out, stamp(now - 30 * day))
        os.symlink(target, link)
        p = self.run_job("prune", BACKUP_NOW=str(now))
        self.assertEqual(p.returncode, 0, p.stderr)
        for gone in (old_ok, old_bad):
            self.assertFalse(os.path.exists(gone), gone)
        for kept in (edge, recent, recent_bad, other, link, target):
            self.assertTrue(os.path.exists(kept), kept)
        self.assertIn(f"deleted {os.path.basename(old_ok)}", p.stdout)

    def test_prune_keeps_the_newest_complete_one(self):
        now = 1793586600
        a = self.make(now - 40 * 86400)
        b = self.make(now - 30 * 86400)
        c = self.make(now - 20 * 86400, ok=False)
        p = self.run_job("prune", BACKUP_NOW=str(now))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse(os.path.exists(a))
        self.assertTrue(os.path.exists(b))
        self.assertFalse(os.path.exists(c))

    def test_prune_refuses_a_bad_keep(self):
        a = self.make(1793586600 - 40 * 86400, ok=False)
        for bad in ("0", "-3", "14d", ""):
            with self.subTest(bad):
                p = self.run_job("prune", BACKUP_NOW="1793586600", KEEP_DAYS=bad)
                if bad == "":
                    continue   # unset or empty means the default, 14
                self.assertEqual(p.returncode, 1)
                self.assertTrue(os.path.exists(a))

    def test_a_run_prunes_after_ok(self):
        now = 1793586600
        old = self.make(now - 20 * 86400)
        p = self.run_job(BACKUP_NOW=str(now))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(os.path.join(self.out, stamp(now), "OK")))
        self.assertLess(p.stdout.index("OK: "), p.stdout.index("deleted "))


def lib(script, **env):
    e = dict(os.environ, **env)
    return subprocess.run(["bash", "-c", f'source "{LIB}"\n{script}'], capture_output=True, text=True, env=e)


class LibAge(unittest.TestCase):
    H = 3600
    NOW = 1793586600

    def status(self, ok_age_h=None, created_age_h=1):
        ok = "" if ok_age_h is None else str(self.NOW - int(ok_age_h * self.H))
        r = lib(f'backup_age_status {self.NOW} "{ok}" {self.NOW - created_age_h * self.H} 20261102-023000Z')
        return r.stdout.strip().split("|", 1)

    def test_thresholds(self):
        self.assertEqual(self.status(2)[0], "OK")
        self.assertEqual(self.status(26)[0], "OK")
        self.assertEqual(self.status(26.1)[0], "WARN")
        self.assertEqual(self.status(72)[0], "WARN")
        self.assertEqual(self.status(72.1)[0], "FAIL")
        self.assertIn("over 72 h", self.status(80)[1])

    def test_none_yet(self):
        self.assertEqual(self.status(None, created_age_h=3)[0], "SKIP")
        self.assertEqual(self.status(None, created_age_h=30)[0], "WARN")
        self.assertEqual(self.status(None, created_age_h=100)[0], "FAIL")

    def test_newest_ok(self):
        d = tempfile.mkdtemp()
        try:
            for n, ok in (("20261030-023000Z", "1793327400 x"), ("20261031-023000Z", "1793413800 x"),
                          ("20261101-023000Z", None), ("20261101-030000Z", "garbage"), ("notastamp", "1 x")):
                os.makedirs(os.path.join(d, n))
                if ok:
                    write(os.path.join(d, n, "OK"), ok + "\n")
            r = lib(f'backup_newest_ok "{d}"; backup_folders "{d}" | wc -l')
            self.assertEqual(r.stdout.split("\n")[:2], ["20261031-023000Z 1793413800", "4"])
            self.assertEqual(lib("backup_dir", BACKUP_DIR="", PROJECT_NAME="medcea").stdout.strip(), "/var/backups/medcea")
        finally:
            shutil.rmtree(d)


class LibChainHead(unittest.TestCase):
    """backup_chain_head: what health-check iamanchor reads from a MANIFEST (Phase 5, G12)."""

    def head(self, line, manifest=True):
        d = tempfile.mkdtemp()
        try:
            if manifest:
                write(os.path.join(d, "MANIFEST"), "# MedCEA backup x\n# namespace: medcea\n"
                      + (line + "\n" if line is not None else "") + "# bytes\tsha256\tpath\n")
            r = lib(f'backup_chain_head "{d}"')
            return r.returncode, r.stdout.strip()
        finally:
            shutil.rmtree(d)

    def test_the_job_s_own_lines(self):
        h = "ab" * 32
        self.assertEqual(self.head(f"# policy chain head (read before the dump): 41 {h} verify_chain=t"),
                         (0, f"head 41 {h} t"))
        self.assertEqual(self.head(f"# policy chain head (read before the dump): 7 {h} verify_chain=f"),
                         (0, f"head 7 {h} f"))
        for why in ("no iam_policy schema in medcea_db", "iam_policy.history is empty",
                    "unexpected answer from psql", "psql exit 2: could not connect"):
            self.assertEqual(self.head(f"# policy chain head: unavailable ({why})"), (0, f"unavailable ({why})"))

    def test_nothing_else_passes_as_a_head(self):
        self.assertEqual(self.head(None), (0, "none"))
        self.assertEqual(self.head("", manifest=False)[0], 1)
        for bad in ("# policy chain head (read before the dump): 41 ABAB verify_chain=t",
                    "# policy chain head (read before the dump): x1 abab verify_chain=t",
                    "# policy chain head (read before the dump): 41 abab verify_chain=t; rm -rf /",
                    "# policy chain head (read before the dump): 41 abab"):
            self.assertEqual(self.head(bad), (0, "unavailable (an unexpected chain head line in MANIFEST)"), bad)
        rc, out = self.head("# policy chain head: unavailable (psql exit 2: $(id); `x` | y)")
        self.assertEqual(rc, 0)
        for c in "$`|;":
            self.assertNotIn(c, out)

    def test_it_reads_the_line_the_job_writes(self):
        # the job's echo and the reader's pattern are the same text
        job = read("apps/backup/backup-job.sh")
        self.assertIn('echo "# policy chain head (read before the dump): $2 $3 verify_chain=$4"', job)
        self.assertIn('echo "# policy chain head: unavailable (', job)


class HealthCheck(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.dir = os.path.join(self.tmp, "backups")
        os.makedirs(self.dir)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def check(self, created=None, backup_dir=None):
        kubectl = os.path.join(self.tmp, "kubectl")
        if created is None:
            body = '#!/bin/sh\necho "Error from server (NotFound): cronjobs.batch \\"medcea-backup\\" not found" >&2\nexit 1\n'
        else:
            body = ('#!/bin/sh\ncase "$*" in "get cronjob medcea-backup -n medcea -o jsonpath={.metadata.creationTimestamp}") '
                    f'printf %s "{created}" ;; *) exit 3 ;; esac\n')
        write(kubectl, body, 0o755)
        src = read("health-check.sh")
        fn = re.search(r"(?ms)^check_backupage\(\) \{.*?^\}", src).group(0)
        script = (f'_record() {{ echo "$1|$2|$3"; }}\nsource "{LIB}"\nTIMEOUT=5\nKUBECTL=kubectl\nNAMESPACE=medcea\n'
                  f"{fn}\ncheck_backupage Backups medcea\n")
        env = dict(os.environ, PATH=self.tmp + ":" + os.environ["PATH"], BACKUP_DIR=backup_dir or self.dir)
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env).stdout.strip()

    def ok_at(self, hours_ago):
        e = int(time.time()) - int(hours_ago * 3600)
        write(os.path.join(self.dir, stamp(e), "OK"), f"{e} x\n")

    def iso(self, hours_ago):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - hours_ago * 3600))

    def test_skip_before_deploy(self):
        self.assertTrue(self.check().startswith("SKIP|Backups|no CronJob medcea-backup in medcea"))

    def test_first_day(self):
        self.assertTrue(self.check(self.iso(2)).startswith("SKIP|Backups|no complete backup yet"))
        self.assertTrue(self.check(self.iso(100)).startswith("FAIL|Backups|no complete backup since"))

    def test_ages(self):
        self.ok_at(80)
        self.assertTrue(self.check(self.iso(200)).startswith("FAIL|"))
        self.ok_at(30)
        self.assertTrue(self.check(self.iso(200)).startswith("WARN|"))
        self.ok_at(2)
        r = self.check(self.iso(200))
        self.assertTrue(r.startswith("OK|Backups|newest complete backup "), r)

    def test_unreadable_dir(self):
        r = self.check(self.iso(2), backup_dir=os.path.join(self.tmp, "nope"))
        self.assertTrue(r.startswith("FAIL|Backups|cannot read"), r)

    def test_wired(self):
        self.assertRegex(read("health-checks.conf"), r"(?m)^Backups +\| backupage +\| \$NAMESPACE")
        self.assertIn('backupage)    check_backupage "$name" "$target"', read("health-check.sh"))
        self.assertIn('source "${SCRIPT_DIR}/apps/backup/lib-backup.sh"', read("health-check.sh"))


class HostCommand(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.tree = os.path.join(self.tmp, "tree")
        self.dir = os.path.join(self.tmp, "backups")
        os.makedirs(self.dir, mode=0o700)
        for rel in ("apps/backup/backups.sh", "apps/backup/lib-backup.sh", "infra/lib-log.sh",
                    "infra/lib-lock.sh", "infra/lib-mk8s.sh"):
            dst = os.path.join(self.tree, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(os.path.join(ROOT, rel), dst)
        write(os.path.join(self.tree, "config.env"),
              f'PROJECT_NAME="medcea"\nNAMESPACE="medcea"\nPOSTGRES_DB="medcea_db"\nPOSTGRES_PASS="{SENTINEL}"\n'
              f'BACKUP_DIR="{self.dir}"\nBACKUP_KEEP_DAYS="14"\n')
        self.bin = os.path.join(self.tmp, "bin")
        self.calls = os.path.join(self.tmp, "calls")
        write(os.path.join(self.bin, "microk8s"),
              '#!/bin/sh\necho "$*" >> "$CALLS"\ncase "$*" in\n'
              '  status*) exit 0 ;;\n'
              '  "kubectl get cronjob medcea-backup"*) echo cronjob.batch/medcea-backup ;;\n'
              '  "kubectl create job"*) ;;\n'
              '  "kubectl get job"*) printf "1 " ;;\n'
              '  "kubectl logs"*) echo "backup: OK: fake complete" ;;\n'
              '  *) exit 9 ;;\nesac\n', 0o755)
        e = int(time.time()) - 3600
        self.name = stamp(e)
        d = os.path.join(self.dir, self.name)
        write(os.path.join(d, "db", "medcea_db.dump"), "PGDMP\n")
        write(os.path.join(d, "volumes", "claim-alice.tar.gz"), "tar\n")
        subprocess.run("sha256sum db/medcea_db.dump volumes/claim-alice.tar.gz > SHA256SUMS", shell=True, cwd=d, check=True)
        write(os.path.join(d, "OK"), f"{e} x\n")
        self.head = "policy chain head (read before the dump): 41 " + "ab" * 32 + " verify_chain=t"
        write(os.path.join(d, "MANIFEST"), "# MedCEA backup\n# " + self.head + "\n")
        os.makedirs(os.path.join(self.dir, stamp(e + 60)))   # a later run without OK

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_cmd(self, *args):
        env = {"PATH": self.bin + ":/usr/bin:/bin", "CALLS": self.calls, "MEDCEA_NO_LOG": "1", "HOME": self.tmp}
        p = subprocess.run(["bash", os.path.join(self.tree, "apps/backup/backups.sh"), *args],
                           capture_output=True, text=True, env=env)
        self.assertNotIn(SENTINEL, p.stdout + p.stderr)
        return p

    def kubectl_calls(self):
        if not os.path.exists(self.calls):
            return ""
        with open(self.calls) as fh:
            return fh.read()

    def test_list(self):
        p = self.run_cmd("list")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertRegex(p.stdout, rf"{self.name} +complete")
        self.assertRegex(p.stdout, r"incomplete")
        self.assertIn(f"Newest complete: {self.name}", p.stdout)
        self.assertEqual(self.kubectl_calls(), "")

    def test_verify(self):
        p = self.run_cmd("verify")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(f"OK: {self.name}, 2 files match", p.stdout)
        # IAM 4.5: the chain head the job recorded, or that a folder from before 4.5 has none
        self.assertEqual(p.stdout.splitlines()[-1], self.head)
        os.remove(os.path.join(self.dir, self.name, "MANIFEST"))
        self.assertEqual(self.run_cmd("verify").stdout.splitlines()[-1],
                         "policy chain head: not recorded (a backup from before IAM 4.5)")
        write(os.path.join(self.dir, self.name, "volumes", "extra.tar.gz"), "x")
        p = self.run_cmd("verify", self.name)
        self.assertEqual(p.returncode, 1)
        self.assertIn("SHA256SUMS does not list: volumes/extra.tar.gz", p.stderr)
        os.remove(os.path.join(self.dir, self.name, "volumes", "extra.tar.gz"))
        write(os.path.join(self.dir, self.name, "db", "medcea_db.dump"), "changed\n")
        self.assertEqual(self.run_cmd("verify", self.name).returncode, 1)

    def test_verify_refuses(self):
        later = sorted(n for n in os.listdir(self.dir))[-1]
        p = self.run_cmd("verify", later)
        self.assertEqual(p.returncode, 1)
        self.assertIn("has no OK marker", p.stderr)
        p = self.run_cmd("verify", "../etc")
        self.assertEqual(p.returncode, 1)
        self.assertIn("is not a backup folder name", p.stderr)

    def test_restore_help_runs_nothing(self):
        p = self.run_cmd("restore-help")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.kubectl_calls(), "")
        out = p.stdout
        for part in ("A. The platform database (medcea_db)", "B. Keycloak", "C. One person's AI workbench home",
                     "D. Node-RED", "E. Grafana", f"{self.dir}/{self.name}/db/medcea_db.dump",
                     "DROP DATABASE IF EXISTS keycloak WITH (FORCE)", "./apps/database/deploy.sh",
                     'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")"'):
            self.assertIn(part, out)
        self.assertIn("This command runs none of them.", out)
        # IAM 4.2a (ops-2): step 2a moves the host's policy file aside, between the restore
        # and the database deploy (the refusals of policy_source_init and apply.sh name it)
        a2, a3 = out.index("  2a. (IAM 4.2a)"), out.index("  3. ./apps/database/deploy.sh")
        self.assertLess(out.index("  2. Drop it and restore it"), a2)
        self.assertLess(a2, a3)
        self.assertIn("bash -c 'source infra/lib-lock.sh && medcea_lock && source infra/lib-policy-source.sh"
                      " && policy_state_retire restore'", out[a2:a3])
        # IAM 4.5 (design §14.8.10): step 5 compares the restored chain with the recorded head
        a5 = out.index("  5. (IAM 4.5)")
        self.assertLess(a3, a5)
        self.assertLess(a5, out.index("B. Keycloak"))
        self.assertIn(f"({self.head})", out[a5:])
        self.assertIn("iam_policy.verify_chain()", out[a5:])

    def test_now(self):
        p = self.run_cmd("now", "--timeout", "10")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        calls = self.kubectl_calls()
        self.assertRegex(calls, r"kubectl create job medcea-backup-now-\d{8}-\d{6} --from=cronjob/medcea-backup -n medcea")
        self.assertIn("backup: OK: fake complete", p.stdout)
        self.assertIn("succeeded", p.stdout)

    def test_unknown(self):
        self.assertEqual(self.run_cmd("delete").returncode, 2)
        p = self.run_cmd("--help")
        self.assertEqual(p.returncode, 0)
        self.assertIn("restore-help", p.stdout)


class Static(unittest.TestCase):
    def test_uninstall_keeps_backup_dir(self):
        src = "\n".join(l for l in read("apps/backup/uninstall.sh").splitlines() if not l.lstrip().startswith("#"))
        self.assertNotRegex(src, r"\brm\b")
        self.assertIn("kept in", src)

    def test_component_and_config(self):
        for f in ("deploy.sh", "uninstall.sh"):
            self.assertTrue(os.access(os.path.join(APP, f), os.X_OK), f)
        ex = read("config.env.example")
        self.assertIn('BACKUP_DIR="/var/backups/$PROJECT_NAME"', ex)
        self.assertIn('BACKUP_KEEP_DAYS="14"', ex)
        deploy = read("apps/backup/deploy.sh")
        self.assertIn("install -d -m 700", deploy)
        self.assertIn("get secret rdbms-postgresql -n \"$NAMESPACE\" -o name", deploy)
        self.assertNotIn("POSTGRES_PASS", deploy)


if __name__ == "__main__":
    unittest.main()
