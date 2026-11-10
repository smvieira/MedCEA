#!/usr/bin/env python3
"""tests/test_health_phase5b.py — health-check.sh's Phase 5 round 2 checks.

Offline, with test_health_phase5.py's scratch tree and fake kubectl (read-only verbs only,
every call logged with its stdin). Nothing reaches a cluster, Keycloak or the repository's
state/.

  IamDrift       G6: access-api's drift counts read from its admin /healthz by one bounded
                 kubectl exec per Running access pod; FAIL on an unexplained role or a failed
                 compensation, WARN on the rest, SKIP without access, no names printed
  IamDriftProbe  the probe itself (python3, as the pod runs it) against a local stand-in
                 for the admin port serving access-api's own drift_status() shape
  IamAnchor      G12: the newest complete backup's MANIFEST chain head against
                 iam_policy.history (one read-only psql, the id as a psql variable); FAIL when
                 the event is missing or its hash differs, WARN without a readable anchor or
                 over 48 h, never sudo, never another backup folder
  IamCatalog     G14: owners, ENABLE ALWAYS triggers, security_invoker views; FAIL on any hit,
                 WARN when unreadable, SKIP before the database deploy
  CatalogParity  G14: every decision statement of iamcatalog is tests/iam-db.sh's, word for word

    python3 tests/test_health_phase5b.py
"""
import http.server
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from test_health_phase5 import Base, body, dep_rules, rule  # noqa: E402

PG = r"exec -i -n medcea rdbms-postgresql-0 -- env PGOPTIONS=-c default_transaction_read_only=on"


def probe_line(state="ok", age=120, accounts=7, unexp=0, ewp=0, comp=0, unrec=0, trunc=0, seeded=1, interval=600, err=""):
    if state != "ok":
        return state + "\n"
    return f"ok {age} {accounts} {unexp} {ewp} {comp} {unrec} {trunc} {seeded} {interval} {err}".rstrip() + "\n"


class IamDrift(Base):
    def scenario(self, lines=None, absent=False, pods=("access-1",)):
        rules = dep_rules("access", list(pods), absent=absent)
        for p in pods:
            rules.append(rule(rf"exec -n medcea {p} -c api -- python3 -c", (lines or {}).get(p, probe_line())))
        self.t.scenario(rules)

    def run_check(self):
        return self.t.fn("check_iamdrift", 'check_iamdrift "Account drift" medcea')

    def test_ok_gives_counts_and_age(self):
        self.scenario()
        self.assertEqual(self.run_check(),
                         "OK|Account drift|7 accounts: 0 unexplained roles, 0 failed compensations, 0 enabled while "
                         "pending, 0 unrecorded; computed 120 s ago (every 600 s)")
        ex = [c for c in self.t.calls() if c["argv"][0] == "exec"]
        self.assertEqual(len(ex), 1)
        self.assertEqual(ex[0]["argv"][:8], ["exec", "-n", "medcea", "access-1", "-c", "api", "--", "python3"])
        self.assertIn("http://127.0.0.1:8081/healthz", ex[0]["argv"][-1])
        self.assertReadOnly()

    def test_fail_on_unexplained_roles_and_failed_compensations(self):
        self.scenario({"access-1": probe_line(unexp=2, unrec=1)})
        r = self.run_check()
        self.assertTrue(r.startswith("FAIL|Account drift|2 platform role(s) no confirmed decision or signed-off review "
                                     "explains (User Manager → Decisions)"), r)
        self.assertIn(";1 enabled account(s) with no request, decision or status record and not seeded", r)
        self.scenario({"access-1": probe_line(comp=1)})
        self.assertTrue(self.run_check().startswith("FAIL|Account drift|1 failed compensation(s): Keycloak is wider "
                                                    "than the record"))

    def test_warnings(self):
        cases = {
            probe_line(ewp=1): "1 account(s) enabled while their grant or activation waits for qa",
            probe_line(unrec=3): "3 enabled account(s) with no request, decision or status record and not seeded",
            probe_line(age=1801): "the drift was computed 30 min ago (over 30 min)",
            probe_line(err="Keycloak answered HTTP 503"): "the last drift computation failed: Keycloak answered HTTP 503",
            probe_line(trunc=1): "Keycloak's account list was cut at access-api's ceiling",
            probe_line(seeded=0): "the seeded accounts could not be read: none is exempt",
            "predates\n": "this access-api predates the drift report: ./apps/access/deploy.sh",
            "notyet - - - - - - 0 - 600\n": "drift not computed yet (the access pod started recently; every 600 s)",
            "notyet - - - - - - 0 - 600 Keycloak unreachable (URLError)\n":
                "drift not computed yet; its last attempt failed: Keycloak unreachable (URLError)",
            "unreachable\n": "access-api's admin /healthz does not answer in pod access-1",
            "": "cannot read the drift report in pod access-1",
            "ok x y\n": "cannot read the drift report in pod access-1",
        }
        for line, want in cases.items():
            self.scenario({"access-1": line})
            r = self.run_check()
            self.assertTrue(r.startswith("WARN|Account drift|"), (line, r))
            self.assertIn(want, r, line)
        # exactly 30 min is still fresh
        self.scenario({"access-1": probe_line(age=1800)})
        self.assertTrue(self.run_check().startswith("OK|"))

    def test_skip_without_access_and_several_pods(self):
        self.scenario(absent=True)
        self.assertEqual(self.run_check(), "SKIP|Account drift|access is not deployed (./apps/access/deploy.sh)")
        self.scenario(pods=())
        self.assertEqual(self.run_check(), "WARN|Account drift|no Running access pod: the drift report cannot be read")
        self.scenario({"access-2": probe_line(unexp=1)}, pods=("access-1", "access-2"))
        r = self.run_check()
        self.assertTrue(r.startswith("FAIL|Account drift|pod access-2: 1 platform role(s)"), r)
        self.assertEqual(len([c for c in self.t.calls() if c["argv"][0] == "exec"]), 2)

    def test_bounded_and_wired(self):
        src = body("check_iamdrift")
        self.assertIn('timeout "$TIMEOUT" $KUBECTL exec -n "$ns" "$pod" -c api -- python3 -c "$probe"', src)
        self.assertIn("timeout=4", src)
        with open(os.path.join(REPO, "health-check.sh")) as f:
            self.assertIn('iamdrift)     check_iamdrift "$name" "$target" ;;', f.read())


# ── G12: the history chain anchor ───────────────────────────────────────────────────────
HASH = "ab" * 32


class IamAnchor(Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        os.makedirs(cls.t.path("apps", "backup"), exist_ok=True)
        shutil.copy(os.path.join(REPO, "apps", "backup", "lib-backup.sh"), cls.t.path("apps", "backup", "lib-backup.sh"))

    def setUp(self):
        self.dir = self.t.path("backups")
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir, mode=0o700)

    def backup(self, hours_ago=3, head=f"# policy chain head (read before the dump): 41 {HASH} verify_chain=t", ok=True,
               manifest=True):
        import time
        e = int(time.time()) - int(hours_ago * 3600)
        d = os.path.join(self.dir, time.strftime("%Y%m%d-%H%M%SZ", time.gmtime(e)))
        os.makedirs(d)
        if manifest:
            with open(os.path.join(d, "MANIFEST"), "w") as f:
                f.write("# MedCEA backup\n# namespace: medcea\n" + (head + "\n" if head else "") + "# bytes\tsha256\tpath\n")
        if ok:
            with open(os.path.join(d, "OK"), "w") as f:
                f.write(f"{e} x\n")
        return d

    def run_check(self, out="anchor|%s|3\n" % HASH, rc=0, err="", backup_dir=None):
        self.t.scenario([rule(PG, out, rc, err, stdin=r"iam_policy\.history")])
        return self.t.fn("check_iamanchor", f'source "{self.t.root}/apps/backup/lib-backup.sh"\n'
                         'check_iamanchor "History chain anchor" medcea_db', helpers=(),
                         BACKUP_DIR=backup_dir or self.dir)

    def test_ok_names_the_event_and_age(self):
        self.backup(30)
        self.backup(3)
        self.backup(1, ok=False)           # a run without OK is no anchor
        r = self.run_check()
        self.assertEqual(r, "OK|History chain anchor|event 41 has the hash backup %s recorded (3 h old), 3 event(s) since"
                         % sorted(os.listdir(self.dir))[1])
        calls = self.t.calls()
        self.assertEqual(len(calls), 1)
        c = calls[0]
        self.assertEqual(c["argv"][:6], ["exec", "-i", "-n", "medcea", "rdbms-postgresql-0", "--"])
        self.assertIn("PGOPTIONS=-c default_transaction_read_only=on -c client_min_messages=warning", c["argv"])
        self.assertEqual(c["argv"][-2:], ["medcea_db", "41"])
        self.assertIn('-v "anchor_id=$1"', c["argv"][-3])
        self.assertIn("WHERE h.event_id = :anchor_id", c["stdin"])
        self.assertNotIn(HASH, " ".join(c["argv"]) + c["stdin"])
        self.assertReadOnly()

    def test_fail_when_cut_or_rewritten(self):
        self.backup(3)
        r = self.run_check("anchor|-|0\n")
        self.assertTrue(r.startswith("FAIL|History chain anchor|event 41, the chain head backup "), r)
        self.assertIn("is missing from iam_policy.history", r)
        r = self.run_check("anchor|%s|0\n" % ("cd" * 32))
        self.assertTrue(r.startswith("FAIL|History chain anchor|event 41's hash is cdcdcdcdcdcd..., backup "), r)
        self.assertIn("recorded abababababab...: the history was rewritten", r)
        r = self.run_check("nohistory\n")
        self.assertTrue(r.startswith("FAIL|History chain anchor|backup "), r)
        self.assertIn("anchors event 41, but medcea_db has no iam_policy.history", r)
        # old, but cut: the FAIL wins
        self.backup(100)
        self.assertTrue(self.run_check("anchor|-|0\n").startswith("FAIL|"))

    def test_backup_of_an_earlier_database_warns(self):
        # BACKUP_DIR outlives a new install or --purge-data: the newest complete backup then
        # comes from an earlier database whose chain restarted at event 1. Its first event
        # (h.at of the lowest event_id) is newer than the backup's OK: WARN, not FAIL.
        import time
        self.backup(3)
        now = int(time.time())
        for out in ("anchor|-|0|%d\n" % now, "anchor|%s|9|%d\n" % ("cd" * 32, now)):
            r = self.run_check(out)
            self.assertTrue(r.startswith("WARN|History chain anchor|no anchor: the newest complete backup "), r)
            self.assertIn("predates this database", r)
        self.assertIn("ORDER BY h.event_id LIMIT 1", self.t.calls()[-1]["stdin"])
        # a restore from an older backup keeps the old first event: still FAIL
        old = now - 30 * 86400
        self.assertTrue(self.run_check("anchor|-|0|%d\n" % old).startswith("FAIL|"))
        self.assertTrue(self.run_check("anchor|%s|0|%d\n" % ("cd" * 32, old)).startswith("FAIL|"))
        # a matching hash is this chain whatever the first event says
        self.assertTrue(self.run_check("anchor|%s|3|%d\n" % (HASH, now)).startswith("OK|"))

    def test_warnings(self):
        self.backup(49)
        r = self.run_check()
        self.assertTrue(r.startswith("WARN|History chain anchor|event 41 has the hash backup "), r)
        self.assertIn("is 49 h old (over 48 h: ./apps/backup/backups.sh list)", r)
        shutil.rmtree(self.dir); os.makedirs(self.dir)
        self.backup(3, head=f"# policy chain head (read before the dump): 41 {HASH} verify_chain=f")
        self.assertIn("the chain did not verify when backup", self.run_check())
        cases = [
            (dict(head="# policy chain head: unavailable (psql exit 2: could not connect)"),
             "could not read the chain head (psql exit 2: could not connect)"),
            (dict(head="# policy chain head: unavailable (iam_policy.history is empty)"),
             "could not read the chain head (iam_policy.history is empty)"),
            (dict(head=None), "records no chain head (a backup from before IAM 4.5)"),
            (dict(head="# policy chain head (read before the dump): 41 ZZ verify_chain=t"),
             "could not read the chain head (an unexpected chain head line in MANIFEST)"),
            (dict(head="# policy chain head (read before the dump): 41; DROP TABLE x verify_chain=t"),
             "an unexpected chain head line"),
            (dict(manifest=False), "cannot read the MANIFEST of backup"),
            (dict(ok=False), "no complete backup in"),
        ]
        for kw, want in cases:
            shutil.rmtree(self.dir); os.makedirs(self.dir)
            self.backup(3, **kw)
            r = self.run_check()
            self.assertTrue(r.startswith("WARN|History chain anchor|no anchor: "), (kw, r))
            self.assertIn(want, r, kw)
            self.assertEqual(self.t.calls(), [], kw)     # no database read without an anchor
        self.assertIn("(BACKUP_DIR) does not exist", self.run_check(backup_dir=self.t.path("nope")))
        os.chmod(self.dir, 0)
        try:
            if not os.access(self.dir, os.R_OK):         # root reads anything
                self.assertIn("cannot read", self.run_check())
        finally:
            os.chmod(self.dir, 0o700)
        shutil.rmtree(self.dir); os.makedirs(self.dir)
        self.backup(3)
        r = self.run_check("", rc=2, err="psql: error: connection to server failed\n")
        self.assertTrue(r.startswith("WARN|History chain anchor|cannot read iam_policy.history"), r)
        self.assertIn("psql: error: connection", r)

    def test_wired(self):
        src = body("check_iamanchor")
        self.assertIn('timeout "$TIMEOUT" $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0', src)
        self.assertIn("default_transaction_read_only=on", src)
        self.assertIn('backup_newest_ok "$dir"', src)
        self.assertIn('backup_chain_head "$dir/$bname"', src)
        self.assertNotIn("sudo", src)
        with open(os.path.join(REPO, "health-check.sh")) as f:
            self.assertIn('iamanchor)  check_iamanchor "$name" "$target" ;;', f.read())


# ── G14: the catalog ────────────────────────────────────────────────────────────────────
def catalog_out(owner=0, ownernames="", iam=(0, 9, ""), invoker=0, invokernames="", always="", unit="A", comm="A"):
    lines = [f"owner|{owner}", f"ownernames|{ownernames}", "iamalways|%d|%d|%s" % iam, f"invoker|{invoker}",
             f"invokernames|{invokernames}", f"always|{always}"]
    if unit is not None:
        lines.append(f"unitalways|{unit}")
    if comm is not None:
        lines.append(f"commalways|{comm}")
    return "\n".join(lines) + "\n"


class IamCatalog(Base):
    def run_check(self, out=None, rc=0, err=""):
        self.t.scenario([rule(PG, catalog_out() if out is None else out, rc, err, stdin="medcea_owner")])
        return self.t.fn("check_iamcatalog", 'check_iamcatalog "Database catalog" medcea_db', helpers=())

    def test_ok(self):
        self.assertEqual(self.run_check(), "OK|Database catalog|every object owned by medcea_owner, 9 iam and all "
                         "append-only triggers ENABLE ALWAYS, every medcea view security_invoker")
        c = self.t.calls()
        self.assertEqual(len(c), 1)
        self.assertIn("PGOPTIONS=-c default_transaction_read_only=on -c client_min_messages=warning", c[0]["argv"])
        self.assertEqual(c[0]["argv"][-1], "medcea_db")
        self.assertReadOnly()
        # a database without the unit or commissioning trigger is not a hit
        self.assertTrue(self.run_check(catalog_out(unit=None, comm=None)).startswith("OK|"))

    def test_every_hit_fails_and_names_the_first_five(self):
        r = self.run_check(catalog_out(owner=7, ownernames="medcea.a medcea.b medcea.c medcea.d medcea.e"))
        self.assertEqual(r, "FAIL|Database catalog|7 object(s) not owned by medcea_owner: medcea.a medcea.b medcea.c "
                         "medcea.d medcea.e ... (./apps/database/deploy.sh; then find who changed it)")
        r = self.run_check(catalog_out(iam=(2, 9, "account_decision.freeze_trg,config_history.config_history_append_only")))
        self.assertIn("2 iam freeze/append-only trigger(s) not ENABLE ALWAYS: account_decision.freeze_trg,"
                      "config_history.config_history_append_only", r)
        self.assertTrue(r.startswith("FAIL|"))
        r = self.run_check(catalog_out(always="a.x_append_only,b.x_append_only,c.x_no_truncate,d.y,e.y,f.y"))
        self.assertIn("append-only/no-truncate trigger(s) not ENABLE ALWAYS: a.x_append_only,b.x_append_only,"
                      "c.x_no_truncate,d.y,e.y,...", r)
        self.assertIn("user_unit_audit_trg is tgenabled 'O', not ENABLE ALWAYS", self.run_check(catalog_out(unit="O")))
        self.assertIn("commissioning_history_trg is tgenabled 'D'", self.run_check(catalog_out(comm="D")))
        r = self.run_check(catalog_out(invoker=1, invokernames="v_measurement"))
        self.assertEqual(r, "FAIL|Database catalog|1 medcea view(s) without security_invoker: v_measurement "
                         "(./apps/database/deploy.sh; then find who changed it)")
        r = self.run_check(catalog_out(owner=1, ownernames="schema:medcea", invoker=1, invokernames="v"))
        self.assertIn("medcea_owner: schema:medcea;1 medcea view(s) without security_invoker: v (", r)

    def test_skip_and_unreadable(self):
        self.assertEqual(self.run_check("nodb\n"),
                         "SKIP|Database catalog|no role medcea_owner or schema medcea in medcea_db yet (./apps/database/deploy.sh)")
        for out, rc in (("", 2), ("owner|0\n", 0), ("psql:<stdin>:3: ERROR:  permission denied\n", 3)):
            r = self.run_check(out, rc)
            self.assertTrue(r.startswith("WARN|Database catalog|cannot read the catalog of medcea_db"), (out, r))

    def test_wired(self):
        src = body("check_iamcatalog")
        self.assertIn('timeout "$TIMEOUT" $KUBECTL exec -i -n "$NAMESPACE" rdbms-postgresql-0', src)
        self.assertIn("default_transaction_read_only=on", src)
        self.assertIn("ON_ERROR_STOP=1", src)
        with open(os.path.join(REPO, "health-check.sh")) as f:
            self.assertIn('iamcatalog) check_iamcatalog "$name" "$target" ;;', f.read())


def _statements(sql):
    """label -> statement (whitespace collapsed) for every SELECT 'label' … ; of a SQL text."""
    sql = "\n".join(l for l in sql.splitlines() if not l.lstrip().startswith(("--", "\\")))
    out = {}
    for m in re.finditer(r"(?s)SELECT '([a-z]+)'.*?;", sql):
        out.setdefault(m.group(1), " ".join(m.group(0).split()))
    return out


class CatalogParity(unittest.TestCase):
    """iamcatalog's decision statements are tests/iam-db.sh's catalog statements, word for word:
    a predicate changed in one place and not the other fails here."""
    SHARED = ("owner", "iamalways", "invoker", "always", "unitalways", "commalways")

    def test_same_statements(self):
        with open(os.path.join(HERE, "iam-db.sh")) as f:
            src = f.read()
        a = src.index("# ── catalog ──")
        fixture = _statements(src[src.index("<<'SQL'", a) + 7:src.index("\nSQL\n", a)])
        hc = body("check_iamcatalog")
        health = _statements(hc[hc.index("<<'SQL'") + 7:hc.index("\nSQL\n")])
        for label in self.SHARED:
            self.assertIn(label, fixture, label)
            self.assertEqual(health.get(label), fixture[label], label)
        # and nothing else decides: the names lines only feed the message
        self.assertEqual(set(health) - set(self.SHARED), {"ownernames", "invokernames", "nodb"})


class ManagedFieldsReads(unittest.TestCase):
    """kubectl 1.21 and later drop managedFields from what `get` prints unless
    --show-managed-fields is given: every read of a write time asks for them (health-check's
    round-1 fix, and tests/iam-hosts.sh's Grafana and proxy pod-age checks)."""

    def test_every_managed_fields_read_asks_for_them(self):
        for f in ("tests/iam-hosts.sh", "health-check.sh"):
            with open(os.path.join(REPO, f)) as fh:
                logical = re.sub(r"\\\n\s*", " ", fh.read()).splitlines()
            for l in logical:
                if re.search(r"\$KUBECTL get ", l) and "managedFields" in l:
                    self.assertIn("--show-managed-fields", l, (f, l))
        self.assertIn("get configmap medcea-iam-lib -n \"$ns\" -o json --show-managed-fields", body("_iamlib_meta"))
        with open(os.path.join(REPO, "tests/iam-hosts.sh")) as fh:
            src = fh.read()
        self.assertIn('get deployment grafana -n "$NAMESPACE" -o json --show-managed-fields', src)
        self.assertEqual(src.count("--show-managed-fields \\\n                    -o jsonpath='{range .metadata.managedFields[*]}"), 2)


# ── the probe as the pod runs it ────────────────────────────────────────────────────────
def _load_access_api():
    spec = importlib.util.spec_from_file_location("access_api_5b", os.path.join(REPO, "apps", "access", "access-api.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class IamDriftProbe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = _load_access_api()
        cls.payload = {}
        test = cls

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                b = json.dumps(test.payload).encode()
                self.send_response(200 if self.path == "/healthz" else 404)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def log_message(self, *a):
                pass
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        probe = re.search(r"(?s)local probe='(.*?)'\n", body("check_iamdrift")).group(1)
        cls.probe = probe.replace("127.0.0.1:8081", "127.0.0.1:%d" % cls.srv.server_address[1])

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def run_probe(self, payload):
        type(self).payload = payload
        p = subprocess.run([sys.executable, "-I", "-c", self.probe], capture_output=True, text=True, timeout=30)
        return p.stdout.strip()

    def healthz(self, **drift):
        api = self.api
        saved = dict(api._drift)
        try:
            api._drift.update(drift)
            return {"ok": True, "access_version": api.ACCESS_VERSION, "enforce_always": True, "drift": api.drift_status()}
        finally:
            api._drift.clear()
            api._drift.update(saved)

    def test_access_apis_own_shape(self):
        import time
        counts = dict.fromkeys(self.api.DRIFT_KINDS, 0)
        counts.update(unexplained_role=2, unrecorded_account=1)
        out = self.run_probe(self.healthz(computed_at=time.time() - 65, accounts=9, counts=counts, seeded_readable=True))
        f = out.split()
        self.assertEqual(f[0], "ok")
        self.assertIn(int(f[1]), range(64, 70))
        self.assertEqual(f[2:], ["9", "2", "0", "0", "1", "0", "1", str(self.api.DRIFT_INTERVAL)])

    def test_not_yet_predates_and_unreachable(self):
        self.assertEqual(self.run_probe(self.healthz()).split()[0], "notyet")
        self.assertEqual(self.run_probe({"ok": True, "access_version": "2.7", "enforce_always": True}), "predates")
        type(self).payload = {}
        p = subprocess.run([sys.executable, "-I", "-c", self.probe.replace(
            "127.0.0.1:%d" % self.srv.server_address[1], "127.0.0.1:9")], capture_output=True, text=True, timeout=30)
        self.assertEqual(p.stdout.strip(), "unreachable")

    def test_the_error_text_is_reduced_to_safe_characters(self):
        import time
        out = self.run_probe(self.healthz(computed_at=time.time(), accounts=1, counts=dict.fromkeys(self.api.DRIFT_KINDS, 0),
                                          live_error='database refused (SQLSTATE 42501) "x";|$(id)\n' + "y" * 200))
        err = out.split(None, 10)[10]
        self.assertTrue(err.startswith("database refused (SQLSTATE 42501) x(id)yyy"), out)
        self.assertEqual(len(err), 80)
        for c in '";|$':
            self.assertNotIn(c, out)
        self.assertEqual(len(out.splitlines()), 1)


class SeededAdmin(unittest.TestCase):
    """The platform admin is a seeded account (owner decision, Phase 5 round 2): deploy-infra
    records it like the first qa person and engineer, so iamdrift neither counts it as
    unrecorded nor its admin role as unexplained."""

    def setUp(self):
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "..", "deploy-infra.sh"), encoding="utf-8") as f:
            self.src = f.read()

    def test_the_backfill_loop_lists_the_admin(self):
        self.assertIn('for _su in "${QA_USER:-}" "${ENGINEER_USER:-}" "${ADMIN_USER:-}"; do', self.src)

    def test_a_created_admin_gets_a_created_fact_after_the_seed_setup(self):
        setup = self.src.index('_SEED_RUN="$(mktemp)"')
        fact = self.src.index('_seed_fact created "$ADMIN_USER"')
        granted = self.src.index('[[ "$_ADMIN_NEW" == 1 ]] && _assign_realm_role "$ADMIN_USER" "admin"')
        self.assertLess(setup, fact)
        self.assertLess(granted, fact)
        block = self.src[self.src.rindex("\nif ", 0, fact):fact]
        self.assertIn('"${_ADMIN_NEW:-0}" == 1', block)
        self.assertIn('_SEED_CREATED+="$ADMIN_USER "', block)
        self.assertIn('admin ""', self.src[fact:fact + 300])


if __name__ == "__main__":
    unittest.main()
