#!/usr/bin/env python3
"""tests/test_health_phase5.py — health-check.sh's Phase 5 checks and fixes (gaps G1-G13).

Offline. Each check runs in a scratch tree (tests/_scratch.py) against a fake kubectl and a
fake curl on PATH: the fake answers from a list of rules (a regex over the argv, optionally
one over stdin), refuses every writing verb and logs each call with the stdin it was given.
The check functions are taken out of health-check.sh with their helpers, as
tests/test_health_policy.py does. Nothing reaches a cluster, Keycloak or the repository's
state/.

  IamGrantsSkip     G1: a P0001 drift whose DETAIL names a medcea_auth function FAILs; only
                    the first ERROR line's two 008b errors SKIP
  IamGrantsClassify G4: the assertion set in the OK text; an unclassified table under
                    IAM_DB_ROLES=false WARNs; classify-sql's predicate is grants' I15 one
  Jwks              G3: Secret medcea-jwks against the realm's certs (FAIL both ways, WARN
                    when the realm does not answer), jwks-sig.json = signing_keys(jwks.json);
                    postgrest no longer compares key ids
  KcScopes          G2: Keycloak's database, read-only; FAIL on API clients, WARN on tools
  IamLoaded         G5: per pod routes digest, the 120 s window, enforcing services, absent ones
  IamMqttDigest     G7: every iam-api pod's mqtt_digest against the ConfigMap
  NodeRedFlowsGit   G9: an uncommitted flow file WARNs
  IamNetpol         G10: the labelled NetworkPolicies against the compile
  IamEnforceSwitches G11: settings.json's switches against config.env; no enforce key FAILs
  IamChainDefiner   G13: verify_chain() SECURITY DEFINER and iam_svc's EXECUTE

    python3 tests/test_health_phase5.py
"""
import base64
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "apps", "iam"))

from _scratch import clean_env, scratch_repo  # noqa: E402

import apply_check  # noqa: E402
from compiler import grants, model  # noqa: E402

FAKE = r'''#!/usr/bin/env python3
# A fake kubectl / microk8s / curl for tests/test_health_phase5.py: read-only verbs only.
import json, os, re, sys
FD = os.environ["FAKE_DIR"]
sc = json.load(open(os.path.join(FD, "scenario.json")))
me = os.path.basename(sys.argv[0])
a = sys.argv[1:]
if me == "microk8s":
    a = a[1:]
stdin = "" if sys.stdin.isatty() else sys.stdin.read()
with open(os.path.join(FD, "calls.log"), "a") as f:
    f.write(json.dumps({"tool": me, "argv": a, "stdin": stdin}) + "\n")
line = " ".join(a)
if me == "curl":
    if "-m" not in a:
        print("fake curl: unbounded call", file=sys.stderr)
        sys.exit(98)
    if "realm" in sc:
        sys.stdout.write(sc["realm"])
        sys.exit(0)
    sys.exit(7)
verb = next((x for i, x in enumerate(a) if x != "-n" and (i == 0 or a[i - 1] != "-n")), "")
if verb not in ("get", "exec", "version"):
    print(f"fake kubectl: refusing to {verb}", file=sys.stderr)
    sys.exit(99)
if verb == "version":
    sys.exit(0)
for r in sc.get("rules", []):
    if re.search(r["argv"], line) and re.search(r.get("stdin", ""), stdin, re.S):
        out = r.get("out", "")
        if verb == "get" and "--show-managed-fields" not in a and out.startswith("{"):
            # real kubectl (1.21 and later) leaves managedFields out of -o json/yaml
            try:
                doc = json.loads(out)
                (doc.get("metadata") or {}).pop("managedFields", None)
                out = json.dumps(doc)
            except Exception:
                pass
        sys.stdout.write(out)
        sys.stderr.write(r.get("err", ""))
        sys.exit(r.get("rc", 0))
if verb == "get":
    print("Error from server (NotFound): not found", file=sys.stderr)
    sys.exit(1)
print("fake kubectl: no rule for " + line, file=sys.stderr)
sys.exit(1)
'''

HELPERS = ("_iamlib_meta", "_iamlib_since", "_running_pods")


def body(fn, src=None):
    if src is None:
        with open(os.path.join(REPO, "health-check.sh")) as f:
            src = f.read()
    return re.search(rf"(?ms)^{fn}\(\) \{{.*?^\}}", src).group(0)


def iso(seconds_ago):
    t = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=seconds_ago)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def rule(argv, out="", rc=0, err="", stdin=""):
    return {"argv": argv, "out": out, "rc": rc, "err": err, "stdin": stdin}


class Tree:
    def __init__(self):
        self.root = scratch_repo("medcea-health5-")
        for f in ("health-check.sh", "infra/jwks-sig.py"):
            shutil.copy(os.path.join(REPO, f), os.path.join(self.root, f))
        self.fd = os.path.join(self.root, ".fake")
        self.bin = os.path.join(self.fd, "bin")
        os.makedirs(self.bin)
        fake = os.path.join(self.fd, "fake.py")
        with open(fake, "w") as f:
            f.write(FAKE)
        os.chmod(fake, 0o755)
        for n in ("kubectl", "microk8s", "curl"):
            os.symlink(fake, os.path.join(self.bin, n))
        self.scenario()

    def path(self, *p):
        return os.path.join(self.root, *p)

    def scenario(self, rules=(), **sc):
        sc["rules"] = list(rules)
        with open(os.path.join(self.fd, "scenario.json"), "w") as f:
            json.dump(sc, f)
        try:
            os.remove(os.path.join(self.fd, "calls.log"))
        except FileNotFoundError:
            pass

    def calls(self):
        try:
            with open(os.path.join(self.fd, "calls.log")) as f:
                return [json.loads(x) for x in f]
        except FileNotFoundError:
            return []

    def fn(self, fn, call, helpers=HELPERS, **env):
        with open(self.path("health-check.sh")) as f:
            src = f.read()
        defs = "\n".join(body(h, src) for h in helpers)
        script = (f'_record() {{ echo "$1|$2|$3"; }}\nSCRIPT_DIR={self.root}\nTIMEOUT=5\nKUBECTL=kubectl\n'
                  f'NAMESPACE=medcea\nsource "$SCRIPT_DIR/infra/lib-policy-source.sh"\n{defs}\n{body(fn, src)}\n{call}\n')
        e = clean_env(PATH=self.bin + os.pathsep + os.environ["PATH"], FAKE_DIR=self.fd, MEDCEA_NO_LOG="1")
        for k in ("IAM_ENFORCE", "IAM_GATES", "IAM_NETPOL", "IAM_POSTGREST_JWT", "IAM_MQTT_PERSON", "IAM_DB_ROLES",
                  "KEYCLOAK_REALM", "MEDCEA_LOG_FILE"):
            e.pop(k, None)
        e.update(env)
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=e, timeout=300,
                           stdin=subprocess.DEVNULL)
        return p.stdout.strip()

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = Tree()

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def assertReadOnly(self):
        for c in self.t.calls():
            if c["tool"] != "curl":
                self.assertIn(c["argv"][0], ("get", "exec", "version"), c)


# ── G1, G4: iamgrants ──────────────────────────────────────────────────────────────────
FLAG = rule(r"to_regnamespace\('iam'\)", "t|t|t|t\n")


class IamGrantsSkip(Base):
    def run_check(self, out, rc):
        self.t.scenario([FLAG, rule(r"rdbms-postgresql-0", out, rc, stdin="grants verified")])
        return self.t.fn("check_iamgrants", 'check_iamgrants "Database grants" medcea_db', helpers=())

    def test_a_medcea_auth_function_in_detail_is_drift(self):
        out = ("psql:<stdin>:412: ERROR:  I15/I10/I9: the catalog differs from the compiled policy\n"
               "DETAIL:  missing: anon EXECUTE function medcea_auth.pre_request() | not compiled: -\n"
               "CONTEXT:  PL/pgSQL function inline_code_block line 12 at RAISE\n")
        r = self.run_check(out, 3)
        self.assertTrue(r.startswith("FAIL|Database grants|grant drift: "), r)
        self.assertIn("I15/I10/I9", r)
        # an extra rr_/svc_ EXECUTE on set_actor is drift too
        out = ("ERROR:  I15 (managed roles): the catalog differs from the compiled policy\n"
               "DETAIL:  missing: - | not compiled: svc_monitor EXECUTE function medcea_auth.set_actor(text,text,text,text)\n")
        self.assertTrue(self.run_check(out, 3).startswith("FAIL|"))

    def test_only_the_first_error_decides_a_skip(self):
        for out in ('psql:<stdin>:2: ERROR:  relation "medcea.platform_setting" does not exist\nLINE 1: ...\n',
                    "ERROR:  function medcea_auth.role_widening(text, text) does not exist\n"):
            self.assertEqual(self.run_check(out, 3),
                             "SKIP|Database grants|migration 008b not applied yet (./apps/database/deploy.sh)")
        # the 008b text only further down (a DETAIL or a later ERROR) is still drift
        out = ("ERROR:  a managed role holds rr_operator DELETE medcea.recipe\n"
               "ERROR:  function medcea_auth.x() does not exist\n")
        self.assertTrue(self.run_check(out, 3).startswith("FAIL|"))

    def test_read_only_and_one_session(self):
        self.run_check("t\ngrants verified\nmode|t\n", 0)
        execs = [c for c in self.t.calls() if c["argv"][0] == "exec" and "grants verified" in c["stdin"]]
        self.assertEqual(len(execs), 1)
        self.assertIn("-c default_transaction_read_only=on -c client_min_messages=warning", " ".join(execs[0]["argv"]))
        self.assertIn("SELECT 'mode|' || :'iam_enforcing';", execs[0]["stdin"])
        self.assertReadOnly()


class IamGrantsClassify(Base):
    def run_check(self, out):
        self.t.scenario([FLAG, rule(r"rdbms-postgresql-0", out, 0, stdin="grants verified")])
        return self.t.fn("check_iamgrants", 'check_iamgrants "Database grants" medcea_db', helpers=())

    def test_the_ok_text_names_the_assertion_set(self):
        self.assertEqual(self.run_check("grants verified\nmode|t\n"),
                         "OK|Database grants|database grants equal the compiled policy (IAM_DB_ROLES=true: every "
                         "grantee, RLS, triggers and classification)")
        self.assertEqual(self.run_check("grants verified\nmode|f\n"),
                         "OK|Database grants|database grants equal the compiled policy (IAM_DB_ROLES=false: "
                         "managed-role and legacy set only)")

    def test_an_unclassified_table_under_false_warns(self):
        r = self.run_check("grants verified\nmode|f\nunclassified|2|medcea.new_table, medcea.v_new\n")
        self.assertTrue(r.startswith("WARN|Database grants|grants equal the compiled policy (IAM_DB_ROLES=false"), r)
        self.assertIn("2 medcea object(s) belong to no group: medcea.new_table, medcea.v_new", r)

    def test_classify_sql_is_i15s_predicate_and_reads_only(self):
        p = model.load_defaults()
        for wi in (False, True):
            cls = apply_check.classify_sql(p, wi)
            verify = grants.sql(p, "verify", without_iam=wi)
            for needle in ("WHERE n.nspname IN", "AND NOT (c.oid = ANY"):
                line = next(x for x in cls.splitlines() if needle in x).strip()
                self.assertIn(line, verify, (wi, needle))
            self.assertNotRegex(cls, r"(?i)\b(insert|update|delete|create|alter|drop|grant|revoke)\b")
            self.assertIn("\\if :iam_enforcing\n\\else\n", cls)
            self.assertTrue(cls.rstrip().endswith("\\endif"))

    def test_the_compiled_verify_sql_does_not_carry_it(self):
        """The recorded grants-verify target stays what every applied version recorded."""
        verify = grants.sql(model.load_defaults(), "verify")
        self.assertNotIn("unclassified|", verify)
        self.assertNotIn("mode|", verify)


# ── G3: jwks ───────────────────────────────────────────────────────────────────────────
def jwk(kid, use="sig", alg="RS256"):
    return {"kty": "RSA", "kid": kid, "use": use, "alg": alg, "n": "n-" + kid, "e": "AQAB", "x5c": ["x"]}


def sig_of(keys):
    sys.path.insert(0, os.path.join(REPO, "infra"))
    import importlib.util
    spec = importlib.util.spec_from_file_location("jwks_sig", os.path.join(REPO, "infra", "jwks-sig.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return {"keys": mod.signing_keys({"keys": keys})}


def secret(full, sig=None, drop=()):
    sig = sig_of(full) if sig is None else sig
    data = {"jwks.json": json.dumps({"keys": full}), "jwks-sig.json": json.dumps(sig, sort_keys=True)}
    return json.dumps({"kind": "Secret", "data": {k: base64.b64encode(v.encode()).decode()
                                                  for k, v in data.items() if k not in drop}})


class Jwks(Base):
    KEYS = [jwk("kidA"), jwk("encB", use="enc", alg="RSA-OAEP")]

    def run_check(self, sec, realm=None, svc=True):
        rules = [rule(r"get secret medcea-jwks -n medcea -o json", sec)] if sec else \
                [rule(r"get secret medcea-jwks", "", 1, 'Error from server (NotFound): secrets "medcea-jwks" not found\n')]
        if svc:
            rules.append(rule(r"get svc keycloak", "10.0.0.5"))
        kw = {} if realm is None else {"realm": json.dumps({"keys": realm})}
        self.t.scenario(rules, **kw)
        return self.t.fn("check_jwks", 'check_jwks "Realm signing keys" medcea', helpers=())

    def test_ok(self):
        r = self.run_check(secret(self.KEYS), self.KEYS)
        self.assertEqual(r, "OK|Realm signing keys|1 signing key(s) (kidA) equal the realm's; jwks-sig.json = "
                            "jwks.json's signing keys")
        curl = [c for c in self.t.calls() if c["tool"] == "curl"]
        self.assertEqual(len(curl), 1)
        self.assertIn("http://10.0.0.5/realms/medcea/protocol/openid-connect/certs", curl[0]["argv"])
        self.assertReadOnly()
        # the Secret reaches python on stdin: never an argument of anything the check runs
        self.assertFalse(any("n-kidA" in " ".join(c["argv"]) for c in self.t.calls()))

    def test_a_new_realm_signing_kid_fails(self):
        r = self.run_check(secret(self.KEYS), self.KEYS + [jwk("kidNEW")])
        self.assertTrue(r.startswith("FAIL|Realm signing keys|the realm signs with key id(s) Secret medcea-jwks "
                                     "lacks: kidNEW"), r)
        self.assertIn("(./deploy-infra.sh)", r)

    def test_a_kid_the_realm_dropped_fails(self):
        r = self.run_check(secret(self.KEYS + [jwk("kidOLD")]), self.KEYS)
        self.assertTrue(r.startswith("FAIL|Realm signing keys|Secret medcea-jwks holds key id(s) the realm no "
                                     "longer publishes: kidOLD"), r)

    def test_sig_not_the_signing_keys_of_full(self):
        r = self.run_check(secret(self.KEYS + [jwk("kidC")], sig=sig_of(self.KEYS)), self.KEYS + [jwk("kidC")])
        self.assertTrue(r.startswith("FAIL|Realm signing keys|jwks-sig.json is not the RS256 signing keys of "
                                     "jwks.json"), r)

    def test_secret_problems_fail(self):
        self.assertTrue(self.run_check(None, self.KEYS).startswith(
            "FAIL|Realm signing keys|Secret medcea-jwks is missing in medcea"))
        r = self.run_check(secret(self.KEYS, drop=("jwks-sig.json",)), self.KEYS)
        self.assertTrue(r.startswith("FAIL|Realm signing keys|Secret medcea-jwks has no jwks-sig.json"), r)
        enc = [jwk("encB", use="enc", alg="RSA-OAEP")]
        r = self.run_check(secret(enc, sig={"keys": []}), self.KEYS)
        self.assertIn("jwks.json in Secret medcea-jwks holds no RS256 signing key", r)
        self.assertTrue(r.startswith("FAIL|"), r)

    def test_realm_unreachable_warns_and_does_not_blame_the_secret(self):
        for svc in (True, False):
            r = self.run_check(secret(self.KEYS), None, svc=svc)
            self.assertEqual(r, "WARN|Realm signing keys|the realm medcea did not answer on the keycloak Service: its "
                                "key ids are not compared (the Keycloak checks report the realm)")
            self.assertNotIn("unreadable(", r)

    def test_skip_without_kubectl(self):
        with open(self.t.path("health-check.sh")) as f:
            fn = body("check_jwks", f.read())
        script = (f'_record() {{ echo "$1|$2|$3"; }}\nSCRIPT_DIR={self.t.root}\nTIMEOUT=5\nKUBECTL=no-such-kubectl\n'
                  f'source "$SCRIPT_DIR/infra/lib-policy-source.sh"\n{fn}\ncheck_jwks J medcea\n')
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=clean_env())
        self.assertEqual(p.stdout.strip(), "SKIP|J|no usable kubectl")

    def test_postgrest_no_longer_compares_key_ids(self):
        with open(os.path.join(REPO, "health-check.sh")) as f:
            pg = body("check_postgrest", f.read())
        self.assertNotIn("openid-connect/certs", pg)
        self.assertNotIn("no longer publishes", pg)
        self.assertIn("jwks-checksum", pg)            # the config-api items stay
        self.assertIn("Bearer x.y.z", pg)


# ── G2: kcscopes ───────────────────────────────────────────────────────────────────────
LOOP = ("portal access policy config monitor scheduler dbmgmt mqtt-explorer pgadmin edge-wizard node-red "
        "workbench grafana superset workbench-notebook").split()


def mapper(type_, **config):
    return {"type": type_, "name": type_, "config": {k.replace("_", "."): v for k, v in config.items()}}


def kc_doc(drop_scope=None, clients=None, groups_mapper=True, aud=True, aud_id="false", person=True):
    scopes = {
        "groups": {"mappers": [mapper("oidc-usermodel-realm-role-mapper", claim_name="groups",
                                      access_token_claim="true")] if groups_mapper else []},
        "medcea-identity": {"mappers": ([mapper("oidc-audience-mapper", included_custom_audience="medcea-api",
                                                access_token_claim="true", id_token_claim=aud_id)] if aud else [])
                            + ([mapper("oidc-usermodel-attribute-mapper", user_attribute="person_id",
                                       claim_name="person_id", access_token_claim="true")] if person else [])}}
    if drop_scope:
        scopes.pop(drop_scope)
    cl = {c: {"full_scope": True, "default": ["groups", "medcea-identity"], "optional": [], "mappers": []}
          for c in LOOP}
    for c, d in (clients or {}).items():
        if d is None:
            cl.pop(c)
        else:
            cl[c].update(d)
    return {"scopes": scopes, "clients": cl}


class KcScopes(Base):
    def run_check(self, doc, rc=0):
        out = "" if doc is False else json.dumps(doc) + "\n"
        self.t.scenario([rule(r"rdbms-postgresql-0", out, rc, stdin="client_scope")])
        return self.t.fn("check_kcscopes", 'check_kcscopes "Keycloak client scopes" medcea', helpers=())

    def test_ok_and_read_only(self):
        r = self.run_check(kc_doc())
        self.assertEqual(r, "OK|Keycloak client scopes|15 clients: groups and medcea-identity default on each "
                            "(10 of them reach a platform API)")
        ex = [c for c in self.t.calls() if c["argv"][0] == "exec"]
        self.assertEqual(len(ex), 1)
        argv = " ".join(ex[0]["argv"])
        self.assertIn("PGOPTIONS=-c default_transaction_read_only=on", argv)
        self.assertIn("-d keycloak", argv)
        self.assertIn("rdbms-postgresql-0", argv)
        self.assertIn(" ".join(LOOP), argv)           # the shared list
        self.assertNotRegex(ex[0]["stdin"], r"(?i)\b(insert|update|delete|create|alter|drop)\b|\bsecret\b")
        self.assertNotIn("port-forward", argv)
        self.assertReadOnly()

    def test_api_client_problems_fail(self):
        r = self.run_check(kc_doc(clients={"monitor": {"default": ["groups"]}}))
        self.assertEqual(r, "FAIL|Keycloak client scopes|medcea-identity is not a default scope of monitor (./deploy-infra.sh)")
        r = self.run_check(kc_doc(clients={"workbench-notebook": None, "edge-wizard": {"default": []}}))
        self.assertTrue(r.startswith("FAIL|"), r)
        self.assertIn("client(s) missing in realm medcea: workbench-notebook", r)
        self.assertIn("groups is not a default scope of edge-wizard", r)
        self.assertIn("medcea-identity is not a default scope of edge-wizard", r)

    def test_tool_client_problems_warn(self):
        r = self.run_check(kc_doc(clients={"grafana": {"default": ["groups"]}, "superset": None}))
        self.assertTrue(r.startswith("WARN|"), r)
        self.assertIn("client(s) missing in realm medcea: superset", r)
        self.assertIn("medcea-identity is not a default scope of grafana", r)

    def test_scope_and_mapper_problems_fail(self):
        self.assertIn("client scope medcea-identity is not in realm medcea",
                      self.run_check(kc_doc(drop_scope="medcea-identity")))
        for kw, text in ((dict(groups_mapper=False), "scope groups has no realm-role mapper"),
                         (dict(aud=False), "no medcea-api audience mapper"),
                         (dict(person=False), "no person_id mapper")):
            r = self.run_check(kc_doc(**kw))
            self.assertTrue(r.startswith("FAIL|"), (kw, r))
            self.assertIn(text, r)

    def test_warnings(self):
        r = self.run_check(kc_doc(aud_id="true", clients={
            "portal": {"default": ["groups"], "optional": ["medcea-identity"]},
            "pgadmin": {"full_scope": False},
            "access": {"mappers": [mapper("oidc-usermodel-realm-role-mapper", claim_name="groups")]}}))
        self.assertTrue(r.startswith("WARN|"), r)
        for text in ("the medcea-api audience is also in the ID token", "optional scope only: portal/medcea-identity",
                     "full_scope_allowed is false on pgadmin", "client-level mapper(s) writing a platform claim: access (groups)"):
            self.assertIn(text, r)

    def test_unreadable_warns_and_a_missing_realm_fails(self):
        self.assertTrue(self.run_check(False, rc=2).startswith("WARN|Keycloak client scopes|cannot read Keycloak database"))
        self.assertEqual(self.run_check(None), "FAIL|Keycloak client scopes|realm medcea is not in Keycloak database "
                                               "keycloak (./deploy-infra.sh)")


# ── G5: iamloaded, G7: iammqtt ─────────────────────────────────────────────────────────
WANT = "a" * 64
MQ = "b" * 64


def lib_cm(routes=WANT, mqtt=MQ, enforce=False, age=600, settings=None):
    """age None: no managedFields at all (only the old creationTimestamp)."""
    s = settings if settings is not None else json.dumps({"enforce": enforce, "switches": {}})
    meta = {"name": "medcea-iam-lib", "creationTimestamp": iso(9999),
            "annotations": {"medcea/routes-digest": routes, "medcea/mqtt-digest": mqtt}}
    if age is not None:
        meta["managedFields"] = [{"manager": "kubectl", "time": iso(9999)}, {"manager": "kubectl", "time": iso(age)}]
    return json.dumps({"kind": "ConfigMap", "metadata": meta, "data": {"settings.json": s}})


def dep_rules(dep, pods, absent=False):
    if absent:
        return [rule(rf"get deployment {dep} -n medcea -o json", "", 1,
                     f'Error from server (NotFound): deployments.apps "{dep}" not found\n')]
    items = [{"metadata": {"name": p}, "status": {"phase": "Running"}} for p in pods]
    items.append({"metadata": {"name": dep + "-old", "deletionTimestamp": iso(1)}, "status": {"phase": "Running"}})
    items.append({"metadata": {"name": dep + "-pending"}, "status": {"phase": "Pending"}})
    return [rule(rf"get deployment {dep} -n medcea -o json",
                 json.dumps({"spec": {"selector": {"matchLabels": {"app": dep}}}})),
            rule(rf"get pods -n medcea -l app={dep} -o json", json.dumps({"items": items}))]


SERVICES = (("scheduler", "api"), ("monitor", "api"), ("dbmgmt", "api"), ("config-ui", "recipe-fileserver"),
            ("access", "api"), ("iam-api", "iam-api"))


class IamLoaded(Base):
    def scenario(self, cm=None, pods=None, absent=(), probe=None):
        rules = [rule(r"get configmap medcea-iam-lib -n medcea -o json", cm or lib_cm())]
        for dep, ctr in SERVICES:
            rules += dep_rules(dep, [f"{dep}-1"], absent=dep in absent)
            out = (probe or {}).get(dep, f"{WANT} 3\n")
            rules.append(rule(rf"exec -n medcea {dep}-1 -c {ctr} -- python3 -c", out))
        self.t.scenario(rules)

    def run_check(self, **env):
        return self.t.fn("check_iamloaded", 'check_iamloaded "Policy loaded by services" medcea', **env)

    def test_ok_counts_and_reads_only_digests(self):
        self.scenario(absent=("dbmgmt",))
        r = self.run_check()
        self.assertEqual(r, "OK|Policy loaded by services|5 pods in 5 services load routes aaaaaaaaaaaa "
                            "(applied_version 3, information only); 1 not deployed (dbmgmt)")
        ex = [c for c in self.t.calls() if c["argv"][0] == "exec"]
        self.assertEqual(len(ex), 5)                       # Running, not terminating, pods only
        probe = ex[0]["argv"][-1]
        self.assertIn('json.load(open("/iam/routes.json"))', probe)
        self.assertIn('d.get("digest")', probe)
        self.assertNotIn("print(d)", probe)
        self.assertReadOnly()

    def test_an_older_applied_version_with_the_current_digest_is_ok(self):
        self.scenario(probe={"scheduler": f"{WANT} 2\n", "monitor": f"{WANT} None\n"})
        r = self.run_check()
        self.assertTrue(r.startswith("OK|"), r)
        self.assertIn("applied_version 2,3,None", r)

    def test_a_stale_digest_fails_after_120_s_and_warns_before(self):
        self.scenario(cm=lib_cm(age=600), probe={"monitor": "c" * 64 + " 2\n"})
        r = self.run_check()
        self.assertTrue(r.startswith("FAIL|Policy loaded by services|pod monitor-1 loads routes cccccccccccc, the "
                                     "ConfigMap holds aaaaaaaaaaaa since 6"), r)
        self.assertIn("(./apps/monitor/deploy.sh)", r)
        self.scenario(cm=lib_cm(age=30), probe={"monitor": "c" * 64 + " 2\n"})
        r = self.run_check()
        self.assertTrue(r.startswith("WARN|"), r)
        self.assertIn("the kubelet syncs within 120 s", r)

    def test_the_write_time_is_read_with_show_managed_fields(self):
        # real kubectl drops managedFields from -o json without the flag (the fake does too):
        # 30 s after a write is a WARN only because _iamlib_meta asks for them
        self.scenario(cm=lib_cm(age=30), probe={"monitor": "c" * 64 + " 2\n"})
        self.assertTrue(self.run_check().startswith("WARN|"))
        gets = [c["argv"] for c in self.t.calls() if c["argv"][:3] == ["get", "configmap", "medcea-iam-lib"]]
        self.assertEqual(len(gets), 1)
        self.assertIn("--show-managed-fields", gets[0])

    def test_no_write_time_is_past_the_grace_and_says_so(self):
        # only creationTimestamp (days old on an object updated in place): no made-up age
        self.scenario(cm=lib_cm(age=None), probe={"monitor": "c" * 64 + " 2\n"})
        r = self.run_check()
        self.assertTrue(r.startswith("FAIL|Policy loaded by services|pod monitor-1 loads routes cccccccccccc, the "
                                     "ConfigMap holds aaaaaaaaaaaa since an unknown time (no write time readable "
                                     "on the ConfigMap) (./apps/monitor/deploy.sh)"), r)
        self.assertNotIn("9999", r)

    def test_a_missing_file_where_the_service_enforces(self):
        self.scenario(probe={"access": "missing\n", "scheduler": "missing\n"})
        r = self.run_check()
        self.assertTrue(r.startswith("FAIL|"), r)
        self.assertIn("pod access-1 has no /iam/routes.json while access enforces", r)
        self.assertIn("pod scheduler-1 has no /iam/routes.json (./apps/scheduler/deploy.sh)", r)
        self.scenario(cm=lib_cm(enforce=True), probe={"scheduler": "missing\n"})
        self.assertIn("pod scheduler-1 has no /iam/routes.json while scheduler enforces", self.run_check())
        self.scenario(probe={"scheduler": "missing\n"})
        self.assertTrue(self.run_check().startswith("WARN|"))

    def test_skip_and_unreadable(self):
        self.t.scenario([])
        self.assertEqual(self.run_check(), "SKIP|Policy loaded by services|no ConfigMap medcea-iam-lib in medcea yet "
                                           "(./deploy-infra.sh)")
        self.scenario(probe={"iam-api": ""})
        r = self.run_check()
        self.assertEqual(r, "WARN|Policy loaded by services|cannot read /iam/routes.json in pod iam-api-1")


class IamMqttDigest(Base):
    def scenario(self, pods=("iam-api-1", "iam-api-2"), digests=None, age=600, absent=False):
        rules = [rule(r"annotations.medcea/mqtt-mode", "true"), rule(r"MQTT_PERSON_CREDENTIALS", "true"),
                 rule(r"configmap mosquitto-config", "per_listener_settings true\n"),
                 rule(r"configmap mqtt-explorer-html", '<html data-mqtt-mode="person">\n'),
                 rule(r"/mosquitto/auth/passwd-ws", "explorer-eng-abc123\n"),
                 rule(r"/mosquitto/auth/passwd", "node-red\n"),
                 rule(r"get configmap medcea-iam-lib -n medcea -o json", lib_cm(age=age))]
        rules += dep_rules("iam-api", list(pods), absent=absent)
        for p in pods:
            d = (digests or {}).get(p, MQ)
            rules.append(rule(rf"exec -n medcea {p} -c iam-api -- python3 -c",
                              json.dumps({"mode": True, "mqtt_digest": d})))
        self.t.scenario(rules)

    def run_check(self):
        return self.t.fn("check_iammqtt", "check_iammqtt MQTT medcea", IAM_MQTT_PERSON="true", IAM_DB_ROLES="true")

    def test_every_pod_carries_the_configmaps_digest(self):
        self.scenario()
        self.assertTrue(self.run_check().startswith("OK|MQTT|"))
        self.assertEqual(len([c for c in self.t.calls() if c["argv"][0] == "exec" and "8085" in c["argv"][-1]]), 2)
        self.assertReadOnly()

    def test_a_stale_pod_fails_after_120_s(self):
        self.scenario(digests={"iam-api-2": "c" * 64})
        r = self.run_check()
        self.assertTrue(r.startswith("FAIL|MQTT|iam-api pod iam-api-2 reads mqtt.json cccccccccccc, the ConfigMap "
                                     "holds bbbbbbbbbbbb since"), r)
        self.assertIn("(./apps/iam/deploy.sh)", r)
        self.scenario(digests={"iam-api-2": "c" * 64}, age=20)
        r = self.run_check()
        self.assertTrue(r.startswith("WARN|MQTT|"), r)
        self.assertIn("the kubelet syncs within 120 s", r)
        self.scenario(digests={"iam-api-2": "c" * 64}, age=None)
        r = self.run_check()
        self.assertIn("the ConfigMap holds bbbbbbbbbbbb since an unknown time", r)
        self.assertTrue(r.startswith("FAIL|MQTT|"), r)

    def test_no_iam_api_fails(self):
        self.scenario(pods=(), absent=True)
        r = self.run_check()
        self.assertTrue(r.startswith("FAIL|MQTT|iam-mqttx does not answer: no Running iam-api pod, no deployment iam-api"), r)


# ── G9: noderedflows ───────────────────────────────────────────────────────────────────
class NodeRedFlowsGit(unittest.TestCase):
    def setUp(self):
        self.t = Tree()
        os.makedirs(self.t.path("apps/node-red/flows"))
        with open(self.t.path("apps/node-red/flows/a.json"), "w") as f:
            f.write("[]\n")
        with open(self.t.path("apps/node-red/flows_diff.py"), "w") as f:
            f.write("import os, sys\nsys.stdin.read()\nprint(os.environ.get('STUB_OUT', 'OK 3 flows equal git'))\n"
                    "sys.exit(int(os.environ.get('STUB_RC', '0')))\n")
        self.t.scenario([rule(r"get deployment node-red", "deployment.apps/node-red"),
                         rule(r"exec -n medcea deployment/node-red -- cat /data/flows.json", "[]")])

    def tearDown(self):
        self.t.close()

    def git(self, *a):
        subprocess.run(["git", "-C", self.t.root, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                        "-c", "commit.gpgsign=false", *a], check=True, capture_output=True)

    def run_check(self, **env):
        return self.t.fn("check_noderedflows", "check_noderedflows Flows medcea", helpers=(), **env)

    def test_committed_ok_uncommitted_warns(self):
        self.git("init", "-q")
        self.git("add", "apps/node-red/flows")
        self.git("commit", "-q", "-m", "flows")
        self.assertEqual(self.run_check(), "OK|Flows|3 flows equal git")
        with open(self.t.path("apps/node-red/flows/a.json"), "w") as f:
            f.write('[{"id": "x"}]\n')
        with open(self.t.path("apps/node-red/flows/b.json"), "w") as f:
            f.write("[]\n")
        r = self.run_check()
        self.assertTrue(r.startswith("WARN|Flows|3 flows equal git; 2 flow file(s) not committed to git: a.json b.json"), r)
        self.assertIn("W1 covers committed flows: commit them", r)
        r = self.run_check(STUB_RC="2", STUB_OUT="FAIL node n1 changed")
        self.assertTrue(r.startswith("FAIL|Flows|node n1 changed"), r)
        self.assertIn("2 flow file(s) not committed", r)
        # read-only: git status --no-optional-locks never refreshes the index
        self.assertFalse(os.path.exists(self.t.path(".git", "index.lock")))

    def test_no_checkout_is_a_note(self):
        r = self.run_check()
        self.assertEqual(r, "OK|Flows|3 flows equal git (not a git checkout (or git did not answer): uncommitted "
                            "flow files not checked)")

    def test_the_call_is_bounded_and_read_only(self):
        with open(os.path.join(REPO, "health-check.sh")) as f:
            fn = body("check_noderedflows", f.read())
        self.assertIn('timeout "$TIMEOUT" git -C "$SCRIPT_DIR" --no-optional-locks status --porcelain -- apps/node-red/flows', fn)


# ── G10: iamnetpol ─────────────────────────────────────────────────────────────────────
class IamNetpol(Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        p = subprocess.run([sys.executable, cls.t.path("apps/iam/compiler/cli.py"), "--defaults", "compile", "netpol",
                            "--namespace", "medcea", "--node-ip", "192.0.2.1"], capture_output=True, text=True,
                           check=True, env=clean_env())
        cls.names = sorted(i["metadata"]["name"] for i in json.loads(p.stdout)["items"])

    def run_check(self, live, **env):
        self.t.scenario([rule(r"get netpol -n medcea -l medcea/iam-netpol=true", " ".join(live))])
        return self.t.fn("check_iamnetpol", 'check_iamnetpol "Network policies" medcea', helpers=(), **env)

    def test_true(self):
        self.assertEqual(self.run_check(self.names), f"OK|Network policies|{len(self.names)} NetworkPolicies of the "
                                                     "application pods, the compiled set")
        r = self.run_check(self.names[1:])
        self.assertTrue(r.startswith(f"FAIL|Network policies|IAM_NETPOL=true, missing: {self.names[0]}:"), r)
        r = self.run_check(self.names + ["iam-gone"])
        self.assertEqual(r, "WARN|Network policies|labelled NetworkPolicies the policy no longer compiles: iam-gone "
                            "(./deploy-infra.sh deletes them)")
        self.assertTrue(self.run_check([]).startswith("FAIL|"))
        self.assertReadOnly()

    def test_false(self):
        self.assertEqual(self.run_check([], IAM_NETPOL="false"),
                         "WARN|Network policies|IAM_NETPOL=false: the application pods accept connections from anywhere "
                         "in the cluster")
        r = self.run_check(self.names[:2], IAM_NETPOL="false")
        self.assertTrue(r.startswith("WARN|Network policies|IAM_NETPOL=false, yet 2 labelled NetworkPolicies remain"), r)


# ── G11: iamenforce ────────────────────────────────────────────────────────────────────
class IamEnforceSwitches(Base):
    SW = {"IAM_GATES": True, "IAM_NETPOL": True, "IAM_POSTGREST_JWT": False, "IAM_MQTT_PERSON": False,
          "written_at": "2026-11-09T10:00:00Z"}

    def run_check(self, settings, pod="false", **env):
        self.t.scenario([rule(r"get configmap medcea-iam-lib -n medcea -o jsonpath=\{\.data\.settings\\\.json\}",
                              json.dumps(settings)),
                         rule(r"get deployment \S+ -n medcea -o jsonpath=.*IAM_ENFORCE", pod)])
        return self.t.fn("check_iamenforce", 'check_iamenforce "Service enforcement" medcea', helpers=(), **env)

    def test_no_enforce_key_fails(self):
        r = self.run_check({"switches": self.SW})
        self.assertEqual(r, "FAIL|Service enforcement|settings.json in ConfigMap medcea-iam-lib has no enforce key: "
                            "the services read it as false (./deploy-infra.sh)")

    def test_switches_against_config_env(self):
        on = dict(IAM_ENFORCE="true", IAM_DB_ROLES="true")
        self.assertEqual(self.run_check({"enforce": True, "switches": self.SW}, pod="true", **on),
                         "OK|Service enforcement|services refuse what the route table does not allow; every pod "
                         "agrees; switches match config.env")
        r = self.run_check({"enforce": True, "switches": self.SW}, pod="true", IAM_MQTT_PERSON="true", **on)
        self.assertEqual(r, "WARN|Service enforcement|settings.json switches differ from config.env: "
                            "IAM_MQTT_PERSON=false (config.env true), as of deploy-infra 2026-11-09T10:00:00Z "
                            "(./deploy-infra.sh)")
        r = self.run_check({"enforce": True}, pod="true", **on)
        self.assertEqual(r, "WARN|Service enforcement|settings.json has no switches block (./deploy-infra.sh writes it)")
        # under false the existing WARN carries it too; an existing FAIL stays a FAIL
        r = self.run_check({"enforce": False, "switches": dict(self.SW, IAM_GATES=False)})
        self.assertTrue(r.startswith("WARN|Service enforcement|IAM_ENFORCE=false: services only log"), r)
        self.assertIn("IAM_GATES=false (config.env true)", r)
        self.assertTrue(self.run_check({"enforce": True, "switches": self.SW}, pod="false", **on).startswith("FAIL|"))


# ── G13: iamchain ──────────────────────────────────────────────────────────────────────
class IamChainDefiner(Base):
    def run_check(self, definer):
        out = "present\n" + (f"definer|{definer}\n" if definer else "") + "t|42||\n"
        self.t.scenario([rule(r"rdbms-postgresql-0", out, stdin="verify_chain")])
        return self.t.fn("check_iamchain", 'check_iamchain "Access policy history" medcea_db', helpers=())

    def test_definer_and_iam_svc(self):
        self.assertEqual(self.run_check("true|true"), "OK|Access policy history|hash chain intact, 42 event(s)")
        self.assertEqual(self.run_check("true|norole"), "OK|Access policy history|hash chain intact, 42 event(s)")
        r = self.run_check("false|true")
        self.assertEqual(r, "WARN|Access policy history|hash chain intact, 42 event(s), but verify_chain() is not "
                            "SECURITY DEFINER: the Policy UI cannot verify the chain as iam_svc (./apps/database/deploy.sh)")
        r = self.run_check("true|false")
        self.assertEqual(r, "WARN|Access policy history|hash chain intact, 42 event(s), but iam_svc may not execute "
                            "verify_chain() (the Policy UI's History tab) (./apps/database/deploy.sh)")
        sql = [c for c in self.t.calls() if c["argv"][0] == "exec"][0]["stdin"]
        self.assertIn("p.prosecdef", sql)
        self.assertIn("has_function_privilege('iam_svc', p.oid, 'EXECUTE')", sql)

    def test_the_session_is_read_only(self):
        # G13's catalog query and verify_chain() run in the same session: read-only like every DB check
        self.run_check("true|true")
        ex = [c for c in self.t.calls() if c["argv"][0] == "exec"]
        self.assertEqual(len(ex), 1)
        self.assertIn("PGOPTIONS=-c default_transaction_read_only=on -c client_min_messages=warning",
                      " ".join(ex[0]["argv"]))
        self.assertIn("default_transaction_read_only=on", body("check_iamchain"))

    def test_a_broken_chain_still_fails(self):
        self.t.scenario([rule(r"rdbms-postgresql-0", "present\ndefiner|true|true\nf|42|17|hash mismatch\n",
                              stdin="verify_chain")])
        self.assertEqual(self.t.fn("check_iamchain", "check_iamchain H medcea_db", helpers=()),
                         "FAIL|H|hash chain broken at event 17: hash mismatch")


if __name__ == "__main__":
    unittest.main()
