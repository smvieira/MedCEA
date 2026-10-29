#!/usr/bin/env python3
"""tests/test_policy.py — the access policy passes its own invariants, and the checker
catches every kind of violation it claims to.

Run from the repository root:  python3 tests/test_policy.py [--update-golden]
Read-only; needs python3-yaml (infra/lib-prereqs.sh). No cluster, no lock.
--update-golden rewrites tests/iam-grants.golden.json from the policy (the compiled
database privileges), so every change of the matrix shows up in review as a diff.
"""
import ast
import copy
import hashlib
import json
import os
import re
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "apps", "iam"))

from compiler import grants, invariants, model, netpol, proxies, routes  # noqa: E402

GOLDEN = os.path.join(REPO, "tests", "iam-grants.golden.json")
UPDATE_GOLDEN = "--update-golden" in sys.argv
if UPDATE_GOLDEN:
    sys.argv.remove("--update-golden")


def _set(path, value):
    """A mutation that sets data[path...] = value."""
    def apply(d):
        node = d
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = value
    return apply


def _append(path, value):
    def apply(d):
        node = d
        for k in path:
            node = node[k]
        node.append(value)
    return apply


def _member(group, key, value):
    """The member of `group` whose `key` is `value` (for mutations)."""
    def find(d):
        return next(m for m in d["resource_groups"][group]["members"] if m.get(key) == value)
    return find


def _with_member(group, key, value, fn):
    def apply(d):
        fn(_member(group, key, value)(d))
    return apply


def _pop(path):
    def apply(d):
        node = d
        for k in path[:-1]:
            node = node[k]
        node.pop(path[-1])
    return apply


# Each case must make the checker fail. The expected text is a fragment of the first
# matching error, so a case that fails for the wrong reason is caught too.
MUTATIONS = {
    "admin reads telemetry": (_set(["matrix", "measurements", "admin"], ["R"]), "I2"),
    "scientist on dashboards (reach)": (_set(["matrix", "dashboards", "bio_scientist"], ["R"]), "I5"),
    "operator on dashboards (own_zone bypass)": (_set(["matrix", "dashboards", "operator"], ["R"]), "I11"),
    "admin in Node-RED": (_set(["matrix", "flows", "admin"], ["R"]), "I2"),
    "production manager creates and releases runs": (_set(["matrix", "runs", "production_manager"], ["R", "C", "O", "A"]), "I4"),
    "auditor creates": (_set(["matrix", "recipes", "auditor"], ["R", "X", "C"]), "I3"),
    "qp loses release": (_set(["matrix", "runs", "qp"], ["R", "X"]), "I7"),
    "cell not closed under implies": (_set(["matrix", "schedules", "production_manager"], ["R", "U"]), "I16"),
    "A on a group without an approval rule": (_set(["matrix", "schedules", "qa"], ["R", "A"]), "I14"),
    "admin approves policy": (_set(["matrix", "iam_policy", "admin"], ["R", "C", "U", "A"]), "I4"),
    "nobody approves policy": (_pop(["matrix", "iam_policy", "qa"]), "I12"),
    "D on regulated data": (_set(["matrix", "runs", "engineer"], ["R", "D"]), "I1"),
    "table in two groups": (_append(["resource_groups", "controllers", "members"],
                                    {"type": "data", "object": "medcea.recipe_unit_permission"}), "I14"),
    "missing help": (_set(["roles", "qc", "description"], ""), "help field description"),
    "service U on regulated without waiver": (_set(["service_identities", "svc_scheduler", "ceiling", "runs"], ["R", "C", "U"]), "I10"),
    "waiver on a core invariant": (_append(["waivers"], {
        "id": "W9", "invariant": "I12", "subject": "admin", "group": "iam_policy", "target": "iam_policy",
        "levels": ["A"], "review_by": "2027-01-01", "rationale": "x", "controls": "x"}), "non-waivable"),
    "service approves recipes": (_set(["service_identities", "svc_monitor", "ceiling", "recipes"], ["R", "A"]), "I10"),
    "meaning for an unsupported type": (_set(["levels", "X", "meaning", "mqtt"], "as R"), "does not support"),
    "D on a data group": (_set(["matrix", "schedules", "admin"], ["D"]), "I13"),
    "shared upstream opens a host": (_append(["hosts", "ACCESS_DOMAIN", "serves"], "access-profile"), "shared upstream"),
    "admin approves accounts": (_set(["matrix", "iam_users", "admin"], ["R", "A", "K"]), "I2"),
    "config proxy cut off from its UI": (_set(["network", "pods", "config-ui", "ingress", 0, "from"], ["node"]),
                                         "CONFIG_DOMAIN serves platform-api"),
    "config-api unreachable through the UI": (_set(["network", "pods", "config-api", "ingress", 0, "from"], ["node"]),
                                              "CONFIG_DOMAIN serves config-api"),
    "unknown network source": (_append(["network", "pods", "monitor", "ingress", 0, "from"], "pod:grafana"), "unknown source"),
    "service carried twice": (_set(["network", "pods", "monitor", "carries", "scheduler"], 80), "carried by both"),
    "portal's /_account/ moved to the admin port": (
        lambda d: (d["network"]["pods"]["access"]["ingress"][1]["from"].remove("proxy:PORTAL_DOMAIN"),
                   d["network"]["pods"]["access"]["ingress"][0]["from"].append("proxy:PORTAL_DOMAIN")),
        "proxy:PORTAL_DOMAIN cannot reach shared upstream access-profile"),
    "gated host without a network entry": (_pop(["network", "proxies", "MONITOR_DOMAIN"]),
                                           "MONITOR_DOMAIN serves monitor but is in neither"),
    "wizard cut off from config-api": (_set(["network", "pods", "config-api", "ingress", 0, "from"], ["pod:config-ui"]),
                                       "ONBOARD_DOMAIN serves config-api"),
    # grants.check (database side, Phase 2a)
    "`on` key on a function member": (_with_member("runs", "function", "medcea.start_run(int)",
                                                   lambda m: (m.pop("level"), m.__setitem__(True, "O"))), "uses the key `on`"),
    "service_only not a list": (_with_member("devices", "object", "medcea.mqtt_credential",
                                             lambda m: m.__setitem__("service_only", True)), "must be a list"),
    "limits_dml_to names a non-member": (_set(["constraints", "assign_only", "limits_dml_to"], ["medcea.recipe_run"]),
                                         "limits_dml_to names medcea.recipe_run"),
    "waiver object outside its group": (_set(["waivers", 1, "objects"], ["medcea.recipe"]), "not a member of its target group"),
    "written_by missing on a table a function writes": (
        _with_member("runs", "object", "medcea.recipe_line_cycle_run", lambda m: m.pop("written_by")), "written_by missing"),
    "approval function that is no member": (_set(["resource_groups", "recipes", "approval", "functions"], ["medcea.approve_nothing(int)"]),
                                            "is not a function member"),
    "infrastructure function for an unknown role": (_set(["infrastructure_functions", 0, "execute"], ["svc_nobody"]),
                                                   "not a database role"),
    "rls on a non-member": (_set(["constraints", "own_zone", "rls", "objects"], ["medcea.nothing"]), "rls object medcea.nothing"),
    "service without a password": (lambda d: d["service_identities"]["svc_monitor"].pop("db_password"), "db_password"),
    "one function under two spellings": (_append(["resource_groups", "recipes", "members"],
                                                 {"type": "data", "function": "medcea.start_run(integer)", "level": "O"}), "I14"),
}


class PolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = model.load()

    def test_defaults_pass(self):
        errors, _ = invariants.check(self.policy)
        self.assertEqual(errors, [], "\n" + "\n".join(errors))

    def test_counts(self):
        p = self.policy
        self.assertEqual(len(p.roles), 11)
        self.assertEqual(len(p.groups), 25)

    def test_mutations_are_caught(self):
        for name, (mutate, expected) in MUTATIONS.items():
            with self.subTest(name):
                d = copy.deepcopy(self.policy.data)
                mutate(d)
                errors, _ = invariants.check(model.Policy(d))
                self.assertTrue(errors, f"{name}: not caught")
                self.assertTrue(any(expected in e for e in errors),
                                f"{name}: caught, but not by '{expected}': {errors[:3]}")

    def test_host_gates(self):
        p = self.policy
        everyone = sorted(p.roles)
        self.assertEqual(proxies.admitted(p, "PORTAL_DOMAIN"), everyone)
        self.assertEqual(proxies.admitted(p, "ONBOARD_DOMAIN"), ["engineer", "maintenance"])
        self.assertEqual(proxies.admitted(p, "PGADMIN_DOMAIN"), ["admin"])
        self.assertNotIn("admin", proxies.admitted(p, "MONITOR_DOMAIN"))       # I2 through tools
        self.assertNotIn("admin", proxies.admitted(p, "NODE_RED_DOMAIN"))
        self.assertNotIn("operator", proxies.admitted(p, "GRAFANA_DOMAIN"))    # own_zone
        for host in p.hosts:
            self.assertTrue(proxies.admitted(p, host), f"{host} admits nobody")


class RoutesTest(unittest.TestCase):
    """compiler/routes.py: the route table in ConfigMap medcea-iam-lib (Phase 1.1)."""

    @classmethod
    def setUpClass(cls):
        cls.policy = model.load()
        cls.doc = routes.compile(cls.policy)

    def test_deterministic_and_digest_covers_body(self):
        again = routes.compile(model.load())
        self.assertEqual(routes.dumps(self.doc), routes.dumps(again))
        body = {k: v for k, v in self.doc.items() if k != "digest"}
        self.assertEqual(self.doc["digest"], hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest())

    def test_every_api_route_is_in_its_service_table(self):
        n = 0
        for g, gd in self.policy.groups.items():
            for m in gd["members"]:
                if m["type"] != "api":
                    continue
                for route, lv in m["routes"].items():
                    n += 1
                    entry = self.doc["services"][m["service"]]["routes"][route]
                    self.assertEqual(entry["group"], g, route)
                    self.assertEqual(entry["levels"], lv if isinstance(lv, list) else [lv], route)
        self.assertEqual(n, sum(len(s["routes"]) for s in self.doc["services"].values()))

    def test_every_route_is_open_to_some_role(self):
        for svc, sd in self.doc["services"].items():
            for route, e in sd["routes"].items():
                self.assertTrue(e["roles"], f"{svc} {route}: no role may call it")
                self.assertTrue(set(e["roles"]) <= set(self.policy.roles), route)

    def test_roles_and_constraints(self):
        sched = self.doc["services"]["scheduler"]["routes"]
        self.assertEqual(sched["POST /api/runs/<id>/execute"]["roles"],
                         {"operator": ["assigned_run"], "production_manager": None})
        mon = self.doc["services"]["monitor"]["routes"]["GET /api/measurements/<unit>"]["roles"]
        self.assertEqual(mon["operator"], ["own_zone"])
        self.assertIsNone(mon["qa"])                    # through the auditor composite
        self.assertNotIn("admin", mon)                  # I2
        self.assertEqual(self.doc["services"]["access"]["routes"]["POST /api/decisions/<id>/confirm"]["roles"],
                         {"qa": ["not_own_author"]})

    def test_clients_and_public(self):
        every = sorted({h["client"] for h in self.policy.hosts.values()})
        self.assertEqual(self.doc["services"]["access-profile"]["clients"], every)
        self.assertEqual(self.doc["services"]["scheduler"]["clients"], ["config", "scheduler"])
        self.assertIn("GET /healthz", self.doc["public"]["*"])
        self.assertIn("POST /api/register", self.doc["public"]["access-public"])

    def test_refuses_bad_tables(self):
        bad = copy.deepcopy(self.policy.data)
        bad["resource_groups"]["run_logs"]["members"][0]["routes"]["fetch /x"] = "R"
        with self.assertRaisesRegex(routes.RouteError, "not 'METHOD /path'"):
            routes.compile(model.Policy(bad))
        clash = copy.deepcopy(self.policy.data)
        clash["public_routes"].append({"service": "scheduler", "route": "GET /api/runs", "why": "x"})
        with self.assertRaisesRegex(routes.RouteError, "public and in group runs"):
            routes.compile(model.Policy(clash))


class NetpolTest(unittest.TestCase):
    """compiler/netpol.py: the application pods' NetworkPolicies (Phase 1.4)."""

    @classmethod
    def setUpClass(cls):
        cls.policy = model.load()
        cls.doc = netpol.compile(cls.policy, "medcea", ["192.168.1.7", "10.1.0.1", "192.168.1.7"])
        cls.by = {i["metadata"]["name"]: i for i in cls.doc["items"]}

    def peers(self, name, port):
        rule = next(r for r in self.by[name]["spec"]["ingress"] if r["ports"] == [{"protocol": "TCP", "port": port}])
        return rule["from"]

    def test_one_labelled_policy_per_pod(self):
        self.assertEqual(set(self.by), {f"iam-{n}" for n in self.policy.data["network"]["pods"]})
        for i in self.doc["items"]:
            self.assertEqual(i["metadata"]["labels"], {netpol.LABEL: "true"})
            self.assertEqual(i["spec"]["policyTypes"], ["Ingress"])

    def test_peers(self):
        self.assertEqual(self.peers("iam-monitor", 80),
                         [{"podSelector": {"matchLabels": {"app.kubernetes.io/instance": "monitor-oauth2-proxy"}}}])
        self.assertIn({"podSelector": {"matchLabels": {"app": "config-ui"}}}, self.peers("iam-scheduler", 80))
        node = [p for p in self.peers("iam-config-api", 3000) if "ipBlock" in p]
        self.assertEqual(node, [{"ipBlock": {"cidr": "10.1.0.1/32"}}, {"ipBlock": {"cidr": "192.168.1.7/32"}}])
        self.assertIn({"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress"}}},
                      self.peers("iam-access", 8080))
        profile = self.peers("iam-access", 8082)
        self.assertEqual(len(profile), 7)                 # every proxy with /_account/ …
        self.assertNotIn({"podSelector": {"matchLabels": {"app.kubernetes.io/instance": "oauth2-proxy"}}}, profile)  # … not Node-RED's

    def test_node_addresses_required(self):
        with self.assertRaisesRegex(ValueError, "no node address"):
            netpol.compile(self.policy, "medcea", [])


class GrantsTest(unittest.TestCase):
    """compiler/grants.py: the database privileges (IAM plan Phase 2a, Appendix B)."""

    @classmethod
    def setUpClass(cls):
        cls.policy = model.load()
        cls.privs = grants.privileges(cls.policy)
        cls.doc = grants.document(cls.policy)

    def holders(self, obj, priv=None):
        return {g for g, k, o, p in self.privs if o == obj and (priv is None or p == priv)}

    def test_pre_request_switches_to_the_db_role(self):
        # pre_request() must SET ROLE to roles.<r>.db_role, the name every grant uses,
        # not to 'rr_' || the key
        p = copy.deepcopy(self.policy)
        p.roles["operator"]["db_role"] = "rr_grower"
        fn = grants.compiled_functions(p)
        self.assertIn("WHEN 'operator' THEN 'rr_grower'", fn)
        self.assertNotIn("'rr_' || own", fn)
        for r, d in grants.people(self.policy).items():
            self.assertIn(f"WHEN '{r}' THEN '{d}'", grants.compiled_functions(self.policy))

    def test_golden(self):
        body = {"privileges": self.doc["privileges"], "memberships": self.doc["memberships"], "rls": self.doc["rls"]}
        if UPDATE_GOLDEN:
            with open(GOLDEN, "w") as f:
                json.dump(body, f, indent=1, sort_keys=True)
                f.write("\n")
        with open(GOLDEN) as f:
            self.assertEqual(json.load(f), json.loads(json.dumps(body)),
                             "the compiled grants changed: review, then python3 tests/test_policy.py --update-golden")

    def test_deterministic(self):
        again = grants.document(model.load())
        self.assertEqual(again["digest"], self.doc["digest"])
        for mode in ("additive", "enforce", "verify"):
            self.assertEqual(grants.sql(self.policy, mode), grants.sql(model.load(), mode))

    def test_anon_holds_only_its_two_items(self):
        anon = {(k, o, p) for g, k, o, p in self.privs if g == "anon"}
        self.assertEqual(anon, {("function", "medcea_auth.pre_request()", "EXECUTE"), ("schema", "medcea_auth", "USAGE")})

    def test_hand_written_negatives(self):
        self.assertEqual(self.holders("medcea.mqtt_credential"), {"mqtt_auth"})
        self.assertEqual(self.holders("medcea.recipe_run", "UPDATE"), set())
        self.assertEqual(self.holders("medcea.recipe_line_cycle_run", "UPDATE"), set())
        self.assertNotIn("svc_scheduler", self.holders("medcea.recipe_line_cycle_run", "INSERT"))
        self.assertNotIn("rr_engineer", self.holders("medcea.recipe_unit_permission", "UPDATE"))
        self.assertIn("rr_engineer", self.holders("medcea.recipe", "UPDATE"))               # draft_only, by trigger
        self.assertEqual(self.holders("medcea.recipe_unit_permission", "UPDATE"), {"rr_production_manager"})
        self.assertNotIn("rr_production_manager", self.holders("medcea.recipe", "UPDATE"))   # assign_only
        for t in ("medcea.mqtt_service_credential", "medcea.mqtt_service_acl"):
            self.assertEqual(self.holders(t), {"mqtt_auth", "iam_svc"}, t)
        self.assertEqual(self.holders("medcea.platform_setting"), set())
        self.assertEqual(self.holders("medcea.algorithm_state", "UPDATE"), {"svc_scheduler"})  # W2's objects
        self.assertEqual(self.holders("medcea_auth.my_zones()"), {"rr_operator"})
        self.assertEqual(self.holders("medcea.release_run(integer)"), {"rr_qp"})
        self.assertEqual(self.holders("medcea.approve_change(text,bigint,text)"), {"rr_qa"})
        self.assertEqual(self.holders("iam_policy.append_history(text,jsonb,text)"), {"iam_svc"})
        self.assertEqual(self.holders("iam_policy.log_export(text[],text[])"), {"svc_dbexport"})
        for g, k, o, p in self.privs:
            self.assertNotIn(p, grants.NEVER, (g, o))
            self.assertFalse(o.startswith("iam."), f"schema iam is deferred to 2.7: {o}")
            self.assertNotEqual(g, "access_svc", "access_svc is deferred to 2.7")
            self.assertTrue(g in grants.managed(self.policy) or g in ("anon", "mqtt_auth"), g)
        # nothing for people on a service_only member
        for g, k, o, p in self.privs:
            if o in ("medcea.mqtt_credential", "medcea.backup_remote_to_insert_measurement"):
                self.assertFalse(g.startswith("rr_"), (g, o))

    def test_written_by_functions_is_select_only(self):
        for g, m in grants._data_members(self.policy):
            if m.get("written_by") == "functions" or m.get("view"):
                self.assertEqual({p for _, _, o, p in self.privs if o == m["object"]} - {"SELECT"}, set(), m["object"])

    def test_rls_and_memberships(self):
        pols = {(x["role"], x["cmd"]): x for x in self.doc["rls"]}
        self.assertIn("my_zones", pols[("rr_operator", "SELECT")]["using"])
        self.assertEqual(pols[("rr_production_manager", "SELECT")]["using"], "true")
        self.assertEqual(pols[("svc_ingest", "INSERT")]["check"], "true")
        readers = {g for g, k, o, p in self.privs if o == "medcea.measurement" and p == "SELECT"}
        self.assertEqual({r for r, c in pols if c == "SELECT"}, readers)
        mem = {(r, m): (i, st) for r, m, i, st in grants.memberships(self.policy)}
        self.assertEqual(mem[("rr_admin", "rr_admin_login")], (True, False))
        self.assertEqual(mem[("rr_operator", "authenticator")], (False, True))
        self.assertEqual(len([1 for r, m in mem if m == "authenticator"]), len(self.policy.roles) + 1)

    def test_modes(self):
        add = grants.sql(self.policy, "additive")
        enf = grants.sql(self.policy, "enforce")
        self.assertNotRegex(add, r"(?<!NO)LOGIN NOSUPERUSER")
        self.assertNotIn("ROW LEVEL SECURITY", add)
        self.assertNotIn("CREATE POLICY", add)
        self.assertNotIn("REVOKE CONNECT", add)
        for label in ("I9", "I10", "I15"):
            self.assertIn(label, enf)
        self.assertIn("CREATE POLICY", enf)
        self.assertIn("ENABLE ROW LEVEL SECURITY", enf)
        self.assertIn("ALTER ROLE svc_scheduler LOGIN", enf)
        self.assertIn("ALTER ROLE rr_operator NOLOGIN", enf)          # people never log in
        self.assertNotIn("ALTER ROLE authenticator PASSWORD", add + enf)  # its password is 2b's
        ver = grants.sql(self.policy, "verify")
        for word in ("GRANT ", "REVOKE ", "CREATE ", "ALTER ", "INSERT ", "UPDATE ", "DELETE "):
            self.assertNotIn(word, ver.replace("NOT INSERT", ""), f"verify must be read-only: {word}")

    def test_not_built_is_not_created(self):
        src = (self.read("apps/database/medcea_db_migrations.sql") + grants.compiled_functions(self.policy))
        for sig in grants.NOT_BUILT:
            name = sig.split("(")[0]
            self.assertNotRegex(src, rf"FUNCTION {re.escape(name)}\s*\(", sig)

    @staticmethod
    def _created_signatures(src):
        """Normalised signatures of every CREATE FUNCTION in `src` (IN arguments only,
        names and defaults dropped), as to_regprocedure() resolves them."""
        out = set()
        for m in re.finditer(r"CREATE (?:OR REPLACE )?FUNCTION ([a-z_]+\.[a-z_]+)\s*\(", src):
            i, depth = m.end(), 1
            while depth:
                depth += {"(": 1, ")": -1}.get(src[i], 0)
                i += 1
            args = []
            for a in re.split(r",(?![^(]*\))", src[m.end():i - 1]):
                a = re.sub(r"\s+DEFAULT\s+.*$", "", a.strip(), flags=re.S)
                if not a or a.split()[0].upper() == "OUT":
                    continue
                words = a.split()
                if words[0].upper() in ("IN", "INOUT"):
                    words = words[1:]
                if len(words) > 1:          # a named argument: drop the name
                    words = words[1:]
                args.append(re.sub(r"\(.*\)", "", " ".join(words)))
            out.add(grants.norm_sig(f"{m.group(1)}({', '.join(args)})"))
        return out

    def test_every_compiled_function_is_created(self):
        # full signatures, not names: a changed argument list must fail here, not
        # silently drop out of the grant and of I15
        src = (self.read("apps/database/medcea_db_migrations.sql") + grants.compiled_functions(self.policy))
        made = self._created_signatures(src)
        for g, k, o, p in self.privs:
            if k == "function":
                self.assertIn(o, made, o)
        for o in grants.declared_functions(self.policy):
            self.assertIn(o, made, o)

    @staticmethod
    def _quoted(text):
        return re.findall(r"'([a-z_]+)'", text)

    def test_enforce_file_attaches_the_checked_triggers(self):
        # parse the two lists the enforce file actually loops over, not the whole file:
        # a table named elsewhere in it must not stand in for a missing trigger
        enf = self.read("apps/database/medcea_db_migrations_008b_enforce.sql")
        spec = re.search(r"spec text\[\]\[\] := ARRAY\[(.*?)\];", enf, re.S)
        self.assertIsNotNone(spec, "the enforce file's trigger spec")
        rows = re.findall(r"\['([a-z_]+)',\s*'([a-z_]+)'", spec.group(1))
        trunc = re.search(r"FOREACH t IN ARRAY ARRAY\[([^\]]*)\] LOOP\s+IF NOT EXISTS[^;]*?tgname = 'iam_no_truncate_trg'",
                          enf, re.S)
        self.assertIsNotNone(trunc, "the enforce file's truncate-trigger loop")
        have = {("medcea." + t, n) for t, n in rows} | {("medcea." + t, "iam_no_truncate_trg")
                                                        for t in self._quoted(trunc.group(1))}
        self.assertEqual(have, set(grants.ENFORCE_TRIGGERS))
        self.assertEqual(len(rows), len(set(rows)), "a trigger is listed twice")

    def test_legacy_list_matches_down_file(self):
        # parse the down file's revoke loop, its explicit REVOKEs and its sequence list
        down = self.read("apps/database/medcea_db_migrations_down_008b.sql")
        loop = re.search(r"FOREACH t IN ARRAY ARRAY\[([^\]]*)\] LOOP\s+IF pg_catalog.to_regclass\('medcea\.' \|\| t\) IS NOT NULL THEN\s+"
                         r"EXECUTE pg_catalog.format\('REVOKE ALL ON medcea.%I FROM anon', t\)", down)
        self.assertIsNotNone(loop, "the down file's anon revoke loop")
        explicit = re.findall(r"^REVOKE ALL ON medcea\.([a-z_]+) FROM anon;", down, re.M)
        revoked = self._quoted(loop.group(1)) + explicit
        self.assertEqual(sorted(revoked), sorted(set(revoked)), "a table is revoked twice")
        self.assertEqual(set(revoked), set(grants.LEGACY_ANON_EXCLUDED))
        seq = re.search(r"AND t\.relname IN \(([^)]*)\) LOOP\s+EXECUTE pg_catalog.format\('REVOKE ALL ON SEQUENCE %s FROM anon'", down)
        self.assertIsNotNone(seq, "the down file's sequence revoke list")
        self.assertEqual(set(self._quoted(seq.group(1))), set(grants.LEGACY_ANON_EXCLUDED))
        for t in grants.LEGACY_ANON_READ_ONLY:
            self.assertRegex(down, rf"(?m)^REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON medcea\.{t} FROM anon;")

    def test_down_file_locks_out_the_managed_roles(self):
        # run by hand straight after true, the down file must not leave a LOGIN role
        # with its enforce-mode grants: it hands CONNECT back to PUBLIC, so section 1
        # sets every managed role NOLOGIN and the full section revokes their privileges
        down = self.read("apps/database/medcea_db_migrations_down_008b.sql")
        full = down.index("\\if :{?full}")
        sec1 = down[:full]
        self.assertLess(sec1.index("GRANT CONNECT ON DATABASE %I TO PUBLIC"), sec1.index("ALTER ROLE %I NOLOGIN"))
        self.assertIn("rolcanlogin", sec1)
        self.assertIn("REVOKE ALL ON ALL TABLES    IN SCHEMA medcea, medcea_auth, iam_policy FROM %I", down[full:])
        pat = re.compile(r"rolname LIKE 'rr\\_%' OR rolname LIKE 'svc\\_%' OR rolname = 'iam_svc'")
        for r in grants.managed(model.load()):
            self.assertTrue(r.startswith(("rr_", "svc_")) or r == "iam_svc", r)
        self.assertGreaterEqual(len(pat.findall(down)), 2)

    def read(self, rel):
        with open(os.path.join(REPO, rel)) as f:
            return f.read()


class WiringTest(unittest.TestCase):
    """The places outside the compiler that must agree with the policy."""

    @classmethod
    def setUpClass(cls):
        cls.policy = model.load()

    def read(self, rel):
        with open(os.path.join(REPO, rel)) as f:
            return f.read()

    def test_every_host_has_an_enforcement_status(self):
        self.assertEqual(set(proxies.ENFORCEMENT), set(self.policy.hosts))

    def test_compiled_gates_are_rendered_from_the_policy(self):
        # values template → (script that renders it, host variable it compiles)
        wiring = {
            "k8s/oauth2-proxy/values-portal.yaml": [("deploy-infra.sh", "PORTAL_DOMAIN")],
            "k8s/oauth2-proxy/values-node-red.yaml": [("deploy-infra.sh", "NODE_RED_DOMAIN")],
            "apps/mqtt-explorer/k8s/oauth2-proxy-values.yaml": [("apps/mqtt-explorer/deploy.sh", "MQTTX_DOMAIN")],
            "k8s/oauth2-proxy/values-app.yaml": [("apps/frontend/deploy.sh", "CONFIG_DOMAIN"),
                                                 ("apps/frontend/deploy.sh", "DBMGMT_DOMAIN"),
                                                 ("apps/monitor/deploy.sh", "MONITOR_DOMAIN"),
                                                 ("apps/scheduler/deploy.sh", "SCHEDULER_DOMAIN")],
        }
        compiled = {h for h, st in proxies.ENFORCEMENT.items() if st == "compiled"}
        self.assertEqual(compiled, {h for v in wiring.values() for _, h in v})
        for template, users in wiring.items():
            self.assertIn("allowed_groups = ${ALLOWED_GROUPS}", self.read(template), template)
            for script, host in users:
                src = self.read(script)
                self.assertIn(f'ALLOWED_GROUPS="$(policy_groups {host})"', src, f"{script}: {host}")
                # envsubst leaves an unlisted ${VAR} as literal text (lib-render.sh)
                renders = [l for l in src.splitlines() if os.path.basename(template) in l and "render " in l]
                self.assertTrue(renders, f"{script} does not render {template}")
                for line in renders:
                    self.assertIn("ALLOWED_GROUPS", line.split(">")[0], f"{script}: render of {template} misses ALLOWED_GROUPS")

    def test_every_gate_explains_its_403(self):
        # Every gated proxy reads /templates; every host but the portal (own page)
        # gets its page from gate_error_page with the list its gate is deployed with.
        for values in ("k8s/oauth2-proxy/values-portal.yaml", "k8s/oauth2-proxy/values-app.yaml",
                       "k8s/oauth2-proxy/values-node-red.yaml",
                       "apps/mqtt-explorer/k8s/oauth2-proxy-values.yaml", "apps/access/k8s/oauth2-proxy-values.yaml"):
            self.assertIn('custom_templates_dir = "/templates"', self.read(values), values)
        pages = {"apps/frontend/deploy.sh": [("config-oauth2-proxy", "CONFIG_DOMAIN"), ("dbmgmt-oauth2-proxy", "DBMGMT_DOMAIN")],
                 "apps/monitor/deploy.sh": [("monitor-oauth2-proxy", "MONITOR_DOMAIN")],
                 "apps/scheduler/deploy.sh": [("scheduler-oauth2-proxy", "SCHEDULER_DOMAIN")],
                 "apps/mqtt-explorer/deploy.sh": [("mqttx-oauth2-proxy", "MQTTX_DOMAIN")],
                 "deploy-infra.sh": [("oauth2-proxy", "NODE_RED_DOMAIN")],
                 "apps/access/deploy.sh": [("access-oauth2-proxy", "ACCESS_DOMAIN")]}
        for script, gates in pages.items():
            src = self.read(script)
            for release, host in gates:
                self.assertRegex(src, rf"gate_error_page {re.escape(release)} {host} ", f"{script}: {host}")
        uninstalls = {"apps/frontend/uninstall.sh": ["config-oauth2-proxy", "dbmgmt-oauth2-proxy"],
                      "apps/monitor/uninstall.sh": ["monitor-oauth2-proxy"], "apps/scheduler/uninstall.sh": ["scheduler-oauth2-proxy"],
                      "apps/mqtt-explorer/uninstall.sh": ["mqttx-oauth2-proxy"], "apps/access/uninstall.sh": ["access-oauth2-proxy"]}
        for script, releases in uninstalls.items():
            for release in releases:
                self.assertIn(f"delete configmap {release}-templates", self.read(script), script)

    def test_gate_page_names_the_deployed_roles(self):
        p = self.policy
        label, roles = proxies.describe(p, "MONITOR_DOMAIN", proxies.admitted(p, "MONITOR_DOMAIN"))
        self.assertEqual(label, "Monitor")
        self.assertEqual(roles, [p.roles[r]["label"] for r in p.roles if r in proxies.admitted(p, "MONITOR_DOMAIN")])
        self.assertEqual(proxies.describe(p, "ACCESS_DOMAIN", ["admin"])[1], [p.roles["admin"]["label"]])
        with self.assertRaises(KeyError):
            proxies.describe(p, "MONITOR_DOMAIN", ["no_such_role"])
        # the template's variables are the ones gate_error_page renders
        tpl = self.read("k8s/oauth2-proxy/error.html")
        self.assertEqual(set(re.findall(r"\$\{([A-Z_]+)\}", tpl)),
                         {"GATE_SERVICE", "GATE_ROLES", "GATE_PORTAL_URL", "GATE_LOGOUT_RD"})
        lib = self.read("infra/lib-oauth2-proxy.sh")
        self.assertIn("error.html\" GATE_SERVICE GATE_ROLES GATE_PORTAL_URL GATE_LOGOUT_RD", lib)

    def test_access_check_reaches_every_service(self):
        # deploy-infra.sh ships the library, the table and the settings in one ConfigMap,
        # and publishes the realm's keys; each Python service mounts both (optional: they
        # are absent until deploy-infra runs), installs PyJWT and checks every request
        # under its own route-table name.
        infra = self.read("deploy-infra.sh")
        for key in ("routes.json=", "settings.json=", "medcea_iam.py=\"$SCRIPT_DIR/apps/iam/lib/medcea_iam.py\""):
            self.assertIn(f"--from-file={key}", infra)
        self.assertIn("create secret generic medcea-jwks", infra)
        self.assertIn('cli.py" compile netpol --namespace "$NAMESPACE" "${_NODE_IPS[@]}"', infra)
        self.assertIn("delete netpol -n \"$NAMESPACE\" -l medcea/iam-netpol=true", infra)
        services = {  # manifest -> (source, how it calls the check)
            "apps/scheduler/k8s/scheduler.yaml": ("apps/scheduler/scheduler-api.py", ["flask_check('scheduler')"]),
            "apps/monitor/k8s/monitor.yaml": ("apps/monitor/monitor-api.py", ["flask_check('monitor')"]),
            "apps/frontend/k8s/dbmgmt.yaml": ("apps/frontend/html/dbmgmt-api.py", ["http_check(self, 'dbmgmt')"]),
            "apps/frontend/k8s/config-ui.yaml": ("apps/frontend/k8s/recipe-fileserver.yaml", ["http_check(self, 'platform-api')"]),
            "apps/access/k8s/access.yaml": ("apps/access/access-api.py", [
                "http_check(self, self.IAM_SERVICE)", "IAM_SERVICE = 'access-public'",
                "IAM_SERVICE = 'access'", "IAM_SERVICE = 'access-profile'"]),
        }
        doc = routes.compile(self.policy)
        table = set(doc["services"]) | set(doc["public"])
        for manifest, (source, calls) in services.items():
            m, src = self.read(manifest), self.read(source)
            self.assertRegex(m, r"name: medcea-iam-lib,?\s+optional: true", manifest)
            self.assertRegex(m, r"secretName: medcea-jwks,?\s+optional: true", manifest)
            self.assertRegex(m, r"name: iam-lib,? +(# .*\n +)?mountPath: /iam", manifest)
            self.assertRegex(m, r"name: jwks,? +(# .*\n +)?mountPath: /jwks", manifest)
            for call in calls:
                self.assertIn(call, src, source)
                for name in re.findall(r"'([a-z-]+)'", call):
                    self.assertIn(name, table, f"{source}: {name} is not a route-table service")
            self.assertIn("/iam/medcea_iam.py", src, source)
            self.assertIn("pyjwt[crypto]", m + src, f"{manifest}: PyJWT is not installed")
        # Every proxy with a Python upstream passes the token; Node-RED's never does.
        for values in ("k8s/oauth2-proxy/values-app.yaml", "k8s/oauth2-proxy/values-portal.yaml",
                       "apps/mqtt-explorer/k8s/oauth2-proxy-values.yaml", "apps/access/k8s/oauth2-proxy-values.yaml"):
            self.assertIn("pass_access_token = true", self.read(values), values)
            self.assertIn("pass_authorization_header = false", self.read(values), values)
        self.assertIn("pass_access_token = false", self.read("k8s/oauth2-proxy/values-node-red.yaml"))

    def test_offered_roles_are_platform_roles_the_database_accepts(self):
        src = self.read("apps/access/access-api.py")
        offered = ast.literal_eval(re.search(r"^ROLES = (\{.*?^\})", src, re.S | re.M).group(1))
        self.assertTrue(set(offered) <= set(self.policy.roles), set(offered) - set(self.policy.roles))
        sql = self.read("apps/access/access_db.sql")
        for column in ("requested_role", "granted_role"):
            m = re.search(rf"ADD CONSTRAINT access_request_{column}_check\s+CHECK \({column} IN \((.*?)\)\)", sql, re.S)
            self.assertIsNotNone(m, f"no re-created CHECK for {column}")
            accepted = set(re.findall(r"'([a-z_]+)'", m.group(1)))
            self.assertEqual(accepted, set(self.policy.roles), column)


    def test_database_wiring_phase_2a(self):
        deploy = self.read("apps/database/deploy.sh") + self.read("apps/database/lib-db-apply.sh")
        migrations = self.read("apps/database/medcea_db_migrations.sql")
        self.assertNotRegex(deploy, r"GRANT [A-Z, ]+ ON ALL TABLES IN SCHEMA medcea TO anon")
        self.assertNotRegex(migrations, r"\bTO anon\b")
        self.assertIn("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA medcea TO anon",
                      self.read("apps/database/medcea_db_migrations_down_008b.sql"))
        sched = self.read("apps/scheduler/scheduler-api.py")
        self.assertNotIn("GRANT", sched)
        self.assertNotIn("CREATE TABLE", sched)
        for f in ("medcea_db_migrations_down_008b.sql", "medcea_db_migrations_008b_enforce.sql", "medcea_db_008b_data.sql",
                  "medcea_db_008b_index.sql", "purge.sql", "medcea_db_owner.sql", "lib-db-apply.sh", "k8s/db-role-secret.yaml"):
            self.assertTrue(os.path.isfile(os.path.join(REPO, "apps", "database", f)), f)
        example, configure = self.read("config.env.example"), self.read("infra/configure.sh")
        self.assertIn('IAM_DB_ROLES="false"', example)
        early_exit = configure.index("&& exit 0")
        for role, var in grants.passwords(self.policy):
            self.assertIn(f'{var}=""', example, var)
            self.assertLess(configure.index(var), early_exit, f"{var} must be generated before configure.sh's early exit")
        ddl = self.read("apps/database/medcea_db_ddl.sql")
        self.assertNotIn("databasechangeloglock", ddl)
        self.assertNotIn("OWNER TO postgres", ddl)
        self.assertIn("SET log_statement = 'none'", self.read("apps/access/deploy.sh"))
        self.assertIn("SET log_statement = 'none'", self.read("apps/database/lib-db-apply.sh"))
        # 008b is one transaction that writes the nonce deploy.sh reads back
        tail = migrations[migrations.index("Migration 008b"):]
        self.assertEqual((tail.count("BEGIN;"), tail.count("COMMIT;")), (1, 1))
        self.assertIn("'008b:last_nonce', :'deploy_nonce'", tail)
        # the mode files run inside the bundle's transaction: no BEGIN/COMMIT of their own
        for f in ("medcea_db_migrations_down_008b.sql", "medcea_db_migrations_008b_enforce.sql"):
            self.assertNotRegex(self.read("apps/database/" + f), r"(?m)^(BEGIN|COMMIT);", f)
        # psql does not interpolate :'var' inside a dollar-quoted body
        for f in ("medcea_db_migrations_down_008b.sql", "medcea_db_migrations_008b_enforce.sql",
                  "medcea_db_008b_data.sql", "medcea_db_008b_index.sql", "purge.sql"):
            for body in re.findall(r"\$(\w*)\$(.*?)\$\1\$", self.read("apps/database/" + f), re.S):
                self.assertNotRegex(body[1], r":'[a-z_]+'", f)
        render = [l for l in self.read("apps/database/deploy.sh").splitlines() if "db-role-secret.yaml" in l]
        self.assertTrue(any("SECRET_NAME DB_ROLE DB_PASS" in l for l in render))
        self.assertIn("db-roles --names", self.read("apps/database/uninstall.sh"))
        self.assertIn("purge.sql", self.read("apps/database/uninstall.sh"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
