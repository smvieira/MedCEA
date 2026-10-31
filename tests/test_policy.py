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

from compiler import grants, invariants, model, mqtt, netpol, proxies, routes, routes_diff, tools  # noqa: E402

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
    "operator on dashboards (own_unit bypass)": (_set(["matrix", "dashboards", "operator"], ["R"]), "I11"),
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
    "scientist exports telemetry": (_set(["matrix", "measurements", "bio_scientist"], ["R", "X"]), "I5"),
    "notebooks reach config-api, which does not admit them": (
        _set(["network", "pods", "config-api", "ingress", 0, "from"], ["pod:config-ui", "node"]),
        "which does not admit client:notebooks"),
    "config-api admits notebooks without their egress hop": (
        lambda d: d["network"]["clients"]["notebooks"]["egress"].pop(0), "which has no egress hop there"),
    "notebook token client is a host's client": (_set(["network", "clients", "notebooks", "token_client"], "config"),
                                                 "is a host's client"),
    "notebook token client without read_only": (_pop(["network", "clients", "notebooks", "read_only"]),
                                                "needs read_only: true or false"),
    "notebook hop with pod and selector": (
        lambda d: d["network"]["clients"]["notebooks"]["egress"][1].__setitem__("pod", "config-api"),
        "names either pod or selector"),
    "unknown per-level constraint": (_set(["matrix", "runs", "operator", "constraint"], {"R": "own_unit", "O": "nope"}),
                                     "unknown constraint nope"),
    "per-level constraint map with applies_to": (_set(["matrix", "runs", "operator", "applies_to"], ["O"]),
                                                 "per-level constraint map takes no applies_to"),
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
    "rls on a non-member": (_set(["constraints", "own_unit", "rls", "objects"], ["medcea.nothing"]), "rls object medcea.nothing"),
    "rls using map misses an object": (_set(["constraints", "own_unit", "rls", "using"], {"medcea.measurement": "true"}),
                                       "rls `using` must name exactly its objects"),
    "service without a password": (lambda d: d["service_identities"]["svc_monitor"].pop("db_password"), "db_password"),
    "one function under two spellings": (_append(["resource_groups", "recipes", "members"],
                                                 {"type": "data", "function": "medcea.start_run(integer)", "level": "O"}), "I14"),
    # IAM 2.7: a K function member compiles EXECUTE for admin (and pgAdmin's login) unless service_only
    "K function member without service_only": (
        _with_member("iam_users", "function", "iam.withdraw_decision(int, text)", lambda m: m.pop("service_only")),
        "at level K needs service_only"),
    # compiler/tools.py: a tool's own role setting (IAM 3.1)
    "Grafana Admin from a cell": (_append(["resource_groups", "dashboards", "tool", "settings"],
                                          {"setting": "Admin", "levels": ["U"]}), "tool dashboards"),
    "constrained dashboards cell": (_set(["matrix", "dashboards", "maintenance"], {"levels": ["R"], "constraint": "own_unit"}),
                                    "cannot evaluate"),
    "admitted role without a Grafana role": (_pop(["resource_groups", "dashboards", "tool", "settings", 1]), "tool dashboards"),
    "tool reaches less than its datasource": (_set(["resource_groups", "dashboards", "reaches"], {"measurements": ["R"], "runs": ["R"]}),
                                              "svc_grafana"),
    "schema older than its tool blocks": (_set(["schema_version"], 2), "schema_version"),
    # IAM 3.2: the AI workbench's JupyterHub setting
    "hub admin by R": (_set(["resource_groups", "research_workbench", "tool", "settings", 0, "levels"], ["R"]),
                       "cannot give jupyterhub's admin"),
    "constrained hub cell": (_set(["matrix", "research_workbench", "bio_scientist"],
                                  {"levels": ["R", "C", "U"], "constraint": "draft_only", "applies_to": ["R", "C", "U"]}),
                             "cannot evaluate"),
    "constrained hub admin": (_set(["matrix", "research_workbench", "admin"], {"levels": ["K"], "constraint": "draft_only"}),
                              "cannot evaluate"),
    "unknown tool kind": (_set(["resource_groups", "research_workbench", "tool", "kind"], "zeppelin"), "unknown kind zeppelin"),
    "notebook with a platform credential": (_set(["resource_groups", "research_workbench", "tool", "service_identity"],
                                                 "svc_grafana"), "no service_identity"),
    # IAM 3.3: Node-RED's editor rights (adminAuth)
    "Node-RED editor by R": (_set(["resource_groups", "flows", "tool", "settings", 0, "levels"], ["R"]),
                             "cannot give node-red's editor"),
    "Node-RED read-only setting": (_set(["resource_groups", "flows", "tool", "settings", 0, "setting"], "read"),
                                   "is not one the policy may give for node-red"),
    "constrained flows cell": (_set(["matrix", "flows", "engineer"], {"levels": ["R", "C", "U"], "constraint": "own_unit"}),
                               "cannot evaluate"),
    "Node-RED reaches less than svc_ingest": (_set(["resource_groups", "flows", "reaches"],
                                                   {"mqtt_sense": ["R"], "mqtt_control": ["R"], "measurements": ["R", "C"]}),
                                              "svc_ingest"),
    # IAM 3.4: the onboarding wizard's --required-role and pgAdmin's OAUTH2_ADDITIONAL_CLAIMS
    "onboarding by R": (_set(["resource_groups", "onboarding", "tool", "settings", 0, "levels"], ["R"]),
                        "cannot give edge-wizard's onboard"),
    "maintenance's existing_slot with nobody enforcing it": (_pop(["resource_groups", "onboarding", "tool", "constraint_enforced_by"]),
                                                             "cannot evaluate"),
    "constraint passed on by a tool with its own credential": (
        _set(["resource_groups", "dashboards", "tool", "constraint_enforced_by"], "the database"),
        "constraint_enforced_by on a tool with its own credential"),
    "pgAdmin sign-in by R": (_set(["resource_groups", "platform_admin", "tool", "settings", 0, "levels"], ["R"]),
                             "cannot give pgadmin's sign_in"),
    "role admitted to pgAdmin without the claim": (_set(["matrix", "platform_admin", "qa"], ["R"]),
                                                   "PGADMIN_DOMAIN admits"),
    # IAM 3.5: the MQTT Explorer's personal credentials (compiler/mqtt.py) and iam-api's network entry
    "unconstrained person write on mqtt_control": (_set(["matrix", "mqtt_control", "engineer"], ["R", "C"]),
                                                   "the broker honours person write rows only"),
    "mqtt topic of a fifth class": (_with_member("mqtt_sense", "topic", "medcea/+/+/sense/#",
                                                 lambda m: m.update(topic="medcea/+/+/telemetry/#")),
                                    "is not medcea/<unit|+>"),
    "auditor admitted to the Explorer with no topic": (_set(["matrix", "mqtt_explorer", "auditor"], ["R"]),
                                                       "the credential would carry no topic"),
    "service mqtt_user in the person namespace": (_set(["service_identities", "svc_ingest", "mqtt_user"], "explorer-x"),
                                                  "namespace of person credentials"),
    "Explorer credential without a lifetime": (_pop(["resource_groups", "mqtt_explorer", "credential", "ttl_hours"]),
                                               "ttl_hours"),
    "iam-mqttx not reachable from the Explorer proxy": (_set(["network", "pods", "iam", "ingress", 0, "from"], ["node"]),
                                                        "MQTTX_DOMAIN serves iam-mqttx"),
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
        self.assertEqual(len(p.groups), 26)

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
        self.assertNotIn("operator", proxies.admitted(p, "GRAFANA_DOMAIN"))    # own_unit
        self.assertEqual(proxies.admitted(p, "ACCESS_DOMAIN"), ["admin", "auditor", "qa", "qp"])
        for host in p.hosts:
            self.assertTrue(proxies.admitted(p, host), f"{host} admits nobody")


class ToolsTest(unittest.TestCase):
    """compiler/tools.py: each tool's own role setting (Grafana 3.1, JupyterHub 3.2,
    Node-RED 3.3, the onboarding wizard and pgAdmin 3.4)."""

    EXPECTED_PATH = ("(contains(groups[*], 'engineer')) && 'Editor' || (contains(groups[*], 'auditor') || "
                     "contains(groups[*], 'maintenance') || contains(groups[*], 'production_manager') || "
                     "contains(groups[*], 'qa') || contains(groups[*], 'qc') || contains(groups[*], 'qp')) && 'Viewer' || ''")

    @classmethod
    def setUpClass(cls):
        cls.policy = model.load()

    def test_grafana_settings(self):
        self.assertEqual(tools.groups(self.policy, "grafana"), ["dashboards"])
        self.assertEqual(dict(tools.settings(self.policy, "dashboards")), {
            "Editor": ["engineer"], "Viewer": ["auditor", "maintenance", "production_manager", "qa", "qc", "qp"]})

    def test_grafana_path_text(self):
        self.assertEqual(tools.grafana_role_path(self.policy), self.EXPECTED_PATH)

    def test_tool_roles_equal_gate(self):
        given = sorted(r for _, roles in tools.settings(self.policy, "dashboards") for r in roles)
        self.assertEqual(given, proxies.admitted(self.policy, "GRAFANA_DOMAIN"))
        for refused in ("operator", "admin", "bio_scientist", "control_scientist"):
            self.assertNotIn(refused, given)

    def test_no_admin_setting(self):
        self.assertEqual(tools.KINDS["grafana"], {"Editor", "Viewer"})
        self.assertNotIn("Admin", tools.grafana_role_path(self.policy))

    def test_reaches_cover_ceiling(self):
        p = self.policy
        reaches = p.groups["dashboards"]["reaches"]
        for g, lv in p.services["svc_grafana"]["ceiling"].items():
            self.assertLessEqual(set(lv), p.closure(reaches.get(g, [])), g)

    def test_jupyterhub_groups(self):
        """IAM 3.2: allowed_groups is the host's gate, admin_groups the holders of K (hub role workbench-admin)."""
        p = self.policy
        self.assertEqual(tools.groups(p, "jupyterhub"), ["research_workbench"])
        allowed = tools.jupyterhub_groups(p, "allowed_groups")
        self.assertEqual(allowed, ["admin", "bio_scientist", "control_scientist", "engineer", "qa"])
        self.assertEqual(allowed, proxies.admitted(p, "WORKBENCH_DOMAIN"))
        self.assertEqual(tools.jupyterhub_groups(p, "admin_groups"), ["admin"])
        for refused in ("operator", "auditor", "production_manager", "maintenance", "qc", "qp"):
            self.assertNotIn(refused, allowed)
        with self.assertRaises(ValueError):
            tools.jupyterhub_groups(p, "admin_users")

    def test_node_red_permissions(self):
        """IAM 3.3: engineer gets every editor scope but nodes.write; nobody else gets any."""
        p = self.policy
        doc = tools.node_red_permissions(p)
        self.assertEqual(doc["group"], "flows")
        self.assertIsNone(doc["default"])
        self.assertEqual(set(doc["permissions"]), {"engineer"})
        self.assertEqual(sorted(doc["permissions"]), proxies.admitted(p, "NODE_RED_DOMAIN"))
        scopes = doc["permissions"]["engineer"]
        self.assertIn("flows.write", scopes)
        self.assertNotIn("nodes.write", scopes)   # palette modules only from packages.txt
        self.assertNotIn("*", scopes)
        self.assertNotIn("read", tools.KINDS["node-red"])   # GET /flows shows the ingest password
        for g, lv in p.services["svc_ingest"]["ceiling"].items():
            self.assertLessEqual(set(lv), p.closure(p.groups["flows"]["reaches"].get(g, [])), g)

    def test_edge_wizard_roles(self):
        """IAM 3.4: the wizard admits the holders of C or U on onboarding, maintenance
        included (existing_slot is the database's, at registration)."""
        p = self.policy
        self.assertEqual(tools.groups(p, "edge-wizard"), ["onboarding"])
        self.assertEqual(tools.edge_wizard_roles(p), ["engineer", "maintenance"])
        self.assertEqual(tools.edge_wizard_roles(p), proxies.admitted(p, "ONBOARD_DOMAIN"))
        self.assertTrue(p.groups["onboarding"]["tool"]["constraint_enforced_by"])

    def test_pgadmin_claims(self):
        p = self.policy
        self.assertEqual(tools.pgadmin_claims(p), "{'groups': ['admin']}")
        self.assertEqual(ast.literal_eval(tools.pgadmin_claims(p)), {"groups": proxies.admitted(p, "PGADMIN_DOMAIN")})

    def test_tool_lists_fail_closed(self):
        # an empty --required-role admits any signed-in account: never compiled
        for group, fn in (("onboarding", tools.edge_wizard_roles), ("platform_admin", tools.pgadmin_claims)):
            d = copy.deepcopy(self.policy.data)
            d["matrix"][group] = {}
            with self.assertRaises(ValueError, msg=group):
                fn(model.Policy(d))

    def test_compile_tool_cli(self):
        import subprocess
        cli = [sys.executable, os.path.join(REPO, "apps", "iam", "compiler", "cli.py"), "compile"]
        out = subprocess.run(cli + ["edge-wizard"], capture_output=True, text=True)
        self.assertEqual((out.returncode, out.stdout), (0, "engineer,maintenance\n"))
        out = subprocess.run(cli + ["pgadmin"], capture_output=True, text=True)
        self.assertEqual((out.returncode, out.stdout), (0, "{'groups': ['admin']}\n"))
        self.assertEqual(subprocess.run(cli + ["zeppelin"], capture_output=True).returncode, 2)

    def test_tool_block_does_not_change_route_digest(self):
        # a tool block is not in the route table: no database deploy, role_widening() unchanged
        d = copy.deepcopy(self.policy.data)
        del d["resource_groups"]["research_workbench"]["tool"]
        self.assertEqual(routes.compile(model.Policy(d))["digest"], routes.compile(self.policy)["digest"])


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
                    lv = lv["levels"] if isinstance(lv, dict) else lv
                    self.assertEqual(entry["levels"], lv if isinstance(lv, list) else [lv], route)
        self.assertEqual(n, sum(len(s["routes"]) for s in self.doc["services"].values()))

    def test_every_route_is_open_to_some_role(self):
        # but for platform-api's recipe PUT, closed on purpose (IAM 2.6, below)
        for svc, sd in self.doc["services"].items():
            for route, e in sd["routes"].items():
                if (svc, route) != ("platform-api", "PUT /<file>"):
                    self.assertTrue(e["roles"], f"{svc} {route}: no role may call it")
                self.assertTrue(set(e["roles"]) <= set(self.policy.roles), route)

    def test_unconstrained_only_routes(self):
        # IAM 2.6: platform-api cannot evaluate draft_only/assign_only/existing_slot, so its
        # file PUTs admit only the roles that hold U there without a constraint
        api = self.doc["services"]["platform-api"]["routes"]
        self.assertEqual(api["PUT /devices/<file>"]["roles"], {"engineer": None})
        self.assertEqual(api["PUT /<file>"]["roles"], {})
        for svc, sd in self.doc["services"].items():
            for route, e in sd["routes"].items():
                if svc == "platform-api":
                    self.assertTrue(all(c is None for c in e["roles"].values()), f"{svc} {route}: constrained")
        bad = copy.deepcopy(self.policy.data)
        _member("recipes", "service", "platform-api")(bad)["routes"]["PUT /<file>"]["only"] = True
        errors, _ = invariants.check(model.Policy(bad))
        self.assertTrue(any("PUT /<file> has keys other than" in e for e in errors), errors)

    def test_roles_and_constraints(self):
        sched = self.doc["services"]["scheduler"]["routes"]
        self.assertEqual(sched["POST /api/runs/<id>/execute"]["roles"],
                         {"operator": ["assigned_run"], "production_manager": None})
        mon = self.doc["services"]["monitor"]["routes"]["GET /api/measurements/<unit>"]["roles"]
        self.assertEqual(mon["operator"], ["own_unit"])
        for r in ("GET /api/runs", "GET /api/runs/<id>"):
            self.assertEqual(sched[r]["roles"]["operator"], ["own_unit"], r)
        self.assertEqual(self.doc["services"]["monitor"]["routes"]["GET /api/runs"]["roles"]["operator"], ["own_unit"])
        held = set(grants.policy_holds_table(self.policy))
        for row in (("operator", "runs", "R", "own_unit"), ("operator", "runs", "O", "assigned_run"),
                    ("operator", "measurements", "R", "own_unit")):
            self.assertIn(row, held)
        self.assertIsNone(mon["qa"])                    # through the auditor composite
        self.assertNotIn("admin", mon)                  # I2
        self.assertEqual(self.doc["services"]["access"]["routes"]["POST /api/decisions/<id>/confirm"]["roles"],
                         {"qa": ["not_own_author"]})

    def test_access_host_compiled(self):
        # IAM 2.7: ACCESS_DOMAIN is compiled; GET / and /api/me (group user_manager) open the
        # page to every role the gate admits, each seeing the tabs its routes allow
        self.assertEqual(proxies.ENFORCEMENT["ACCESS_DOMAIN"], "compiled")
        admitted = proxies.admitted(self.policy, "ACCESS_DOMAIN")
        self.assertEqual(admitted, ["admin", "auditor", "qa", "qp"])
        access = self.doc["services"]["access"]["routes"]
        for r in ("GET /", "GET /api/me"):
            self.assertEqual(access[r]["group"], "user_manager", r)
            self.assertEqual(sorted(access[r]["roles"]), admitted, r)
        for r, level in (("POST /api/decisions/<id>/refuse", ["A"]), ("POST /api/decisions/<id>/review", ["A"]),
                         ("POST /api/decisions/<id>/withdraw", ["K"])):
            self.assertEqual((access[r]["group"], access[r]["levels"]), ("iam_users", level), r)
        self.assertEqual(access["POST /api/decisions/<id>/withdraw"]["roles"], {"admin": ["qa_dual_control"]})
        self.assertEqual(access["POST /api/review"]["roles"], {"qa": None})
        self.assertEqual(sorted(access["GET /api/review/<id>"]["roles"]), ["auditor", "qa", "qp"])
        self.assertNotIn("admin", access["GET /api/config-history"]["roles"])      # I2 (Q4)

    def test_routes_widening_table(self):
        p = self.policy
        w = self.doc["widening"]
        for old in [None] + sorted(p.roles):
            for new in sorted(p.roles):
                want = [[g, l] for g, l in p.widening(old, new)]
                self.assertEqual(w.get("-" if old is None else old, {}).get(new, []), want, (old, new))
        for row in w.values():
            self.assertTrue(row and all(row.values()), "empty entries are left out")
        self.assertEqual(self.doc["waivers"], [
            {"id": x["id"], "invariant": x["invariant"], "subject": x["subject"], "target": x["target"],
             "levels": x["levels"], "review": x["review_by"]} for x in p.waivers])

    def test_role_includes_and_scheduler_routes_2_4(self):
        # medcea_iam.actor_role() reads role_includes: the database's _own_role() rule
        inc = self.doc["role_includes"]
        self.assertEqual(set(inc), set(self.policy.roles))
        for r in self.policy.roles:
            self.assertEqual(inc[r], sorted(self.policy.effective_roles(r) - {r}), r)
        self.assertEqual(inc["production_manager"], ["operator"])
        sched = self.doc["services"]["scheduler"]["routes"]
        self.assertEqual(sched["GET /api/param-sets"]["group"], "controllers")
        # DELETE on a schedule retires it (medcea.retire_schedule): still level U
        self.assertEqual(sched["DELETE /api/schedules/<id>"]["levels"], ["U"])

    def test_exports_table_2_6(self):
        # Database Management's only source for what a person may export (IAM 2.6)
        ex = self.doc["exports"]
        self.assertEqual(ex["tool"], "db_export")
        mirrors = sorted(self.policy.groups["db_export"]["mirrors"])
        self.assertEqual(sorted(ex["groups"]), mirrors)
        self.assertEqual(sorted(ex["roles"]), sorted(self.policy.roles))
        for r in ("auditor", "qa"):
            self.assertEqual(ex["roles"][r], mirrors, r)
        self.assertEqual(ex["roles"]["qp"], ["audit_histories", "measurements", "runs"])
        for r in set(self.policy.roles) - {"auditor", "qa", "qp"}:
            self.assertEqual(ex["roles"][r], [], r)
        # the export and the service ceiling cannot drift apart
        objs = {o for g in ex["groups"].values() for o in g}
        selects = {o for g, k, o, pv in grants.privileges(self.policy)
                   if g == "svc_dbexport" and k == "table" and pv == "SELECT"}
        self.assertEqual(objs, selects)
        for o in ("medcea.mqtt_credential", "iam.mail_settings", "medcea.backup_remote_to_insert_measurement"):
            self.assertNotIn(o, objs)
        bad = copy.deepcopy(self.policy.data)
        del bad["resource_groups"]["db_export"]["mirrors"]
        with self.assertRaisesRegex(routes.RouteError, "db_export"):
            routes.compile(model.Policy(bad))

    def test_every_x_group_with_data_is_exported(self):
        # an X cell on a group with data the export does not mirror would export nothing, silently
        mirrors = set(self.policy.groups["db_export"]["mirrors"])
        for g, gd in self.policy.groups.items():
            has_data = any(m["type"] == "data" and "object" in m and not m.get("service_only") for m in gd["members"])
            if has_data and routes._who(self.policy, g, ["X"]):
                self.assertIn(g, mirrors, g)

    def test_no_constrained_x(self):
        # dbmgmt cannot evaluate a constraint: a constrained X would quietly export nothing.
        # If one appears, decide how dbmgmt evaluates it before relaxing this.
        for g in self.policy.groups:
            for r, c in routes._who(self.policy, g, ["X"]).items():
                self.assertIsNone(c, (g, r))

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


class WideningTest(unittest.TestCase):
    """model.Policy.widening (qa_dual_control, IAM 2.7) and its two compiled copies."""

    @classmethod
    def setUpClass(cls):
        cls.policy = model.load()

    def test_widening_values(self):
        p = self.policy
        w = p.widening("operator", "production_manager")
        self.assertEqual(len(w), 12)
        # operator held runs R under own_unit and O under assigned_run; production_manager holds both free
        self.assertIn(("runs", "R"), w)
        self.assertIn(("runs", "O"), w)
        self.assertEqual(p.widening("production_manager", "operator"), [])
        self.assertEqual(p.widening("qa", "auditor"), [])
        self.assertEqual(p.widening("engineer", "maintenance"), [])
        self.assertEqual(len(p.widening("auditor", "qa")), 11)
        self.assertEqual(len(p.widening(None, "operator")), 9)
        for r in p.roles:
            self.assertEqual(p.widening(r, r), [], r)
        self.assertEqual(p.holds(None), {})
        h = p.holds("operator")
        self.assertEqual(h[("runs", "R")], frozenset({"own_unit"}))
        self.assertEqual(h[("portal", "R")], "free")

    def test_widening_constraint_rules(self):
        d = copy.deepcopy(self.policy.data)
        # more alternative constraints OR together: wider; a subset is not
        # (schedules: no tool reaches it, and a reached level counts as free)
        d["matrix"]["schedules"]["maintenance"] = {"levels": ["R"], "constraint": "commissioning_unit"}
        d["matrix"]["schedules"]["qc"] = {"levels": ["R"], "constraint": "own_unit"}
        d["matrix"]["schedules"]["qp"] = {"levels": ["R"], "constraint": {"R": "own_unit"}}
        q = model.Policy(d)
        self.assertIn(("schedules", "R"), q.widening("qc", "maintenance"))       # another constraint
        self.assertIn(("schedules", "R"), q.widening("qc", "engineer"))          # constrained -> free
        self.assertNotIn(("schedules", "R"), q.widening("engineer", "qc"))       # free -> constrained
        self.assertNotIn(("schedules", "R"), q.widening("qc", "qp"))             # the same constraint
        # a role holding both alternatives (composite) is wider than one holding either
        q.roles["qc"] = dict(q.roles["qc"], includes=["maintenance"])
        self.assertIn(("schedules", "R"), q.widening("maintenance", "qc"))
        self.assertNotIn(("schedules", "R"), q.widening("qc", "maintenance"))

    def _compiled_rows(self, sql):
        body = re.search(r"FUNCTION medcea_auth\.role_widening\(p_old text, p_new text\).*?\(VALUES\s*(.*?)\n\s*\) t\(o, n, g, l\)",
                         sql, re.S)
        self.assertIsNotNone(body, "role_widening's VALUES")
        rows = set()
        for m in re.finditer(r"\((NULL|'[a-z_]+'), '([a-z_]+)', '([a-z_]+)', '([A-Z])'\)", body.group(1)):
            rows.add((None if m.group(1) == "NULL" else m.group(1).strip("'"), m.group(2), m.group(3), m.group(4)))
        return rows

    def test_widening_compiled_matches_model(self):
        p = self.policy
        rows = self._compiled_rows(grants.compiled_functions(p))
        want = {(old, new, g, l) for old in [None] + list(p.roles) for new in p.roles for g, l in p.widening(old, new)}
        self.assertEqual(rows, want)

    def test_role_widening_digest(self):
        doc = routes.compile(self.policy)
        fn = grants.compiled_functions(self.policy)
        self.assertIn(f"COMMENT ON FUNCTION medcea_auth.role_widening(text, text) IS 'policy {doc['digest']}';", fn)
        # verify (health-check iamgrants, tests/iam-schema.sh) compares the comment
        self.assertIn(f"'policy {doc['digest']}'", grants.sql(self.policy, "verify"))
        # a policy file given by name changes the route table's source, so both follow it
        other = routes.compile(self.policy, "v7.yaml")["digest"]
        self.assertIn(f"'policy {other}'", grants.sql(self.policy, "verify", source="v7.yaml"))

    def test_role_widening_stub_raises(self):
        # compiled: 22023 on a NULL or unknown new role and on an unknown old role
        fn = grants.compiled_functions(self.policy)
        body = fn[fn.index("FUNCTION medcea_auth.role_widening"):]
        body = body[:body.index("$w$;")]
        self.assertRegex(body, r"IF p_new IS NULL OR NOT \(p_new = ANY .*\(p_old IS NOT NULL AND NOT \(p_old = ANY ")
        self.assertIn("ERRCODE = '22023'", body)
        self.assertIn("IMMUTABLE SET search_path = pg_catalog", body)
        self.assertIn("ALTER FUNCTION medcea_auth.role_widening(text, text) OWNER TO medcea_owner;", fn)
        self.assertIn("REVOKE ALL ON FUNCTION medcea_auth.role_widening(text, text) FROM PUBLIC;", fn)
        # the migrations' stub raises (never '[]': an uncompiled database must not say "narrowing")
        with open(os.path.join(REPO, "apps", "database", "medcea_db_migrations.sql")) as f:
            mig = f.read()
        m = re.search(r"FUNCTION medcea_auth\.role_widening\s*\((.*?)\$[a-z_]*\$\s*;", mig, re.S)
        self.assertIsNotNone(m, "the migrations define no role_widening stub")
        self.assertIn("not compiled", m.group(1))
        self.assertRegex(m.group(1), r"RAISE EXCEPTION")
        self.assertNotIn("'[]'", m.group(1))


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


class MqttTest(unittest.TestCase):
    """compiler/mqtt.py: the MQTT Explorer's personal credential rows (IAM 3.5)."""

    @classmethod
    def setUpClass(cls):
        cls.policy = model.load()

    def test_engineer_rows(self):
        doc = mqtt.compile(self.policy)
        self.assertEqual(list(doc["roles"]), ["engineer"])     # only the roles holding R on mqtt_explorer
        rows = {(r["access"], r["topic"], r["constraint"]) for r in doc["roles"]["engineer"]}
        self.assertEqual(rows, {("read", "+/+/sense/#", None), ("read", "+/+/control/#", None),
                                ("read", "+/+/control_setpoint/#", None),
                                # control_setpoint is person_write: false (boards report there; IAM 3.5 decision)
                                ("write", "+/+/control/#", "commissioning_unit")})
        self.assertEqual((doc["ttl_hours"], doc["max_active"], doc["listener"]), (8, 3, "websocket"))
        self.assertEqual(doc["roles"]["engineer"] and proxies.admitted(self.policy, "MQTTX_DOMAIN"), ["engineer"])

    def test_deterministic_and_digest(self):
        a, b = mqtt.dumps(mqtt.compile(self.policy)), mqtt.dumps(mqtt.compile(model.load()))
        self.assertEqual(a, b)
        doc = json.loads(a)
        body = {k: v for k, v in doc.items() if k != "digest"}
        self.assertEqual(hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                         doc["digest"])

    def test_route_digest_does_not_move(self):
        # mqtt.json is its own ConfigMap key: the route table (and role_widening's stamp) ignore it
        d = copy.deepcopy(self.policy.data)
        d["resource_groups"]["mqtt_explorer"]["credential"]["ttl_hours"] = 4
        self.assertEqual(routes.compile(model.Policy(d))["digest"], routes.compile(self.policy)["digest"])

    def test_iam_pod_and_proxy_upstream(self):
        doc = netpol.compile(self.policy, "medcea", ["192.168.1.7"])
        iam = next(i for i in doc["items"] if i["metadata"]["name"] == "iam-iam")
        self.assertEqual(iam["spec"]["podSelector"], {"matchLabels": {"app": "iam-api"}})
        self.assertEqual(iam["spec"]["ingress"][0]["ports"], [{"protocol": "TCP", "port": 8085}])
        self.assertIn({"podSelector": {"matchLabels": {"app.kubernetes.io/instance": "mqttx-oauth2-proxy"}}},
                      iam["spec"]["ingress"][0]["from"])
        with open(os.path.join(REPO, "apps", "mqtt-explorer", "k8s", "oauth2-proxy-values.yaml")) as fh:
            self.assertIn('"http://iam-mqttx.${NAMESPACE}.svc.cluster.local:8085/_mqtt-credential"', fh.read())
        with open(os.path.join(REPO, "apps", "iam", "k8s", "iam.yaml")) as fh:
            m = fh.read()
        self.assertIn("name: iam-mqttx", m)
        self.assertIn("containerPort: 8085", m)

    def test_infra_ships_mqtt_json(self):
        with open(os.path.join(REPO, "deploy-infra.sh")) as fh:
            infra = fh.read()
        self.assertIn('--from-file=mqtt.json="$_IAM_DIR/mqtt.json"', infra)
        self.assertIn('"medcea/mqtt-digest=$IAM_MQTT_DIGEST"', infra)
        self.assertIn('"IAM_MQTT_PERSON": e["SW_MQTT"] == "true"', infra)
        self.assertRegex(infra, r'dba_record_switch "\$NAMESPACE" [^\n]*IAM_MQTT_PERSON')
        with open(os.path.join(REPO, "health-check.sh")) as fh:
            self.assertIn("iammqtt)      check_iammqtt", fh.read())


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

    def test_notebook_tokens_only_read(self):
        # IAM 3.2b review: notebook code is unvalidated; its tokens read, never write
        self.assertEqual(grants.read_only_clients(self.policy), ["workbench-notebook"])
        fn = grants.compiled_functions(self.policy)
        pre = fn[fn.index("FUNCTION medcea_auth.pre_request()"):fn.index("$pre$;")]
        self.assertIn("(c ->> 'azp') = ANY (ARRAY['workbench-notebook']::text[])", pre)
        self.assertIn("NOT IN ('GET', 'HEAD')", pre)
        self.assertIn("'client % may only read'", pre)
        self.assertIn("SET LOCAL transaction_read_only = on;", pre)
        # checked before the role is taken, so no write runs as the person's role
        self.assertLess(pre.index("may only read"), pre.index("SET LOCAL ROLE"))
        for c in grants.token_clients(self.policy):
            if c != "workbench-notebook":
                self.assertNotIn(c, grants.read_only_clients(self.policy))

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
        self.assertEqual(self.holders("medcea_auth.my_units()"), {"rr_operator"})
        self.assertEqual(self.holders("iam_policy.user_unit"),
                         {"access_svc", "iam_svc", "rr_auditor", "rr_qa", "svc_dbexport", "svc_monitor", "svc_scheduler"})
        self.assertEqual(self.holders("medcea.release_run(integer)"), {"rr_qp"})
        self.assertEqual(self.holders("medcea.approve_change(text,bigint,text)"), {"rr_qa"})
        self.assertEqual(self.holders("iam_policy.append_history(text,jsonb,text)"), {"iam_svc"})
        self.assertEqual(self.holders("iam_policy.log_export(text[],text[])"), {"svc_dbexport"})
        for g, k, o, p in self.privs:
            self.assertNotIn(p, grants.NEVER, (g, o))
            self.assertTrue(g in grants.managed(self.policy) or g in ("anon", "mqtt_auth", "access_svc"), g)
        # nothing for people on a service_only member
        for g, k, o, p in self.privs:
            if o in ("medcea.mqtt_credential", "medcea.backup_remote_to_insert_measurement"):
                self.assertFalse(g.startswith("rr_"), (g, o))

    def test_access_2_7(self):
        # the account decisions and the review: access_svc only (service_only), never rr_qa
        # through the approval rule, never svc_dbexport/iam_svc through audit_histories C
        for fn in ("iam.record_decision(text,text,text,text,text,text,text,text,bigint)",
                   "iam.withdraw_decision(integer,text)", "iam.confirm_decision(integer,text)",
                   "iam.refuse_decision(integer,text)", "iam.review_decision(integer,text)",
                   "iam.create_review(jsonb)", "iam.sign_off_review(integer,text)",
                   "medcea.revoke_person_mqtt(uuid,text)"):
            self.assertEqual(self.holders(fn), {"access_svc"}, fn)
        self.assertIn("access_svc", self.holders("medcea_auth.set_actor(text,text,text,text)"))
        self.assertEqual(self.holders("medcea_auth.role_widening(text,text)"), set())
        self.assertEqual(self.holders("medcea_auth._account_actor(text,text)"), set())
        self.assertEqual(self.holders("iam_policy.append_history(text,jsonb,text)"), {"iam_svc"})
        self.assertFalse({o for g, k, o, p in self.privs if g == "rr_qa" and k == "function" and o.startswith("iam.")})
        # access_svc reads no MQTT credential: revoke_person_mqtt is an owner definer
        self.assertNotIn("access_svc", self.holders("medcea.mqtt_service_credential"))
        # the decision record and the histories are written by the functions only
        for t in ("iam.account_decision", "iam.user_status_history", "iam.access_request_history",
                  "iam.config_history", "iam.access_review"):
            self.assertEqual({p for g, k, o, p in self.privs if o == t}, {"SELECT"}, t)
        self.assertEqual({p for g, k, o, p in self.privs if g == "access_svc" and o == "iam.mail_settings_pending"},
                         {"SELECT", "INSERT", "UPDATE"})
        self.assertIn("access_svc", self.holders("medcea.cea_unit", "SELECT"))            # Q7: unit codes
        self.assertNotIn("iam_policy.propose_unit(uuid,integer,text)", {o for g, k, o, p in self.privs})
        self.assertEqual(grants.NOT_BUILT["iam_policy.propose_unit(uuid,integer,text)"], "4.3")
        for sig in ("iam.confirm_decision(integer,text)", "iam.sign_off_review(integer,text)"):
            self.assertNotIn(sig, grants.NOT_BUILT)

    def test_no_iam_delete(self):
        for g, k, o, p in self.privs:
            if o.startswith("iam.") or o.startswith("iam_policy."):
                self.assertIn(p, ("SELECT", "INSERT", "UPDATE", "EXECUTE"), (g, o, p))
        # the access deploy grants nothing itself any more (the compiler does), CONNECT aside
        sql = self.read("apps/access/access_db.sql")
        self.assertNotRegex(sql, r"(?m)^\s*GRANT\s+(?!CONNECT\b)[A-Z, ]*\bON\b")
        self.assertNotRegex(sql, r"(?m)^\s*GRANT\b[^;]*\bDELETE\b")

    def test_sign_off_service_only(self):
        for fn in ("iam.sign_off_review(integer,text)", "iam.create_review(jsonb)"):
            self.assertFalse(self.holders(fn) & {"svc_dbexport", "iam_svc", "rr_qa"}, fn)

    def test_without_iam(self):
        # --without-iam: no iam.* object and no access_svc anywhere, as DEFERRED was
        priv = grants.privileges(self.policy, without_iam=True)
        self.assertFalse([x for x in priv if x[2].startswith("iam.") or x[2] == "iam" or x[0] == "access_svc"])
        self.assertEqual(set(priv), {x for x in self.privs if not (x[2].startswith("iam.") or x[2] == "iam"
                                                                   or x[0] == "access_svc")})
        for mode in ("additive", "enforce", "verify"):
            text = grants.sql(self.policy, mode, without_iam=True)
            self.assertNotRegex(text, r"(?<![a-z_])iam\.[a-z_]+", mode)
            self.assertNotIn("access_svc", text, mode)
            self.assertNotRegex(text, r"IN SCHEMA [a-z_, ]*\biam\b(?!_)", mode)
            full = grants.sql(self.policy, mode)
            self.assertIn("access_svc", full, mode)
            self.assertRegex(full, r"\biam\.account_decision\b", mode)
        # its I9 still asserts anon and PUBLIC hold nothing in iam
        enf = grants.sql(self.policy, "enforce", without_iam=True)
        self.assertIn("I9: anon/PUBLIC hold % in schema iam", enf)
        self.assertNotIn("I9: anon/PUBLIC hold % in schema iam", grants.sql(self.policy, "enforce"))
        self.assertIn("medcea, medcea_auth, iam_policy, iam FROM %I", grants.sql(self.policy, "enforce"))
        self.assertIn("medcea, medcea_auth, iam_policy FROM %I", enf)
        # access_svc connects and is in the I15 scope in both modes with iam
        self.assertRegex(grants.sql(self.policy, "enforce"), r"FOREACH g IN ARRAY ARRAY\[[^]]*'access_svc'[^]]*\]::text\[\] LOOP\s+"
                                                            r"CONTINUE WHEN NOT EXISTS \(SELECT FROM pg_catalog.pg_roles WHERE rolname = g\);\s+"
                                                            r"EXECUTE pg_catalog.format\('GRANT CONNECT")
        self.assertNotIn("access_svc", grants.managed(self.policy))
        self.assertNotIn("access_svc", grants.login_roles(self.policy))

    def test_scheduler_2_4(self):
        # DELETE /api/schedules/<id> retires through medcea.retire_schedule (U on schedules)
        self.assertEqual(self.holders("medcea.retire_schedule(integer)"), {"rr_production_manager", "svc_scheduler"})
        # the runner reads a unit's actuators (device, component), never the credentials
        self.assertIn("svc_scheduler", self.holders("medcea.device", "SELECT"))
        self.assertEqual({p for g, k, o, p in self.privs if g == "svc_scheduler" and o == "medcea.device"}, {"SELECT"})
        self.assertNotIn("svc_scheduler", self.holders("medcea.mqtt_credential"))
        self.assertNotIn("svc_scheduler", self.holders("medcea.schedule", "DELETE"))
        for fn in ("medcea.start_run(integer)", "medcea.set_run_status(integer,text)", "medcea.finish_run(integer,text)",
                   "medcea.record_cycle(integer,jsonb)", "medcea.propose_setting(text,jsonb)",
                   "medcea_auth.set_actor(text,text,text,text)", "medcea_auth.set_system_actor(text,text,bigint)"):
            self.assertIn("svc_scheduler", self.holders(fn), fn)
        # the internal actor is the deploy scripts' only (superuser): the scheduler
        # uses it under IAM_DB_ROLES=false as postgres, never as svc_scheduler
        self.assertEqual(self.holders("medcea_auth._set_internal_actor(text)"), set())

    def test_written_by_functions_is_select_only(self):
        for g, m in grants._data_members(self.policy):
            if m.get("written_by") == "functions" or m.get("view"):
                self.assertEqual({p for _, _, o, p in self.privs if o == m["object"]} - {"SELECT"}, set(), m["object"])

    def test_rls_and_memberships(self):
        pols = {(x["object"], x["role"], x["cmd"]): x for x in self.doc["rls"]}
        self.assertIn("my_zones", pols[("medcea.measurement", "rr_operator", "SELECT")]["using"])
        for o in ("medcea.recipe_run", "medcea.recipe_line_cycle_run", "medcea.run_release"):
            self.assertIn("my_units", pols[(o, "rr_operator", "SELECT")]["using"])
            self.assertEqual(pols[(o, "rr_production_manager", "SELECT")]["using"], "true")
        self.assertEqual(pols[("medcea.measurement", "rr_production_manager", "SELECT")]["using"], "true")
        self.assertEqual(pols[("medcea.measurement", "svc_ingest", "INSERT")]["check"], "true")
        for o in ("medcea.measurement", "medcea.recipe_run", "medcea.recipe_line_cycle_run", "medcea.run_release"):
            readers = {g for g, k, ob, p in self.privs if ob == o and p == "SELECT"}
            self.assertEqual({r for (ob, r, c) in pols if ob == o and c == "SELECT"}, readers, o)
        mem = {(r, m): (i, st) for r, m, i, st in grants.memberships(self.policy)}
        self.assertEqual(mem[("rr_admin", "rr_admin_login")], (True, False))
        self.assertEqual(mem[("rr_operator", "authenticator")], (False, True))
        self.assertEqual(len([1 for r, m in mem if m == "authenticator"]), len(self.policy.roles) + 1)

    def test_service_logins(self):
        # IAM Phase 2.5 (IAM_DB_SERVICE_ROLES): the listed login roles log in while
        # IAM_DB_ROLES is false; nobody else does, and a person's rr_ role never
        add = grants.sql(self.policy, "additive", service_logins=["svc_scheduler", "rr_admin_login"])
        self.assertIn("ALTER ROLE svc_scheduler LOGIN", add)
        self.assertIn("ALTER ROLE rr_admin_login LOGIN", add)
        self.assertIn("ALTER ROLE svc_monitor NOLOGIN", add)
        self.assertIn("ALTER ROLE rr_admin NOLOGIN", add)
        # pgAdmin's login inherits rr_admin while it may log in, and only then
        self.assertIn("GRANT rr_admin TO rr_admin_login WITH INHERIT TRUE, SET FALSE;", add)
        self.assertNotIn("GRANT rr_admin TO rr_admin_login",
                         grants.sql(self.policy, "additive", service_logins=["svc_scheduler"]))
        self.assertNotIn("TO authenticator WITH", add)                # its memberships are enforce's
        for bad in (["rr_operator"], ["authenticator"], ["anon"]):
            with self.assertRaises(grants.GrantsError):
                grants.sql(self.policy, "additive", service_logins=bad)
        with self.assertRaises(grants.GrantsError):
            grants.sql(self.policy, "enforce", service_logins=["svc_scheduler"])
        # the privileges do not depend on who may log in
        self.assertEqual(grants.sql(self.policy, "additive", part="assert"),
                         grants.sql(self.policy, "additive", part="assert", service_logins=["svc_ingest"]))
        # the assertions read the state, so verify (health-check) needs no parameter:
        # rr_admin_login -> rr_admin only while it may log in; no other managed role logs in
        a = grants.sql(self.policy, "verify")
        self.assertIn("rolcanlogin FROM pg_catalog.pg_roles WHERE rolname = 'rr_admin_login'", a)
        self.assertIn("managed roles that are no login role may log in", a)

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
        src = (self.read("apps/database/medcea_db_migrations.sql") + self.read("apps/access/access_db.sql")
               + grants.compiled_functions(self.policy))
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
        src = (self.read("apps/database/medcea_db_migrations.sql") + self.read("apps/access/access_db.sql")
               + grants.compiled_functions(self.policy))
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

    def test_own_unit_reads_are_scoped(self):
        # IAM 2.6: every monitor/scheduler handler of a route that grants own_unit calls
        # _unit_scope, and the services' SQL is still my_units()/my_zones()'s rule
        doc, iam = routes.compile(self.policy), routes_diff._medcea_iam()
        found = {}
        for svc in ("monitor", "scheduler"):
            table = doc["services"][svc]["routes"]
            tree = ast.parse(self.read(routes_diff.SOURCES[svc]["file"]))
            for fn in ast.walk(tree):
                if not isinstance(fn, ast.FunctionDef):
                    continue
                served, _, _ = routes_diff._flask(ast.Module(body=[fn], type_ignores=[]))
                for method, path in served:
                    key = iam.match(table, method, path)
                    if key and any("own_unit" in (c or []) for c in table[key]["roles"].values()):
                        calls = {n.func.id for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
                        self.assertIn("_unit_scope", calls, f"{svc} {method} {path} ({fn.name})")
                        found[svc] = found.get(svc, 0) + 1
        self.assertEqual(found, {"monitor": 4, "scheduler": 5})
        units = "FROM iam_policy.user_unit uu WHERE uu.person_sub = %s::uuid"
        zones = "JOIN iam_policy.user_unit uu ON uu.unit_id = cz.unit_id"
        mon, sch = self.read("apps/monitor/monitor-api.py"), self.read("apps/scheduler/scheduler-api.py")
        self.assertIn(units, mon)
        self.assertIn(units, sch)
        self.assertIn(zones, mon)
        mig = self.read("apps/database/medcea_db_migrations.sql")
        body = mig[mig.index("FUNCTION medcea_auth.my_zones()"):]
        self.assertIn(zones, body[:body.index("END $$")])
        for src in (mon, sch):   # iam_signin_flow counts 'would refuse' lines
            self.assertNotIn("own_unit: would refuse", src)
            self.assertNotIn("run_logs: would refuse", src)

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
            "apps/access/k8s/oauth2-proxy-values.yaml": [("apps/access/deploy.sh", "ACCESS_DOMAIN")],
        }
        compiled = {h for h, st in proxies.ENFORCEMENT.items() if st == "compiled"}
        self.assertEqual(compiled, {h for v in wiring.values() for _, h in v})
        for template, users in wiring.items():
            self.assertIn("allowed_groups = ${ALLOWED_GROUPS}", self.read(template), template)
            for script, host in users:
                src = self.read(script)
                # (the access deploy compiles it before it changes anything, into _COMPILED_GROUPS,
                # and narrows to ["admin"] until every pod is proven to enforce: spec §4.6)
                self.assertRegex(src, rf'(?m)^\s*(ALLOWED_GROUPS|_COMPILED_GROUPS)="\$\(policy_groups {host}\)"',
                                 f"{script}: {host}")
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
        self.assertEqual(proxies.describe(p, "ACCESS_DOMAIN", ["admin"])[1], [p.roles["admin"]["label"]])  # the narrow fallback
        self.assertEqual(proxies.describe(p, "ACCESS_DOMAIN", proxies.admitted(p, "ACCESS_DOMAIN"))[1],
                         [p.roles[r]["label"] for r in p.roles if r in ("admin", "auditor", "qa", "qp")])
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
            # IAM 2.6: an export leaves the platform, so dbmgmt enforces whatever IAM_ENFORCE says
            "apps/frontend/k8s/dbmgmt.yaml": ("apps/frontend/html/dbmgmt-api.py", ["http_check(self, 'dbmgmt', enforce=True)"]),
            "apps/frontend/k8s/config-ui.yaml": ("apps/frontend/k8s/recipe-fileserver.yaml", ["http_check(self, 'platform-api')"]),
            "apps/access/k8s/access.yaml": ("apps/access/access-api.py", [
                # IAM 2.7: the admin port enforces whatever IAM_ENFORCE says (spec §5.1),
                # through medcea_iam.http_check(..., enforce=True)
                "http_check(self, iam, self.IAM_SERVICE, self.ENFORCE_ALWAYS)", "ENFORCE_ALWAYS = True",
                "enforce=True", "IAM_SERVICE = 'access-public'",
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
        # IAM 2.6: each pod carries IAM_ENFORCE (rendered by its deploy) and, when /iam/ is
        # missing, fails closed on it alone (dbmgmt always); health-check iamenforce
        # compares the copies
        for manifest, (source, _) in services.items():
            self.assertRegex(self.read(manifest), r'name: IAM_ENFORCE,?\s+(# .*\n\s+)?value: "\$\{IAM_ENFORCE\}"', manifest)
            fallback = ("send_error(503, 'access policy not loaded')" if "dbmgmt" in source
                        else "os.environ.get('IAM_ENFORCE') == 'true'")
            self.assertTrue(fallback in self.read(source), f"{source}: no fail-closed fallback {fallback}")
        for deploy, manifests in (("apps/scheduler/deploy.sh", ["scheduler.yaml"]), ("apps/monitor/deploy.sh", ["monitor.yaml"]),
                                  ("apps/frontend/deploy.sh", ["config-ui.yaml", "dbmgmt.yaml"]),
                                  ("apps/access/deploy.sh", ["access.yaml"])):
            lines = self.read(deploy).splitlines()
            for mf in manifests:
                render = [l for l in lines if "render " in l and f"k8s/{mf}" in l]
                self.assertTrue(render and all("IAM_ENFORCE" in l for l in render), f"{deploy}: {mf}")
        self.assertRegex(self.read("health-checks.conf"), r"\| iamenforce +\|")
        self.assertIn('iamenforce)   check_iamenforce', self.read("health-check.sh"))
        # ... and every IAM_ENFORCE transition is in the hash chain
        self.assertRegex(infra, r'dba_record_switch "\$NAMESPACE" [^\n]*IAM_ENFORCE')
        self.assertIn("dba_record_switch()", self.read("apps/database/lib-db-apply.sh"))

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

    def test_grafana_wiring(self):
        """IAM 3.1: Grafana's role setting is rendered from the policy, its admin never in argv."""
        values = self.read("k8s/grafana/values.yaml")
        self.assertIn('GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH: "${GRAFANA_ROLE_PATH}"', values)
        self.assertIn('GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_STRICT: "${GRAFANA_ROLE_STRICT}"', values)
        self.assertIn('GF_AUTH_GENERIC_OAUTH_ALLOW_ASSIGN_GRAFANA_ADMIN: "false"', values)
        self.assertIn('GF_AUTH_GENERIC_OAUTH_SCOPES: "openid profile email groups"', values)
        self.assertIn("existingSecret: grafana-admin", values)
        # no persistence: a changed role path rolls a pod with an empty database, which is
        # what ends the old sessions (there is no revocation step)
        self.assertNotRegex(values, r"(?m)^persistence:")
        infra = self.read("deploy-infra.sh")
        # envsubst leaves an unlisted ${VAR} as literal text (lib-render.sh)
        call = re.search(r'render "\$SCRIPT_DIR/k8s/grafana/values.yaml"(.*?)>', infra, re.S).group(1)
        used = set(re.findall(r"\$\{([A-Z_]+)\}", values))
        self.assertEqual(used - set(call.replace("\\", " ").split()), set())
        # compiled before the realm loses the grafana_* roles and their mapper
        self.assertLess(infra.index("policy_grafana ||"), infra.index("roles/${_r}"))
        self.assertLess(infra.index("policy_grafana ||"), infra.index("grafana-realm-roles"))
        self.assertLess(infra.index("policy_grafana ||"), infra.index("helm3 upgrade --install grafana"))
        self.assertNotIn("adminPassword=", infra)
        self.assertNotIn("adminUser=", infra)
        for script in ("apps/report/deploy.sh", "apps/report/uninstall.sh"):
            src = self.read(script)
            self.assertNotIn('-u "admin:', src, script)
            self.assertNotIn("ADMIN_PASS", src, script)
            self.assertIn("-K <(grafana_admin_cfg)", src, script)
        lib = self.read("infra/lib-oauth2-proxy.sh")
        pre_31 = ("contains(roles[*], 'grafana_admin') && 'Admin' || "
                  "contains(roles[*], 'grafana_developer') && 'Editor' || 'Viewer'")
        self.assertIn(f'GRAFANA_PRE_31_PATH="{pre_31}"', lib)
        self.assertIn("compile grafana", lib)
        self.assertIn("allowUiUpdates: false", self.read("apps/report/k8s/dashboard-provider.yaml"))
        # generated before configure.sh's early exit, or an existing install never gets it
        conf = self.read("infra/configure.sh")
        self.assertLess(conf.index("cfg_set GRAFANA_BREAKGLASS_PASS"), conf.index("[[ ${#MISSING[@]} -eq 0"))

    def test_workbench_wiring(self):
        """IAM 3.2: JupyterHub's gate is rendered from the policy and fails closed."""
        values = self.read("k8s/workbench/values.yaml")
        for line in ("allow_all: ${WORKBENCH_ALLOW_ALL}", "admin_users: []",
                     "allowed_groups: ${WORKBENCH_ALLOWED_GROUPS}", "groups: ${WORKBENCH_ADMIN_GROUPS}",
                     "users: ${WORKBENCH_HUBADMIN_USERS}", "loadRoles:", "workbench-admin:",
                     "scopes: [admin-ui, list:users, read:users, servers, delete:users]",
                     "custom_403_message: ${WORKBENCH_403_MESSAGE}",
                     'auth_state_groups_key: "oauth_user.groups"', "delete_pvc: false",
                     "allow_existing_users: false", "enable_auth_state: false", "oauth_token_expires_in: 3600"):
            self.assertIn(line, values)
        self.assertNotIn("${ADMIN_USER}", values)   # the hub administrator comes from policy_workbench
        code = "\n".join(l.split("#")[0] for l in values.splitlines())   # comments may name them
        self.assertNotIn("admin_groups:", code)      # it would give the built-in admin role (tokens)
        self.assertNotIn("load_roles", code)         # hub.loadRoles keeps the chart's idle-culler role
        src = self.read("infra/deploy-workbench.sh")
        self.assertIn("policy_workbench || die", src)
        self.assertLess(src.index("policy_workbench || die"), src.index("upgrade --install workbench"))
        call = re.search(r'render "\$REPO_ROOT/k8s/workbench/values.yaml"(.*?)>', src, re.S).group(1)
        used = set(re.findall(r"\$\{([A-Z_]+)\}", values))
        self.assertEqual(used - set(call.replace("\\", " ").split()), set())
        lib = self.read("infra/lib-oauth2-proxy.sh")
        self.assertIn("compile jupyterhub --setting allowed_groups", lib)
        self.assertIn("compile jupyterhub --setting admin_groups", lib)

    def test_onboarding_and_pgadmin_wiring(self):
        """IAM 3.4: the wizard's --required-role and pgAdmin's claims come from policy_tool."""
        self.assertEqual({h for h, st in proxies.ENFORCEMENT.items() if st.startswith("tool")},
                         {"GRAFANA_DOMAIN", "WORKBENCH_DOMAIN", "ONBOARD_DOMAIN", "PGADMIN_DOMAIN"})
        tmpl = self.read("k8s/pgadmin/pgadmin.yaml")
        self.assertIn("'OAUTH2_ADDITIONAL_CLAIMS': ${PGADMIN_OAUTH2_CLAIMS}}]", tmpl)
        self.assertNotIn("{'groups': [", tmpl)
        infra = self.read("deploy-infra.sh")
        self.assertIn('PGADMIN_OAUTH2_CLAIMS="$(REPO_ROOT="$SCRIPT_DIR" policy_tool pgadmin)"', infra)
        # envsubst leaves an unlisted ${VAR} as literal text; the call spans two lines
        call = re.search(r'render "\$SCRIPT_DIR/k8s/pgadmin/pgadmin.yaml"(.*?)\|', infra, re.S).group(1)
        used = set(re.findall(r"\$\{([A-Z_]+)\}", tmpl))
        self.assertEqual(used - set(call.replace("\\", " ").split()), set())
        self.assertLess(infra.index("policy_tool pgadmin"), infra.index('render "$SCRIPT_DIR/k8s/pgadmin/pgadmin.yaml"'))
        self.assertIn("compile \"$1\"", self.read("infra/lib-policy-tools.sh"))
        deploy = self.read("apps/edge-wizard/deploy.sh")
        self.assertIn("policy_tool edge-wizard", deploy)
        self.assertLess(deploy.index("unit_flash_runs | xargs"), deploy.index('systemctl --user restart "$UNIT"'))
        self.assertLess(deploy.index("policy_tool edge-wizard"), deploy.index('systemctl --user restart "$UNIT"'))
        # the deployment's env holds the client secret: on stdin only, never an argument
        for script in ("health-check.sh", "tests/iam-hosts.sh"):
            src = self.read(script)
            self.assertIn('PGADMIN_CONFIG_OAUTH2_CONFIG")].value}', src, script)
            self.assertNotRegex(src, r'python3 -c [^\n]*"\$(cfg|have_env|oauth)"', script)
        self.assertIn("pgadminroles", self.read("health-checks.conf"))
        self.assertIn("onboardroles", self.read("health-checks.conf"))

    def _health_fn(self, fn, setup, kubectl_out, env=None):
        """Run one health-check function with a fake kubectl/pgrep; its _record line."""
        import subprocess
        import tempfile
        tmp = tempfile.mkdtemp()
        for name, body in (("kubectl", f"#!/bin/sh\ncat <<'EOF'\n{kubectl_out}\nEOF\n"),
                           ("pgrep", "#!/bin/sh\nprintf '%s\\n' \"$FAKE_PGREP\"\n")):
            path = os.path.join(tmp, name)
            with open(path, "w") as f:
                f.write(body)
            os.chmod(path, 0o755)
        src = self.read("health-check.sh")
        body = re.search(rf"(?ms)^{fn}\(\) \{{.*?^\}}", src).group(0)
        script = (f'_record() {{ echo "$1|$2|$3"; }}\nSCRIPT_DIR={REPO}\nTIMEOUT=5\nKUBECTL=kubectl\n'
                  f"{body}\n{setup}\n")
        e = dict(os.environ, PATH=tmp + ":" + os.environ["PATH"], **(env or {}))
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=e).stdout.strip()

    def test_health_pgadminroles(self):
        secret = "S3CRET-pgadmin-client"
        live = ("[{'OAUTH2_NAME': 'keycloak', 'OAUTH2_CLIENT_SECRET': '%s', "
                "'OAUTH2_ADDITIONAL_CLAIMS': {'groups': ['admin']}}]" % secret)
        out = self._health_fn("check_pgadminroles", 'check_pgadminroles "pgAdmin roles" medcea', live)
        self.assertTrue(out.startswith("OK|"), out)
        self.assertNotIn(secret, out)
        out = self._health_fn("check_pgadminroles", 'check_pgadminroles "pgAdmin roles" medcea',
                              live.replace("['admin']", "['admin', 'qa']"))
        self.assertTrue(out.startswith("FAIL|"), out)
        self.assertNotIn(secret, out)
        out = self._health_fn("check_pgadminroles", 'check_pgadminroles "pgAdmin roles" medcea', live,
                              {"IAM_GATES": "false"})
        self.assertTrue(out.startswith("WARN|"), out)

    def test_health_onboardroles(self):
        daemon = "42 python3 edge/src/host/wizard_server.py --dir /tmp/x --daemon --auth keycloak"
        run = lambda argv, **env: self._health_fn(  # noqa: E731
            "check_onboardroles", 'check_onboardroles "Onboarding roles"', "", dict(FAKE_PGREP=argv, **env))
        self.assertTrue(run(daemon + " --required-role engineer,maintenance --allowed-host x").startswith("OK|"))
        self.assertTrue(run(daemon + " --required-role engineer").startswith("FAIL|"))
        self.assertTrue(run(daemon).startswith("FAIL|"))
        self.assertTrue(run("").startswith("SKIP|"))
        self.assertTrue(run(daemon, IAM_GATES="false", EDGE_WIZARD_ROLE="").startswith("WARN|"))

    def test_policy_tool_shell(self):
        """infra/lib-policy-tools.sh: compiled under IAM_GATES=true, pre-policy under false."""
        import subprocess

        def run(tool, env, repo=REPO):
            e = dict(os.environ, REPO_ROOT=repo, **env)
            return subprocess.run(["bash", "-c", f'source "{REPO}/infra/lib-policy-tools.sh"; policy_tool {tool}'],
                                  capture_output=True, text=True, env=e)
        r = run("edge-wizard", {"IAM_GATES": "true", "EDGE_WIZARD_ROLE": ""})
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "engineer,maintenance\n", ""))
        r = run("edge-wizard", {"IAM_GATES": "true", "EDGE_WIZARD_ROLE": "operator"})
        self.assertEqual(r.stdout, "engineer,maintenance\n")
        self.assertIn("is ignored", r.stderr)
        r = run("edge-wizard", {"IAM_GATES": "false", "EDGE_WIZARD_ROLE": "operator"})
        self.assertEqual(r.stdout, "operator\n")
        self.assertIn("IAM_GATES=false", r.stderr)
        self.assertEqual(run("edge-wizard", {"IAM_GATES": "false", "EDGE_WIZARD_ROLE": ""}).stdout, "\n")
        self.assertEqual(run("pgadmin", {"IAM_GATES": "false"}).stdout, "{'groups': ['admin']}\n")
        r = run("edge-wizard", {"IAM_GATES": "true"}, repo="/nonexistent")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")
        self.assertEqual(run("zeppelin", {}).returncode, 2)

    def test_node_red_wiring(self):
        """IAM 3.3: Node-RED's adminAuth is rendered from the policy; tokens never in argv."""
        infra = self.read("deploy-infra.sh")
        self.assertIn('cli.py" compile node-red)', infra)
        self.assertIn("create configmap node-red-auth", infra)
        self.assertIn("auth/strategy/callback", infra)
        self.assertNotIn("--set timezone", infra)   # chart 0.40.0 has no such value: TZ in env
        values = self.read("k8s/node-red/values.yaml")
        call = re.search(r'render "\$SCRIPT_DIR/k8s/node-red/values.yaml"(.*?)>', infra, re.S).group(1)
        used = set(re.findall(r"\$\{([A-Z_]+)\}", values))
        self.assertEqual(used - set(call.replace("\\", " ").split()), set())
        self.assertIn("NR_SETTINGS_CHECKSUM", used)
        for line in ("configMapName: node-red-settings", "name: node-red-auth, optional: true",
                     "mountPath: /auth-policy", "passport-openidconnect@0.1.2", "storageClass: microk8s-hostpath",
                     "name: node-red-oidc, key: client-secret", "name: node-red-admin-tokens, key: deploy"):
            self.assertIn(line, values)
        self.assertNotRegex(values, r"subPath: permissions")   # a directory mount follows the ConfigMap
        js = self.read("k8s/node-red/settings.js")
        for text in ("/auth-policy/permissions.json", "audit: true", "autoLogin: true", "functionExternalModules: false",
                     "timingSafeEqual", "type: 'credentials', users: []"):
            self.assertIn(text, js)
        self.assertNotRegex(js, r"(?m)^\s*httpNodeAuth")
        self.assertNotRegex(js, r"(?m)^\s*default:")
        # nine parameters: Node-RED 3.1 copies the arity, passport-openidconnect then passes the claims
        self.assertRegex(js, r"verify: function \((\w+, ){8}done\)")
        for script in ("apps/node-red/deploy.sh", "apps/node-red/uninstall.sh"):
            src = self.read(script)
            self.assertIn("lib-node-red.sh", src, script)
            self.assertNotRegex(src, r'(?<!nr_)\bcurl [^\n]*\$NR_BASE', script)
            self.assertNotIn("__PG_PASS__|", src, script)   # no password through sed's argv
        lib = self.read("infra/lib-node-red.sh")
        self.assertIn("-H @<(printf 'Authorization: Bearer %s\\n'", lib)
        self.assertNotRegex(lib + self.read("apps/node-red/deploy.sh"), r'-H "Authorization: Bearer \$')
        lib_op = self.read("infra/lib-oauth2-proxy.sh")
        self.assertRegex(lib_op, r"NODE_RED_DOMAIN\|MQTTX_DOMAIN\)")   # keep the compiled list under false
        conf, hc = self.read("health-checks.conf"), self.read("health-check.sh")
        for kind in ("noderedflows", "noderedauth"):
            self.assertRegex(conf, rf"\| {kind} +\|")
            self.assertIn(f"{kind}) ", hc)

    def test_2_6_scheduler_routes_removed(self):
        """No person compresses or deletes a run log, nothing deletes a Q-table (IAM 2.6)."""
        api = self.read("apps/scheduler/scheduler-api.py")
        for gone in ("/api/logs/compress", "/api/logs/delete", "algorithm-state', methods=['DELETE']",
                     "DELETE FROM medcea.algorithm_state"):
            self.assertNotIn(gone, api)
        self.assertIn("id='sys_log_retention'", api)
        self.assertIn("job.id.startswith('sched_')", api)
        self.assertIn('log_retention.py="$SCRIPT_DIR/log_retention.py"', self.read("apps/scheduler/deploy.sh"))
        self.assertIn("apps/scheduler/log_retention.py", self.read("tests/iam-runner.sh"))
        for ui in ("apps/scheduler/html/scheduler.html", "apps/frontend/html/index.html"):
            html = self.read(ui)
            self.assertNotIn("logs/compress", html, ui)
            self.assertNotIn("logs/delete", html, ui)
            self.assertNotRegex(html, r"algorithm-state[^\n]*method:\s*'DELETE'", ui)
        index = self.read("apps/frontend/html/index.html")
        self.assertIn("'/rpc/retire_algorithm_state'", index)
        self.assertIn("e.code === '42501'", index)
        self.assertEqual(routes_diff.REMOVED, {})


if __name__ == "__main__":
    unittest.main(verbosity=1)
