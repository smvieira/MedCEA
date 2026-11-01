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
        # the editor token arrives as /?access_token=…; the proxy must not log "/"
        self.assertIn('exclude_logging_paths = "/"', self.read("k8s/oauth2-proxy/values-node-red.yaml"))
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
        # persistent (decision of 1 Nov 2026): Editors' own dashboards survive a restart; a
        # changed role path reaches a session at its 5 min idle / 1 h bound, not at the restart
        import yaml
        doc = yaml.safe_load(values)
        self.assertEqual(doc["persistence"]["enabled"], True)
        self.assertEqual(doc["persistence"]["type"], "pvc")
        self.assertEqual(doc["persistence"]["storageClassName"], "microk8s-hostpath")
        self.assertEqual(doc["persistence"]["size"], "${GRAFANA_STORAGE}")
        self.assertNotIn("existingClaim", doc["persistence"])
        # one Grafana on the SQLite file at a time; the chart chowns the hostpath to 472
        self.assertEqual(doc["deploymentStrategy"], {"type": "Recreate"})
        self.assertTrue(doc["initChownData"]["enabled"])
        self.assertNotIn("securityContext", doc)          # the chart's runAsUser/fsGroup 472
        # microk8s-hostpath makes the volume root 0777 with no sticky bit: closed at each start
        (close,) = doc["extraInitContainers"]
        self.assertEqual(close["command"], ["chmod", "0700", "/var/lib/grafana"])
        self.assertEqual(close["volumeMounts"], [{"name": "storage", "mountPath": "/var/lib/grafana"}])
        self.assertEqual(close["securityContext"]["capabilities"], {"drop": ["ALL"], "add": ["FOWNER"]})
        self.assertEqual(close["image"], "docker.io/library/busybox:1.36")
        self.assertNotIn("{{", yaml.safe_dump(close))     # the chart runs tpl on it
        self.assertIn('GRAFANA_STORAGE="2Gi"', self.read("config.env.example"))
        self.assertIn('GRAFANA_STORAGE="${GRAFANA_STORAGE:-2Gi}"', self.read("deploy-infra.sh"))
        self.assertIn("Grafana volume           | pvc   | $NAMESPACE/grafana",
                      self.read("health-checks.conf"))
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
                     "allow_existing_users: false", "enable_auth_state: false", "oauth_token_expires_in: 300",
                     "cookie_max_age_days: 0.003472", 'logout_redirect_url: "${WORKBENCH_LOGOUT_URL}"'):
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
        # envsubst leaves an unlisted ${VAR} as literal text; each call spans lines.
        # The first render only hashes Secret pgadmin-config, the second is applied.
        calls = [c.replace("\\", " ").split() for c in
                 re.findall(r'render "\$SCRIPT_DIR/k8s/pgadmin/pgadmin.yaml"(.*?)\|', infra, re.S)]
        self.assertEqual(len(calls), 2)
        used = set(re.findall(r"\$\{([A-Z_]+)\}", tmpl))
        self.assertEqual(used - set(calls[1]), set())
        self.assertEqual(used - set(calls[0]), {"PGADMIN_CONFIG_CHECKSUM"})
        self.assertLess(infra.index("policy_tool pgadmin"), infra.index('render "$SCRIPT_DIR/k8s/pgadmin/pgadmin.yaml"'))
        self.assertLess(infra.index('PGADMIN_CONFIG_CHECKSUM="$('),
                        infra.index("PLATFORM_IP PGADMIN_OAUTH2_SERVER_USERS PGADMIN_CONFIG_CHECKSUM | $MK8S kubectl apply"))
        self.assertIn("compile \"$1\"", self.read("infra/lib-policy-tools.sh"))
        deploy = self.read("apps/edge-wizard/deploy.sh")
        self.assertIn("policy_tool edge-wizard", deploy)
        self.assertLess(deploy.index("unit_flash_runs | xargs"), deploy.index('systemctl --user restart "$UNIT"'))
        self.assertLess(deploy.index("policy_tool edge-wizard"), deploy.index('systemctl --user restart "$UNIT"'))
        # Secret pgadmin-config holds the client secret: on stdin only, never an
        # argument; the deployment is read whole on stdin for literal env values
        for script in ("health-check.sh", "tests/iam-hosts.sh"):
            src = self.read(script)
            self.assertIn("get secret pgadmin-config", src, script)
            self.assertIn("-o jsonpath='{.data.oauth2-config}' 2>/dev/null \\\n        | base64 -d 2>/dev/null | python3 -c '",
                          src, script)
            self.assertIn('get deployment,replicaset -n', src, script)
            self.assertIn("-l app=pgadmin -o json 2>/dev/null \\\n        | python3 -c '", src, script)
            self.assertIn("get secret pgadmin-config -n", src, script)
            self.assertIn("Secret pgadmin-config is missing in", src, script)
            self.assertNotIn('PGADMIN_CONFIG_OAUTH2_CONFIG")].value}', src, script)
            self.assertNotRegex(src, r'python3 -c [^\n]*"\$(cfg|have_env|oauth|literal)"', script)
        self.assertIn("pgadminroles", self.read("health-checks.conf"))
        self.assertIn("onboardroles", self.read("health-checks.conf"))

    def _health_fn(self, fn, setup, kubectl_out, env=None, kubectl=None, extra_env=None):
        """Run one health-check function with a fake kubectl/pgrep; its _record line."""
        import subprocess
        import tempfile
        tmp = tempfile.mkdtemp()
        env = dict(env or {}, **(extra_env or {}))
        for name, body in (("kubectl", kubectl or f"#!/bin/sh\ncat <<'EOF'\n{kubectl_out}\nEOF\n"),
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
        """The claims come from Secret pgadmin-config; a plain env value FAILs; no secret printed."""
        import base64
        secret, password = "S3CRET-pgadmin-client", "ADM1N-pass"
        live = ("[{'OAUTH2_NAME': 'keycloak', 'OAUTH2_CLIENT_SECRET': '%s', "
                "'OAUTH2_ADDITIONAL_CLAIMS': {'groups': ['admin']}}]" % secret)

        def ref(key):
            return {"secretKeyRef": {"name": "pgadmin-config", "key": key}}

        def obj(kind, name, oauth_env, pass_env):
            env = [{"name": "PGADMIN_DEFAULT_EMAIL", "value": "admin@example.org"},
                   dict(name="PGADMIN_DEFAULT_PASSWORD", **pass_env),
                   dict(name="PGADMIN_CONFIG_OAUTH2_CONFIG", **oauth_env)]
            return {"kind": kind, "metadata": {"name": name},
                    "spec": {"template": {"spec": {"containers": [{"name": "pgadmin", "env": env}]}}}}

        def listing(*objs):
            return json.dumps({"kind": "List", "items": list(objs)})

        def deployment(oauth_env, pass_env, *rs):
            return listing(obj("Deployment", "pgadmin", oauth_env, pass_env), *rs)

        new_env = ({"valueFrom": ref("oauth2-config")}, {"valueFrom": ref("default-password")})
        moved = deployment(*new_env, obj("ReplicaSet", "pgadmin-new", *new_env))

        def run(dep, cfg, env=None, oauth="ok 1", passfile="readable"):
            # answers the existence check (nothing), the deployment's JSON, the Secret's
            # key, the passfile test and the in-pod users/servers query (stdin read)
            out = self._health_fn("check_pgadminroles", 'check_pgadminroles "pgAdmin roles" medcea', "", env,
                                  kubectl=("#!/bin/sh\ncase \"$*\" in\n"
                                           "*'exec -n medcea deployment/pgadmin -c pgadmin -- sh -c "
                                           "test -r /pgpassfile && echo readable || echo unreadable') "
                                           "[ -n \"$FAKE_PASSFILE\" ] && printf '%s\\n' \"$FAKE_PASSFILE\" ;;\n"
                                           "*'exec -i -n medcea deployment/pgadmin -c pgadmin -- "
                                           "/venv/bin/python3 - /var/lib/pgadmin/pgadmin4.db') "
                                           "cat >/dev/null; printf '%s\\n' \"$FAKE_OAUTH\" ;;\n"
                                           "*exec*) exit 1 ;;\n"
                                           "*'get secret pgadmin-config'*\"{.data.oauth2-config}\"*) "
                                           "printf %s \"$FAKE_SECRET\" ;;\n"
                                           "*'get secret pgadmin-config'*) [ -n \"$FAKE_SECRET\" ] ;;\n"
                                           "*'-o json'*) printf %s \"$FAKE_DEPLOYMENT\" ;;\n"
                                           "esac\n"),
                                  extra_env={"FAKE_SECRET": base64.b64encode(cfg.encode()).decode(),
                                             "FAKE_DEPLOYMENT": dep, "FAKE_OAUTH": oauth,
                                             "FAKE_PASSFILE": passfile})
            self.assertNotIn(secret, out)
            self.assertNotIn(password, out)
            return out
        out = run(moved, live)
        self.assertTrue(out.startswith("OK|"), out)
        self.assertIn("1 OAuth2 user(s) have the IoT Postgres entry", out)
        # the passfile pgAdmin's user cannot read (it was root's until 1 Nov 2026)
        out = run(moved, live, passfile="unreadable")
        self.assertTrue(out.startswith("FAIL|"), out)
        self.assertIn("cannot read /pgpassfile", out)
        # an exec that cannot reach the container is not a passfile verdict
        out = run(moved, live, passfile="")
        self.assertTrue(out.startswith("FAIL|"), out)
        self.assertIn("cannot reach pgAdmin's container (still starting?", out)
        self.assertNotIn("/pgpassfile", out)
        # the postStart hook's work: a listed e-mail without its user or its server
        out = run(moved, live, oauth="missing bob@example.org (no OAuth2 user); "
                                     "ann@example.org (no IoT Postgres entry)")
        self.assertTrue(out.startswith("FAIL|"), out)
        self.assertIn("bob@example.org (no OAuth2 user); ann@example.org (no IoT Postgres entry)", out)
        for unreadable in ("?", ""):
            out = run(moved, live, oauth=unreadable)
            self.assertTrue(out.startswith("FAIL|"), out)
            self.assertIn("cannot read pgAdmin's users and servers", out)
        out = run(moved, live, oauth="empty")
        self.assertTrue(out.startswith("WARN|"), out)
        self.assertIn("PGADMIN_OAUTH2_SERVER_USERS is empty", out)
        out = run(moved, live.replace("['admin']", "['admin', 'qa']"))
        self.assertTrue(out.startswith("FAIL|"), out)
        self.assertIn("./deploy-infra.sh", out)
        self.assertTrue(run(moved, live, {"IAM_GATES": "false"}).startswith("WARN|"))
        # a pre-change pgAdmin: either secret still a literal env value
        old_env = ({"value": live}, {"value": password})
        for dep, names in ((deployment(*old_env),
                            "deployment/pgadmin (PGADMIN_DEFAULT_PASSWORD, PGADMIN_CONFIG_OAUTH2_CONFIG)"),
                           (deployment({"valueFrom": ref("oauth2-config")}, {"value": password}),
                            "deployment/pgadmin (PGADMIN_DEFAULT_PASSWORD)"),
                           # moved, but a kept pre-change ReplicaSet still holds both
                           (deployment(*new_env, obj("ReplicaSet", "pgadmin-new", *new_env),
                                       obj("ReplicaSet", "pgadmin-old", *old_env)),
                            "replicaset/pgadmin-old (PGADMIN_DEFAULT_PASSWORD, PGADMIN_CONFIG_OAUTH2_CONFIG)")):
            out = run(dep, live)
            self.assertTrue(out.startswith("FAIL|"), out)
            self.assertIn(names, out)
            self.assertIn("./deploy-infra.sh", out)
            self.assertNotIn("pgadmin-new", out)
        # no Secret: named as missing, not as unreadable claims
        out = run(moved, "")
        self.assertTrue(out.startswith("FAIL|"), out)
        self.assertIn("Secret pgadmin-config is missing in medcea", out)
        # an unreadable listing, or one without the Deployment: never reported as a leak
        for dep in ("not json", listing(obj("ReplicaSet", "pgadmin-new", *new_env))):
            out = run(dep, live)
            self.assertTrue(out.startswith("FAIL|"), out)
            self.assertIn("cannot read pgAdmin's deployment", out)
            self.assertNotIn("plain env", out)

    def test_pgadmin_secrets_not_in_env(self):
        """Rendered offline: the two secrets live in Secret pgadmin-config, never in Deployment env."""
        import subprocess
        import yaml
        tmpl = self.read("k8s/pgadmin/pgadmin.yaml")
        dep_text = tmpl[tmpl.index("kind: Deployment"):]
        self.assertNotIn("${PGADMIN_OAUTH_SECRET}", dep_text)
        self.assertNotIn("${ADMIN_PASS}", dep_text)
        names = ("NAMESPACE POSTGRES_DB PGA_DB_USER PGA_DB_PASS ADMIN_EMAIL ADMIN_PASS PGADMIN_DOMAIN "
                 "PGADMIN_OAUTH2_CLAIMS KEYCLOAK_DOMAIN KEYCLOAK_REALM PGADMIN_OAUTH_SECRET PLATFORM_IP "
                 "PGADMIN_OAUTH2_SERVER_USERS PGADMIN_CONFIG_CHECKSUM").split()
        vals = {n: f"dummy-{n.lower()}" for n in names}
        vals.update(PGADMIN_OAUTH2_CLAIMS="{'groups': ['admin']}", PLATFORM_IP="10.0.0.1",
                    PGADMIN_CONFIG_CHECKSUM="0" * 64)
        out = subprocess.run(["bash", "-c", f'source "{REPO}/infra/lib-render.sh"; render "$0" "$@"',
                              os.path.join(REPO, "k8s/pgadmin/pgadmin.yaml")] + names,
                             capture_output=True, text=True, env=dict(os.environ, **vals), check=True).stdout
        docs = {(d["kind"], d["metadata"]["name"]): d for d in yaml.safe_load_all(out) if d}
        sec = docs[("Secret", "pgadmin-config")]["stringData"]
        self.assertEqual(sec["default-password"], vals["ADMIN_PASS"])
        cfg = ast.literal_eval(sec["oauth2-config"])[0]
        self.assertEqual(cfg["OAUTH2_CLIENT_SECRET"], vals["PGADMIN_OAUTH_SECRET"])
        self.assertEqual(cfg["OAUTH2_ADDITIONAL_CLAIMS"], {"groups": ["admin"]})
        dep = docs[("Deployment", "pgadmin")]
        dep_dump = json.dumps(dep)
        self.assertNotIn(vals["ADMIN_PASS"], dep_dump)
        self.assertNotIn(vals["PGADMIN_OAUTH_SECRET"], dep_dump)
        self.assertEqual(dep["spec"]["template"]["metadata"]["annotations"]["medcea/config-checksum"], "0" * 64)
        # no old ReplicaSet keeps a pre-Secret pod template with the plain values
        self.assertEqual(dep["spec"]["revisionHistoryLimit"], 0)
        env = {e["name"]: e for e in dep["spec"]["template"]["spec"]["containers"][0]["env"]}
        for name, key in (("PGADMIN_CONFIG_OAUTH2_CONFIG", "oauth2-config"),
                          ("PGADMIN_DEFAULT_PASSWORD", "default-password")):
            self.assertNotIn("value", env[name])
            self.assertEqual(env[name]["valueFrom"], {"secretKeyRef": {"name": "pgadmin-config", "key": key}})
        self.assertNotIn("${", out)

    def test_pgadmin_config_checksum(self):
        """deploy-infra's hash follows the Secret's values and ConfigMap pgadmin-servers (the
        postStart hook, servers.json): a new claim, secret or hook restarts pgAdmin."""
        import subprocess
        infra = self.read("deploy-infra.sh")
        block = re.search(r'PGADMIN_CONFIG_CHECKSUM="\$\(set -o pipefail\n(.*?)\)" \\\n', infra, re.S).group(1)
        names = ("NAMESPACE POSTGRES_DB PGA_DB_USER PGA_DB_PASS ADMIN_EMAIL ADMIN_PASS PGADMIN_DOMAIN "
                 "PGADMIN_OAUTH2_CLAIMS KEYCLOAK_DOMAIN KEYCLOAK_REALM PGADMIN_OAUTH_SECRET PLATFORM_IP").split()

        def checksum(**over):
            vals = {n: f"dummy-{n.lower()}" for n in names}
            vals["PGADMIN_OAUTH2_CLAIMS"] = "{'groups': ['admin']}"
            vals.update(over)
            r = subprocess.run(["bash", "-c", f'source "{REPO}/infra/lib-render.sh"; SCRIPT_DIR="{REPO}"\n{block}'],
                               capture_output=True, text=True, env=dict(os.environ, **vals))
            self.assertEqual((r.returncode, r.stderr), (0, ""))
            self.assertRegex(r.stdout, r"^[0-9a-f]{64}\n$")
            self.assertNotIn(vals["PGADMIN_OAUTH_SECRET"], r.stdout)
            self.assertNotIn(vals["PGA_DB_PASS"], r.stdout)
            return r.stdout
        base = checksum()
        self.assertEqual(checksum(), base)
        # servers.json names the database user: a new one restarts pgAdmin (as medcea/db-user does)
        self.assertNotEqual(checksum(PGA_DB_USER="rr_admin_login"), base)
        # a rotated rr_admin_login password restarts pgAdmin (the passfile copies are made at start)
        self.assertNotEqual(checksum(PGA_DB_PASS="other"), base)
        self.assertNotEqual(checksum(PGADMIN_OAUTH_SECRET="other"), base)
        self.assertNotEqual(checksum(PGADMIN_OAUTH2_CLAIMS="{'groups': ['admin', 'qa']}"), base)
        self.assertNotEqual(checksum(ADMIN_PASS="other"), base)

    PGADMIN_NAMES = ("NAMESPACE POSTGRES_DB PGA_DB_USER PGA_DB_PASS ADMIN_EMAIL ADMIN_PASS PGADMIN_DOMAIN "
                     "PGADMIN_OAUTH2_CLAIMS KEYCLOAK_DOMAIN KEYCLOAK_REALM PGADMIN_OAUTH_SECRET PLATFORM_IP "
                     "PGADMIN_OAUTH2_SERVER_USERS PGADMIN_CONFIG_CHECKSUM").split()

    def _pgadmin_render(self, **over):
        import subprocess
        import yaml
        vals = {n: f"dummy-{n.lower()}" for n in self.PGADMIN_NAMES}
        vals.update(PGADMIN_OAUTH2_CLAIMS="{'groups': ['admin']}", PLATFORM_IP="10.0.0.1",
                    PGADMIN_CONFIG_CHECKSUM="0" * 64,
                    PGADMIN_OAUTH2_SERVER_USERS="admin@cea.com,ann@example.org", **over)
        out = subprocess.run(["bash", "-c", f'source "{REPO}/infra/lib-render.sh"; render "$0" "$@"',
                              os.path.join(REPO, "k8s/pgadmin/pgadmin.yaml")] + self.PGADMIN_NAMES,
                             capture_output=True, text=True, env=dict(os.environ, **vals), check=True).stdout
        return {(d["kind"], d["metadata"]["name"]): d for d in yaml.safe_load_all(out) if d}

    def test_pgadmin_manifest_image_and_hook(self):
        """1 Nov 2026: pinned image, unshared server, the postStart hook and its user list."""
        infra = self.read("deploy-infra.sh")
        docs = self._pgadmin_render()
        cm = docs[("ConfigMap", "pgadmin-servers")]["data"]
        servers = json.loads(cm["servers.json"])["Servers"]["1"]
        self.assertEqual((servers["Name"], servers["Shared"], servers["PassFile"]), ("IoT Postgres", False, "/pgpassfile"))
        self.assertIn("load-servers", cm["oauth2-servers.sh"])
        pod = docs[("Deployment", "pgadmin")]["spec"]["template"]["spec"]
        c = pod["containers"][0]
        self.assertRegex(c["image"], r"^dpage/pgadmin4:9\.19\.0@sha256:[0-9a-f]{64}$")
        self.assertIn("3591b3d02910dcd817dec6fcaa681c278ba6966945283dd0ea0042731c330c83", c["image"])
        self.assertEqual(c["lifecycle"]["postStart"]["exec"]["command"], ["sh", "/medcea/oauth2-servers.sh"])
        mounts = {m["mountPath"]: m for m in c["volumeMounts"]}
        self.assertEqual((mounts["/medcea/oauth2-servers.sh"]["name"], mounts["/medcea/oauth2-servers.sh"]["subPath"]),
                         ("servers-config", "oauth2-servers.sh"))
        env = {e["name"]: e for e in c["env"]}
        self.assertEqual(env["PGADMIN_OAUTH2_SERVER_USERS"], {"name": "PGADMIN_OAUTH2_SERVER_USERS",
                                                               "value": "admin@cea.com,ann@example.org"})
        # still no data volume: the reason the hook runs at every start
        self.assertEqual({v["name"] for v in pod["volumes"]}, {"servers-config", "pgpassfile-src", "pgpassfile-rw"})
        # the init container leaves the passfile to pgAdmin's user, 0600
        init = pod["initContainers"][0]["command"][-1]
        self.assertIn("chown 5050:0 /pgpassfile-rw/pgpassfile", init)
        self.assertIn("chmod 0600 /pgpassfile-rw/pgpassfile", init)
        # deploy-infra: the list comes from the claims, through the admin-API library,
        # before both renders, and it is on both render lists (checked above too)
        self.assertIn('kc_claim_emails "$KEYCLOAK_REALM" "$PGADMIN_OAUTH2_CLAIMS" "$ADMIN_EMAIL"', infra)
        self.assertLess(infra.index('PGADMIN_OAUTH2_SERVER_USERS="$(_pgadmin_server_users)"'),
                        infra.index('PGADMIN_CONFIG_CHECKSUM="$('))
        self.assertLess(infra.index('PGADMIN_OAUTH2_CLAIMS="$(REPO_ROOT'),
                        infra.index('PGADMIN_OAUTH2_SERVER_USERS="$(_pgadmin_server_users)"'))
        self.assertIn("--timeout=16m", infra[infra.index("rollout status deployment/pgadmin"):][:120])
        # the Deployment's progress deadline outlasts that wait, or rollout status
        # fails at the default 600 s whatever its --timeout
        timeout = re.search(r"rollout status deployment/pgadmin\s*\\\s*-n \"\$NAMESPACE\" --timeout=(\d+)m", infra)
        self.assertIsNotNone(timeout)
        self.assertGreaterEqual(docs[("Deployment", "pgadmin")]["spec"]["progressDeadlineSeconds"],
                                int(timeout.group(1)) * 60)
        # a failed Keycloak read keeps the live list (a shorter one restarts pgAdmin
        # with a fresh database); ADMIN_EMAIL only without one
        fn = infra[infra.index("_pgadmin_server_users() {"):infra.index('PGADMIN_OAUTH2_SERVER_USERS="$(_pgadmin_server_users)"')]
        self.assertIn('out="$(kc_claim_emails ', fn)
        self.assertIn('env[?(@.name=="PGADMIN_OAUTH2_SERVER_USERS")].value', fn)
        self.assertLess(fn.index('printf \'%s\\n\' "$live"'), fn.index('printf \'%s\\n\' "${ADMIN_EMAIL,,}"'))

    def _hook(self, users, *, ready_after=0.0, wait=30, fail_load=False, db=True, shell=("sh",)):
        """Run the rendered postStart hook under sh with a fake python/setup.py."""
        import subprocess
        import tempfile
        import time
        tmp = tempfile.mkdtemp()
        script = os.path.join(tmp, "hook.sh")
        with open(script, "w") as f:
            f.write(self._pgadmin_render()[("ConfigMap", "pgadmin-servers")]["data"]["oauth2-servers.sh"])
        py = os.path.join(tmp, "python3")
        with open(py, "w") as f:
            f.write('#!/bin/sh\necho "$(pwd)|$*" >> "$CALLS"\n'
                    'case "$1 $2" in\n'
                    '"-c "*) exit 0 ;;\n'
                    '"setup.py get-users") exit 0 ;;\n'
                    '"setup.py add-external-user") exit 1 ;;\n'  # "already exists" is fine
                    '"setup.py load-servers") [ -z "$FAIL_LOAD" ] ;;\n'
                    '*) exit 3 ;;\nesac\n')
        os.chmod(py, 0o755)
        dbf, calls, log = (os.path.join(tmp, n) for n in ("pgadmin4.db", "calls", "log"))
        passfile = os.path.join(tmp, "pgpassfile")
        with open(passfile, "w") as f:
            f.write("rdbms:5432:*:rr_admin_login:PW-secret\n")
        env = dict(os.environ, HOOK_PY=py, HOOK_DIR=tmp, HOOK_DB=dbf, HOOK_SERVERS="/srv/servers.json",
                   HOOK_STORAGE=os.path.join(tmp, "storage"), HOOK_PASSFILE=passfile,
                   HOOK_LOG=log, HOOK_WAIT=str(wait), HOOK_STEP="1", CALLS=calls,
                   PGADMIN_OAUTH2_SERVER_USERS=users, FAIL_LOAD="1" if fail_load else "")
        p = subprocess.Popen([*shell, script], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if db:
            time.sleep(ready_after)
            open(dbf, "w").close()
        out, err = p.communicate(timeout=60)
        def read(path):
            if not os.path.exists(path):
                return []
            with open(path) as f:
                return f.read().splitlines()
        return (p.returncode, [c.split("|", 1)[1] for c in read(calls)], read(log),
                {c.split("|")[0] for c in read(calls) if "|setup.py" in c}, tmp)

    def _hook_main_checks(self, rc, calls, log, cwds, tmp):
        self.assertEqual(rc, 0)
        # setup.py runs from pgAdmin's directory
        self.assertEqual(cwds, {tmp})
        setup = [c for c in calls if c.startswith("setup.py")]
        self.assertEqual(setup[0], "setup.py get-users")
        self.assertEqual([c for c in setup if not c.endswith("get-users")], [
            "setup.py add-external-user admin@cea.com --auth-source oauth2 --email admin@cea.com",
            "setup.py load-servers /srv/servers.json --user admin@cea.com --auth-source oauth2 --replace",
            "setup.py add-external-user ann@example.org --auth-source oauth2 --email ann@example.org",
            "setup.py load-servers /srv/servers.json --user ann@example.org --auth-source oauth2 --replace"])
        self.assertTrue(any(c.startswith("-c ") and c.endswith("http://127.0.0.1:80/misc/ping") for c in calls), calls)
        self.assertEqual(log.count("medcea oauth2-servers: skipped an entry that is not a plain lower-case e-mail address"), 2)
        self.assertIn("medcea oauth2-servers: admin@cea.com: server entry loaded, password file in place", log)
        self.assertIn("medcea oauth2-servers: ann@example.org: server entry loaded, password file in place", log)
        self.assertFalse(any("rm -rf" in c for c in calls + log))
        # the passfile in each user's storage folder (pgAdmin's preprocess_username), 600 in 700
        import stat
        for d in ("admin_cea.com", "ann_example.org"):
            f = os.path.join(tmp, "storage", d, "pgpassfile")
            self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(f)).st_mode), 0o700)
            with open(f) as fh:
                self.assertIn("rr_admin_login", fh.read())
        self.assertEqual(sorted(os.listdir(os.path.join(tmp, "storage"))), ["admin_cea.com", "ann_example.org"])
        self.assertFalse(any("PW-secret" in l for l in log))

    def test_pgadmin_hook_script(self):
        """The postStart hook waits, loads servers.json per valid e-mail, skips bad ones, exits 0."""
        import subprocess
        text = self._pgadmin_render()[("ConfigMap", "pgadmin-servers")]["data"]["oauth2-servers.sh"]
        self.assertNotIn("${", self.read("k8s/pgadmin/pgadmin.yaml").split("oauth2-servers.sh: |")[1].split("---")[0])
        self.assertEqual(subprocess.run(["sh", "-n"], input=text, text=True).returncode, 0)
        # the image's sh is busybox ash: the same run there when the host has busybox
        import shutil
        for shell in [("sh",)] + ([(shutil.which("busybox"), "sh")] if shutil.which("busybox") else []):
            rc, calls, log, cwds, tmp = self._hook("admin@cea.com,Bad@Example.org,x;rm -rf @a.com,ann@example.org",
                                                   ready_after=1.5, shell=shell)
            self._hook_main_checks(rc, calls, log, cwds, tmp)
        # setup.py failing: three tries, a log line, still exit 0
        rc, calls, log, _, _ = self._hook("ann@example.org", fail_load=True)
        self.assertEqual(rc, 0)
        self.assertEqual(sum(c.startswith("setup.py load-servers") for c in calls), 3)
        self.assertIn("medcea oauth2-servers: ann@example.org: load-servers failed 3 times: no server entry", log)
        # never ready: gives up after HOOK_WAIT, exit 0, no setup.py write
        rc, calls, log, _, _ = self._hook("ann@example.org", wait=2, db=False)
        self.assertEqual(rc, 0)
        self.assertEqual(calls, [])
        self.assertIn("not ready after 2 s", log[0])
        # a special-use domain pgAdmin refuses: skipped like a bad address
        rc, calls, log, _, _ = self._hook("demo@medcea.invalid,qa@x.test")
        self.assertEqual(rc, 0)
        self.assertEqual([c for c in calls if c.startswith("setup.py")], ["setup.py get-users"])
        self.assertEqual(log.count("medcea oauth2-servers: skipped an entry that is not a plain lower-case e-mail address"), 2)
        # a local part starting with a digit: pgAdmin's folder is pga_user_<name>
        rc, calls, log, _, tmp = self._hook("7ann@example.org")
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.isfile(os.path.join(tmp, "storage", "pga_user_7ann_example.org", "pgpassfile")))
        # an empty list: nothing to do
        rc, calls, log, _, _ = self._hook("")
        self.assertEqual((rc, calls), (0, []))
        self.assertIn("PGADMIN_OAUTH2_SERVER_USERS is empty", log[0])

    def test_kc_claim_emails(self):
        """The e-mails of the enabled accounts the claims admit, from a fake admin API; fallback on failure."""
        import subprocess
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer
        R = "/admin/realms/medcea/roles"
        u = lambda i, name, email, enabled=True: {"id": i, "username": name, "email": email, "enabled": enabled}  # noqa: E731
        routes = {
            R: [{"name": "admin", "composite": False}, {"name": "operator", "composite": False},
                {"name": "production_manager", "composite": True}, {"name": "qa", "composite": True},
                {"name": "auditor", "composite": False}, {"name": "default-roles-medcea", "composite": True}],
            R + "/production_manager/composites/realm": [{"name": "operator"}],
            R + "/qa/composites/realm": [{"name": "auditor"}],
            R + "/default-roles-medcea/composites/realm": [{"name": "offline_access"}],
            R + "/admin/users": [u("1", "admin", "Admin@CEA.com"), u("2", "old", "old@cea.com", False),
                                 u("3", "noemail", ""), u("4", "odd", "odd@localhost"),
                                 u("5", "bob", "bob@example.org"), u("9", "demo", "demo@medcea.invalid")],
            R + "/operator/users": [u("6", "op", "op@example.org")],
            R + "/production_manager/users": [u("7", "pm", "pm@example.org"), u("5", "bob", "bob@example.org")],
            R + "/qa/users": [u("8", "qa", "qa@example.org")],
            R + "/auditor/users": [],
        }
        state = {"fail": False, "auth": set()}

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                state["auth"].add(self.headers.get("Authorization"))
                path = self.path.split("?")[0]
                if state["fail"] or path not in routes:
                    self.send_response(500 if state["fail"] else 404)
                    self.end_headers()
                    return
                body = json.dumps(routes[path]).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            def run(claims):
                r = subprocess.run(["bash", "-c", f'source "{REPO}/infra/lib-keycloak-admin.sh"\n'
                                    'kc_admin_token() { printf tok; }\n'
                                    'kc_claim_emails medcea "$1" "$2"', "x", claims, "Admin@CEA.com"],
                                   capture_output=True, text=True,
                                   env=dict(os.environ, KC_URL="http://127.0.0.1:%d" % srv.server_port))
                # 1 = a failed read (FALLBACK printed), so the caller can keep the live list
                self.assertEqual(r.returncode, 1 if state["fail"] or claims == "not a literal" else 0, r.stderr)
                return r.stdout.strip(), r.stderr
            out, err = run("{'groups': ['admin']}")
            self.assertEqual(out, "admin@cea.com,bob@example.org")
            self.assertIn("'noemail' has no e-mail", err)
            self.assertIn("'odd' has an e-mail pgAdmin is not given", err)
            # a special-use domain pgAdmin's e-mail check refuses (the demo accounts')
            self.assertIn("'demo' has an e-mail on a special-use domain", err)
            self.assertNotIn("old", err)
            self.assertEqual(state["auth"], {"Bearer tok"})
            # through a composite: production_manager's holders carry operator too
            out, _ = run("{'groups': ['operator']}")
            self.assertEqual(out, "bob@example.org,op@example.org,pm@example.org")
            out, _ = run("{'groups': ['auditor', 'admin']}")
            self.assertEqual(out, "admin@cea.com,bob@example.org,qa@example.org")
            state["fail"] = True
            out, err = run("{'groups': ['admin']}")
            self.assertEqual(out, "admin@cea.com")
            self.assertIn("cannot read the role holders", err)
            state["fail"] = False
            out, err = run("not a literal")
            self.assertEqual(out, "admin@cea.com")
        finally:
            srv.shutdown()

    def test_pgadmin_users_query(self):
        """health-check pgadminroles' in-pod query (shared with iam-hosts.sh) on a pgAdmin-shaped database."""
        import sqlite3
        import subprocess
        import tempfile
        grab = lambda src: re.search(r"<<'PY'\n(import os, sqlite3.*?)\nPY\n", src, re.S).group(1)  # noqa: E731
        q = grab(self.read("health-check.sh"))
        self.assertEqual(q, grab(self.read("tests/iam-hosts.sh")))
        self.assertIn("mode=ro", q)
        db = os.path.join(tempfile.mkdtemp(), "pgadmin4.db")
        con = sqlite3.connect(db)
        con.executescript('''
            CREATE TABLE "user" (id INTEGER PRIMARY KEY, username TEXT, email TEXT, auth_source TEXT);
            CREATE TABLE server (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT);
            INSERT INTO "user" VALUES (1, 'admin@cea.com', 'admin@cea.com', 'internal'),
                                      (2, 'admin@cea.com', 'admin@cea.com', 'oauth2'),
                                      (3, 'ann@example.org', 'ann@example.org', 'oauth2');
            INSERT INTO server VALUES (1, 1, 'IoT Postgres'), (2, 2, 'IoT Postgres'), (3, 3, 'Other');
        ''')
        con.commit()
        con.close()
        # the password file next to pgAdmin's database: <data>/storage/<user folder>/pgpassfile
        os.makedirs(os.path.join(os.path.dirname(db), "storage", "admin_cea.com"))
        open(os.path.join(os.path.dirname(db), "storage", "admin_cea.com", "pgpassfile"), "w").close()

        def run(users):
            return subprocess.run(["python3", "-", db], input=q, capture_output=True, text=True,
                                  env=dict(os.environ, PGADMIN_OAUTH2_SERVER_USERS=users)).stdout.strip()
        self.assertEqual(run("admin@cea.com"), "ok 1")
        self.assertEqual(run("admin@cea.com,ann@example.org,bob@example.org"),
                         "missing bob@example.org (no OAuth2 user); ann@example.org (no IoT Postgres entry)")
        self.assertEqual(run(""), "empty")
        os.remove(os.path.join(os.path.dirname(db), "storage", "admin_cea.com", "pgpassfile"))
        self.assertEqual(run("admin@cea.com"), "missing admin@cea.com (no password file)")
        before = os.path.getmtime(db)
        self.assertEqual(subprocess.run(["python3", "-", db + ".absent"], input=q, capture_output=True,
                                        text=True).stdout.strip(), "?")
        self.assertFalse(os.path.exists(db + ".absent"))
        self.assertEqual(os.path.getmtime(db), before)

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


def _created_functions(sql):
    """{normalised signature} of every CREATE [OR REPLACE] FUNCTION in an SQL text (IN
    arguments only, names dropped, as grants.norm_sig writes them)."""
    out = set()
    for m in re.finditer(r"CREATE (?:OR REPLACE )?FUNCTION ([a-z_]+\.[a-z_]+)\(", sql):
        depth, i = 1, m.end()
        while depth:
            depth += {"(": 1, ")": -1}.get(sql[i], 0)
            i += 1
        args = []
        for a in re.split(r",(?![^(]*\))", sql[m.end():i - 1]):
            a = re.sub(r"\s+DEFAULT\s+.*$", "", " ".join(a.split()), flags=re.S)
            if not a or a.startswith("OUT "):
                continue
            words = a.split(" ")
            args.append(" ".join(words[1:]) if len(words) > 1 and not words[0].startswith("medcea") else a)
        out.add(grants.norm_sig(f"{m.group(1)}({', '.join(args)})"))
    return out


class ShortSessionsTest(unittest.TestCase):
    """Decision of 1 Nov 2026, "short sessions + one-hop sign-out": each tool's own session
    is short and follows the Keycloak person when it ends (workbench in
    tests/test_workbench_render.py, Node-RED in tests/test_node_red_flows.py, the user
    menu's Sign out in tests/test_access_api.py and tests/test_access_deploy.sh)."""

    def read(self, rel):
        with open(os.path.join(REPO, rel)) as f:
            return f.read()

    def test_grafana(self):
        import yaml
        env = yaml.safe_load(self.read("k8s/grafana/values.yaml"))["env"]
        # 5 minutes without use, at most an hour in use (review of 1 Nov 2026: a hard 5-minute
        # end reloads the page and drops unsaved panel edits every 5 minutes)
        self.assertEqual(env["GF_AUTH_LOGIN_MAXIMUM_LIFETIME_DURATION"], "1h")
        self.assertEqual(env["GF_AUTH_LOGIN_MAXIMUM_INACTIVE_LIFETIME_DURATION"], "5m")
        # rotation (minimum 2) inside the inactivity limit, so a session in use is never cut at 5 minutes
        self.assertEqual(env["GF_AUTH_TOKEN_ROTATION_INTERVAL_MINUTES"], "2")
        self.assertEqual(env["GF_AUTH_OAUTH_AUTO_LOGIN"], "true")      # silent re-sign-in at expiry
        # A Grafana sign-out URL with post_logout_redirect_uri would get the ID token appended
        # (id_token_hint): none is set.
        self.assertFalse([k for k in env if "SIGNOUT_REDIRECT" in k])

    def test_pgadmin(self):
        import subprocess
        import yaml
        names = ("NAMESPACE POSTGRES_DB PGA_DB_USER PGA_DB_PASS ADMIN_EMAIL ADMIN_PASS PGADMIN_DOMAIN "
                 "PGADMIN_OAUTH2_CLAIMS KEYCLOAK_DOMAIN KEYCLOAK_REALM PGADMIN_OAUTH_SECRET PLATFORM_IP "
                 "PGADMIN_OAUTH2_SERVER_USERS PGADMIN_CONFIG_CHECKSUM").split()
        vals = {n: f"dummy-{n.lower()}" for n in names}
        vals.update(PGADMIN_OAUTH2_CLAIMS="{'groups': ['admin']}", PLATFORM_IP="10.0.0.1",
                    PGADMIN_CONFIG_CHECKSUM="0" * 64)
        out = subprocess.run(["bash", "-c", f'source "{REPO}/infra/lib-render.sh"; render "$0" "$@"',
                              os.path.join(REPO, "k8s/pgadmin/pgadmin.yaml")] + names,
                             capture_output=True, text=True, env=dict(os.environ, **vals), check=True).stdout
        docs = [d for d in yaml.safe_load_all(out) if d]
        dep = [d for d in docs if d["kind"] == "Deployment"][0]
        sec = [d for d in docs if d["kind"] == "Secret" and d["metadata"]["name"] == "pgadmin-config"][0]
        env = {e["name"]: e.get("value") for e in dep["spec"]["template"]["spec"]["containers"][0]["env"]}
        # The image's entrypoint writes NAME = value into config_distro.py: Python literals.
        self.assertIs(ast.literal_eval(env["PGADMIN_CONFIG_OAUTH2_AUTO_LOGIN"]), True)
        # SESSION_EXPIRATION_TIME * 86400 is gunicorn's --timeout (an integer): a fraction of
        # a day stops pgAdmin from starting (1 Nov 2026), so it keeps its default of one day
        self.assertNotIn("PGADMIN_CONFIG_SESSION_EXPIRATION_TIME", env)
        # auto-login applies only with OAuth2 the only source and one provider
        self.assertEqual(ast.literal_eval(env["PGADMIN_CONFIG_AUTHENTICATION_SOURCES"]), ["oauth2"])
        self.assertEqual(len(ast.literal_eval(sec["stringData"]["oauth2-config"])), 1)
        self.assertNotIn("PGADMIN_CONFIG_MAX_SESSION_IDLE_TIME", env)   # stays 60 minutes
        self.assertNotIn("{id_token}", out)                             # no token in a logout URL

    def test_workbench_client_returns_to_the_portal(self):
        src = self.read("deploy-infra.sh")
        self.assertIn('local POST_LOGOUT="${ORIGIN}/*${5:+##$5}"', src)
        self.assertEqual(src.count('\\"post.logout.redirect.uris\\":\\"${POST_LOGOUT}\\"'), 2)
        self.assertIn('_create_client "workbench" "https://${WORKBENCH_DOMAIN}/hub/oauth_callback" false "" '
                      '"https://${PORTAL_DOMAIN}/*"', src)

    def test_user_menu_clients_return_to_the_workbench(self):
        """Sign out (review of 1 Nov 2026): every HOST_CLIENTS client's end-session returns to
        the workbench's /hub/logout, so that URI is registered on each, whatever
        WORKBENCH_ENABLED says (otherwise Keycloak answers "Invalid redirect uri" and the
        session is not ended)."""
        src = self.read("deploy-infra.sh")
        self.assertIn('_HUB_LOGOUT_URI="https://${WORKBENCH_DOMAIN}/hub/logout"', src)
        dep = self.read("apps/access/deploy.sh")
        clients = re.findall(r'=([a-z-]+)', "".join(l for l in dep.splitlines() if l.startswith("HOST_CLIENTS")))
        self.assertEqual(sorted(clients), sorted(["portal", "config", "access", "monitor", "scheduler", "dbmgmt",
                                                  "mqtt-explorer"]))
        for c in clients:
            calls = re.findall(r'_create_client "%s" "[^"]+"( [^)]*)?\)' % re.escape(c), src)
            self.assertEqual(len(calls), 1, c)
            self.assertTrue(calls[0].endswith(' "" "$_HUB_LOGOUT_URI"'), (c, calls[0]))
        self.assertLess(src.index('_HUB_LOGOUT_URI="'), src.index('_create_client "portal"'))
        # the access deploy renders the same address
        self.assertIn('SIGNOUT_HUB="https://${WORKBENCH_DOMAIN:-ai-workbench.$DOMAIN}/hub/logout"', dep)


class ApproveCommissionTest(unittest.TestCase):
    """The Approve action and the commissioning screen's database side (2026-10-31): the
    noted approvals, return and withdraw, the read functions, commissioning rules."""

    NEW = ("medcea.approve_recipe(integer,text)", "medcea.approve_algorithm(integer,text)",
           "medcea.approve_params(integer,text)", "medcea.return_change(text,bigint,text)",
           "medcea.withdraw_change(bigint,text)", "medcea.approval_queue(boolean)", "medcea.my_approvals()",
           "medcea.unit_commissioning()", "medcea._unit_busy(integer)", "medcea._unit_schedulable(integer)",
           "medcea._pending_lock(bigint)", "medcea._pending_open(medcea.pending_change)", "medcea.log_commissioning()",
           "medcea_auth._changes_since(text,jsonb)")

    @classmethod
    def setUpClass(cls):
        cls.policy = model.load()
        cls.privs = grants.privileges(cls.policy)
        with open(os.path.join(REPO, "apps/database/medcea_db_migrations.sql")) as f:
            cls.mig = f.read()
        with open(os.path.join(REPO, "apps/database/medcea_db_migrations_down_008b.sql")) as f:
            cls.down = f.read()

    def holders(self, obj, priv="EXECUTE"):
        return {g for g, k, o, p in self.privs if o == obj and p == priv}

    def body(self, sig_start):
        i = self.mig.index(sig_start)
        return self.mig[i:self.mig.index("END $$;", i)]

    def test_who_holds_what(self):
        people = set(grants.people(self.policy).values())
        for fn in ("medcea.approve_recipe(integer,text)", "medcea.approve_algorithm(integer,text)",
                   "medcea.approve_params(integer,text)", "medcea.approve_recipe(integer)",
                   "medcea.approve_algorithm(integer)", "medcea.approve_params(integer)",
                   "medcea.return_change(text,bigint,text)", "medcea.approve_change(text,bigint,text)"):
            self.assertEqual(self.holders(fn), {"rr_qa"}, fn)
        # audit_histories R: qa, qp, auditor, and services whose call the function refuses
        self.assertEqual(self.holders("medcea.approval_queue(boolean)"),
                         {"rr_qa", "rr_qp", "rr_auditor", "svc_dbexport", "iam_svc", "access_svc"})
        self.assertIn("'approval_queue: read it in the Configuration UI with your own sign-in'", self.mig)
        # portal R: every person, no service (own records only)
        for fn in ("medcea.my_approvals()", "medcea.withdraw_change(bigint,text)"):
            self.assertEqual(self.holders(fn), people, fn)
        self.assertTrue(people <= self.holders("medcea.unit_commissioning()"))
        self.assertEqual(self.holders("medcea.propose_commissioning(integer,boolean,text)"), {"rr_engineer"})
        # the proposer still reads no audit record directly
        for t in ("medcea.pending_change", "medcea.approval", "medcea.row_change"):
            self.assertNotIn("rr_engineer", self.holders(t, "SELECT"), t)
            self.assertNotIn("rr_admin", self.holders(t, "SELECT"), t)

    def test_created_and_dropped_by_the_full_down(self):
        created = _created_functions(self.mig)
        drops = " ".join(re.findall(r"DROP FUNCTION IF EXISTS (.*?);", self.down, re.S))
        dropped = {grants.norm_sig(x.strip()) for x in re.split(r",\s*(?=[a-z_]+\.[a-z_]+\()", drops)}
        for fn in self.NEW:
            self.assertIn(fn, created, fn)
            self.assertIn(fn, dropped, f"{fn} is not in the down file's -v full=1 DROP list")
            self.assertIn(fn, grants.declared_functions(self.policy) + [
                "medcea._unit_busy(integer)", "medcea._unit_schedulable(integer)", "medcea._pending_lock(bigint)",
                "medcea.log_commissioning()", "medcea._pending_open(medcea.pending_change)"], fn)
        self.assertIn("'commissioning_history_trg'", self.down)

    def test_noted_overloads_have_no_default(self):
        # a DEFAULT would make the 1-argument PostgREST call ambiguous (PGRST203)
        for f in ("approve_recipe(p_recipe_id integer, p_note text)", "approve_algorithm(p_algorithm_id integer, p_note text)",
                  "approve_params(p_params_id integer, p_note text)"):
            self.assertIn(f"FUNCTION medcea.{f} RETURNS bigint", self.mig)
        for f, arg in (("approve_recipe", "p_recipe_id"), ("approve_algorithm", "p_algorithm_id"),
                       ("approve_params", "p_params_id")):
            self.assertIn(f"RETURN medcea.{f}({arg}, NULL::text);", self.body(f"FUNCTION medcea.{f}({arg} integer) RETURNS"))

    def test_return_and_withdraw_count_as_no_approval(self):
        for chk in re.findall(r"CHECK \(action IN \(([^)]*)\)\)", self.mig):
            self.assertIn("'return'", chk)
            self.assertIn("'withdraw'", chk)
        for fn in ("FUNCTION medcea_auth._changes_since(", "FUNCTION medcea_auth._authors(", "FUNCTION medcea_auth._is_approved("):
            i = self.mig.index(fn)
            seg = self.mig[i:self.mig.index("$$;", self.mig.index("AS $$", i) + 5)]
            self.assertNotIn("'return'", seg, fn)
            self.assertNotIn("'withdraw'", seg, fn)
        self.assertIn("FROM medcea_auth._changes_since(p_target, p_key) ch WHERE ch.authors", self.mig)
        # commissioning alone makes nobody an author, and is out of the digest
        self.assertIn("bool_and(k IN ('status', 'retired_at', 'commissioning'))", self.mig)
        self.assertIn("(p_digest AND k IN ('status', 'retired_at', 'commissioning'))", self.mig)

    def test_commissioning_rules(self):
        prop = self.body("FUNCTION medcea.propose_commissioning(")
        self.assertIn("FOR NO KEY UPDATE", prop)
        self.assertIn("medcea._unit_busy(p_unit_id)", prop)
        self.assertIn("medcea_auth.policy_refuse(format('commissioning: unit %s has run %s in %s", prop)
        self.assertIn("CASE WHEN p_value THEN NULL ELSE now() END", prop)          # off applies at once
        self.assertIn("is already %", prop)
        self.assertIn("already waits for qa", prop)
        busy = self.mig[self.mig.index("FUNCTION medcea._unit_busy("):]
        self.assertIn("r.recipe_run_status IN ('R', 'S')", busy[:600])
        appr = self.body("FUNCTION medcea.approve_change(")
        self.assertIn("medcea._unit_busy((pc.row_key ->> 0)::integer)", appr)
        self.assertIn("'review', p_note", appr)                                   # the review of an off
        self.assertLess(appr.index("medcea._pending_lock(p_id)"), appr.index("medcea._pending_open(pc)"))
        lock = self.body("FUNCTION medcea._pending_lock(")
        self.assertLess(lock.index("FOR NO KEY UPDATE"), lock.index("pg_advisory_xact_lock"))
        self.assertIn("WHERE u.unit_id = r.unit_id FOR SHARE;", self.body("FUNCTION medcea.start_run("))
        # every flag change is in the policy hash chain, ENABLE ALWAYS
        self.assertIn("'commissioning_enabled' ELSE 'commissioning_disabled'", self.mig)
        self.assertIn("ALTER TABLE medcea.cea_unit ENABLE ALWAYS TRIGGER commissioning_history_trg", self.mig)
        # the other half: a run is never scheduled (S) on a flagged unit, and its unit row
        # is read FOR SHARE first, so approve_change's _unit_busy() sees it
        sch = self.body("FUNCTION medcea._unit_schedulable(")
        self.assertIn("FOR SHARE", sch)
        self.assertIn("schedule its run once commissioning ends", sch)
        self.assertIn("medcea_auth.policy_refuse(", sch)
        nrd = self.body("FUNCTION medcea.new_run_defaults(")
        self.assertLess(nrd.index("medcea._unit_schedulable(NEW.unit_id)"), nrd.index("NEW.recipe_run_status := 'S'"))
        srs = self.body("FUNCTION medcea.set_run_status(")
        self.assertIn("IF p_status = 'S' THEN\n        PERFORM medcea._unit_schedulable(r.unit_id);", srs)
        self.assertLess(srs.index("is not a transition"), srs.index("_unit_schedulable"))
        self.assertLess(srs.index("_unit_schedulable"), srs.index("_owner_write(true)"))
        # a log-setting proposal is closed by qa or its proposer only, like commissioning
        ps = self.body("FUNCTION medcea.propose_setting(")
        self.assertIn("your token carries no person_id", ps)
        self.assertIn("pg_advisory_xact_lock(hashtextextended('medcea.scheduler_config:' || p_key, 0))", ps)
        self.assertIn("waiting.proposed_by_person IS DISTINCT FROM a.person", ps)
        self.assertIn("already waits for qa", ps)
        self.assertLess(ps.index("pg_advisory_xact_lock"), ps.index("medcea._pending_open(waiting)"))
        uc = self.body("FUNCTION medcea.unit_commissioning(")
        self.assertIn("medcea_auth.policy_holds(a.role, 'runs', 'R') IS NOT DISTINCT FROM 'free'", uc)
        self.assertIn("last_approved_by := CASE WHEN hist THEN", uc)


class RunReleaseTest(unittest.TestCase):
    """Release in the Approvals tab (2026-10-31): release_run(run, note) and the completed
    runs in approval_queue() for qp, with release_run's rule as its may_approve."""

    NEW = ("medcea.release_run(integer,text)", "medcea.release_run(integer)")
    setUpClass = classmethod(ApproveCommissionTest.setUpClass.__func__)
    holders = ApproveCommissionTest.holders
    body = ApproveCommissionTest.body

    def test_who_holds_what(self):
        for fn in self.NEW:
            self.assertEqual(self.holders(fn), {"rr_qp"}, fn)
        self.assertIn("medcea.release_run(int, text)", self.policy.groups["runs"]["approval"]["functions"])

    def test_created_and_dropped_by_the_full_down(self):
        created = _created_functions(self.mig)
        drops = " ".join(re.findall(r"DROP FUNCTION IF EXISTS (.*?);", self.down, re.S))
        dropped = {grants.norm_sig(x.strip()) for x in re.split(r",\s*(?=[a-z_]+\.[a-z_]+\()", drops)}
        for fn in self.NEW:
            self.assertIn(fn, created, fn)
            self.assertIn(fn, dropped, f"{fn} is not in the down file's -v full=1 DROP list")
            self.assertIn(fn, grants.declared_functions(self.policy), fn)

    def test_noted_overload_has_no_default(self):
        self.assertIn("FUNCTION medcea.release_run(p_run_id integer, p_note text) RETURNS bigint", self.mig)
        self.assertIn("RETURN medcea.release_run(p_run_id, NULL::text);", self.body("FUNCTION medcea.release_run(p_run_id integer) RETURNS"))
        rel = self.body("FUNCTION medcea.release_run(p_run_id integer, p_note text)")
        self.assertIn("nt   text := nullif(btrim(p_note), '');", rel)
        self.assertIn("VALUES (p_run_id, h, nt, ap.sub", rel)                     # run_release.note
        self.assertIn("'runs', 'release', nt, au.persons", rel)                    # approval.note
        # the order the queue mirrors: approver, completed, not yet released, own author,
        # unattributed, no recorded creator or start (a run from before 008b)
        order = ["medcea_auth._approver('runs')", "not completed", "is already released", "not_own_author", "unattributed changes",
                 "no attributed history"]
        self.assertEqual([rel.index(x) for x in order], sorted(rel.index(x) for x in order))

    def test_queue_mirrors_release_run(self):
        q = self.body("FUNCTION medcea.approval_queue(")
        runs = q[q.index("FOR rn IN"):]
        # only A on runs and every unit's runs (an own_unit reader sees no run row)
        gate = q[:q.index("FOR rn IN")]
        self.assertIn("medcea_auth.policy_holds(a.role, 'runs', 'A') IS NULL", gate)
        self.assertIn("medcea_auth.policy_holds(a.role, 'runs', 'R') IS DISTINCT FROM 'free'", gate)
        self.assertIn("WHERE x.recipe_run_status = 'C'", runs)
        self.assertIn("NOT EXISTS (SELECT 1 FROM medcea.run_release rl WHERE rl.recipe_run_id = x.recipe_run_id)", runs)
        self.assertIn("medcea_auth._changes_since('medcea.recipe_run', rk)", runs)
        self.assertIn("WHEN a.person = ANY (cs.persons) OR a.person = rn.executed_by_person THEN 'own_author'", runs)
        self.assertLess(runs.index("THEN 'no_person'"), runs.index("THEN 'own_author'"))
        self.assertLess(runs.index("THEN 'own_author'"), runs.index("THEN 'unattributed'"))
        self.assertLess(runs.index("THEN 'unattributed'"), runs.index("THEN 'no_attribution'"))
        # one rule: the queue's no_attribution is release_run's refusal, predicate for predicate
        rel = self.body("FUNCTION medcea.release_run(p_run_id integer, p_note text)")
        pred = ("WHERE c.target = 'medcea.recipe_run' AND c.row_key = {} AND c.op IN ('I', 'U')",
                "AND c.new_values ->> 'recipe_run_status' = 'R' AND c.actor_person IS NOT NULL")
        for text, key in ((runs, "rk"), (rel, "k")):
            self.assertIn(pred[0].format(key), text)
            self.assertIn(pred[1], text)
        self.assertIn("WHEN rn.created_by_person IS NULL", runs)
        self.assertIn("r.created_by_person IS NULL", rel)
        self.assertIn("may_return := false;", runs)


if __name__ == "__main__":
    unittest.main(verbosity=1)
