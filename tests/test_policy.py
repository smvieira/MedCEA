#!/usr/bin/env python3
"""tests/test_policy.py — the access policy passes its own invariants, and the checker
catches every kind of violation it claims to.

IAM 4.5 (design §14.8.11): ApplyEventSetParity (new_draft's guard and policy_db_state read
one set of apply events), RollbackBoundTest (explain.rollback_bound), AuditVersionTest
(cli.py audit-version, the RS256 verifier), StagedResolutionTest (cli.py --staged).

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

sys.path.insert(0, os.path.join(REPO, "tests"))
from _scratch import clean_env, scratch_repo  # noqa: E402

_SCRATCH = []


def scratch_root():
    """One scratch copy for the tests that run cli.py or the shell libraries in a subprocess
    (design v4 §14.4.15): the repository's state/ never decides their outcome."""
    if not _SCRATCH:
        _SCRATCH.append(scratch_repo("medcea-test-policy-"))
    return _SCRATCH[0]


def tearDownModule():
    import shutil
    for d in _SCRATCH:
        shutil.rmtree(d, ignore_errors=True)

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


# Superset stage C (7 Nov 2026, commit B): the policy's additions, as defaults.yaml carries
# them. STAGE_C lists where they live; without_superset(d) is the policy as commit A had it
# (no host, group, service identity, pod or cell), add_superset(d) puts the factory file's
# additions back (a no-op on the defaults), so a test can build either side.
STAGE_C = (("hosts", "SUPERSET_DOMAIN"), ("service_identities", "svc_superset"),
           ("resource_groups", "analysis"), ("network", "pods", "superset"), ("matrix", "analysis"))


def _at(d, path):
    for k in path[:-1]:
        d = d[k]
    return d


def without_superset(d):
    """The policy without stage C's additions: what commit A's defaults.yaml was."""
    for path in STAGE_C:
        _at(d, path).pop(path[-1], None)
    return d


def add_superset(d):
    """Superset stage C (decisions D7, D8, N1-N3) on any policy, from the factory file: host
    SUPERSET_DOMAIN, group analysis (Alpha from U, Gamma from R), service identity
    svc_superset reading master_data and measurements only (no runs: I5 unchanged), the pod
    superset (8088 from ingress and the node), builders bio_scientist, control_scientist and
    engineer, viewers qp, qc and production_manager (no qa, no auditor)."""
    factory = model.load_defaults().data
    for path in STAGE_C:
        _at(d, path)[path[-1]] = copy.deepcopy(_at(factory, path)[path[-1]])
    return d


def _superset(*mutations):
    """A mutation of the policy with the Superset fixture added first."""
    def apply(d):
        add_superset(d)
        for m in mutations:
            m(d)
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
    # IAM 4.1: the one exception to "never a host's client" (only_rpc), and I12's availability rule
    "host client as token_client without only_rpc": (_pop(["network", "clients", "iam-approvals", "only_rpc"]),
                                                     "is a host's client"),
    "only_rpc without a token_client": (_pop(["network", "clients", "iam-approvals", "token_client"]),
                                        "only_rpc needs a token_client"),
    "only_rpc with read_only true": (_set(["network", "clients", "iam-approvals", "read_only"], True),
                                     "only_rpc with read_only: true"),
    "only_rpc client of a host that serves config-api": (_set(["network", "clients", "iam-approvals", "token_client"], "config"),
                                                          "which serves config-api"),
    "only_rpc name that is no medcea function": (_append(["network", "clients", "iam-approvals", "only_rpc"], "approve_nothing"),
                                                 "is no medcea function member"),
    "I12 approver only at availability later": (_set(["roles", "qa", "availability"], "later"),
                                                "I12 every role holding A on iam_policy"),
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
    # Superset stage B: the superset tool kind, on the stage C fixture (add_superset)
    "Superset Alpha by R": (_superset(_set(["resource_groups", "analysis", "tool", "settings", 0, "levels"], ["R"])),
                            "cannot give superset's Alpha"),
    "Superset Admin from a cell": (_superset(_append(["resource_groups", "analysis", "tool", "settings"],
                                                     {"setting": "Admin", "levels": ["K"]})),
                                   "is not one the policy may give for superset"),
    "Superset without its datasource identity": (_superset(_pop(["resource_groups", "analysis", "tool", "service_identity"])),
                                                 "is not a service identity"),
    "Superset reaches less than svc_superset": (_superset(_set(["resource_groups", "analysis", "reaches"], {"master_data": ["R"]})),
                                                "svc_superset reads"),
    "role admitted to Superset without a setting": (_superset(_pop(["resource_groups", "analysis", "tool", "settings", 1])),
                                                    "SUPERSET_DOMAIN admits"),
    "constrained analysis cell": (_superset(_set(["matrix", "analysis", "engineer"],
                                                 {"levels": ["R", "C", "U"], "constraint": "own_unit"})),
                                  "cannot evaluate"),
    "Superset reads runs for the scientists": (_superset(_set(["service_identities", "svc_superset", "ceiling", "runs"], ["R"]),
                                                         _set(["resource_groups", "analysis", "reaches", "runs"], ["R"])),
                                               "I5"),
}


# IAM 4.2b: deploy-infra's policy blocks live in infra/lib-policy-artefacts.sh (called at the
# same place), and the apps' gates are app_gate calls (infra/lib-oauth2-proxy.sh). The source
# checks read what runs: deploy-infra.sh with the library, and each app_gate call expanded into
# the lines app_gate runs for it (AppGateTest pins that app_gate runs exactly those).
APP_GATE = re.compile(r'app_gate "\$_MODE" (\S+) \S+ "[^"]*" "[^"]*" \\?\s*(\w+) "[^"]*" "([^"]+)"(?: (\S+))?')


def read_wired(rel):
    with open(os.path.join(REPO, rel)) as f:
        src = f.read()
    if rel == "deploy-infra.sh":
        with open(os.path.join(REPO, "infra/lib-policy-artefacts.sh")) as f:
            src += "\n" + f.read()

    def expand(m):
        release, host, tpl, svc = m.groups()
        app = f"APP_SERVICE={svc} " if svc else ""
        return (f'\nALLOWED_GROUPS="$(policy_groups {host})"\n'
                f'gate_error_page {release} {host} "$ALLOWED_GROUPS"\n'
                f'{app}render "{tpl}" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE ALLOWED_GROUPS > "$values"')
    return APP_GATE.sub(expand, src)


class PolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = model.load_defaults()

    def test_defaults_pass(self):
        errors, _ = invariants.check(self.policy)
        self.assertEqual(errors, [], "\n" + "\n".join(errors))

    def test_counts(self):
        p = self.policy
        self.assertEqual(len(p.roles), 11)
        self.assertEqual(len(p.groups), 28)        # policy_page (IAM 4.1), analysis (Superset stage C)

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
        cls.policy = model.load_defaults()

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
        cli = [sys.executable, os.path.join(REPO, "apps", "iam", "compiler", "cli.py"), "--defaults", "compile"]
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


class SupersetToolTest(unittest.TestCase):
    """Superset stage B (6 Nov 2026): the superset tool kind and AUTH_ROLES_MAPPING; stage C
    (7 Nov 2026, commit B): defaults.yaml's group analysis carries it, with the six factory
    cells (N1, N2). `absent` is the policy as commit A had it (without_superset)."""

    @classmethod
    def setUpClass(cls):
        cls.p = model.load_defaults()
        cls.absent = model.Policy(without_superset(copy.deepcopy(cls.p.data)))

    def test_defaults_pass_the_checker(self):
        errors, _ = invariants.check(self.p)
        self.assertEqual(errors, [], "\n" + "\n".join(errors))
        self.assertEqual(invariants.check(self.absent)[0], [])

    def test_the_fixtures(self):
        """add_superset is a no-op on the defaults and undoes without_superset."""
        self.assertEqual(add_superset(copy.deepcopy(self.p.data)), self.p.data)
        self.assertEqual(add_superset(copy.deepcopy(self.absent.data)), self.p.data)
        for path in STAGE_C:
            self.assertIn(path[-1], _at(self.p.data, path), path)
            self.assertNotIn(path[-1], _at(self.absent.data, path), path)

    def test_the_real_group(self):
        """The shape commit B ships (B1): a config group whose only member is the host, its
        reach exactly svc_superset's ceiling, Alpha from U and Gamma from R, no proxy (the
        tool signs people in itself, F4), the pod admitting ingress-nginx and the node only."""
        g = self.p.groups["analysis"]
        self.assertEqual(g["class"], "config")
        self.assertEqual(g["members"], [{"type": "ui", "host": "SUPERSET_DOMAIN"}])
        self.assertEqual(g["reaches"], {"master_data": ["R"], "measurements": ["R"]})
        self.assertEqual({k: v for k, v in g["tool"].items() if k != "help"},
                         {"kind": "superset", "host": "SUPERSET_DOMAIN", "service_identity": "svc_superset",
                          "settings": [{"setting": "Alpha", "levels": ["U"]}, {"setting": "Gamma", "levels": ["R"]}],
                          "otherwise": "refuse"})
        for key in ("mirrors", "approval"):
            self.assertNotIn(key, g)
        self.assertEqual(self.p.hosts["SUPERSET_DOMAIN"], {"label": "Superset", "client": "superset", "serves": ["superset"]})
        net = self.p.data["network"]
        self.assertNotIn("SUPERSET_DOMAIN", net["proxies"])
        self.assertNotIn("SUPERSET_DOMAIN", net.get("unproxied") or {})
        pod = net["pods"]["superset"]
        self.assertEqual((pod["selector"], pod["carries"]), ({"app": "superset"}, {}))
        self.assertEqual([(i["port"], i["from"]) for i in pod["ingress"]], [(8088, ["ingress", "node"])])
        self.assertIn("superset-init", pod["ingress"][0]["why"])
        svc = self.p.services["svc_superset"]
        self.assertEqual((svc["db_role"], svc["db_password"]), ("svc_superset", "SVC_SUPERSET_DB_PASS"))
        self.assertNotIn("mqtt_user", svc)
        self.assertEqual(self.p.data["matrix"]["analysis"],
                         {"production_manager": ["R"], "qc": ["R"], "qp": ["R"],
                          "engineer": ["R", "C", "U"], "bio_scientist": ["R", "C", "U"], "control_scientist": ["R", "C", "U"]})
        self.assertEqual(proxies.ENFORCEMENT["SUPERSET_DOMAIN"], "tool (Superset AUTH_ROLES_MAPPING)")
        self.assertIn("iam-superset", {i["metadata"]["name"] for i in netpol.compile(self.p, "medcea", ["10.0.0.5"])["items"]})

    def test_kind_settings_and_identity(self):
        self.assertEqual(tools.KINDS["superset"], {"Alpha", "Gamma"})
        self.assertEqual(tools.SETTING_LEVELS[("superset", "Alpha")], {"U"})
        self.assertIn("superset", tools.SERVICE_IDENTITY)
        self.assertEqual(tools.SUPERSET_ROLES, {"Alpha": ["Alpha", "sql_lab"], "Gamma": ["Gamma", "MedCEA Viewer"]})
        for fab_roles in tools.SUPERSET_ROLES.values():
            self.assertNotIn("Admin", fab_roles)   # never from the policy

    def test_mapping(self):
        alpha, gamma = ["Alpha", "sql_lab"], ["Gamma", "MedCEA Viewer"]
        mapping = tools.superset_roles_mapping(self.p)
        self.assertEqual(mapping, {"bio_scientist": alpha, "control_scientist": alpha, "engineer": alpha,
                                   "production_manager": gamma, "qc": gamma, "qp": gamma})
        self.assertEqual(sorted(mapping), proxies.admitted(self.p, "SUPERSET_DOMAIN"))
        for refused in ("qa", "auditor", "admin", "operator", "maintenance"):   # D8
            self.assertNotIn(refused, mapping)
        self.assertEqual(dict(tools.settings(self.p, "analysis")),
                         {"Alpha": ["bio_scientist", "control_scientist", "engineer"],
                          "Gamma": ["production_manager", "qc", "qp"]})

    def test_ceiling_reads_no_runs(self):
        """D7: master_data and measurements only, so I5 needs no change."""
        self.assertEqual(self.p.services["svc_superset"]["ceiling"], {"master_data": ["R"], "measurements": ["R"]})
        reaches = self.p.groups["analysis"]["reaches"]
        for g, lv in self.p.services["svc_superset"]["ceiling"].items():
            self.assertLessEqual(set(lv), self.p.closure(reaches.get(g, [])), g)

    def test_absent_is_an_error(self):
        self.assertEqual(tools.groups(self.absent, "superset"), [])
        with self.assertRaisesRegex(ValueError, "found 0"):
            tools.superset_roles_mapping(self.absent)

    def test_empty_mapping_is_an_error(self):
        d = copy.deepcopy(self.p.data)
        d["matrix"]["analysis"] = {}
        with self.assertRaisesRegex(ValueError, "admit nobody"):
            tools.superset_roles_mapping(model.Policy(d))

    def test_present_without_cells(self):
        """Stage C's skeleton version alone (F1): the tool block with no cell passes the
        checker; has-tool says present (0), has-tool --admitting says nobody (3), compile
        refuses (1). policy_tool maps that 3 to its "not in the applied policy" 5."""
        import subprocess
        import tempfile
        import yaml
        d = copy.deepcopy(self.p.data)
        del d["matrix"]["analysis"]
        skel = model.Policy(d)
        self.assertEqual(invariants.check(skel)[0], [])
        self.assertFalse(tools.admits_anyone(skel, "superset"))
        self.assertTrue(tools.admits_anyone(self.p, "superset"))
        with self.assertRaisesRegex(ValueError, "found 0"):
            tools.admits_anyone(self.absent, "superset")
        cli_py = os.path.join(REPO, "apps", "iam", "compiler", "cli.py")
        defaults = [sys.executable, cli_py, "--defaults"]   # the factory file, never the host's
        with_file = [sys.executable, cli_py, "--file"]
        r = subprocess.run(defaults + ["has-tool", "superset", "--admitting"], capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout), (0, ""))   # N2: the factory cells
        with tempfile.TemporaryDirectory() as tmp:
            for name, data, want in (("absent", self.absent.data, (1, 1)), ("skel", d, (0, 3)),
                                     ("full", self.p.data, (0, 0))):
                f = os.path.join(tmp, f"{name}.yaml")
                with open(f, "w") as fh:
                    yaml.safe_dump(data, fh)
                with self.subTest(name):
                    for extra, rc in (([], want[0]), (["--admitting"], want[1])):
                        r = subprocess.run(with_file + [f, "--label", name, "has-tool", "superset"] + extra,
                                           capture_output=True, text=True)
                        self.assertEqual((r.returncode, r.stdout), (rc, ""), extra)
            r = subprocess.run(with_file + [os.path.join(tmp, "skel.yaml"), "--label", "skel", "compile", "superset"],
                               capture_output=True, text=True)
            self.assertEqual((r.returncode, r.stdout), (1, ""))
            self.assertIn("Superset would admit nobody", r.stderr)

    def test_two_superset_groups_are_an_error(self):
        d = copy.deepcopy(self.p.data)
        d["resource_groups"]["analysis_copy"] = copy.deepcopy(d["resource_groups"]["analysis"])
        with self.assertRaisesRegex(ValueError, "found 2"):
            tools.superset_roles_mapping(model.Policy(d))

    def test_alpha_given_by_r_is_refused(self):
        d = copy.deepcopy(self.p.data)
        d["resource_groups"]["analysis"]["tool"]["settings"][0]["levels"] = ["R"]
        errors, _ = invariants.check(model.Policy(d))
        self.assertTrue(any("cannot give superset's Alpha" in e for e in errors), errors)

    def test_tool_block_does_not_change_route_digest(self):
        d = copy.deepcopy(self.p.data)
        del d["resource_groups"]["analysis"]["tool"]
        self.assertEqual(routes.compile(model.Policy(d))["digest"], routes.compile(self.p)["digest"])

    def test_cli(self):
        import subprocess
        import tempfile
        import yaml
        cli_py = os.path.join(REPO, "apps", "iam", "compiler", "cli.py")
        defaults = [sys.executable, cli_py, "--defaults"]   # the factory file, never the host's
        with_file = [sys.executable, cli_py, "--file"]
        out = subprocess.run(defaults + ["compile", "superset"], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout, json.dumps(tools.superset_roles_mapping(self.p), sort_keys=True) + "\n")
        self.assertEqual(subprocess.run(defaults + ["has-tool", "superset"], capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run(defaults + ["has-tool", "grafana"], capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run(defaults + ["has-tool", "zeppelin"], capture_output=True).returncode, 2)
        with tempfile.TemporaryDirectory() as tmp:
            f = os.path.join(tmp, "absent.yaml")
            with open(f, "w") as fh:
                yaml.safe_dump(self.absent.data, fh)
            out = subprocess.run(with_file + [f, "--label", "absent", "compile", "superset"],
                                 capture_output=True, text=True)
            self.assertEqual((out.returncode, out.stdout), (1, ""))
            self.assertIn("no group has a superset tool block", out.stderr)
            self.assertEqual(subprocess.run(with_file + [f, "--label", "absent", "has-tool", "superset"],
                                            capture_output=True).returncode, 1)
            f = os.path.join(tmp, "superset.yaml")
            with open(f, "w") as fh:
                yaml.safe_dump(self.p.data, fh)
            out = subprocess.run(with_file + [f, "--label", "fixture", "compile", "superset"],
                                 capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(out.stdout, json.dumps(tools.superset_roles_mapping(self.p), sort_keys=True) + "\n")
            self.assertEqual(subprocess.run(with_file + [f, "--label", "fixture", "has-tool", "superset"],
                                            capture_output=True).returncode, 0)
            bad = copy.deepcopy(self.p.data)
            bad["resource_groups"]["analysis"]["tool"]["settings"][0]["levels"] = ["R"]
            with open(f, "w") as fh:
                yaml.safe_dump(bad, fh)
            out = subprocess.run(with_file + [f, "--label", "fixture", "compile", "superset"],
                                 capture_output=True, text=True)
            self.assertEqual((out.returncode, out.stdout), (1, ""))
            self.assertEqual(subprocess.run(with_file + [f, "--label", "fixture", "has-tool", "superset"],
                                            capture_output=True).returncode, 2)


class RoutesTest(unittest.TestCase):
    """compiler/routes.py: the route table in ConfigMap medcea-iam-lib (Phase 1.1)."""

    @classmethod
    def setUpClass(cls):
        cls.policy = model.load_defaults()
        cls.doc = routes.compile(cls.policy)

    def test_deterministic_and_digest_covers_body(self):
        again = routes.compile(model.load_defaults())
        self.assertEqual(routes.dumps(self.doc), routes.dumps(again))
        # IAM 4.2a: the digest covers the body but its unhashed labels (routes.UNHASHED)
        body = {k: v for k, v in self.doc.items() if k != "digest" and k not in routes.UNHASHED}
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
        cls.policy = model.load_defaults()

    def test_widening_values(self):
        p = self.policy
        w = p.widening("operator", "production_manager")
        self.assertEqual(len(w), 13)
        self.assertIn(("analysis", "R"), w)   # Superset's viewer (stage C, N1)
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
        # IAM 4.2a: the source's label is not hashed, so a policy file given by name keeps
        # the digest of the same content (design §14.4.7)
        other = routes.compile(self.policy, "v7.yaml")["digest"]
        self.assertEqual(other, doc["digest"])
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
        cls.policy = model.load_defaults()
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
        self.assertEqual(len(profile), 8)                 # every proxy with /_account/ (POLICY_DOMAIN's: IAM 4.1) …
        self.assertNotIn({"podSelector": {"matchLabels": {"app.kubernetes.io/instance": "oauth2-proxy"}}}, profile)  # … not Node-RED's

    def test_node_addresses_required(self):
        with self.assertRaisesRegex(ValueError, "no node address"):
            netpol.compile(self.policy, "medcea", [])


class MqttTest(unittest.TestCase):
    """compiler/mqtt.py: the MQTT Explorer's personal credential rows (IAM 3.5)."""

    @classmethod
    def setUpClass(cls):
        cls.policy = model.load_defaults()

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
        a, b = mqtt.dumps(mqtt.compile(self.policy)), mqtt.dumps(mqtt.compile(model.load_defaults()))
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
        infra = read_wired("deploy-infra.sh")
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
        cls.policy = model.load_defaults()
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
        again = grants.document(model.load_defaults())
        self.assertEqual(again["digest"], self.doc["digest"])
        for mode in ("additive", "enforce", "verify"):
            self.assertEqual(grants.sql(self.policy, mode), grants.sql(model.load_defaults(), mode))

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
        # iam_svc lost zones in IAM 4.1 (propose_unit was dropped); access_svc writes it through
        # the decision functions and iam.record_unit_decision (the User Manager's Units section)
        self.assertEqual(self.holders("iam_policy.user_unit"),
                         {"access_svc", "rr_auditor", "rr_qa", "svc_dbexport", "svc_monitor", "svc_scheduler"})
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
                   "medcea.revoke_person_mqtt(uuid,text)",
                   # zones: an admin assigns or removes a unit in the User Manager (units, commit B)
                   "iam.record_unit_decision(text,text,text,text,integer,text)"):
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
        # propose_unit left the policy in IAM 4.1 (owner decision 4); NOT_BUILT holds the waiver editing only
        self.assertNotIn("iam_policy.propose_unit(uuid,integer,text)", {o for g, k, o, p in self.privs})
        self.assertNotIn("iam_policy.propose_unit(uuid,integer,text)", grants.NOT_BUILT)
        self.assertEqual(set(grants.NOT_BUILT.values()), {"4.7"})
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
        for r in grants.managed(model.load_defaults()):
            self.assertTrue(r.startswith(("rr_", "svc_")) or r == "iam_svc", r)
        self.assertGreaterEqual(len(pat.findall(down)), 2)

    def read(self, rel):
        return read_wired(rel)


class WiringTest(unittest.TestCase):
    """The places outside the compiler that must agree with the policy."""

    @classmethod
    def setUpClass(cls):
        cls.policy = model.load_defaults()

    def read(self, rel):
        return read_wired(rel)

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
        wiring["k8s/oauth2-proxy/values-app.yaml"].append(("apps/iam/deploy.sh", "POLICY_DOMAIN"))   # IAM 4.3
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
        tail = migrations[migrations.index("Migration 008b"):migrations.index("Migration 008c")]
        self.assertEqual((tail.count("BEGIN;"), tail.count("COMMIT;")), (1, 1))
        self.assertIn("'008b:last_nonce', :'deploy_nonce'", tail)
        # 008c (IAM 4.1) is a second transaction after it, with the same nonce, read back too
        tail_c = migrations[migrations.index("Migration 008c"):migrations.index("Migration 009")]
        self.assertEqual((tail_c.count("BEGIN;"), tail_c.count("COMMIT;")), (1, 1))
        # each later migration (009, msg_type HB/TS) is a transaction of its own
        tail_9 = migrations[migrations.index("Migration 009"):migrations.index("Migration 010")]
        self.assertEqual(tail_9.count("BEGIN;"), tail_9.count("COMMIT;"))
        tail_10 = migrations[migrations.index("Migration 010"):]
        self.assertEqual((tail_10.count("BEGIN;"), tail_10.count("COMMIT;")), (1, 1))
        self.assertIn("'010:last_nonce', :'deploy_nonce'", tail_10)
        self.assertIn("key = '010:last_nonce'", self.read("apps/database/lib-db-apply.sh"))
        self.assertIn("'008c:last_nonce', :'deploy_nonce'", tail_c)
        self.assertIn("key = '008c:last_nonce'", self.read("apps/database/lib-db-apply.sh"))
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
                         {"GRAFANA_DOMAIN", "WORKBENCH_DOMAIN", "ONBOARD_DOMAIN", "PGADMIN_DOMAIN", "SUPERSET_DOMAIN"})
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
        # SCRIPT_DIR is a scratch copy: the health functions compile through policy_tool
        script = (f'_record() {{ echo "$1|$2|$3"; }}\nSCRIPT_DIR={scratch_root()}\nTIMEOUT=5\nKUBECTL=kubectl\n'
                  f"{body}\n{setup}\n")
        e = clean_env(PATH=tmp + ":" + os.environ["PATH"], **(env or {}))
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

        def run(tool, env, repo=None):
            root = scratch_root()
            e = clean_env(REPO_ROOT=repo or root, **env)
            return subprocess.run(["bash", "-c", f'source "{root}/infra/lib-policy-tools.sh"; policy_tool {tool}'],
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

    def test_policy_tool_superset_shell(self):
        """Superset stage B: rc 5 while the policy has no superset tool, and (stage C, F1) while
        its group gives no role a setting, 3 under IAM_GATES=false, 1 on a broken policy, the
        compiled mapping once a group carries the tool and its cells (the factory file since
        stage C's commit B); never a word on stdout but the mapping."""
        import shutil
        import subprocess
        import yaml

        def run(root, env, repo=None):
            e = clean_env(REPO_ROOT=repo or root, **env)
            e.pop("EDGE_WIZARD_ROLE", None)
            return subprocess.run(["bash", "-c", f'source "{root}/infra/lib-policy-tools.sh"; policy_tool superset'],
                                  capture_output=True, text=True, env=e)
        r = run(scratch_root(), {"IAM_GATES": "true"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), tools.superset_roles_mapping(model.load_defaults()))
        r = run(scratch_root(), {"IAM_GATES": "false"})
        self.assertEqual((r.returncode, r.stdout), (3, ""))
        self.assertIn("IAM_GATES=false", r.stderr)
        r = run(scratch_root(), {"IAM_GATES": "true", "MEDCEA_POLICY_FILE": os.path.join(REPO, "apps/iam/policy/defaults.yaml"),
                                 "MEDCEA_POLICY_BREAK_GLASS": "trial"})
        self.assertEqual((r.returncode, r.stdout), (1, ""))     # an inherited override is refused
        self.assertIn("MEDCEA_POLICY_FILE is set", r.stderr)
        root = scratch_repo("medcea-test-superset-")
        try:
            data = copy.deepcopy(model.load_defaults().data)
            target = os.path.join(root, "apps", "iam", "policy", "defaults.yaml")
            with open(target, "w") as fh:   # commit A's policy: no tool
                yaml.safe_dump(without_superset(copy.deepcopy(data)), fh)
            r = run(root, {"IAM_GATES": "true"})
            self.assertEqual((r.returncode, r.stdout), (5, ""), r.stderr)
            self.assertIn("not in the applied access policy (no group has a superset tool block)", r.stderr)
            skel = copy.deepcopy(data)   # the skeleton version alone: the block, no cell
            del skel["matrix"]["analysis"]
            with open(target, "w") as fh:
                yaml.safe_dump(skel, fh)
            r = run(root, {"IAM_GATES": "true"})
            self.assertEqual((r.returncode, r.stdout), (5, ""), r.stderr)
            self.assertIn("gives no role a setting", r.stderr)
            with open(target, "w") as fh:
                yaml.safe_dump(data, fh)
            r = run(root, {"IAM_GATES": "true"})
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout), tools.superset_roles_mapping(model.Policy(data)))
            self.assertEqual(r.stdout.count("\n"), 1)
            data["resource_groups"]["analysis"]["tool"]["settings"][0]["levels"] = ["R"]   # broken: Alpha by R
            with open(target, "w") as fh:
                yaml.safe_dump(data, fh)
            r = run(root, {"IAM_GATES": "true"})
            self.assertEqual((r.returncode, r.stdout), (1, ""))
            r = run(root, {"IAM_GATES": "true"}, repo="/nonexistent")
            self.assertEqual((r.returncode, r.stdout), (1, ""))
        finally:
            shutil.rmtree(root, ignore_errors=True)

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
        self.assertIn("NR_LOGOUT_URL", used)
        self.assertIn('NR_LOGOUT_URL="$(node_red_logout_url)" ||', infra)
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
        return read_wired(rel)

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
                                                  "mqtt-explorer", "policy"]))   # policy: the Policy UI, IAM 4.3
        for c in clients:
            calls = re.findall(r'_create_client "%s" "[^"]+"( [^)]*)?\)' % re.escape(c), src)
            self.assertEqual(len(calls), 1, c)
            self.assertTrue(calls[0].endswith(' "" "$_HUB_LOGOUT_URI"'), (c, calls[0]))
        self.assertLess(src.index('_HUB_LOGOUT_URI="'), src.index('_create_client "portal"'))
        # Node-RED's editor Logout (5 Nov 2026, node_red_logout_url) returns there too, so the
        # node-red client registers it, and the address is defined before that client
        nr = re.search(r'_create_client "node-red" (.*?)\)\n', src, re.S).group(1)
        self.assertTrue(nr.rstrip().endswith('"$_HUB_LOGOUT_URI"'), nr)
        self.assertLess(src.index('_HUB_LOGOUT_URI="'), src.index('_create_client "node-red"'))
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
        cls.policy = model.load_defaults()
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


class Phase41Test(unittest.TestCase):
    """IAM Phase 4, slice 4.1 (design §14.2): migration 008c and its down file, the
    only_rpc exception and pre_request's block, _rpc_client, dual_control, the exports,
    the entries digest's Python twin, and the members' agreement with the SQL."""

    WRAPPERS = ("medcea.approve_policy(integer,text,text,text,text)", "medcea.return_policy(integer,text)",
                "medcea.confirm_policy(integer,text,text)", "medcea.dispute_policy(integer,text)")
    TABLES = ("version", "entry", "waiver", "skeleton", "version_diff", "approval_evidence")

    @classmethod
    def setUpClass(cls):
        cls.policy = model.load_defaults()
        cls.privs = grants.privileges(cls.policy)
        with open(os.path.join(REPO, "apps/database/medcea_db_migrations.sql")) as f:
            cls.mig = f.read()
        cls.c = cls.mig[cls.mig.index("Migration 008c"):cls.mig.index("Migration 009")]
        with open(os.path.join(REPO, "apps/database/medcea_db_migrations_down_008c.sql")) as f:
            cls.down_c = f.read()
        with open(os.path.join(REPO, "apps/database/medcea_db_migrations_down_008b.sql")) as f:
            cls.down_b = f.read()
        cls.full = cls.down_b[cls.down_b.index("\\if :{?full}"):]

    def holders(self, obj, priv="EXECUTE"):
        return {g for g, k, o, p in self.privs if o == obj and p == priv}

    @staticmethod
    def outside_bodies(sql):
        """The SQL text with every dollar-quoted body blanked: what runs at the top level."""
        return re.sub(r"\$(\w*)\$.*?\$\1\$", "$$", sql, flags=re.S)

    @staticmethod
    def dropped(sql):
        drops = ", ".join(re.findall(r"DROP FUNCTION IF EXISTS\s+(.*?);", sql, re.S))
        return {grants.norm_sig(x.strip()) for x in re.split(r",\s*(?=[a-z_]+\.[a-z_]+\()", drops) if x.strip()}

    def test_members_match_the_sql(self):
        created = _created_functions(self.c)
        declared = set(grants.declared_functions(self.policy)) | set(grants.NOT_BUILT)
        for fn in created:
            self.assertIn(fn, declared, f"{fn}: created by 008c but no member or infrastructure function")
        named = {f for f in declared if f.startswith("iam_policy.") or f in self.WRAPPERS}
        existing = _created_functions(self.mig[:self.mig.index("Migration 008c")])
        for fn in named - existing:
            self.assertTrue(fn in created or fn in grants.NOT_BUILT, f"{fn}: named by the policy, created nowhere")
        self.assertEqual(set(grants.NOT_BUILT), {"iam_policy.save_waiver(integer,jsonb,text,double precision)",
                                                 "iam_policy.drop_waiver(integer,text,text,double precision)"})
        for fn in grants.NOT_BUILT:
            self.assertNotIn(fn, created)
        self.assertIn("iam._changed_since(text,text,double precision)", _created_functions(self.read_access()))
        self.assertIn("medcea_auth._person_actor(text,text,text)", _created_functions(self.mig))

    def read_access(self):
        with open(os.path.join(REPO, "apps/access/access_db.sql")) as f:
            return f.read()

    def test_down_files_name_everything(self):
        created = {f for f in _created_functions(self.c) if not f.startswith("medcea_auth.")}
        # dropped, or (append_history, whose filter 008c puts in front) given back its 008b body
        self.assertEqual(created - self.dropped(self.down_c) - _created_functions(self.down_c), set(),
                         "down_008c misses a 008c function")
        self.assertEqual(_created_functions(self.down_c), {"iam_policy.append_history(text,jsonb,text)"})
        for t in self.TABLES:
            self.assertIn(f"'{t}'", self.down_c[self.down_c.index("DROP TRIGGER IF EXISTS") - 300:])
        for trg in ("freeze_policy_trg", "freeze_policy_truncate_trg"):
            self.assertIn(trg, self.down_c)
            self.assertIn(trg, self.full)
        full_drops = self.dropped(self.full)
        for fn in self.WRAPPERS + ("medcea_auth._person_actor(text,text,text)", "medcea_auth._rpc_client(text)"):
            self.assertIn(fn, full_drops, f"{fn} is not in the down file's -v full=1 DROP list")
        # the wrappers go before schema medcea is given back to postgres
        self.assertLess(self.full.index("medcea.approve_policy("), self.full.index("ALTER SCHEMA medcea OWNER TO postgres"))
        self.assertIn("policy versions exist", self.down_c)
        self.assertNotRegex(self.down_c, r"(?m)^(BEGIN|COMMIT);")

    def test_008c_is_rerun_safe(self):
        top = self.outside_bodies(self.c)
        # no row is written but the nonce, and no table altered outside a guarded DO block
        self.assertEqual(re.findall(r"INSERT INTO ([a-z_.]+)", top), ["medcea.platform_setting"])
        self.assertNotRegex(top, r"\bUPDATE iam_policy\.")
        self.assertNotRegex(top, r"(?m)^\s*ALTER TABLE")
        self.assertNotRegex(self.c, r"(?m)^[^-\n]*CREATE OR REPLACE TRIGGER")   # (comments may name it)
        self.assertNotRegex(top, r"CREATE (UNIQUE )?INDEX")
        # ENABLE ALWAYS, only where the trigger is not in that mode yet
        self.assertIn("tgenabled <> 'A'", self.c)
        self.assertIn("ENABLE ALWAYS TRIGGER freeze_policy_trg", self.c)
        # new tables lose PUBLIC/anon/authenticator right after their CREATE
        self.assertIn("REVOKE ALL ON iam_policy.entry, iam_policy.skeleton, iam_policy.version_diff, "
                      "iam_policy.approval_evidence\n    FROM PUBLIC, anon, authenticator;", self.c)
        # the gap the coverage check found (§2.2): _sync_skeleton writes resource_group.retired
        self.assertIn("['resource_group', 'retired', 'boolean NOT NULL DEFAULT false']", self.c)
        # its own ownership loop: 008b's (B21) ran before it
        self.assertLess(self.mig.index("B21. Ownership"), self.mig.index("Migration 008c"))
        self.assertIn("ALTER FUNCTION %s OWNER TO medcea_owner", self.c)

    def test_policy_events_only_through_the_writer(self):
        # iam_svc executes append_history (iam-api), so it must not reach the events the
        # policy's versions are read from: 008c's filter refuses them, the functions use
        # the owner-only _append_history (review of slice 4.1)
        i = self.c.index("CREATE OR REPLACE FUNCTION iam_policy.append_history(")
        flt = self.c[i:self.c.index("END $$;", i)]
        events = set(re.findall(r"_append_history\('([a-z_]+)'", self.c))
        events |= {"applied", "partial_apply", "bootstrap_applied", "break_glass_seen", "apply_deferred", "account_seeded"}
        for ev in events:
            self.assertTrue(f"'{ev}'" in flt or ev.startswith(("skeleton_", "waiver_")), ev)
        self.assertIn("LIKE 'skeleton\\_%'", flt)
        self.assertIn("LIKE 'waiver\\_%'", flt)
        self.assertIn("ERRCODE = '42501'", flt)
        self.assertIn("RETURN iam_policy._append_history(p_event, p_payload - 'version', p_reason);", flt)
        # no 008c function body calls the public one any more
        self.assertEqual(re.findall(r"(?<![_\w])iam_policy\.append_history\('", self.c), [])
        rec = self.c[self.c.index("FUNCTION iam_policy._record("):]
        self.assertIn("iam_policy._append_history(p_event", rec[:rec.index("END $$;")])
        # B16's body is re-created only while 008c's writer is absent, so a re-run opens no window
        b16 = self.mig[self.mig.index("B16. append_history"):self.mig.index("Migration 008c")]
        self.assertLess(b16.index("\\if :b16_writer"), b16.index("FUNCTION iam_policy.append_history("))
        self.assertIn("\\endif", b16[b16.index("FUNCTION iam_policy.append_history("):b16.index("log_export(groups")])
        # the down file restores the writer before dropping _append_history
        self.assertIn("iam_policy._append_history(text, jsonb, text)", self.down_c)
        self.assertLess(self.down_c.index("FUNCTION iam_policy.append_history("),
                        self.down_c.index("iam_policy._append_history(text, jsonb, text)"))

    def test_wrappers_are_plpgsql_definers(self):
        for w in ("approve_policy", "return_policy", "confirm_policy", "dispute_policy"):
            i = self.c.index(f"FUNCTION medcea.{w}(")
            head = self.c[i:self.c.index("AS $$", i)]
            self.assertIn("LANGUAGE plpgsql SECURITY DEFINER", head, w)   # _rpc_client is compiled after the migrations
        # the internals check the client the wrapper is named for
        for internal, rpc in (("approve", "approve_policy"), ("return_version", "return_policy"),
                              ("confirm_applied", "confirm_policy"), ("dispute_applied", "dispute_policy")):
            i = self.c.index(f"FUNCTION iam_policy.{internal}(")
            self.assertIn(f"iam_policy._qa('{rpc}')", self.c[i:self.c.index("END $$;", i)], internal)
        qa = self.c[self.c.index("FUNCTION iam_policy._qa("):]
        qa = qa[:qa.index("END $$;")]
        order = ["medcea_auth._approver('iam_policy')", "medcea_auth._rpc_client(p_rpc)", "iam_policy._changed_since("]
        self.assertEqual([qa.index(x) for x in order], sorted(qa.index(x) for x in order))
        self.assertIn("'approve access-policy versions in the Policy UI'", qa)

    def test_approver_blank_person(self):
        ap = self.mig[self.mig.index("FUNCTION medcea_auth._approver("):]
        ap = ap[:ap.index("END $$;")]
        self.assertIn("IF a.person IS NULL OR btrim(a.person) = '' THEN", ap)
        # the queue's advisory codes follow the same rule (coverage check, G9)
        q = self.mig[self.mig.index("FUNCTION medcea.approval_queue("):]
        q = q[:q.index("END $$;")]
        self.assertNotIn("WHEN a.person IS NULL THEN 'no_person'", q)
        self.assertEqual(q.count("WHEN btrim(coalesce(a.person, '')) = '' THEN 'no_person'"), 3)
        acc = self.mig[self.mig.index("FUNCTION medcea_auth._account_actor("):]
        self.assertIn("medcea_auth._person_actor('access_svc', p_group, p_level)", acc[:acc.index("END $$;")])

    def test_pre_request_only_rpc(self):
        fn = grants.compiled_functions(self.policy)
        pre = fn[fn.index("FUNCTION medcea_auth.pre_request()"):fn.index("$pre$;")]
        self.assertEqual(pre.count("may only call"), 1)
        for w in ("approve_policy", "return_policy", "confirm_policy", "dispute_policy"):
            self.assertIn(f"'/rpc/{w}'", pre)
        self.assertIn("IS DISTINCT FROM 'POST'", pre)
        # IAM 4.2a (L6): the only_rpc refusal runs in both modes, so before the mode check
        # and therefore before the azp check of enforce mode
        self.assertLess(pre.index("may only call"), pre.index("may not use the API"))
        self.assertLess(pre.index("may only call"), pre.index("may only read"))
        self.assertIn("'policy'", pre[:pre.index("may not use the API")])
        self.assertEqual(grants.only_rpc_clients(self.policy),
                         {"policy": ["approve_policy", "confirm_policy", "dispute_policy", "return_policy"]})
        self.assertIn("policy", grants.token_clients(self.policy))
        self.assertNotIn("policy", grants.read_only_clients(self.policy))
        rc = fn[fn.index("FUNCTION medcea_auth._rpc_client("):fn.index("$rc$;")]
        self.assertEqual(re.findall(r"WHEN '([a-z_]+)' THEN '([a-z-]+)'", rc),
                         [("approve_policy", "policy"), ("confirm_policy", "policy"),
                          ("dispute_policy", "policy"), ("return_policy", "policy")])
        self.assertEqual(grants.document(self.policy)["only_rpc"], grants.only_rpc_clients(self.policy))
        # without an only_rpc client: no block, and _rpc_client answers NULL for everything
        d = copy.deepcopy(self.policy.data)
        del d["network"]["clients"]["iam-approvals"]
        d["network"]["pods"]["config-api"]["ingress"][0]["from"].remove("client:iam-approvals")
        fn2 = grants.compiled_functions(model.Policy(d))
        self.assertNotIn("may only call", fn2)
        self.assertIn("SELECT NULL::text", fn2)

    def test_who_holds_the_008c_functions(self):
        for w in self.WRAPPERS:
            self.assertEqual(self.holders(w), {"rr_qa"}, w)
        for fn in ("iam_policy.new_draft(text,text,double precision,jsonb,jsonb)",
                   "iam_policy.save_entry(integer,text,text,jsonb,text,jsonb,double precision)",
                   "iam_policy.submit(integer,text,double precision)", "iam_policy.withdraw(integer,text,double precision)",
                   "iam._changed_since(text,text,double precision)"):
            self.assertEqual(self.holders(fn), {"iam_svc"}, fn)
        for fn in ("iam_policy.why_not(integer)", "iam_policy.entries_digest(integer)", "iam_policy.audit_versions()"):
            self.assertEqual(self.holders(fn), {"iam_svc", "rr_qa", "rr_admin", "rr_auditor", "svc_dbexport"}, fn)
        self.assertEqual(self.holders("iam_policy.verify_chain()"), {"iam_svc"})
        for internal in ("iam_policy.approve(integer,text,text,text,text)", "iam_policy._mark_applied(integer,jsonb,text,uuid,text,text)",
                         "iam_policy._build_version(text,jsonb,jsonb,integer,integer,text)", "medcea_auth._rpc_client(text)",
                         "medcea_auth._person_actor(text,text,text)", "iam_policy.freeze_policy()",
                         "iam_policy._append_history(text,jsonb,text)"):
            self.assertEqual(self.holders(internal), set(), internal)
        self.assertEqual({g for g, k, o, p in self.privs if o == "iam_policy.approval_evidence"}, set())
        for t in ("iam_policy.role", "iam_policy.resource_group", "iam_policy.member", "iam_policy.effective_route",
                  "iam_policy.skeleton", "iam_policy.version_diff"):
            self.assertEqual({p for g, k, o, p in self.privs if o == t}, {"SELECT"}, t)
        # svc_iam approves nothing (I10): no A in its ceiling, no zones
        self.assertEqual(self.policy.services["svc_iam"]["ceiling"],
                         {"iam_policy": ["R", "C", "U"], "iam_users": ["R"], "mqtt_explorer": ["R", "C", "U"],
                          "audit_histories": ["R", "C"]})
        self.assertNotIn(("svc_iam", "iam_policy"), invariants.SERVICE_APPROVERS)

    def test_dual_control(self):
        self.assertEqual(routes.dual_control(self.policy),
                         {"iam_policy": {"approver_roles": ["qa"], "maker_roles": ["admin"]},
                          "iam_users": {"approver_roles": ["qa"], "maker_roles": ["admin"]}})
        d = copy.deepcopy(self.policy.data)
        d["roles"]["qp"]["includes"] = list(d["roles"]["qp"].get("includes") or []) + ["qa"]
        dc = routes.dual_control(model.Policy(d))
        self.assertIn("qp", dc["iam_policy"]["approver_roles"])        # a composite holding A counts
        self.assertIn("dual_control", routes.compile(self.policy))

    def test_exports(self):
        ex = routes.export_table(self.policy)
        self.assertIn("iam_policy.skeleton", ex["groups"]["iam_policy"])
        self.assertIn("iam_policy.version_diff", ex["groups"]["iam_policy"])
        self.assertNotIn("iam_policy.approval_evidence", ex["groups"]["iam_policy"])
        self.assertNotIn("iam_policy.role", ex["groups"]["iam_policy"])

    def test_policy_page(self):
        self.assertEqual({r: c for r, c in self.policy.matrix["policy_page"].items()},
                         {"qa": ["R"], "qp": ["R"], "admin": ["R"], "auditor": ["R"]})
        self.assertEqual(self.policy.hosts["POLICY_DOMAIN"]["serves"], ["iam"])
        self.assertEqual(sorted(proxies.admitted(self.policy, "POLICY_DOMAIN")), ["admin", "auditor", "qa", "qp"])

    def test_access_changed_since(self):
        sql = self.read_access()
        i = sql.index("FUNCTION iam._changed_since(")
        body = sql[i:sql.index("$$;", i)]
        self.assertIn("LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog", body)
        for k in ("'deactivate'", "'activate'", "'role_change'", "'person_id'", "'grant'",
                  "d.subject_person = p_person", "d.new_person_id = p_person", "d.checked_at >="):
            self.assertIn(k, body)
        self.assertIn("REVOKE ALL ON FUNCTION iam._changed_since(text, text, double precision) FROM PUBLIC;", sql)
        self.assertLess(sql.index("CREATE TABLE IF NOT EXISTS iam.account_decision"), i)
        lib = open(os.path.join(REPO, "apps/database/lib-db-apply.sh")).read()
        flag = lib[lib.index("dba_iam_flag() {"):]
        self.assertLess(flag.index("no iam.confirm_decision"), flag.index("no iam._changed_since"))  # PREV27's text first

    def test_entries_digest_jsonb_text(self):
        from compiler import source
        self.assertEqual(source.pg_jsonb_text({"bb": 1, "a": None, "ab": [True, "x"], "é": "ü"}),
                         '{"a": null, "ab": [true, "x"], "bb": 1, "é": "ü"}')
        self.assertEqual(source.pg_jsonb_text("q\"b\\n\n\t\x01"), '"q\\"b\\\\n\\n\\t\\u0001"')
        rows = [{"role": "qa", "group_code": "portal", "level": "R", "constraint_name": None},
                {"role": "admin", "group_code": "portal", "level": "R", "constraint_name": None}]
        w = [{"id": "W1", "invariant": "I11", "subject": "engineer", "group": "flows", "target": "measurements",
              "levels": ["C"], "objects": ["medcea.measurement"], "review_by": "2027-10-27",
              "rationale": "é", "controls": "c"}]
        doc = ('{"kind": "bootstrap", "roles": ["admin", "qa"], "groups": ["portal"], "entries": '
               '[["admin", "portal", "R", null], ["qa", "portal", "R", null]], "waivers": [{"id": "W1", '
               '"levels": ["C"], "target": "measurements", "objects": ["medcea.measurement"], "subject": "engineer", '
               '"controls": "c", "invariant": "I11", "rationale": "é", "review_by": "2027-10-27", '
               '"group_code": "flows"}]}')
        self.assertEqual(source.entries_digest("bootstrap", ["portal"], ["qa", "admin"], rows, w),
                         hashlib.sha256(doc.encode()).hexdigest())
        # one row per level, byte order (upper case before lower case)
        self.assertEqual(source.entries_digest("change", None, None, list(reversed(rows)), []),
                         source.entries_digest("change", None, None, rows, []))
        self.assertRegex(source.policy_entries_digest(self.policy.data), r"^[0-9a-f]{64}$")
        # the SQL side orders and keys the same way
        ed = self.c[self.c.index("FUNCTION iam_policy.entries_digest("):]
        ed = ed[:ed.index("$$;")]
        for k in ("'kind', v.kind", "'groups'", "'roles'", "'entries'", "'waivers'", "COLLATE \"C\"",
                  "pg_catalog.to_jsonb(w) - 'version'", "ORDER BY w.id COLLATE \"C\""):
            self.assertIn(k, ed)


class Phase42aTest(unittest.TestCase):
    """IAM Phase 4, slice 4.2a (design §14.4.2, §14.4.7): the 008c edits (_system_as, the
    actors of _record/_accept_skeleton/_sync_skeleton, the filter), pre_request's only_rpc
    block in both modes, and the route table's unhashed labels."""

    @classmethod
    def setUpClass(cls):
        cls.policy = model.load_defaults()
        with open(os.path.join(REPO, "apps/database/medcea_db_migrations.sql")) as f:
            mig = f.read()
        cls.c = mig[mig.index("Migration 008c"):mig.index("Migration 009")]
        with open(os.path.join(REPO, "apps/database/medcea_db_migrations_down_008c.sql")) as f:
            cls.down_c = f.read()

    def body(self, sig):
        i = self.c.index(f"CREATE OR REPLACE FUNCTION iam_policy.{sig}")
        return self.c[i:self.c.index("END $$;", i)]

    def test_pre_request_only_rpc_in_both_modes(self):
        fn = grants.compiled_functions(self.policy)
        pre = fn[fn.index("FUNCTION medcea_auth.pre_request()"):fn.index("$pre$;")]
        claims = pre.index("c := nullif(pg_catalog.current_setting('request.jwt.claims', true), '')::jsonb;")
        block = pre.index("may only call")
        mode = pre.index("IF pg_catalog.current_setting('medcea.iam_db_roles', true) IS DISTINCT FROM 'true' THEN")
        self.assertLess(claims, block)
        self.assertLess(block, mode)
        self.assertEqual(pre.count("request.jwt.claims"), 1)
        self.assertIn("IF c IS NOT NULL AND (c ->> 'azp') = ANY (ARRAY['policy']", pre)
        # without an only_rpc client the mode check comes straight after reading the claims
        d = copy.deepcopy(self.policy.data)
        del d["network"]["clients"]["iam-approvals"]
        d["network"]["pods"]["config-api"]["ingress"][0]["from"].remove("client:iam-approvals")
        fn2 = grants.compiled_functions(model.Policy(d))
        self.assertIn("::jsonb;\n    IF pg_catalog.current_setting('medcea.iam_db_roles', true)", fn2)

    def test_system_as(self):
        sa = self.body("_system_as(p_allowed text[])")
        self.assertNotIn("SECURITY DEFINER", sa[:sa.index("AS $$")])
        self.assertIn("PERFORM medcea_auth._set_internal_actor(p_allowed[1]);", sa)
        self.assertIn("a.sub = ANY (p_allowed)", sa)
        self.assertIn("ERRCODE = '42501'", sa)
        self.assertIn("PERFORM iam_policy._system_as(ARRAY['system:apply']);", self.body("_system()"))
        # in the YAML (owner only) and in the down file
        fns = {f["function"]: f for f in self.policy.data["infrastructure_functions"]}
        self.assertEqual(fns["iam_policy._system_as(text[])"]["execute"], [])
        self.assertIn("iam_policy._system_as(text[])", self.down_c)
        self.assertNotIn("iam_policy._system_as", grants.NOT_BUILT)

    def test_who_may_act(self):
        both = "ARRAY['system:apply', 'system:deploy']"
        for sig in ("_accept_skeleton(p_digest text", "_sync_skeleton(p_body jsonb"):
            b = self.body(sig)
            self.assertIn(f"PERFORM iam_policy._system_as({both});", b)
            self.assertNotIn("iam_policy._system();", b)
        for sig in ("_build_version(", "_mark_applied(", "_mark_reverted(", "_withdraw_open(", "_propose_skeleton("):
            b = self.body(sig)
            self.assertIn("PERFORM iam_policy._system();", b, sig)
            self.assertNotIn("system:deploy", b, sig)
        # _record: system:deploy only for the three deploy events
        rec = self.body("_record(p_event text")
        apply_only = rec.index("IF p_event IN ('applied', 'partial_apply', 'bootstrap_applied', 'apply_deferred') THEN")
        deploy = rec.index("ELSIF p_event IN ('break_glass_seen', 'break_glass_ended', 'account_seeded') THEN")
        self.assertLess(apply_only, deploy)
        self.assertEqual(rec[apply_only:deploy].count("_system_as(ARRAY['system:apply'])"), 1)
        self.assertIn(f"_system_as({both})", rec[deploy:rec.index("ELSE", deploy)])
        self.assertEqual(rec.count("system:deploy"), 1)
        self.assertIn("'source' = 'file'", rec)
        self.assertIn("WHERE x.status = 'applied'", rec)          # the version filled in
        self.assertIn("RETURN v_id;", rec)                       # idempotent per content

    def test_accept_records_what_it_replaced(self):
        b = self.body("_accept_skeleton(p_digest text")
        self.assertIn("'from', v_from", b)
        self.assertLess(b.index("SELECT s.digest INTO v_from"), b.index("INSERT INTO iam_policy.skeleton"))
        self.assertLess(b.index("SELECT s.digest INTO v_from"), b.index("UPDATE iam_policy.skeleton"))

    def test_account_seeded_fact_id_twin(self):
        # the SQL hashes jsonb_build_object(fact, username, sub, role, person_id)::text; Python
        # builds the same text with source.pg_jsonb_text (design §14.4.2 item 3)
        from compiler import source
        rec = self.body("_record(p_event text")
        self.assertIn("'fact', p_payload -> 'fact', 'username', p_payload -> 'username', 'sub', p_payload -> 'sub',\n"
                      "                     'role', p_payload -> 'role', 'person_id', p_payload -> 'person_id')::text", rec)
        fact = {"fact": "observed", "username": "qa1", "sub": "33333333-3333-4333-8333-333333333333",
                "role": "qa", "person_id": "p-1"}
        text = source.pg_jsonb_text(fact)
        self.assertEqual(text, '{"sub": "33333333-3333-4333-8333-333333333333", "fact": "observed", "role": "qa", '
                               '"username": "qa1", "person_id": "p-1"}')
        self.assertRegex(hashlib.sha256(text.encode()).hexdigest(), r"^[0-9a-f]{64}$")

    def test_filter(self):
        flt = self.body("append_history(p_event text, p_payload jsonb, p_reason text)\nRETURNS bigint LANGUAGE plpgsql "
                        "SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$\nDECLARE\n    e text")
        self.assertIn("e text := pg_catalog.lower(p_event);", flt)
        self.assertIn("'break_glass_ended'", flt)
        for pre in ("waiver", "skeleton", "break\\_glass", "apply", "bootstrap", "policy"):
            self.assertIn(f"e LIKE '{pre}\\_%'", flt)
        self.assertNotIn("p_event LIKE", flt)
        self.assertIn("session_user = 'iam_svc' AND p_event IS DISTINCT FROM 'mqtt_credential_issued'", flt)
        self.assertLess(flt.index("is a policy version event"), flt.index("iam_svc writes only"))
        self.assertIn("p_payload - 'version'", flt)
        # every event apply.sh or a deploy records is refused through the public function
        for ev in ("applied", "partial_apply", "bootstrap_applied", "apply_deferred", "break_glass_seen",
                   "break_glass_ended", "account_seeded", "apply_started", "apply_reverted"):
            self.assertIn(f"'{ev}'", flt)
        # account_decision_withdrawn (units.sql) is no prefix match
        self.assertFalse(re.match(r"^(waiver|skeleton|break_glass|apply|bootstrap|policy)_", "account_decision_withdrawn"))

    def test_routes_unhashed(self):
        self.assertEqual(routes.UNHASHED, ("source", "applied_version"))
        a = routes.compile(self.policy)
        b = routes.compile(self.policy, "version-1", 1)
        self.assertEqual(a["digest"], b["digest"])
        self.assertEqual((a["source"], a["applied_version"]), ("defaults.yaml", None))
        self.assertEqual((b["source"], b["applied_version"]), ("version-1", 1))
        self.assertEqual({k: v for k, v in a.items() if k not in routes.UNHASHED},
                         {k: v for k, v in b.items() if k not in routes.UNHASHED})
        # content still moves it
        d = copy.deepcopy(self.policy.data)
        d["policy_version"] = "other"
        self.assertNotEqual(routes.compile(model.Policy(d))["digest"], a["digest"])
        # role_widening()'s comment carries the same digest whatever the label
        self.assertEqual(grants.policy_digest(self.policy, "break-glass:x"), a["digest"])


class ExplainCellTest(unittest.TestCase):
    """explain.cell (IAM 4.3, the Policy UI's "See more"): what a cell gives is exactly the
    reach it adds (ExplainParity), and the Policy UI's compiler fits its ConfigMap."""

    @classmethod
    def setUpClass(cls):
        cls.p = model.load_defaults()

    def test_parity_with_reach(self):
        from compiler import explain
        for g in self.p.groups:
            for r in self.p.roles:
                d = explain.cell(self.p, self.p, r, g)
                full = {tuple(tuple(x) if isinstance(x, list) else x for x in t) for t in
                        [list(t) for t in explain.reach(self.p, r)]}
                gives = {tuple(tuple(x) if isinstance(x, list) else x for x in t) for t in d["gives"]}
                self.assertLessEqual(gives, full, (r, g))
                if not self.p.cell(g, r):
                    self.assertEqual(gives, set(), (r, g))
                self.assertTrue(d["changed"]["same"], (r, g))
                self.assertEqual(d["changed"]["adds"] + d["changed"]["removes"], [], (r, g))

    def test_known_cells(self):
        from compiler import explain
        d = explain.cell(self.p, None, "qa", "iam_policy")
        self.assertEqual(d["levels"], ["A", "R"])
        self.assertEqual(d["constraints"]["A"]["name"], "not_own_author")
        self.assertIn(["db", "medcea.confirm_policy(integer,text,text)", "EXECUTE", None], d["gives"])
        self.assertIsNone(d["changed"])
        d = explain.cell(self.p, None, "operator", "runs")
        self.assertEqual(d["constraints"]["R"]["name"], "own_unit")
        with self.assertRaises(KeyError):
            explain.cell(self.p, None, "nobody", "runs")

    def test_a_superset_cell(self):
        """Stage C on the factory policy: a builder's cell gives the host, its levels and
        Alpha; a viewer's Gamma; a role without a cell nothing. Against the skeleton version
        alone (no cell applied) the change version's cell adds exactly what it gives."""
        from compiler import explain
        p = model.Policy(add_superset(copy.deepcopy(self.p.data)))
        d = copy.deepcopy(p.data)
        del d["matrix"]["analysis"]
        skel = model.Policy(d)
        eng = explain.cell(p, skel, "engineer", "analysis")
        self.assertEqual(eng["levels"], ["C", "R", "U"])
        self.assertIn(["tool", "analysis", "Alpha", None], eng["gives"])
        self.assertIn(["host", "SUPERSET_DOMAIN", None], eng["gives"])
        self.assertNotIn(["tool", "analysis", "Gamma", None], eng["gives"])
        self.assertFalse(eng["changed"]["same"])
        self.assertEqual(sorted(map(str, eng["changed"]["adds"])), sorted(map(str, eng["gives"])))
        self.assertEqual(eng["changed"]["removes"], [])
        qp = explain.cell(p, None, "qp", "analysis")
        self.assertEqual(qp["levels"], ["R"])
        self.assertIn(["tool", "analysis", "Gamma", None], qp["gives"])
        self.assertNotIn(["tool", "analysis", "Alpha", None], qp["gives"])
        for r in ("qa", "auditor", "admin", "operator", "maintenance"):   # D8
            self.assertEqual(explain.cell(p, None, r, "analysis")["gives"], [], r)

    def test_compiler_configmap_size(self):
        sys.path.insert(0, os.path.join(REPO, "apps", "iam"))
        import compiler_cm
        cm, sha, items = compiler_cm.build(os.path.join(REPO, "apps", "iam"), "medcea")
        self.assertLess(len(json.dumps(cm).encode()), compiler_cm.LIMIT)
        self.assertIn({"key": "policy__defaults.yaml", "path": "policy/defaults.yaml"}, items)
        self.assertIn({"key": "compiler____init__.py", "path": "compiler/__init__.py"}, items)
        self.assertEqual(cm["metadata"]["annotations"]["medcea/compiler-sha256"], sha)


class ExplainDiffTest(unittest.TestCase):
    """explain.diff / diff_document (IAM 4.4, design §14.7.3): the bytes qa approves are
    deterministic, carry no compiler digest, commit or time, and survive jsonb."""

    @classmethod
    def setUpClass(cls):
        from compiler import explain
        cls.explain = explain
        cls.p = model.load_defaults()
        cls.empty = explain.diff(cls.p, cls.p)
        # a new cell: the first (group, role) in byte order with no cell, given R
        cls.cell_key = next((g, r) for g in sorted(cls.p.groups) for r in sorted(cls.p.roles)
                            if not cls.p.cell(g, r) and "R" in cls.p.levels)
        d = copy.deepcopy(cls.p.data)
        d["matrix"].setdefault(cls.cell_key[0], {})[cls.cell_key[1]] = ["R"]
        cls.p_cell = model.Policy(d)
        cls.d_cell = explain.diff(cls.p, cls.p_cell)
        # operator's own_unit on runs dropped: the lost constraint is an added tuple
        d = copy.deepcopy(cls.p.data)
        c = d["matrix"]["runs"]["operator"]
        d["matrix"]["runs"]["operator"] = list(c["levels"])
        cls.p_free = model.Policy(d)
        cls.d_free = explain.diff(cls.p, cls.p_free)

    def test_equal_policies_give_an_empty_diff(self):
        self.assertEqual(self.empty, {"cells": [], "waivers": {"added": [], "removed": []}, "roles": {},
                                      "system": {"added": [], "removed": []}})

    def test_a_cell_change_shows_in_cells_and_roles(self):
        g, r = self.cell_key
        self.assertEqual(self.d_cell["cells"], [{"group": g, "role": r, "before": {}, "after": {"R": None}}])
        self.assertIn(["level", g, "R", None], self.d_cell["roles"][r]["added"])
        self.assertEqual(self.d_cell["roles"][r]["removed"], [])
        # every role whose reach moved, and only those
        for role in self.p.roles:
            moved = self.explain.reach(self.p, role) != self.explain.reach(self.p_cell, role)
            self.assertEqual(role in self.d_cell["roles"], moved, role)
        # the reverse diff swaps added and removed
        back = self.explain.diff(self.p_cell, self.p)
        self.assertEqual(back["roles"][r], {"added": [], "removed": self.d_cell["roles"][r]["added"]})
        self.assertEqual(back["cells"][0]["before"], {"R": None})

    def test_a_lost_constraint_shows_as_added(self):
        cell = self.d_free["cells"]
        self.assertEqual([(c["group"], c["role"]) for c in cell], [("runs", "operator")])
        self.assertEqual(cell[0]["before"]["R"], "own_unit")
        self.assertIsNone(cell[0]["after"]["R"])
        self.assertIn(["level", "runs", "R", None], self.d_free["roles"]["operator"]["added"])
        self.assertIn(["level", "runs", "R", ["own_unit"]], self.d_free["roles"]["operator"]["removed"])

    def test_waivers_by_id(self):
        d = copy.deepcopy(self.p.data)
        w = dict(copy.deepcopy(d["waivers"][0]), id="W-test", rationale="x")
        d["waivers"] = list(d.get("waivers") or []) + [w]
        p2 = model.Policy(d)
        got = self.explain.diff(self.p, p2)["waivers"]
        from compiler import source
        self.assertEqual(got, {"added": [source.waiver_row(w)], "removed": []})
        d3 = copy.deepcopy(d)
        d3["waivers"][-1]["rationale"] = "changed"
        got = self.explain.diff(p2, model.Policy(d3))["waivers"]
        self.assertEqual([x["id"] for x in got["added"]], ["W-test"])
        self.assertEqual([x["id"] for x in got["removed"]], ["W-test"])

    def test_determinism(self):
        p_again = model.load_defaults()
        d = copy.deepcopy(p_again.data)
        d["matrix"].setdefault(self.cell_key[0], {})[self.cell_key[1]] = ["R"]
        a = self.explain.diff_document("change", 2, 1, "0" * 64, self.p, self.p_cell)
        b = self.explain.diff_document("change", 2, 1, "0" * 64, p_again, model.Policy(d))
        self.assertEqual(self.explain.diff_bytes(a), self.explain.diff_bytes(b))
        self.assertEqual(self.explain.diff_digest(a), hashlib.sha256(self.explain.diff_bytes(a)).hexdigest())
        self.assertRegex(self.explain.diff_digest(a), r"^[0-9a-f]{64}$")
        # the document is its own JSON round trip (tuples are lists)
        self.assertEqual(json.loads(self.explain.diff_bytes(a)), a)

    def test_document_fields(self):
        from compiler import source
        doc = self.explain.diff_document("change", 2, 1, "a" * 64, self.p, self.p_cell)
        self.assertEqual(set(doc), {"schema", "kind", "version", "against", "entries_digest", "skeleton",
                                    "cells", "waivers", "roles", "system"})
        self.assertEqual((doc["schema"], doc["kind"], doc["version"], doc["against"], doc["skeleton"]),
                         (1, "change", 2, 1, None))
        self.assertEqual(self.explain.diff_bytes(doc), source.canonical(doc))
        text = self.explain.diff_bytes(doc).decode()
        for word in ("compiler", "commit", "written_at", "label", "source"):
            self.assertNotIn(f'"{word}', text, word)
        sk = self.explain.diff_document("skeleton", 3, 1, "a" * 64, self.p, self.p,
                                        skeleton={"from": "b" * 64, "to": "c" * 64,
                                                  "sections": [("section", "network.ingress_namespace")]})
        self.assertEqual(sk["skeleton"], {"from": "b" * 64, "to": "c" * 64,
                                          "sections": [["section", "network.ingress_namespace"]]})
        with self.assertRaises(ValueError):
            self.explain.diff_document("bootstrap", 1, None, "a" * 64, self.p, self.p)
        with self.assertRaises(ValueError):
            self.explain.diff_document("skeleton", 3, 1, "a" * 64, self.p, self.p)
        with self.assertRaises(ValueError):
            self.explain.diff_document("change", 3, 1, "a" * 64, self.p, self.p, skeleton={"from": "", "to": ""})

    def test_the_keys_the_database_reads(self):
        """approve()/why_not() and health read diff -> 'skeleton' ->> 'from' and
        diff -> 'roles' -> <role> -> 'added' (§14.7.1)."""
        with open(os.path.join(REPO, "apps/database/medcea_db_migrations.sql")) as f:
            sql = f.read()
        self.assertIn("x.diff -> 'skeleton' ->> 'from'", sql)
        self.assertIn("x.diff -> 'roles' -> hr.role_code -> 'added'", sql)
        doc = self.explain.diff_document("skeleton", 3, 1, "a" * 64, self.p, self.p_free,
                                         skeleton={"from": "b" * 64, "to": "c" * 64, "sections": []})
        self.assertEqual(doc["skeleton"]["from"], "b" * 64)
        self.assertIsInstance(doc["roles"]["operator"]["added"], list)

    def test_jsonb_round_trip(self):
        """Python canonical -> jsonb text -> json.loads -> canonical: the same sha256 (the
        stored diff of a skeleton version is re-serialised before it is served)."""
        from compiler import source
        d = copy.deepcopy(self.p_cell.data)
        d["waivers"] = list(d.get("waivers") or []) + [
            dict(copy.deepcopy(d["waivers"][0]), id="W-é", rationale="a → b — café", controls="\"quoted\" \\ tab\t")]
        doc = self.explain.diff_document("skeleton", 4, 1, "a" * 64, self.p, model.Policy(d),
                                         skeleton={"from": "b" * 64, "to": "c" * 64, "sections": []})
        raw = self.explain.diff_bytes(doc)
        self.assertIn("→ b — café".encode(), raw)
        stored = source.pg_jsonb_text(json.loads(raw))
        self.assertNotEqual(stored.encode(), raw)          # jsonb reorders and spaces
        again = source.canonical(json.loads(stored))
        self.assertEqual(hashlib.sha256(again).hexdigest(), self.explain.diff_digest(doc))


class ExplainParity(unittest.TestCase):
    """explain.who_can (IAM 4.4, design §14.7.5) names exactly the roles the compiled
    artefacts admit: the route table, grants.document(), proxies.admitted(), mqtt.rows(),
    and every tuple it shows is in reach() / system_reach(). explain.cell keeps its own
    check (ExplainCellTest.test_parity_with_reach)."""

    @classmethod
    def setUpClass(cls):
        from compiler import explain
        cls.explain = explain
        cls.p = model.load_defaults()
        cls.cache = {}
        cls.seen = []

    def who(self, obj, level=None):
        out = self.explain.who_can(self.p, obj, level, cache=self.cache)
        self.seen.append(out)
        return out

    def test_routes(self):
        doc = routes.compile(self.p)
        for svc, sd in doc["services"].items():
            for route, rd in sd["routes"].items():
                got = {x["role"] for x in self.who(f"{svc} {route}")["roles"]}
                self.assertEqual(got, set(rd["roles"]), (svc, route))
        for svc, rs in doc["public"].items():
            for route in rs:
                self.assertIn(["public", svc, route], self.who(f"{svc} {route}")["services"], (svc, route))

    def test_db_objects(self):
        people = {v: k for k, v in grants.people(self.p).items()}
        want = {}
        for grantee, _kind, obj, priv in grants.document(self.p)["privileges"]:
            if grantee in people:
                want.setdefault(obj, {}).setdefault(priv, set()).add(people[grantee])
        self.assertTrue(want)
        for obj, privs in want.items():
            w = self.who(obj)
            for priv, roles in privs.items():
                got = {x["role"] for x in w["roles"] if any(t[0] == "db" and t[2] == priv for t in x["tuples"])}
                self.assertEqual(got, roles, (obj, priv))

    def test_function_signatures_as_written(self):
        # a member's signature as the YAML writes it finds the normalised grant
        w = self.who("medcea.propose_commissioning(int, boolean, text)")
        self.assertEqual(w["object"], "medcea.propose_commissioning(integer,boolean,text)")
        self.assertIn("master_data", w["groups"])
        self.assertTrue(w["roles"])

    def test_hosts(self):
        for host in self.p.hosts:
            got = {x["role"] for x in self.who(host)["roles"]}
            self.assertEqual(got, set(proxies.admitted(self.p, host)), host)

    def test_mqtt_topics(self):
        topics = sorted({m["topic"] for gd in self.p.groups.values() for m in gd.get("members") or []
                         if m.get("type") == "mqtt"})
        self.assertTrue(topics)
        for topic in topics:
            stripped = topic.split("/", 1)[1]
            want = {r for r in mqtt.admitted(self.p) if any(x["topic"] == stripped for x in mqtt.rows(self.p, r))}
            got = {x["role"] for x in self.who(topic)["roles"]}
            self.assertEqual(got, want, topic)

    def test_groups_tools_and_level(self):
        w = self.who("group:iam_policy")
        self.assertEqual(w["groups"], ["iam_policy"])
        holders = {r for r in self.p.roles if any(g == "iam_policy" for g, _ in self.p.holds(r))}
        self.assertEqual({x["role"] for x in w["roles"]}, holders)
        qa = next(x for x in w["roles"] if x["role"] == "qa")
        self.assertEqual(qa["levels"]["A"], "not_own_author")
        self.assertEqual({x["role"] for x in self.who("group:iam_policy", "A")["roles"]},
                         {r for r in holders if ("iam_policy", "A") in self.p.holds(r)})
        g = self.who("grafana")
        self.assertEqual(g["groups"], ["dashboards"])
        self.assertTrue(all(t[0] == "tool" for x in g["roles"] for t in x["tuples"]))
        with self.assertRaises(KeyError):
            self.explain.who_can(self.p, "group:nope", cache=self.cache)

    def test_index(self):
        idx = self.explain.who_can_index(self.p)["objects"]
        names = [o["name"] for o in idx]
        self.assertEqual(names, sorted(names, key=lambda n: n.encode()))
        self.assertEqual(len(names), len(set(names)))
        by = {o["name"]: o for o in idx}
        self.assertEqual(by["grafana"]["type"], "tool")
        self.assertIn("PORTAL_DOMAIN", by)
        # every index name is answered with the same groups
        for o in idx[:40]:
            self.assertEqual(self.who(o["name"])["groups"], o["groups"], o["name"])

    def test_zz_every_tuple_is_reach(self):
        if not self.seen:
            self.who("medcea.cea_unit")
        reach = self.cache["reach"]
        system = {self.explain.source.canonical(list(t)) for t in self.cache["system"]}
        for w in self.seen:
            for x in w["roles"]:
                mine = {self.explain.source.canonical(list(t)) for t in reach[x["role"]]}
                for t in x["tuples"]:
                    self.assertIn(self.explain.source.canonical(t), mine, (w["object"], x["role"], t))
            for t in w["services"]:
                self.assertIn(self.explain.source.canonical(t), system, (w["object"], t))


class BreakGlassPredicateParity(unittest.TestCase):
    """approve()'s and why_not()'s break-glass refusal (IAM 4.4, §14.7.1) use
    policy_db_state's break_glass_open predicate (infra/lib-policy-source.sh), inline; and
    the own-widening closure is the same CTE in both functions."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(REPO, "apps/database/medcea_db_migrations.sql")) as f:
            sql = f.read()
        with open(os.path.join(REPO, "infra/lib-policy-source.sh")) as f:
            lib = f.read()

        def body(name):
            start = sql.index(f"CREATE OR REPLACE FUNCTION iam_policy.{name}(")
            return sql[start:sql.index("$$;", start)]
        cls.approve, cls.why_not = body("approve"), body("why_not")
        start = lib.index("'break_glass_open'")
        cls.lib = lib[start:lib.index("'system_functions'", start)]

    @staticmethod
    def facts(text):
        """The events, payload keys and source literal a predicate names."""
        return (frozenset(re.findall(r"\b[a-z]\.event = '([a-z_]+)'", text)),
                frozenset(re.findall(r"payload ->>? '([a-z_]+)'", text)) - {"reason"},
                frozenset(re.findall(r"->> 'source' = '([a-z]+)'", text)))

    @staticmethod
    def between(text, start, end):
        i = text.index(start)
        return text[i:text.index(end, i)]

    def test_same_events_and_keys(self):
        want = self.facts(self.lib)
        self.assertEqual(want, (frozenset({"break_glass_seen", "break_glass_ended"}),
                                frozenset({"components", "source", "since_event", "component"}),
                                frozenset({"file"})))
        for name, text in (("approve", self.between(self.approve, "-- a policy break-glass", "RAISE EXCEPTION")),
                           ("why_not", self.between(self.why_not, "bg := EXISTS", "IF v.kind"))):
            self.assertEqual(self.facts(text), want, name)
        self.assertIn("a policy break-glass is open (event %)", self.approve)
        self.assertIn("'break_glass_open'", self.why_not)

    def test_own_widening_closure_is_one_cte(self):
        def cte(text):
            start = text.index("WITH RECURSIVE held(role_code) AS (")
            end = text.index("'added') > 0", start) + len("'added') > 0")
            block = text[start:end]
            head = block[:block.index("SELECT", block.index("unnest(r.includes)"))]
            conds = re.findall(r"pg_catalog\.jsonb_\w+\(x\.diff -> 'roles' -> hr\.role_code -> 'added'\)[^\n]*", block)
            return " ".join(head.split()), conds
        a, w = cte(self.approve), cte(self.why_not)
        self.assertEqual(a, w)
        self.assertIn("iam_policy.role r ON r.code = hr.role_code", a[0])
        self.assertEqual(len(a[1]), 2)
        self.assertIn("'own_widening'", self.why_not)
        self.assertIn("widens role %, which you hold", self.approve)


class ApplyEventSetParity(unittest.TestCase):
    """IAM 4.5 (design §14.8.3): new_draft's S-D4 guard reads the applied version's latest
    apply event over the set policy_db_state's last_apply_event uses, so a seed fact or a
    skeleton accept filed under the applied version cannot mask an unfinished apply."""

    EVENTS = re.compile(r"h\.event IN \(([^)]*)\)")

    @staticmethod
    def events(text):
        return frozenset(re.findall(r"'([a-z_]+)'", text))

    def test_one_set(self):
        with open(os.path.join(REPO, "apps/database/medcea_db_migrations.sql")) as f:
            sql = f.read()
        with open(os.path.join(REPO, "infra/lib-policy-source.sh")) as f:
            lib = f.read()
        i = sql.index("CREATE OR REPLACE FUNCTION iam_policy.new_draft(")
        body = sql[i:sql.index("$$;", i)]
        guard = body[:body.index("IF last_ev IN ('apply_started', 'partial_apply')")]
        guard = guard[guard.rindex("SELECT h.event INTO last_ev"):]
        j = lib.index("'last_apply_event'")
        state = lib[j:lib.index("LIMIT 1", j)]
        a, b = self.EVENTS.findall(guard), self.EVENTS.findall(state)
        self.assertEqual((len(a), len(b)), (1, 1), (guard, state))
        want = frozenset({"apply_started", "applied", "bootstrap_applied", "apply_reverted", "partial_apply",
                          "apply_deferred"})
        self.assertEqual(self.events(a[0]), want)
        self.assertEqual(self.events(b[0]), want)
        self.assertNotIn("status_changed", guard)
        self.assertIn("IF last_ev IN ('apply_started', 'partial_apply') THEN", body)


class RollbackBoundTest(unittest.TestCase):
    """apply.sh --rollback-to's bound (design §14.8.7 step 5, OA-c): version K's rows under
    today's skeleton reach nothing they did not reach under the skeleton K was approved
    under (explain.rollback_bound, explain.bound_skeleton)."""

    @classmethod
    def setUpClass(cls):
        from compiler import explain, source
        cls.explain, cls.source = explain, source
        cls.f = model.load_defaults().data
        cls.rows = source.entries_and_waivers(cls.f)

    @staticmethod
    def jsonb(obj):
        """obj as psql returns a jsonb value: every dict's keys by length, then bytes."""
        if isinstance(obj, dict):
            return {k: RollbackBoundTest.jsonb(obj[k]) for k in sorted(obj, key=lambda k: (len(k.encode()), k.encode()))}
        if isinstance(obj, list):
            return [RollbackBoundTest.jsonb(x) for x in obj]
        return obj

    def narrower(self):
        k = copy.deepcopy(self.f)
        api = next(m for m in k["resource_groups"]["portal"]["members"] if m["type"] == "api")
        api["routes"].pop("GET /_account/api/me")
        return k

    def test_a_skeleton_that_widens_k_is_refused(self):
        b = self.explain.rollback_bound(self.f, self.narrower(), self.rows)
        self.assertIn("qa", b["added"])
        self.assertTrue(any(t[0] == "route" and t[2] == "GET /_account/api/me" for t in b["added"]["qa"]))
        self.assertEqual(b["dropped"], {"today": 0, "k": 0})
        msg = self.explain.rollback_refusal(4, b)
        self.assertTrue(msg.startswith("version 4 under today's skeleton grants more than was approved ("), msg)
        self.assertIn("admin: route access-profile GET /_account/api/me | auditor: ", msg)
        self.assertIn(f"| {len(b['added']) - 3} more role(s)): ", msg)
        self.assertTrue(msg.endswith("draft from version 4 in the Policy UI (Changes → New draft from version 4) "
                                     "and have qa approve it"), msg)
        # the other way round (today narrower than K's) holds
        b = self.explain.rollback_bound(self.narrower(), self.f, self.rows)
        self.assertEqual(b["added"], {})
        self.assertIsNone(self.explain.rollback_refusal(4, b))
        self.assertEqual(self.explain.rollback_bound(self.f, self.f, self.rows)["added"], {})

    def test_rows_naming_a_retired_group_are_dropped(self):
        today = copy.deepcopy(self.f)
        del today["resource_groups"]["portal"]
        n = sum(len(self.source._cell_levels(c)) for c in self.f["matrix"]["portal"].values())
        b = self.explain.rollback_bound(today, self.f, self.rows)
        self.assertEqual(b["added"], {})
        self.assertEqual(b["dropped"], {"today": n, "k": 0})

    def test_jsonb_body_reordered_reaches_as_its_yaml(self):
        k = self.narrower()
        digest = self.source.skeleton_digest(k)
        body = self.jsonb(json.loads(json.dumps(self.source.skeleton(k))))
        self.assertNotEqual(list(body["levels"]), list(k["levels"]))      # jsonb sorted them
        skel_j, how = self.explain.bound_skeleton(digest, k_yaml=None, k_body=body, ref=self.f)
        self.assertEqual(how, "jsonb")
        self.assertEqual(list(skel_j["levels"]), list(k["levels"]))      # the git order back
        skel_y, how = self.explain.bound_skeleton(digest, k_yaml=k, k_body=body, ref=self.f)
        self.assertEqual(how, "yaml")
        p_j = model.Policy(self.source.compose(skel_j, self.rows, drop_unknown=True))
        p_y = model.Policy(self.source.compose(skel_y, self.rows, drop_unknown=True))
        from compiler import explain
        for r in sorted(self.f["roles"]):
            self.assertEqual(explain.reach(p_j, r), explain.reach(p_y, r), r)
        self.assertEqual(self.explain.rollback_bound(self.f, skel_j, self.rows),
                         self.explain.rollback_bound(self.f, skel_y, self.rows))
        # a YAML of another skeleton falls back to the body; neither carrying the digest raises
        self.assertEqual(self.explain.bound_skeleton(digest, k_yaml=self.f, k_body=body, ref=self.f)[1], "jsonb")
        with self.assertRaises(self.source.SourceError):
            self.explain.bound_skeleton(digest, k_yaml=self.f, k_body=self.source.skeleton(self.f), ref=self.f)


def _rsa_key(bits=2048, seed=45):
    """(n, e, d) of a deterministic RSA key, pure Python (no `cryptography` needed)."""
    import random
    rnd = random.Random(seed)
    small = [q for q in range(3, 2000, 2) if all(q % x for x in range(3, int(q ** 0.5) + 1, 2))]

    def probable_prime(c):
        d, r = c - 1, 0
        while d % 2 == 0:
            d, r = d // 2, r + 1
        for _ in range(24):
            x = pow(rnd.randrange(2, c - 2), d, c)
            if x in (1, c - 1):
                continue
            for _ in range(r - 1):
                x = pow(x, 2, c)
                if x == c - 1:
                    break
            else:
                return False
        return True

    def prime(b):
        while True:
            c = rnd.getrandbits(b) | (1 << (b - 1)) | (1 << (b - 2)) | 1
            if all(c % q for q in small) and probable_prime(c):
                return c
    e = 65537
    while True:
        p, q = prime(bits // 2), prime(bits // 2)
        if p != q and (p - 1) % e and (q - 1) % e:
            return p * q, e, pow(e, -1, (p - 1) * (q - 1))


def _b64u(b):
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _sign_rs256(key, header, claims):
    n, _, d = key
    k = (n.bit_length() + 7) // 8
    h = _b64u(json.dumps(header).encode()) + "." + _b64u(json.dumps(claims).encode())
    info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(h.encode()).digest()
    em = b"\x00\x01" + b"\xff" * (k - 3 - len(info)) + b"\x00" + info
    return h + "." + _b64u(pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big"))


class AuditVersionTest(unittest.TestCase):
    """cli.py audit-version --record F (IAM 4.5, design §14.8.10): a recorded change version
    (rows, apply_started, applied with its jwk, the approval and its evidence) recompiles to
    its digests; a changed row is 1; a commit it cannot reproduce is 2; the JWS and claim
    checks of §14.8.5 against the recorded key."""

    ISS = "https://keycloak.medcea/realms/medcea"

    @classmethod
    def setUpClass(cls):
        import subprocess
        from compiler import cli, source
        import apply_check
        cls.cli, cls.source, cls.ac = cli, source, apply_check
        r = subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"], capture_output=True, text=True)
        cls.head = r.stdout.strip() if r.returncode == 0 else None
        if not cls.head:
            return
        cls.f = model.load_defaults().data
        cls.key = _rsa_key()
        cls.artefacts = apply_check.digests_of(apply_check.compile_all(["--defaults"]), cls.head)

    def setUp(self):
        if not self.head:
            self.skipTest("no git")

    def record(self, commit=None, compiler=None, artefacts=None, claims=None, f=None):
        src, f, n = self.source, f or self.f, self.key[0]
        commit = commit or self.head
        ew = src.entries_and_waivers(f)
        rows = {"entries": json.loads(json.dumps(ew["entries"])),
                "waivers": json.loads(json.dumps([src.waiver_row(w) for w in ew["waivers"]]))}
        groups, roles = sorted(f["resource_groups"]), sorted(f["roles"])
        started = {"version": 2, "kind": "change", "previous": 1, "commit": commit,
                   "skeleton_digest": src.skeleton_digest(f), "compiler_digest": compiler or src.compiler_digest()}
        sub, person = "6f1c0a52-8b1e-4c55-9d0f-3c2a1b7e9a10", "p-qa-1"
        c = {"sub": sub, "person_id": person, "jti": "jti-2", "iat": 1793000000, "exp": 1793000300,
             "azp": "policy", "aud": ["medcea-api", "account"], "typ": "Bearer", "iss": self.ISS,
             "groups": ["qa", "auditor", "default-roles-medcea"]}
        c.update(claims or {})
        jws = _sign_rs256(self.key, {"alg": "RS256", "kid": "k1", "typ": "JWT"}, c)
        return {
            "version": {"version": 2, "kind": "change", "status": "applied",
                        "entries_digest": src.entries_digest("change", groups, roles, ew["entries"], ew["waivers"]),
                        "groups": groups, "roles": roles, "based_on": 1, "approved_by_sub": sub,
                        "approved_by_person": person, "approved_at": self.at(40.5),
                        "approved_iat": 1793000000},
            "entries": rows["entries"], "waivers": rows["waivers"],
            "apply_started": started,
            "applied": {"event": "applied", "event_id": 90,
                        "payload": {"version": 2, "git_commit": commit, "artefacts": artefacts or self.artefacts,
                                    "jwk": {"kid": "k1", "kty": "RSA", "n": _b64u(n.to_bytes(256, "big")),
                                            "e": _b64u((65537).to_bytes(3, "big"))}}},
            "approval": {"event": {"event_id": 80, "payload": {
                "version": 2, "source": "token", "role": "qa", "person": person, "sub": sub, "iat": 1793000000,
                "jti": "jti-2", "azp": "policy", "jws_sha256": hashlib.sha256(jws.encode()).hexdigest()}},
                "evidence": {"jws": jws, "claims": c}, "other_approved_jti": ["jti-1"]},
            "previous": {"version": 1, "kind": "bootstrap", "entries": rows["entries"], "waivers": rows["waivers"],
                         "apply_started": dict(started, version=1, kind="bootstrap", previous=None)},
            "audit_findings": [], "chain": {"ok": True}, "issuer": self.ISS}

    @staticmethod
    def at(seconds_after_iat):
        """approved_at as psql's JSON writes a timestamptz, `seconds_after_iat` after the token's iat"""
        import datetime
        return datetime.datetime.fromtimestamp(1793000000 + seconds_after_iat, datetime.timezone.utc).isoformat()

    def audit(self, doc):
        rc, lines = self.cli.audit_version(doc)
        return rc, "\n".join(f"{c} {t}" for c, t in lines)

    def test_a_record_recompiles_to_its_digests(self):
        rc, out = self.audit(self.record())
        self.assertEqual(rc, 0, out)
        self.assertIn("OK approval: the token verifies against the recorded jwk (kid k1)", out)
        self.assertIn("artefact routes:", out)
        self.assertNotIn("FAIL", out)

    def test_a_changed_row_is_a_mismatch(self):
        doc = self.record()
        e = next(x for x in doc["entries"] if x["group_code"] == "master_data" and x["role"] == "engineer"
                 and x["level"] == "U")
        doc["entries"].remove(e)
        rc, out = self.audit(doc)
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL entries digest recomputed from the rows", out)
        self.assertIn("FAIL artefact grants_document", out)
        doc = self.record(artefacts=dict(self.artefacts, routes="0" * 64))
        rc, out = self.audit(doc)
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL artefact routes: recompiled", out)

    def test_an_unreproducible_commit_is_2(self):
        for commit in (self.head + "-dirty", "unknown", "f" * 40):
            rc, out = self.audit(self.record(commit=commit))
            self.assertEqual(rc, 2, (commit, out))
            self.assertIn("CANNOT", out)
        doc = self.record()
        del doc["apply_started"]
        self.assertEqual(self.audit(doc)[0], 2)

    def test_the_approval_checks(self):
        """§14.8.5's checks against the record (cli._claims_problems, which audit_version runs
        before its recompile; one full audit below proves the wiring)."""
        p_prev = model.load_defaults()

        def problems(doc):
            return self.cli._claims_problems(doc, doc["version"], p_prev)
        self.assertEqual(problems(self.record()), [])
        jws = self.record()["approval"]["evidence"]["jws"]
        cases = {
            "signature": lambda d: d["approval"]["evidence"].__setitem__(
                "jws", jws[:-4] + ("AAAA" if not jws.endswith("AAAA") else "BBBB")),
            "replayed jti": lambda d: d["approval"]["other_approved_jti"].append("jti-2"),
            "stored claims": lambda d: d["approval"]["evidence"]["claims"].__setitem__("jti", "other"),
            "other key": lambda d: d["applied"]["payload"]["jwk"].__setitem__("kid", "k2"),
            "no jwk": lambda d: d["applied"]["payload"].pop("jwk"),
            "issuer": lambda d: d.__setitem__("issuer", "https://elsewhere/realms/medcea"),
            "approved late": lambda d: d["version"].__setitem__("approved_at", self.at(331)),
            "approved early": lambda d: d["version"].__setitem__("approved_at", self.at(-31)),
            "person": lambda d: d["version"].__setitem__("approved_by_person", "p-other"),
            "iat": lambda d: d["version"].__setitem__("approved_iat", 1793000001),
            "not a token": lambda d: d["approval"]["event"]["payload"].__setitem__("source", "set_actor"),
            "jws_sha256": lambda d: d["approval"]["event"]["payload"].__setitem__("jws_sha256", "0" * 64),
            "no approval": lambda d: d.__setitem__("approval", None),
        }
        for name, change in cases.items():
            doc = self.record()
            change(doc)
            self.assertNotEqual(problems(doc), [], name)
        for name, claims in (("azp config", {"azp": "config"}), ("two own roles", {"groups": ["qa", "admin"]}),
                             ("not an approver", {"groups": ["auditor"]}), ("not Bearer", {"typ": "ID"}),
                             ("aud", {"aud": "account"}), ("sub", {"sub": "00000000-0000-0000-0000-000000000000"})):
            self.assertNotEqual(problems(self.record(claims=claims)), [], name)
        # PostgREST stores the claims with the role it took (anon under contract C1): the
        # record still reproduces; any other role, or an added key, does not (source.claims_recorded)
        doc = self.record()
        doc["approval"]["evidence"]["claims"]["role"] = "anon"
        self.assertEqual(problems(doc), [])
        doc["approval"]["evidence"]["claims"] = json.dumps(doc["approval"]["evidence"]["claims"])
        self.assertEqual(problems(doc), [], "jsonb text as read from the database")
        for bad in ({"role": "rr_qa"}, {"role": "anon", "extra": 1}):
            doc = self.record()
            doc["approval"]["evidence"]["claims"].update(bad)
            self.assertNotEqual(problems(doc), [], bad)
        # composites collapse: qa + auditor (qa includes auditor) is one own role, qa
        self.assertEqual(problems(self.record(claims={"groups": ["qa", "auditor"]})), [])
        # a jti another version's confirm or dispute carried is no replay (§14.8.5): only
        # other_approved_jti counts, which apply.sh --audit fills from approved evidence alone
        self.assertEqual(problems(self.record()), [])
        doc = self.record()
        doc["approval"]["other_approved_jti"].append("jti-2")
        rc, out = self.audit(doc)
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL approval: the approval token was also used to approve another version", out)

    def test_rs256_refusals(self):
        n, e, _ = self.key
        jwk = {"kid": "k1", "n": _b64u(n.to_bytes(256, "big")), "e": _b64u(e.to_bytes(3, "big"))}
        good = _sign_rs256(self.key, {"alg": "RS256", "kid": "k1"}, {"sub": "x"})
        self.assertIsNone(self.cli.rs256_problem(good, jwk))
        h, p, sig = good.split(".")
        self.assertIsNotNone(self.cli.rs256_problem(f"{h}.{_b64u(b'{\"sub\": \"y\"}')}.{sig}", jwk))
        for header in ({"alg": "none", "kid": "k1"}, {"alg": "HS256", "kid": "k1"}, {"alg": "RS256", "kid": "k9"}):
            t = _b64u(json.dumps(header).encode()) + "." + p + "." + sig
            self.assertIsNotNone(self.cli.rs256_problem(t, jwk), header)
        raw = self.cli._b64url(sig)
        self.assertIn("malformed", self.cli.rs256_problem(f"{h}.{p}.{_b64u(raw[1:])}", jwk))
        self.assertIn("malformed", self.cli.rs256_problem(f"{h}.{p}.{_b64u(n.to_bytes(256, 'big'))}", jwk))
        self.assertIsNotNone(self.cli.rs256_problem(f"{h}.{p}", jwk))

    def test_the_compiler_of_the_recorded_commit(self):
        """A record whose compiler is not this tree's recompiles with that commit's (git archive
        of apps/iam/compiler): 05c1af9's compiler gives the same digests (Phase45Delta)."""
        import shutil
        import subprocess
        import tempfile
        pre = "05c1af9"
        tmp = tempfile.mkdtemp(prefix="medcea-audit-test-")
        try:
            r = subprocess.run(f'git -C "{REPO}" archive {pre} apps/iam/compiler | tar -x -C "{tmp}"',
                               shell=True, capture_output=True, text=True)
            if r.returncode != 0:
                self.skipTest(f"no git archive of {pre}")
            cd = self.source.compiler_digest(os.path.join(tmp, "apps", "iam", "compiler"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        if cd == self.source.compiler_digest():
            self.skipTest("this tree's compiler is 05c1af9's")
        # the version recorded under that commit holds that commit's policy (Superset stage
        # C's commit B moved defaults.yaml's skeleton and matrix since)
        import yaml
        r = subprocess.run(["git", "-C", REPO, "show", f"{pre}:apps/iam/policy/defaults.yaml"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        f_pre = yaml.safe_load(r.stdout)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "pre.yaml")
            with open(path, "w") as fh:
                fh.write(r.stdout)
            arts = self.ac.digests_of(self.ac.compile_all(["--file", path, "--label", "pre"]), pre,
                                      self.source.skeleton_digest(f_pre))
        rc, out = self.audit(self.record(commit=pre, compiler=cd, f=f_pre, artefacts=arts))
        self.assertEqual(rc, 0, out)
        self.assertIn(f"compiled with the compiler of {pre}", out)
        rc, out = self.audit(self.record(commit=pre, compiler="0" * 64, f=f_pre, artefacts=arts))
        self.assertEqual(rc, 1, out)
        self.assertIn(f"FAIL the compiler of commit {pre} is", out)


class StagedResolutionTest(unittest.TestCase):
    """cli.py --staged (IAM 4.5, design §14.8.4.1) through source.resolve: a bad header is
    exit 2, the label is version-N; tests/test_policy_source.py Staged covers the pin."""

    def test_resolve_and_label(self):
        import shutil
        import subprocess
        from compiler import source
        root = scratch_root()
        cli = os.path.join(root, "apps", "iam", "compiler", "cli.py")
        f = model.load_defaults().data
        ew = source.entries_and_waivers(f)
        st = {"state": "version-9", "version": 9, "kind": "change", "entries_digest": source.policy_entries_digest(f, "change"),
              "groups": sorted(f["resource_groups"]), "roles": sorted(f["roles"]),
              "accepted": {"digest": source.skeleton_digest(f), "body": source.skeleton(f)},
              "entries": ew["entries"], "waivers": [source.waiver_row(w) for w in ew["waivers"]]}
        d = os.path.join(root, "stage-test")
        os.makedirs(d, mode=0o700, exist_ok=True)
        try:
            path = os.path.join(d, "policy-applied.yaml")
            text = source.host_file_text(st, "abc1234", "2026-11-04T00:00:00Z")
            with open(path, "w") as fh:
                fh.write(text)
            sha = hashlib.sha256(text.encode()).hexdigest()
            src = source.resolve(staged=path, env={"MEDCEA_POLICY_STAGED_SHA256": sha})
            self.assertEqual((src.kind, src.version, source.label(src)), ("staged", 9, "version-9"))
            self.assertEqual(src.data["matrix"], f["matrix"])
            for env in ({}, {"MEDCEA_POLICY_STAGED_SHA256": sha.replace(sha[0], "f" if sha[0] != "f" else "e", 1)}):
                with self.assertRaises(source.SourceError):
                    source.resolve(staged=path, env=env)
            with self.assertRaises(source.SourceError):
                source.resolve(path=path, staged=path, env={"MEDCEA_POLICY_STAGED_SHA256": sha})
            bad = text.replace("# medcea-applied: version=9", "# medcea-applied: version=x", 1)
            with open(path, "w") as fh:
                fh.write(bad)
            r = subprocess.run([sys.executable, cli, "--staged", path, "compile", "routes"], capture_output=True,
                               text=True, env=clean_env(MEDCEA_POLICY_STAGED_SHA256=hashlib.sha256(bad.encode()).hexdigest()))
            self.assertEqual((r.returncode, r.stdout), (2, ""), r.stderr)
            self.assertIn("header names version 'x'", r.stderr)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class AppGateTest(unittest.TestCase):
    """app_gate (IAM 4.2b) runs, for each call, the lines read_wired() expands it into"""

    def test_app_gate_body(self):
        with open(os.path.join(REPO, "infra/lib-oauth2-proxy.sh")) as f:
            lib = f.read()
        body = lib[lib.index("app_gate() {"):]
        body = body[:body.index("\n}\n")]
        self.assertIn('ALLOWED_GROUPS="$(policy_groups "$host_var")"', body)
        self.assertIn('gate_error_page "$release" "$host_var" "$ALLOWED_GROUPS"', body)
        self.assertEqual(len(re.findall(r'render "\$tpl" KEYCLOAK_DOMAIN KEYCLOAK_REALM NAMESPACE (APP_SERVICE )?ALLOWED_GROUPS > "\$values"', body)), 2)

    def test_every_app_gate_call_is_expanded(self):
        for script in ("apps/frontend/deploy.sh", "apps/monitor/deploy.sh", "apps/scheduler/deploy.sh",
                       "apps/mqtt-explorer/deploy.sh"):
            with open(os.path.join(REPO, script)) as f:
                raw = f.read()
            self.assertEqual(raw.count("app_gate "), len(APP_GATE.findall(raw)), script)


if __name__ == "__main__":
    unittest.main(verbosity=1)
