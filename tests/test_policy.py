#!/usr/bin/env python3
"""tests/test_policy.py — the access policy passes its own invariants, and the checker
catches every kind of violation it claims to.

Run from the repository root:  python3 tests/test_policy.py
Read-only; needs python3-yaml (infra/lib-prereqs.sh). No cluster, no lock.
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

from compiler import invariants, model, netpol, proxies, routes  # noqa: E402


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


if __name__ == "__main__":
    unittest.main(verbosity=1)
