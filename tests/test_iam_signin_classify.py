#!/usr/bin/env python3
"""tests/test_iam_signin_classify.py — iam_signin_flow.py's pgAdmin and Superset verdicts and
its host list, offline: no cluster, no lock, no config.env.

GatedHosts (Superset stage C, finding F8): an ENFORCEMENT entry for a host the policy does
not have yet is skipped, not a KeyError; Superset is skipped under IAM_GATES=false (no
pre-policy sign-in) and while iam-signin.sh found no deployment/superset; once deployed it
expects exactly the roles the analysis group admits. SupersetChecks: the FAB roles against
the compiled mapping, /sqllab/ for builders only, and medcea_security.py's own 403 page
read as "refused". The policy is the factory file (model.load_defaults(), never the host's
state/), with the stage C fixture added where Superset must be in it.

The bodies are pgAdmin 9's login page as render_page.html renders it (dpage/pgadmin4:9):
window.renderSecurityPage(page, page_props|tojson, other_props|tojson), other_props holding
"messages", get_flashed_messages(with_categories=true). pgAdmin's MessageType.ERROR is the
one-element tuple ('Error',), so its claims refusal (authenticate/oauth2.py, flash(msg,
MessageType.ERROR)) is serialised [["Error"], "The user is not authorized ..."], which a
regex expecting a quoted lowercase category never matched. Flask's tojson is compact in
production and escapes ' as \\u0027; both forms are tried.

  python3 tests/test_iam_signin_classify.py
"""
import copy
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import iam_signin_flow as flow  # noqa: E402
from compiler import model, proxies  # noqa: E402  (iam_signin_flow put apps/iam on the path)

DOMAIN = "pgadmin.medcea.example.org"
LOGIN = f"https://{DOMAIN}/login?next=%2Fbrowser%2F"
REFUSAL = ("The user is not authorized to login based on your identity profile. "
           "Please contact your administrator.")


def page(messages, compact=True):
    """pgAdmin's login page with these flashed (category, message) pairs, as Flask renders it."""
    seps = (",", ":") if compact else (", ", ": ")
    dump = lambda v: json.dumps(v, separators=seps, sort_keys=True).replace("'", "\\u0027")
    props = dump({"csrfToken": "abc", "loginBanner": "", "oauth2Config": [{"OAUTH2_NAME": "keycloak"}]})
    other = dump({"messages": [[list(c) if isinstance(c, tuple) else c, m] for c, m in messages]})
    return ("<!DOCTYPE html><html><head><title>pgAdmin 4</title></head><body>"
            '<div id="root" style="height: 100%"></div><script>try {require(["security.pages"],'
            f"function() {{window.renderSecurityPage('login.html', {props},\n                {other});}}"
            ");} catch (err) {console.log(err);}</script></body></html>")


class PgadminClassify(unittest.TestCase):
    def verdict(self, body, url=LOGIN, status=200):
        return flow.classify_pgadmin(DOMAIN, status, url, body)

    def test_claims_refusal_with_tuple_category_is_refused(self):
        for compact in (True, False):
            body = page([(("Error",), REFUSAL)], compact)
            self.assertIn('[["Error"],', body.replace(", ", ","))
            self.assertEqual(self.verdict(body), ("refused", ""), compact)

    def test_claims_refusal_found_among_other_messages(self):
        body = page([("Info", "Please log in to access this page."), (("Error",), REFUSAL)])
        self.assertEqual(self.verdict(body), ("refused", ""))

    def test_other_flash_is_an_error_in_pgadmins_words(self):
        msg = "'admin@medcea.invalid' does not appear to be a valid email address."
        outcome, why = self.verdict(page([(("Error",), msg)]))
        self.assertEqual(outcome, "error")
        self.assertIn("pgAdmin refused the sign-in: ", why)
        self.assertIn("does not appear to be a valid email address", why)
        self.assertIn("'admin@medcea.invalid'", why)   # ' decoded, not shown raw

    def test_string_category_still_read(self):
        outcome, why = self.verdict(page([("Warning", "Login session expired. Please try again.")]))
        self.assertEqual(outcome, "error")
        self.assertIn("Login session expired", why)

    def test_no_flash_on_login_page(self):
        outcome, why = self.verdict(page([]))
        self.assertEqual(outcome, "error")
        self.assertIn("without a flashed message", why)

    def test_browser_is_in(self):
        self.assertEqual(self.verdict("<html></html>", f"https://{DOMAIN}/browser/"), ("in", ""))

    def test_flash_on_another_host_is_not_read(self):
        outcome, why = self.verdict(page([(("Error",), REFUSAL)]), "https://kc.example.org/realms/x")
        self.assertEqual(outcome, "error")
        self.assertNotIn("refused the sign-in", why)

    def test_broken_json_is_not_fatal(self):
        self.assertEqual(flow.pgadmin_flashes('{"messages": [[["Error"], "unterminated'), [])


SUPERSET_ENFORCEMENT = "tool (Superset AUTH_ROLES_MAPPING)"
BUILDERS = ("bio_scientist", "control_scientist", "engineer")
VIEWERS = ("production_manager", "qc", "qp")


def with_superset(d):
    """Stage C's policy additions as tests/test_policy.py's add_superset fixture has them
    (D7, D8): host SUPERSET_DOMAIN, group analysis (Alpha from U, Gamma from R)."""
    ceiling = {"master_data": ["R"], "measurements": ["R"]}
    d["hosts"]["SUPERSET_DOMAIN"] = {"label": "Superset", "client": "superset", "serves": ["superset"]}
    d["service_identities"]["svc_superset"] = {
        "label": "Superset datasource", "description": "Superset's charts and SQL Lab.",
        "db_role": "svc_superset", "db_password": "SVC_SUPERSET_DB_PASS", "ceiling": copy.deepcopy(ceiling)}
    d["resource_groups"]["analysis"] = {
        "label": "Superset analysis", "class": "config", "description": "Charts, dashboards and SQL Lab.",
        "why_this_class": "Presentation configuration.", "risk": "SQL Lab runs any SELECT svc_superset may run.",
        "reaches": copy.deepcopy(ceiling), "members": [{"type": "ui", "host": "SUPERSET_DOMAIN"}],
        "tool": {"kind": "superset", "host": "SUPERSET_DOMAIN", "service_identity": "svc_superset",
                 "settings": [{"setting": "Alpha", "levels": ["U"]}, {"setting": "Gamma", "levels": ["R"]}],
                 "otherwise": "refuse", "help": "U gives Alpha with SQL Lab, R gives Gamma with MedCEA Viewer."}}
    d["matrix"]["analysis"] = {r: ["R", "C", "U"] for r in BUILDERS}
    d["matrix"]["analysis"].update({r: ["R"] for r in VIEWERS})
    return d


class GatedHosts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.factory = model.load_defaults()
        cls.staged = model.Policy(with_superset(copy.deepcopy(cls.factory.data)))
        # the policy as commit A has it, whatever defaults.yaml says later: no host yet
        bare = copy.deepcopy(cls.factory.data)
        bare["hosts"].pop("SUPERSET_DOMAIN", None)
        bare["resource_groups"].pop("analysis", None)
        bare["matrix"].pop("analysis", None)
        cls.bare = model.Policy(bare)

    def hosts(self, p, **env):
        """gated_hosts with SUPERSET_DOMAIN in ENFORCEMENT (whether or not A1 put it there),
        every host variable set, and only `env` besides."""
        enforcement = dict(proxies.ENFORCEMENT, SUPERSET_DOMAIN=SUPERSET_ENFORCEMENT)
        environ = {v: v.lower().replace("_", "-") + ".example.org" for v in enforcement}
        environ.update(env)
        skipped = []
        with mock.patch.dict(proxies.ENFORCEMENT, enforcement), mock.patch.dict(os.environ, environ, clear=True):
            out = flow.gated_hosts(p, skipped)
        return {var: (label, want) for var, _, label, want in out}, dict(skipped)

    def test_host_not_in_the_policy_is_skipped_not_a_keyerror(self):
        for gates in ("true", "false"):
            got, skipped = self.hosts(self.bare, IAM_GATES=gates, SUPERSET_DEPLOYED="true")
            self.assertNotIn("SUPERSET_DOMAIN", got, gates)
            self.assertEqual(skipped, {"SUPERSET_DOMAIN": "not in the applied access policy"}, gates)
            for var, status in proxies.ENFORCEMENT.items():
                if var in self.bare.hosts and (status == "compiled" or status.startswith("tool")):
                    self.assertIn(var, got, (gates, var))

    def test_superset_skipped_while_not_deployed(self):
        for env in ({}, {"SUPERSET_DEPLOYED": "false"}, {"SUPERSET_DEPLOYED": ""}):
            got, skipped = self.hosts(self.staged, IAM_GATES="true", **env)
            self.assertNotIn("SUPERSET_DOMAIN", got, env)
            self.assertEqual(skipped, {"SUPERSET_DOMAIN": "not deployed"}, env)

    def test_superset_deployed_expects_the_analysis_roles(self):
        got, skipped = self.hosts(self.staged, IAM_GATES="true", SUPERSET_DEPLOYED="true")
        self.assertEqual(skipped, {})
        self.assertEqual(got["SUPERSET_DOMAIN"], ("Superset", set(BUILDERS + VIEWERS)))
        # the other hosts are unchanged by the fixture
        base, _ = self.hosts(self.bare, IAM_GATES="true")
        self.assertEqual({v: w for v, w in got.items() if v != "SUPERSET_DOMAIN"}, base)

    def test_superset_skipped_under_iam_gates_false(self):
        got, skipped = self.hosts(self.staged, IAM_GATES="false", SUPERSET_DEPLOYED="true")
        self.assertNotIn("SUPERSET_DOMAIN", got)
        self.assertIn("IAM_GATES=false", skipped["SUPERSET_DOMAIN"])
        # every other tool host keeps its pre-policy expectation: any account, role-less included
        everyone = set(self.staged.roles) | {"none"}
        self.assertEqual(got["GRAFANA_DOMAIN"][1], everyone)
        self.assertEqual(got["WORKBENCH_DOMAIN"][1], everyone)
        self.assertEqual(got["PGADMIN_DOMAIN"][1], {"admin"})

    def test_unset_domain_is_left_out_silently(self):
        enforcement = dict(proxies.ENFORCEMENT, SUPERSET_DOMAIN=SUPERSET_ENFORCEMENT)
        with mock.patch.dict(proxies.ENFORCEMENT, enforcement), \
                mock.patch.dict(os.environ, {"IAM_GATES": "true", "SUPERSET_DEPLOYED": "true"}, clear=True):
            self.assertEqual(flow.gated_hosts(self.staged), [])


class FakeResponse:
    def __init__(self, status, url, body):
        self.status, self._url, self._body = status, url, body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def geturl(self):
        return self._url

    def read(self):
        return self._body.encode()


class FakeOpener:
    """A signed-in Superset session: path -> (status, final url, body)."""
    def __init__(self, pages):
        self.pages = pages

    def open(self, req, timeout=None):
        path = req.full_url.split(SS, 1)[1]
        status, url, body = self.pages[path]
        return FakeResponse(status, url, body)


SS = "superset.medcea.example.org"


def me_roles(*names):
    return json.dumps({"result": {"username": "test-x", "roles": {n: [["can_read", "Chart"]] for n in names}}})


class SupersetChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = model.Policy(with_superset(copy.deepcopy(model.load_defaults().data)))
        # medcea_security.py's Flask-free part (as apps/superset/deploy.sh reads it)
        src = os.path.join(flow.REPO, "apps", "superset", "medcea_security.py")
        with open(src) as f:
            text = f.read()
        cls.sec = {}
        exec(compile(text.split("\nfrom flask import", 1)[0], src, "exec"), cls.sec)

    def run_checks(self, role, roles_body, sqllab):
        op = FakeOpener({"/api/v1/me/roles/": (200, f"https://{SS}/api/v1/me/roles/", roles_body),
                         "/sqllab/": sqllab})
        return flow.superset_checks(op, SS, self.p, role)

    def test_builder_alpha_with_sql_lab(self):
        self.assertEqual(self.run_checks("engineer", me_roles("sql_lab", "Alpha"),
                                         (200, f"https://{SS}/sqllab/", "<html></html>")), [])

    def test_viewer_gamma_without_sql_lab(self):
        # FAB's has_access sends a role without the permission to the index
        self.assertEqual(self.run_checks("qp", me_roles("Gamma", "MedCEA Viewer"),
                                         (200, f"https://{SS}/superset/welcome/", "<html></html>")), [])
        self.assertEqual(self.run_checks("qc", me_roles("Gamma", "MedCEA Viewer"),
                                         (403, f"https://{SS}/sqllab/", "Forbidden")), [])

    def test_viewer_reaching_sql_lab_fails(self):
        out = self.run_checks("production_manager", me_roles("Gamma", "MedCEA Viewer"),
                              (200, f"https://{SS}/sqllab/", "<html></html>"))
        self.assertEqual(len(out), 1)
        self.assertIn("SQL Lab opens", out[0])

    def test_builder_without_sql_lab_fails(self):
        out = self.run_checks("bio_scientist", me_roles("Alpha", "sql_lab"),
                              (200, f"https://{SS}/superset/welcome/", "<html></html>"))
        self.assertEqual(len(out), 1)
        self.assertIn("SQL Lab does not open", out[0])

    def test_roles_not_the_mapping_fail(self):
        out = self.run_checks("qp", me_roles("Gamma", "MedCEA Viewer", "Admin"),
                              (200, f"https://{SS}/superset/welcome/", ""))
        self.assertEqual(len(out), 1)
        self.assertIn("Superset roles ['Admin', 'Gamma', 'MedCEA Viewer'], the policy gives ['Gamma', 'MedCEA Viewer']",
                      out[0])

    def test_unreadable_roles_is_an_error(self):
        out = self.run_checks("engineer", "<html>login</html>", (200, f"https://{SS}/sqllab/", ""))
        self.assertEqual(len(out), 1)
        self.assertIn("GET /api/v1/me/roles/ answered 200", out[0])

    def test_role_list_form_is_read_too(self):
        body = json.dumps({"result": {"roles": [{"name": "Alpha"}, {"name": "sql_lab"}]}})
        self.assertEqual(self.run_checks("engineer", body, (200, f"https://{SS}/sqllab/", "")), [])

    def test_superset_refusal_page_is_refused(self):
        mapping = {r: ["Gamma", "MedCEA Viewer"] for r in VIEWERS}
        body = self.sec["no_access_page"]("test-qa-abc123", mapping, "https://portal.example.org/")
        url = f"https://{SS}/oauth-authorized/keycloak?code=x&state=y"
        self.assertEqual(flow.classify(SS, "Superset", 403, url, body), ("refused", ""))
        self.assertEqual(flow.classify(SS, "Superset", 200, f"https://{SS}/superset/welcome/", "<html>"), ("in", ""))
        # the sign-in failure page is no refusal
        outcome, _ = flow.classify(SS, "Superset", 400, url, self.sec["failed_page"]("https://portal.example.org/"))
        self.assertEqual(outcome, "error")


if __name__ == "__main__":
    unittest.main()
