#!/usr/bin/env python3
"""tests/test_workbench_data.py — reading platform data from a notebook (IAM 3.2b), offline.

  - k8s/workbench/examples/medcea_data.py against a fake Keycloak and a fake config-api
    (one ThreadingHTTPServer on 127.0.0.1:0): the device grant (pending, slow_down,
    denied, expired), the token checks (azp, audience, groups), refresh before expiry and
    after the session ended, the Bearer header, a 401 about the token retried once after
    a refresh (a 42501 never), the refusals turned into what to do, and the query strings
    (percent-encoded, never quoted; the measurement window, newest first, capped). Tokens are unsigned JWT-shaped strings: the helper reads
    them for display only, config-api verifies them. The DataFrame helpers run when
    pandas is installed (it is in the workbench image), and are skipped otherwise.
  - the example notebooks: valid nbformat 4, no outputs or execution counts (what
    nbstripout would leave), ConfigMap-safe names, under 200 KiB (kubectl apply copies
    the ConfigMap into an annotation, and an object's annotations hold 256 KiB).
  - the policy: scientists hold R (not X) on measurements; config-api accepts the
    workbench-notebook client (pre_request's azp list) and admits the notebook pods.
  - infra/lib-workbench-homes.sh against a fake kubectl: lists each claim-<name> with its
    directory and how to keep it, says nothing without claims, warns when it cannot ask.

  python3 tests/test_workbench_data.py
"""
import base64
import datetime
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(REPO, "k8s", "workbench", "examples")
sys.path.insert(0, EXAMPLES)
sys.path.insert(0, os.path.join(REPO, "apps", "iam"))

import medcea_data as md  # noqa: E402
from compiler import grants, model, netpol  # noqa: E402

try:
    import pandas  # noqa: F401
    HAVE_PANDAS = True
except ImportError:
    HAVE_PANDAS = False

CLIENT = "workbench-notebook"


def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def token(**over):
    c = {"typ": "Bearer", "azp": CLIENT, "aud": ["medcea-api", "account"], "sub": "0b7c2f5e-1111-4222-8333-944455556666",
         "preferred_username": "bio1", "groups": ["default-roles-medcea", "bio_scientist"]}
    c.update(over)
    return "h." + b64(c) + ".sig"


class Fake:
    """What the fake server answers: queues of (status, body) per path, and a log."""

    def __init__(self):
        self.answers = {}
        self.calls = []

    def queue(self, path, *answers):
        """Answers in order; the last one repeats."""
        self.answers.setdefault(path, []).extend(answers)

    def set(self, path, *answers):
        """Replace what `path` answers from now on."""
        self.answers[path] = list(answers)


def make_server(fake):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _answer(self, form=None):
            path = self.path.split("?")[0]
            fake.calls.append({"method": self.command, "path": self.path, "form": form,
                               "auth": self.headers.get("Authorization")})
            q = fake.answers.get(path) or [(404, {"message": "no fake answer for " + path})]
            status, body = q.pop(0) if len(q) > 1 else q[0]
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            self._answer(dict(urllib.parse.parse_qsl(self.rfile.read(n).decode())))

        def do_GET(self):
            self._answer()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


DEVICE = "/realms/medcea/protocol/openid-connect/auth/device"
TOKEN = "/realms/medcea/protocol/openid-connect/token"


class HelperTest(unittest.TestCase):
    def setUp(self):
        self.fake = Fake()
        self.srv = make_server(self.fake)
        base = "http://127.0.0.1:%d" % self.srv.server_address[1]
        self.clock = Clock()
        self.shown = []
        self.s = md.Session(keycloak=base + "/realms/medcea", api=base + "/api", client_id=CLIENT,
                            clock=self.clock, sleep=self.clock.sleep, show=lambda *a: self.shown.append(a))

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def device(self, interval=5, expires=600):
        self.fake.queue(DEVICE, (200, {"device_code": "dev-1", "user_code": "ABCD-EFGH", "interval": interval,
                                       "expires_in": expires,
                                       "verification_uri": "https://kc.test/realms/medcea/device",
                                       "verification_uri_complete": "https://kc.test/realms/medcea/device?user_code=ABCD-EFGH"}))

    def signed_in(self, **over):
        self.device()
        self.fake.queue(TOKEN, (200, {"access_token": token(**over), "expires_in": 300,
                                      "refresh_token": "r1", "refresh_expires_in": 1800}))
        self.s.sign_in()

    def posts(self, path):
        return [c["form"] for c in self.fake.calls if c["path"] == path]

    # ------------------------------------------------------------ sign-in ----
    def test_device_flow(self):
        self.device()
        self.fake.queue(TOKEN, (400, {"error": "authorization_pending"}), (400, {"error": "slow_down"}),
                        (502, {}), (200, {"access_token": token(), "expires_in": 300, "refresh_token": "r1"}))
        self.assertEqual(self.s.sign_in(), "bio1")
        self.assertEqual(self.s.role, "bio_scientist")
        self.assertEqual(self.shown, [("https://kc.test/realms/medcea/device?user_code=ABCD-EFGH",
                                       "https://kc.test/realms/medcea/device", "ABCD-EFGH", 600)])
        self.assertEqual(self.posts(DEVICE), [{"client_id": CLIENT, "scope": "openid"}])
        polls = self.posts(TOKEN)
        self.assertEqual(len(polls), 4)
        self.assertEqual(polls[0], {"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                                    "device_code": "dev-1", "client_id": CLIENT})
        self.assertFalse(any("client_secret" in p for p in polls + self.posts(DEVICE)), "a public client: no secret")
        self.assertNotIn("r1", repr(self.s))
        self.assertNotIn(token(), repr(self.s))

    def test_device_flow_refusals(self):
        for answer, words in (((400, {"error": "access_denied"}), "denied"),
                              ((400, {"error": "expired_token"}), "expired"),
                              ((401, {"error": "unauthorized_client"}), "refused")):
            with self.subTest(answer):
                self.fake.answers.clear()
                self.device()
                self.fake.queue(TOKEN, answer)
                with self.assertRaises(md.SignInError) as cm:
                    self.s.sign_in()
                self.assertIn(words, str(cm.exception))

    def test_code_expires(self):
        self.device(interval=5, expires=12)
        self.fake.queue(TOKEN, (400, {"error": "authorization_pending"}))
        with self.assertRaises(md.SignInError) as cm:
            self.s.sign_in()
        self.assertIn("expired", str(cm.exception))

    def test_device_endpoint_refused(self):
        self.fake.queue(DEVICE, (401, {"error": "unauthorized_client", "error_description": "device grant off"}))
        with self.assertRaises(md.SignInError) as cm:
            self.s.sign_in()
        self.assertIn("./deploy-infra.sh", str(cm.exception))

    def test_token_claims_checked(self):
        for over, words in (({"azp": "config"}, "azp workbench-notebook"), ({"aud": "account"}, "medcea-api"),
                            ({"groups": []}, "groups")):
            with self.subTest(over):
                self.fake.answers.clear()
                with self.assertRaises(md.SignInError) as cm:
                    self.signed_in(**over)
                self.assertIn(words, str(cm.exception))
                with self.assertRaises(md.SignInError):
                    self.s.token()     # nothing kept

    # ------------------------------------------------------------ refresh ----
    def test_refresh_before_expiry(self):
        self.signed_in()
        first = self.s.token()
        self.clock.t += 200                          # 100 s left: still served
        self.assertEqual(self.s.token(), first)
        self.clock.t += 50                           # 50 s left: refreshed
        self.fake.set(TOKEN, (200, {"access_token": token(preferred_username="bio1", jti="2"), "expires_in": 300}))
        second = self.s.token()
        self.assertNotEqual(second, first)
        self.assertEqual(self.posts(TOKEN)[-1], {"grant_type": "refresh_token", "refresh_token": "r1", "client_id": CLIENT})

    def test_session_ended(self):
        self.signed_in()
        self.clock.t += 290
        self.fake.set(TOKEN, (400, {"error": "invalid_grant", "error_description": "Session not active"}))
        with self.assertRaises(md.SignInError) as cm:
            self.s.token()
        self.assertIn("sign_in() again", str(cm.exception))
        self.assertIsNone(self.s.user)

    def test_sign_out_forgets(self):
        self.signed_in()
        self.s.sign_out()
        with self.assertRaises(md.SignInError):
            self.s.token()

    # ---------------------------------------------------------- config-api ----
    def test_bearer_and_query(self):
        self.signed_in()
        self.fake.queue("/api/cea_unit", (200, [{"unit_id": 1, "unit_code": "UNIT01"}]))
        self.assertEqual(self.s.get(*md.units_query()), [{"unit_id": 1, "unit_code": "UNIT01"}])
        call = self.fake.calls[-1]
        self.assertEqual(call["auth"], "Bearer " + token())
        self.assertEqual(call["path"], "/api/cea_unit?select=unit_id,unit_code,description,is_active&order=unit_code.asc")

    def test_401_refreshes_once(self):
        self.signed_in()
        self.fake.queue("/api/cea_zone", (401, {"code": "PGRST301", "message": "JWT expired"}), (200, []))
        self.fake.set(TOKEN, (200, {"access_token": token(jti="2"), "expires_in": 300}))
        self.assertEqual(self.s.get("cea_zone"), [])
        self.assertEqual(self.posts(TOKEN)[-1]["grant_type"], "refresh_token")

    def test_refusals(self):
        self.signed_in()
        for answer, words in (
                ((403, {"code": "28000", "message": "client workbench-notebook may not use the API"}), "./apps/database/deploy.sh"),
                # what config-api answers: every token runs as anon until pre_request
                # picks the role, and PostgREST 12 answers 42501 for anon with 401
                ((401, {"code": "42501", "message": "permission denied for view v_ap_measurements"}), "your role may not read"),
                ((403, {"code": "42501", "message": "permission denied for view v_ap_measurements"}), "your role may not read"),
                ((500, {"code": "PGRST300", "message": "Server lacks JWT secret"}), "IAM_POSTGREST_JWT"),
                ((403, {"code": "28000", "message": "no platform role"}), "no platform role")):
            with self.subTest(answer):
                self.fake.answers.pop("/api/v_ap_measurements", None)
                self.fake.queue("/api/v_ap_measurements", answer)
                with self.assertRaises(md.AccessError) as cm:
                    self.s.get("v_ap_measurements")
                self.assertIn(words, str(cm.exception))
                self.assertEqual(cm.exception.status, answer[0])
        self.assertEqual([f for f in self.posts(TOKEN) if f.get("grant_type") == "refresh_token"], [],
                         "a refusal that is not about the token spent a refresh")

    def test_unreachable(self):
        s = md.Session(keycloak="http://127.0.0.1:9/realms/medcea", api="http://127.0.0.1:9", client_id=CLIENT,
                       show=lambda *a: None)
        with self.assertRaises(md.SignInError) as cm:
            s.sign_in()
        self.assertIn("ask an administrator", str(cm.exception))

    def test_not_configured(self):
        s = md.Session(keycloak="", api="", client_id=CLIENT, show=lambda *a: None)
        s.keycloak = ""
        with self.assertRaises(md.SignInError) as cm:
            s.sign_in()
        self.assertIn("MEDCEA_KEYCLOAK", str(cm.exception))

    def test_measurement_query(self):
        now = datetime.datetime(2026, 10, 31, 12, 0, tzinfo=datetime.timezone.utc)
        path, params = md.measurement_query("UNIT 01", "Z\"1", "air_temperature", 90, now=now)
        self.assertEqual(path, "v_ap_measurements")
        qs = md.query_string(params)
        self.assertIn("unit_code=eq.UNIT%2001", qs)
        self.assertIn("zone_code=eq.Z%221", qs)           # a quote is a value, never PostgREST quoting
        self.assertIn("tag=eq.air_temperature", qs)
        self.assertIn("measure_timestamp=gte.2026-10-31T10%3A30%3A00%2B00%3A00", qs)   # '+' never a space
        self.assertIn("order=measure_timestamp.desc", qs)   # a capped window keeps its newest rows
        self.assertIn("limit=50000", qs)
        self.assertIn("select=measure_timestamp,unit_code,zone_code,tag,value,unit_of_measurement", qs)
        for bad in (("", "Z", "t", 5), ("U", "Z", "t", 0), ("U", "Z", "t", -1)):
            with self.subTest(bad), self.assertRaises(ValueError):
                md.measurement_query(*bad)

    @unittest.skipUnless(HAVE_PANDAS, "pandas is not installed here (it is in the workbench image)")
    def test_dataframes(self):
        self.signed_in()
        self.fake.queue("/api/v_ap_measurements", (200, [
            {"measure_timestamp": "2026-10-31T11:00:00+00:00", "unit_code": "UNIT01", "zone_code": "ZONE01",
             "tag": "air_temperature", "value": 21.5, "unit_of_measurement": "C"}]))
        df = self.s.measurements("UNIT01", "ZONE01", minutes=60)
        self.assertEqual(list(df.columns), list(md.MEASUREMENT_COLUMNS))
        self.assertEqual(float(df["value"].iloc[0]), 21.5)
        self.fake.queue("/api/cea_zone", (200, [{"zone_id": 3, "unit_id": 1, "zone_code": "ZONE01",
                                                  "zone_description": "", "is_active": "Y"}]))
        self.fake.queue("/api/cea_unit", (200, [{"unit_id": 1, "unit_code": "UNIT01", "description": "", "is_active": "Y"}]))
        self.assertEqual(self.s.zones()["unit_code"].tolist(), ["UNIT01"])
        self.assertFalse(df.attrs["truncated"])

    @unittest.skipUnless(HAVE_PANDAS, "pandas is not installed here (it is in the workbench image)")
    def test_capped_window_warns_and_sorts(self):
        self.signed_in()
        rows = [{"measure_timestamp": "2026-10-31T11:0%d:00+00:00" % m, "unit_code": "UNIT01", "zone_code": "ZONE01",
                 "tag": "air_temperature", "value": m, "unit_of_measurement": "C"} for m in (2, 1)]
        self.fake.queue("/api/v_ap_measurements", (200, rows))
        with self.assertWarnsRegex(UserWarning, "only the latest 2 readings"):
            df = self.s.measurements("UNIT01", "ZONE01", minutes=60, limit=2)
        self.assertTrue(df.attrs["truncated"])
        self.assertEqual(df["value"].tolist(), [1, 2])   # oldest first for the chart

    def test_writes_nothing(self):
        """The helper never writes a file or an environment variable."""
        with open(os.path.join(EXAMPLES, "medcea_data.py")) as f:
            src = f.read()
        import re
        for needle in (r"(?<![\w.])open\(", r"os\.environ\[", "putenv", "pickle", "shelve", r"\.write\("):
            self.assertIsNone(re.search(needle, src), needle)


class ExamplesTest(unittest.TestCase):
    def test_notebooks_are_stripped(self):
        names = sorted(os.listdir(EXAMPLES))
        self.assertEqual([n for n in names if not n.startswith("__")],
                         ["01-connect.ipynb", "02-air-temperature.ipynb", "SAVE_TO_GIT.md", "medcea_data.py",
                          "nb_output_guard.py"])
        total = 0
        for n in names:
            p = os.path.join(EXAMPLES, n)
            if not os.path.isfile(p):
                continue
            total += os.path.getsize(p)
            self.assertRegex(n, r"^[-._a-zA-Z0-9]+$")       # a ConfigMap key
            if n.endswith(".ipynb"):
                with open(p) as f:
                    nb = json.load(f)
                self.assertEqual(nb["nbformat"], 4)
                for c in nb["cells"]:
                    if c["cell_type"] == "code":
                        self.assertEqual(c["outputs"], [], n)
                        self.assertIsNone(c["execution_count"], n)
        # deploy-workbench applies the ConfigMap client-side, which copies it into the
        # last-applied annotation: all annotations together may hold 256 KiB
        self.assertLess(total, 200 * 1024)

    def test_chart_settings_on_top(self):
        with open(os.path.join(EXAMPLES, "02-air-temperature.ipynb")) as f:
            cells = json.load(f)["cells"]
        first_code = "".join(next(c for c in cells if c["cell_type"] == "code")["source"])
        for var in ("UNIT =", "ZONE =", "MINUTES ="):
            self.assertIn(var, first_code)


class PolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = model.load(None)

    def test_scientists_read_telemetry(self):
        for r in ("bio_scientist", "control_scientist"):
            self.assertEqual(self.p.effective("measurements", r), {"R"}, r)

    def test_config_api_accepts_notebooks(self):
        self.assertIn(CLIENT, grants.token_clients(self.p))
        self.assertIn("'workbench-notebook'", grants.compiled_functions(self.p))
        np = netpol.compile(self.p, "medcea", ["10.0.0.1"])
        api = next(i for i in np["items"] if i["metadata"]["name"] == "iam-config-api")
        peers = [peer for rule in api["spec"]["ingress"] for peer in rule["from"]]
        self.assertIn({"podSelector": {"matchLabels": {"app": "jupyterhub", "component": "singleuser-server",
                                                       "release": "workbench"}}}, peers)

    def test_egress_is_the_two_hops(self):
        self.assertEqual(netpol.egress(self.p, "notebooks"), [
            {"to": [{"podSelector": {"matchLabels": {"app": "config-api"}}}], "ports": [{"protocol": "TCP", "port": 3000}]},
            {"to": [{"podSelector": {"matchLabels": {"app": "keycloak"}}}], "ports": [{"protocol": "TCP", "port": 8080}]}])
        with self.assertRaises(ValueError):
            netpol.egress(self.p, "nobody")


class HomesTest(unittest.TestCase):
    def run_warn(self, kubectl_body):
        d = tempfile.mkdtemp()
        k = os.path.join(d, "kubectl")
        with open(k, "w") as f:
            f.write("#!/bin/sh\n" + kubectl_body + "\n")
        os.chmod(k, 0o755)
        r = subprocess.run(["bash", "-c", f'source "{REPO}/infra/lib-workbench-homes.sh"; workbench_homes_warn medcea; echo "rc=$?"'],
                           env=dict(os.environ, KUBECTL=k), capture_output=True, text=True)
        return r.stdout

    def test_lists_homes(self):
        pvcs = json.dumps({"items": [
            {"metadata": {"name": "claim-bio1"}, "spec": {"volumeName": "pvc-1"}, "status": {"capacity": {"storage": "10Gi"}}},
            {"metadata": {"name": "data-rdbms-postgresql-0"}, "spec": {"volumeName": "pvc-2"}}]})
        out = self.run_warn(f"""case "$*" in
  "get pvc -n medcea -o json") echo '{pvcs}' ;;
  "get pv pvc-1 -o jsonpath={{.spec.hostPath.path}}") printf /var/snap/microk8s/common/default-storage/medcea-claim-bio1-pvc-1 ;;
  *) exit 1 ;;
esac""")
        self.assertIn("bio1: claim-bio1 (10Gi), on this host in /var/snap/microk8s/common/default-storage/medcea-claim-bio1-pvc-1", out)
        self.assertNotIn("rdbms", out)
        self.assertIn("sudo cp -a", out)
        self.assertIn("SAVE_TO_GIT.md", out)
        self.assertTrue(out.rstrip().endswith("rc=0"))

    def test_no_homes_no_words(self):
        self.assertEqual(self.run_warn("""echo '{"items": []}'""").strip(), "rc=0")

    def test_cannot_ask(self):
        out = self.run_warn("exit 1")
        self.assertIn("Could not list the AI workbench homes", out)
        self.assertTrue(out.rstrip().endswith("rc=0"))

    def test_every_uninstall_path_warns_before_it_asks(self):
        with open(os.path.join(REPO, "deploy-infra.sh")) as f:
            infra = f.read()
        for branch, ask in (('"--uninstall" ]]', "Type 'yes' to confirm uninstall"), ('"--reset" ]]', "Type 'reset' to confirm")):
            part = infra[infra.index(branch):]
            self.assertLess(part.index("workbench_homes_warn"), part.index(ask), branch)
        with open(os.path.join(REPO, "install.sh")) as f:
            inst = f.read()
        for branch, ask in (("uninstall-infra)\n", "confirm reset"), ("uninstall-all)\n", "confirm uninstall")):
            part = inst[inst.rindex(branch):]
            self.assertLess(part.index("workbench_homes "), part.index(ask), branch)
        with open(os.path.join(REPO, "infra", "bootstrap-infra.sh")) as f:
            boot = f.read()
        part = boot[boot.index("MICROK8S RESET LOGIC"):]
        self.assertLess(part.index("workbench_homes_warn"), part.index("Fully wipe MicroK8s"), "bootstrap wipe")


if __name__ == "__main__":
    unittest.main()
