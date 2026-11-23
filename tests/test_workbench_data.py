#!/usr/bin/env python3
"""tests/test_workbench_data.py — reading platform data from a notebook (IAM 3.2b), offline.

  - k8s/workbench/examples/medcea_data.py against a fake Keycloak and a fake config-api
    (one ThreadingHTTPServer on 127.0.0.1:0): the device grant (pending, slow_down,
    denied, expired), the token checks (azp, audience, groups), refresh before expiry and
    after the session ended, the Bearer header, a 401 about the token retried once after
    a refresh (a 42501 never), the refusals turned into what to do, and the query strings
    (percent-encoded, never quoted; the measurement window, newest first, capped; the
    reading's sensor column and the sensor= filter, feedback control Phase 1; a database
    without the column, 42703, says to run the database deploy). Tokens are unsigned JWT-shaped strings: the helper reads
    them for display only, config-api verifies them. The DataFrame helpers run when
    pandas is installed (it is in the workbench image), and are skipped otherwise.
  - the lake mode (research sandbox Phase 2b, MEDCEA_LAKE set): medcea_data.py against a
    fake lake-api (PostgREST): mode(), the kept names (sign_in/sign_out a deprecation line,
    whoami without a role), connect() pinning the newest snapshot once, use_snapshot with
    expect= refusing another lineage, the lineage recomputed with the database's rule and a
    snapshot whose lineage does not recompute refused, the measurement window counted back
    from the snapshot's cut (one warning) or start=/end=, the RPC query strings
    (percent-encoded, never quoted), the refusals (22023 says its message, unreachable names
    the lake-api deploy), and with pandas the DataFrames: kept columns plus ingested_at and
    snapshot_id, oldest first, truncated, provenance in attrs["medcea"].
  - the example notebooks: md.connect() (both modes), one chart line per sensor; valid nbformat 4, no outputs or execution counts (what
    nbstripout would leave), ConfigMap-safe names, under 200 KiB (kubectl apply copies
    the ConfigMap into an annotation, and an object's annotations hold 256 KiB).
  - the policy: on version 7, scientists hold R (not X) on measurements; config-api accepts
    the workbench-notebook client (pre_request's azp list) and admits the notebook pods;
    on the factory file since research sandbox 2b's commit B, none of it (the notebooks are
    a research zone pod reaching lake-api).
  - infra/lib-data-volumes.sh against a fake kubectl: lists each claim-<name> and Grafana's
    volume with its directory and how to keep it, says nothing without them, warns when it
    cannot ask.

  python3 tests/test_workbench_data.py
"""
import base64
import datetime
import hashlib
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
                # a database from before migration 010 (the views without sensor)
                ((400, {"code": "42703", "message": "column v_ap_measurements.sensor does not exist"}),
                 "./apps/database/deploy.sh"),
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
        self.assertIn("select=measure_timestamp,unit_code,zone_code,tag,value,unit_of_measurement,sensor&", qs)
        self.assertNotIn("sensor=", qs)                     # every sensor unless one is asked for
        _, params = md.measurement_query("U", "Z", "air_humidity", 5, now=now, sensor="sht45_1")
        self.assertIn("&tag=eq.air_humidity&sensor=eq.sht45_1&", md.query_string(params))
        for bad in (("", "Z", "t", 5), ("U", "Z", "t", 0), ("U", "Z", "t", -1)):
            with self.subTest(bad), self.assertRaises(ValueError):
                md.measurement_query(*bad)

    @unittest.skipUnless(HAVE_PANDAS, "pandas is not installed here (it is in the workbench image)")
    def test_dataframes(self):
        self.signed_in()
        self.fake.queue("/api/v_ap_measurements", (200, [
            {"measure_timestamp": "2026-10-31T11:00:00+00:00", "unit_code": "UNIT01", "zone_code": "ZONE01",
             "tag": "air_temperature", "value": 21.5, "unit_of_measurement": "C", "sensor": "sht45_1"}]))
        df = self.s.measurements("UNIT01", "ZONE01", minutes=60)
        self.assertEqual(list(df.columns), list(md.MEASUREMENT_COLUMNS))
        self.assertEqual(float(df["value"].iloc[0]), 21.5)
        self.assertEqual(df["sensor"].iloc[0], "sht45_1")
        self.fake.queue("/api/cea_zone", (200, [{"zone_id": 3, "unit_id": 1, "zone_code": "ZONE01",
                                                  "zone_description": "", "is_active": "Y"}]))
        self.fake.queue("/api/cea_unit", (200, [{"unit_id": 1, "unit_code": "UNIT01", "description": "", "is_active": "Y"}]))
        self.assertEqual(self.s.zones()["unit_code"].tolist(), ["UNIT01"])
        self.assertFalse(df.attrs["truncated"])

    @unittest.skipUnless(HAVE_PANDAS, "pandas is not installed here (it is in the workbench image)")
    def test_capped_window_warns_and_sorts(self):
        self.signed_in()
        rows = [{"measure_timestamp": "2026-10-31T11:0%d:00+00:00" % m, "unit_code": "UNIT01", "zone_code": "ZONE01",
                 "tag": "air_temperature", "value": m, "unit_of_measurement": "C", "sensor": "default"}
                for m in (2, 1)]
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


# ------------------------------------------------------------------------------ lake ----
SNAPS = [
    {"snapshot_id": 1, "cut_at": "2026-11-18T03:00:00+00:00", "previous_cut_at": None,
     "created_at": "2026-11-18T03:00:05.12+00:00", "contract_version": 1, "rows": {"measurement": 2},
     "digests": {"measurement": "a" * 64, "units": "1" * 64, "zones": "2" * 64}},
    {"snapshot_id": 2, "cut_at": "2026-11-19T03:00:00+00:00", "previous_cut_at": "2026-11-18T03:00:00+00:00",
     "created_at": "2026-11-19T03:00:04+00:00", "contract_version": 1, "rows": {"measurement": 3},
     "digests": {"measurement": "b" * 64, "units": "3" * 64, "zones": "4" * 64}},
]


def with_lineage(snaps, tamper=None):
    """The rows lake_api.snapshots() answers: each with the database's lineage."""
    out, prev = [], ""
    for r in snaps:
        prev = hashlib.sha256((prev + "\n" + r["digests"]["measurement"]).encode()).hexdigest()
        out.append(dict(r, lineage=prev if r["snapshot_id"] != tamper else "f" * 64))
    return out


LAKE_ROW = {"snapshot_id": 2, "ingested_at": "2026-11-18T10:00:01+00:00", "measured_at": "2026-11-18T10:00:00+00:00",
            "unit_code": "UNIT01", "zone_code": "ZONE01", "tag": "air_temperature", "sensor": "sht45_1",
            "value": 21.5, "uom": "C"}


class LakeHelperTest(unittest.TestCase):
    def setUp(self):
        self.fake = Fake()
        self.srv = make_server(self.fake)
        self.base = "http://127.0.0.1:%d/lake" % self.srv.server_address[1]
        self.fake.queue("/lake/rpc/snapshots", (200, with_lineage(SNAPS)))
        self.s = md.LakeSession(lake=self.base)

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def gets(self, fn):
        return [c["path"] for c in self.fake.calls if c["path"].split("?")[0] == "/lake/rpc/" + fn]

    def test_mode_follows_the_environment(self):
        old = os.environ.get("MEDCEA_LAKE")
        try:
            os.environ["MEDCEA_LAKE"] = self.base
            self.assertEqual(md.mode(), "lake")
            os.environ["MEDCEA_LAKE"] = " "
            self.assertEqual(md.mode(), "platform")
            del os.environ["MEDCEA_LAKE"]
            self.assertEqual(md.mode(), "platform")
        finally:
            if old is not None:
                os.environ["MEDCEA_LAKE"] = old

    def test_module_session_follows_the_mode(self):
        old_env, old_session = os.environ.get("MEDCEA_LAKE"), md._session
        try:
            os.environ["MEDCEA_LAKE"] = self.base
            md._session = None
            self.assertIsInstance(md.session(), md.LakeSession)
            self.assertEqual(md.whoami()["role"], None)
            os.environ.pop("MEDCEA_LAKE")
            md._session = None
            self.assertIsInstance(md.session(), md.Session)
            with self.assertRaises(md.AccessError):
                md.snapshots()   # lake-only names refuse on the platform
            with self.assertRaises(ValueError):
                md.measurements("U", "Z", start="2026-11-18")
        finally:
            md._session = old_session
            if old_env is not None:
                os.environ["MEDCEA_LAKE"] = old_env

    def test_kept_names(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertIsNone(self.s.sign_in())
            self.s.sign_out()
        self.assertEqual(len(buf.getvalue().strip().splitlines()), 2)
        self.assertIn("not needed", buf.getvalue())
        self.assertEqual(self.fake.calls, [])   # no Keycloak, nothing asked
        who = self.s.whoami()
        self.assertEqual((who["role"], who["snapshot"]), (None, None))
        self.assertTrue(issubclass(md.SignInError, Exception))

    def test_connect_pins_the_newest_once(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            doc = self.s.connect()
            self.s.connect()
        self.assertEqual(doc["snapshot_id"], 2)
        self.assertTrue(doc["lineage_verified"])
        self.assertIn("Snapshot 2, cut 2026-11-19T03:00:00+00:00 (contract 1), lineage %s (verified)"
                      % with_lineage(SNAPS)[1]["lineage"], buf.getvalue())
        self.assertEqual(len(self.gets("snapshots")), 1)   # resolved once, then kept
        self.assertEqual(self.s.whoami()["snapshot"], 2)
        # a newer snapshot later does not move the pin
        self.fake.set("/lake/rpc/snapshots", (200, with_lineage(SNAPS + [dict(SNAPS[1], snapshot_id=3)])))
        self.assertEqual(self.s.snapshot()["snapshot_id"], 2)

    def test_use_snapshot_and_expect(self):
        lin1 = with_lineage(SNAPS)[0]["lineage"]
        self.assertEqual(self.s.use_snapshot(1, expect=lin1.upper())["snapshot_id"], 1)
        self.assertEqual(self.s.whoami()["snapshot"], 1)
        with self.assertRaises(md.AccessError) as cm:
            self.s.use_snapshot(2, expect=lin1)
        self.assertIn("not the same data", str(cm.exception))
        self.assertEqual(self.s.whoami()["snapshot"], 1)   # a refusal keeps the pin
        with self.assertRaises(md.AccessError) as cm:
            self.s.use_snapshot(9)
        self.assertIn("no snapshot 9", str(cm.exception))

    def test_a_lineage_that_does_not_recompute_is_refused(self):
        self.fake.set("/lake/rpc/snapshots", (200, with_lineage(SNAPS, tamper=2)))
        with self.assertRaises(md.AccessError) as cm:
            self.s.connect()
        self.assertIn("lineage does not recompute", str(cm.exception))
        with self.assertRaises(md.AccessError):
            self.s.use_snapshot(2)
        self.assertEqual(self.s.use_snapshot(1)["snapshot_id"], 1)

    def test_lineage_rule(self):
        chain = md.lineage_chain(list(reversed(SNAPS)))
        prev = ""
        for r in SNAPS:
            prev = hashlib.sha256((prev + "\n" + r["digests"]["measurement"]).encode()).hexdigest()
            self.assertEqual(chain[r["snapshot_id"]], prev)

    def test_no_snapshot_yet(self):
        self.fake.set("/lake/rpc/snapshots", (200, []))
        with self.assertRaises(md.AccessError) as cm:
            self.s.connect()
        self.assertIn("no snapshot yet", str(cm.exception))

    def test_window_counts_back_from_the_cut(self):
        with self.assertWarnsRegex(UserWarning, "count back from the snapshot's cut"):
            doc, params = self.s.measurement_params("UNIT 01", "Z\"1", minutes=90)
        q = dict(params)
        self.assertEqual(q["p_snapshot"], 2)
        self.assertEqual(q["p_to"], "2026-11-19T03:00:00+00:00")
        self.assertEqual(q["p_from"], "2026-11-19T01:30:00+00:00")
        qs = md.query_string([(k, v) for k, v in params if v is not None])
        self.assertIn("p_unit=UNIT%2001", qs)
        self.assertIn("p_zone=Z%221", qs)                 # a quote is a value, never PostgREST quoting
        self.assertIn("p_to=2026-11-19T03%3A00%3A00%2B00%3A00", qs)   # '+' never a space
        self.assertIn("p_tag=air_temperature", qs)
        self.assertIn("p_limit=50000", qs)
        self.assertNotIn("p_sensor", qs)
        import warnings as w
        with w.catch_warnings(record=True) as caught:
            w.simplefilter("always")
            self.s.measurement_params("U", "Z", minutes=5)
        self.assertEqual([c for c in caught if "cut" in str(c.message)], [])   # once per kernel
        # start/end instead: start exclusive, end inclusive, either may be left out
        _, params = self.s.measurement_params("U", "Z", start="2026-11-01", end="2026-11-02T12:00Z", sensor="s1")
        q = dict(params)
        self.assertEqual((q["p_from"], q["p_to"], q["p_sensor"]),
                         ("2026-11-01T00:00:00+00:00", "2026-11-02T12:00:00+00:00", "s1"))
        _, params = self.s.measurement_params("U", "Z", start="2026-11-01T00:00:00+02:00")
        self.assertEqual((dict(params)["p_from"], dict(params)["p_to"]), ("2026-11-01T00:00:00+02:00", None))
        _, params = self.s.measurement_params("U", "Z", snapshot=1, minutes=60)
        self.assertEqual(dict(params)["p_snapshot"], 1)
        self.assertEqual(dict(params)["p_to"], "2026-11-18T03:00:00+00:00")
        for bad in ({"unit": ""}, {"minutes": 0}, {"limit": 0}, {"limit": 50001}):
            with self.subTest(bad), self.assertRaises(ValueError):
                self.s.measurement_params(**dict({"unit": "U", "zone": "Z"}, **bad))

    def test_rpc_and_refusals(self):
        self.fake.queue("/lake/rpc/holds", (200, [{"unit_code": "UNIT01", "zone_code": None,
                                                   "from_at": "2026-12-01T10:00:00+00:00",
                                                   "to_at": "2026-12-01T11:00:00+00:00"}]))
        rows, raw = self.s.rpc("holds")
        self.assertEqual(rows[0]["unit_code"], "UNIT01")
        self.assertEqual(json.loads(raw), rows)
        call = [c for c in self.fake.calls if c["path"] == "/lake/rpc/holds"][0]
        self.assertIsNone(call["auth"])   # no identity, no token
        self.assertEqual(call["method"], "GET")
        self.fake.queue("/lake/rpc/units", (200, []))
        self.s.rpc("units", [("p_snapshot", 2), ("p_x", None)])
        self.assertEqual(self.gets("units")[-1], "/lake/rpc/units?p_snapshot=2")   # None never sent
        for answer, words in (((400, {"code": "22023", "message": "no snapshot 9"}), "no snapshot 9"),
                              ((500, {"code": "57014", "message": "canceling statement due to statement timeout"}),
                               "after 30 s"),
                              ((404, {"code": "PGRST202", "message": "Could not find the function"}),
                               "answered 404")):
            with self.subTest(answer):
                self.fake.set("/lake/rpc/measurements", answer)
                with self.assertRaises(md.AccessError) as cm:
                    self.s.rpc("measurements", [("p_snapshot", 9)])
                self.assertIn(words, str(cm.exception))
                self.assertEqual(cm.exception.status, answer[0])

    def test_unreachable_and_not_configured(self):
        s = md.LakeSession(lake="http://127.0.0.1:9")
        with self.assertRaises(md.AccessError) as cm:
            s.connect()
        self.assertEqual(str(cm.exception), "the lake reader is not reachable (./apps/lake-api/deploy.sh)")
        s = md.LakeSession(lake="")
        s.lake = ""
        with self.assertRaises(md.AccessError) as cm:
            s.rpc("holds")
        self.assertIn("MEDCEA_LAKE", str(cm.exception))

    @unittest.skipUnless(HAVE_PANDAS, "pandas is not installed here (it is in the workbench image)")
    def test_measurements_dataframe(self):
        older = dict(LAKE_ROW, snapshot_id=1, measured_at="2026-11-18T09:00:00+00:00",
                     ingested_at="2026-11-18T09:00:01+00:00", value=20.0)
        self.fake.queue("/lake/rpc/measurements", (200, [LAKE_ROW, older]))
        with warnings_ok():
            df = self.s.measurements("UNIT01", "ZONE01", minutes=60 * 24, limit=2)
        self.assertEqual(list(df.columns), list(md.MEASUREMENT_COLUMNS) + ["ingested_at", "snapshot_id"])
        self.assertEqual(df["value"].tolist(), [20.0, 21.5])   # oldest first
        self.assertEqual(df["unit_of_measurement"].tolist(), ["C", "C"])
        self.assertTrue(df.attrs["truncated"])
        p = md.provenance(df)
        self.assertEqual((p["snapshot_id"], p["contract_version"], p["set"], p["set_digest"]),
                         (2, 1, "measurement", "b" * 64))
        self.assertEqual(p["lineage"], with_lineage(SNAPS)[1]["lineage"])
        self.assertTrue(p["lineage_verified"])
        self.assertEqual(p["query"]["function"], "measurements")
        self.assertEqual(p["query"]["params"]["p_unit"], "UNIT01")
        raw = json.dumps([LAKE_ROW, older]).encode()   # what the fake sent, byte for byte
        self.assertEqual(p["response_sha256"], hashlib.sha256(raw).hexdigest())

    @unittest.skipUnless(HAVE_PANDAS, "pandas is not installed here (it is in the workbench image)")
    def test_units_and_zones_lose_their_ids(self):
        self.fake.queue("/lake/rpc/units", (200, [{"snapshot_id": 2, "unit_code": "UNIT01", "recipe_type": "FUNGI",
                                                   "area": 1.5, "height": 2, "is_active": "Y"}]))
        self.fake.queue("/lake/rpc/zones", (200, [{"snapshot_id": 2, "unit_code": "UNIT01", "zone_code": "ZONE01",
                                                   "is_active": "Y"}]))
        with self.assertWarnsRegex(UserWarning, "not the platform's ids"):
            u = self.s.units()
        self.assertNotIn("unit_id", u.columns)
        self.assertEqual(u["recipe_type"].tolist(), ["FUNGI"])
        z = self.s.zones()
        self.assertEqual(list(z.columns), ["unit_code", "zone_code", "is_active", "snapshot_id"])
        self.assertEqual(md.provenance(z)["set_digest"], "4" * 64)
        self.assertEqual(self.gets("zones")[-1], "/lake/rpc/zones?p_snapshot=2")


def warnings_ok():
    """Warnings off for one block (a capped window warns)."""
    import contextlib
    import warnings as w

    @contextlib.contextmanager
    def ctx():
        with w.catch_warnings():
            w.simplefilter("ignore")
            yield
    return ctx()

class ExamplesTest(unittest.TestCase):
    def test_notebooks_are_stripped(self):
        names = sorted(os.listdir(EXAMPLES))
        self.assertEqual([n for n in names if not n.startswith("__")],
                         ["01-connect.ipynb", "02-air-temperature.ipynb", "03-agent-campaign.ipynb", "04-agent-other-session.ipynb",
                          "SAVE_TO_GIT.md", "medcea_agent.py", "medcea_data.py",
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

    def test_agent_notebooks_use_the_client_as_it_is(self):
        # 03/04 (exercise E48): every Client method they call exists, and their code compiles
        import ast
        import importlib.util
        spec = importlib.util.spec_from_file_location("nb_medcea_agent", os.path.join(EXAMPLES, "medcea_agent.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for n in ("03-agent-campaign.ipynb", "04-agent-other-session.ipynb"):
            with open(os.path.join(EXAMPLES, n)) as f:
                code = "\n".join("".join(c["source"]) for c in json.load(f)["cells"] if c["cell_type"] == "code")
            tree = ast.parse(code)
            used = {x.attr for x in ast.walk(tree) if isinstance(x, ast.Attribute)
                    and isinstance(x.value, ast.Name) and x.value.id in ("c", "Client")}
            self.assertTrue(used)
            self.assertEqual(sorted(m for m in used if not hasattr(mod.Client, m)), [], n)

    def test_notebooks_connect_in_both_modes(self):
        for n in ("01-connect.ipynb", "02-air-temperature.ipynb"):
            with open(os.path.join(EXAMPLES, n)) as f:
                code = "\n".join("".join(c["source"]) for c in json.load(f)["cells"] if c["cell_type"] == "code")
            self.assertIn("md.connect()", code, n)
            self.assertNotIn("md.sign_in()", code, n)   # connect() signs in on the platform
        with open(os.path.join(EXAMPLES, "01-connect.ipynb")) as f:
            code = "\n".join("".join(c["source"]) for c in json.load(f)["cells"] if c["cell_type"] == "code")
        self.assertIn("md.units()", code)
        with open(os.path.join(EXAMPLES, "02-air-temperature.ipynb")) as f:
            code = "\n".join("".join(c["source"]) for c in json.load(f)["cells"] if c["cell_type"] == "code")
        self.assertIn("prov = md.provenance(df)", code)   # the title names the snapshot in the lake
        self.assertIn("snapshot {prov['snapshot_id']}", code)
        with open(os.path.join(EXAMPLES, "SAVE_TO_GIT.md")) as f:
            text = f.read()
        self.assertIn("person-free snapshots", text)
        self.assertIn("you hold read access, not export", text)

    def test_chart_settings_on_top(self):
        with open(os.path.join(EXAMPLES, "02-air-temperature.ipynb")) as f:
            cells = json.load(f)["cells"]
        first_code = "".join(next(c for c in cells if c["cell_type"] == "code")["source"])
        for var in ("UNIT =", "ZONE =", "MINUTES =", "SENSOR ="):
            self.assertIn(var, first_code)

    def test_chart_one_line_per_sensor(self):
        # two sensors of one tag (SHT45 and SCD30) never become one zig-zag line
        with open(os.path.join(EXAMPLES, "02-air-temperature.ipynb")) as f:
            code = "\n".join("".join(c["source"]) for c in json.load(f)["cells"] if c["cell_type"] == "code")
        self.assertIn('for name, part in df.groupby("sensor"):', code)
        self.assertIn("sensor=SENSOR", code)
        self.assertNotIn('ax.plot(df["measure_timestamp"]', code)


class PolicyTest(unittest.TestCase):
    """The platform path (IAM 3.2b) on version 7's policy (tests/rs2b_fixture.py v7_policy),
    which the live host runs until research sandbox Phase 2b's skeleton version; and the
    factory file since commit B: no notebooks client, the scientists' telemetry gone
    (the change version's cells), the notebooks a research zone pod reaching lake-api."""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, os.path.join(REPO, "tests"))
        import rs2b_fixture
        cls.p = model.Policy(rs2b_fixture.v7_policy())
        cls.b = model.load_defaults()

    def test_scientists_read_telemetry(self):
        for r in ("bio_scientist", "control_scientist"):
            self.assertEqual(self.p.effective("measurements", r), {"R"}, r)
            self.assertEqual(self.b.effective("measurements", r), set(), r)   # commit B's factory cells

    def test_config_api_accepts_notebooks(self):
        self.assertIn(CLIENT, grants.token_clients(self.p))
        self.assertIn("'workbench-notebook'", grants.compiled_functions(self.p))
        nb = {"podSelector": {"matchLabels": {"app": "jupyterhub", "component": "singleuser-server",
                                              "release": "workbench"}}}
        for p, there in ((self.p, True), (self.b, False)):
            np = netpol.compile(p, "medcea", ["10.0.0.1"])
            api = next(i for i in np["items"] if i["metadata"]["name"] == "iam-config-api")
            peers = [peer for rule in api["spec"]["ingress"] for peer in rule["from"]]
            self.assertEqual(nb in peers, there)
        self.assertNotIn(CLIENT, grants.token_clients(self.b))
        self.assertNotIn("'workbench-notebook'", grants.compiled_functions(self.b))

    def test_egress_is_the_two_hops(self):
        self.assertEqual(netpol.egress(self.p, "notebooks"), [
            {"to": [{"podSelector": {"matchLabels": {"app": "config-api"}}}], "ports": [{"protocol": "TCP", "port": 3000}]},
            {"to": [{"podSelector": {"matchLabels": {"app": "keycloak"}}}], "ports": [{"protocol": "TCP", "port": 8080}]}])
        with self.assertRaises(ValueError):
            netpol.egress(self.p, "nobody")
        with self.assertRaises(ValueError):   # commit B: no notebooks client
            netpol.egress(self.b, "notebooks")

    def test_commit_b_notebooks_reach_the_lake(self):
        pod = self.b.data["network"]["pods"]["notebooks"]
        self.assertEqual(pod["zone"], "research")
        self.assertIn({"pod": "lake-api", "port": 3000}, [{k: v for k, v in h.items() if k != "why"}
                                                          for h in pod["egress"]])
        self.assertNotIn("config-api", json.dumps(pod))


class HomesTest(unittest.TestCase):
    def run_warn(self, kubectl_body, backup_dir=None, **env):
        d = tempfile.mkdtemp()
        k = os.path.join(d, "kubectl")
        with open(k, "w") as f:
            f.write("#!/bin/sh\n" + kubectl_body + "\n")
        os.chmod(k, 0o755)
        # An empty BACKUP_DIR of its own unless given: never the host's /var/backups.
        if backup_dir is None:
            backup_dir = os.path.join(d, "no-backups")
            os.makedirs(backup_dir)
        r = subprocess.run(["bash", "-c", f'source "{REPO}/infra/lib-data-volumes.sh"; data_volumes_warn medcea; echo "rc=$?"'],
                           env=dict({k_: v for k_, v in os.environ.items() if k_ != "RESEARCH_NAMESPACE"},
                                    KUBECTL=k, BACKUP_DIR=backup_dir, **env), capture_output=True, text=True)
        return r.stdout

    BOTH = json.dumps({"items": [
        {"metadata": {"name": "claim-bio1"}, "spec": {"volumeName": "pvc-1"}, "status": {"capacity": {"storage": "10Gi"}}},
        {"metadata": {"name": "grafana"}, "spec": {"volumeName": "pvc-g"}, "status": {"capacity": {"storage": "2Gi"}}}]})

    def backup_fixture(self, ok):
        b = tempfile.mkdtemp()
        os.makedirs(os.path.join(b, "20261102-023000Z"))
        if ok:
            with open(os.path.join(b, "20261102-023000Z", "OK"), "w") as f:
                f.write("1793586600 2026-11-02T02:30:00Z started 20261102-023000Z\n")
        return b

    def test_names_newest_backup(self):
        """The sourcing of ../apps/backup/lib-backup.sh works: a moved file or a renamed
        backup_newest_ok would silently fall back to 'nothing backs'."""
        b = self.backup_fixture(ok=True)
        out = self.run_warn(f"""case "$*" in "get pvc -n medcea -o json") echo '{self.BOTH}' ;; *) exit 1 ;; esac""", b)
        want = f"newest nightly backup: 20261102-023000Z in {b}, which this keeps"
        self.assertIn(f"AI workbench homes that this deletes ({want})", out)
        self.assertIn(f"Grafana's volume, which this deletes ({want})", out)
        self.assertNotIn("nothing backs", out)

    def test_incomplete_backup_is_none(self):
        b = self.backup_fixture(ok=False)
        out = self.run_warn(f"""case "$*" in "get pvc -n medcea -o json") echo '{self.BOTH}' ;; *) exit 1 ;; esac""", b)
        self.assertIn("AI workbench homes that this deletes (nothing backs them up)", out)
        self.assertIn("Grafana's volume, which this deletes (nothing backs it up)", out)
        self.assertNotIn("newest nightly backup", out)

    def test_confirmations_do_not_deny_the_backup(self):
        """The fixed text before data_volumes_warn must not say 'not backed up' while
        the warning under it may name a backup this keeps."""
        for path in ("install.sh", "deploy-infra.sh"):
            with open(os.path.join(REPO, path)) as f:
                src = f.read()
            self.assertNotIn("neither backed up", src, path)
            self.assertNotIn("neither is backed up", src, path)
            self.assertNotIn("nothing backs", src, path)
        with open(os.path.join(REPO, "install.sh")) as f:
            inst = f.read()
        fn = inst[inst.index("data_volumes() {"):]
        fn = fn[:fn.index("\n}\n")]
        # BACKUP_DIR comes from config.env, sourced in a subshell around the warning.
        self.assertRegex(fn, r"\(\s*\[\[ -f config\.env \]\] && source \./config\.env\s+KUBECTL=\"\$k\" data_volumes_warn")

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
        self.assertNotIn("Grafana", out)
        self.assertTrue(out.rstrip().endswith("rc=0"))

    def test_lists_grafana(self):
        pvcs = json.dumps({"items": [
            {"metadata": {"name": "grafana"}, "spec": {"volumeName": "pvc-g"}, "status": {"capacity": {"storage": "2Gi"}}},
            {"metadata": {"name": "grafana-other"}, "spec": {"volumeName": "pvc-x"}}]})
        out = self.run_warn(f"""case "$*" in
  "get pvc -n medcea -o json") echo '{pvcs}' ;;
  "get pv pvc-g -o jsonpath={{.spec.hostPath.path}}") printf /var/snap/microk8s/common/default-storage/medcea-grafana-pvc-g ;;
  *) exit 1 ;;
esac""")
        self.assertIn("Grafana's volume", out)
        self.assertIn("grafana (2Gi), on this host in /var/snap/microk8s/common/default-storage/medcea-grafana-pvc-g", out)
        self.assertIn("Export", out)
        self.assertNotIn("grafana-other", out)
        self.assertNotIn("AI workbench homes", out)
        self.assertTrue(out.rstrip().endswith("rc=0"))

    def test_names_superset_database(self):
        # Superset (stage B): its metadata database sits inside PostgreSQL's volume
        out = self.run_warn("""case "$*" in
  "get pvc -n medcea -o json") echo '{"items": []}' ;;
  "get deployment superset -n medcea -o name") echo deployment.apps/superset ;;
  *) exit 1 ;;
esac""")
        self.assertIn("Superset's database, which this deletes (nothing backs it up)", out)
        self.assertIn("database superset, inside PostgreSQL's volume (data-rdbms-postgresql-0)", out)
        self.assertIn("db/superset.dump", out)
        self.assertNotIn("AI workbench homes", out)
        self.assertNotIn("Grafana's volume", out)
        self.assertTrue(out.rstrip().endswith("rc=0"))
        # with homes too, and a backup named
        b = self.backup_fixture(ok=True)
        out = self.run_warn(f"""case "$*" in
  "get pvc -n medcea -o json") echo '{self.BOTH}' ;;
  "get deployment superset -n medcea -o name") echo deployment.apps/superset ;;
  *) exit 1 ;;
esac""", b)
        self.assertIn("AI workbench homes that this deletes", out)
        self.assertIn("Superset's database, which this deletes (newest nightly backup: 20261102-023000Z", out)

    def test_no_superset_no_words(self):
        for body in ("echo '{\"items\": []}'",
                     'case "$*" in "get deployment superset -n medcea -o name") echo "Error from server (NotFound)" >&2; exit 1 ;; *) echo \'{"items": []}\' ;; esac'):
            out = self.run_warn(body)
            self.assertNotIn("Superset", out, body)
        out = self.run_warn("exit 1")
        self.assertIn("database superset, inside PostgreSQL", out)

    def test_no_homes_no_words(self):
        self.assertEqual(self.run_warn("""echo '{"items": []}'""").strip(), "rc=0")

    def test_cannot_ask(self):
        out = self.run_warn("exit 1")
        self.assertIn("Could not list the AI workbench homes", out)
        self.assertIn("Grafana's volume", out)
        self.assertTrue(out.rstrip().endswith("rc=0"))

    RS_PVC = """  "get pvc data-research-postgresql-0 -n medcea-research "*) printf 'pvc-r\\t10Gi' ;;
  "get pv pvc-r -o jsonpath={.spec.hostPath.path}") printf /var/snap/microk8s/common/default-storage/medcea-research-data-research-postgresql-0-pvc-r ;;
"""

    def test_names_the_research_database(self):
        """Research sandbox (Phase 2a): the research database's volume, in RESEARCH_NAMESPACE,
        is named after the platform's, alone or with homes; also when the platform's list
        cannot be read."""
        for platform, has_homes in (("""  "get pvc -n medcea -o json") echo '{"items": []}' ;;\n""", False),
                                    ("""  "get pvc -n medcea -o json") echo '%s' ;;\n""" % self.BOTH, True),
                                    ("", False)):
            with self.subTest(homes=has_homes, platform=bool(platform)):
                out = self.run_warn('case "$*" in\n' + platform + self.RS_PVC + "  *) exit 1 ;;\nesac",
                                    RESEARCH_NAMESPACE="medcea-research")
                self.assertIn("The research database's volume, which this deletes (nothing backs it up)", out)
                self.assertIn("data-research-postgresql-0 (10Gi) in namespace medcea-research, on this host in "
                              "/var/snap/microk8s/common/default-storage/medcea-research-data-research-postgresql-0-pvc-r", out)
                self.assertIn("medcea_research", out)
                self.assertEqual("AI workbench homes that this deletes" in out, has_homes)
                if has_homes:
                    self.assertLess(out.index("Grafana's volume"), out.index("The research database's volume"))
                self.assertTrue(out.rstrip().endswith("rc=0"))

    def test_no_research_no_words(self):
        """No such claim, no RESEARCH_NAMESPACE, or one equal to the platform's: nothing said."""
        body = 'case "$*" in\n  "get pvc -n medcea -o json") echo \'{"items": []}\' ;;\n  *) exit 1 ;;\nesac'
        for env in ({}, {"RESEARCH_NAMESPACE": "medcea-research"}, {"RESEARCH_NAMESPACE": "medcea"}):
            with self.subTest(env=env):
                self.assertEqual(self.run_warn(body, **env).strip(), "rc=0")
        out = self.run_warn('case "$*" in\n  "get pvc -n medcea -o json") echo \'{"items": []}\' ;;\n' + self.RS_PVC
                            + "  *) exit 1 ;;\nesac", RESEARCH_NAMESPACE="medcea")
        self.assertNotIn("research database", out)

    def test_every_uninstall_path_warns_before_it_asks(self):
        with open(os.path.join(REPO, "deploy-infra.sh")) as f:
            infra = f.read()
        for branch, ask in (('"--uninstall" ]]', "Type 'yes' to confirm uninstall"), ('"--reset" ]]', "Type 'reset' to confirm")):
            part = infra[infra.index(branch):]
            self.assertLess(part.index("data_volumes_warn"), part.index(ask), branch)
        with open(os.path.join(REPO, "install.sh")) as f:
            inst = f.read()
        for branch, ask in (("uninstall-infra)\n", "confirm reset"), ("uninstall-all)\n", "confirm uninstall")):
            part = inst[inst.rindex(branch):]
            self.assertLess(part.index("data_volumes "), part.index(ask), branch)
        with open(os.path.join(REPO, "infra", "bootstrap-infra.sh")) as f:
            boot = f.read()
        part = boot[boot.index("MICROK8S RESET LOGIC"):]
        self.assertLess(part.index("data_volumes_warn"), part.index("Fully wipe MicroK8s"), "bootstrap wipe")


if __name__ == "__main__":
    unittest.main()
