#!/usr/bin/env python3
"""tests/test_wizard_test_message.py — the wizard's Send test message, offline.

POST /api/test-message runs edge/src/host/mqtt_test.py as the board the last run
onboarded. Here mqtt_test.py is a stub script (wizard_server.MQTT_TEST points at
it) that records its argv and prints the result its test asks for, the record
directory is a mktemp dir (PROVISIONED_DIR), and Keycloak is test_edge_auth's
FakeKC. Covers the guards (JSON, Origin, sign-in, run owner, run id, a finished
run with a registered board, the rate limit, the role re-check), the board taken
from the run and never from the request, no secret on argv, and 200/502.

    python3 -m unittest tests.test_wizard_test_message
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_edge_auth as tea  # noqa: E402  (FakeKC, tokens, load_wizard)

MQTT_PW = "MQTT-PW-never-on-argv"
SECRETS = (MQTT_PW, "WIFI-PSK-secret", "WEBREPL-secret")

STUB = r'''#!/usr/bin/env python3
import json, os, sys, time
here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "argv.json"), "w") as f:
    json.dump(sys.argv[1:], f)
mode = open(os.path.join(here, "mode")).read().strip()
if mode == "slow":
    time.sleep(10)
if mode == "ok":
    print(json.dumps({"ok": True, "topic": "medcea/UNIT01/ZONE01/sense/_test",
                      "client_id": "unit01-s-zone01-test-ab12",
                      "timestamp": "2026-11-06 12:00:00", "msg_type": "TS",
                      "password": "MQTT-PW-never-on-argv"}))
    sys.exit(0)
if mode == "noise":
    print("not json")
    sys.exit(1)
print(json.dumps({"ok": False, "error": "not authorised"}))
sys.exit(1)
'''


class TestMessage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = tea.load_wizard()

    def setUp(self):
        self.kc = tea.FakeKC()
        self.kc.token = lambda form: (200, tea.token_response(roles=("engineer",)))
        self.tmp = tempfile.mkdtemp()
        self.spool = os.path.join(self.tmp, "spool")
        self.prov = os.path.join(self.tmp, "provisioned")
        self.stubdir = os.path.join(self.tmp, "stub")
        for d in (self.spool, self.prov, self.stubdir):
            os.mkdir(d)
        self.stub = os.path.join(self.stubdir, "mqtt_test.py")
        with open(self.stub, "w") as f:
            f.write(STUB)
        self.mode("ok")
        self.saved = {k: getattr(self.ws, k) for k in
                      ("MQTT_TEST", "PROVISIONED_DIR", "TEST_MSG_TIMEOUT", "TEST_MSG_GAP")}
        self.ws.MQTT_TEST = self.stub
        self.ws.PROVISIONED_DIR = self.prov
        S = self.ws.STATE
        S.update({"dir": self.spool, "auth": "keycloak", "oidc": self.kc.oidc(),
                  "client_id": tea.CLIENT, "client_secret": tea.SECRET, "ssl_ctx": None,
                  "required_role": tea.edge_auth.roles_of("engineer"), "repo_root": self.tmp, "flash_args": [],
                  "run": None, "run_auth": None, "token": "tok",
                  "run_owner": {"sub": "u-alice", "user": "alice"},
                  "sessions": {}, "pending": {}, "daemon": True, "catalog": [],
                  "hosts": {}, "run_id": "r1", "test_sent": None})
        self.record = self.board("unit01-s-zone01")
        self.finish(self.record)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), self.ws.Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.srv.server_address[1]

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        for k, v in self.saved.items():
            setattr(self.ws, k, v)
        r = self.ws.STATE["run"]
        if r is not None:
            if r.poll() is None:
                r.kill()
            r.wait()
        self.kc.shutdown()
        self.kc.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- fixtures ----
    def mode(self, m):
        with open(os.path.join(self.stubdir, "mode"), "w") as f:
            f.write(m)

    def board(self, dns, state="REGISTERED", role="SENSE", mqtt=True, where=None):
        rec = {"state": state, "role": role, "hostname": dns, "unit_code": "UNIT01",
               "zone_code": "ZONE01", "mac": "aa:bb:cc:dd:ee:ff", "ip_at_provision": "10.0.0.9",
               "micropython": "1.24.1", "wifi_psk": SECRETS[1], "webrepl_password": SECRETS[2],
               "mqtt": {"host": "192.168.1.10", "port": 31884, "tls_name": "mqtt.medcea",
                        "topic_root": "medcea", "username": dns, "password": MQTT_PW}
               if mqtt else None}
        path = os.path.join(where or self.prov, dns + ".json")
        with open(path, "w") as f:
            json.dump(rec, f)
        return path

    def finish(self, record, rc="0"):
        with open(os.path.join(self.spool, "done.json"), "w") as f:
            json.dump({"title": "Board is up", "fields": [["hostname", "x", True],
                                                          ["record", record, False]]}, f)
        with open(os.path.join(self.spool, "finished"), "w") as f:
            f.write(rc)

    def session(self, sub="u-alice", user="alice"):
        ts = tea.tokenset(sub=sub, user=user, roles=("engineer",))
        return self.ws.new_session({"sub": sub, "preferred_username": user}, "idtok", ts)

    def post(self, sid, body, ctype="application/json", origin=True, path="/api/test-message"):
        h = {"Content-Type": ctype}
        if sid:
            h["Cookie"] = "%s=%s" % (self.ws.COOKIE, sid)
        if origin is True:
            h["Origin"] = self.base
        elif origin:
            h["Origin"] = origin
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), headers=h)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            with e:
                raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, {"raw": raw.decode("utf-8", "replace")}

    def argv(self):
        p = os.path.join(self.stubdir, "argv.json")
        if not os.path.exists(p):
            return None
        with open(p) as f:
            return json.load(f)

    def state(self, sid):
        req = urllib.request.Request(self.base + "/api/state",
                                     headers={"Cookie": "%s=%s" % (self.ws.COOKIE, sid)})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())

    # ---- tests ----
    def test_the_owner_sends_as_the_runs_board(self):
        alice = self.session()
        # A name or a path in the request is ignored: the board is the run's.
        status, res = self.post(alice, {"run": "r1", "record": "/etc/passwd",
                                        "board": "unit09-s-zone09"})
        self.assertEqual(status, 200, res)
        self.assertEqual(res, {"ok": True, "topic": "medcea/UNIT01/ZONE01/sense/_test",
                               "client_id": "unit01-s-zone01-test-ab12",
                               "timestamp": "2026-11-06 12:00:00", "msg_type": "TS"})
        argv = self.argv()
        self.assertIn("--record=" + os.path.realpath(self.record), argv)
        self.assertIn("--host=192.168.1.10", argv)
        self.assertIn("--port=31884", argv)
        self.assertIn("--tls-name=mqtt.medcea", argv)
        self.assertIn("--source=wizard", argv)
        self.assertTrue(any(a.startswith("--ca=") and a.endswith(os.path.join(".ca", "ca.crt"))
                            for a in argv), argv)
        for s in SECRETS:
            self.assertNotIn(s, json.dumps(argv))
        # The forced refresh re-checked the role on the session's token.
        self.assertEqual([f["grant_type"] for p, f in self.kc.calls if p == "/token"],
                         ["refresh_token"])

    def test_a_failed_send_is_502_with_its_reason(self):
        self.mode("fail")
        status, res = self.post(self.session(), {"run": "r1"})
        self.assertEqual((status, res), (502, {"ok": False, "error": "not authorised"}))
        self.ws.STATE["test_sent"] = None
        self.mode("noise")
        status, res = self.post(self.session(), {"run": "r1"})
        self.assertEqual(status, 502)
        self.assertIn("no result (exit 1)", res["error"])

    def test_a_sender_that_hangs_is_cut_off(self):
        self.ws.TEST_MSG_TIMEOUT = 1
        self.mode("slow")
        t = time.time()
        status, res = self.post(self.session(), {"run": "r1"})
        self.assertEqual(status, 502)
        self.assertIn("no answer within 1 s", res["error"])
        self.assertLess(time.time() - t, 8)

    def test_another_session_is_403(self):
        bob = self.session(sub="u-bob", user="bob")
        status, res = self.post(bob, {"run": "r1"})
        self.assertEqual(status, 403)
        self.assertIn("belongs to alice", res["error"])
        self.assertIsNone(self.argv())
        self.assertFalse(self.state(bob)["test_message"])
        self.assertTrue(self.state(self.session())["test_message"])

    def test_a_run_that_acted_for_nobody_has_no_sender(self):
        self.ws.STATE["run_owner"] = None
        status, res = self.post(self.session(), {"run": "r1"})
        self.assertEqual(status, 403)
        self.assertIsNone(self.argv())

    def test_unauthenticated_is_refused_as_elsewhere(self):
        status, _ = self.post(None, {"run": "r1"})
        self.assertEqual(status, 401)
        self.ws.STATE["auth"] = "token"
        status, _ = self.post(None, {"run": "r1"})                 # no ?t=
        self.assertEqual(status, 403)
        status, res = self.post(None, {"run": "r1"}, path="/api/test-message?t=tok")
        self.assertEqual(status, 200, res)

    def test_json_and_same_origin_only(self):
        alice = self.session()
        self.assertEqual(self.post(alice, {"run": "r1"}, ctype="text/plain")[0], 415)
        self.assertEqual(self.post(alice, {"run": "r1"}, origin=None)[0], 403)
        self.assertEqual(self.post(alice, {"run": "r1"}, origin="http://evil.example")[0], 403)
        self.assertIsNone(self.argv())
        # Behind the TLS ingress the origin is the registered https name.
        self.ws.STATE["hosts"] = {"onboard.medcea": "https"}
        req = urllib.request.Request(self.base + "/api/test-message",
                                     data=b'{"run":"r1"}',
                                     headers={"Content-Type": "application/json",
                                              "Host": "onboard.medcea",
                                              "Origin": "https://onboard.medcea",
                                              "Cookie": "%s=%s" % (self.ws.COOKIE, alice)})
        with urllib.request.urlopen(req, timeout=30) as r:
            self.assertEqual(r.status, 200)

    def test_wrong_run_is_409(self):
        alice = self.session()
        for body in ({"run": "r0"}, {}, ["r1"]):
            self.assertEqual(self.post(alice, body)[0], 409, body)
        self.assertIsNone(self.argv())

    def test_only_after_the_run_finished_a_registered_board(self):
        alice = self.session()
        self.finish(self.record, rc="1")
        self.assertEqual(self.post(alice, {"run": "r1"})[0], 409)
        os.unlink(os.path.join(self.spool, "finished"))
        self.assertEqual(self.post(alice, {"run": "r1"})[0], 409)
        self.finish(self.board("cea-un-aabbcc", state="UNREGISTERED", mqtt=False))
        self.assertEqual(self.post(alice, {"run": "r1"})[0], 409)
        # a record outside edge/provisioned, or named for another board
        other = os.path.join(self.tmp, "elsewhere")
        os.mkdir(other)
        self.finish(self.board("unit01-s-zone01", where=other))
        self.assertEqual(self.post(alice, {"run": "r1"})[0], 409)
        renamed = os.path.join(self.prov, "unit02-s-zone01.json")
        shutil.copy(self.record, renamed)
        self.finish(renamed)
        status, res = self.post(alice, {"run": "r1"})
        self.assertEqual(status, 409)
        self.assertIn("not registered", res["error"])
        # a run still going
        self.finish(self.record)
        self.ws.STATE["run"] = subprocess.Popen(["sleep", "30"])
        status, res = self.post(alice, {"run": "r1"})
        self.assertEqual((status, res["error"]), (409, "the run is still going"))
        self.assertFalse(self.state(alice)["test_message"])
        self.assertIsNone(self.argv())

    def test_one_per_five_seconds_per_run(self):
        alice = self.session()
        self.assertEqual(self.post(alice, {"run": "r1"})[0], 200)
        status, res = self.post(alice, {"run": "r1"})
        self.assertEqual(status, 429)
        self.assertIn("every 5 s", res["error"])
        self.ws.STATE["test_sent"] = ("r1", time.time() - 6)
        self.assertEqual(self.post(alice, {"run": "r1"})[0], 200)

    def test_a_lost_role_is_403_and_ends_the_session(self):
        self.kc.token = lambda form: (200, tea.token_response(roles=()))
        alice = self.session()
        status, res = self.post(alice, {"run": "r1"})
        self.assertEqual(status, 403)
        self.assertIn("'engineer'", res["error"])
        self.assertNotIn(alice, self.ws.STATE["sessions"])
        self.assertIsNone(self.argv())

    def test_an_ended_keycloak_session_is_401(self):
        self.kc.token = lambda form: (400, {"error": "invalid_grant"})
        alice = self.session()
        self.assertEqual(self.post(alice, {"run": "r1"})[0], 401)
        self.assertNotIn(alice, self.ws.STATE["sessions"])
        self.assertIsNone(self.argv())

    def test_a_refused_check_does_not_use_up_the_slot(self):
        # A 401 or 403 sent nothing, so it must not hold back the attempt after the
        # page signed in again (silent SSO: the same person, a new session).
        for refusal, status in (((400, {"error": "invalid_grant"}), 401),
                                ((200, tea.token_response(roles=())), 403)):
            with self.subTest(status=status):
                self.ws.STATE["test_sent"] = None
                self.kc.token = lambda form, r=refusal: r
                self.assertEqual(self.post(self.session(), {"run": "r1"})[0], status)
                self.assertIsNone(self.ws.STATE["test_sent"])
                self.kc.token = lambda form: (200, tea.token_response(roles=("engineer",)))
                self.assertEqual(self.post(self.session(), {"run": "r1"})[0], 200)
                self.assertIsNotNone(self.argv())
                os.unlink(os.path.join(self.stubdir, "argv.json"))

    def test_the_page_offers_the_button_and_escapes_the_result(self):
        page = self.ws.PAGE
        self.assertIn('id="ptest"', page)
        self.assertIn('"/api/test-message"', page)
        # The result is set as text, never as markup.
        i = page.index('$("ptest").onclick')
        block = page[i:page.index("function send()", i)]
        self.assertNotIn("innerHTML", block)
        self.assertIn("textContent", block)
        # renderPrompt's guard against re-mounting under the poll is still there.
        self.assertIn("if (p.id === curId) return;", page)


if __name__ == "__main__":
    unittest.main()
