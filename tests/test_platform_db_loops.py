#!/usr/bin/env python3
"""edge/src/host/platform_db.py's control-loop calls (feedback control Phase 2, Q19, Q20),
offline against a local stand-in for config-api: `loops ZONE_ID` (medcea.zone_loop_context)
and `save-loops ZONE_ID` (medcea.save_zone_loops, every loop the zone keeps), the bodies
they send, the person's token as Bearer under IAM_POSTGREST_JWT=true, and the refusals
mapped by SQLSTATE: 42501 refused whatever the HTTP status (config-api answers it 401 in both
IAM_DB_ROLES modes: the request's PostgREST role is anon either way, so flash-device words it from
config.env and the person's role, D-b/D-c), PGRST202/404/55000 not deployed, 55006 busy in words,
22023 the problem list. The texts are the migration's.

    python3 -m unittest tests.test_platform_db_loops
"""
import base64
import importlib.util
import json
import os
import re
import subprocess
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PDB = os.path.join(ROOT, "edge", "src", "host", "platform_db.py")
MIGRATIONS = os.path.join(ROOT, "apps", "database", "medcea_db_migrations.sql")


def load():
    spec = importlib.util.spec_from_file_location("platform_db_loops_t", PDB)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class Fake:
    """config-api: answers from a queue, records every request."""

    def __init__(self):
        self.answers, self.seen = [], []
        fake = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                fake.seen.append({"path": self.path, "auth": self.headers.get("Authorization"),
                                  "body": json.loads(self.rfile.read(n) or b"null")})
                status, body = fake.answers.pop(0)
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.srv.server_address[1]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def err(code, message, details=None):
    return {"code": code, "message": message, "details": details, "hint": None}


CONTEXT = {"zone_id": 3, "zone_code": "ZONE01", "unit_id": 1, "unit_code": "UNIT01", "active": True,
           "deployed": True, "busy": None, "sensors": [], "old_boards": [], "sensor_problems": [],
           "actuators": [], "loops": [], "allowed": {}}


def token(user="eng", exp=None):
    def b(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return "%s.%s.sig" % (b({"alg": "RS256"}), b({"preferred_username": user, "exp": exp or time.time() + 300}))


class ZoneLoops(unittest.TestCase):
    def setUp(self):
        self.fake = Fake()
        self.addCleanup(self.fake.close)
        self.m = load()
        os.environ.pop("IAM_POSTGREST_JWT", None)

    def test_reads_the_context(self):
        self.fake.answers.append((200, CONTEXT))
        out = self.m.zone_loops(self.fake.base, 3)
        self.assertEqual(out, {"state": "ok", "why": "", "context": CONTEXT})
        self.assertEqual(self.fake.seen, [{"path": "/rpc/zone_loop_context", "auth": None, "body": {"p_zone_id": 3}}])

    def test_table_missing(self):
        self.fake.answers.append((200, dict(CONTEXT, deployed=False)))
        self.assertEqual(self.m.zone_loops(self.fake.base, 3)["state"], "not_deployed")

    def assertState(self, status, body, state, words):
        self.fake.answers.append((status, body))
        out = self.m.zone_loops(self.fake.base, 3)
        self.assertEqual(out["state"], state)
        self.assertIn(words, out["why"])
        return out

    def test_refusals_by_sqlstate(self):
        self.assertState(404, err("PGRST202", "Could not find the function medcea.zone_loop_context(p_zone_id)"),
                         "not_deployed", "./apps/database/deploy.sh")
        # 42501 is 401 in both IAM_DB_ROLES modes (anon is the PostgREST role either way):
        # one state, never decided on the status; flash-device words it (D-b, D-c).
        for status in (401, 403):
            a = self.assertState(status, err("42501", "permission denied for function zone_loop_context"),
                                 "refused", "permission denied for function zone_loop_context")
            b = self.assertState(status, err("42501", "zone_loop_context: role maintenance holds no U on master_data"),
                                 "refused", "holds no U on master_data")
            self.assertNotIn("IAM_DB_ROLES", a["why"] + b["why"])
            self.assertState(status, err("42501", "zone_loop_context: a person's own token is required"),
                             "refused", "own sign-in is required")
        self.assertState(400, err("22023", "zone_loop_context: no zone 3"), "problem", "no zone 3")

    def test_unreachable(self):
        self.fake.close()
        out = self.m.zone_loops(self.fake.base, 3)
        self.assertEqual(out["state"], "error")
        self.assertIn("cannot reach", out["why"])

    def test_token_problems_in_what_to_do_words(self):
        os.environ["IAM_POSTGREST_JWT"] = "true"
        self.addCleanup(os.environ.pop, "IAM_POSTGREST_JWT", None)
        self.m._TOKEN = token()
        self.assertState(401, err("PGRST303", "JWT expired"), "error", "expired")
        self.m._TOKEN = ""
        out = self.m.zone_loops(self.fake.base, 3)
        self.assertEqual(out["state"], "error")
        self.assertIn("no valid sign-in token", out["why"])
        self.assertEqual(len(self.fake.seen), 1)       # refused locally, nothing sent

    def test_bearer_under_phase_2(self):
        os.environ["IAM_POSTGREST_JWT"] = "true"
        self.addCleanup(os.environ.pop, "IAM_POSTGREST_JWT", None)
        self.m._TOKEN = tok = token()
        self.fake.answers.append((200, CONTEXT))
        self.m.zone_loops(self.fake.base, 3)
        self.assertEqual(self.fake.seen[0]["auth"], "Bearer " + tok)


class SaveLoops(unittest.TestCase):
    LOOPS = [{"loop_code": "co2", "recipe_lower": "co2_lower_limit", "recipe_upper": "co2_upper_limit",
              "input": {"tag": "co2", "sources": ["scd30_1"], "rule": "reference", "reference": "scd30_1"},
              "output": {"actuator": "co2", "mode": "command", "command_map": {"DOWN": "UP", "UP": "OFF", "OFF": "OFF"}}}]

    def setUp(self):
        self.fake = Fake()
        self.addCleanup(self.fake.close)
        self.m = load()
        os.environ.pop("IAM_POSTGREST_JWT", None)

    def test_body_and_result(self):
        res = {"zone_id": 3, "zone_code": "ZONE01", "changed": True, "inserted": [{"loop_id": 9, "loop_code": "co2"}],
               "updated": [], "deactivated": [], "unchanged": []}
        self.fake.answers.append((200, res))
        out = self.m.save_loops(self.fake.base, 3, self.LOOPS)
        self.assertEqual(out, {"state": "ok", "why": "", "problems": [], "result": res})
        self.assertEqual(self.fake.seen[0]["path"], "/rpc/save_zone_loops")
        self.assertEqual(self.fake.seen[0]["body"], {"p_zone_id": 3, "p_loops": self.LOOPS})

    def test_busy_in_words(self):
        # the exact text of the save's (and the table guard's) RAISE
        self.fake.answers.append((400, err("55006", "control_loop: unit UNIT01 has run 42 in R; change its loops "
                                                   "when no run is running or scheduled")))
        out = self.m.save_loops(self.fake.base, 3, self.LOOPS)
        self.assertEqual(out["state"], "busy")
        self.assertEqual(out["why"], "the control loops were not saved: unit UNIT01 has run 42 running (R); loops "
                                     "change only while no run is running or scheduled")
        self.fake.answers.append((400, err("55006", "control_loop: unit UNIT01 has run 43 in S; change its loops "
                                                   "when no run is running or scheduled")))
        self.assertIn("run 43 scheduled (S)", self.m.save_loops(self.fake.base, 3, self.LOOPS)["why"])

    def test_problem_list(self):
        errs = ["co2: sensor scd30_1 does not publish co2", "co2: actuator co2 is not on an active CONTROL board of zone ZONE01"]
        self.fake.answers.append((400, err("22023", "save_zone_loops: " + "; ".join(errs), json.dumps(errs))))
        out = self.m.save_loops(self.fake.base, 3, self.LOOPS)
        self.assertEqual((out["state"], out["problems"]), ("problem", errs))
        # without a DETAIL the message is split
        self.fake.answers.append((400, err("22023", "save_zone_loops: " + "; ".join(errs))))
        self.assertEqual(self.m.save_loops(self.fake.base, 3, self.LOOPS)["problems"], errs)

    def test_refusals(self):
        for status, body, state in ((401, err("42501", "permission denied for function save_zone_loops"), "refused"),
                                    (403, err("42501", "permission denied for function save_zone_loops"), "refused"),
                                    (400, err("55000", "save_zone_loops: medcea.control_loop is not deployed yet"), "not_deployed"),
                                    (404, err("PGRST202", "Could not find the function"), "not_deployed")):
            self.fake.answers.append((status, body))
            self.assertEqual(self.m.save_loops(self.fake.base, 3, self.LOOPS)["state"], state, body)
        self.assertEqual(self.m.save_loops(self.fake.base, 3, {"co2": 1})["state"], "problem")


class TextsAreTheMigrations(unittest.TestCase):
    """The words platform_db maps from are the RAISE texts of migration 010."""

    def test_raise_texts(self):
        with open(MIGRATIONS, encoding="utf-8") as f:
            sql = f.read()
        busy = "control_loop: unit % has run % in %; change its loops when no run is running or scheduled"
        save = re.search(r"FUNCTION medcea\.save_zone_loops\(.*?END \$\$;", sql, re.S).group(0)
        self.assertIn(busy, save)
        self.assertIn("ERRCODE = '55006'", save)
        self.assertIn("USING ERRCODE = '22023', DETAIL = array_to_json(errs)::text", save)
        self.assertIn("USING ERRCODE = '55000'", save)
        ctx = re.search(r"FUNCTION medcea\.zone_loop_context\(.*?END \$\$;", sql, re.S).group(0)
        for fn in (ctx, save):
            self.assertIn("a person''s own token is required' USING ERRCODE = '42501'", fn)
            self.assertIn("holds no U on master_data", fn)
        m = load()
        e = m.RpcError(400, "55006", busy.replace("%", "X", 1).replace("%", "42", 1).replace("%", "R", 1), None)
        self.assertEqual(m._classify(e, "save_zone_loops")[0], "busy")
        self.assertIn("run 42 running (R)", m._classify(e, "save_zone_loops")[1])


class Cli(unittest.TestCase):
    def setUp(self):
        self.fake = Fake()
        self.addCleanup(self.fake.close)

    def run_pdb(self, args, stdin=""):
        env = dict(os.environ, CEA_CONFIG_API=self.fake.base, IAM_POSTGREST_JWT="false")
        env.pop("PLATFORM_DB_TOKEN_FD", None)
        return subprocess.run([sys.executable, PDB] + args, input=stdin, capture_output=True, text=True,
                              env=env, timeout=60)

    def test_loops_prints_one_line_and_nothing_on_stderr(self):
        self.fake.answers.append((200, CONTEXT))
        r = self.run_pdb(["loops", "3"])
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(json.loads(r.stdout)["state"], "ok")
        self.fake.answers.append((401, err("42501", "permission denied for function zone_loop_context")))
        r = self.run_pdb(["loops", "3"])
        self.assertEqual((r.returncode, r.stderr), (0, ""))          # the state says it
        self.assertEqual(json.loads(r.stdout)["state"], "refused")

    def test_save_loops(self):
        res = {"changed": False, "inserted": [], "updated": [], "deactivated": [], "unchanged": [{"loop_code": "co2"}]}
        self.fake.answers.append((200, res))
        r = self.run_pdb(["save-loops", "3"], json.dumps(SaveLoops.LOOPS))
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(json.loads(r.stdout)["result"], res)
        self.fake.answers.append((400, err("55006", "control_loop: unit UNIT01 has run 42 in R; change its loops "
                                                   "when no run is running or scheduled")))
        r = self.run_pdb(["save-loops", "3"], json.dumps(SaveLoops.LOOPS))
        self.assertEqual(r.returncode, 1)
        self.assertEqual(json.loads(r.stdout)["state"], "busy")
        self.assertIn("unit UNIT01 has run 42 running", r.stderr)
        self.assertEqual(self.run_pdb(["loops", "x"]).returncode, 2)

    def test_docstring_names_them(self):
        with open(PDB, encoding="utf-8") as f:
            doc = f.read().split('"""')[1]
        self.assertIn("loops ZONE_ID", doc)
        self.assertIn("save-loops ZONE_ID", doc)


if __name__ == "__main__":
    unittest.main()
