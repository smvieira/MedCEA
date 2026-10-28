#!/usr/bin/env python3
"""tests/test_platform_db_token.py — how edge/src/host/platform_db.py carries the
operator's token (IAM plan 1.5), against a fake PostgREST on 127.0.0.1:0.

Phase 1 (IAM_POSTGREST_JWT=false) sends no credential at all; Phase 2 sends
Authorization: Bearer and refuses locally without a usable token. The token
arrives on fd 3 only when PLATFORM_DB_TOKEN_FD=3, and never shows up in output.
Also checks, statically, that flash-device.sh reaches platform_db only through
platdb() and that no secret is put on a command line.

Run from the repository root:  python3 tests/test_platform_db_token.py
"""
import base64
import json
import os
import re
import subprocess
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PDB = os.path.join(REPO, "edge", "src", "host", "platform_db.py")


def jwt(**c):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return "%s.%s.c2lnbmF0dXJl" % (enc({"alg": "RS256"}), enc(c))


TOKEN = jwt(sub="u-alice", preferred_username="alice", exp=int(time.time()) + 300,
            aud="medcea-api", azp="edge-wizard")
EXPIRED = jwt(sub="u-alice", preferred_username="alice", exp=int(time.time()) - 5)

ROWS = {
    "/cea_unit": [{"unit_id": 1, "unit_code": "UNIT01", "unit_type": "", "is_active": "Y"}],
    "/cea_zone": [{"zone_id": 1, "unit_id": 1, "zone_code": "ZONE01",
                   "zone_description": "", "is_active": "Y"}],
    "/device": [],
}


class FakePostgREST(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.base = "http://127.0.0.1:%d" % self.server_address[1]
        self.seen = []                   # request headers, one dict per request
        self.answer = None               # (status, body) to force, or None
        threading.Thread(target=self.serve_forever, daemon=True).start()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.server.seen.append({k.lower(): v for k, v in self.headers.items()})
        status, body = self.server.answer or (200, ROWS.get(self.path.split("?")[0], []))
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class PlatformDbToken(unittest.TestCase):
    def setUp(self):
        self.pg = FakePostgREST()

    def tearDown(self):
        self.pg.shutdown()
        self.pg.server_close()

    def run_pdb(self, args, token=None, phase2=False, token_env=True, close_writer=True):
        """platform_db.py with `token` on its fd 3, the way platdb() does it."""
        r, w = os.pipe()
        if token is not None:
            os.write(w, token.encode())
        if close_writer:
            os.close(w)
        env = {k: v for k, v in os.environ.items()
               if k not in ("PLATFORM_DB_TOKEN_FD", "IAM_POSTGREST_JWT")}
        env.update(CEA_CONFIG_API=self.pg.base, IAM_POSTGREST_JWT="true" if phase2 else "false")
        if token_env:
            env["PLATFORM_DB_TOKEN_FD"] = "3"
        try:
            p = subprocess.run(["bash", "-c", 'exec 3<&%d %d<&-; exec "$@"' % (r, r), "pdb",
                                sys.executable, PDB] + args,
                               pass_fds=(r,), env=env, capture_output=True, text=True,
                               timeout=30)
        finally:
            leftover = b""
            if not close_writer:
                os.close(w)
            os.set_blocking(r, False)
            try:
                leftover = os.read(r, 65536)
            except BlockingIOError:
                pass
            os.close(r)
        for out in (p.stdout, p.stderr):
            self.assertNotIn(TOKEN, out)
            self.assertNotIn(TOKEN.split(".")[1], out)
        return p, leftover

    # ---- Phase 1 ----
    def test_phase1_sends_no_credential_and_is_quiet(self):
        for args in (["slots"], ["board", "aabbccddeeff"]):
            self.pg.seen.clear()
            p, _ = self.run_pdb(args, token=TOKEN)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stderr, "", args)
            self.assertTrue(self.pg.seen)
            for h in self.pg.seen:
                self.assertNotIn("authorization", h)
                self.assertNotIn("x-forwarded-access-token", h)
        p, _ = self.run_pdb(["slots"], token=TOKEN)
        self.assertTrue(p.stdout.startswith("SLOT\t"))

    # ---- Phase 2 ----
    def test_phase2_sends_bearer(self):
        p, _ = self.run_pdb(["slots"], token=TOKEN, phase2=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stderr, "")
        self.assertTrue(self.pg.seen)
        for h in self.pg.seen:
            self.assertEqual(h.get("authorization"), "Bearer " + TOKEN)

    def test_phase2_without_token_makes_no_request(self):
        p, _ = self.run_pdb(["slots"], token=None, phase2=True, token_env=False)
        self.assertEqual(p.returncode, 1)
        self.assertIn("no valid sign-in token", p.stderr)
        self.assertEqual(self.pg.seen, [])

    def test_phase2_expired_token_refused_locally(self):
        p, _ = self.run_pdb(["slots"], token=EXPIRED, phase2=True)
        self.assertEqual(p.returncode, 1)
        self.assertIn("expired before the call", p.stderr)
        self.assertEqual(self.pg.seen, [])

    def test_phase2_maps_postgrest_refusals(self):
        self.pg.answer = (401, {"code": "PGRST301", "message": "JWT expired"})
        p, _ = self.run_pdb(["slots"], token=TOKEN, phase2=True)
        self.assertEqual(p.returncode, 1)
        self.assertIn("expired during the request", p.stderr)
        self.pg.answer = (401, {"code": "PGRST300", "message": "Server lacks JWT secret"})
        p, _ = self.run_pdb(["slots"], token=TOKEN, phase2=True)
        self.assertIn("config-api has no JWT key", p.stderr)
        self.pg.answer = (403, {"code": "42501", "message": "permission denied for table cea_unit"})
        p, _ = self.run_pdb(["slots"], token=TOKEN, phase2=True)
        self.assertEqual(p.returncode, 1)
        self.assertIn("alice's role may not onboard boards", p.stderr)
        self.assertIn("User Manager", p.stderr)

    # ---- fd 3 ----
    def test_fd3_ignored_without_the_variable(self):
        p, leftover = self.run_pdb(["slots"], token=TOKEN, token_env=False, close_writer=False)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(leftover, TOKEN.encode())

    def test_silent_writer_does_not_hang(self):
        t0 = time.monotonic()
        p, _ = self.run_pdb(["slots"], token=None, close_writer=False)
        self.assertLess(time.monotonic() - t0, 8)
        self.assertEqual(p.returncode, 0, p.stderr)
        for h in self.pg.seen:
            self.assertNotIn("authorization", h)


def code_lines(path):
    """The file's lines with comments dropped (a comment may name what is forbidden)."""
    with open(path, encoding="utf-8") as f:
        return [(n, l) for n, l in enumerate(f, 1) if not l.lstrip().startswith("#")]


class StaticChecks(unittest.TestCase):
    FLASH = os.path.join(REPO, "edge", "flash-device.sh")
    DAEMON = os.path.join(REPO, "edge", "wizard-daemon.sh")

    def test_platform_db_only_through_platdb(self):
        lines = code_lines(self.FLASH)
        calls = [n for n, l in lines if 'python3 "$PLATDB"' in l]
        self.assertEqual(len(calls), 1, calls)
        with open(self.FLASH, encoding="utf-8") as f:
            text = f.read()
        m = re.search(r"^platdb\(\) \{\n(.*?)^\}", text, re.S | re.M)
        self.assertIsNotNone(m, "platdb() not found")
        self.assertIn('python3 "$PLATDB"', m.group(1))
        self.assertIn("3< <(printf '%s' \"$EDGE_TOKEN\")", m.group(1))

    def test_no_secret_on_a_command_line(self):
        for path in (self.FLASH, self.DAEMON):
            for n, l in code_lines(path):
                self.assertNotIn("--client-secret", l, "%s:%d" % (path, n))
        for n, l in code_lines(self.FLASH):
            self.assertNotIn("3<<<", l, "flash-device.sh:%d" % n)
            self.assertNotRegex(l, r"export\s+EDGE_TOKEN", "flash-device.sh:%d" % n)


if __name__ == "__main__":
    unittest.main(verbosity=1)
