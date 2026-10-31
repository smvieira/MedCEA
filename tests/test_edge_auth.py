#!/usr/bin/env python3
"""tests/test_edge_auth.py — the edge wizard's token holder (IAM plan 1.5), offline.

Keycloak is a ThreadingHTTPServer on 127.0.0.1:0 (or an injected post function);
tokens are unsigned JWT-shaped strings, which is all the holder reads (its tokens
come from a back-channel it authenticated, see edge_auth.claims). Covers fresh(),
the device grant, the line protocol, the agent subprocess and wizard_server's
start_run / callback / logout. No cluster, no Keycloak, no network.

Run from the repository root:  python3 tests/test_edge_auth.py
"""
import base64
import http.client
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST_DIR = os.path.join(REPO, "edge", "src", "host")
sys.path.insert(0, HOST_DIR)

import edge_auth  # noqa: E402

CLIENT = "edge-wizard"
SECRET = "s3cret-edge-wizard-client"


def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def jwt(**c):
    return "%s.%s.sig" % (b64({"alg": "RS256", "typ": "JWT"}), b64(c))


def access(sub="u-alice", user="alice", exp_in=300, aud="medcea-api", azp=CLIENT,
           groups=("operator",), typ="Bearer", roles=(), name="Alice Example"):
    return jwt(sub=sub, preferred_username=user, name=name, exp=int(time.time()) + exp_in,
               aud=aud, azp=azp, typ=typ, groups=list(groups),
               realm_access={"roles": list(roles)})


def token_response(refresh="R2", exp_in=300, **kw):
    return {"access_token": access(exp_in=exp_in, **kw), "expires_in": exp_in,
            "refresh_token": refresh, "refresh_expires_in": 1800,
            "id_token": jwt(sub=kw.get("sub", "u-alice"),
                            preferred_username=kw.get("user", "alice"))}


def tokenset(exp_in=300, refresh="R1", **kw):
    ts = edge_auth.TokenSet.from_response(token_response(refresh=refresh, exp_in=exp_in, **kw),
                                          time.time())
    return ts


OIDC = {"token_endpoint": "http://kc.invalid/token",
        "device_authorization_endpoint": "http://kc.invalid/device",
        "revocation_endpoint": "http://kc.invalid/revoke",
        "issuer": "http://kc.invalid/realms/medcea"}


# ------------------------------------------------------------- fake Keycloak --
class FakeKC(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), KCHandler)
        self.base = "http://127.0.0.1:%d" % self.server_address[1]
        self.calls = []          # (path, form)
        self.token = lambda form: (200, token_response())
        self.device = lambda form: (200, {"device_code": "DC", "user_code": "ABCD-EFGH",
                                          "verification_uri": self.base + "/device-page",
                                          "expires_in": 30, "interval": 1})
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def oidc(self):
        b = self.base
        return {"issuer": b + "/realms/medcea", "token_endpoint": b + "/token",
                "authorization_endpoint": b + "/auth",
                "device_authorization_endpoint": b + "/device",
                "revocation_endpoint": b + "/revoke",
                "end_session_endpoint": b + "/logout"}


class KCHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path.endswith("/.well-known/openid-configuration"):
            return self._json(200, self.server.oidc())
        self._json(404, {})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        form = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode()).items()}
        self.server.calls.append((self.path, form))
        if self.path == "/token":
            return self._json(*self.server.token(form))
        if self.path == "/device":
            return self._json(*self.server.device(form))
        if self.path == "/revoke":
            return self._json(200, {})
        self._json(404, {})


# --------------------------------------------------------------------- fresh --
class Poster:
    def __init__(self, *answers, delay=0):
        self.answers, self.calls, self.delay = list(answers), [], delay
        self.lock = threading.Lock()

    def __call__(self, url, data, ctx, timeout=15):
        with self.lock:
            self.calls.append((url, dict(data)))
        if self.delay:
            time.sleep(self.delay)
        a = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(a, Exception):
            raise a
        return a


class FreshTests(unittest.TestCase):
    def test_no_post_while_enough_left(self):
        ts, post = tokenset(exp_in=300), Poster((200, token_response()))
        self.assertEqual(edge_auth.fresh(ts, OIDC, CLIENT, SECRET, None, 120, post=post),
                         ("ok", None))
        self.assertEqual(post.calls, [])

    def test_refresh_below_min_ttl_stores_rotated_refresh(self):
        ts, post = tokenset(exp_in=100), Poster((200, token_response(refresh="R2")))
        self.assertEqual(edge_auth.fresh(ts, OIDC, CLIENT, SECRET, None, 120, post=post)[0], "ok")
        self.assertEqual(len(post.calls), 1)
        self.assertEqual(post.calls[0][1]["grant_type"], "refresh_token")
        self.assertEqual(post.calls[0][1]["refresh_token"], "R1")
        self.assertEqual(ts.refresh, "R2")
        self.assertGreater(ts.access_exp - time.time(), 250)

    def test_330_forces_a_refresh(self):
        ts, post = tokenset(exp_in=300), Poster((200, token_response()))
        edge_auth.fresh(ts, OIDC, CLIENT, SECRET, None, edge_auth.FORCE_TTL, post=post)
        self.assertEqual(len(post.calls), 1)

    def test_invalid_grant_is_reauth(self):
        ts = tokenset(exp_in=10)
        post = Poster((400, {"error": "invalid_grant", "error_description": "Session not active"}))
        kind, _ = edge_auth.fresh(ts, OIDC, CLIENT, SECRET, None, 120, post=post)
        self.assertEqual(kind, "reauth")
        self.assertEqual(ts.state, "reauth")
        self.assertEqual(ts.access, "")

    def test_refused_connection_keeps_a_token_with_time_left(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()                                   # nothing listens there now
        oidc = dict(OIDC, token_endpoint="http://127.0.0.1:%d/token" % port)
        ts = tokenset(exp_in=100)
        old = ts.access
        self.assertEqual(edge_auth.fresh(ts, oidc, CLIENT, SECRET, None, 120)[0], "ok")
        self.assertEqual(ts.access, old)
        ts = tokenset(exp_in=30)
        self.assertEqual(edge_auth.fresh(ts, oidc, CLIENT, SECRET, None, 120)[0], "unreachable")

    def test_two_threads_one_refresh(self):
        ts, post = tokenset(exp_in=10), Poster((200, token_response()), delay=0.2)
        out = []
        th = [threading.Thread(target=lambda: out.append(
            edge_auth.fresh(ts, OIDC, CLIENT, SECRET, None, 120, post=post)[0])) for _ in "ab"]
        [t.start() for t in th]
        [t.join() for t in th]
        self.assertEqual(out, ["ok", "ok"])
        self.assertEqual(len(post.calls), 1)

    def test_lost_role_on_refresh_ends_the_set(self):
        # A role change does not end the Keycloak session: the refresh succeeds,
        # and only the role check on the new token stops the run.
        ts = tokenset(exp_in=10, roles=("engineer",))
        post = Poster((200, token_response(roles=())))
        kind, msg = edge_auth.fresh(ts, OIDC, CLIENT, SECRET, None, 120, post=post,
                                    required_role="engineer")
        self.assertEqual(kind, "role")
        self.assertIn("'engineer'", msg)
        self.assertEqual((ts.state, ts.access, ts.refresh), ("closed", "", ""))
        # ...and stays refused without asking Keycloak again.
        self.assertEqual(edge_auth.fresh(ts, OIDC, CLIENT, SECRET, None, 120, post=post)[0],
                         "role")
        self.assertEqual(len(post.calls), 1)
        ts = tokenset(exp_in=10, roles=("engineer",))
        post = Poster((200, token_response(roles=("engineer",), groups=("engineer",))))
        self.assertEqual(edge_auth.fresh(ts, OIDC, CLIENT, SECRET, None, 120, post=post,
                                         required_role="engineer")[0], "ok")
        self.assertEqual(ts.role, "engineer")

    def test_http_exception_is_the_network(self):
        # IncompleteRead is no OSError; it used to end the token channel.
        ts = tokenset(exp_in=100)
        post = Poster(http.client.IncompleteRead(b""))
        self.assertEqual(edge_auth.fresh(ts, OIDC, CLIENT, SECRET, None, 120, post=post)[0], "ok")
        ts = tokenset(exp_in=10)
        self.assertEqual(edge_auth.fresh(ts, OIDC, CLIENT, SECRET, None, 120, post=post)[0],
                         "unreachable")

    def test_refreshed_token_without_audience_is_client(self):
        ts = tokenset(exp_in=10)
        post = Poster((200, token_response(aud="account")))
        kind, msg = edge_auth.fresh(ts, OIDC, CLIENT, SECRET, None, 120, post=post)
        self.assertEqual(kind, "client")
        self.assertIn("./deploy-infra.sh", msg)


# -------------------------------------------------------------- device grant --
class Clock:
    def __init__(self):
        self.t, self.slept = 1000.0, []

    def now(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


DEVICE_OK = (200, {"device_code": "DC", "user_code": "WXYZ-1234",
                   "verification_uri": "https://kc/device", "expires_in": 600, "interval": 5})


class RolesTests(unittest.TestCase):
    """IAM 3.4: --required-role is the access policy's onboarding list; any one admits."""

    def test_roles_of(self):
        self.assertIsNone(edge_auth.roles_of(None))
        self.assertIsNone(edge_auth.roles_of(""))
        self.assertIsNone(edge_auth.roles_of(" , "))
        self.assertEqual(edge_auth.roles_of("engineer"), ("engineer",))
        self.assertEqual(edge_auth.roles_of("engineer,maintenance"), ("engineer", "maintenance"))
        self.assertEqual(edge_auth.roles_of(["engineer", "maintenance"]), ("engineer", "maintenance"))
        self.assertEqual(edge_auth.roles_of(("engineer",)), ("engineer",))

    def test_roles_text(self):
        self.assertEqual(edge_auth.roles_text("engineer"), "the 'engineer' role")
        self.assertEqual(edge_auth.roles_text("engineer,maintenance"),
                         "one of the roles 'engineer', 'maintenance'")

    def test_has_role_is_any_of(self):
        need = ("engineer", "maintenance")
        self.assertTrue(edge_auth.has_role({"realm_access": {"roles": ["maintenance"]}}, need))
        self.assertTrue(edge_auth.has_role({"groups": ["engineer"]}, "engineer,maintenance"))
        self.assertFalse(edge_auth.has_role({"realm_access": {"roles": ["operator"]},
                                             "groups": ["operator"]}, need))
        self.assertFalse(edge_auth.has_role({"realm_access": {"roles": ["engineer"]}}, None))

    def test_fresh_with_two_roles(self):
        need = ("engineer", "maintenance")
        ts = tokenset(exp_in=10, roles=("maintenance",), groups=("maintenance",))
        post = Poster((200, token_response(roles=("maintenance",), groups=("maintenance",))))
        self.assertEqual(edge_auth.fresh(ts, OIDC, CLIENT, SECRET, None, 120, post=post,
                                         required_role=need)[0], "ok")
        ts = tokenset(exp_in=10, roles=("engineer",))
        post = Poster((200, token_response(roles=("operator",))))
        kind, msg = edge_auth.fresh(ts, OIDC, CLIENT, SECRET, None, 120, post=post,
                                    required_role=need)
        self.assertEqual(kind, "role")
        self.assertIn("'engineer', 'maintenance'", msg)
        self.assertIn("which is required to onboard boards", msg)

    def test_holder_takes_the_comma_list(self):
        h = edge_auth.Holder(None, None, CLIENT, SECRET, required_role="engineer,maintenance")
        self.assertEqual(h.required_role, ("engineer", "maintenance"))
        self.assertIsNone(edge_auth.Holder(None, None, CLIENT, SECRET, required_role="").required_role)


class DeviceLoginTests(unittest.TestCase):
    def login(self, *answers, role=None):
        clk, emitted = Clock(), []
        post = Poster(DEVICE_OK, *answers)
        try:
            ts = edge_auth.device_login(OIDC, CLIENT, SECRET, None, emitted.append,
                                        required_role=role, sleep=clk.sleep, now=clk.now,
                                        post=post)
            return ts, None, emitted, clk, post
        except edge_auth.AuthError as e:
            return None, e, emitted, clk, post

    def test_pending_twice_then_success(self):
        ts, err, emitted, clk, post = self.login(
            (400, {"error": "authorization_pending"}), (400, {"error": "authorization_pending"}),
            (200, token_response()))
        self.assertIsNone(err)
        self.assertEqual(ts.user, "alice")
        self.assertEqual(ts.role, "operator")
        waits = [e for e in emitted if e.startswith(b"WAIT\tdevice\t")]
        self.assertEqual(len(waits), 1)
        self.assertIn(b"WXYZ-1234", waits[0])
        self.assertNotIn("offline_access", post.calls[0][1].get("scope", ""))

    def test_slow_down_adds_five_seconds(self):
        _ts, err, _e, clk, _p = self.login((400, {"error": "slow_down"}), (200, token_response()))
        self.assertIsNone(err)
        self.assertEqual(clk.slept, [5, 10])

    def test_denied_and_expired(self):
        self.assertEqual(self.login((400, {"error": "access_denied"}))[1].code, "denied")
        self.assertEqual(self.login((400, {"error": "expired_token"}))[1].code, "expired_code")

    def test_client_errors_say_what_to_do(self):
        clk = Clock()
        for err, want in (("unauthorized_client", "./deploy-infra.sh"),
                          ("invalid_client", "EDGE_WIZARD_SECRET")):
            with self.assertRaises(edge_auth.AuthError) as cm:
                edge_auth.device_login(OIDC, CLIENT, SECRET, None, lambda b: None,
                                       sleep=clk.sleep, now=clk.now,
                                       post=Poster((401, {"error": err})))
            self.assertEqual(cm.exception.code, "client")
            self.assertIn(want, cm.exception.msg)

    def test_missing_role(self):
        _ts, err, _e, _c, _p = self.login((200, token_response()), role="engineer")
        self.assertEqual(err.code, "role")
        self.assertIn("'engineer'", err.msg)
        self.assertIn("User Manager", err.msg)
        ts, err, _e, _c, _p = self.login((200, token_response(roles=("engineer",))),
                                         role="engineer")
        self.assertIsNone(err)

    def test_5xx_and_errorless_answers_keep_polling(self):
        ts, err, _e, _c, _p = self.login((503, {}), (502, {}), (400, {}),
                                         (400, {"error": "authorization_pending"}),
                                         (200, token_response()))
        self.assertIsNone(err)
        self.assertEqual(ts.user, "alice")
        # Still a 5xx when the code runs out: said as such, not as a client error.
        _ts, err, _e, _c, _p = self.login((503, {}))
        self.assertEqual(err.code, "unreachable")

    def test_wrong_audience_or_azp(self):
        self.assertEqual(self.login((200, token_response(aud="account")))[1].code, "client")
        self.assertEqual(self.login((200, token_response(azp="config")))[1].code, "client")


# ------------------------------------------------------------------ protocol --
class ProtocolTests(unittest.TestCase):
    def test_fields_never_hold_tabs_or_newlines_and_are_never_empty(self):
        for line in (edge_auth.fmt_wait("browser", "a\tb\nc"), edge_auth.fmt_err("x", ""),
                     edge_auth.fmt_wait("device", "", "CODE", 600)):
            self.assertTrue(line.endswith(b"\n"))
            body = line[:-1]
            self.assertNotIn(b"\n", body)
            self.assertNotIn(b"", body.split(b"\t"))
        self.assertEqual(edge_auth.fmt_err("x", "").split(b"\t")[2], b"-\n")
        ts = tokenset(name="")
        ts.name = ""
        self.assertEqual(edge_auth.fmt_ok(ts).split(b"\t")[3], b"-")

    def test_oversized_reply_becomes_err(self):
        ts = tokenset()
        ts.access = "x" * 5000
        self.assertTrue(edge_auth.fmt_ok(ts).startswith(b"ERR\tclient\t"))

    def serve(self, ts):
        req_r, req_w = os.pipe()
        rep_r, rep_w = os.pipe()
        holder = edge_auth.Holder(OIDC, None, CLIENT, SECRET, ts=ts)
        th = threading.Thread(target=edge_auth.serve, args=(req_r, rep_w, holder), daemon=True)
        th.start()
        return holder, th, req_w, rep_r, (req_r, rep_w)

    def read_all(self, fd):
        out = b""
        while True:
            c = os.read(fd, 65536)
            if not c:
                return out
            out += c

    def test_ok_over_pipes_and_eof_wipes(self):
        ts = tokenset()
        holder, th, req_w, rep_r, others = self.serve(ts)
        os.write(req_w, b"token\t120\tx\n")
        os.close(req_w)
        th.join(5)
        self.assertFalse(th.is_alive())
        os.close(others[1])
        out = self.read_all(rep_r)
        fields = out.rstrip(b"\n").split(b"\t")
        self.assertEqual(fields[0], b"OK")
        self.assertEqual(len(fields), 6)
        self.assertEqual(fields[2], b"alice")
        self.assertEqual(ts.state, "closed")
        self.assertEqual(ts.access, "")
        self.assertEqual(ts.refresh, "")

    def test_garbage_and_long_lines_close_the_channel(self):
        for req in (b"hello\n", b"token\tabc\tx\n", b"token\t99999\tx\n", b"x" * 600):
            ts = tokenset()
            _h, th, req_w, rep_r, others = self.serve(ts)
            os.write(req_w, req)
            th.join(5)
            self.assertFalse(th.is_alive(), req)
            os.close(others[1])
            self.assertTrue(self.read_all(rep_r).startswith(b"ERR\tbad_request\t"), req)
            os.close(req_w)

    def test_unexpected_exception_is_an_err_and_the_channel_stays(self):
        ts = tokenset(exp_in=10)
        req_r, req_w = os.pipe()
        rep_r, rep_w = os.pipe()
        holder = edge_auth.Holder(OIDC, None, CLIENT, SECRET, ts=ts,
                                  post=Poster(ValueError("boom"), (200, token_response())))
        th = threading.Thread(target=edge_auth.serve, args=(req_r, rep_w, holder), daemon=True)
        th.start()
        os.write(req_w, b"token\t120\tx\n")
        first = os.read(rep_r, 4096)
        self.assertTrue(first.startswith(b"ERR\tunreachable\t"), first)
        os.write(req_w, b"token\t120\tx\n")
        self.assertTrue(os.read(rep_r, 4096).startswith(b"OK\t"))
        os.close(req_w)
        th.join(5)
        self.assertFalse(th.is_alive())
        for fd in (req_r, rep_r, rep_w):
            os.close(fd)

    def test_unbound_holder_binds_only_when_allowed(self):
        holder = edge_auth.Holder(OIDC, None, CLIENT, SECRET)
        taken, why = holder.offer(tokenset())
        self.assertFalse(taken)
        self.assertIn("token", why)
        self.assertIsNone(holder.ts)
        self.assertEqual(holder.offer(tokenset(), may_bind=True), (True, None))

    def test_repr_holds_no_token(self):
        ts = tokenset()
        self.assertNotIn(ts.access, repr(ts))
        self.assertNotIn(ts.refresh, repr(ts))
        self.assertIn("alice", repr(ts))


# --------------------------------------------------------------------- agent --
class AgentTests(unittest.TestCase):
    def setUp(self):
        self.kc = FakeKC()
        polls = []

        def token(form):
            if form.get("grant_type", "").endswith("device_code"):
                polls.append(1)
                if len(polls) == 1:
                    return 400, {"error": "authorization_pending"}
                return 200, token_response(refresh="AGENT-REFRESH")
            return 400, {"error": "unsupported_grant_type"}
        self.kc.token = token

    def tearDown(self):
        self.kc.shutdown()
        self.kc.server_close()

    def test_secret_not_in_argv_and_eof_revokes_nothing(self):
        env = dict(os.environ, EDGE_WIZARD_SECRET=SECRET)
        p = subprocess.Popen([sys.executable, os.path.join(HOST_DIR, "edge_auth.py"), "agent",
                              "--issuer", self.kc.base + "/realms/medcea", "--client-id", CLIENT],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
        try:
            with open("/proc/%d/cmdline" % p.pid, "rb") as f:
                self.assertNotIn(SECRET.encode(), f.read())
            p.stdin.write(b"token\t120\tread the free slots\n")
            p.stdin.flush()
            first = p.stdout.readline()
            self.assertTrue(first.startswith(b"WAIT\tdevice\t"), first)
            self.assertIn(b"ABCD-EFGH", first)
            ok = p.stdout.readline()
            self.assertTrue(ok.startswith(b"OK\t"), ok[:40])
            self.assertEqual(len(ok.rstrip(b"\n").split(b"\t")), 6)
            p.stdin.close()
            self.assertEqual(p.wait(15), 0)
        finally:
            if p.poll() is None:
                p.kill()
            p.stdout.close()
        # No revocation: Keycloak's would detach edge-wizard from every session
        # the person has (their other runs and tabs), not just this one.
        self.assertEqual([p for p, _f in self.kc.calls if p not in ("/device", "/token")], [])
        self.assertTrue(all(f.get("client_secret") == SECRET for _p, f in self.kc.calls))

    def test_no_secret_exits_2(self):
        env = {k: v for k, v in os.environ.items() if k != "EDGE_WIZARD_SECRET"}
        p = subprocess.run([sys.executable, os.path.join(HOST_DIR, "edge_auth.py"), "agent",
                            "--issuer", self.kc.base], env=env, capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(self.kc.calls, [])


# ------------------------------------------------------------- wizard_server --
def load_wizard():
    spec = importlib.util.spec_from_file_location("wizard_server_t",
                                                  os.path.join(HOST_DIR, "wizard_server.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CHILD = r'''#!/usr/bin/env python3
import os, sys
a = sys.argv
d = a[a.index("--ui-spool") + 1]
fd = int(a[a.index("--token-fd") + 1])
os.write(fd, b"token\t120\tt\n")
buf = b""
while not buf.endswith(b"\n"):
    c = os.read(fd, 4096)
    if not c:
        break
    buf += c
f = buf.decode().rstrip("\n").split("\t")
for name, src in (("cmdline", "/proc/self/cmdline"), ("environ", "/proc/self/environ")):
    with open(src, "rb") as i, open(os.path.join(d, name), "wb") as o:
        o.write(i.read())
with open(os.path.join(d, "result.tmp"), "w") as o:
    o.write("%s %d" % (f[0], len(f[-1]) if f[0] == "OK" else 0))
os.replace(os.path.join(d, "result.tmp"), os.path.join(d, "result"))
'''


class WizardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = load_wizard()

    def setUp(self):
        self.kc = FakeKC()
        self.tmp = tempfile.mkdtemp()
        self.spool = os.path.join(self.tmp, "spool")
        os.mkdir(self.spool)
        script = os.path.join(self.tmp, "child.py")
        with open(script, "w") as f:
            f.write(CHILD)
        os.chmod(script, 0o755)
        S = self.ws.STATE
        S.update({"dir": self.spool, "auth": "keycloak", "oidc": self.kc.oidc(),
                  "client_id": CLIENT, "client_secret": SECRET, "ssl_ctx": None,
                  "required_role": None, "repo_root": self.tmp, "flash_args": [],
                  "run": None, "run_auth": None, "run_owner": None, "token": "tok",
                  "sessions": {}, "pending": {},
                  "daemon": True,
                  "catalog": [{"id": "dev", "name": "Dev", "status": "available",
                               "_script": script}]})

    def tearDown(self):
        r = self.ws.STATE["run"]
        if r is not None and r.poll() is None:
            r.kill()
        self.kc.shutdown()
        self.kc.server_close()

    def session(self, ts, sub="u-alice"):
        sid = self.ws.new_session({"sub": sub, "preferred_username": "alice"}, "idtok", ts)
        return sid, self.ws.STATE["sessions"][sid]

    def test_start_run_hands_out_tokens_on_the_socket_only(self):
        issued = token_response(refresh="RUN-REFRESH")
        self.kc.token = lambda form: (200, issued)
        sess_ts = tokenset(exp_in=200, refresh="SESSION-REFRESH")
        _sid, sess = self.session(sess_ts)
        status, err = self.ws.start_run(sess, "dev")
        self.assertEqual((status, err), (200, None))
        self.ws.STATE["run"].wait(15)
        path = os.path.join(self.spool, "result")
        for _ in range(50):
            if os.path.exists(path):
                break
            time.sleep(0.1)
        with open(path) as f:
            kind, n = f.read().split()
        self.assertEqual(kind, "OK")
        self.assertEqual(int(n), len(issued["access_token"]))
        # The forced refresh happened before the spawn: one refresh_token grant.
        self.assertEqual([f["grant_type"] for p, f in self.kc.calls if p == "/token"],
                         ["refresh_token"])
        for name in ("cmdline", "environ"):
            with open(os.path.join(self.spool, name), "rb") as f:
                raw = f.read()
            for secret in (issued["access_token"], "RUN-REFRESH", "SESSION-REFRESH",
                           sess_ts.access, SECRET):
                self.assertNotIn(secret.encode(), raw, name)
        with open(os.path.join(self.spool, "log")) as f:
            self.assertIn("started by alice", f.readline())
        # The session itself was refreshed (so a later Start does not present a
        # refresh token as old as the sign-in), and the run took a copy of it.
        self.assertEqual(sess_ts.refresh, "RUN-REFRESH")
        self.assertEqual(self.ws.STATE["run_owner"], {"sub": "u-alice", "user": "alice"})
        for _ in range(50):
            if self.ws.STATE["run_auth"] is None:
                break
            time.sleep(0.1)
        self.assertIsNone(self.ws.STATE["run_auth"])

    def test_failed_forced_refresh_is_401_and_spawns_nothing(self):
        self.kc.token = lambda form: (400, {"error": "invalid_grant"})
        sid, sess = self.session(tokenset(exp_in=200))
        status, err = self.ws.start_run(sess, "dev")
        self.assertEqual(status, 401)
        self.assertEqual(err, "login required")
        self.assertIsNone(self.ws.STATE["run"])
        self.assertNotIn(sid, self.ws.STATE["sessions"])

    def test_lost_role_at_start_is_403(self):
        self.ws.STATE["required_role"] = "engineer"
        self.kc.token = lambda form: (200, token_response(roles=()))
        sid, sess = self.session(tokenset(exp_in=200, roles=("engineer",)))
        status, err = self.ws.start_run(sess, "dev")
        self.assertEqual(status, 403)
        self.assertIn("'engineer'", err)
        self.assertIsNone(self.ws.STATE["run"])
        self.assertNotIn(sid, self.ws.STATE["sessions"])

    def answer(self, sid):
        with open(os.path.join(self.spool, "prompt.json"), "w") as f:
            json.dump({"id": "p1", "label": "Slot?"}, f)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), self.ws.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            req = urllib.request.Request(
                "http://127.0.0.1:%d/api/answer" % srv.server_address[1],
                data=json.dumps({"id": "p1", "value": "1"}).encode(),
                headers={"Cookie": "%s=%s" % (self.ws.COOKIE, sid),
                         "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    return r.status, r.read()
            except urllib.error.HTTPError as e:
                with e:
                    return e.code, e.read()
        finally:
            srv.shutdown()
            srv.server_close()

    def test_only_the_run_owner_answers(self):
        self.ws.STATE["run_owner"] = {"sub": "u-alice", "user": "alice"}
        bob, _ = self.session(tokenset(sub="u-bob", user="bob"), sub="u-bob")
        status, body = self.answer(bob)
        self.assertEqual(status, 403)
        self.assertIn(b"belongs to alice", body)
        self.assertFalse(os.path.exists(os.path.join(self.spool, "answer")))
        alice, _ = self.session(tokenset())
        self.assertEqual(self.answer(alice)[0], 200)
        with open(os.path.join(self.spool, "answer")) as f:
            self.assertEqual(f.read(), "1")

    def test_ui_run_is_bound_only_by_the_terminal_link(self):
        self.ws.STATE["daemon"] = False
        self.ws.STATE["token"] = "RUN-URL-TOKEN"
        holder = self.ws.edge_auth.Holder(self.kc.oidc(), None, CLIENT, SECRET,
                                          waiter=self.ws.BrowserWaiter())
        self.ws.STATE["run_auth"] = holder
        # Someone who reached the port first, from the bare address.
        self.assertEqual(self.callback(token_response(sub="u-eve", user="eve"))[0], 302)
        self.assertIsNone(holder.ts)
        self.assertIsNone(self.ws.STATE["run_owner"])
        # The operator, through the printed link.
        self.assertEqual(self.callback(token_response(), bind=True)[0], 302)
        self.assertEqual(holder.ts.sub, "u-alice")
        self.assertEqual(self.ws.STATE["run_owner"]["user"], "alice")

    def reauth_holder(self):
        ts = tokenset(exp_in=200)
        ts.state = "reauth"
        holder = self.ws.edge_auth.Holder(self.kc.oidc(), None, CLIENT, SECRET,
                                          waiter=self.ws.BrowserWaiter(), ts=ts)
        self.ws.STATE["run_auth"] = holder
        out, emitted = [], []
        th = threading.Thread(target=lambda: out.append(holder.handle(120, "record the board",
                                                                      emitted.append)),
                              daemon=True)
        th.start()
        return holder, th, out, emitted

    def callback(self, resp, role=None, bind=False):
        """Drive /oauth2/callback through the real handler; returns the HTTP status."""
        self.ws.STATE["required_role"] = role
        self.kc.token = lambda form: (200, resp) if form["grant_type"] == "authorization_code" \
            else (400, {"error": "invalid_grant"})
        srv = ThreadingHTTPServer(("127.0.0.1", 0), self.ws.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            host = "127.0.0.1:%d" % srv.server_address[1]
            self.ws.STATE["hosts"] = {host: "http"}
            self.ws.STATE["pending"]["st"] = {"exp": time.time() + 60,
                                              "redirect_uri": "http://%s/oauth2/callback" % host,
                                              "bind": bind}

            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **k):
                    return None
            op = urllib.request.build_opener(NoRedirect)
            try:
                with op.open("http://%s/oauth2/callback?code=c&state=st" % host, timeout=10) as r:
                    return r.status, r.read()
            except urllib.error.HTTPError as e:
                with e:
                    return e.code, e.read()
        finally:
            srv.shutdown()
            srv.server_close()

    def test_reauth_resumes_on_same_sub_only(self):
        holder, th, out, emitted = self.reauth_holder()
        for _ in range(50):
            if emitted:
                break
            time.sleep(0.05)
        self.assertIn(b"Sign in again as alice", emitted[0])
        # Someone else signs in: they get a session, the run stays paused.
        status, _ = self.callback(token_response(sub="u-bob", user="bob"))
        self.assertEqual(status, 302)
        th.join(0.5)
        self.assertTrue(th.is_alive())
        # The owner signs in again: the run continues.
        status, _ = self.callback(token_response(sub="u-alice", refresh="R-NEW"))
        self.assertEqual(status, 302)
        th.join(5)
        self.assertFalse(th.is_alive())
        self.assertTrue(out[0].startswith(b"OK\t"))
        self.assertEqual(holder.ts.refresh, "R-NEW")

    def test_different_sub_stays_blocked_until_the_run_ends(self):
        holder, th, out, _e = self.reauth_holder()
        self.callback(token_response(sub="u-bob", user="bob"))
        alive = [True]
        holder.alive = lambda: alive[0]
        alive[0] = False
        th.join(10)
        self.assertTrue(out[0].startswith(b"ERR\ttimeout\t"))

    def test_owner_logout_sets_reauth(self):
        ts = tokenset(exp_in=200)
        holder = self.ws.edge_auth.Holder(self.kc.oidc(), None, CLIENT, SECRET,
                                          waiter=self.ws.BrowserWaiter(), ts=ts)
        self.ws.STATE["run_auth"] = holder
        sid, _ = self.session(tokenset())
        srv = ThreadingHTTPServer(("127.0.0.1", 0), self.ws.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            req = urllib.request.Request("http://127.0.0.1:%d/logout" % srv.server_address[1],
                                         headers={"Cookie": "%s=%s" % (self.ws.COOKIE, sid)})

            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **k):
                    return None
            try:
                urllib.request.build_opener(NoRedirect).open(req, timeout=10)
            except urllib.error.HTTPError as e:
                e.close()
                self.assertEqual(e.code, 302)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(ts.state, "reauth")
        self.assertEqual(ts.access, "")

    def test_role_is_read_from_the_access_token(self):
        # The ID token carries no roles at all; the access token decides.
        status, _ = self.callback(token_response(roles=("engineer",)), role="engineer")
        self.assertEqual(status, 302)
        status, body = self.callback(token_response(roles=()), role="engineer")
        self.assertEqual(status, 403)
        self.assertIn(b"User Manager", body)
        status, body = self.callback(token_response(aud="account"))
        self.assertEqual(status, 502)
        self.assertIn(b"./deploy-infra.sh", body)

    def test_callback_with_the_policy_list(self):
        # IAM 3.4: STATE holds the tuple main() makes of "engineer,maintenance"
        need = self.ws.edge_auth.roles_of("engineer,maintenance")
        self.assertEqual(need, ("engineer", "maintenance"))
        status, body = self.callback(token_response(roles=("operator",)), role=need)
        self.assertEqual(status, 403)
        self.assertIn(b"required to provision hardware", body)   # iam_signin_flow.py classifies on it
        self.assertIn(b"'engineer', 'maintenance'", body)
        status, _ = self.callback(token_response(roles=("maintenance",), groups=("maintenance",)), role=need)
        self.assertEqual(status, 302)


if __name__ == "__main__":
    unittest.main(verbosity=1)
