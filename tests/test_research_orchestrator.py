"""research orchestrator (stage 6a): lifecycle, person routes, sign-in relay, sim API, against a
fake Kubernetes interface and a fake research-session. No cluster, no network beyond local ports."""
import importlib.util
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "apps", "research-agents"))
sys.path.insert(0, ROOT)
import jobs  # noqa: E402

spec = importlib.util.spec_from_file_location("orch", os.path.join(ROOT, "apps", "research-agents", "orchestrator.py"))
orch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(orch)

SID = "A" * 22
WHO = {"sub": "11111111-1111-1111-1111-111111111111", "person_id": "p-1", "username": "bio"}
CFG = {"image": "img", "code_commit": "abc1234", "session_url": "http://s:8101", "mcp_sim_url": "http://sim:8080",
       "mcp_lake_url": "http://lake:8080", "profiles_dir": os.path.join(ROOT, "research", "agents", "profiles"), "pool": 2}


class FakeKube:
    def __init__(self):
        self.jobs, self.deleted, self.pods, self.status, self.logs = {}, [], {}, {}, {}
        self.fail_create = False

    def create_job(self, m):
        if self.fail_create:
            raise RuntimeError("no")
        self.jobs[m["metadata"]["name"]] = m

    def job_status(self, name):
        if name not in self.jobs:
            return None
        return self.status.get(name, {"active": 1, "succeeded": 0, "failed": 0, "reason": ""})

    def pod_of_job(self, name):
        return self.pods.get(name)

    def delete_job(self, name):
        self.deleted.append(name)
        return self.jobs.pop(name, None) is not None

    def pod_log(self, pod, limit=0):
        return self.logs[pod]


class FakeHttp:
    def __init__(self):
        self.calls, self.sessions, self.answers = [], {}, {}

    def request(self, method, path, body=None, headers=None):
        self.calls.append((method, path, body, headers))
        if (method, path) in self.answers:
            return self.answers[(method, path)]
        if method == "POST" and path == "/mint":
            return 201, {"sid": SID, "claim": "c" * 43, "exp": 99}
        if method == "GET" and path.startswith("/sessions/"):
            i = self.sessions.get(path.split("/")[2])
            return (200, i) if i else (404, {})
        return 200, {}


def info(person="p-1", active=True):
    return {"sid": SID, "sup_person": person, "profile": "compare_controllers", "backend": "scripted", "exp": 99,
            "claimed": False, "active": active, "revoked": False, "budget": {}, "spent": {}}


def make(clock=None):
    k, ph, sh = FakeKube(), FakeHttp(), FakeHttp()
    sh.sessions[SID] = info()
    return orch.Orchestrator(CFG, k, ph, sh, clock=clock or (lambda: 1000.0)), k, ph, sh


class LifecycleTest(unittest.TestCase):
    def test_start_mints_and_creates_job(self):
        o, k, ph, sh = make()
        st, r = o.start(WHO, "TOK", {"profile": "compare_controllers", "budget": {"turns": 5}})
        self.assertEqual((st, r["sid"]), (201, SID))
        mint = ph.calls[0]
        self.assertEqual(mint[1], "/mint")
        self.assertEqual(mint[3], {"X-Forwarded-Access-Token": "TOK"})
        self.assertEqual(mint[2]["budget"]["turns"], 5)
        self.assertEqual(len(mint[2]["profile_sha256"]), 64)
        job = k.jobs[jobs.agent_job_name(SID)]
        env = {e["name"]: e["value"] for e in job["spec"]["template"]["spec"]["containers"][0]["env"]}
        self.assertEqual((env["MEDCEA_SID"], env["MEDCEA_CLAIM"]), (SID, "c" * 43))
        self.assertNotIn("ownerReferences", job["metadata"])
        self.assertFalse(job["spec"]["template"]["spec"]["automountServiceAccountToken"])
        self.assertRegex(job["metadata"]["name"], r"^agent-[0-9a-f]{20}$")

    def test_start_refusals(self):
        o, k, ph, sh = make()
        self.assertEqual(o.start(WHO, "T", {"profile": "../x"})[0], 400)
        self.assertEqual(o.start(WHO, "T", {"profile": "nope"})[0], 400)
        self.assertEqual(o.start(WHO, "T", {"profile": "compare_controllers", "budget": {"turns": 9999}})[0], 400)
        self.assertEqual(o.start(WHO, "T", {"profile": "compare_controllers", "budget": {"wall_h": 1}})[0], 400)
        ph.answers[("POST", "/mint")] = (409, {"error": "person already has 2 active sessions"})
        self.assertEqual(o.start(WHO, "T", {"profile": "compare_controllers"})[0], 409)
        self.assertEqual(k.jobs, {})

    def test_a_local_profile_is_refused_without_a_gateway(self):
        o, k, ph, sh = make()
        st, r = o.start(WHO, "T", {"profile": "compare_controllers_local"})
        self.assertEqual(st, 409)
        self.assertIn("local model", r["error"])
        self.assertIn("no model gateway is configured", r["error"])
        self.assertEqual((ph.calls, k.jobs), ([], {}))       # nothing minted, no Job

    def test_a_local_profile_with_a_gateway(self):
        gw = "http://model-gateway.medcea-research-gw.svc.cluster.local:8120"
        o, k, ph, sh = make()
        o.cfg = dict(o.cfg, model_gateway_url=gw)
        st, r = o.start(WHO, "T", {"profile": "compare_controllers_local"})
        self.assertEqual(st, 201)
        mint = ph.calls[0][2]
        self.assertEqual((mint["backend"], mint["profile"]), ("local", "compare_controllers_local"))
        job = k.jobs[jobs.agent_job_name(SID)]
        env = {e["name"]: e["value"] for e in job["spec"]["template"]["spec"]["containers"][0]["env"]}
        self.assertEqual(env["MEDCEA_MODEL_GATEWAY"], gw)
        self.assertEqual(env["MEDCEA_PROFILE"], "compare_controllers_local")

    INVENTORY = [{"name": "local", "kind": "llama", "model": "qwen3-4b", "context": 4096, "deterministic": True,
                  "tools": "native", "where": "this host (CPU)"},
                 {"name": "gpu", "kind": "openai", "model": "Qwen/Qwen3-14B-AWQ", "context": 12288, "deterministic": True,
                  "tools": "text", "thinking": False, "where": "another server"},
                 {"name": "spare", "kind": "openai", "model": "m", "context": 8192, "deterministic": False,
                  "tools": "native", "where": "another server"}]

    def picker(self):
        o, k, ph, sh = make()
        o.cfg = dict(o.cfg, model_gateway_url="http://g:8120", endpoints=["local", "gpu"], inventory=self.INVENTORY)
        return o, k, ph, sh

    def test_the_model_picker_lists_the_enabled_endpoints(self):
        """Research Phase 4d: GET /api/sessions carries the inventory (no route of its own: no policy change)."""
        o, *_ = self.picker()
        st, r = o.listing(WHO)
        self.assertEqual(st, 200)
        self.assertEqual([e["name"] for e in r["endpoints"]], ["local", "gpu"])     # 'spare' is not enabled
        self.assertNotIn("url", json.dumps(r))
        self.assertEqual(orch._inventory(""), [])
        self.assertEqual(orch._inventory("not base64!"), [])
        import base64
        self.assertEqual(orch._inventory(base64.b64encode(json.dumps(self.INVENTORY).encode()).decode()), self.INVENTORY)

    def test_start_on_a_chosen_endpoint(self):
        o, k, ph, sh = self.picker()
        st, r = o.start(WHO, "T", {"profile": "compare_controllers_local", "endpoint": "gpu"})
        self.assertEqual((st, r["endpoint"]), (201, "gpu"))
        self.assertEqual(ph.calls[0][2]["backend"], "gpu")          # the session's backend: the gateway serves it
        env = {e["name"]: e["value"] for e in k.jobs[jobs.agent_job_name(SID)]["spec"]["template"]["spec"]["containers"][0]["env"]}
        self.assertEqual((env["MEDCEA_ENDPOINT"], env["MEDCEA_ENDPOINT_CONTEXT"]), ("gpu", "12288"))
        # without a choice, the profile's own model and no endpoint in the Job
        o, k, ph, sh = self.picker()
        st, r = o.start(WHO, "T", {"profile": "compare_controllers_local"})
        self.assertEqual((st, r["endpoint"], ph.calls[0][2]["backend"]), (201, "local", "local"))
        env = {e["name"]: e["value"] for e in k.jobs[jobs.agent_job_name(SID)]["spec"]["template"]["spec"]["containers"][0]["env"]}
        self.assertNotIn("MEDCEA_ENDPOINT", env)

    def test_a_choice_that_is_refused(self):
        o, k, ph, sh = self.picker()
        st, r = o.start(WHO, "T", {"profile": "compare_controllers_local", "endpoint": "spare"})
        self.assertEqual(st, 409)
        self.assertIn("choose one of local, gpu", r["error"])
        self.assertEqual(o.start(WHO, "T", {"profile": "compare_controllers", "endpoint": "gpu"})[0], 400)   # scripted
        self.assertEqual(o.start(WHO, "T", {"profile": "compare_controllers_local", "endpoint": 7})[0], 409)
        o.cfg = dict(o.cfg, inventory=[])                                # enabled, but no inventory (an older deploy)
        st, r = o.start(WHO, "T", {"profile": "compare_controllers_local", "endpoint": "gpu"})
        self.assertEqual(st, 409)
        self.assertIn("./apps/research-agents/deploy.sh", r["error"])
        self.assertEqual((ph.calls, k.jobs), ([], {}))

    def test_a_scripted_session_is_unchanged_by_a_gateway(self):
        o, k, ph, sh = make()
        o.cfg = dict(o.cfg, model_gateway_url="http://g:8120")
        o.start(WHO, "T", {"profile": "compare_controllers"})
        self.assertEqual(ph.calls[0][2]["backend"], "scripted")

    def test_no_gateway_address_in_a_job_without_one(self):
        o, k, ph, sh = make()
        o.start(WHO, "T", {"profile": "compare_controllers"})
        env = {e["name"] for e in k.jobs[jobs.agent_job_name(SID)]["spec"]["template"]["spec"]["containers"][0]["env"]}
        self.assertNotIn("MEDCEA_MODEL_GATEWAY", env)

    def test_job_failure_revokes(self):
        o, k, ph, sh = make()
        k.fail_create = True
        self.assertEqual(o.start(WHO, "T", {"profile": "compare_controllers"})[0], 502)
        self.assertEqual(sh.calls[-1][:2], ("POST", "/sessions/%s/revoke" % SID))

    def test_tick_registers_pod_ip_then_revokes_on_end(self):
        o, k, ph, sh = make()
        o.start(WHO, "T", {"profile": "compare_controllers"})
        name = jobs.agent_job_name(SID)
        k.pods[name] = {"name": "p", "phase": "Pending", "ip": ""}
        o.tick()
        self.assertFalse([c for c in sh.calls if c[0] == "PUT"])
        k.pods[name] = {"name": "p", "phase": "Running", "ip": "10.1.2.3"}
        o.tick()
        o.tick()
        puts = [c for c in sh.calls if c[0] == "PUT"]
        self.assertEqual(len(puts), 1)
        self.assertEqual((puts[0][1], puts[0][2]), ("/claims/%s/expect" % SID, {"peer": "10.1.2.3"}))
        k.status[name] = {"active": 0, "succeeded": 1, "failed": 0, "reason": ""}
        o.tick()
        self.assertEqual(sh.calls[-1][:3], ("POST", "/sessions/%s/revoke" % SID, {"reason": "job ended"}))
        self.assertIn(name, k.deleted)
        self.assertEqual(o.track, {})

    def test_a_failed_agent_job_leaves_its_log_tail(self):
        # E48 (23 Nov 2026): an agent that died at start was revoked "job ended" and its Job deleted with its log
        import contextlib
        import io
        o, k, ph, sh = make()
        o.start(WHO, "T", {"profile": "compare_controllers"})
        name = jobs.agent_job_name(SID)
        k.pods[name] = {"name": "agentpod", "phase": "Failed", "ip": "10.1.2.3"}
        k.logs["agentpod"] = "Traceback (most recent call last):\n" + "x" * 500 + "\nToolError: refused\n"
        k.status[name] = {"active": 0, "succeeded": 0, "failed": 1, "reason": "BackoffLimitExceeded"}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            o.tick()
        self.assertEqual(sh.calls[-1][2], {"reason": "job failed"})
        out = err.getvalue()
        self.assertIn("agent Job %s failed" % name, out)
        self.assertIn("  | ToolError: refused", out)
        self.assertNotIn("x" * 301, out)
        self.assertIn(name, k.deleted)

    def test_pod_that_never_runs_is_stopped(self):
        now = [1000.0]
        o, k, ph, sh = make(clock=lambda: now[0])
        o.start(WHO, "T", {"profile": "compare_controllers"})
        k.pods[jobs.agent_job_name(SID)] = {"name": "p", "phase": "Pending", "ip": ""}
        now[0] += orch.START_GRACE_S + 1
        o.tick()
        self.assertEqual(sh.calls[-1][2], {"reason": "pod did not start"})

    def test_tick_survives_a_kube_error(self):
        o, k, ph, sh = make()
        o.start(WHO, "T", {"profile": "compare_controllers"})
        k.pod_of_job = lambda n: (_ for _ in ()).throw(RuntimeError("x"))
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()):
            o.tick()
        self.assertIn(SID, o.track)

    def test_stop_deletes_agent_and_sim_jobs(self):
        o, k, ph, sh = make()
        o.start(WHO, "T", {"profile": "compare_controllers"})
        cid = "c" + "a" * 20
        o.runner.start(cid, {"x": 1}, 1.0, 100, sid=SID)
        self.assertEqual(o.stop(WHO, "T", SID)[0], 200)
        self.assertEqual(ph.calls[-1][:3], ("POST", "/revoke", {"sid": SID, "reason": "stopped by the supervisor"}))
        self.assertEqual(sorted(k.jobs), [])
        self.assertEqual(o.stop(dict(WHO, person_id="p-2"), "T", SID)[0], 404)   # not the supervisor

    def test_ownership_everywhere(self):
        o, k, ph, sh = make()
        other = dict(WHO, person_id="p-2")
        self.assertEqual(o.info(other, SID)[0], 404)
        self.assertEqual(o.events(other, SID, 0)[0], 404)
        self.assertEqual(o.decide(other, "T", "gates", SID, "g1", {"decision": "approve"})[0], 404)
        self.assertEqual(o.replay(other, SID)[0], 404)
        self.assertEqual(o.info(WHO, "bad")[0], 404)

    def test_gate_default_cap_comes_from_the_pending_event(self):
        o, k, ph, sh = make()
        sh.answers[("GET", "/gates/g1?sid=%s" % SID)] = (200, {"state": "pending", "pending": {"cap_h": 3.0}})
        o.decide(WHO, "T", "gates", SID, "g1", {"decision": "approve"})
        post = ph.calls[-1]
        self.assertEqual((post[1], post[2]["approved_cap_h"], post[3]), ("/sessions/%s/gates/g1" % SID, 3.001, {"X-Forwarded-Access-Token": "T"}))
        o.decide(WHO, "T", "gates", SID, "g1", {"decision": "approve", "approved_cap_h": 2})
        self.assertEqual(ph.calls[-1][2]["approved_cap_h"], 2)
        o.decide(WHO, "T", "gates", SID, "g1", {"decision": "deny"})
        self.assertNotIn("approved_cap_h", ph.calls[-1][2])

    def test_replay_of_a_running_session_is_refused(self):
        o, k, *_ = make()
        self.assertEqual(o.replay(WHO, SID)[0], 409)
        self.assertEqual(k.jobs, {})


class SimApiTest(unittest.TestCase):
    CID = "c" + "b" * 20

    def test_sim_start_and_status(self):
        o, k, ph, sh = make()
        st, r = o.sim_start({"sid": SID, "cid": self.CID, "spec": {"a": 1}, "cap_h": 1.5, "deadline_s": 900})
        self.assertEqual(st, 200)
        job = k.jobs["sim-" + self.CID]
        self.assertEqual(job["spec"]["activeDeadlineSeconds"], 900)
        cmd = job["spec"]["template"]["spec"]["containers"][0]["command"]
        self.assertIn("--max-cpu-hours", cmd)
        self.assertEqual(o.sim_status(self.CID), (200, {"state": "running"}))

    def test_sim_start_refusals(self):
        o, k, ph, sh = make()
        base = {"sid": SID, "cid": self.CID, "spec": {}, "cap_h": 1, "deadline_s": 10}
        self.assertEqual(o.sim_start(dict(base, cid="x"))[0], 400)
        self.assertEqual(o.sim_start(dict(base, cap_h=99))[0], 400)
        sh.sessions[SID]["active"] = False
        self.assertEqual(o.sim_start(base)[0], 403)
        self.assertEqual(k.jobs, {})


class HttpTest(unittest.TestCase):
    """The handlers over real local ports with a fake check()."""

    class Dec:
        def __init__(self, allow, status=200, reason="", who=None):
            self.allow, self.status, self.reason, self.who = allow, status, reason, who

    class Iam:
        def __init__(self):
            self.seen = []

        def check(self, service, method, path, headers):
            self.seen.append((service, method, path))
            if headers.get("X-Forwarded-Access-Token") != "TOK":
                return HttpTest.Dec(False, 401, "no token")
            return HttpTest.Dec(True, who=WHO)

    def setUp(self):
        self.o, self.k, self.ph, self.sh = make()
        self.o.iam = self.Iam()
        self.srvs = orch.make_servers(self.o, "127.0.0.1", (0, 0))
        self.ports = [s.server_address[1] for s in self.srvs]
        for s in self.srvs:
            threading.Thread(target=s.serve_forever, daemon=True).start()

    def tearDown(self):
        for s in self.srvs:
            s.shutdown()
            s.server_close()

    def call(self, i, method, path, body=None, token="TOK"):
        h = {"Content-Type": "application/json"}
        if token:
            h["X-Forwarded-Access-Token"] = token
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.ports[i], path),
                                     None if body is None else json.dumps(body).encode(), h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_routes_are_checked_as_the_orchestrator_service(self):
        self.assertEqual(self.call(0, "POST", "/api/sessions", {"profile": "compare_controllers"}, token=None)[0], 401)
        st, r = self.call(0, "POST", "/api/sessions", {"profile": "compare_controllers"})
        self.assertEqual((st, r["sid"]), (201, SID))
        self.assertEqual(self.o.iam.seen[-1], ("research-orchestrator", "POST", "/api/sessions"))
        self.assertEqual(self.call(0, "GET", "/api/sessions")[1]["sessions"][0]["sid"], SID)
        self.assertEqual(self.call(0, "GET", "/api/sessions/" + SID)[0], 200)
        self.assertEqual(self.call(0, "GET", "/api/sessions/%s/events?after=3" % SID)[0], 200)
        self.assertIn(("GET", "/events/%s?after=3" % SID), [c[:2] for c in self.sh.calls])
        self.assertEqual(self.call(0, "POST", "/api/sessions/%s/stop" % SID, {})[0], 200)
        self.assertEqual(self.call(0, "POST", "/api/sessions/%s/replay" % SID, {})[0], 409)   # routed and owned; the fake session is still active
        self.assertEqual(self.call(0, "GET", "/api/nothing")[0], 404)

    def test_signin_relay_is_public_and_forwarded(self):
        self.sh.answers[("POST", "/signin/start")] = (200, {"device_code": "x" * 12, "user_code": "AB"})
        st, r = self.call(0, "POST", "/api/signin/start", {}, token=None)
        self.assertEqual((st, r["user_code"]), (200, "AB"))
        self.sh.answers[("POST", "/signin/poll")] = (400, {"error": "authorization_pending"})
        self.assertEqual(self.call(0, "POST", "/api/signin/poll", {"device_code": "x"}, token=None),
                         (400, {"error": "authorization_pending"}))
        self.sh.answers[("POST", "/signin/refresh")] = (0, {})
        self.assertEqual(self.call(0, "POST", "/api/signin/refresh", {"refresh_token": "x"}, token=None)[0], 502)
        self.assertEqual(self.o.iam.seen, [])                      # check() was never asked

    def test_sim_port_has_no_person_routes(self):
        self.assertEqual(self.call(1, "GET", "/api/sessions")[0], 404)
        st, _ = self.call(1, "POST", "/internal/sims", {"sid": SID, "cid": "c" + "c" * 20, "spec": {}, "cap_h": 1, "deadline_s": 60})
        self.assertEqual(st, 200)
        self.assertEqual(self.call(1, "GET", "/internal/sims/" + "c" + "c" * 20)[1], {"state": "running"})

    def test_no_secret_in_the_log(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            self.call(0, "POST", "/api/sessions", {"profile": "compare_controllers"})
        self.assertNotIn("TOK", buf.getvalue())
        self.assertNotIn("c" * 43, buf.getvalue())


if __name__ == "__main__":
    unittest.main()
