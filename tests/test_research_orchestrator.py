"""research orchestrator (stage 6a): lifecycle, person routes, sign-in relay, sim API, against a
fake Kubernetes interface and a fake research-session. No cluster, no network beyond local ports."""
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import sys
import tempfile
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

    def test_the_gpu_profile_on_its_own_endpoint(self):
        """compare_controllers_gpu (26 Nov 2026): 12000 tokens of context on the endpoint named gpu; refused where gpu
        is not enabled or holds less than its caps.context_tokens + loop.CONTEXT_MARGIN (96)."""
        o, k, ph, sh = self.picker()
        st, r = o.start(WHO, "T", {"profile": "compare_controllers_gpu"})
        self.assertEqual((st, r["endpoint"], ph.calls[0][2]["backend"]), (201, "gpu", "gpu"))
        self.assertEqual(ph.calls[0][2]["profile"], "compare_controllers_gpu")
        o, k, ph, sh = self.picker()
        o.cfg = dict(o.cfg, endpoints=["local"])
        st, r = o.start(WHO, "T", {"profile": "compare_controllers_gpu"})
        self.assertEqual(st, 409)
        self.assertIn("uses the endpoint gpu, which is not enabled", r["error"])
        small = [dict(i, context=8192) if i["name"] == "gpu" else i for i in self.INVENTORY]
        o.cfg = dict(o.cfg, endpoints=["local", "gpu"], inventory=small)
        st, r = o.start(WHO, "T", {"profile": "compare_controllers_gpu"})
        self.assertEqual(st, 409)
        self.assertEqual(r["error"], "the profile compare_controllers_gpu needs 12000 tokens of context and the endpoint gpu "
                                     "holds 8096 (8192 less the chat template's 96): choose another profile, or this one "
                                     "with an endpoint that holds more")
        self.assertEqual((ph.calls, k.jobs), ([], {}))
        # naming the profile's own endpoint (the picker, reexecute) is checked the same way (review of 26 Nov 2026)
        st, r = o.start(WHO, "T", {"profile": "compare_controllers_gpu", "endpoint": "gpu"})
        self.assertEqual(st, 409)
        self.assertIn("needs 12000 tokens of context and the endpoint gpu holds 8096", r["error"])
        self.assertEqual((ph.calls, k.jobs), ([], {}))
        # the local profile fits the local model exactly (4000 = 4096 - 96); the picker's choice is the loop's to cap
        o, k, ph, sh = self.picker()
        self.assertEqual(o.start(WHO, "T", {"profile": "compare_controllers_local"})[0], 201)
        o, k, ph, sh = self.picker()
        self.assertEqual(o.start(WHO, "T", {"profile": "compare_controllers_gpu", "endpoint": "local"})[0], 201)

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

    def test_sim_finished_is_written_when_the_job_ends(self):
        # research Phase 4e (design 2.2): the orchestrator records the campaign's end itself, once; session_status
        # counts one sim_finished per cid, so mcp-sim's own record does not double it
        o, k, ph, sh = make()
        o.sim_start({"sid": SID, "cid": self.CID, "spec": {"a": 1}, "cap_h": 1.5, "deadline_s": 900})
        traces = lambda: [c for c in sh.calls if c[:2] == ("POST", "/trace")]
        o.tick()
        self.assertEqual(traces(), [])                                   # still running: nothing
        name = "sim-" + self.CID
        k.status[name] = {"active": 0, "succeeded": 1, "failed": 0, "reason": ""}
        k.pods[name] = {"name": "simpod", "phase": "Succeeded", "ip": ""}
        k.logs["simpod"] = 'x\nSIM_RESULT {"state": "done", "cpu_hours": 0.4, "manifest": {"result_digest": "dd"}}\n'
        o.tick()
        o.tick()
        self.assertEqual(len(traces()), 1)
        body = traces()[0][2]
        self.assertEqual((body["server"], body["sid"], body["event"]), ("orchestrator", SID, "sim_finished"))
        self.assertEqual(body["payload"], {"cid": self.CID, "state": "done", "cpu_hours": 0.4, "result_digest": "dd",
                                           "cap_h": 1.5})
        # a failed Job without a result line is recorded as failed, with no CPU
        cid2 = "c" + "e" * 20
        o.sim_start({"sid": SID, "cid": cid2, "spec": {"a": 1}, "cap_h": 1, "deadline_s": 900})
        k.status["sim-" + cid2] = {"active": 0, "succeeded": 0, "failed": 1, "reason": "DeadlineExceeded"}
        o.tick()
        self.assertEqual(traces()[-1][2]["payload"], {"cid": cid2, "state": "failed", "cpu_hours": 0.0,
                                                      "result_digest": None, "cap_h": 1})

    def test_a_campaign_running_at_the_sessions_end_is_recorded_once_as_stopped(self):
        # the session's end deletes the sim Job: the trace must not leave the campaign running; its CPU is unknown
        o, k, ph, sh = make()
        o.start(WHO, "T", {"profile": "compare_controllers"})
        o.sim_start({"sid": SID, "cid": self.CID, "spec": {"a": 1}, "cap_h": 1.5, "deadline_s": 900})
        k.status[jobs.agent_job_name(SID)] = {"active": 0, "succeeded": 1, "failed": 0, "reason": ""}
        o.tick()
        o.tick()
        fin = [c[2] for c in sh.calls if c[:2] == ("POST", "/trace") and c[2]["event"] == "sim_finished"]
        self.assertEqual(fin, [{"server": "orchestrator", "sid": SID, "event": "sim_finished", "payload": {
            "cid": self.CID, "state": "failed", "cpu_hours": None, "result_digest": None, "cap_h": 1.5,
            "error": "stopped with the session before the Job finished"}}])
        self.assertIn("sim-" + self.CID, k.deleted)
        self.assertEqual((o.runner.owner, o.sim_caps, o.sims_reported), ({}, {}, set()))

    def test_a_campaign_that_ended_with_the_session_is_reported_with_its_result(self):
        o, k, ph, sh = make()
        o.start(WHO, "T", {"profile": "compare_controllers"})
        o.sim_start({"sid": SID, "cid": self.CID, "spec": {"a": 1}, "cap_h": 1, "deadline_s": 900})
        name = "sim-" + self.CID
        k.status[name] = {"active": 0, "succeeded": 1, "failed": 0, "reason": ""}
        k.pods[name] = {"name": "simpod", "phase": "Succeeded", "ip": ""}
        k.logs["simpod"] = 'SIM_RESULT {"state": "done", "cpu_hours": 0.2, "manifest": {"result_digest": "ee"}}\n'
        k.status[jobs.agent_job_name(SID)] = {"active": 0, "succeeded": 1, "failed": 0, "reason": ""}
        o.tick()
        fin = [c[2]["payload"] for c in sh.calls if c[:2] == ("POST", "/trace") and c[2]["event"] == "sim_finished"]
        self.assertEqual(fin, [{"cid": self.CID, "state": "done", "cpu_hours": 0.2, "result_digest": "ee", "cap_h": 1}])

    def test_the_series_interval_reaches_the_sim_job(self):
        # research Phase 4e: RS_SIM_SERIES_EVERY (cfg series_every), 60 s when unset
        for cfg, want in ((CFG, "60"), (dict(CFG, series_every=0.0), "0"), (dict(CFG, series_every=120.0), "120")):
            k, ph, sh = FakeKube(), FakeHttp(), FakeHttp()
            sh.sessions[SID] = info()
            o = orch.Orchestrator(cfg, k, ph, sh, clock=lambda: 1000.0)
            self.assertEqual(o.sim_start({"sid": SID, "cid": self.CID, "spec": {"a": 1}, "cap_h": 1,
                                          "deadline_s": 900})[0], 200)
            cmd = k.jobs["sim-" + self.CID]["spec"]["template"]["spec"]["containers"][0]["command"]
            self.assertEqual(cmd[cmd.index("--series-every") + 1], want)

    def test_sim_finished_is_retried_until_the_session_answers(self):
        o, k, ph, sh = make()
        o.sim_start({"sid": SID, "cid": self.CID, "spec": {"a": 1}, "cap_h": 1.5, "deadline_s": 900})
        k.status["sim-" + self.CID] = {"active": 0, "succeeded": 0, "failed": 1, "reason": ""}
        sh.answers[("POST", "/trace")] = (0, {})                          # research-session unreachable
        o.tick()
        sh.answers.pop(("POST", "/trace"))
        o.tick()
        o.tick()
        self.assertEqual(len([c for c in sh.calls if c[:2] == ("POST", "/trace")]), 2)

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

    def call(self, i, method, path, body=None, token="TOK", origin=None):
        h = {"Content-Type": "application/json"}
        if token:
            h["X-Forwarded-Access-Token"] = token
        if origin is not None:
            h["Origin"] = origin
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

    def test_the_origin_rule(self):
        """research Phase 4e (design rs4e §1, CSRF): a POST carrying an Origin must carry the console's own
        (RS_CONSOLE_ORIGIN); without one (the CLI's urllib) it passes; GETs are not affected."""
        self.o.cfg = dict(self.o.cfg, console_origin="https://agents.medcea")
        body = {"profile": "compare_controllers"}
        self.assertEqual(self.call(0, "POST", "/api/sessions", body, origin="https://evil.example"),
                         (403, {"error": "wrong origin"}))
        self.assertEqual(self.call(0, "POST", "/api/signin/start", {}, token=None, origin="https://evil.example")[0], 403)
        self.assertEqual(self.call(0, "POST", "/api/sessions/%s/stop" % SID, {}, origin="null")[0], 403)
        self.assertEqual(self.o.iam.seen, [])                      # refused before the token check
        self.assertEqual(self.call(0, "POST", "/api/sessions", body, origin="https://agents.medcea")[0], 201)
        self.assertEqual(self.call(0, "POST", "/api/sessions/%s/stop" % SID, {})[0], 200)           # no Origin: the CLI
        self.assertEqual(self.call(0, "GET", "/api/sessions", origin="https://evil.example")[0], 200)
        # unset (no console configured): any Origin on a POST is refused
        self.o.cfg = dict(self.o.cfg, console_origin=None)
        self.assertEqual(self.call(0, "POST", "/api/sessions", body, origin="https://agents.medcea")[0], 403)

    def test_json_answers_carry_nosniff(self):
        req = urllib.request.Request("http://127.0.0.1:%d/healthz" % self.ports[0])
        with urllib.request.urlopen(req, timeout=5) as r:
            self.assertEqual((r.headers["X-Content-Type-Options"], r.headers["Cache-Control"]), ("nosniff", "no-store"))

    def test_main_reads_the_console_origin(self):
        with open(orch.__file__) as f:
            src = f.read()
        self.assertIn('"console_origin": os.environ.get("RS_CONSOLE_ORIGIN", "") or None', src)

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


class ConsoleRoutes(unittest.TestCase):
    """Research Phase 4e commit B (design rs4e 3.1): the research console's routes over real local ports, a fake check()
    whose decision carries the person's roles, a fake research-session holding a trace, and a temporary runs volume."""

    OTHER = "B" * 22
    CID = "c" + "1" * 20

    class Dec:
        def __init__(self, allow, status=200, reason="", who=None):
            self.allow, self.status, self.reason, self.who = allow, status, reason, who

    class Iam:
        ROUTES_FILE = "routes.json"

        def __init__(self, roles=("bio_scientist",), table=None):
            self.roles, self.table, self.seen = list(roles), table, []

        def check(self, service, method, path, headers):
            self.seen.append((service, method, path))
            if headers.get("X-Forwarded-Access-Token") is None:
                return ConsoleRoutes.Dec(False, 401, "no token")
            return ConsoleRoutes.Dec(True, who=dict(WHO, roles=list(self.roles)))

        def actor_role(self, d):
            return d.who["roles"][0] if len(d.who["roles"]) == 1 else None

        def _load(self, path):
            return self.table

    class Session(FakeHttp):
        """research-session's server port: sessions, events (pages of 1000) and the person's history."""

        def __init__(self):
            super().__init__()
            self.trace = {}

        def request(self, method, path, body=None, headers=None):
            m = re.match(r"^/events/([^/?]+)\?after=(\d+)$", path)
            if method == "GET" and m and (method, path) not in self.answers:
                self.calls.append((method, path, body, headers))
                return 200, {"events": [e for e in self.trace.get(m.group(1), []) if e["event_id"] > int(m.group(2))][:1000]}
            return super().request(method, path, body, headers)

    def setUp(self):
        self.o, self.k, self.ph, self.sh = make()
        self.sh = self.o.sh = self.Session()
        self.sh.sessions[SID] = dict(info(), sup_username="bio", sup_role="bio_scientist", created_at=900)
        self.sh.sessions[self.OTHER] = dict(info(person="p-2"), sid=self.OTHER)
        self.runs = tempfile.mkdtemp()
        self.o.cfg = dict(self.o.cfg, runs_root=self.runs, console_origin="https://agents.medcea")
        self.o.iam = self.Iam(table=self.route_table())
        self.srvs = orch.make_servers(self.o, "127.0.0.1", (0, 0))
        self.port = self.srvs[0].server_address[1]
        for srv in self.srvs:
            threading.Thread(target=srv.serve_forever, daemon=True).start()

    def tearDown(self):
        for srv in self.srvs:
            srv.shutdown()
            srv.server_close()
        shutil.rmtree(self.runs, ignore_errors=True)

    @staticmethod
    def route_table():
        sys.path.insert(0, os.path.join(ROOT, "apps", "iam"))
        from compiler import model, routes
        return routes.compile(model.load_defaults())

    def call(self, method, path, body=None, token="TOK", origin=None, gz=False):
        h = {"Content-Type": "application/json"}
        if token:
            h["X-Forwarded-Access-Token"] = token
        if origin is not None:
            h["Origin"] = origin
        if gz:
            h["Accept-Encoding"] = "gzip"
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.port, path),
                                     None if body is None else json.dumps(body).encode(), h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                raw = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                return r.status, json.loads(raw)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def campaign_trace(self, digest):
        def ev(i, event, payload, actor="mcp-sim"):
            return {"event_id": i, "at": "2026-11-27T10:00:%02dZ" % i, "actor": actor, "event": event, "payload": payload}
        return [ev(1, "session_minted", {"profile": "compare_controllers", "code_commit": "abc1234", "reexecutes": None},
                   "research-session"),
                ev(2, "gate_pending", {"gid": self.CID, "estimate_h": 3.0, "cap_h": 3.75, "runs": 36, "spec_sha256": "a" * 64}),
                ev(3, "gate_decided", {"gid": self.CID, "decision": "approve", "approved_cap_h": 3.0, "by_username": "bio"},
                   "research-session"),
                ev(4, "sim_started", {"cid": self.CID, "spec_sha256": "a" * 64, "estimate_h": 3.0, "cap_h": 3.0}),
                ev(5, "sim_finished", {"cid": self.CID, "state": "done", "cpu_hours": 0.1, "result_digest": digest}),
                ev(6, "agent_spawned", {"agent": "a0.1", "parent": "a0", "profile_name": "campaign"}, "agent"),
                ev(7, "session_revoked", {"reason": "job ended"}, "research-session")]

    def put_campaign(self, series=True):
        with open(os.path.join(ROOT, "tests", "fixtures", "research", "e58_campaign.json")) as f:
            rows = json.load(f)["rows"]
        d = os.path.join(self.runs, "campaigns", self.CID)
        os.makedirs(os.path.join(d, "series"))
        body = "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows).encode()
        digest = hashlib.sha256(body).hexdigest()
        with open(os.path.join(d, "results.jsonl"), "wb") as f:
            f.write(body)
        man = {"runs": len(rows), "result_digest": digest}
        if series:
            man["series"] = {"every_s": 60.0, "files": ["series/%d.json.gz" % i for i in range(len(rows))], "digest": "d" * 64}
            n = 3000
            doc = {"header": {"schema": 1, "every_s": 60.0, "loops": []}, "changes": [[60.0, "light", 0, 1]],
                   "columns": {"t": [i * 60.0 for i in range(n)], "air_temperature": [20 + i % 9 for i in range(n)]}}
            with open(os.path.join(d, "series", "0.json.gz"), "wb") as f:
                f.write(gzip.compress(json.dumps(doc).encode(), mtime=0))
        with open(os.path.join(d, "manifest.json"), "w") as f:
            json.dump(man, f)
        self.sh.trace[SID] = self.campaign_trace(digest)
        return rows, d

    # ── /api/me and /api/profiles
    def test_me(self):
        st, r = self.call("GET", "/api/me")
        self.assertEqual((st, r["username"], r["role"]), (200, "bio", "bio_scientist"))
        self.assertEqual(r["can"], {"start": True, "decide": True, "stop": True, "replay": True, "reexecute": True})
        self.o.iam.roles = ["engineer"]
        self.assertEqual(self.call("GET", "/api/me")[1]["can"],
                         {"start": False, "decide": False, "stop": False, "replay": True, "reexecute": False})
        self.o.iam.table = None                     # no route table: the page shows the buttons, the server decides
        self.assertIsNone(self.call("GET", "/api/me")[1]["can"])

    def test_profiles(self):
        st, r = self.call("GET", "/api/profiles")
        self.assertEqual(st, 200)
        names = [p["name"] for p in r["profiles"]]
        self.assertEqual(names, sorted(f[:-5] for f in os.listdir(CFG["profiles_dir"]) if f.endswith(".yaml")))
        team = next(p for p in r["profiles"] if p["name"] == "compare_controllers_team")
        self.assertEqual(team["team"], ["campaign", "tuning"])
        self.assertEqual(set(team), {"name", "backend", "caps", "tools", "skill", "team"})
        self.assertEqual(r["endpoints"], [])

    # ── sessions: history and the session's own facts
    def test_listing_has_the_history(self):
        self.sh.answers[("GET", "/persons/p-1/sessions?before=99&limit=2")] = (200, {"sessions": [{"sid": SID}], "next_before": 7})
        st, r = self.call("GET", "/api/sessions?before=99&limit=2")
        self.assertEqual((st, r["history"], r["next_before"], r["sessions"]), (200, [{"sid": SID}], 7, []))
        self.assertEqual(self.call("GET", "/api/sessions?before=x")[0], 400)
        self.assertEqual(self.call("GET", "/api/sessions?limit=500")[0], 400)
        self.sh.answers[("GET", "/persons/p-1/sessions")] = (0, {})
        st, r = self.call("GET", "/api/sessions")
        self.assertEqual((st, r["history"]), (200, []))
        self.assertIn("history_error", r)
        self.o.start(WHO, "TOK", {"profile": "compare_controllers"})
        run = self.call("GET", "/api/sessions")[1]["sessions"][0]
        self.assertEqual((run["sid"], run["state"], run["backend"], run["exp"]), (SID, "starting", "scripted", 99))

    def test_the_person_comes_from_the_token(self):
        self.call("GET", "/api/sessions?person=p-2")
        self.assertIn("/persons/p-1/sessions", [c[1].split("?")[0] for c in self.sh.calls])
        self.assertNotIn("/persons/p-2/sessions", [c[1].split("?")[0] for c in self.sh.calls])

    def test_info_gains_the_traces_facts(self):
        self.put_campaign()
        st, r = self.call("GET", "/api/sessions/" + SID)
        self.assertEqual(st, 200)
        self.assertEqual((r["sup_username"], r["sup_role"], r["created_at"], r["code_commit"], r["revoke_reason"]),
                         ("bio", "bio_scientist", 900, "abc1234", "job ended"))
        self.assertEqual(r["agents"], [{"id": "a0", "parent": None}, {"id": "a0.1", "parent": "a0", "profile": "campaign"}])
        self.assertNotIn("reexecutes", r)
        n = len(self.sh.calls)
        self.call("GET", "/api/sessions/" + SID)          # read incrementally: one page after the last event seen
        self.assertEqual([c[1] for c in self.sh.calls[n:] if c[1].startswith("/events/")], ["/events/%s?after=7" % SID])

    # ── long-poll
    def test_long_poll_waits_and_returns_on_an_event(self):
        t = [1000.0]
        self.o.clock = lambda: t[0]

        def sleep(d):
            t[0] += d
            if t[0] >= 1003:
                self.sh.trace[SID] = [{"event_id": 1, "event": "x", "payload": {}}]
        self.o.sleep = sleep
        st, r = self.o.events(WHO, SID, 0, wait=20)
        self.assertEqual((st, len(r["events"]), t[0]), (200, 1, 1003.0))

    def test_long_poll_is_bounded_by_wait_and_the_token(self):
        t = [1000.0]
        self.o.clock = lambda: t[0]
        self.o.sleep = lambda d: t.__setitem__(0, t[0] + d)
        self.assertEqual(self.o.events(WHO, SID, 0, wait=99), (200, {"events": []}))
        self.assertEqual(t[0], 1020.0)                     # at most 20 s
        t[0] = 1000.0
        self.o.events(WHO, SID, 0, wait=20, token_exp=1008)
        self.assertEqual(t[0], 1003.0)                     # the token's exp - 5 s
        t[0] = 1000.0
        self.o.events(WHO, SID, 0)
        self.assertEqual(t[0], 1000.0)                     # without wait: as before

    def test_token_exp(self):
        import base64
        tok = "h." + base64.urlsafe_b64encode(json.dumps({"exp": 1234}).encode()).decode().rstrip("=") + ".s"
        self.assertEqual(orch._token_exp(tok), 1234)
        self.assertIsNone(orch._token_exp("nonsense"))

    # ── campaigns
    def test_campaigns_and_a_campaign(self):
        rows, _ = self.put_campaign()
        st, r = self.call("GET", "/api/sessions/%s/campaigns" % SID)
        self.assertEqual((st, [c["cid"] for c in r["campaigns"]]), (200, [self.CID]))
        st, r = self.call("GET", "/api/sessions/%s/campaigns/%s?limit=5&offset=2" % (SID, self.CID))
        self.assertEqual(st, 200)
        self.assertEqual((r["runs"]["offset"], r["runs"]["total"], len(r["runs"]["rows"])), (2, 36, 5))
        self.assertEqual(r["series"], {"every_s": 60.0, "runs": 36})
        self.assertEqual(r["by_setting"]["count"]["total"], r["by_setting"]["count"]["shown"])
        st, r = self.call("GET", "/api/sessions/%s/campaigns/%s/runs/4" % (SID, self.CID))
        self.assertEqual((st, r), (200, rows[4]))
        self.assertEqual(self.call("GET", "/api/sessions/%s/campaigns/%s/runs/40" % (SID, self.CID))[0], 404)

    def test_a_campaign_of_another_session_is_not_found(self):
        self.put_campaign()
        self.sh.trace[SID] = [e for e in self.sh.trace[SID] if e["event"] in ("session_minted",)]
        for path in ("/campaigns/%s", "/campaigns/%s/runs/0", "/campaigns/%s/runs/0/series"):
            st, r = self.call("GET", "/api/sessions/%s%s" % (SID, path % self.CID))
            self.assertEqual((st, r), (404, {"error": "no such campaign"}), path)

    def test_digest_mismatch_gone_and_series(self):
        _, d = self.put_campaign()
        st, r = self.call("GET", "/api/sessions/%s/campaigns/%s/runs/0/series?points=500" % (SID, self.CID), gz=True)
        self.assertEqual((st, len(r["columns"]["t"]), r["decimated"]["from"]), (200, 500, 3000))
        self.assertEqual(r["changes"], [[60.0, "light", 0, 1]])
        self.assertEqual(self.call("GET", "/api/sessions/%s/campaigns/%s/runs/0/series?points=5000" % (SID, self.CID))[0], 400)
        self.assertEqual(self.call("GET", "/api/sessions/%s/campaigns/%s/runs/1/series" % (SID, self.CID))[0], 410)
        with open(os.path.join(d, "results.jsonl"), "ab") as f:
            f.write(b"{}\n")
        self.assertEqual(self.call("GET", "/api/sessions/%s/campaigns/%s" % (SID, self.CID)),
                         (409, {"error": "results do not match the trace"}))
        shutil.rmtree(d)
        st, r = self.call("GET", "/api/sessions/%s/campaigns/%s" % (SID, self.CID))
        self.assertEqual((st, r["state"]), (410, "gone"))

    def test_a_campaign_without_series(self):
        self.put_campaign(series=False)
        self.assertEqual(self.call("GET", "/api/sessions/%s/campaigns/%s/runs/0/series" % (SID, self.CID)),
                         (404, {"error": "no series recorded for this campaign"}))

    def test_a_running_campaign(self):
        self.put_campaign()
        self.sh.trace[SID] = [e for e in self.sh.trace[SID] if e["event"] != "sim_finished"]
        self.assertEqual(self.call("GET", "/api/sessions/%s/campaigns/%s" % (SID, self.CID)),
                         (200, {"state": "running", "cid": self.CID}))

    def test_an_approved_campaign_not_started(self):
        self.put_campaign()
        self.sh.trace[SID] = [e for e in self.sh.trace[SID] if e["event"] not in ("sim_started", "sim_finished")]
        self.assertEqual(self.call("GET", "/api/sessions/%s/campaigns/%s" % (SID, self.CID)),
                         (200, {"state": "approved", "cid": self.CID}))
        self.assertEqual(self.call("GET", "/api/sessions/%s/campaigns" % SID)[1]["campaigns"][0]["state"], "approved")

    def test_too_large(self):
        import campaigns
        self.put_campaign()
        old = campaigns.RESULTS_MAX
        campaigns.RESULTS_MAX = 10
        try:
            self.assertEqual(self.call("GET", "/api/sessions/%s/campaigns/%s" % (SID, self.CID))[0], 413)
        finally:
            campaigns.RESULTS_MAX = old

    # ── another person's session: 404 on every route
    def test_another_persons_session(self):
        self.put_campaign()
        self.sh.trace[self.OTHER] = self.sh.trace[SID]
        for method, path in (("GET", ""), ("GET", "/events"), ("GET", "/events?wait=2"), ("GET", "/campaigns"),
                             ("GET", "/campaigns/%s" % self.CID), ("GET", "/campaigns/%s/runs/0" % self.CID),
                             ("GET", "/campaigns/%s/runs/0/series" % self.CID), ("GET", "/otel"),
                             ("POST", "/reexecute"), ("POST", "/stop"), ("POST", "/replay")):
            with self.subTest(path):
                st, r = self.call(method, "/api/sessions/" + self.OTHER + path, {} if method == "POST" else None)
                self.assertEqual((st, r), (404, {"error": "no such session"}))

    # ── re-execution
    def test_reexecute(self):
        self.sh.sessions[SID] = dict(self.sh.sessions[SID], backend="gpu", profile="compare_controllers_gpu", active=False)
        self.o.cfg = dict(self.o.cfg, model_gateway_url="http://g:8120", endpoints=["local", "gpu"],
                          inventory=LifecycleTest.INVENTORY)
        st, r = self.call("POST", "/api/sessions/%s/reexecute" % SID, {}, origin="https://agents.medcea")
        self.assertEqual((st, r["reexecutes"], r["endpoint"]), (201, SID, "gpu"))
        mint = [c for c in self.ph.calls if c[1] == "/mint"][-1][2]
        self.assertEqual((mint["reexecutes"], mint["backend"], mint["profile"]), (SID, "gpu", "compare_controllers_gpu"))
        self.assertEqual(self.o.iam.seen[-1], ("research-orchestrator", "POST", "/api/sessions/%s/reexecute" % SID))

    def test_reexecute_refusals(self):
        st, r = self.call("POST", "/api/sessions/%s/reexecute" % SID, {})
        self.assertEqual((st, r), (409, {"error": "the session is not a model session: nothing to re-execute"}))
        self.sh.sessions[SID] = dict(self.sh.sessions[SID], backend="gpu", profile="compare_controllers_gpu")
        st, r = self.call("POST", "/api/sessions/%s/reexecute" % SID, {})     # gpu not enabled: start's 409
        self.assertEqual(st, 409)
        self.assertIn("RESEARCH_ENDPOINTS", r["error"])
        self.assertEqual(self.call("POST", "/api/sessions/%s/reexecute" % SID, {}, origin="https://evil.example"),
                         (403, {"error": "wrong origin"}))
        self.assertEqual(self.call("POST", "/api/sessions/%s/reexecute" % SID, None)[0], 400)
        self.assertEqual([c for c in self.ph.calls if c[1] == "/mint"], [])

    # ── OpenTelemetry export
    def test_otel(self):
        self.put_campaign()
        st, r = self.call("GET", "/api/sessions/%s/otel" % SID)
        self.assertEqual(st, 200)
        res = r["resourceSpans"][0]
        attrs = {a["key"]: a["value"] for a in res["resource"]["attributes"]}
        self.assertEqual(attrs["medcea.session.id"], {"stringValue": SID})
        self.assertNotIn(WHO["sub"], json.dumps(r))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.call("GET", "/api/sessions/%s/otel?content=1" % SID)[0], 200)
        # design rs4e 4.5: an export with content is recorded, naming the session and the person (review of commit B)
        line = [l for l in err.getvalue().splitlines() if "OpenTelemetry export with content" in l]
        self.assertEqual(len(line), 1, err.getvalue())
        self.assertIn(SID, line[0])
        self.assertIn(" for bio", line[0])
        self.assertNotIn(WHO["sub"], err.getvalue())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.call("GET", "/api/sessions/%s/otel" % SID)[0], 200)
        self.assertNotIn("OpenTelemetry export", err.getvalue())

    def test_handlers_add_root_to_sys_path_once(self):
        """Review of commit B: profiles, campaign and otel ran sys.path.insert(0, ROOT) on every request."""
        self.put_campaign()
        self.call("GET", "/api/profiles")
        n = len(sys.path)
        for _ in range(3):
            self.call("GET", "/api/profiles")
            self.call("GET", "/api/sessions/%s/campaigns/%s" % (SID, self.CID))
            self.call("GET", "/api/sessions/%s/otel" % SID)
        self.assertEqual(len(sys.path), n)

    # ── the router serves every declared route (routes_diff.SOURCES cannot see the handlers)
    def test_every_declared_route_is_routed(self):
        sys.path.insert(0, os.path.join(ROOT, "apps", "iam"))
        from compiler import routes_diff
        self.put_campaign()
        ids = {"<sid>": SID, "<gid>": self.CID, "<pid>": "p5", "<cid>": self.CID, "<n>": "0"}
        for method, path in routes_diff.SOURCES["research-orchestrator"]["routes"]:
            with self.subTest(path):
                for k, v in ids.items():
                    path = path.replace(k, v)
                st, r = self.call(method, path, {} if method == "POST" else None)
                self.assertNotIn((st, r.get("error")), ((404, "not found"), (405, "method not allowed")), path)
        for path in ("/api/nothing", "/api/sessions/%s/campaigns/%s/runs" % (SID, self.CID),
                     "/api/sessions/%s/campaigns/%s/runs/0/series/x" % (SID, self.CID)):
            self.assertEqual(self.call("GET", path), (404, {"error": "not found"}), path)

    def test_every_declared_route_is_in_the_route_table(self):
        sys.path.insert(0, os.path.join(ROOT, "apps", "iam"))
        from compiler import routes_diff
        t = self.route_table()
        table = set(t["services"]["research-orchestrator"]["routes"]) | set(t["public"]["research-orchestrator"])
        declared = {"%s %s" % r for r in routes_diff.SOURCES["research-orchestrator"]["routes"]}
        self.assertEqual(declared, table)


if __name__ == "__main__":
    unittest.main()
