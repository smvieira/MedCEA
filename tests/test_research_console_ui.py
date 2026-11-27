"""The research console's page (research Phase 4e commit A2, part 2; codeplan/rs4e-design.md §4, §7):
apps/research-console/html/{index.html, console.js, console.css, cytoscape-container.css, vendor/}.

- The console-logic block (pure functions between /* console-logic:begin */ and /* console-logic:end */) runs
  under node (skipped without node) and is checked against the servers' own code:
  - parity: EVENT_KINDS = agent_trace._port_events (+ trace_refused), AGENT_EVENTS = replay.AGENT, TOOL_SERVER =
    session.TOOL_SERVER, the agent id regex = the SQL's, CONTEXT_MARGIN, SHOWN_MAX, RECORD_MAX, MAX_CAMPAIGN_H,
    LOOP_METRICS, BUDGET_KEYS; every API path the page calls is a declared route of the orchestrator and in its compiled
    route table (the routes came with commit B); every KNOWN_ERRORS text is a literal of orchestrator.py, session.py or mcp_sim.py;
  - foldEvents is incremental (fold(b, fold(a)) = fold(a + b) at every split point) on an E58-shaped trace and on
    the scripted team of A1b;
  - graphElements: one-agent and team traces (agents, specialists, servers, delegation and tool-use edges, the
    waiting state at a pending gate); lanes: lane order, spans, the sim.status poll fold, open spans to now;
  - inspect: what the model saw = context.wrap_result's shown text; the server twin record;
  - bySettingPlot and proposalCheckView against mcp_sim.summarise_settings / compare_evidence on 36 runs;
  - capProblems; startProblems = the orchestrator's 400/409 rule (texts too); replayView maps a mismatch to the
    event replay.replay names; compareTurns = cli.Client.compare_turns; seriesToUplot and decimate on a
    SeriesRecorder document; pollNext (long-poll, fallback to plain polls, backoff, tail, hidden); errorText;
    actionsFor; parseRoute/routeHash; mergeSessions/sessionRow.
- Static: no inline script or style or on*= in index.html, every script and stylesheet served by console.py's
  manifest, no innerHTML/eval/new Function/insertAdjacentHTML/style attributes in console.js, no DOM or clock in the
  logic block; light and dark tokens; the vendored libraries equal their VERSION files and run without eval or an
  inline <style>; the ConfigMap stays under 800 KiB (the design moves the vendor files out beyond that).
"""
import copy
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, TESTS)
sys.path.insert(0, os.path.join(ROOT, "apps", "research-agents"))
APP = os.path.join(ROOT, "apps", "research-console")
HTML = os.path.join(APP, "html")
JS = os.path.join(HTML, "console.js")
CSS = os.path.join(HTML, "console.css")
INDEX = os.path.join(HTML, "index.html")
VENDOR = os.path.join(HTML, "vendor")
NODE = shutil.which("node")
CID = "c0123456789abcdef0123"


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def logic_block():
    m = re.search(r"/\* console-logic:begin \*/(.*?)/\* console-logic:end \*/", read(JS), re.S)
    assert m, "console-logic block missing"
    return m.group(1)


def strip_comments(src):
    """JavaScript without its /* */ and // comments (a // after ':' or a quote is part of a URL)."""
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"(?m)(?<![:'\"\\])//.*$", "", src)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_js(body, data=None):
    """Run the logic block, then `body` (which prints one JSON value); IN is `data`."""
    d = tempfile.mkdtemp()
    try:
        with open(os.path.join(d, "in.json"), "w", encoding="utf-8") as f:
            json.dump(data, f)
        script = os.path.join(d, "t.js")
        with open(script, "w", encoding="utf-8") as f:
            f.write(logic_block() + "\nconst IN = JSON.parse(require('fs').readFileSync(%s, 'utf8'));\n%s\n"
                    % (json.dumps(os.path.join(d, "in.json")), body))
        out = subprocess.run([NODE, script], capture_output=True, text=True, timeout=60)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    if out.returncode:
        raise AssertionError(out.stderr)
    return json.loads(out.stdout)


def js_value(name):
    return run_js("console.log(JSON.stringify(%s));" % name)


def e58():
    import test_agent_otel
    return test_agent_otel.e58()


def team():
    import test_agent_otel
    return test_agent_otel.team_trace()


def at(sec):
    return "2026-11-26T10:%02d:%02d.000000+00:00" % (sec // 60, sec % 60)


def ev(i, sec, actor, event, payload):
    return {"event_id": i, "at": at(sec), "actor": actor, "event": event, "payload": payload,
            "prev_hash": "%064x" % (i - 1), "hash": "%064x" % i}


def poll_trace(done=True):
    """A lead that runs a campaign and checks sim.status three times on it, then estimates again."""
    out = [ev(1, 0, "research-session", "session_minted", {"profile": "p", "backend": "scripted"})]
    n, sec = 2, 1
    def add(actor, event, payload):
        nonlocal n, sec
        out.append(ev(n, sec, actor, event, payload))
        n += 1
        sec += 1
    add("agent", "tool_call", {"turn": 1, "call": 1, "tool": "sim.run", "args": {"spec": "x"}})
    add("mcp-sim", "sim_started", {"cid": CID, "estimate_h": 0.1, "cap_h": 0.2})
    add("mcp-sim", "tool_result", {"tool": "sim.run", "call": 1, "result_sha256": "a" * 64, "agent": "a0", "agent_call": 1})
    add("agent", "tool_result", {"turn": 1, "call": 1, "tool": "sim.run", "result": json.dumps({"cid": CID, "state": "started"}),
                                 "result_sha256": "a" * 64, "recorded_complete": True})
    for k in range(2, 5):
        add("agent", "tool_call", {"turn": k, "call": k, "tool": "sim.status", "args": {"cid": CID}})
        add("mcp-sim", "tool_result", {"tool": "sim.status", "call": k, "result_sha256": "b" * 64, "agent": "a0", "agent_call": k})
        add("agent", "tool_result", {"turn": k, "call": k, "tool": "sim.status", "result": '{"state":"running"}',
                                     "result_sha256": "b" * 64, "recorded_complete": True})
    add("orchestrator", "sim_finished", {"cid": CID, "state": "done", "cpu_hours": 0.05})
    add("agent", "tool_call", {"turn": 5, "call": 5, "tool": "sim.estimate", "args": {"spec": "x"}})
    if done:
        add("agent", "tool_result", {"turn": 5, "call": 5, "tool": "sim.estimate", "result": "{}", "result_sha256": "c" * 64,
                                     "recorded_complete": True})
    return out


def runner_rows():
    """36 runner rows (research/harness/runner.run_scenario's shape): four settings × seeds 1-3 × offsets 0, 5, 10."""
    settings = [("IF_THEN_ELSE", {}, 28.3, 1.60), ("PID", {"cycle_time": 10.0}, 85.1, 0.29),
                ("PID", {"cycle_time": 30.0}, 84.0, 0.27), ("MPC", {"horizon": 6}, 60.2, 0.41)]
    rows = []
    for code, params, energy, rmsd in settings:
        for seed in (1, 2, 3):
            for off in (0.0, 5.0, 10.0):
                rows.append({"scenario": "smoke_air_temperature", "controller": {"code": code, "params": params},
                             "seed": seed, "clock_offset_s": off, "jitter_s": 0.0, "valid": not (code == "MPC" and seed == 3),
                             "energy_total_wh": energy + seed * 0.1 + off * 0.01,
                             "loops": {"air_temperature": {"rmsd_mid": rmsd + seed * 0.001, "out_of_band": 0.01 * seed,
                                                           "boundary_hugging": 0.0}}})
    return rows


@unittest.skipUnless(NODE, "node not installed")
class Parity(unittest.TestCase):
    def test_event_kinds_are_the_trace_ports(self):
        sql = read(os.path.join(ROOT, "apps", "research", "db", "agent_trace.sql"))
        body = re.search(r"FUNCTION agent_trace\._port_events\(p_port text\).*?END\n\$\$;", sql, re.S).group(0)
        want = {}
        for port, arr in re.findall(r"WHEN '(\w+)'\s+THEN ARRAY\[([^\]]*)\]", body):
            for e in re.findall(r"'(\w+)'", arr):
                want.setdefault(e, set()).add(port)
        self.assertIn("trace_refused", sql)
        want["trace_refused"] = {"database"}
        got = js_value("Object.fromEntries(Object.keys(EVENT_KINDS).map((k) => [k, EVENT_KINDS[k].ports]))")
        self.assertEqual({k: set(v) for k, v in got.items()}, want)

    def test_constants_mirror_the_servers(self):
        from research.agents import context, loop, replay
        import mcp_sim
        orch = load("rc_orch", os.path.join(ROOT, "apps", "research-agents", "orchestrator.py"))
        session_src = read(os.path.join(ROOT, "apps", "research-agents", "session.py"))
        tool_server = json.loads(re.search(r"^TOOL_SERVER = (\{[^}]*\})", session_src, re.M).group(1).replace("'", '"'))
        got = js_value("{LEAD, CONTEXT_MARGIN, SHOWN_MAX, RECORD_MAX, MAX_CAMPAIGN_H, LOOP_METRICS, BUDGET_KEYS, "
                       "TOOL_SERVER, TEAM_TOOL, AGENT_EVENTS, EVENTS_PAGE, EVENTS_CAP, re: AGENT_RE.source, CAP_FACTOR}")
        self.assertEqual(got["LEAD"], loop.LEAD)
        self.assertEqual(got["CONTEXT_MARGIN"], loop.CONTEXT_MARGIN)
        self.assertEqual(got["SHOWN_MAX"], context.SHOWN_MAX)
        self.assertEqual(got["RECORD_MAX"], loop.RECORD_MAX)
        self.assertEqual(got["MAX_CAMPAIGN_H"], mcp_sim.MAX_CAMPAIGN_H)
        self.assertEqual(got["LOOP_METRICS"], list(mcp_sim.LOOP_METRICS))
        self.assertEqual(got["BUDGET_KEYS"], list(orch.BUDGET_KEYS))
        self.assertEqual(got["TOOL_SERVER"], tool_server)
        self.assertEqual(got["TEAM_TOOL"], loop.TEAM_TOOL)
        self.assertEqual(got["AGENT_EVENTS"], list(replay.AGENT))
        sql = read(os.path.join(ROOT, "apps", "research", "db", "agent_trace.sql"))
        self.assertIn("v_re     CONSTANT text := '%s';" % got["re"], sql)
        self.assertRegex(sql, r"LIMIT %d\b" % got["EVENTS_PAGE"])
        self.assertIn("EVENTS_CAP = %d" % got["EVENTS_CAP"], session_src)
        self.assertIn("cap = min(max(%s * e + cal, CAP_FLOOR_H), remaining)" % got["CAP_FACTOR"],
                      read(os.path.join(ROOT, "apps", "research-agents", "mcp_sim.py")))

    def test_every_api_path_is_routed_and_in_the_route_table(self):
        """Every API entry the page calls (research Phase 4e commit B: the routes come with the access policy
        version, code and YAML together) is a declared route of the orchestrator (routes_diff.SOURCES, whose
        literals iam-routes-diff checks in the file), matches a route of the compiled route table for service
        research-orchestrator at the same method, and is answered by the orchestrator's router (not its "not
        found"); the page calls every entry and fetches nothing else."""
        sys.path.insert(0, os.path.join(ROOT, "apps", "iam"))
        sys.path.insert(0, os.path.join(ROOT, "apps", "iam", "lib"))
        from compiler import model, routes, routes_diff
        import medcea_iam
        table = routes.compile(model.load_defaults())["services"]["research-orchestrator"]["routes"]
        declared = {tuple(r) for r in routes_diff.SOURCES["research-orchestrator"]["routes"]}
        api = js_value("API")
        self.assertFalse(any("b" in a for a in api.values()), "a b mark left over from commit A2")
        ids = {"<sid>": "A" * 22, "<gid>": CID, "<pid>": "p12", "<cid>": CID, "<n>": "3"}
        for name, a in api.items():
            with self.subTest(name):
                key = medcea_iam.match(table, a["method"], a["path"])
                self.assertEqual(key, "%s %s" % (a["method"], a["path"]))
                self.assertIn((a["method"], a["path"]), declared)
                path = a["path"]
                for k, v in ids.items():
                    path = path.replace(k, v)
                self.assertEqual(medcea_iam.match(table, a["method"], path), key)
        page = read(JS).split("/* console-logic:end */", 1)[1]
        called = set(re.findall(r"\bapi\('([a-z]+)'", page))
        self.assertTrue(called <= set(api), called - set(api))
        self.assertEqual(set(api) - called, set(), "an API entry the page never calls")
        self.assertEqual(re.findall(r"\bfetch\(([^,)]*)", page), ["path", "'/static/MANIFEST.json'"])

    def test_known_errors_are_the_servers_own_texts(self):
        srcs = "".join(read(os.path.join(ROOT, "apps", "research-agents", f))
                       for f in ("orchestrator.py", "session.py", "mcp_sim.py"))
        for k in js_value("Object.keys(KNOWN_ERRORS)"):
            self.assertIn('"%s"' % k, srcs, k)


@unittest.skipUnless(NODE, "node not installed")
class Fold(unittest.TestCase):
    def test_incremental_at_every_split(self):
        for events in (e58()[0], team()[0], poll_trace()):
            r = run_js("const all = JSON.stringify(foldEvents(IN));"
                       "const bad = [];"
                       "for (let k = 0; k <= IN.length; k++) {"
                       "  const s = JSON.stringify(foldEvents(IN.slice(k), foldEvents(IN.slice(0, k))));"
                       "  if (s !== all) bad.push(k);"
                       "}"
                       "const twice = JSON.stringify(foldEvents(IN, foldEvents(IN))) === all;"
                       "console.log(JSON.stringify({bad, twice}));", events)
            self.assertEqual(r, {"bad": [], "twice": True})

    def test_an_e58_session(self):
        events, k = e58()
        m = run_js("console.log(JSON.stringify(foldEvents(IN)));", events)
        c = m["campaigns"][CID]
        self.assertEqual((c["gate"], c["state"], c["cpu_hours"], c["approved_cap_h"], c["decided_by"], c["agent"]),
                         ("approved", "done", 0.11, 0.5, "sci", "a0"))
        self.assertEqual(c["writers"], ["orchestrator", "mcp-sim"])        # two writers, counted once
        pid = "p%d" % k["prop"]
        self.assertEqual(m["proposals"][pid]["doc"]["algorithm_code"], "PID")
        self.assertEqual(m["proposals"][pid]["decided"]["decision"], "approve")
        self.assertEqual((m["stop"]["reason"], m["revoked"]["reason"], m["replays"][0]["ok"]), ("finished", "job_ended", True))
        self.assertEqual(m["order"], ["a0"])
        self.assertEqual(m["calls"]["a0#5"]["refusal"], "tool not allowed")
        self.assertEqual(m["agents"]["a0"]["prompt_tokens"], sum(900 + i for i in range(1, 6)) + 950)

    def test_an_old_cli_names_a_proposal_by_its_digest(self):
        events, k = e58()
        events = copy.deepcopy(events)
        for e in events:
            if e["event"] == "proposal_decided":
                e["payload"]["pid"] = "%064d" % 304
                e["payload"]["pid"] = e["payload"]["pid"][:12]
        m = run_js("console.log(JSON.stringify(foldEvents(IN)));", events)
        self.assertEqual(m["proposals"]["p%d" % k["prop"]]["decided"]["decision"], "approve")


@unittest.skipUnless(NODE, "node not installed")
class Graph(unittest.TestCase):
    def test_one_agent(self):
        g = run_js("console.log(JSON.stringify(graphElements(IN)));", e58()[0])
        self.assertEqual([n["data"]["id"] for n in g["nodes"]], ["agent:a0", "server:model-gateway", "server:mcp-sim"])
        self.assertEqual(g["nodes"][0]["data"]["state"], "stopped")
        self.assertEqual({e["data"]["id"]: e["data"]["count"] for e in g["edges"]},
                         {"use:a0>model-gateway": 6, "use:a0>mcp-sim": 4})       # admin.drop reached no server
        self.assertEqual(g["edges"][0]["data"]["label"], "6 turns")
        self.assertTrue(all(x["group"] in ("nodes", "edges") for x in g["nodes"] + g["edges"]))

    def test_a_team(self):
        from research.agents.cli import Client
        events, p = team()
        g = run_js("console.log(JSON.stringify(graphElements(IN)));", events)
        ids = [n["data"]["id"] for n in g["nodes"]]
        self.assertEqual(ids, ["agent:a0", "agent:a0.1", "agent:a0.2", "server:mcp-sim"])
        members = Client.team(events)
        for mem in members:
            node = next(n for n in g["nodes"] if n["data"]["id"] == "agent:" + mem["agent"])
            self.assertIn(mem["specialist"], node["data"]["label"])
            self.assertEqual(node["data"]["state"], "stopped")
            edge = next(e for e in g["edges"] if e["data"]["id"] == "delegate:" + mem["agent"])
            self.assertEqual((edge["data"]["source"], edge["data"]["target"]), ("agent:" + mem["parent"], "agent:" + mem["agent"]))
            self.assertEqual(edge["data"]["label"], " ".join(mem["task"].split())[:80])
        use = {e["data"]["id"]: e["data"]["count"] for e in g["edges"] if e["data"]["kind"] == "use"}
        self.assertEqual(use, {"use:a0.1>mcp-sim": 2, "use:a0.2>mcp-sim": 1})   # the lead only delegated
        self.assertNotIn("server:model-gateway", ids)                                # scripted: no gateway

    def test_an_agent_waits_at_a_pending_gate(self):
        events, _ = e58()
        cut = next(i for i, e in enumerate(events) if e["event"] == "gate_pending") + 1
        g = run_js("console.log(JSON.stringify(graphElements(IN)));", events[:cut])
        self.assertEqual(g["nodes"][0]["data"]["state"], "waiting")
        self.assertIn("waiting", g["nodes"][0]["classes"])

    def test_labels_stay_data(self):
        """A task with markup is a label string (Cytoscape draws canvas text), never parsed."""
        events, p = team()
        events = copy.deepcopy(events)
        for e in events:
            if e["event"] == "agent_spawned":
                e["payload"]["task"] = "<img src=x onerror=alert(1)> run it"
        g = run_js("console.log(JSON.stringify(graphElements(IN)));", events)
        lab = next(e for e in g["edges"] if e["data"]["kind"] == "delegate")["data"]["label"]
        self.assertEqual(lab, "<img src=x onerror=alert(1)> run it")


@unittest.skipUnless(NODE, "node not installed")
class Lanes(unittest.TestCase):
    def test_team_lanes(self):
        events, _ = team()
        lz = run_js("const m = foldEvents(IN); console.log(JSON.stringify(lanes(m, null)));", events)
        self.assertEqual([l["id"] for l in lz["lanes"]], ["agent:a0", "agent:a0.1", "agent:a0.2", "supervisor", "server:mcp-sim"]
                         if any(e["actor"] == "mcp-sim" for e in events) else ["agent:a0", "agent:a0.1", "agent:a0.2", "supervisor"])
        self.assertEqual([l["depth"] for l in lz["lanes"][:3]], [0, 1, 1])
        dele = [s for s in lz["spans"] if s["kind"] == "delegate"]
        self.assertEqual([s["lane"] for s in dele], ["agent:a0", "agent:a0"])
        turns = {}
        for s in lz["spans"]:
            if s["kind"] == "turn":
                turns[s["lane"]] = turns.get(s["lane"], 0) + 1
        want = {}
        for e in events:
            if e["event"] == "turn_request":
                lane = "agent:" + e["payload"].get("agent", "a0")
                want[lane] = want.get(lane, 0) + 1
        self.assertEqual(turns, want)
        # a delegation span holds its specialist's whole life
        child = [s for s in lz["spans"] if s["lane"] == "agent:a0.1"]
        self.assertTrue(dele[0]["start"] <= min(s["start"] for s in child) and dele[0]["end"] >= max(s["end"] for s in child))

    def test_status_polls_fold_into_one_waiting_span(self):
        lz = run_js("console.log(JSON.stringify(lanes(foldEvents(IN), null)));", poll_trace())
        tools = [s for s in lz["spans"] if s["lane"] == "agent:a0" and s["kind"] in ("tool", "waiting")]
        self.assertEqual([(s["kind"], s["label"], s["count"]) for s in tools],
                         [("tool", "sim.run", 1), ("waiting", "waiting · 3 status checks", 3), ("tool", "sim.estimate", 1)])
        recs = [m for m in lz["marks"] if m["lane"] == "server:mcp-sim" and m["kind"] == "record"]
        self.assertEqual([(m["tool"], m["count"]) for m in recs], [("sim.run", 1), ("sim.status", 3)])
        camp = [s for s in lz["spans"] if s["kind"] == "campaign"]
        self.assertEqual((len(camp), camp[0]["open"]), (1, False))
        self.assertIn("server:orchestrator", [l["id"] for l in lz["lanes"]])

    def test_open_spans_end_now(self):
        events = poll_trace(done=False)
        now = 1795687200000 + 3600 * 1000
        lz = run_js("console.log(JSON.stringify(lanes(foldEvents(IN), %d)));" % now, events)
        last = [s for s in lz["spans"] if s["lane"] == "agent:a0"][-1]
        self.assertEqual((last["label"], last["open"], last["end"]), ("sim.estimate", True, now))
        self.assertEqual(lz["t1"], now)

    def test_the_svg_description_is_attributes_and_text(self):
        events, _ = team()
        d = run_js("const lz = lanes(foldEvents(IN), null); console.log(JSON.stringify(laneSvg(lz, 900, null, 'a0.2')));", events)
        labels = [x["text"] for x in d["elements"] if x["tag"] == "text" and "lane-label" in x["attrs"]["class"]]
        self.assertNotIn("a0.1 campaign", labels)                          # filtered to a0.2
        self.assertIn("a0.2 tuning", labels)
        allowed = {"x", "y", "width", "height", "class", "rx", "x1", "x2", "y1", "y2", "d", "data-event", "cx", "cy", "r"}
        for x in d["elements"]:
            self.assertLessEqual(set(x["attrs"]), allowed)
            self.assertIn(x["tag"], ("rect", "text", "line", "path", "circle"))


@unittest.skipUnless(NODE, "node not installed")
class Inspector(unittest.TestCase):
    def test_what_the_model_saw_and_the_server_twin(self):
        from research.agents.context import wrap_result
        events = poll_trace()
        text = '{"note":"<b>bold</b> & ' + "x" * 1200 + '"}'
        res = next(e for e in events if e["actor"] == "agent" and e["event"] == "tool_result" and e["payload"]["call"] == 1)
        res["payload"]["result"] = text
        v = run_js("const m = foldEvents(IN.ev); console.log(JSON.stringify(inspect(IN.ev.find((e) => e.event_id === IN.id), m, "
                   "{sup_username: 'sci', sup_role: 'control_scientist'})));", {"ev": events, "id": res["event_id"]})
        shown = next(b for b in v["blocks"] if b["title"].startswith("What the model saw"))["text"]
        self.assertEqual(shown, wrap_result("sim.run", 1, text)[2])
        full = next(b for b in v["blocks"] if b["title"].startswith("The full record"))["text"]
        self.assertEqual(full, text)
        rows = dict((r[0], r[1]) for r in v["rows"])
        self.assertEqual(rows["Supervisor"], "sci (control_scientist)")
        self.assertIn("Server record", rows)
        self.assertIn("mcp-sim sim.run: same digest", rows["Server record"])

    def test_a_turn(self):
        events, _ = e58()
        resp = next(e for e in events if e["event"] == "turn_response")
        v = run_js("const m = foldEvents(IN.ev); console.log(JSON.stringify(inspect(IN.ev.find((e) => e.event_id === IN.id), m, null)));",
                   {"ev": events, "id": resp["event_id"]})
        rows = dict((r[0], r[1]) for r in v["rows"])
        self.assertEqual(rows["Response sha256"], resp["payload"]["response_sha256"])
        self.assertIn('"prompt_tokens":901', rows["Usage"])
        self.assertEqual(rows["hash"], resp["hash"])

    def test_a_gateway_turn_shows_its_prompt_cache(self):
        # model-gateway puts cache_n inside usage (apps/research-model/gateway.py)
        events, _ = e58()
        events = copy.deepcopy(events)
        resp = next(e for e in events if e["event"] == "turn_response")
        resp["actor"] = "model-gateway"
        resp["payload"]["usage"] = dict(resp["payload"].get("usage") or {}, cache_n=777)
        resp["payload"].pop("cache_n", None)
        v = run_js("const m = foldEvents(IN.ev); console.log(JSON.stringify(inspect(IN.ev.find((e) => e.event_id === IN.id), m, null)));",
                   {"ev": events, "id": resp["event_id"]})
        rows = dict((r[0], r[1]) for r in v["rows"])
        self.assertEqual(rows["Prompt cache (cache_n)"], 777)


@unittest.skipUnless(NODE, "node not installed")
class CampaignViews(unittest.TestCase):
    def test_every_state_before_a_result_has_its_own_words(self):
        """Review of commit B: the campaign route answers the entry's own state (waiting, approved, running); the view
        never calls an approved, not yet started campaign running."""
        with open(JS, encoding="utf-8") as f:
            src = f.read()
        i = src.index("const pending = {running:")
        block = src[i:src.index("}[cr.body.state]", i)]
        for st in ("running", "approved", "waiting"):
            self.assertRegex(block, r"\b%s: '" % st)
        self.assertNotIn("still running", block.split("approved:")[1])

    @staticmethod
    def defaults(code):
        return {"PID": {"cycle_time": 10.0, "kp": 1.0}, "MPC": {"horizon": 6}}.get(code, {})

    def test_by_setting_against_mcp_sim(self):
        import mcp_sim
        rows = runner_rows()
        for sort in (None, "energy_wh", "air_temperature.rmsd_mid"):
            table = mcp_sim.summarise_settings(rows, self.defaults, sort)
            for crit in table["columns"][4:]:
                d = run_js("console.log(JSON.stringify({crit: criteriaOf(IN.t), p: bySettingPlot(IN.t, IN.c, "
                           "{proposed: {code: 'PID', params: {cycle_time: 30.0}}})}));", {"t": table, "c": crit})
                self.assertEqual(d["crit"], table["columns"][4:])
                col = table["columns"].index(crit)
                self.assertEqual([pt["value"] for pt in d["p"]["points"]], [r[col] for r in table["settings"]])
                self.assertEqual([pt["proposed"] for pt in d["p"]["points"]],
                                 [r[0] == "PID" and r[1] == {"cycle_time": 30.0} for r in table["settings"]])
                self.assertEqual(d["p"]["problems"], [])
        fitted = mcp_sim.fit_table(mcp_sim.clean_obj(mcp_sim.summarise_settings(rows, self.defaults)))
        d = run_js("console.log(JSON.stringify(bySettingPlot(IN, 'nope.rmsd_mid')));", fitted)
        self.assertEqual(len(d["problems"]), 1)
        d = run_js("console.log(JSON.stringify(bySettingPlot(IN, 'energy_wh')));", fitted)
        self.assertEqual(len(d["points"]), fitted["count"]["shown"])

    def test_the_check_against_compare_evidence(self):
        import mcp_sim
        check = mcp_sim.clean_obj(mcp_sim.compare_evidence(runner_rows(), "PID", {"cycle_time": 30.0},
                                                           "air_temperature.rmsd_mid", self.defaults))
        v = run_js("console.log(JSON.stringify(proposalCheckView(IN)));", check)
        self.assertEqual((v["criterion"], v["proposedMean"], v["proposedRuns"], v["total"], v["more"]),
                         (check["criterion"], check["proposed_mean"], check["proposed_runs"], check["compared_total"], 0))
        got = [dict(r, params=json.loads(r["params"])) for r in v["rows"]]     # canonical JSON (JS writes 10.0 as 10)
        self.assertEqual(got, [{"code": o["code"], "params": o["params"], "runs": o["runs"], "proposed": o["proposed"],
                                "other": o["other"], "outcome": o["outcome"], "better": o["outcome"] == "better"}
                               for o in check["compared"]])
        self.assertTrue(all(r["better"] for r in v["rows"]))

    def test_cap_rules(self):
        gate = {"estimate_h": 0.4, "cap_h": 0.55}
        cases = [("0.5", 2.0, []), ("", 2.0, ["number"]), ("abc", 2.0, ["number"]), ("0", 2.0, ["more than 0"]),
                 ("0.6", 2.0, ["1.25"]), ("0.5", 0.3, ["remaining"]), ("30", 100, ["at most 24", "1.25"])]
        got = run_js("console.log(JSON.stringify(IN.map((c) => capProblems(c[0], IN_G, c[1]))));".replace("IN_G", json.dumps(gate)),
                     [[c, r] for c, r, _ in cases])
        for (cap, rem, want), problems in zip(cases, got):
            self.assertEqual(len(problems), len(want), (cap, problems))
            for w, p in zip(want, problems):
                self.assertIn(w, p)
        r = run_js("console.log(JSON.stringify([defaultCap({cap_h: 0.5555559}, 9), defaultCap({estimate_h: 0.4}, 0.3), "
                   "gateLimit({estimate_h: 0.4})]));")
        self.assertEqual(r, [0.555, 0.3, 0.5])


@unittest.skipUnless(NODE, "node not installed")
class Start(unittest.TestCase):
    def test_the_orchestrators_409_rule(self):
        import test_research_orchestrator as tro
        from research.agents import loop
        profs = {}
        for name in ("compare_controllers", "compare_controllers_local", "compare_controllers_gpu"):
            p = loop.load_profile(os.path.join(ROOT, "research", "agents", "profiles", name + ".yaml"))
            profs[name] = {"name": p["name"], "backend": p["backend"], "caps": p["caps"]}
        inv = tro.ProfilesAndEndpoints.INVENTORY if hasattr(tro, "ProfilesAndEndpoints") else None
        inv = inv or [{"name": "local", "kind": "llama", "model": "qwen3-4b", "context": 4096, "deterministic": True},
                      {"name": "gpu", "kind": "openai", "model": "Qwen/Qwen3-14B-AWQ", "context": 12288, "deterministic": True},
                      {"name": "spare", "kind": "openai", "model": "m", "context": 8192, "deterministic": False}]
        inventories = [inv, [dict(i, context=8192) if i["name"] == "gpu" else i for i in inv],
                       [i for i in inv if i["name"] != "gpu"], [dict(i, context=None) if i["name"] == "spare" else i for i in inv]]
        cases = []
        for inventory in inventories:
            for pname, prof in profs.items():
                for chosen in (None, "local", "gpu", "spare", "nope"):
                    o, k, ph, sh = tro.make()
                    o.cfg = dict(o.cfg, model_gateway_url="http://g:8120", endpoints=[i["name"] for i in inventory],
                                 inventory=inventory)
                    body = {"profile": pname}
                    if chosen:
                        body["endpoint"] = chosen
                    st, r = o.start(tro.WHO, "tok", body)
                    cases.append({"prof": prof, "chosen": chosen, "inv": inventory, "st": st, "err": r.get("error")})
        got = run_js("console.log(JSON.stringify(IN.map((c) => startProblems(c.prof, c.chosen, c.inv))));", cases)
        for c, problems in zip(cases, got):
            if c["st"] == 201:
                self.assertEqual(problems, [], c)
            else:
                self.assertIn(c["st"], (400, 409))
                self.assertEqual(problems, [c["err"]], c)
        self.assertTrue(any(c["st"] == 201 for c in cases) and any(c["st"] == 409 for c in cases)
                        and any(c["st"] == 400 for c in cases))


@unittest.skipUnless(NODE, "node not installed")
class ReplayAndReexecution(unittest.TestCase):
    def test_a_mismatch_points_at_the_event_replay_names(self):
        from test_agent_team import LEAD_SKILL, run_team
        from test_agent_loop import STANDING, FakeTools
        from research.agents.replay import AGENT, replay
        _, events, p = run_team()
        events = copy.deepcopy(events)
        spawned = next(e for e in events if e["event"] == "agent_spawned" and e["payload"]["agent"] == "a0.2")
        spawned["payload"]["task"] = "Something else."
        v = replay(events, p, STANDING, LEAD_SKILL, FakeTools().list_tools())
        self.assertFalse(v["ok"])
        rec = [e for e in events if e.get("actor") == "agent" and e["event"] in AGENT]
        want = rec[v["first_mismatch"]["index"]]["event_id"]
        r = run_js("console.log(JSON.stringify(replayView(IN.ev, IN.v)));", {"ev": events, "v": v})
        self.assertEqual((r["state"], r["event_id"], r["agent"], r["event"]), ("mismatch", want, "a0.2", "agent_spawned"))
        self.assertEqual(r["event_id"], spawned["event_id"])
        ok = run_js("console.log(JSON.stringify(replayView(IN, {ok: true, first_mismatch: null, events: 9})));", events)
        self.assertEqual(ok["state"], "ok")
        self.assertEqual(run_js("console.log(JSON.stringify(replayView([], {state: 'running'})));")["state"], "running")

    def test_compare_turns_is_the_clis(self):
        from research.agents.cli import Client

        def session(answers, reqs=None, start=0):
            out, n = [], 1
            for t, ans in enumerate(answers, 1):
                req = (reqs or {}).get(t, "r%d" % t)
                out.append({"event_id": n, "at": at(start + t * 10), "actor": "model-gateway", "event": "turn_request",
                            "payload": {"turn": t, "request_sha256": req}})
                n += 1
                if ans is not None:
                    out.append({"event_id": n, "at": "2026-11-26T10:%02d:%02d.250000+00:00" % ((start + t * 10 + t) // 60, (start + t * 10 + t) % 60),
                                "actor": "model-gateway", "event": "turn_response", "payload": {"turn": t, "response_sha256": ans}})
                    n += 1
                out.append({"event_id": n, "at": at(start + t * 10 + 5), "actor": "agent", "event": "turn_request",
                            "payload": {"turn": t, "agent": "a0.1", "request_sha256": "x"}})
                n += 1
            return out
        pairs = [(session(["a", "b", "c"]), session(["a", "b", "c"], start=7)),
                 (session(["a", "b", "c", "d"]), session(["a", "X", "c", "Y"])),
                 (session(["a", "b", "c"]), session(["a", "b", "c"], reqs={2: "changed"})),
                 (session(["a", None, "c"]), session(["a", "b", "c"])),
                 ([], session(["a"]))]
        for a, b in pairs:
            got = run_js("console.log(JSON.stringify(compareTurns(IN[0], IN[1])));", [a, b])
            self.assertEqual(got, json.loads(json.dumps(Client.compare_turns(a, b))))


@unittest.skipUnless(NODE, "node not installed")
class Series(unittest.TestCase):
    @staticmethod
    def doc(points=3000):
        from research.harness.series import SeriesRecorder
        rec = SeriesRecorder(60)
        rec.start(points * 60, 3600, [("air_temperature", 18.0, 22.0)], ("heater", "fan"))
        for i in range(points):
            t = i * 60.0
            temp = 20 + (5 if i == 1234 else 0) + (-4 if i == 2222 else 0) + (i % 7) * 0.1
            cmd = "UP" if i % 50 < 25 else "OFF"
            rec.tick(t, {"air_temperature": cmd}, {"heater": cmd == "UP", "fan": False}, i % 100 < 50, i // 1000)
            rec.sample(t, {"air_temperature": temp, "air_humidity": 80.0, "co2": 900.0, "ground_temperature": 19.0},
                       {"air_temperature": ("ok", temp, cmd)}, {"heater": cmd == "UP", "fan": False}, i % 100 < 50,
                       i * 0.5, i // 1000, {}, {"temperature": 15, "humidity": 60, "co2": 420})
        return rec.document()

    def test_panels(self):
        d = self.doc(300)
        u = run_js("console.log(JSON.stringify(seriesToUplot(IN, null)));", d)
        ids = [p["id"] for p in u["panels"]]
        self.assertEqual(ids, ["air_temperature", "air_humidity", "co2", "ground_temperature", "energy", "strips"])
        at_ = u["panels"][0]
        self.assertEqual([s["label"] for s in at_["series"]], ["air_temperature (truth)", "loop value", "upper", "lower"])
        self.assertEqual(at_["band"], [3, 4])
        self.assertEqual(set(at_["data"][3]), {22.0})
        self.assertEqual(set(at_["data"][4]), {18.0})
        self.assertTrue(all(len(col) == 300 for col in at_["data"]))
        self.assertEqual(at_["data"][0][1], 60 / 3600)
        self.assertEqual(u["metricsFromH"], 1.0)
        self.assertTrue(u["panels"][-1]["step"])
        self.assertEqual(u["changes"], len(d["changes"]))

    def test_decimate_keeps_extremes_and_switches(self):
        d = self.doc(3000)
        r = run_js("const x = decimate(IN, 50); console.log(JSON.stringify({n: x.columns.t.length, d: x.decimated, "
                   "max: Math.max(...x.columns.air_temperature), min: Math.min(...x.columns.air_temperature), "
                   "changes: x.changes.length, same: decimate(IN, 5000) === IN}));", d)
        self.assertLessEqual(r["n"], 50 * 2 + 50 * 2 * 20)
        self.assertLess(r["n"], 3000)
        self.assertEqual((r["max"], r["min"]), (max(d["columns"]["air_temperature"]), min(d["columns"]["air_temperature"])))
        self.assertEqual(r["changes"], len(d["changes"]))
        self.assertTrue(r["same"])


@unittest.skipUnless(NODE, "node not installed")
class Polling(unittest.TestCase):
    def steps(self, outcomes):
        return run_js("let s = pollStart(); const out = []; let now = 0;"
                      "for (const o of IN) { now += o.dt || 0; const r = pollNext(s, o, now); s = r.state; "
                      "out.push([r.state.mode, r.delay, r.wait, !!r.paused]); }"
                      "console.log(JSON.stringify(out));", outcomes)

    def test_long_poll_then_plain_after_two_failures_with_backoff(self):
        r = self.steps([{"ok": True, "active": True, "got": 3, "elapsed": 20000},
                        {"ok": False}, {"ok": False}, {"ok": False},
                        {"ok": True, "active": True, "got": 0, "elapsed": 50}])
        self.assertEqual(r, [["long", 0, 20, False], ["long", 1000, 20, False], ["plain", 2000, 0, False],
                             ["plain", 4000, 0, False], ["plain", 3000, 0, False]])

    def test_a_server_that_does_not_wait_falls_back_to_plain_polls(self):
        r = self.steps([{"ok": True, "active": True, "got": 0, "elapsed": 30}] * 3)
        self.assertEqual([x[0] for x in r], ["long", "plain", "plain"])
        self.assertEqual([x[1] for x in r], [0, 3000, 3000])

    def test_a_full_page_is_read_at_once_and_the_token_bounds_the_wait(self):
        r = self.steps([{"ok": True, "active": True, "got": 1000, "elapsed": 10},
                        {"ok": True, "active": True, "got": 1, "elapsed": 9000, "expS": 12},
                        {"ok": True, "active": True, "got": 1, "elapsed": 9000, "expS": 4}])
        self.assertEqual(r, [["long", 0, 0, False], ["long", 0, 7, False], ["long", 3000, 0, False]])

    def test_tail_after_the_stop_then_stopped_and_hidden_pauses(self):
        r = self.steps([{"ok": True, "active": False, "got": 0}, {"ok": True, "active": False, "got": 0, "dt": 60000},
                        {"ok": True, "active": False, "got": 0, "dt": 61000}, {"hidden": True}])
        self.assertEqual(r, [["tail", 15000, 0, False], ["tail", 15000, 0, False], ["stopped", None, 0, False],
                             ["stopped", None, 0, True]])

    def test_backoff_is_bounded(self):
        r = self.steps([{"ok": False}] * 9)
        self.assertEqual(r[-1][1], 30000)


@unittest.skipUnless(NODE, "node not installed")
class Small(unittest.TestCase):
    def test_esc(self):
        r = run_js("console.log(JSON.stringify([esc('<script>&\"\\''), esc(null), esc(5)]));")
        self.assertEqual(r, ["&lt;script&gt;&amp;&quot;&#39;", "", "5"])

    def test_parse_at(self):
        r = run_js("console.log(JSON.stringify([parseAt('2026-11-26T10:00:00.250000+00:00'), parseAt('2026-11-26T11:00:00+01:00'),"
                   "parseAt('2026-11-26T10:00:00Z'), parseAt('nope'), parseAt(null)]));")
        self.assertEqual(r, [1795687200250, 1795687200000, 1795687200000, None, None])

    def test_error_texts(self):
        r = run_js("console.log(JSON.stringify([errorText(401, {}), errorText(403, {error: 'wrong origin'}),"
                   "errorText(409, {error: 'budget gone'}), errorText(0, null), errorText(404, null), errorText(418, {})]));")
        self.assertTrue(r[0]["reload"])
        self.assertEqual(r[1]["server"], "wrong origin")
        self.assertEqual(r[2]["text"], "Not possible now: budget gone")
        self.assertIn("could not reach", r[3]["text"])
        self.assertEqual(r[4]["text"], "Not found (or not available yet).")
        self.assertEqual(r[5]["text"], "Error 418.")

    def test_actions(self):
        r = run_js("""const m = foldEvents(IN);
          console.log(JSON.stringify([
            actionsFor({active: true, backend: 'gpu'}, null, m),
            actionsFor({active: false, backend: 'gpu'}, {can: {start: false, decide: false, stop: true, replay: true, reexecute: false}}, m),
            actionsFor({active: false, backend: 'scripted'}, null, m)]));""", e58()[0][:-6])
        self.assertTrue(r[0]["stop"] and not r[0]["replay"] and not r[0]["reexecute"])
        self.assertFalse(r[1]["start"] or r[1]["stop"] or r[1]["reexecute"])
        self.assertTrue(r[1]["replay"])
        self.assertTrue(r[2]["replay"] and not r[2]["reexecute"])

    def test_routes(self):
        sid, other = "A" * 22, "B" * 21 + "_"
        cases = [("", {"view": "sessions"}), ("#/", {"view": "sessions"}), ("#/s/" + sid, {"view": "session", "sid": sid}),
                 ("#/s/%s/e/12" % sid, {"view": "session", "sid": sid, "event": 12}),
                 ("#/s/%s/replay" % sid, {"view": "replay", "sid": sid}),
                 ("#/s/%s/c/%s" % (sid, CID), {"view": "campaign", "sid": sid, "cid": CID}),
                 ("#/s/%s/c/%s/r/4" % (sid, CID), {"view": "run", "sid": sid, "cid": CID, "n": 4}),
                 ("#/cmp/%s/%s" % (sid, other), {"view": "compare", "a": sid, "b": other}),
                 ("#/s/../etc", {"view": "notfound"}), ("#/s/%s/c/..%%2F" % sid, {"view": "notfound"}), ("#/x", {"view": "notfound"})]
        got = run_js("console.log(JSON.stringify(IN.map((h) => { const r = parseRoute(h); return [r, parseRoute(routeHash(r))]; })));",
                     [c[0] for c in cases])
        for (h, want), (r, back) in zip(cases, got):
            self.assertEqual(r, want, h)
            if want["view"] not in ("notfound",):
                self.assertEqual(back, want, h)

    def test_sessions_merge_and_rows(self):
        a, b = "A" * 22, "B" * 22
        listing = {"sessions": [{"sid": b, "profile": "p", "state": "running"}, {"sid": a, "profile": "p", "state": "running"}],
                   "history": [{"sid": a, "profile": "p", "backend": "gpu", "active": True, "spent": {"turns": 3}},
                               {"sid": "C" * 22, "profile": "q", "active": False, "revoked": True, "revoke_reason": "job_ended"},
                               {"sid": "../x", "profile": "bad"}]}
        r = run_js("console.log(JSON.stringify(mergeSessions(IN).map((x) => sessionRow(x, 0))));", listing)
        self.assertEqual([x["sid"] for x in r], [b, a, "C" * 22])
        self.assertEqual([x["state"] for x in r], ["running", "running", "ended"])
        self.assertEqual(r[2]["stateText"], "ended: job_ended")
        self.assertEqual(r[1]["bars"][0]["text"], "3")

    def test_budget_bars(self):
        r = run_js("console.log(JSON.stringify(budgetBars({turns: 10, cpu_hours: 2}, {turns: 12, cpu_hours: '0.5'}, "
                   "{start: 0, end: 7200000, now: 3600000})));")
        self.assertEqual([(b["key"], b["frac"], b["over"]) for b in r],
                         [("turns", 1, True), ("cpu_hours", 0.25, False), ("wall_h", 0.5, False)])

    def test_start_problems_without_a_profile_and_scripted(self):
        r = run_js("console.log(JSON.stringify([startProblems(null, null, []), startProblems({name: 'x', backend: 'scripted', caps: {}}, null, [])]));")
        self.assertEqual(r, [["choose a profile"], []])


# The whole page (console.js) under node, against a stub DOM, a stub fetch serving one person's sessions and the
# two libraries stubbed: it must boot, list, show a session (graph, lanes, gates, proposals, inspector), decide a
# gate and a proposal with the right bodies, poll once, show a campaign, a run's series, a replay and a
# comparison, download the export, and never touch innerHTML, a style attribute or an on* attribute.
PAGE_HARNESS = r"""
const fs = require('fs'), vm = require('vm');
const D = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const code = fs.readFileSync(process.argv[3], 'utf8');
const out = {errors: [], fetches: [], posts: [], cyAdds: [], plots: [], downloads: 0};
const timers = [];
let tid = 0;
let docRoot = null;
class Node_ {
  constructor(tag) { this.tagName = String(tag).toUpperCase(); this.children = []; this.attrs = {}; this.style = {};
    this._text = ''; this.listeners = {}; this.parentNode = null; this.disabled = false; this.value = ''; this.checked = false;
    this.clientWidth = 900; this._cls = new Set();
    const self = this;
    this.classList = {add: (c) => self._cls.add(c), remove: (c) => self._cls.delete(c), contains: (c) => self._cls.has(c)}; }
  set className(v) { this._cls = new Set(String(v).split(/\s+/).filter(Boolean)); }
  get className() { return Array.from(this._cls).join(' '); }
  setAttribute(k, v) { if (/^on/i.test(k) || k.toLowerCase() === 'style') throw new Error('unsafe attribute ' + k);
    if (k === 'class') this.className = v; else this.attrs[k] = String(v);
    if (k === 'value') this.value = String(v); }
  getAttribute(k) { return k === 'class' ? this.className : (k in this.attrs ? this.attrs[k] : null); }
  removeAttribute(k) { delete this.attrs[k]; }
  appendChild(c) { if (typeof c === 'string') { const t = new Node_('#text'); t._text = c; c = t; }
    c.parentNode = this; this.children.push(c);
    if (this.tagName === 'SELECT' && c.tagName === 'OPTION' && this.value === '' && this.children.length === 1) this.value = c.attrs.value;
    return c; }
  append(...cs) { for (const c of cs) if (c !== null && c !== undefined) this.appendChild(c); }
  replaceChildren(...cs) { this.children = []; this._text = ''; this.append(...cs); }
  remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter((x) => x !== this); }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
  set innerHTML(v) { throw new Error('innerHTML used'); }
  get innerHTML() { throw new Error('innerHTML read'); }
  set outerHTML(v) { throw new Error('outerHTML used'); }
  insertAdjacentHTML() { throw new Error('insertAdjacentHTML used'); }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  fire(t, ev) { for (const f of this.listeners[t] || []) f(Object.assign({target: this, clientX: 0}, ev || {})); }
  click() { this.fire('click'); }
  scrollIntoView() { this.scrolled = true; }
  all() { const r = [this]; for (const c of this.children) r.push(...c.all()); return r; }
  querySelectorAll(sel) { const m = /^\[data-event="(\d+)"\]$/.exec(sel); if (!m) throw new Error('selector ' + sel);
    return this.all().filter((n) => n.attrs['data-event'] === m[1]); }
}
const byId = (id) => docRoot.all().find((n) => n.attrs.id === id) || null;
const find = (pred) => docRoot.all().filter(pred);
const text = (id) => (byId(id) || {textContent: ''}).textContent;
const listeners = {};
const documentElement = new Node_('html');
const body = new Node_('body');
documentElement.appendChild(body);
docRoot = documentElement;
for (const [tag, id] of [['span', 'who'], ['button', 'theme'], ['a', 'signout'], ['main', 'main'], ['div', 'toast']]) {
  const n = new Node_(tag); n.setAttribute('id', id); body.appendChild(n);
}
const store = () => { const m = {}; return {getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }}; };
const location = {hash: '', reloads: 0, reload() { this.reloads += 1; }};
const fire = (t) => { for (const f of listeners[t] || []) f({}); };
const resp = (status, bodyv, blob) => ({status, ok: status >= 200 && status < 300,
  json: async () => { if (bodyv === undefined) throw new Error('no json'); return JSON.parse(JSON.stringify(bodyv)); },
  blob: async () => ({size: 3, blob: true})});
let replayCalls = 0;
// hold: the events requests wait until release() (a held long-poll); an abort rejects as fetch does
let hold = false, inFlight = 0;
const held = [];
const release = () => { for (const h of held.splice(0)) h.done(); };
async function fetchStub(url, init) {
  const method = (init && init.method) || 'GET';
  out.fetches.push(method + ' ' + url);
  if (init && init.body) {
    out.posts.push({url, body: JSON.parse(init.body), ct: init.headers['Content-Type']});
  }
  const [path, query] = url.split('?');
  const q = Object.fromEntries((query || '').split('&').filter(Boolean).map((x) => x.split('=')));
  if (path === '/static/MANIFEST.json') return resp(200, {schema: 1, signout: D.signout, files: {}});
  if (path === '/api/me') return resp(200, D.me);
  if (path === '/api/profiles') return resp(200, D.profiles);
  if (path === '/api/sessions' && method === 'GET') return resp(200, D.listing);
  if (path === '/api/sessions' && method === 'POST') return resp(201, {sid: D.sid2, exp: 9, job: 'agent-x', endpoint: 'gpu'});
  let m = /^\/api\/sessions\/([^/]+)(\/.*)?$/.exec(path);
  if (!m) return resp(404, {error: 'not found'});
  const s = D.sessions[m[1]];
  if (!s) return resp(404, {error: 'no such session'});
  const sub = m[2] || '';
  if (sub === '' && method === 'GET') return resp(200, s.info);
  if (sub === '/events' && hold) {
    inFlight += 1;
    return new Promise((resolve, reject) => {
      let over = false;
      const end = () => { if (over) return false; over = true; inFlight -= 1; return true; };
      held.push({done: () => { if (end()) resolve(resp(200, {events: []})); }});
      if (init && init.signal) init.signal.addEventListener('abort', () => {
        if (end()) { const e = new Error('aborted'); e.name = 'AbortError'; reject(e); } });
    });
  }
  if (sub === '/events') {
    const after = +(q.after || 0);
    const pool = q.wait ? s.events.concat(s.later || []) : s.events;
    if (q.wait) s.events = pool;
    return resp(200, {events: pool.filter((e) => e.event_id > after).slice(0, 1000)});
  }
  if (sub === '/replay') { replayCalls += 1; return replayCalls === 1 ? resp(202, {state: 'running'}) : resp(200, D.verdict); }
  if (sub === '/stop' || /^\/(gates|proposals)\//.test(sub)) return resp(200, {event_id: 99});
  if (sub === '/reexecute') return resp(201, {sid: D.sid2, exp: 9, job: 'agent-y', endpoint: 'gpu', reexecutes: m[1]});
  if (sub === '/otel') return resp(200, {}, true);
  if (/^\/campaigns\/[^/]+$/.test(sub)) return resp(200, D.campaign);
  if (/^\/campaigns\/[^/]+\/runs\/0$/.test(sub)) return resp(200, D.row);
  if (/^\/campaigns\/[^/]+\/runs\/0\/series$/.test(sub)) return resp(200, D.series);
  return resp(404, {error: 'not found'});
}
function cytoscape(opts) {
  const els = {};
  const coll = (id) => ({data: (d) => { if (d) els[id] = Object.assign(els[id] || {}, d); return els[id]; }, classes: () => {}});
  return {on: () => {}, style: () => {}, destroy: () => {}, elements: () => ({remove: () => { for (const k in els) delete els[k]; }}),
          add: (list) => { out.cyAdds.push(list.map((x) => x.data.id)); for (const x of list) els[x.data.id] = x.data; },
          layout: (o) => ({run: () => { out.layout = o.name; }}), getElementById: coll};
}
function uPlot(opts, data, el) { out.plots.push({series: opts.series.length, cols: data.length, band: !!opts.bands}); this.destroy = () => {}; }
uPlot.paths = {stepped: () => 'stepped'};
const sandbox = {console, JSON, Math, Date, Object, Array, String, Number, Promise, RegExp, Error, Set, Map, isFinite,
  encodeURIComponent, decodeURIComponent, AbortController,
  setTimeout: (fn, d) => { tid += 1; timers.push({fn, d, id: tid}); return tid; },
  clearTimeout: (id) => { const i = timers.findIndex((t) => t.id === id); if (i >= 0) timers.splice(i, 1); },
  document: {createElement: (t) => new Node_(t), createElementNS: (ns, t) => new Node_(t), getElementById: byId,
             addEventListener: (t, f) => { (listeners[t] = listeners[t] || []).push(f); }, hidden: false,
             documentElement, body},
  window: {addEventListener: (t, f) => { (listeners[t] = listeners[t] || []).push(f); }},
  location, localStorage: store(), sessionStorage: store(), fetch: fetchStub, confirm: () => true,
  getComputedStyle: () => ({getPropertyValue: (n) => '#123456'}), cytoscape, uPlot,
  URL: {createObjectURL: () => { out.downloads += 1; return 'blob:x'; }, revokeObjectURL: () => {}}};
const ctx = vm.createContext(sandbox);
const settle = async () => { for (let i = 0; i < 60; i++) await new Promise((r) => setImmediate(r)); };
const runTimers = async () => { const now = timers.splice(0); for (const t of now) t.fn(); await settle(); };
const go = async (hash) => { location.hash = hash; fire('hashchange'); await settle(); };
const buttons = (label) => find((n) => n.tagName === 'BUTTON' && n.textContent === label);
(async () => {
  try {
    vm.runInContext(code, ctx, {filename: 'console.js'});
    fire('DOMContentLoaded');
    await settle();
    out.signout = byId('signout').attrs.href;
    out.who = text('who');
    out.list = text('main');
    out.startDisabled = buttons('Start')[0].disabled;
    buttons('Start')[0].disabled = false; buttons('Start')[0].click(); await settle();
    out.afterStart = location.hash;
    // a finished session
    await go('#/s/' + D.sid);
    out.head = text('sess-head');
    out.work = text('work');
    out.lanesRects = find((n) => n.tagName === 'RECT' && /\bspan\b/.test(n.className)).length;
    out.marks = find((n) => n.tagName === 'PATH' && /\bmark\b/.test(n.className)).length;
    const ev = find((n) => n.attrs['data-event'])[0];
    byId('lanes').fire('click', {target: ev});
    fire('hashchange');
    await settle();
    out.hashAfterClick = location.hash;
    out.inspector = text('inspector');
    out.selected = find((n) => n.classList.contains('selected')).length;
    buttons('Download OTel')[0].click(); await settle();
    buttons('Re-execute')[0].click(); await settle();
    out.afterReexecute = location.hash;
    // a live session waiting at a gate
    await go('#/s/' + D.live);
    out.liveWork = text('work');
    const cap = find((n) => n.tagName === 'INPUT' && n.attrs.type === 'number')[0];
    out.capDefault = cap.value;
    buttons('Approve')[0].click(); await settle();
    buttons('Accept').forEach((b) => b.click()); await settle();
    out.timersQueued = timers.length;
    byId('otel-content').checked = true;             // ticked before a live update redraws the header
    await runTimers();
    out.liveWorkAfter = text('work');
    out.otelKept = byId('otel-content').checked;
    buttons('Stop')[0].click(); await settle();
    // a decision while a long-poll is held: the held request is aborted and one loop goes on (§3.3)
    await go('#/s/' + D.held);
    hold = true;
    await runTimers();
    out.heldBefore = {inFlight, timers: timers.length};
    buttons('Approve')[0].click(); await settle();
    out.heldAfterClick = {inFlight};
    await runTimers();                               // the kick's poll (and the toast's timer)
    out.heldKicked = {inFlight, timers: timers.length};
    release(); await settle();
    out.heldAfterRelease = {inFlight, timers: timers.length};
    await runTimers();
    out.heldNext = {inFlight, timers: timers.length};
    release(); await settle();
    hold = false;
    // the campaign, a run, the replay, a comparison, the theme
    await go('#/s/' + D.sid + '/c/' + D.cid);
    out.campaign = text('main');
    out.dots = find((n) => n.tagName === 'CIRCLE').length;
    out.proposedDots = find((n) => n.tagName === 'CIRCLE' && n.classList.contains('proposed')).length;
    await go('#/s/' + D.sid + '/c/' + D.cid + '/r/0');
    out.run = text('main');
    await go('#/s/' + D.sid + '/replay');
    await runTimers(); await runTimers();
    out.replay = text('main');
    out.scrolled = find((n) => n.scrolled).length;
    await go('#/cmp/' + D.sid + '/' + D.sid);
    out.compare = text('main');
    byId('theme').click();
    out.theme = documentElement.attrs['data-theme'] || null;
  } catch (e) { out.errors.push(String(e && e.stack || e)); }
  console.log(JSON.stringify(out));
})();
process.on('unhandledRejection', (e) => { out.errors.push('unhandled: ' + String(e && e.stack || e)); });
"""


@unittest.skipUnless(NODE, "node not installed")
class PageUnderNode(unittest.TestCase):
    """console.js as a whole (the DOM part too) against a stub DOM and a stub API."""

    @classmethod
    def setUpClass(cls):
        import mcp_sim
        from research.agents import otel  # noqa: F401  (the trace builders below import the agent code)
        events, k = e58()
        sid = "Q" * 22
        live_sid = "L" * 22
        cut = next(i for i, e in enumerate(events) if e["event"] == "gate_pending") + 1
        table = mcp_sim.summarise_settings(runner_rows(), CampaignViews.defaults)
        check = mcp_sim.compare_evidence(runner_rows(), "PID", {"cycle_time": 30.0}, "air_temperature.rmsd_mid",
                                         CampaignViews.defaults)
        events = copy.deepcopy(events)
        for e in events:              # the proposal carries the check, its evidence names the campaign
            if e["event"] == "tool_result" and e["actor"] == "agent" and e["payload"].get("tool") == "propose.parameter_set":
                doc = {"kind": "parameter_set", "algorithm_code": "PID", "params": {"cycle_time": 30.0},
                       "evidence": [{"cid": CID, "spec_digest": "s" * 64, "result_digest": "d" * 64}],
                       "check": mcp_sim.clean_obj(check), "rationale": "<b>lowest</b> rmsd"}
                e["payload"]["result"] = json.dumps({"proposal": doc, "proposal_sha256": "e" * 64})
        live = [e for e in events[:cut]]
        later = [dict(e, event_id=e["event_id"]) for e in events[cut:cut + 3]]
        no_decision = [e for e in events if e["event"] != "proposal_decided"]
        info = {"sid": sid, "profile": "compare_controllers_gpu", "backend": "gpu", "exp": 1795716000, "claimed": True,
                "active": False, "revoked": True, "budget": {"turns": 14, "cpu_hours": 2}, "spent": {"turns": 6, "cpu_hours": 0.11}}
        data = {
            "signout": "https://agents.example/oauth2/sign_out?rd=https%3A%2F%2Fkeycloak.example",
            "me": {"username": "sci", "role": "control_scientist",
                   "can": {"start": True, "decide": True, "stop": True, "replay": True, "reexecute": True}},
            "profiles": {"profiles": [{"name": "compare_controllers", "backend": "scripted", "caps": {"context_tokens": 4000}},
                                      {"name": "compare_controllers_gpu", "backend": "gpu", "caps": {"context_tokens": 12000}}],
                         "endpoints": [{"name": "gpu", "model": "Qwen/Qwen3-14B-AWQ", "context": 12288}]},
            "listing": {"sessions": [], "history": [dict(info, created_at="2026-11-26T10:00:00+00:00")], "endpoints": []},
            "sid": sid, "live": live_sid, "held": "H" * 22, "sid2": "N" * 22, "cid": CID,
            "sessions": {sid: {"info": info, "events": no_decision},
                         live_sid: {"info": dict(info, sid=live_sid, active=True, revoked=False, spent={"cpu_hours": 0.1}),
                                    "events": live, "later": later},
                         "H" * 22: {"info": dict(info, sid="H" * 22, active=True, revoked=False, spent={"cpu_hours": 0.1}),
                                    "events": copy.deepcopy(live)}},
            "campaign": {"manifest": {"runs": 36}, "by_setting": table, "series": {"every_s": 60, "runs": 1},
                         "runs": {"offset": 0, "total": 36, "rows": [mcp_sim.summarise_row(r) for r in runner_rows()[:3]]}},
            "row": runner_rows()[0], "series": Series.doc(400),
            "verdict": {"ok": False, "events": 7, "first_mismatch": {"index": 2, "agent": "a0", "event": "tool_call",
                                                                     "field": "args_sha256", "recorded": "a", "replayed": "b"}},
        }
        d = tempfile.mkdtemp()
        cls.addClassCleanup(shutil.rmtree, d)
        with open(os.path.join(d, "data.json"), "w") as f:
            json.dump(data, f)
        with open(os.path.join(d, "h.js"), "w") as f:
            f.write(PAGE_HARNESS)
        r = subprocess.run([NODE, os.path.join(d, "h.js"), os.path.join(d, "data.json"), JS], capture_output=True, text=True,
                           timeout=120)
        if r.returncode:
            raise AssertionError(r.stderr)
        cls.o = json.loads(r.stdout.strip().splitlines()[-1])
        cls.data, cls.k = data, k

    def test_no_errors(self):
        self.assertEqual(self.o["errors"], [])

    def test_boot_and_the_list(self):
        o = self.o
        self.assertEqual(o["signout"], self.data["signout"])
        self.assertEqual(o["who"], "sci · control_scientist")
        self.assertIn("QQQQQQQQ", o["list"])
        self.assertIn("ended", o["list"])
        self.assertIn("Start a session", o["list"])
        self.assertFalse(o["startDisabled"])                       # the scripted profile, its own model
        start = next(p for p in o["posts"] if p["url"] == "/api/sessions")
        self.assertEqual((start["body"], start["ct"]), ({"profile": "compare_controllers"}, "application/json"))
        self.assertEqual(o["afterStart"], "#/s/" + "N" * 22)

    def test_a_session(self):
        o = self.o
        self.assertIn("compare_controllers_gpu", o["head"])
        self.assertIn("ended", o["head"])
        self.assertIn("campaign " + CID, o["work"])
        self.assertIn("gate approved by sci", o["work"])
        self.assertIn("<b>lowest</b> rmsd", o["work"])               # as text, never markup
        self.assertIn("Criterion air_temperature.rmsd_mid", o["work"])
        self.assertIn("Accept", o["work"])                          # undecided in this listing
        self.assertGreater(o["lanesRects"], 10)
        self.assertGreater(o["marks"], 3)
        self.assertEqual(o["cyAdds"][0], ["agent:a0", "server:model-gateway", "server:mcp-sim",
                                          "use:a0>model-gateway", "use:a0>mcp-sim"])
        self.assertEqual(o["layout"], "breadthfirst")
        self.assertRegex(o["hashAfterClick"], r"^#/s/Q{22}/e/\d+$")
        self.assertIn("Inspector: ", o["inspector"])
        self.assertIn("prev_hash", o["inspector"])
        self.assertGreaterEqual(o["selected"], 1)
        self.assertEqual(o["downloads"], 1)
        self.assertIn("GET /api/sessions/%s/otel" % ("Q" * 22), o["fetches"])
        self.assertEqual(o["afterReexecute"], "#/s/" + "N" * 22)

    def test_a_live_session_decides_and_polls(self):
        o = self.o
        self.assertIn("Waiting for you", o["liveWork"])
        self.assertEqual(o["capDefault"], "0.55")
        gate = next(p for p in o["posts"] if "/gates/" in p["url"])
        self.assertEqual(gate["url"], "/api/sessions/%s/gates/%s" % ("L" * 22, CID))
        self.assertEqual(gate["body"], {"decision": "approve", "note": "", "approved_cap_h": 0.55})
        self.assertTrue(any(f.startswith("GET /api/sessions/%s/events?after=" % ("L" * 22)) and "wait=" in f for f in o["fetches"]))
        self.assertIn("sim_started", json.dumps(self.data["sessions"]["L" * 22]["later"]))
        self.assertIn("running", o["liveWorkAfter"])                # the poll brought sim_started
        stop = next(p for p in o["posts"] if p["url"].endswith("/stop"))
        self.assertEqual(stop["body"], {})
        self.assertTrue(o["otelKept"])                              # "with content" survives the redraw

    def test_a_decision_during_a_held_long_poll_keeps_one_loop(self):
        o = self.o
        self.assertEqual(o["heldBefore"], {"inFlight": 1, "timers": 0})
        # the kick aborts the held request, then starts one new one (before the fix: two in flight, two loops)
        self.assertEqual(o["heldAfterClick"], {"inFlight": 0})
        self.assertEqual(o["heldKicked"], {"inFlight": 1, "timers": 0})
        self.assertEqual(o["heldAfterRelease"], {"inFlight": 0, "timers": 1})
        self.assertEqual(o["heldNext"], {"inFlight": 1, "timers": 0})
        self.assertTrue(any(p["url"] == "/api/sessions/%s/gates/%s" % ("H" * 22, CID) for p in o["posts"]))

    def test_campaign_run_replay_compare_theme(self):
        o = self.o
        self.assertIn("Settings", o["campaign"])
        self.assertEqual(o["dots"], 4)
        self.assertEqual(o["proposedDots"], 1)
        self.assertIn("Runs (36)", o["campaign"])
        self.assertIn("400 points every 60 s", o["run"])
        self.assertIn("The result row", o["run"])
        self.assertEqual(len(o["plots"]), 6)
        self.assertTrue(o["plots"][0]["band"])
        self.assertIn("The replay differs at the 3th agent event (agent a0): tool_call, field args_sha256", o["replay"])
        self.assertEqual(o["scrolled"], 1)
        self.assertIn("turn(s) compared", o["compare"])
        self.assertEqual(o["theme"], "light")

    def test_every_post_is_json_to_the_api(self):
        for p in self.o["posts"]:
            self.assertEqual(p["ct"], "application/json")
            self.assertTrue(p["url"].startswith("/api/"))



class Static(unittest.TestCase):
    def test_index_has_nothing_inline(self):
        html = read(INDEX)
        self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)|<style|\sstyle=|\son[a-z]+=")
        page = load("rc_page", os.path.join(APP, "page.py"))
        names = set(page.files())
        for ref in re.findall(r'(?:src|href)="([^"#]+)"', html):
            if ref.startswith("/oauth2/"):
                continue                       # the proxy's own Sign out until the manifest's is read
            self.assertTrue(ref.startswith("/static/"), ref)
            self.assertIn(ref[len("/static/"):], names, ref)
        self.assertNotRegex(html, r"https?://")
        self.assertIn('id="__________cytoscape_stylesheet"', html)
        self.assertIn(".__________cytoscape_container { position: relative; }", read(os.path.join(HTML, "cytoscape-container.css")))

    def test_console_js_never_parses_markup(self):
        src = read(JS)
        code = strip_comments(src)
        for bad in (r"\.innerHTML", r"\.outerHTML", r"insertAdjacentHTML", r"document\.write", r"\beval\s*\(",
                    r"new\s+Function", r"\bFunction\s*\(", r"setAttribute\(\s*['\"]style", r"setAttribute\(\s*['\"]on",
                    r"\.cssText", r"setTimeout\(\s*['\"]", r"javascript:"):
            self.assertNotRegex(code, bad)
        urls = re.findall(r"https?://[A-Za-z][^'\"\s]*", code)       # a host: the bare scheme is the Sign out check
        self.assertEqual(urls, ["http://www.w3.org/2000/svg"])
        # el() takes text through textContent only, and attributes through setAttribute
        self.assertIn("n.textContent = String(o.text)", src)

    def test_the_logic_block_has_no_dom_or_clock(self):
        block = strip_comments(logic_block())
        for bad in ("document", "window", "fetch(", "Date.now", "localStorage", "sessionStorage", "location", "setTimeout",
                    "Math.random"):
            self.assertNotIn(bad, block)

    def test_theme_tokens_light_and_dark(self):
        css = read(CSS)
        root = re.search(r"^:root \{(.*?)\n\}", css, re.S | re.M).group(1)
        dark_media = re.search(r'@media \(prefers-color-scheme: dark\) \{\s*:root:not\(\[data-theme="light"\]\) \{(.*?)\}', css, re.S).group(1)
        dark_choice = re.search(r':root\[data-theme="dark"\] \{(.*?)\}', css, re.S).group(1)
        for tok in ("--bg", "--panel", "--ink", "--muted", "--line", "--accent", "--ok", "--warn", "--bad", "--band"):
            for block in (root, dark_media, dark_choice):
                self.assertRegex(block, re.escape(tok) + r":")
        self.assertIn("--bg: #0f172a; --panel: #1e293b", dark_media)          # the portal's slate palette
        self.assertEqual(re.sub(r"\s+", "", dark_media), re.sub(r"\s+", "", dark_choice))
        self.assertRegex(css, r"body \{[^}]*background: var\(--bg\)")
        self.assertRegex(css, r"main \{[^}]*padding: 12px 16px")
        js = read(JS)
        for tok in re.findall(r"token\('(--[a-z-]+)'\)", js):
            self.assertRegex(root, re.escape(tok) + r":", tok)

    def test_vendor_files_are_their_versions(self):
        libs = sorted(os.listdir(VENDOR))
        self.assertEqual(libs, ["cytoscape", "uplot"])
        expect = {"uplot": ("uplot 1.6.32", ["uPlot.iife.min.js", "uPlot.min.css", "LICENSE"]),
                  "cytoscape": ("cytoscape 3.35.0", ["cytoscape.min.js", "LICENSE"])}
        for lib in libs:
            text = read(os.path.join(VENDOR, lib, "VERSION"))
            head, files = expect[lib]
            self.assertTrue(text.startswith(head + " (MIT"), text[:40])
            self.assertRegex(text, r"source: https://registry\.npmjs\.org/%s/-/%s-%s\.tgz" % (lib, lib, head.split()[1]))
            self.assertRegex(text, r"tarball sha512 \(= the registry's dist\.integrity\): sha512-[A-Za-z0-9+/]{86}==")
            self.assertRegex(text, r"tarball sha256: [0-9a-f]{64}")
            listed = dict((n, h) for h, n in re.findall(r"(?m)^([0-9a-f]{64})  (\S+)$", text))
            self.assertEqual(sorted(listed), sorted(files))
            self.assertEqual(sorted(os.listdir(os.path.join(VENDOR, lib))), sorted(files + ["VERSION"]))
            for n, h in listed.items():
                with open(os.path.join(VENDOR, lib, n), "rb") as f:
                    self.assertEqual(hashlib.sha256(f.read()).hexdigest(), h, n)
            self.assertIn("MIT", read(os.path.join(VENDOR, lib, "LICENSE")))

    def test_the_libraries_need_no_eval_and_no_inline_style(self):
        u = read(os.path.join(VENDOR, "uplot", "uPlot.iife.min.js"))
        c = read(os.path.join(VENDOR, "cytoscape", "cytoscape.min.js"))
        for src in (u, c):
            self.assertNotRegex(src, r"\beval\(|new Function|setAttribute\(\"style\"|insertAdjacentHTML|\.innerHTML\s*=")
        self.assertNotIn("Function(", u)
        self.assertNotIn('createElement("style")', u)
        self.assertEqual(c.count("Function("), 1)
        self.assertIn('t||Function("return this")()', c)                    # lodash's global probe: self comes first
        # the one <style> Cytoscape would add is skipped while an element with its id exists (index.html's link)
        self.assertRegex(c, r'o="__________cytoscape_stylesheet",[^;]*?l=null!=a\.getElementById\(o\);if\([^{]*?!l\)\{var u=a\.createElement\("style"\)')
        self.assertEqual(c.count('createElement("style")'), 1)
        self.assertNotRegex(c, r"new Worker|importScripts|XMLHttpRequest")

    def test_the_configmap_stays_small(self):
        page = load("rc_page2", os.path.join(APP, "page.py"))
        cm = page.configmap("medcea-research-agents", "https://agents.example/oauth2/sign_out")
        size = sum(len(v.encode()) for v in cm["data"].values()) + sum(len(v) for v in cm.get("binaryData", {}).values())
        self.assertLess(size, 800 * 1024, "past 800 KiB the vendor files move to their own ConfigMap (design §4.2)")
        names = json.loads(cm["data"]["MANIFEST.json"])["files"]
        for n in ("index.html", "console.js", "console.css", "cytoscape-container.css", "uplot/uPlot.iife.min.js",
                  "uplot/uPlot.min.css", "cytoscape/cytoscape.min.js"):
            self.assertIn(n, names)


if __name__ == "__main__":
    unittest.main()
