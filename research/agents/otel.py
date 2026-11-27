"""research/agents/otel.py (research Phase 4e commit A3; design 4.5, OD-4e-11): a session's trace as OpenTelemetry.

export(events, session, content=False) -> an OTLP/JSON ExportTraceServiceRequest (a dict; json.dumps it), for opening
in Jaeger (its "JSON file" upload) or Grafana with a Tempo data source, or handing to another tool. One-way: the record
stays agent_trace (hash chain, backup anchor, replay); the export is derived from it, never read back, and names the
chain head it was made from (resource attribute medcea.trace.chain_head). Stdlib only, pure: the same events give the
same bytes (no clock, no randomness), so two exports of one session can be compared.

  events   the session's events as GET /api/sessions/<sid>/events returns them, oldest first (every page):
           {event_id, at, actor, event, payload[, prev_hash, hash]}
  session  what is known of the session beside its trace: sid (required), and when known profile, backend,
           code_commit, sup_username, sup_role, endpoint_kind. Only these keys are read: a sub, person id, token,
           claim or key id the dict may also hold never reaches the export.

The spans (one trace per session; parent first):

  invoke_agent <profile>       the session: session_minted -> the lead's stop or the revocation, whichever comes first;
                               status from the lead's stop reason
    invoke_agent a0            the lead: its claim (claim_exchanged) -> its stop
      chat <model>             a turn: turn_request -> turn_response (the agent's, or the model-gateway's for a model
                               behind it), usage and finish reasons
      execute_tool <tool>      a call: tool_call -> the agent's tool_result; status ERROR on a refusal; the tool
                               server's own record of the call is a span event
        sim.campaign           a campaign the call started: sim_started -> the first sim_finished (CPU-hours)
      invoke_agent a0.N        a specialist (research Phase 4e A1b): agent_spawned -> agent_returned, under its
                               parent agent's span, with its own chat/execute_tool spans
  span events: gate_pending/gate_decided on the call that asked for the gate, proposal/proposal_decided and
  checkpoint on the agent's span, claims, revocation, trace_refused and replay_result on the session's span.

No content unless content=True: by default digests and sizes only (request, response, arguments, result sha256), never
the model's text, a tool's arguments or result, a specialist's task or answer, or a supervisor's note. content=True
adds what the trace holds (already cut to the trace's own limits, so "as the trace shows them") as span events named
after the GenAI attribute they carry. The model's request itself is never in the trace (only its sha256), so
gen_ai.input.messages appears only for a specialist's task. The session token, claim and the supervisor's sub never
appear in either mode: the supervisor is its username and role, a decision its username.

Span ids: traceId = the first 16 bytes of sha256("medcea-session:" + sid); spanId = the first 8 bytes of
sha256(sid + str(event_id)) of the event that opens the span (session_minted, agent_spawned, turn_request, tool_call,
sim_started; the lead's claim_exchanged). The lead's span, when no claim is recorded, takes sha256(sid + str(event_id)
+ "/a0") of session_minted, so it never shares the session span's id. A span still open at the end of the trace ends
at its last event, with medcea.incomplete = true."""
import hashlib
import json
from datetime import datetime, timezone

# The OpenTelemetry semantic conventions followed, and the resource's schema_url. Checked against the GenAI conventions
# as published in semantic-conventions v1.37.0 (August 2025), the release that renamed gen_ai.system to
# gen_ai.provider.name and introduced gen_ai.input.messages / gen_ai.output.messages (JSON, role + parts). Used here:
# span names "invoke_agent {gen_ai.agent.name}", "chat {gen_ai.request.model}", "execute_tool {gen_ai.tool.name}";
# gen_ai.operation.name (invoke_agent, chat, execute_tool), gen_ai.provider.name, gen_ai.conversation.id,
# gen_ai.agent.id, gen_ai.agent.name, gen_ai.request.model, gen_ai.request.max_tokens / temperature / top_k / seed,
# gen_ai.response.finish_reasons, gen_ai.usage.input_tokens / output_tokens, gen_ai.tool.name, gen_ai.tool.call.id,
# gen_ai.tool.type, error.type. Uncertain (written down, not verified against a later release): the conventions are
# still "Development" status, so a later release may rename these; gen_ai.tool.call.arguments / gen_ai.tool.call.result
# are named as later drafts name them, and here only ever carry content (content=True); "llama.cpp" and
# "medcea.scripted" are not well-known gen_ai.provider.name values (custom values are allowed). Our own attributes are
# under medcea.*.
SEMCONV = "1.37.0"
SCHEMA_URL = "https://opentelemetry.io/schemas/" + SEMCONV
EXPORT_VERSION = "1"
SCOPE = "medcea.research.agents.otel"
SERVICE = "medcea-research-agents"
LEAD = "a0"

KIND_INTERNAL, KIND_CLIENT = 1, 3                  # Span.SpanKind
STATUS_UNSET, STATUS_OK, STATUS_ERROR = 0, 1, 2    # Status.StatusCode
# A stop reason's status: finished is OK; a model or turn failure is ERROR; a cap, the context end, no tool call or a
# revocation is neither (the session ended as its profile or its supervisor bounds it): UNSET, the reason an attribute
OK_REASONS = frozenset(["finished"])
ERROR_REASONS = frozenset(["model_error", "model_refused", "model_busy", "turn_timeout"])
SERVER_ACTORS = frozenset(["mcp-sim", "mcp-lake"])


def trace_id(sid):
    return hashlib.sha256(("medcea-session:" + sid).encode("utf-8")).hexdigest()[:32]


def span_id(sid, event_id, role=""):
    h = hashlib.sha256((sid + str(event_id) + ("/" + role if role else "")).encode("utf-8")).hexdigest()[:16]
    return h if h != "0" * 16 else "0" * 15 + "1"          # an all-zero id is invalid in OTLP


def _ns(at):
    """An event's `at` (ISO 8601, as the orchestrator returns it) as integer nanoseconds since the epoch, or None."""
    if not isinstance(at, str):
        return None
    try:
        d = datetime.fromisoformat(at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    t = d - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (t.days * 86400 + t.seconds) * 1000000000 + t.microseconds * 1000


def _value(v):
    if isinstance(v, bool):
        return {"boolValue": v}
    if isinstance(v, int):
        return {"intValue": str(v)}
    if isinstance(v, float):
        return {"doubleValue": v} if v == v and v not in (float("inf"), float("-inf")) else {"stringValue": str(v)}
    if isinstance(v, (list, tuple)):
        return {"arrayValue": {"values": [_value(x) for x in v]}}
    if isinstance(v, (dict,)):
        return {"stringValue": json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)}
    return {"stringValue": str(v)}


def _attrs(pairs):
    return [{"key": k, "value": _value(v)} for k, v in pairs if v is not None]


def _num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _dbl(v):
    x = _num(v)
    return None if x is None else float(x)


def _str(v):
    return v if isinstance(v, str) else None


def _json(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class _Span:
    def __init__(self, sid_, opener, role, parent, name, kind, start):
        self.id = span_id(sid_, opener, role)
        self.parent, self.name, self.kind = parent, name, kind
        self.start, self.end = start, None
        self.attrs, self.events = [], []
        self.status, self.message = STATUS_UNSET, None

    def attr(self, *pairs):
        """Set attributes; a key set again keeps its first place and takes the later value (a specialist's stop, then
        its agent_returned)."""
        for k, v in pairs:
            i = next((n for n, (k2, _) in enumerate(self.attrs) if k2 == k), None)
            if i is None:
                self.attrs.append((k, v))
            elif v is not None:
                self.attrs[i] = (k, v)

    def event(self, t, name, *pairs):
        self.events.append((t, name, list(pairs)))

    def close(self, t):
        if self.end is None:
            self.end = t

    def otlp(self, tid):
        s = {"traceId": tid, "spanId": self.id}
        if self.parent is not None:
            s["parentSpanId"] = self.parent.id
        s.update(name=self.name, kind=self.kind, startTimeUnixNano=str(self.start),
                 endTimeUnixNano=str(max(self.end, self.start)), attributes=_attrs(self.attrs))
        if self.events:
            s["events"] = [{"timeUnixNano": str(t), "name": n, "attributes": _attrs(a)} for t, n, a in self.events]
        st = {"code": self.status}
        if self.message:
            st["message"] = self.message
        s["status"] = st
        return s


def _status(span, reason):
    if reason in OK_REASONS:
        span.status = STATUS_OK
    elif reason in ERROR_REASONS:
        span.status, span.message = STATUS_ERROR, reason


def _provider(backend, flags, endpoint_kind):
    if backend == "scripted" or (backend or "").startswith("scripted:"):     # the profile, or its script's model id
        return "medcea.scripted"
    kind = (flags or {}).get("endpoint_kind") or endpoint_kind
    if kind == "openai":
        return "openai"           # an OpenAI-compatible API (vLLM on the tailnet's GPU)
    if kind == "llama" or backend == "local":
        return "llama.cpp"
    return None


def _output_messages(resp, finish):
    parts = []
    if resp.get("text"):
        parts.append({"type": "text", "content": resp["text"]})
    tool = resp.get("tool")
    if isinstance(tool, dict):
        parts.append({"type": "tool_call", "name": tool.get("name"), "arguments": tool.get("args", {})})
    m = {"role": "assistant", "parts": parts}
    if finish:
        m["finish_reason"] = finish
    return _json([m])


def export(events, session, content=False):
    """-> an OTLP/JSON ExportTraceServiceRequest of the session (see the module's text)."""
    sid = session["sid"]
    if not isinstance(sid, str) or not sid:
        raise ValueError("session needs its sid")
    content = bool(content)
    evs = sorted((e for e in events if isinstance(e, dict) and isinstance(e.get("event_id"), int)),
                 key=lambda e: e["event_id"])
    tid = trace_id(sid)
    spans = []
    profile, backend = _str(session.get("profile")), _str(session.get("backend"))
    code_commit = _str(session.get("code_commit"))
    endpoint_kind = _str(session.get("endpoint_kind"))
    flags_seen = None
    st = {"t": 0}
    root = None
    agents, chats, tools, sims, gates, props = {}, {}, {}, {}, {}, {}
    stack = []                       # open execute_tool spans, innermost last (agents run sequentially)
    lead_stop = revoked = None
    head = None

    def new(opener, role, parent, name, kind, start):
        s = _Span(sid, opener, role, parent, name, kind, start)
        spans.append(s)
        return s

    def ensure_root(e, t):
        nonlocal root
        if root is None:
            role = "" if e["event"] == "session_minted" else "session"
            root = new(e["event_id"], role, None, "invoke_agent", KIND_INTERNAL, t)
        return root

    def agent_span(agent, e, t):
        """The agent's span; created at its first event when nothing opened it (the lead without a recorded claim)."""
        if agent in agents:
            return agents[agent]
        r = ensure_root(e, t)
        if agent == LEAD:
            s = new(r_opener[0], "a0", r, "invoke_agent " + LEAD, KIND_INTERNAL, t)
        else:
            parent = agents.get(agent.rsplit(".", 1)[0], r)
            s = new(e["event_id"], "agent " + agent, parent, "invoke_agent " + agent, KIND_INTERNAL, t)
        s.attr(("gen_ai.operation.name", "invoke_agent"), ("gen_ai.agent.id", agent), ("gen_ai.conversation.id", sid))
        if agent == LEAD:
            s.attr(("gen_ai.agent.name", profile))
        agents[agent] = s
        return s

    def top_tool():
        return tools[stack[-1]] if stack else None

    r_opener = [None]
    for e in evs:
        t = _ns(e.get("at"))
        t = st["t"] if t is None else t
        st["t"] = t
        if isinstance(e.get("hash"), str):
            head = "%d:%s" % (e["event_id"], e["hash"])
        ev, p, actor = e.get("event"), e.get("payload") or {}, e.get("actor")
        if not isinstance(p, dict):
            p = {}
        agent = p.get("agent") if isinstance(p.get("agent"), str) else LEAD
        if r_opener[0] is None:
            r_opener[0] = e["event_id"]

        if ev == "session_minted":
            r = ensure_root(e, t)
            profile = _str(p.get("profile")) or profile
            backend = _str(p.get("backend")) or backend
            code_commit = _str(p.get("code_commit")) or code_commit
            r.attr(("medcea.profile.sha256", _str(p.get("profile_sha256"))), ("medcea.reexecutes", _str(p.get("reexecutes"))))
            continue
        r = ensure_root(e, t)

        if ev == "claim_exchanged":
            if LEAD not in agents:
                s = new(e["event_id"], "", r, "invoke_agent " + LEAD, KIND_INTERNAL, t)
                s.attr(("gen_ai.operation.name", "invoke_agent"), ("gen_ai.agent.id", LEAD),
                       ("gen_ai.conversation.id", sid), ("gen_ai.agent.name", profile))
                agents[LEAD] = s
            else:
                r.event(t, "claim_exchanged")
        elif ev == "claim_reused":
            r.event(t, "claim_reused")
        elif ev == "turn_request":
            a = agent_span(agent, e, t)
            turn = p.get("turn")
            if (agent, turn) in chats:
                chats.pop((agent, turn)).close(t)
            model = _str(p.get("model")) or _str(p.get("backend")) or backend or "model"
            flags = p.get("flags") if isinstance(p.get("flags"), dict) else {}
            if actor == "model-gateway" and flags_seen is None:
                flags_seen = flags
            c = new(e["event_id"], "", a, "chat " + model, KIND_CLIENT, t)
            sampler = flags.get("sampler") if isinstance(flags.get("sampler"), dict) else {}
            c.attr(("gen_ai.operation.name", "chat"), ("gen_ai.request.model", model),
                   ("gen_ai.provider.name", _provider(_str(p.get("backend")) or backend, flags, endpoint_kind)),
                   ("gen_ai.conversation.id", sid), ("medcea.agent.id", agent), ("medcea.turn", _num(turn)),
                   ("gen_ai.request.max_tokens", _num(flags.get("max_tokens"))),
                   ("gen_ai.request.temperature", _dbl(sampler.get("temperature"))),
                   ("gen_ai.request.top_k", _dbl(sampler.get("top_k"))),
                   ("gen_ai.request.seed", _num(sampler.get("seed"))),
                   ("medcea.model.sha256", _str(p.get("model_sha256")) or None),
                   ("medcea.request.sha256", _str(p.get("request_sha256"))),
                   ("medcea.request.est_tokens", _num(p.get("est_prompt_tokens"))),
                   ("medcea.context_tokens", _num(flags.get("ctx"))), ("medcea.recorded_by", actor))
            chats[(agent, turn)] = c
        elif ev == "turn_response":
            turn = p.get("turn")
            c = chats.pop((agent, turn), None)
            if c is None:
                c = new(e["event_id"], "", agent_span(agent, e, t), "chat " + (backend or "model"), KIND_CLIENT, t)
                c.attr(("gen_ai.operation.name", "chat"), ("medcea.agent.id", agent), ("medcea.turn", _num(turn)))
            c.close(t)
            if p.get("error"):
                c.status, c.message = STATUS_ERROR, _str(p.get("error"))
                c.attr(("error.type", _str(p.get("error"))))
                continue
            resp = p.get("response") if isinstance(p.get("response"), dict) else {}
            u = p.get("usage") if isinstance(p.get("usage"), dict) else {}
            finish = _str(p.get("finish_reason")) or ("tool_calls" if resp.get("tool") else ("stop" if resp else None))
            c.attr(("gen_ai.response.finish_reasons", [finish] if finish else None),
                   ("gen_ai.usage.input_tokens", _num(u.get("prompt_tokens"))),
                   ("gen_ai.usage.output_tokens", _num(u.get("output_tokens"))),
                   ("medcea.usage.estimated", u.get("estimated") if isinstance(u.get("estimated"), bool) else None),
                   ("medcea.response.sha256", _str(p.get("response_sha256"))),
                   ("medcea.response.bytes", len(_json(resp).encode("utf-8")) if resp else None),
                   ("medcea.response.tool", _str((resp.get("tool") or {}).get("name")) if isinstance(resp.get("tool"), dict) else None),
                   ("medcea.dropped_calls", _num(p.get("dropped_calls"))))
            if content and resp:
                c.event(t, "gen_ai.output.messages", ("gen_ai.output.messages", _output_messages(resp, finish)))
        elif ev == "tool_call":
            a = agent_span(agent, e, t)
            call, name = p.get("call"), _str(p.get("tool")) or "tool"
            s = new(e["event_id"], "", a, "execute_tool " + name, KIND_INTERNAL, t)
            s.attr(("gen_ai.operation.name", "execute_tool"), ("gen_ai.tool.name", name),
                   ("gen_ai.tool.call.id", str(call) if call is not None else None), ("gen_ai.tool.type", "function"),
                   ("gen_ai.conversation.id", sid), ("medcea.agent.id", agent), ("medcea.turn", _num(p.get("turn"))),
                   ("medcea.tool.args_sha256", _str(p.get("args_sha256"))))
            if content and "args" in p:
                s.event(t, "gen_ai.tool.call.arguments", ("gen_ai.tool.call.arguments", _json(p["args"])))
            key = (agent, call)
            if key in tools and key in stack:
                stack.remove(key)
            tools[key] = s
            stack.append(key)
        elif ev == "tool_result" and actor not in SERVER_ACTORS:
            key = (agent, p.get("call"))
            s = tools.get(key)
            if s is None:
                s = new(e["event_id"], "", agent_span(agent, e, t), "execute_tool " + (_str(p.get("tool")) or "tool"),
                        KIND_INTERNAL, t)
                tools[key] = s
            if key in stack:
                stack.remove(key)
            s.close(t)
            s.attr(("medcea.tool.result_sha256", _str(p.get("result_sha256"))), ("medcea.tool.result_bytes", _num(p.get("bytes"))),
                   ("medcea.tool.truncated", p.get("truncated") if isinstance(p.get("truncated"), bool) else None))
            if p.get("error") is True:
                s.status = STATUS_ERROR
                s.attr(("error.type", "malformed_call" if p.get("tool") == "invalid_call" else "tool_refused"))
            if content and isinstance(p.get("result"), str):
                s.event(t, "gen_ai.tool.call.result", ("gen_ai.tool.call.result", p["result"]),
                        ("medcea.content.complete", p.get("recorded_complete") if isinstance(p.get("recorded_complete"), bool) else None))
        elif ev == "tool_result":           # the tool server's own record of the call
            ac = p.get("agent_call")
            s = tools.get((agent, ac)) if isinstance(p.get("agent"), str) and isinstance(ac, int) else None
            if s is None:
                s = next((tools[k] for k in reversed(stack) if tools[k].name == "execute_tool " + str(p.get("tool"))), None)
            (s or r).event(t, "tool_result", ("medcea.actor", actor), ("gen_ai.tool.name", _str(p.get("tool"))),
                           ("medcea.server.call", _num(p.get("call"))),
                           ("medcea.tool.result_sha256", _str(p.get("result_sha256"))),
                           ("medcea.tool.result_bytes", _num(p.get("bytes"))),
                           ("medcea.tool.error", p.get("error") if isinstance(p.get("error"), bool) else None))
        elif ev == "proposal":
            a = agent_span(agent, e, t)
            pid = "p%d" % e["event_id"]
            props[pid] = (a, _str(p.get("result_sha256")) or "")
            a.event(t, "proposal", ("medcea.proposal.id", pid), ("gen_ai.tool.name", _str(p.get("tool"))),
                    ("gen_ai.tool.call.id", str(p["call"]) if p.get("call") is not None else None),
                    ("medcea.proposal.sha256", _str(p.get("result_sha256"))))
        elif ev == "proposal_decided":
            pid = _str(p.get("pid")) or ""
            target = props.get(pid)
            if target is None and pid:      # a decision made with an older CLI names a prefix of the proposal's digest
                target = next((v for v in props.values() if v[1].startswith(pid)), None)
            (target[0] if target else r).event(
                t, "proposal_decided", ("medcea.proposal.id", pid), ("medcea.decision", _str(p.get("decision"))),
                ("medcea.decided_by", _str(p.get("by_username"))), ("medcea.note", _str(p.get("note")) if content else None))
        elif ev == "checkpoint":
            agent_span(agent, e, t).event(t, "checkpoint", ("medcea.checkpoint.seq", _num(p.get("seq"))),
                                          ("medcea.turn", _num(p.get("turn"))), ("medcea.checkpoint.sha256", _str(p.get("sha256"))))
        elif ev == "stop":
            a = agent_span(agent, e, t)
            reason = _str(p.get("reason"))
            a.attr(("medcea.stop.reason", reason), ("medcea.turns", _num(p.get("turns"))),
                   ("gen_ai.usage.input_tokens", _num(p.get("prompt_tokens"))),
                   ("gen_ai.usage.output_tokens", _num(p.get("output_tokens"))), ("medcea.cpu_hours", _num(p.get("cpu_hours"))))
            _status(a, reason)
            if agent == LEAD:
                a.close(t)
                if lead_stop is None:
                    lead_stop = (t, reason, p)
            elif a.end is None:
                a.event(t, "stop", ("medcea.stop.reason", reason))
        elif ev == "agent_spawned" and agent != LEAD:
            parent = agents.get(_str(p.get("parent")) or agent.rsplit(".", 1)[0]) or agent_span(LEAD, e, t)
            s = new(e["event_id"], "", parent, "invoke_agent " + agent, KIND_INTERNAL, t)
            caps = p.get("caps") if isinstance(p.get("caps"), dict) else {}
            s.attr(("gen_ai.operation.name", "invoke_agent"), ("gen_ai.agent.id", agent),
                   ("gen_ai.agent.name", _str(p.get("profile_name"))), ("gen_ai.conversation.id", sid),
                   ("medcea.agent.parent", _str(p.get("parent"))),
                   ("medcea.profile.sha256", _str(p.get("profile_sha256"))), ("medcea.skill.sha256", _str(p.get("skill_sha256"))),
                   ("medcea.tools.sha256", _str(p.get("tools_sha256"))), ("medcea.task.sha256", _str(p.get("task_sha256"))),
                   *[("medcea.caps." + k, _num(caps[k])) for k in sorted(caps)])
            if content and isinstance(p.get("task"), str):
                s.event(t, "gen_ai.input.messages", ("gen_ai.input.messages",
                                                     _json([{"role": "user", "parts": [{"type": "text", "content": p["task"]}]}])))
            agents[agent] = s
        elif ev == "agent_returned" and agent != LEAD:
            s = agent_span(agent, e, t)
            s.close(t)
            reason = _str(p.get("stop_reason"))
            s.attr(("medcea.stop.reason", reason), ("medcea.turns", _num(p.get("turns"))),
                   ("gen_ai.usage.input_tokens", _num(p.get("prompt_tokens"))),
                   ("gen_ai.usage.output_tokens", _num(p.get("output_tokens"))),
                   ("medcea.cpu_hours", _num(p.get("cpu_hours"))), ("medcea.result.sha256", _str(p.get("result_sha256"))))
            _status(s, reason)
            if content and isinstance(p.get("result"), str):
                s.event(t, "gen_ai.output.messages", ("gen_ai.output.messages",
                                                      _json([{"role": "assistant", "parts": [{"type": "text", "content": p["result"]}]}])))
        elif ev == "gate_pending":
            s = top_tool() or r
            gid = _str(p.get("gid"))
            gates[gid] = s
            s.event(t, "gate_pending", ("medcea.gate.id", gid), ("medcea.gate.estimate_h", _num(p.get("estimate_h"))),
                    ("medcea.gate.cap_h", _num(p.get("cap_h"))), ("medcea.gate.runs", _num(p.get("runs"))),
                    ("medcea.spec.sha256", _str(p.get("spec_sha256"))))
        elif ev == "gate_decided":
            gid = _str(p.get("gid"))
            gates.get(gid, r).event(t, "gate_decided", ("medcea.gate.id", gid), ("medcea.decision", _str(p.get("decision"))),
                                    ("medcea.gate.approved_cap_h", _num(p.get("approved_cap_h"))),
                                    ("medcea.decided_by", _str(p.get("by_username"))),
                                    ("medcea.note", _str(p.get("note")) if content else None))
        elif ev == "sim_started":
            cid = _str(p.get("cid"))
            if cid in sims:
                sims[cid].event(t, "sim_started")
                continue
            s = new(e["event_id"], "", top_tool() or r, "sim.campaign", KIND_INTERNAL, t)
            s.attr(("medcea.sim.cid", cid), ("medcea.spec.sha256", _str(p.get("spec_sha256"))),
                   ("medcea.sim.estimate_h", _num(p.get("estimate_h"))), ("medcea.sim.cap_h", _num(p.get("cap_h"))),
                   ("medcea.sim.deadline_s", _num(p.get("deadline_s"))), ("gen_ai.conversation.id", sid))
            sims[cid] = s
        elif ev == "sim_finished":
            cid = _str(p.get("cid"))
            s = sims.get(cid)
            if s is None:
                r.event(t, "sim_finished", ("medcea.sim.cid", cid), ("medcea.actor", actor), ("medcea.sim.state", _str(p.get("state"))))
            elif s.end is None:
                s.close(t)
                s.attr(("medcea.sim.state", _str(p.get("state"))), ("medcea.cpu_hours", _num(p.get("cpu_hours"))),
                       ("medcea.sim.result_digest", _str(p.get("result_digest"))),
                       ("medcea.sim.cap_h_final", _num(p.get("cap_h"))), ("medcea.sim.reported_by", actor))
                if p.get("state") == "failed":
                    s.status = STATUS_ERROR
                    s.attr(("error.type", "campaign_failed"))
                elif p.get("state") == "done":
                    s.status = STATUS_OK
            else:                            # the other writer's record of the same end (counted once)
                s.event(t, "sim_finished", ("medcea.actor", actor), ("medcea.cpu_hours", _num(p.get("cpu_hours"))))
        elif ev == "session_revoked":
            reason = _str(p.get("reason"))
            r.event(t, "session_revoked", ("medcea.revoke.reason", reason))
            if revoked is None:
                revoked = (t, reason)
        elif ev == "replay_result":
            fm = p.get("first_mismatch") if isinstance(p.get("first_mismatch"), dict) else {}
            r.event(t, "replay_result", ("medcea.replay.ok", p.get("ok") if isinstance(p.get("ok"), bool) else None),
                    ("medcea.replay.events", _num(p.get("events"))), ("medcea.code_commit", _str(p.get("code_commit"))),
                    ("medcea.replay.mismatch.index", _num(fm.get("index"))),
                    ("medcea.replay.mismatch.event", _str(fm.get("event"))),
                    ("medcea.replay.mismatch.field", _str(fm.get("field"))),
                    ("medcea.replay.mismatch.agent", _str(fm.get("agent"))),
                    ("medcea.replay.mismatch.recorded", _str(fm.get("recorded")) if content else None),
                    ("medcea.replay.mismatch.replayed", _str(fm.get("replayed")) if content else None))
        elif ev == "trace_refused":
            r.event(t, "trace_refused", ("medcea.trace_refused.port", _str(p.get("port"))),
                    ("medcea.trace_refused.event", _str(p.get("event"))), ("medcea.reason", _str(p.get("why"))))
        else:
            r.event(t, str(ev or "event"))

    if root is None:            # an empty trace: nothing to export but the resource
        out_spans = []
    else:
        last = st["t"]
        root.name = "invoke_agent " + (profile or "session")
        ends = [x[0] for x in (lead_stop, revoked) if x is not None]
        root.close(min(ends) if ends else last)
        if not ends:
            root.attr(("medcea.incomplete", True))
        root.attr(("gen_ai.operation.name", "invoke_agent"), ("gen_ai.agent.name", profile), ("gen_ai.conversation.id", sid),
                  ("gen_ai.provider.name", _provider(backend, flags_seen, endpoint_kind)), ("medcea.backend", backend),
                  ("medcea.code_commit", code_commit),
                  ("medcea.supervisor.username", _str(session.get("sup_username"))),
                  ("medcea.supervisor.role", _str(session.get("sup_role"))))
        if lead_stop is not None:
            lp = lead_stop[2]
            root.attr(("medcea.stop.reason", lead_stop[1]), ("medcea.turns", _num(lp.get("turns"))),
                      ("gen_ai.usage.input_tokens", _num(lp.get("prompt_tokens"))),
                      ("gen_ai.usage.output_tokens", _num(lp.get("output_tokens"))), ("medcea.cpu_hours", _num(lp.get("cpu_hours"))))
            _status(root, lead_stop[1])
        if revoked is not None:
            root.attr(("medcea.revoke.reason", revoked[1]))
        for s in spans:
            if s.end is None:
                s.close(last)
                s.attr(("medcea.incomplete", True))
        out_spans = [s.otlp(tid) for s in spans]

    resource = _attrs([("service.name", SERVICE), ("medcea.session.id", sid), ("medcea.code_commit", code_commit),
                       ("medcea.trace.chain_head", head), ("medcea.trace.events", len(evs)),
                       ("medcea.export.content", content), ("medcea.export.version", EXPORT_VERSION)])
    return {"resourceSpans": [{
        "resource": {"attributes": resource},
        "scopeSpans": [{"scope": {"name": SCOPE, "version": EXPORT_VERSION}, "spans": out_spans, "schemaUrl": SCHEMA_URL}],
        "schemaUrl": SCHEMA_URL}]}


def dumps(doc):
    """The export as bytes: canonical JSON (sorted keys), so two exports of one trace compare byte for byte."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
