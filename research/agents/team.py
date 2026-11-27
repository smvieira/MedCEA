"""research/agents/team.py (research Phase 4e commit A1b; design 2.1, AH.9, OD-4e-4, OD-4e-5): agent teams.

A profile's `team:` key names its specialists; the lead's model gets the tool team.delegate {specialist, task},
which this module serves inside the agent loop (never an MCP server, never a network call of its own):

  - the specialist runs as a sub-agent a0.N (N = the lead's Nth delegation) through loop.run, **sequentially**:
    the lead waits for it, with the same model client (a scripted team answers each specialist from its own
    script), the same trace client and the same tools;
  - its profile is the lead's narrowed (loop.child_profile: its tools a subset of the lead's, team.delegate never
    among them, so a specialist does not delegate; every cap no larger than the lead's, and the budget caps --
    turns, prompt_tokens, output_tokens, cpu_hours -- no larger than what the lead has left when it delegates);
  - the spend is the session's one budget (OD-4e-5): the specialist's turns, tokens and CPU count against the
    lead's caps too, a campaign's CPU once whoever ran it;
  - agent_spawned {agent, parent, profile_name, profile_sha256, skill_sha256, tools_sha256, caps, task_sha256, task}
    before it and agent_returned {agent, parent, stop_reason, turns, prompt_tokens, output_tokens, cpu_hours,
    result_sha256, result} after it, both on the agent port;
  - the lead gets {agent, specialist, stop_reason, turns, answer (its last text, at most 1000 characters)
    [, cid: the newest campaign handle its tools answered]} as the tool result, wrapped like any other; the
    answer is shortened further until the whole escaped result fits in the SHOWN_MAX characters the lead is shown.

A refused delegation (unknown specialist, a bad task, no budget left) is a refused tool call, never an exception.
Replay (replay.py) runs the same code with the recorded responses, so a team trace replays and a mismatch names the
agent it is in. Parallel specialists are Phase 5c. Stdlib + the agent package."""
import os
import re

from . import context, loop
from .context import canonical, sha
from .model import ScriptedModel

DELEGATE = loop.TEAM_TOOL
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
SPEC_KEYS = ("description", "skill", "tools", "caps", "script", "finish_after", "nudges", "checkpoint_every")
STATIC_CAPS = ("wall_h", "turn_timeout_s", "context_tokens")      # not spent: never above the lead's
SHARED_CAPS = ("turns",) + loop.BUDGET_CAPS                         # spent: never above what the lead has left
MAX_SPECIALISTS = 8
TASK_MAX = 2000
ANSWER_MAX = 1000
RESULT_MAX = 2000                     # agent_returned's `result`, as agent_trace._agent_problem allows
DESCRIPTION_MAX = 200
HANDLE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SKILLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "skills")


def check_profile(p):
    """A team profile's rules (load_profile calls this); ValueError names the first one broken."""
    team, tools = p.get("team"), p["tools"]
    if team is None:
        raise ValueError("profile: %s is served only to a profile with a team" % DELEGATE)
    if not isinstance(team, dict) or not 1 <= len(team) <= MAX_SPECIALISTS:
        raise ValueError("profile: team is a mapping of 1 to %d specialists" % MAX_SPECIALISTS)
    if DELEGATE not in tools:
        raise ValueError("profile: a team profile lists %s among its tools" % DELEGATE)
    for name, s in team.items():
        where = "profile: team.%s" % name
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise ValueError("profile: a specialist's name is lower case letters, digits and _ (%r)" % (name,))
        if not isinstance(s, dict) or set(s) - set(SPEC_KEYS):
            raise ValueError("%s: a mapping of %s" % (where, ", ".join(SPEC_KEYS)))
        if not isinstance(s.get("skill"), str) or not NAME_RE.match(s["skill"]):
            raise ValueError("%s: skill names a file of skills/" % where)
        st = s.get("tools")
        if not isinstance(st, list) or not st or not all(isinstance(t, str) for t in st):
            raise ValueError("%s: tools must be a list of names" % where)
        if DELEGATE in st:
            raise ValueError("%s: a specialist does not delegate (%s)" % (where, DELEGATE))
        if not set(st) <= set(tools):
            raise ValueError("%s: a specialist may not use a tool its lead lacks (%s)"
                             % (where, ", ".join(sorted(set(st) - set(tools)))))
        caps = s.get("caps", {})
        if not isinstance(caps, dict):
            raise ValueError("%s: caps must be a mapping" % where)
        for k, v in caps.items():
            if k not in loop.CAPS:
                raise ValueError("%s: caps.%s is not a cap" % (where, k))
            if not isinstance(v, (int, float)) or isinstance(v, bool) or v <= 0:
                raise ValueError("%s: caps.%s must be a positive number" % (where, k))
            if v > p["caps"][k]:
                raise ValueError("%s: caps.%s may not exceed the lead's (%s)" % (where, k, p["caps"][k]))
        d = s.get("description", "")
        if not isinstance(d, str) or len(d) > DESCRIPTION_MAX:
            raise ValueError("%s: description is at most %d characters" % (where, DESCRIPTION_MAX))
        if p["backend"] == "scripted" and not isinstance(s.get("script"), list):
            raise ValueError("%s: a scripted team gives each specialist a script" % where)
        fa = s.get("finish_after", [])
        if not isinstance(fa, list) or not all(isinstance(t, str) and t in st for t in fa):
            raise ValueError("%s: finish_after must list tools of the specialist" % where)
        n = s.get("nudges", 1)
        if not isinstance(n, int) or isinstance(n, bool) or not 0 <= n <= 3:
            raise ValueError("%s: nudges is a whole number from 0 to 3" % where)
        ce = s.get("checkpoint_every", 0)
        if not isinstance(ce, int) or isinstance(ce, bool) or ce < 0:
            raise ValueError("%s: checkpoint_every is a whole number" % where)


def read_skill(name):
    with open(os.path.join(SKILLS_DIR, name + ".md"), encoding="utf-8") as f:
        return f.read()


def _forward(tools, name, args, meta):
    if meta is not None and getattr(tools, "accepts_meta", False):
        return tools.call(name, args, meta=meta)
    return tools.call(name, args)


def _shown_len(result):
    """-> (length of the result as the lead is shown it, before the cut; its canonical text)"""
    t = canonical(result).decode("utf-8")
    return len(t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")), t


class _Seen:
    """A specialist's tools: the lead's, listed once, noting the newest campaign handle a result showed."""
    def __init__(self, tools, listing):
        self.tools, self.listing, self.cid = tools, listing, None
        self.accepts_meta = getattr(tools, "accepts_meta", False)

    def list_tools(self):
        return list(self.listing)

    def call(self, name, args, meta=None):
        r = _forward(self.tools, name, args, meta)
        if isinstance(r, dict) and isinstance(r.get("cid"), str) and HANDLE_RE.match(r["cid"]):
            self.cid = r["cid"]
        return r


class Team:
    """The lead's tools plus team.delegate. loop.run builds it for a profile with a team; `caps` are the lead's
    effective caps, `remaining()` what the lead may still spend of prompt_tokens, output_tokens and cpu_hours,
    `deadline` the clock value the lead's wall_h ends at."""
    accepts_meta = True       # the lead's other calls go on to the tools with their (agent, call) key

    def __init__(self, profile, tools, trace, model, standing, agent, caps, shared, remaining, deadline, clock,
                 backend, skills=None):
        self.profile, self.team, self.tools, self.trace = profile, profile["team"], tools, trace
        self.model, self.standing, self.agent, self.caps = model, standing, agent, caps
        self.shared, self.remaining, self.deadline, self.clock = shared, remaining, deadline, clock
        self.backend, self.skills = backend, skills or read_skill
        self.n, self._inner = 0, None

    def inner(self):
        if self._inner is None:
            self._inner = list(self.tools.list_tools())
        return self._inner

    def entry(self):
        names = sorted(self.team)
        who = "; ".join("%s: %s" % (n, self.team[n].get("description") or "a specialist") for n in names)
        return {"name": DELEGATE,
                "description": ("Hand one task to a specialist of your team and wait for its answer (it runs with its "
                                "own skill and a part of this session's budget). Specialists: " + who),
                "inputSchema": {"type": "object", "additionalProperties": False, "required": ["specialist", "task"],
                                "properties": {"specialist": {"type": "string", "enum": names},
                                               "task": {"type": "string", "minLength": 1, "maxLength": TASK_MAX}}}}

    def list_tools(self):
        return self.inner() + [self.entry()]

    def call(self, name, args, meta=None):
        if name != DELEGATE:
            return _forward(self.tools, name, args, meta)
        return self.delegate(args)

    def _child_caps(self, s):
        left = self.remaining()
        caps = {}
        for k in STATIC_CAPS:
            caps[k] = min(s.get("caps", {}).get(k, self.caps[k]), self.caps[k])
        for k in SHARED_CAPS:
            if left[k] <= 0:
                raise loop.ToolError("the session has no %s left for a specialist" % k)
            v = min(s.get("caps", {}).get(k, self.caps[k]), left[k])
            caps[k] = round(v, 6) if isinstance(v, float) else v
            if caps[k] <= 0:
                raise loop.ToolError("the session has no %s left for a specialist" % k)
        if "reserve_tokens" in self.caps:
            caps["reserve_tokens"] = min(self.caps["reserve_tokens"], caps["context_tokens"] - 1)
        return caps

    def delegate(self, args):
        names = sorted(self.team)
        if (not isinstance(args, dict) or set(args) != {"specialist", "task"} or args.get("specialist") not in self.team
                or not isinstance(args.get("task"), str) or not 0 < len(args["task"]) <= TASK_MAX):
            raise loop.ToolError("%s takes {specialist, task}: specialist one of %s, task 1 to %d characters"
                                 % (DELEGATE, ", ".join(names), TASK_MAX))
        name, task = args["specialist"], args["task"]
        s = self.team[name]
        child_id = "%s.%d" % (self.agent, self.n + 1)
        if not loop.agent_ok(child_id, self.agent):
            raise loop.ToolError("no more specialists in this session (agent ids end at %s)" % self.agent)
        caps = self._child_caps(s)
        lead = dict(self.profile, caps=dict(self.caps))
        narrowed = loop.child_profile(lead, {"tools": s["tools"], "caps": caps})       # never wider than the lead
        child = {"name": name, "backend": narrowed["backend"], "skill": s["skill"], "tools": narrowed["tools"],
                 "caps": narrowed["caps"], "task": task,
                 "checkpoint_every": s.get("checkpoint_every", self.profile.get("checkpoint_every", 4))}
        for k in ("script", "finish_after", "nudges"):
            if k in s:
                child[k] = s[k]
        try:
            skill = self.skills(s["skill"])
        except OSError:
            raise loop.ToolError("the skill of specialist %s is missing" % name)
        self.n += 1
        listed = {t["name"]: t for t in self.inner()}
        spec = loop.tool_spec(child["tools"], listed, loop.through_gateway(child))
        self.trace.post("agent_spawned", {
            "agent": child_id, "parent": self.agent, "profile_name": name, "profile_sha256": sha(canonical(child)),
            "skill_sha256": sha(skill), "tools_sha256": sha(canonical(spec)), "caps": child["caps"],
            "task_sha256": sha(task), "task": task})
        scripted = child["backend"] == "scripted"
        # a scripted team answers each specialist from its own script; any other model (the gateway's, replay's)
        # serves every agent and is told which one asks
        model = ScriptedModel(s["script"]) if isinstance(self.model, ScriptedModel) else self.model
        backend = ScriptedModel(s["script"]).id if scripted else self.backend
        tools = _Seen(self.tools, self.inner())
        report = {}
        reason = loop.run(child, self.standing, skill, model, tools, self.trace, clock=self.clock, backend_id=backend,
                          agent=child_id, parent=self.agent, shared=self.shared, deadline=self.deadline,
                          report=report, skills=self.skills)
        result = {"agent": child_id, "specialist": name, "stop_reason": reason, "turns": report.get("turns", 0),
                  "answer": str(report.get("answer", ""))[:ANSWER_MAX]}
        if tools.cid:
            result["cid"] = tools.cid
        # the lead is shown SHOWN_MAX characters of the escaped result: shorten the answer until the whole result
        # fits, so the cid, specialist, stop_reason and turns (sorted after "answer") always reach it
        n, text = _shown_len(result)
        while n > context.SHOWN_MAX and result["answer"]:
            result["answer"] = result["answer"][:max(0, len(result["answer"]) - (n - context.SHOWN_MAX) - 1)]
            n, text = _shown_len(result)
        o = report.get("spent") or {}
        self.trace.post("agent_returned", {
            "agent": child_id, "parent": self.agent, "stop_reason": reason, "turns": report.get("turns", 0),
            "prompt_tokens": o.get("prompt_tokens", 0), "output_tokens": o.get("output_tokens", 0),
            "cpu_hours": round(o.get("cpu_hours", 0.0), 6), "result_sha256": sha(text), "result": text[:RESULT_MAX]})
        return result
