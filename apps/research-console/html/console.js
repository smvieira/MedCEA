/* apps/research-console/html/console.js — the research console's page (research Phase 4e,
   codeplan/rs4e-design.md §4).

   Served by console.py from ConfigMap research-console-html under a strict CSP: no inline script
   or style, no eval. Every string that comes from a trace (model output, tool results, task texts,
   notes) is untrusted and reaches the page only through textContent, an attribute set with
   setAttribute, Cytoscape's canvas labels or esc(); innerHTML is never used.

   The pure part sits between the console-logic markers below: no DOM, no fetch, no clock of its
   own. tests/test_research_console_ui.py runs it under node and checks it against the servers'
   own code (the trace's port events, mcp_sim's tables, replay, compare_turns, the start rule). */

/* console-logic:begin */
'use strict';

// ── constants mirrored from the servers (each pinned by a parity test)
const LEAD = 'a0';                                       // research/agents/loop.py LEAD
const AGENT_RE = /^a0(\.[1-9][0-9]{0,2}){0,3}$/;          // agent_trace._agent_problem's v_re
const CONTEXT_MARGIN = 96;                               // research/agents/loop.py CONTEXT_MARGIN
const MAX_CAMPAIGN_H = 24;                               // mcp_sim.MAX_CAMPAIGN_H
const CAP_FACTOR = 1.25;                                 // mcp_sim: cap = 1.25 × estimate + calibration
const SHOWN_MAX = 1000;                                  // research/agents/context.py SHOWN_MAX
const RECORD_MAX = 6000;                                 // research/agents/loop.py RECORD_MAX
const EVENTS_PAGE = 1000;                                // agent_trace.events() LIMIT
const EVENTS_CAP = 100000;                               // the replay's and session.py's cap
const BUDGET_KEYS = ['turns', 'prompt_tokens', 'output_tokens', 'cpu_hours'];   // orchestrator.BUDGET_KEYS
const LOOP_METRICS = ['rmsd_mid', 'out_of_band', 'boundary_hugging'];          // mcp_sim.LOOP_METRICS
const TOOL_SERVER = {lake: 'mcp-lake', sim: 'mcp-sim', propose: 'mcp-sim'};    // session.TOOL_SERVER
const TEAM_TOOL = 'team.delegate';                       // research/agents/loop.py TEAM_TOOL
const AGENT_EVENTS = ['turn_request', 'turn_response', 'tool_call', 'tool_result', 'checkpoint', 'proposal', 'stop',
                      'agent_spawned', 'agent_returned'];                        // research/agents/replay.py AGENT
const SERVERS = ['model-gateway', 'mcp-sim', 'mcp-lake', 'orchestrator'];
const STATUS_TOOL = 'sim.status';

// Live updates (design §3.3): one long-poll at a time, wait ≤ 20 s; a plain poll every 3 s after two
// long-poll failures; every 15 s for 2 minutes after the session stops; backoff on error.
const POLL = {LONG_WAIT_S: 20, PLAIN_MS: 3000, TAIL_MS: 15000, TAIL_FOR_MS: 120000, BACKOFF_MS: 1000,
              BACKOFF_MAX_MS: 30000, LONG_FAILS: 2, QUICK_MS: 1000};

// Every event the trace may hold (agent_trace._port_events, plus trace_refused, which the database writes).
const EVENT_KINDS = {
  session_minted:   {ports: ['person'], label: 'Session started'},
  claim_exchanged:  {ports: ['person'], label: 'Agent signed in'},
  claim_reused:     {ports: ['person'], label: 'Claim used twice: session revoked'},
  gate_decided:     {ports: ['person'], label: 'Gate decided'},
  proposal_decided: {ports: ['person'], label: 'Proposal decided'},
  session_revoked:  {ports: ['person'], label: 'Session ended'},
  turn_request:     {ports: ['agent', 'server'], label: 'Model asked'},
  turn_response:    {ports: ['agent', 'server'], label: 'Model answered'},
  tool_call:        {ports: ['agent'], label: 'Tool called'},
  tool_result:      {ports: ['agent', 'server'], label: 'Tool result'},
  checkpoint:       {ports: ['agent'], label: 'Checkpoint'},
  proposal:         {ports: ['agent'], label: 'Proposal'},
  stop:             {ports: ['agent'], label: 'Agent stopped'},
  agent_spawned:    {ports: ['agent'], label: 'Specialist started'},
  agent_returned:   {ports: ['agent'], label: 'Specialist returned'},
  gate_pending:     {ports: ['server'], label: 'Gate: waiting for the supervisor'},
  sim_started:      {ports: ['server'], label: 'Campaign started'},
  sim_finished:     {ports: ['server'], label: 'Campaign finished'},
  replay_result:    {ports: ['server'], label: 'Replay verdict'},
  trace_refused:    {ports: ['database'], label: 'A trace write was refused'},
};

// The orchestrator's person API as the page calls it (every path is in its route table since the access policy
// version that brings the console, research Phase 4e commit B; the page still copes with a 404 from an older one).
const API = {
  me:        {method: 'GET',  path: '/api/me'},
  profiles:  {method: 'GET',  path: '/api/profiles'},
  sessions:  {method: 'GET',  path: '/api/sessions'},
  start:     {method: 'POST', path: '/api/sessions'},
  session:   {method: 'GET',  path: '/api/sessions/<sid>'},
  events:    {method: 'GET',  path: '/api/sessions/<sid>/events'},
  stop:      {method: 'POST', path: '/api/sessions/<sid>/stop'},
  replay:    {method: 'POST', path: '/api/sessions/<sid>/replay'},
  gate:      {method: 'POST', path: '/api/sessions/<sid>/gates/<gid>'},
  proposal:  {method: 'POST', path: '/api/sessions/<sid>/proposals/<pid>'},
  reexecute: {method: 'POST', path: '/api/sessions/<sid>/reexecute'},
  campaign:  {method: 'GET',  path: '/api/sessions/<sid>/campaigns/<cid>'},
  run:       {method: 'GET',  path: '/api/sessions/<sid>/campaigns/<cid>/runs/<n>'},
  series:    {method: 'GET',  path: '/api/sessions/<sid>/campaigns/<cid>/runs/<n>/series'},
  otel:      {method: 'GET',  path: '/api/sessions/<sid>/otel'},
};

const SID_RE = /^[A-Za-z0-9_-]{22}$/;
const XID_RE = /^[A-Za-z0-9_.-]{1,40}$/;

// ── small helpers
function esc(s) {
  return String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g,
    (c) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
}
function isObj(x) { return x !== null && typeof x === 'object' && !Array.isArray(x); }
function isNum(x) { return typeof x === 'number' && isFinite(x); }
function isInt(x) { return typeof x === 'number' && Number.isInteger(x); }
function clone(x) { return x === undefined ? undefined : JSON.parse(JSON.stringify(x)); }
function canonical(x) {          // sorted keys, no spaces: the servers' canonical JSON
  if (Array.isArray(x)) return '[' + x.map(canonical).join(',') + ']';
  if (isObj(x)) return '{' + Object.keys(x).sort().map((k) => JSON.stringify(k) + ':' + canonical(x[k])).join(',') + '}';
  return JSON.stringify(x === undefined ? null : x);
}
function short(s, n) {
  const t = String(s === null || s === undefined ? '' : s).replace(/\s+/g, ' ').trim();
  return t.length <= n ? t : t.slice(0, n - 1) + '…';
}
function fmt(v, digits) {
  if (!isNum(v)) return v === null || v === undefined ? '–' : String(v);
  const d = digits === undefined ? 4 : digits;
  return Number(v.toPrecision(d)).toString();
}
function parseAt(s) {            // an event's ISO 8601 time -> epoch milliseconds (microseconds kept), or null
  if (typeof s !== 'string') return null;
  const m = /^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d(?::?\d\d)?)?$/.exec(s.trim());
  if (!m) return null;
  let ms = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  if (m[7]) ms += Number('0.' + m[7]) * 1000;
  if (m[8] && m[8] !== 'Z') {
    const sign = m[8][0] === '-' ? -1 : 1;
    const hh = +m[8].slice(1, 3), mm = m[8].length > 3 ? +m[8].slice(-2) : 0;
    ms -= sign * (hh * 60 + mm) * 60000;
  }
  return ms;
}
function agentOf(p) {
  return isObj(p) && typeof p.agent === 'string' && AGENT_RE.test(p.agent) ? p.agent : LEAD;
}
function parentOf(id) { return id === LEAD ? null : id.slice(0, id.lastIndexOf('.')); }
function serverOfTool(tool) {
  if (typeof tool !== 'string') return null;
  return TOOL_SERVER[tool.split('.')[0]] || null;
}
function kindOf(ev) {
  return EVENT_KINDS[ev] || {ports: [], label: short(ev, 40), unknown: true};
}
function parseJsonText(t) {
  if (typeof t !== 'string' || t.length > RECORD_MAX) return null;
  try { return JSON.parse(t); } catch (e) { return null; }
}
function pathOf(name, ids) {     // API[name].path with <sid> <gid> <pid> <cid> <n> filled (each checked)
  let p = API[name].path;
  for (const k of Object.keys(ids || {})) {
    const v = String(ids[k]);
    if (!/^[A-Za-z0-9_.-]{1,64}$/.test(v)) throw new Error('bad id');
    p = p.replace('<' + k + '>', encodeURIComponent(v));
  }
  if (/<[a-z]+>/.test(p)) throw new Error('missing id');
  return p;
}

// ── the trace folded into a model (incremental: foldEvents(b, foldEvents(a)) = foldEvents(a + b))
function newAgent(id, parent) {
  return {id: id, parent: parent, profile: null, task: null, state: 'running', stop_reason: null, turns: 0, calls: 0,
          spawned: null, returned: null, answer: null, prompt_tokens: 0, output_tokens: 0, stopped_at: null};
}
function emptyModel() {
  return {v: 1, last: 0, n: 0, t0: null, t1: null, mint: null, claimed: null, agents: {a0: newAgent(LEAD, null)},
          order: [LEAD], turns: {}, calls: {}, open: [], records: [], servers: {}, campaigns: {}, proposals: {},
          markers: [], stop: null, revoked: null, replays: [], refused: [], unknown: 0};
}
function ensureAgent(m, id) {
  if (!m.agents[id]) {
    const parent = parentOf(id);
    if (parent) ensureAgent(m, parent);
    m.agents[id] = newAgent(id, parent);
    m.order.push(id);
  }
  return m.agents[id];
}
function ensureCampaign(m, cid) {
  if (!m.campaigns[cid]) {
    m.campaigns[cid] = {cid: cid, gid: null, agent: null, call: null, estimate_h: null, cap_h: null, runs: null,
                        spec_sha256: null, gate: null, gate_at: null, gate_id: null, decided_at: null, decided_id: null,
                        decided_by: null, note: null, approved_cap_h: null, started_at: null, started_id: null,
                        finished_at: null, finished_id: null, state: 'pending', cpu_hours: null, result_digest: null,
                        writers: [], by_setting: null};
  }
  return m.campaigns[cid];
}
function innermostCall(m) {
  for (let i = m.open.length - 1; i >= 0; i--) {
    const c = m.calls[m.open[i]];
    if (c && c.tool !== TEAM_TOOL) return c;
  }
  return null;
}
function mark(m, lane, kind, e, text) {
  m.markers.push({lane: lane, kind: kind, at: parseAt(e.at), id: e.event_id, text: short(text, 160)});
}

function foldStep(m, e) {
  const p = isObj(e.payload) ? e.payload : {};
  const at = parseAt(e.at);
  const ev = e.event, actor = String(e.actor || '');
  m.last = e.event_id;
  m.n += 1;
  if (at !== null) {
    if (m.t0 === null || at < m.t0) m.t0 = at;
    if (m.t1 === null || at > m.t1) m.t1 = at;
  }
  const ag = agentOf(p);
  if (AGENT_EVENTS.indexOf(ev) >= 0 || (ev === 'tool_result' && actor !== 'agent')) ensureAgent(m, ag);
  switch (ev) {
    case 'session_minted':
      m.mint = {profile: p.profile || null, backend: p.backend || null, code_commit: p.code_commit || null,
                exp: p.exp || null, reexecutes: p.reexecutes || null, at: at, id: e.event_id};
      mark(m, 'supervisor', 'minted', e, 'session started: ' + (p.profile || '') + ' on ' + (p.backend || ''));
      break;
    case 'claim_exchanged':
      m.claimed = {at: at, id: e.event_id};
      mark(m, 'supervisor', 'claim', e, 'the agent signed in');
      break;
    case 'claim_reused':
      mark(m, 'supervisor', 'refused', e, 'the claim was used twice: the session is revoked');
      break;
    case 'turn_request': {
      const key = ag + '#' + p.turn;
      const t = m.turns[key] || (m.turns[key] = {agent: ag, turn: p.turn, gw: false, req_at: null, req_id: null,
        resp_at: null, resp_id: null, request_sha256: null, response_sha256: null, model: null, usage: null,
        cache_n: null, error: null, tool: null, says: null});
      if (actor === 'model-gateway') t.gw = true;
      if (t.req_id === null) { t.req_at = at; t.req_id = e.event_id; }
      t.request_sha256 = p.request_sha256 || t.request_sha256;
      t.model = p.model || p.backend || t.model;
      if (isInt(p.turn) && p.turn > m.agents[ag].turns) m.agents[ag].turns = p.turn;
      break;
    }
    case 'turn_response': {
      const key = ag + '#' + p.turn;
      const t = m.turns[key] || (m.turns[key] = {agent: ag, turn: p.turn, gw: actor === 'model-gateway', req_at: null,
        req_id: null, resp_at: null, resp_id: null, request_sha256: null, response_sha256: null, model: null,
        usage: null, cache_n: null, error: null, tool: null, says: null});
      t.resp_at = at; t.resp_id = e.event_id;
      t.response_sha256 = p.response_sha256 || null;
      t.usage = isObj(p.usage) ? p.usage : null;
      t.cache_n = isObj(p.usage) && isInt(p.usage.cache_n) ? p.usage.cache_n : (isInt(p.cache_n) ? p.cache_n : null);   // the gateway puts it in usage
      t.error = p.error ? short(p.error, 120) : null;
      const r = isObj(p.response) ? p.response : {};
      t.tool = isObj(r.tool) && typeof r.tool.name === 'string' ? r.tool.name : null;
      t.says = typeof r.text === 'string' ? short(r.text, 200) : null;
      const u = t.usage || {};
      if (isNum(u.prompt_tokens)) m.agents[ag].prompt_tokens += u.prompt_tokens;
      if (isNum(u.output_tokens)) m.agents[ag].output_tokens += u.output_tokens;
      if (isInt(p.turn) && p.turn > m.agents[ag].turns) m.agents[ag].turns = p.turn;
      break;
    }
    case 'tool_call': {
      const key = ag + '#' + p.call;
      m.calls[key] = {agent: ag, call: p.call, turn: isInt(p.turn) ? p.turn : null, tool: String(p.tool || ''),
                      args: isObj(p.args) ? p.args : null, at: at, id: e.event_id, res_at: null, res_id: null,
                      error: null, refusal: null, bytes: null, truncated: null, result_sha256: null,
                      shown_sha256: null, recorded_complete: null, cid: null, server: [], proposal: null,
                      proposal_sha256: null, by_setting: null, child: null};
      if (m.calls[key].args && typeof m.calls[key].args.cid === 'string') m.calls[key].cid = m.calls[key].args.cid;
      m.agents[ag].calls += 1;
      m.open.push(key);
      break;
    }
    case 'tool_result': {
      if (actor === 'agent') {
        const key = ag + '#' + p.call;
        const c = m.calls[key] || (m.calls[key] = {agent: ag, call: p.call, turn: null, tool: String(p.tool || ''),
          args: null, at: at, id: e.event_id, res_at: null, res_id: null, error: null, refusal: null, bytes: null,
          truncated: null, result_sha256: null, shown_sha256: null, recorded_complete: null, cid: null, server: [],
          proposal: null, proposal_sha256: null, by_setting: null, child: null});
        c.res_at = at; c.res_id = e.event_id;
        c.error = !!p.error;
        c.bytes = isInt(p.bytes) ? p.bytes : null;
        c.truncated = !!p.truncated;
        c.result_sha256 = p.result_sha256 || null;
        c.shown_sha256 = p.shown_sha256 || null;
        c.recorded_complete = p.recorded_complete === true;
        const obj = parseJsonText(p.result);
        if (isObj(obj)) {
          if (typeof obj.cid === 'string') c.cid = obj.cid;
          if (Object.keys(obj).length === 1 && typeof obj.error === 'string') c.refusal = short(obj.error, 300);
          if (isObj(obj.proposal)) { c.proposal = obj.proposal; c.proposal_sha256 = obj.proposal_sha256 || null; }
          if (isObj(obj.by_setting)) {
            c.by_setting = obj.by_setting;
            if (c.cid) ensureCampaign(m, c.cid).by_setting = obj.by_setting;
          }
          if (c.tool === TEAM_TOOL && typeof obj.agent === 'string') c.child = obj.agent;
        }
        const i = m.open.lastIndexOf(key);
        if (i >= 0) m.open.splice(i, 1);
      } else {
        const s = m.servers[actor] || (m.servers[actor] = {count: 0, agents: {}});
        s.count += 1;
        const sa = s.agents[ag] || (s.agents[ag] = {count: 0, tools: {}});
        sa.count += 1;
        const tool = String(p.tool || '');
        sa.tools[tool] = (sa.tools[tool] || 0) + 1;
        let target = null;
        if (isInt(p.agent_call)) target = m.calls[ag + '#' + p.agent_call] || null;
        if (!target) target = innermostCall(m);
        if (target) target.server.push(e.event_id);
        m.records.push({actor: actor, agent: ag, tool: tool, at: at, id: e.event_id, error: !!p.error,
                        result_sha256: p.result_sha256 || null, call: target ? target.agent + '#' + target.call : null});
      }
      break;
    }
    case 'gate_pending': {
      const c = ensureCampaign(m, String(p.gid || ''));
      c.gid = p.gid || null;
      c.estimate_h = isNum(p.estimate_h) ? p.estimate_h : c.estimate_h;
      c.cap_h = isNum(p.cap_h) ? p.cap_h : c.cap_h;
      c.runs = isInt(p.runs) ? p.runs : c.runs;
      c.spec_sha256 = p.spec_sha256 || c.spec_sha256;
      c.gate = 'pending'; c.gate_at = at; c.gate_id = e.event_id;
      const call = innermostCall(m);
      if (call && !c.agent) { c.agent = call.agent; c.call = call.call; call.cid = call.cid || c.cid; }
      break;
    }
    case 'gate_decided': {
      const c = ensureCampaign(m, String(p.gid || ''));
      c.gate = p.decision === 'approve' ? 'approved' : 'denied';
      c.decided_at = at; c.decided_id = e.event_id;
      c.decided_by = p.by_username || null;
      c.note = typeof p.note === 'string' ? p.note : null;
      c.approved_cap_h = isNum(p.approved_cap_h) ? p.approved_cap_h : null;
      if (c.gate === 'denied') c.state = 'denied';
      mark(m, 'supervisor', c.gate === 'approved' ? 'approve' : 'deny', e, 'gate ' + c.cid + ' ' + c.gate);
      break;
    }
    case 'sim_started': {
      const c = ensureCampaign(m, String(p.cid || ''));
      if (c.started_id === null) { c.started_at = at; c.started_id = e.event_id; }
      c.state = 'running';
      if (isNum(p.estimate_h)) c.estimate_h = p.estimate_h;
      if (isNum(p.cap_h)) c.cap_h = p.cap_h;
      c.spec_sha256 = p.spec_sha256 || c.spec_sha256;
      const call = innermostCall(m);
      if (call && !c.agent) { c.agent = call.agent; c.call = call.call; call.cid = call.cid || c.cid; }
      break;
    }
    case 'sim_finished': {
      const c = ensureCampaign(m, String(p.cid || ''));
      if (c.writers.indexOf(actor) < 0) c.writers.push(actor);
      if (c.finished_id === null) {           // counted once, whichever writer came first (design 2.2)
        c.finished_at = at; c.finished_id = e.event_id;
        c.state = typeof p.state === 'string' ? p.state : 'done';
        c.cpu_hours = isNum(p.cpu_hours) ? p.cpu_hours : null;
        c.result_digest = p.result_digest || null;
      }
      if (actor === 'orchestrator') mark(m, 'server:orchestrator', 'finished', e, 'campaign ' + c.cid + ' ' + c.state);
      break;
    }
    case 'proposal': {
      const pid = 'p' + e.event_id;
      const call = m.calls[ag + '#' + p.call] || null;
      m.proposals[pid] = {pid: pid, id: e.event_id, at: at, agent: ag, call: isInt(p.call) ? p.call : null,
                          tool: String(p.tool || ''), result_sha256: p.result_sha256 || null,
                          doc: call ? call.proposal : null, decided: null};
      mark(m, 'agent:' + ag, 'proposal', e, 'proposal ' + pid);
      break;
    }
    case 'proposal_decided': {
      const named = String(p.pid || '');
      let hit = m.proposals[named] || null;
      if (!hit && /^[0-9a-f]{6,64}$/.test(named)) {         // an older CLI named it by a digest prefix
        for (const k of Object.keys(m.proposals)) {
          if (String(m.proposals[k].result_sha256 || '').indexOf(named) === 0) { hit = m.proposals[k]; break; }
        }
      }
      if (hit) hit.decided = {decision: p.decision || null, by: p.by_username || null, note: p.note || '', at: at,
                              id: e.event_id};
      mark(m, 'supervisor', p.decision === 'approve' ? 'approve' : 'deny',
           e, 'proposal ' + named + (p.decision === 'approve' ? ' accepted' : ' discarded'));
      break;
    }
    case 'checkpoint':
      mark(m, 'agent:' + ag, 'checkpoint', e, 'checkpoint after turn ' + p.turn);
      break;
    case 'stop': {
      const a = m.agents[ag];
      a.state = 'stopped'; a.stop_reason = p.reason || null; a.stopped_at = at;
      if (ag === LEAD) m.stop = {reason: p.reason || null, turns: p.turns, at: at, id: e.event_id};
      mark(m, 'agent:' + ag, 'stop', e, 'stopped: ' + (p.reason || ''));
      break;
    }
    case 'agent_spawned': {
      const a = m.agents[ag];
      a.profile = p.profile_name || null;
      a.task = typeof p.task === 'string' ? p.task : null;
      a.spawned = {at: at, id: e.event_id};
      mark(m, 'agent:' + ag, 'spawned', e, 'started by ' + (a.parent || '') + ': ' + short(a.task, 80));
      break;
    }
    case 'agent_returned': {
      const a = m.agents[ag];
      a.returned = {at: at, id: e.event_id, stop_reason: p.stop_reason || null, turns: p.turns, cpu_hours: p.cpu_hours};
      a.state = 'stopped';
      if (!a.stop_reason) a.stop_reason = p.stop_reason || null;
      const obj = parseJsonText(p.result);
      a.answer = isObj(obj) && typeof obj.answer === 'string' ? short(obj.answer, 300) : null;
      mark(m, 'agent:' + (a.parent || LEAD), 'returned', e, a.id + ' returned: ' + (p.stop_reason || ''));
      break;
    }
    case 'session_revoked':
      m.revoked = {reason: p.reason || null, at: at, id: e.event_id};
      for (const id of m.order) {
        const a = m.agents[id];
        if (a.state !== 'stopped') { a.state = 'stopped'; a.stop_reason = a.stop_reason || 'revoked'; }
      }
      mark(m, 'supervisor', 'revoked', e, 'session ended: ' + (p.reason || ''));
      break;
    case 'replay_result':
      m.replays.push({ok: !!p.ok, events: p.events, first_mismatch: isObj(p.first_mismatch) ? p.first_mismatch : null,
                      code_commit: p.code_commit || null, at: at, id: e.event_id});
      mark(m, SERVERS.indexOf(actor) >= 0 ? 'server:' + actor : 'supervisor', 'replay', e,
           'replay ' + (p.ok ? 'matches' : 'differs'));
      break;
    case 'trace_refused':
      m.refused.push({port: p.port || null, event: p.event || null, why: short(p.why, 200), at: at, id: e.event_id});
      mark(m, 'supervisor', 'refused', e, 'refused: ' + short(p.why, 120));
      break;
    default:
      m.unknown += 1;
  }
}

function foldEvents(events, prior) {
  const m = prior ? clone(prior) : emptyModel();
  const list = (Array.isArray(events) ? events : []).filter((e) => isObj(e) && isInt(e.event_id))
    .slice().sort((a, b) => a.event_id - b.event_id);
  for (const e of list) {
    if (e.event_id <= m.last) continue;      // a long-poll may overlap the last page
    foldStep(m, e);
  }
  return m;
}

function agentState(m, id) {
  const a = m.agents[id];
  if (!a) return 'unknown';
  if (a.state === 'stopped' || m.revoked) return 'stopped';
  for (const cid of Object.keys(m.campaigns)) {
    const c = m.campaigns[cid];
    if (c.gate === 'pending' && c.agent === id) return 'waiting';
  }
  return 'running';
}

// The agents in depth-first order (a0, a0.1, a0.1.1, a0.2 …) with their depth: the lane order.
function layoutTree(m) {
  const kids = {};
  for (const id of m.order) {
    const p = m.agents[id].parent;
    if (p) (kids[p] = kids[p] || []).push(id);
  }
  const num = (id) => +id.slice(id.lastIndexOf('.') + 1);
  const out = [];
  const walk = (id, depth) => {
    out.push({id: id, depth: depth, parent: m.agents[id].parent});
    for (const k of (kids[id] || []).slice().sort((a, b) => num(a) - num(b))) walk(k, depth + 1);
  };
  walk(LEAD, 0);
  return out;
}
function agentTree(m) {
  const node = (id) => ({id: id, profile: m.agents[id].profile, state: agentState(m, id),
                         children: layoutTree(m).filter((x) => x.parent === id).map((x) => node(x.id))});
  return node(LEAD);
}

// The agent graph as Cytoscape elements: one node per agent (lead and specialists) and per tool
// server used, delegation edges (parent -> child, the task's first 80 characters) and tool-use edges
// (agent -> server, the number of calls; agent -> model-gateway, the number of turns). Labels are data:
// Cytoscape draws them as canvas text, never HTML.
function graphElements(input) {
  const m = Array.isArray(input) ? foldEvents(input) : input;
  const nodes = [], edges = [];
  for (const x of layoutTree(m)) {
    const a = m.agents[x.id], st = agentState(m, x.id);
    const label = x.id === LEAD ? 'a0 lead' + (m.mint && m.mint.profile ? '\n' + m.mint.profile : '')
                                : x.id + '\n' + (a.profile || 'specialist');
    nodes.push({group: 'nodes', data: {id: 'agent:' + x.id, label: label, kind: 'agent', agent: x.id, state: st,
                                       turns: a.turns, calls: a.calls}, classes: 'agent ' + st});
    if (a.parent) {
      edges.push({group: 'edges', data: {id: 'delegate:' + x.id, source: 'agent:' + a.parent, target: 'agent:' + x.id,
                                         kind: 'delegate', label: short(a.task || '', 80)}, classes: 'delegate'});
    }
  }
  const use = {};
  const add = (srv, ag, n) => { (use[srv] = use[srv] || {})[ag] = ((use[srv] || {})[ag] || 0) + n; };
  for (const k of Object.keys(m.calls)) {
    const c = m.calls[k];
    const srv = c.tool === TEAM_TOOL ? null : serverOfTool(c.tool);
    if (srv) add(srv, c.agent, 1);
  }
  for (const k of Object.keys(m.turns)) if (m.turns[k].gw) add('model-gateway', m.turns[k].agent, 1);
  for (const srv of SERVERS) {
    if (!use[srv]) continue;
    let total = 0;
    for (const ag of Object.keys(use[srv])) total += use[srv][ag];
    nodes.push({group: 'nodes', data: {id: 'server:' + srv, label: srv, kind: 'server', calls: total},
                classes: 'server'});
    for (const x of layoutTree(m)) {
      const n = use[srv][x.id];
      if (!n) continue;
      const unit = srv === 'model-gateway' ? (n === 1 ? ' turn' : ' turns') : (n === 1 ? ' call' : ' calls');
      edges.push({group: 'edges', data: {id: 'use:' + x.id + '>' + srv, source: 'agent:' + x.id,
                                         target: 'server:' + srv, kind: 'use', count: n, label: n + unit},
                  classes: 'use'});
    }
  }
  return {nodes: nodes, edges: edges};
}

// Swimlanes: one lane per agent (depth-first), the supervisor, then each server actor that wrote.
// Spans: turn (request -> response), tool (call -> the agent's result; a run of sim.status checks on
// one campaign folds into one "waiting" span with its count), campaign (sim_started -> sim_finished),
// gate (gate_pending -> gate_decided). Open spans end at `now`. Markers for the rest.
function lanes(m, now) {
  const end = isNum(now) ? now : m.t1;
  const L = [];
  for (const x of layoutTree(m)) {
    const a = m.agents[x.id];
    L.push({id: 'agent:' + x.id, kind: 'agent', agent: x.id, depth: x.depth,
            label: x.id === LEAD ? 'a0 lead' : x.id + (a.profile ? ' ' + a.profile : '')});
  }
  L.push({id: 'supervisor', kind: 'supervisor', depth: 0, label: 'Supervisor'});
  const used = {};
  for (const r of m.records) used[r.actor] = true;
  for (const k of Object.keys(m.turns)) if (m.turns[k].gw) used['model-gateway'] = true;
  for (const cid of Object.keys(m.campaigns)) if (m.campaigns[cid].started_at !== null) used['mcp-sim'] = true;
  for (const mk of m.markers) if (mk.lane.indexOf('server:') === 0) used[mk.lane.slice(7)] = true;
  for (const s of SERVERS) if (used[s]) L.push({id: 'server:' + s, kind: 'server', depth: 0, label: s});
  const spans = [], marks = [];
  const tkeys = Object.keys(m.turns).sort((a, b) => (m.turns[a].req_id || m.turns[a].resp_id || 0) -
                                                    (m.turns[b].req_id || m.turns[b].resp_id || 0));
  for (const k of tkeys) {
    const t = m.turns[k];
    const start = t.req_at !== null ? t.req_at : t.resp_at;
    if (start === null) continue;
    const open = t.resp_at === null;
    const span = {lane: 'agent:' + t.agent, kind: 'turn', start: start, end: open ? end : t.resp_at, open: open,
                  id: t.req_id || t.resp_id, label: 'turn ' + t.turn + (t.tool ? ' → ' + t.tool : ''),
                  error: !!t.error};
    spans.push(span);
    if (t.gw) spans.push(Object.assign({}, span, {lane: 'server:model-gateway', label: t.agent + ' turn ' + t.turn}));
  }
  const byAgent = {};
  for (const k of Object.keys(m.calls)) (byAgent[m.calls[k].agent] = byAgent[m.calls[k].agent] || []).push(m.calls[k]);
  for (const ag of Object.keys(byAgent)) {
    let prev = null;
    for (const c of byAgent[ag].slice().sort((a, b) => a.id - b.id)) {
      if (c.at === null) continue;
      const open = c.res_at === null;
      const cend = open ? end : c.res_at;
      const cid = c.args && typeof c.args.cid === 'string' ? c.args.cid : null;
      if (c.tool === STATUS_TOOL && prev && prev.tool === STATUS_TOOL && prev.cid === cid) {
        prev.end = cend; prev.open = open; prev.count += 1;
        prev.kind = 'waiting';
        prev.label = 'waiting · ' + prev.count + ' status checks';
        continue;
      }
      prev = {lane: 'agent:' + ag, kind: c.tool === TEAM_TOOL ? 'delegate' : 'tool', start: c.at, end: cend,
              open: open, id: c.id, label: c.tool, tool: c.tool, cid: cid, count: 1, error: !!c.error};
      spans.push(prev);
    }
  }
  for (const cid of Object.keys(m.campaigns)) {
    const c = m.campaigns[cid];
    if (c.started_at !== null) {
      const open = c.finished_at === null;
      spans.push({lane: 'server:mcp-sim', kind: 'campaign', start: c.started_at, end: open ? end : c.finished_at,
                  open: open, id: c.started_id, label: 'campaign ' + cid + (open ? '' : ' ' + c.state),
                  error: !open && c.state !== 'done'});
    }
    if (c.gate_at !== null) {
      const open = c.decided_at === null;
      spans.push({lane: 'supervisor', kind: 'gate', start: c.gate_at, end: open ? end : c.decided_at, open: open,
                  id: c.gate_id, label: 'gate ' + cid + (open ? ' waiting' : ' ' + c.gate), error: c.gate === 'denied'});
    }
  }
  const lastMark = {};
  for (const r of m.records) {
    if (r.at === null) continue;
    const lane = 'server:' + r.actor;
    const prev = lastMark[lane];
    if (r.tool === STATUS_TOOL && prev && prev.tool === STATUS_TOOL) {
      prev.count += 1;
      prev.end = r.at;
      prev.text = r.actor + ': ' + prev.count + ' sim.status records';
      continue;
    }
    const mk = {lane: lane, kind: 'record', at: r.at, end: r.at, id: r.id, tool: r.tool, count: 1, error: r.error,
                text: r.actor + ' recorded ' + r.tool + (r.error ? ' (refused)' : '')};
    marks.push(mk);
    lastMark[lane] = mk;
  }
  for (const mk of m.markers) {
    if (mk.at === null) continue;
    marks.push({lane: mk.lane, kind: mk.kind, at: mk.at, end: mk.at, id: mk.id, count: 1, text: mk.text});
  }
  const lo = m.t0, hi = Math.max(isNum(end) ? end : 0, m.t1 === null ? 0 : m.t1);
  return {lanes: L, spans: spans, marks: marks, t0: lo, t1: m.t0 === null ? null : hi};
}

// The lanes as SVG element descriptions ({tag, attrs, text}); the page makes them with
// createElementNS/setAttribute/textContent. view: {from, to} in ms (zoom/pan), width in px.
function laneSvg(lz, width, view, filterAgent) {
  const W = Math.max(320, width || 800), LEFT = 150, ROW = 24, TOP = 22, out = [];
  const shown = lz.lanes.filter((l) => !filterAgent || l.kind !== 'agent' || l.agent === filterAgent ||
                                       l.agent.indexOf(filterAgent + '.') === 0);
  const H = TOP + shown.length * ROW + 8;
  if (lz.t0 === null) return {width: W, height: H, elements: out, scale: null};
  const from = view && isNum(view.from) ? view.from : lz.t0;
  let to = view && isNum(view.to) ? view.to : lz.t1;
  if (!(to > from)) to = from + 1000;
  const x = (t) => LEFT + (t - from) / (to - from) * (W - LEFT - 8);
  const row = {};
  shown.forEach((l, i) => { row[l.id] = TOP + i * ROW; });
  shown.forEach((l, i) => {
    out.push({tag: 'rect', attrs: {x: 0, y: TOP + i * ROW, width: W, height: ROW,
                                   class: 'lane-bg' + (i % 2 ? ' odd' : '')}});
    out.push({tag: 'text', attrs: {x: 6 + l.depth * 10, y: TOP + i * ROW + 16, class: 'lane-label lane-' + l.kind},
              text: short(l.label, 22)});
  });
  for (const tk of timeTicks(from, to, 6)) {
    const tx = x(tk.at);
    out.push({tag: 'line', attrs: {x1: tx, x2: tx, y1: TOP - 4, y2: H - 8, class: 'tick'}});
    out.push({tag: 'text', attrs: {x: tx + 2, y: 14, class: 'tick-label'}, text: tk.label});
  }
  for (const s of lz.spans) {
    if (!(s.lane in row) || s.end < from || s.start > to) continue;
    const x1 = Math.max(LEFT, x(s.start)), x2 = Math.min(W - 8, x(s.end));
    const cls = 'span span-' + s.kind + (s.open ? ' open' : '') + (s.error ? ' bad' : '');
    out.push({tag: 'rect', attrs: {x: x1, y: row[s.lane] + 5, width: Math.max(2, x2 - x1), height: ROW - 10, rx: 2,
                                   class: cls, 'data-event': s.id}, title: s.label});
  }
  for (const mk of lz.marks) {
    if (!(mk.lane in row) || mk.at < from || mk.at > to) continue;
    const mx = x(mk.at), my = row[mk.lane] + ROW / 2;
    out.push({tag: 'path', attrs: {d: 'M' + mx + ' ' + (my - 6) + 'L' + (mx + 5) + ' ' + my + 'L' + mx + ' ' + (my + 6) +
                                      'L' + (mx - 5) + ' ' + my + 'Z',
                                   class: 'mark mark-' + mk.kind + (mk.error ? ' bad' : ''), 'data-event': mk.id},
              title: mk.text + (mk.count > 1 ? ' (×' + mk.count + ')' : '')});
  }
  return {width: W, height: H, elements: out, scale: {from: from, to: to, left: LEFT, right: W - 8}};
}
function timeTicks(from, to, n) {
  const span = Math.max(1, to - from), raw = span / Math.max(1, n);
  const steps = [1e3, 2e3, 5e3, 1e4, 15e3, 3e4, 6e4, 12e4, 3e5, 6e5, 9e5, 18e5, 36e5, 72e5, 144e5, 288e5, 864e5];
  const step = steps.find((s) => s >= raw) || 864e5;
  const out = [];
  for (let t = Math.ceil(from / step) * step; t <= to && out.length < 50; t += step) {
    const d = new Date(t);
    const hh = String(d.getUTCHours()).padStart(2, '0'), mm = String(d.getUTCMinutes()).padStart(2, '0');
    const ss = String(d.getUTCSeconds()).padStart(2, '0');
    out.push({at: t, label: step < 6e4 ? hh + ':' + mm + ':' + ss : hh + ':' + mm});
  }
  return out;
}
function zoomView(view, lz, factor, centre) {     // factor < 1 zooms in; centre in ms
  const from = view && isNum(view.from) ? view.from : lz.t0, to = view && isNum(view.to) ? view.to : lz.t1;
  if (from === null || to === null) return null;
  const c = isNum(centre) ? centre : (from + to) / 2;
  const half = Math.max(500, (to - from) * factor / 2);
  const lo = Math.max(lz.t0, c - half), hi = Math.min(lz.t1, c + half);
  return hi - lo >= (lz.t1 - lz.t0) ? null : {from: lo, to: Math.max(hi, lo + 1000)};
}
function panView(view, lz, deltaMs) {
  if (!view) return null;
  let from = view.from + deltaMs, to = view.to + deltaMs;
  if (from < lz.t0) { to += lz.t0 - from; from = lz.t0; }
  if (to > lz.t1) { from -= to - lz.t1; to = lz.t1; }
  return {from: Math.max(lz.t0, from), to: to};
}

// ── the inspector: what one event says, with the twin records the trace holds for it
function shownText(result) {     // what the model saw of a result: context.wrap_result's escaped first 1000 characters
  const s = String(result === null || result === undefined ? '' : result)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return s.slice(0, SHOWN_MAX);
}
function inspect(e, m, session) {
  if (!isObj(e)) return null;
  const p = isObj(e.payload) ? e.payload : {};
  const k = kindOf(e.event);
  const rows = [['Event', e.event_id], ['Kind', e.event + (k.unknown ? ' (not known to this page)' : ' — ' + k.label)],
                ['Time', e.at || ''], ['Actor', e.actor || '']];
  if (AGENT_EVENTS.indexOf(e.event) >= 0 || (e.event === 'tool_result')) rows.push(['Agent', agentOf(p)]);
  if (isObj(session)) {
    if (session.sup_username) rows.push(['Supervisor', session.sup_username + (session.sup_role ? ' (' + session.sup_role + ')' : '')]);
  }
  const blocks = [];
  if (e.event === 'turn_request' || e.event === 'turn_response') {
    const t = m && m.turns[agentOf(p) + '#' + p.turn];
    rows.push(['Turn', p.turn]);
    if (t) {
      rows.push(['Request sha256', t.request_sha256 || '']);
      rows.push(['Response sha256', t.response_sha256 || '']);
      if (t.usage) rows.push(['Usage', canonical(t.usage)]);
      if (t.cache_n !== null) rows.push(['Prompt cache (cache_n)', t.cache_n]);
      if (t.model) rows.push(['Model', t.model]);
      if (t.error) rows.push(['Error', t.error]);
    }
  }
  if (e.event === 'tool_call' || e.event === 'tool_result') {
    rows.push(['Tool', p.tool || '']);
    if (isInt(p.call)) rows.push(['Call', p.call]);
    if (isInt(p.agent_call)) rows.push(["Agent's call", p.agent_call]);
    if (p.result_sha256) rows.push(['Result sha256', p.result_sha256]);
  }
  if (e.event === 'tool_result' && e.actor === 'agent') {
    const c = m && m.calls[agentOf(p) + '#' + p.call];
    rows.push(['Shown sha256', p.shown_sha256 || '']);
    rows.push(['Record', p.recorded_complete ? 'complete' : 'cut at ' + RECORD_MAX + ' characters']);
    if (typeof p.result === 'string') {
      blocks.push({title: 'What the model saw (the first ' + SHOWN_MAX + ' characters, escaped as the model sees them)' +
                          (p.truncated ? ', cut' : ''), text: shownText(p.result)});
      blocks.push({title: 'The full record (' + (p.recorded_complete ? 'complete' : 'its first ' + RECORD_MAX +
                          ' characters') + ')', text: p.result});
    }
    if (c && c.server.length) {
      const twins = (m.records || []).filter((r) => c.server.indexOf(r.id) >= 0);
      for (const r of twins) {
        rows.push(['Server record', '#' + r.id + ' ' + r.actor + ' ' + r.tool + ': ' +
                   (r.result_sha256 === p.result_sha256 ? 'same digest' : 'digest ' + String(r.result_sha256 || '').slice(0, 12))]);
      }
    }
  }
  if (e.event === 'tool_call' && p.args !== undefined) blocks.push({title: 'Arguments', text: JSON.stringify(p.args, null, 2)});
  rows.push(['prev_hash', e.prev_hash || '']);
  rows.push(['hash', e.hash || '']);
  blocks.push({title: 'Payload', text: JSON.stringify(p, null, 2)});
  return {title: k.label, rows: rows, blocks: blocks};
}

// ── sessions list and budgets
function budgetBars(budget, spent, wall) {
  const out = [];
  const labels = {turns: 'Turns', prompt_tokens: 'Prompt tokens', output_tokens: 'Output tokens', cpu_hours: 'CPU-hours'};
  for (const k of BUDGET_KEYS) {
    const cap = isObj(budget) && isNum(budget[k]) ? budget[k] : null;
    const used = isObj(spent) && isNum(Number(spent[k])) && spent[k] !== null ? Number(spent[k]) : null;
    if (cap === null && used === null) continue;
    out.push({key: k, label: labels[k], spent: used, cap: cap,
              frac: cap ? Math.max(0, Math.min(1, (used || 0) / cap)) : null, over: cap !== null && (used || 0) > cap,
              text: fmt(used === null ? 0 : used) + (cap !== null ? ' of ' + fmt(cap) : '')});
  }
  if (isObj(wall) && isNum(wall.start) && isNum(wall.end) && wall.end > wall.start && isNum(wall.now)) {
    const used = Math.max(0, Math.min(wall.now, wall.end) - wall.start) / 3600000, cap = (wall.end - wall.start) / 3600000;
    out.push({key: 'wall_h', label: 'Wall clock (hours)', spent: used, cap: cap, frac: Math.min(1, used / cap),
              over: false, text: fmt(used, 3) + ' of ' + fmt(cap, 3)});
  }
  return out;
}
function sessionState(item, nowMs) {
  if (!isObj(item)) return {state: 'unknown', text: 'unknown'};
  if (item.revoked) return {state: 'ended', text: 'ended' + (item.revoke_reason ? ': ' + short(item.revoke_reason, 60) : '')};
  const exp = typeof item.exp === 'string' ? parseAt(item.exp) : (isNum(item.exp) ? item.exp * 1000 : null);
  if (item.active === false && exp !== null && isNum(nowMs) && exp <= nowMs) return {state: 'expired', text: 'expired'};
  if (item.active === false) return {state: 'ended', text: 'ended'};
  if (item.state && item.state !== 'running') return {state: String(item.state), text: short(item.state, 40)};
  return {state: 'running', text: 'running'};
}
function sessionRow(item, nowMs) {
  const st = sessionState(item, nowMs);
  return {sid: item.sid, short: String(item.sid || '').slice(0, 8), state: st.state, stateText: st.text,
          profile: item.profile || '', endpoint: item.backend || '', created: item.created_at || null,
          reexecutes: item.reexecutes || null, code_commit: item.code_commit || null,
          bars: budgetBars(item.budget, item.spent)};
}
function mergeSessions(listing) {     // the running ones of this orchestrator and the history (newest first), one row per sid
  const out = [], seen = {};
  const hist = isObj(listing) && Array.isArray(listing.history) ? listing.history : [];
  const run = isObj(listing) && Array.isArray(listing.sessions) ? listing.sessions : [];
  for (const s of hist) if (isObj(s) && SID_RE.test(String(s.sid || '')) && !seen[s.sid]) { seen[s.sid] = out.length; out.push(Object.assign({}, s)); }
  for (const s of run) {
    if (!isObj(s) || !SID_RE.test(String(s.sid || ''))) continue;
    if (seen[s.sid] !== undefined) Object.assign(out[seen[s.sid]], {state: s.state || out[seen[s.sid]].state});
    else { seen[s.sid] = out.length; out.unshift(Object.assign({active: true}, s)); }
  }
  return out;
}

// ── campaign views: mcp_sim's by_setting table and the proposal check
function criteriaOf(table) {
  return isObj(table) && Array.isArray(table.columns) ? table.columns.slice(4) : [];
}
function sameSetting(code, params, row) {
  return row[0] === code && canonical(isObj(row[1]) ? row[1] : {}) === canonical(isObj(params) ? params : {});
}
function bySettingPlot(table, criterion, opts) {
  const o = opts || {};
  const crit = criteriaOf(table);
  const col = isObj(table) ? table.columns.indexOf(criterion) : -1;
  if (!isObj(table) || !Array.isArray(table.settings) || col < 4) {
    return {criterion: criterion, problems: ['the table has no ' + criterion + ' (it has ' + crit.join(', ') + ')'],
            points: [], elements: [], width: 0, height: 0};
  }
  const W = Math.max(360, o.width || 640), LEFT = 230, ROW = 22, TOP = 26;
  const rows = table.settings.filter((r) => Array.isArray(r) && r.length > col);
  const vals = rows.map((r) => r[col]).filter(isNum);
  let lo = vals.length ? Math.min.apply(null, vals) : 0, hi = vals.length ? Math.max.apply(null, vals) : 1;
  if (hi === lo) { lo -= Math.abs(lo) * 0.05 || 0.5; hi += Math.abs(hi) * 0.05 || 0.5; }
  const pad = (hi - lo) * 0.06;
  lo -= pad; hi += pad;
  const x = (v) => LEFT + (v - lo) / (hi - lo) * (W - LEFT - 70);
  const H = TOP + rows.length * ROW + 30;
  const prop = isObj(o.proposed) ? o.proposed : null;
  const out = [], points = [];
  out.push({tag: 'text', attrs: {x: LEFT, y: 14, class: 'axis-title'}, text: criterion + ' (lower is better)'});
  rows.forEach((r, i) => {
    const y = TOP + i * ROW + ROW / 2;
    const v = isNum(r[col]) ? r[col] : null;
    const proposed = !!prop && sameSetting(prop.code, prop.params, r);
    const label = r[0] + ' ' + short(canonical(isObj(r[1]) ? r[1] : {}), 40);
    points.push({index: i, code: r[0], params: r[1], runs: r[2], valid: r[3], value: v, proposed: proposed,
                 x: v === null ? null : x(v), y: y});
    out.push({tag: 'text', attrs: {x: 4, y: y + 4, class: 'row-label' + (proposed ? ' proposed' : '')}, text: short(label, 34)});
    out.push({tag: 'line', attrs: {x1: LEFT, x2: W - 70, y1: y, y2: y, class: 'row-rule'}});
    if (v !== null) {
      out.push({tag: 'circle', attrs: {cx: x(v), cy: y, r: proposed ? 6 : 4, class: 'dot' + (proposed ? ' proposed' : '')},
                title: label + ': ' + fmt(v) + ' (' + r[3] + ' of ' + r[2] + ' runs valid)'});
      out.push({tag: 'text', attrs: {x: W - 66, y: y + 4, class: 'row-value'}, text: fmt(v)});
    } else {
      out.push({tag: 'text', attrs: {x: W - 66, y: y + 4, class: 'row-value none'}, text: 'no valid run'});
    }
  });
  const axY = TOP + rows.length * ROW + 8;
  for (const t of niceTicks(lo, hi, 4)) {
    out.push({tag: 'line', attrs: {x1: x(t), x2: x(t), y1: TOP - 4, y2: axY, class: 'tick'}});
    out.push({tag: 'text', attrs: {x: x(t), y: axY + 14, class: 'tick-label mid'}, text: fmt(t, 3)});
  }
  return {criterion: criterion, problems: [], points: points, elements: out, width: W, height: H,
          count: isObj(table.count) ? table.count : null, order: table.order || null};
}
function niceTicks(lo, hi, n) {
  const span = hi - lo;
  if (!(span > 0)) return [lo];
  const raw = span / n, mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const step = [1, 2, 2.5, 5, 10].map((f) => f * mag).find((s) => s >= raw) || 10 * mag;
  const out = [];
  for (let t = Math.ceil(lo / step) * step; t <= hi + 1e-12 && out.length < 20; t += step) out.push(Number(t.toPrecision(12)));
  return out;
}
function proposalCheckView(check) {
  if (!isObj(check)) return null;
  const compared = Array.isArray(check.compared) ? check.compared.filter(isObj) : [];
  const total = isInt(check.compared_total) ? check.compared_total : compared.length;
  return {criterion: check.criterion || '', lowerIsBetter: check.lower_is_better !== false,
          proposedMean: isNum(check.proposed_mean) ? check.proposed_mean : null,
          proposedRuns: isInt(check.proposed_runs) ? check.proposed_runs : null,
          rows: compared.map((o) => ({code: o.code, params: canonical(isObj(o.params) ? o.params : {}), runs: o.runs,
                                      proposed: isNum(o.proposed) ? o.proposed : null, other: isNum(o.other) ? o.other : null,
                                      outcome: o.outcome, better: o.outcome === 'better'})),
          total: total, more: Math.max(0, total - compared.length), by: check.by || ''};
}
function proposalView(pr) {      // a proposal of the model (its document from the agent's tool result)
  if (!isObj(pr)) return null;
  const d = isObj(pr.doc) ? pr.doc : {};
  return {pid: pr.pid, agent: pr.agent, kind: d.kind || null, code: d.algorithm_code || null,
          params: canonical(isObj(d.params) ? d.params : {}), rationale: typeof d.rationale === 'string' ? d.rationale : '',
          evidence: Array.isArray(d.evidence) ? d.evidence.filter(isObj).map((x) => ({cid: x.cid, spec_digest: x.spec_digest,
                                                                                      result_digest: x.result_digest})) : [],
          check: proposalCheckView(d.check), decided: pr.decided, result_sha256: pr.result_sha256,
          state: pr.decided ? (pr.decided.decision === 'approve' ? 'accepted' : 'discarded') : 'waiting'};
}

// ── gates
function gateLimit(gate) {
  if (!isObj(gate)) return null;
  if (isNum(gate.cap_h)) return gate.cap_h;               // the server's cap: 1.25 × estimate + calibration (bounded)
  if (isNum(gate.estimate_h)) return CAP_FACTOR * gate.estimate_h;
  return null;
}
function capProblems(cap, gate, remaining) {
  const v = typeof cap === 'string' ? (cap.trim() === '' ? NaN : Number(cap)) : cap;
  if (!isNum(v)) return ['the cap must be a number of CPU-hours'];
  const out = [];
  if (v <= 0) out.push('the cap must be more than 0 CPU-hours');
  if (v > MAX_CAMPAIGN_H) out.push('the cap must be at most ' + MAX_CAMPAIGN_H + ' CPU-hours, the most one campaign may use');
  if (isNum(remaining) && v > remaining) out.push("the cap must be at most the session's remaining " + fmt(remaining) + ' CPU-hours');
  const lim = gateLimit(gate);
  if (lim !== null && v > lim + 1e-9) out.push('the cap must be at most ' + fmt(lim) +
                                               ' CPU-hours: 1.25 × the estimate + calibration, as the server set it');
  return out;
}
function defaultCap(gate, remaining) {
  let lim = gateLimit(gate);
  if (lim === null) return null;
  if (isNum(remaining)) lim = Math.min(lim, remaining);
  lim = Math.min(lim, MAX_CAMPAIGN_H);
  return Math.max(0.001, Math.floor(lim * 1000) / 1000);
}
function gateView(c, budget, spent) {
  if (!isObj(c)) return null;
  const remaining = isObj(budget) && isNum(budget.cpu_hours)
    ? budget.cpu_hours - (isObj(spent) && isNum(Number(spent.cpu_hours)) ? Number(spent.cpu_hours) : 0) : null;
  return {gid: c.gid || c.cid, cid: c.cid, estimate_h: c.estimate_h, cap_h: c.cap_h, runs: c.runs, state: c.gate,
          pending: c.gate === 'pending', decided_by: c.decided_by, note: c.note, approved_cap_h: c.approved_cap_h,
          agent: c.agent, remaining: remaining, limit: gateLimit(c), suggested: defaultCap(c, remaining)};
}

// ── start: the orchestrator's refusals of POST /api/sessions, as the page can know them (the endpoints
// the listing names are the enabled ones; a missing model gateway is the server's to say)
function startProblems(profile, chosen, endpoints) {
  if (!isObj(profile)) return ['choose a profile'];
  const inv = Array.isArray(endpoints) ? endpoints.filter(isObj) : [];
  const names = inv.map((i) => i.name);
  if (chosen !== null && chosen !== undefined && chosen !== '') {
    if (profile.backend === 'scripted') return ['a scripted profile has no model to choose'];
    if (typeof chosen !== 'string' || names.indexOf(chosen) < 0) {
      return ['the endpoint ' + String(chosen).slice(0, 40) + ' is not enabled on this install (RESEARCH_ENDPOINTS); ' +
              'choose one of ' + (names.join(', ') || 'none')];
    }
    const ep = inv.find((i) => i.name === chosen);
    if (!isInt(ep.context)) {
      return ['the endpoint ' + chosen + ' is enabled but not in the model inventory: run ./apps/research-agents/deploy.sh'];
    }
  }
  const backend = chosen || profile.backend;
  if (backend !== 'scripted' && names.indexOf(backend) < 0) {
    return ['this profile uses the endpoint ' + backend + ', which is not enabled on this install (RESEARCH_ENDPOINTS)'];
  }
  if (backend !== 'scripted' && backend === profile.backend) {
    const own = inv.find((i) => i.name === backend);
    const ctx = own ? own.context : null;
    const caps = isObj(profile.caps) ? profile.caps : {};
    if (isInt(ctx) && isNum(caps.context_tokens)) {
      const room = ctx - CONTEXT_MARGIN;
      if (caps.context_tokens > room) {
        return ['the profile ' + profile.name + ' needs ' + caps.context_tokens + ' tokens of context and the endpoint ' +
                backend + ' holds ' + room + ' (' + ctx + " less the chat template's " + CONTEXT_MARGIN +
                '): choose another profile, or this one with an endpoint that holds more'];
      }
    }
  }
  return [];
}

// ── replay and re-execution
function agentRecord(events) {     // replay.replay's `rec`: the agent's own events, in order
  return (Array.isArray(events) ? events : []).filter((e) => isObj(e) && e.actor === 'agent' &&
                                                             AGENT_EVENTS.indexOf(e.event) >= 0)
    .slice().sort((a, b) => a.event_id - b.event_id);
}
function replayView(events, verdict) {
  if (!isObj(verdict)) return {state: 'none'};
  if (verdict.state === 'running') return {state: 'running', text: 'The replay runs as a Job: this page asks again every 5 s.'};
  if (verdict.ok) return {state: 'ok', events: verdict.events, text: 'The replay matches the record: ' + verdict.events + ' events.'};
  const fm = isObj(verdict.first_mismatch) ? verdict.first_mismatch : null;
  const rec = agentRecord(events);
  const idx = fm && isInt(fm.index) ? fm.index : null;
  const ev = idx !== null && idx < rec.length ? rec[idx] : null;
  const agent = fm && typeof fm.agent === 'string' ? fm.agent : (ev ? agentOf(ev.payload) : null);
  const str = (v) => v === null || v === undefined ? '' : (typeof v === 'string' ? v : canonical(v));
  return {state: 'mismatch', index: idx, event_id: ev ? ev.event_id : null, agent: agent,
          event: fm ? fm.event : null, field: fm ? fm.field : null, recorded: fm ? str(fm.recorded) : '',
          replayed: fm ? str(fm.replayed) : '', error: verdict.error || null,
          text: fm ? 'The replay differs at the ' + (idx === null ? '?' : idx + 1) + 'th agent event' +
                     (agent ? ' (agent ' + agent + ')' : '') + ': ' + (fm.event || 'the end of the record') + ', field ' + fm.field
                   : 'The replay did not finish' + (verdict.error ? ': ' + short(verdict.error, 200) : '.')};
}
function turnsOf(events) {         // cli.Client.turns: the model-gateway's records of the lead's turns
  const out = {}, at = {};
  for (const e of Array.isArray(events) ? events : []) {
    const p = isObj(e.payload) ? e.payload : {};
    if (e.actor !== 'model-gateway' || !isInt(p.turn) || (p.agent === undefined ? LEAD : p.agent) !== LEAD) continue;
    const t = p.turn;
    if (e.event === 'turn_request') { out[t] = [p.request_sha256 === undefined ? null : p.request_sha256, null, null]; at[t] = e.at; }
    else if (e.event === 'turn_response' && out[t] !== undefined) {
      let secs = null;
      if (at[t] && e.at) {
        const a = parseAt(at[t]), b = parseAt(e.at);
        if (a !== null && b !== null) secs = Math.round((b - a)) / 1000;
      }
      out[t] = [out[t][0], p.response_sha256 === undefined ? null : p.response_sha256, secs];
    }
  }
  return out;
}
function compareTurns(first, second) {      // cli.Client.compare_turns, word for word
  const a = turnsOf(first), b = turnsOf(second);
  const keys = Object.keys(a).filter((t) => b[t] !== undefined).map(Number).sort((x, y) => x - y);
  let compared = 0, same = 0, firstDiff = null, ended = null;
  for (const t of keys) {
    if (a[t][0] !== b[t][0]) { ended = {turn: t, why: 'the requests differ (an earlier tool result changed)'}; break; }
    if (a[t][1] === null || b[t][1] === null) { ended = {turn: t, why: 'a turn has no answer'}; break; }
    compared += 1;
    if (a[t][1] === b[t][1]) same += 1;
    else if (firstDiff === null) firstDiff = t;
  }
  const sorted = (o) => Object.keys(o).map(Number).sort((x, y) => x - y);
  return {turns_compared: compared, same_answers: same,
          rate: compared ? Math.round(same / compared * 10000) / 10000 : null,
          first_different_answer: firstDiff, ended: ended,
          seconds: {first: sorted(a).map((t) => a[t][2]), second: sorted(b).map((t) => b[t][2])}};
}

// ── a run's chamber series (research/harness/series.py's document) for uPlot
function decimate(doc, width) {    // min and max per bucket of every column; command/relay changes stay whole
  if (!isObj(doc) || !isObj(doc.columns) || !Array.isArray(doc.columns.t)) return doc;
  const t = doc.columns.t, n = t.length, buckets = Math.max(1, Math.floor(width || 600));
  if (n <= buckets * 2) return doc;
  const cols = [];
  const walk = (obj, path) => {
    for (const k of Object.keys(obj)) {
      if (Array.isArray(obj[k]) && obj[k].length === n) cols.push(path.concat(k));
      else if (isObj(obj[k])) walk(obj[k], path.concat(k));
    }
  };
  walk(doc.columns, []);
  const keep = {};
  const get = (path) => path.reduce((o, k) => o[k], doc.columns);
  for (let b = 0; b < buckets; b++) {
    const lo = Math.floor(b * n / buckets), hi = Math.floor((b + 1) * n / buckets);
    if (hi <= lo) continue;
    keep[lo] = true; keep[hi - 1] = true;
    for (const path of cols) {
      if (path[0] === 't') continue;
      const arr = get(path);
      let mi = -1, ma = -1;
      for (let i = lo; i < hi; i++) {
        const v = arr[i];
        if (!isNum(v)) continue;
        if (mi < 0 || v < arr[mi]) mi = i;
        if (ma < 0 || v > arr[ma]) ma = i;
      }
      if (mi >= 0) keep[mi] = true;
      if (ma >= 0) keep[ma] = true;
    }
  }
  const idx = Object.keys(keep).map(Number).sort((a, b) => a - b);
  const pick = (obj) => {
    const out = {};
    for (const k of Object.keys(obj)) {
      if (Array.isArray(obj[k]) && obj[k].length === n) out[k] = idx.map((i) => obj[k][i]);
      else if (isObj(obj[k])) out[k] = pick(obj[k]);
      else out[k] = obj[k];
    }
    return out;
  };
  return Object.assign({}, doc, {columns: pick(doc.columns), decimated: {from: n, to: idx.length}});
}
const SERIES_UNITS = {air_temperature: '°C', air_humidity: '%RH', co2: 'ppm', ground_temperature: '°C'};
function seriesToUplot(doc, band) {
  if (!isObj(doc) || !isObj(doc.columns) || !Array.isArray(doc.columns.t)) return {panels: [], problems: ['no series']};
  const h = isObj(doc.header) ? doc.header : {};
  const c = doc.columns;
  const th = c.t.map((s) => isNum(s) ? s / 3600 : null);
  const bands = Object.assign({}, isObj(h.band) ? h.band : {}, isObj(band) ? band : {});
  const loops = Array.isArray(h.loops) ? h.loops : Object.keys(isObj(c.loops) ? c.loops : {});
  const panels = [];
  const truthKeys = ['air_temperature', 'air_humidity', 'co2', 'ground_temperature'];
  for (const q of truthKeys) {
    if (!Array.isArray(c[q]) || !c[q].some(isNum)) continue;
    const loopKey = loops.find((k) => k === q || k.split('@')[0] === q) || null;
    const data = [th, c[q]];
    const series = [{label: q + ' (truth)', cls: 'truth'}];
    if (loopKey && isObj(c.loops) && isObj(c.loops[loopKey]) && Array.isArray(c.loops[loopKey].value)) {
      data.push(c.loops[loopKey].value);
      series.push({label: 'loop value', cls: 'value'});
    }
    const b = loopKey && Array.isArray(bands[loopKey]) ? bands[loopKey] : (Array.isArray(bands[q]) ? bands[q] : null);
    let bandIdx = null;
    if (b && isNum(b[0]) && isNum(b[1])) {
      data.push(th.map(() => b[1]));
      series.push({label: 'upper', cls: 'band'});
      data.push(th.map(() => b[0]));
      series.push({label: 'lower', cls: 'band'});
      bandIdx = [data.length - 2, data.length - 1];
    }
    panels.push({id: q, title: q.replace(/_/g, ' ') + ' (' + (SERIES_UNITS[q] || '') + ')', data: data, series: series,
                 band: bandIdx, step: false});
  }
  if (Array.isArray(c.energy_wh) && c.energy_wh.some(isNum)) {
    panels.push({id: 'energy', title: 'cumulative energy (Wh)', data: [th, c.energy_wh],
                 series: [{label: 'energy_wh', cls: 'energy'}], band: null, step: false});
  }
  const strips = [th], sseries = [];
  loops.forEach((k) => {
    if (isObj(c.loops) && isObj(c.loops[k]) && Array.isArray(c.loops[k].cmd)) {
      strips.push(c.loops[k].cmd); sseries.push({label: k + ' command (0 none, 1 UP, 2 DOWN, 3 OFF)', cls: 'cmd'});
    }
  });
  if (Array.isArray(c.light)) { strips.push(c.light); sseries.push({label: 'light', cls: 'light'}); }
  if (Array.isArray(c.relays)) { strips.push(c.relays); sseries.push({label: 'relays (bitmask)', cls: 'relays'}); }
  if (sseries.length) panels.push({id: 'strips', title: 'commands, light and relays', data: strips, series: sseries,
                                    band: null, step: true});
  const changes = Array.isArray(doc.changes) ? doc.changes.length : 0;
  return {panels: panels, metricsFromH: isNum(h.metrics_from_s) ? h.metrics_from_s / 3600 : null,
          disturbances: Array.isArray(c.disturbance) ? th.filter((_, i) => c.disturbance[i]) : [],
          points: c.t.length, changes: changes, every_s: h.every_s || null, error: doc.error || null, problems: []};
}

// ── what the person may do here (me.can from GET /api/me; unknown = shown, the server decides)
function actionsFor(info, me, m) {
  const can = isObj(me) && isObj(me.can) ? me.can : null;
  const allow = (k) => can === null ? true : !!can[k];
  const active = isObj(info) && info.active === true;
  const model = isObj(info) && typeof info.backend === 'string' && info.backend !== 'scripted';
  const pendingGates = m ? Object.keys(m.campaigns).filter((k) => m.campaigns[k].gate === 'pending').length : 0;
  const open = m ? Object.keys(m.proposals).filter((k) => !m.proposals[k].decided).length : 0;
  return {start: allow('start'), stop: active && allow('stop'), replay: isObj(info) && !active && allow('replay'),
          reexecute: isObj(info) && !active && model && allow('reexecute'),
          decideGates: active && pendingGates > 0 && allow('decide'), decideProposals: open > 0 && allow('decide'),
          otel: isObj(info)};
}

// ── answers the page shows: the server's own text, led by what to do
const KNOWN_ERRORS = {
  'wrong origin': "The request did not come from the console's own page: reload it.",
  'no such session': 'No such session: it was started by someone else, or it does not exist.',
  'no such gate': 'No such gate in this session.',
  'this gate is already decided': 'Someone already decided this gate: the page shows it at the next update.',
  'no such proposal': 'No such proposal in this session.',
  'this proposal is already decided': 'This proposal is already decided.',
  'the session is still running: replay it after it has stopped': 'Replay the session once it has stopped.',
  'approved_cap_h is required to approve a gate': 'Give a cap to approve the gate.',
  'Content-Type must be application/json': 'The page sent something other than JSON: reload it.',
};
function errorText(status, body) {
  const msg = isObj(body) && typeof body.error === 'string' ? body.error : '';
  if (status === 401) return {text: 'Your sign-in has ended: the page reloads to sign you in again.', reload: true};
  if (status === 0) return {text: 'The console could not reach the server: check the connection and try again.'};
  if (msg && Object.prototype.hasOwnProperty.call(KNOWN_ERRORS, msg)) return {text: KNOWN_ERRORS[msg], server: msg};
  const base = {400: 'Not accepted', 403: 'Refused', 404: 'Not found (or not available yet)', 405: 'Not allowed here',
                409: 'Not possible now', 410: 'Gone: the files are no longer on the runs volume',
                413: 'Too large to show', 415: 'Not JSON', 429: 'Busy: try again in a moment',
                500: 'Something went wrong on the server', 502: 'A research service did not answer',
                503: 'Not available'}[status] || ('Error ' + status);
  return {text: msg ? base + ': ' + short(msg, 300) : base + '.', server: msg || null};
}

// ── live updates as a pure state machine: pollNext(state, outcome, now) -> {state, delay ms | null, wait s}
// outcome: {ok, active, hidden, got (events in this answer), elapsed ms, expS (seconds the token has left)}
function pollStart() { return {mode: 'long', fails: 0, longFails: 0, tailUntil: null}; }
function pollNext(state, o, now) {
  const s = Object.assign(pollStart(), state || {});
  const out = (delay, wait) => ({state: s, delay: delay, wait: wait});
  if (o.hidden) return {state: s, delay: null, wait: 0, paused: true};
  if (!o.ok) {
    s.fails += 1;
    if (s.mode === 'long') { s.longFails += 1; if (s.longFails >= POLL.LONG_FAILS) s.mode = 'plain'; }
    return out(Math.min(POLL.BACKOFF_MAX_MS, POLL.BACKOFF_MS * Math.pow(2, s.fails - 1)),
               s.mode === 'long' ? POLL.LONG_WAIT_S : 0);
  }
  s.fails = 0;
  if (!o.active) {
    if (s.mode !== 'tail' && s.mode !== 'stopped') { s.mode = 'tail'; s.tailUntil = now + POLL.TAIL_FOR_MS; }
    if (s.mode === 'tail' && now >= s.tailUntil) s.mode = 'stopped';
    if (s.mode === 'stopped') return out(null, 0);
    return out(o.got >= EVENTS_PAGE ? 0 : POLL.TAIL_MS, 0);
  }
  if (s.mode === 'tail' || s.mode === 'stopped') { s.mode = s.longFails >= POLL.LONG_FAILS ? 'plain' : 'long'; s.tailUntil = null; }
  // a long-poll answered at once with nothing: the server does not wait (an orchestrator from before the console)
  if (s.mode === 'long' && o.got === 0 && isNum(o.elapsed) && o.elapsed < POLL.QUICK_MS) {
    s.longFails += 1;
    if (s.longFails >= POLL.LONG_FAILS) s.mode = 'plain';
  }
  if (o.got >= EVENTS_PAGE) return out(0, 0);
  if (s.mode === 'long') {
    const wait = isNum(o.expS) ? Math.max(0, Math.min(POLL.LONG_WAIT_S, Math.floor(o.expS - 5))) : POLL.LONG_WAIT_S;
    return out(wait > 0 ? 0 : POLL.PLAIN_MS, wait);
  }
  return out(POLL.PLAIN_MS, 0);
}

// ── hash routes
function parseRoute(hash) {
  const h = String(hash || '').replace(/^#/, '');
  const seg = h.split('/').filter((x) => x !== '');
  if (!seg.length) return {view: 'sessions'};
  if (seg[0] === 's' && SID_RE.test(seg[1] || '')) {
    const sid = seg[1];
    if (seg.length === 2) return {view: 'session', sid: sid};
    if (seg[2] === 'e' && /^[0-9]{1,9}$/.test(seg[3] || '') && seg.length === 4) return {view: 'session', sid: sid, event: +seg[3]};
    if (seg[2] === 'replay' && seg.length === 3) return {view: 'replay', sid: sid};
    if (seg[2] === 'c' && XID_RE.test(seg[3] || '')) {
      if (seg.length === 4) return {view: 'campaign', sid: sid, cid: seg[3]};
      if (seg[4] === 'r' && /^[0-9]{1,6}$/.test(seg[5] || '') && seg.length === 6) return {view: 'run', sid: sid, cid: seg[3], n: +seg[5]};
    }
    return {view: 'notfound'};
  }
  if (seg[0] === 'cmp' && SID_RE.test(seg[1] || '') && SID_RE.test(seg[2] || '') && seg.length === 3) {
    return {view: 'compare', a: seg[1], b: seg[2]};
  }
  return {view: 'notfound'};
}
function routeHash(r) {
  switch (r.view) {
    case 'session': return '#/s/' + r.sid + (isInt(r.event) ? '/e/' + r.event : '');
    case 'replay': return '#/s/' + r.sid + '/replay';
    case 'campaign': return '#/s/' + r.sid + '/c/' + r.cid;
    case 'run': return '#/s/' + r.sid + '/c/' + r.cid + '/r/' + r.n;
    case 'compare': return '#/cmp/' + r.a + '/' + r.b;
    default: return '#/';
  }
}
/* console-logic:end */

// ─────────────────────────────────────────────────────────────────────────────
// The page: DOM and fetch. Nothing below builds markup from text: el() sets textContent.
(function () {
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const $ = (id) => document.getElementById(id);
  const S = {me: undefined, profiles: undefined, listing: null, before: null, manifest: null, route: null,
             cur: null, gen: 0, cy: null, plots: [], toastTimer: null};

  function el(tag, opts, children) {
    const n = document.createElement(tag);
    const o = opts || {};
    if (o.cls) n.className = o.cls;
    if (o.text !== undefined && o.text !== null) n.textContent = String(o.text);
    if (o.attrs) for (const k of Object.keys(o.attrs)) if (o.attrs[k] !== null && o.attrs[k] !== undefined) n.setAttribute(k, String(o.attrs[k]));
    if (o.on) for (const k of Object.keys(o.on)) n.addEventListener(k, o.on[k]);
    for (const c of children || []) if (c) n.appendChild(c);
    return n;
  }
  function svgFrom(desc) {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 ' + desc.width + ' ' + desc.height);
    svg.setAttribute('width', String(desc.width));
    svg.setAttribute('height', String(desc.height));
    svg.setAttribute('role', 'img');
    for (const d of desc.elements) {
      const n = document.createElementNS(SVG_NS, d.tag);
      for (const k of Object.keys(d.attrs)) n.setAttribute(k, String(d.attrs[k]));
      if (d.text !== undefined) n.textContent = d.text;
      if (d.title) { const t = document.createElementNS(SVG_NS, 'title'); t.textContent = d.title; n.appendChild(t); }
      svg.appendChild(n);
    }
    return svg;
  }
  function toast(text, bad) {
    const t = $('toast');
    t.textContent = text;
    t.className = 'toast show' + (bad ? ' bad' : '');
    clearTimeout(S.toastTimer);
    S.toastTimer = setTimeout(() => { t.className = 'toast'; }, 6000);
  }

  // ── fetch
  async function api(name, ids, opts) {
    const o = opts || {};
    let path = pathOf(name, ids || {});
    if (o.query) {
      const q = Object.keys(o.query).filter((k) => o.query[k] !== null && o.query[k] !== undefined)
        .map((k) => encodeURIComponent(k) + '=' + encodeURIComponent(String(o.query[k]))).join('&');
      if (q) path += '?' + q;
    }
    const init = {method: API[name].method, credentials: 'same-origin', headers: {Accept: 'application/json'},
                  cache: 'no-store'};
    if (API[name].method === 'POST') {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(o.body || {});
    }
    if (o.signal) init.signal = o.signal;
    let res;
    try { res = await fetch(path, init); } catch (e) {
      if (e && e.name === 'AbortError') throw e;
      return {status: 0, body: null};
    }
    if (o.raw && res.ok) return {status: res.status, blob: await res.blob()};
    let body = null;
    try { body = await res.json(); } catch (e) { body = null; }
    if (res.status === 401) reloadOnce();
    return {status: res.status, body: body};
  }
  function reloadOnce() {
    let last = 0;
    try { last = Number(sessionStorage.getItem('console-reload') || 0); } catch (e) { last = 0; }
    if (Date.now() - last < 15000) { toast(errorText(401).text + ' (it just did: sign in again from the portal)', true); return; }
    try { sessionStorage.setItem('console-reload', String(Date.now())); } catch (e) { /* storage blocked: reload anyway */ }
    location.reload();
  }
  function failed(r) {
    toast(errorText(r.status, r.body).text, true);
  }

  // ── theme
  function applyTheme(t) {
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
    else document.documentElement.removeAttribute('data-theme');
    $('theme').textContent = t === 'light' ? 'Theme: light' : t === 'dark' ? 'Theme: dark' : 'Theme: system';
    if (S.cy) styleGraph();
    if (S.route && S.route.view === 'run') render();
  }
  function themeInit() {
    let t = 'auto';
    try { t = localStorage.getItem('console-theme') || 'auto'; } catch (e) { t = 'auto'; }
    applyTheme(t);
    $('theme').addEventListener('click', () => {
      const cur = document.documentElement.getAttribute('data-theme') || 'auto';
      const next = cur === 'auto' ? 'light' : cur === 'light' ? 'dark' : 'auto';
      try { localStorage.setItem('console-theme', next); } catch (e) { /* per-viewer convenience only */ }
      applyTheme(next);
    });
  }
  function token(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || '#888'; }

  // ── boot
  async function boot() {
    themeInit();
    try {
      const r = await fetch('/static/MANIFEST.json', {credentials: 'same-origin', cache: 'no-store'});
      S.manifest = r.ok ? await r.json() : null;
    } catch (e) { S.manifest = null; }
    const so = S.manifest && typeof S.manifest.signout === 'string' && S.manifest.signout.indexOf('https://') === 0
      ? S.manifest.signout : '/oauth2/sign_out';
    $('signout').setAttribute('href', so);
    const me = await api('me');
    S.me = me.status === 200 && isObj(me.body) ? me.body : null;
    if (S.me) $('who').textContent = (S.me.username || '') + (S.me.role ? ' · ' + S.me.role : '');
    window.addEventListener('hashchange', render);
    document.addEventListener('visibilitychange', () => { if (!document.hidden && S.cur && S.cur.kick) S.cur.kick(); });
    render();
  }

  function setMain(title, nodes) {
    const main = $('main');
    main.replaceChildren();
    if (title) main.appendChild(el('h2', {text: title}));
    for (const n of nodes) if (n) main.appendChild(n);
  }
  function leave() {                       // stop the current view's polls and charts
    S.gen += 1;
    if (S.cur && S.cur.abort) S.cur.abort.abort();
    if (S.cur && S.cur.timer) clearTimeout(S.cur.timer);
    S.cur = null;
    if (S.cy) { S.cy.destroy(); S.cy = null; }
    for (const p of S.plots) p.destroy();
    S.plots = [];
  }

  function render() {
    const r = parseRoute(location.hash);
    const same = S.route && S.cur && S.route.sid && r.sid === S.route.sid && r.view === 'session' && S.route.view === 'session';
    S.route = r;
    if (same && S.cur.select) { S.cur.select(r.event); return; }
    leave();
    if (r.view === 'sessions') return viewSessions();
    if (r.view === 'session') return viewSession(r.sid, r.event);
    if (r.view === 'replay') return viewReplay(r.sid);
    if (r.view === 'campaign') return viewCampaign(r.sid, r.cid);
    if (r.view === 'run') return viewRun(r.sid, r.cid, r.n);
    if (r.view === 'compare') return viewCompare(r.a, r.b);
    setMain('Not found', [el('p', {text: 'This address names nothing on the console.'}), el('a', {text: 'All sessions', attrs: {href: '#/'}})]);
  }

  // ── view 1: sessions
  async function viewSessions(more) {
    const gen = S.gen;
    if (!more) setMain('Sessions', [el('p', {cls: 'muted', text: 'Loading…'})]);
    const [lr, pr] = await Promise.all([api('sessions', {}, {query: {before: more ? S.before : null}}),
                                        S.profiles === undefined ? api('profiles') : Promise.resolve(null)]);
    if (gen !== S.gen) return;
    if (pr) S.profiles = pr.status === 200 && isObj(pr.body) ? pr.body : null;
    if (lr.status !== 200) { setMain('Sessions', [el('p', {cls: 'err', text: errorText(lr.status, lr.body).text})]); return; }
    if (more && S.listing) {
      S.listing.history = (S.listing.history || []).concat(lr.body.history || []);
    } else S.listing = lr.body;
    S.before = lr.body.next_before || null;
    const rows = mergeSessions(S.listing);
    const now = Date.now();
    const list = el('div', {cls: 'cards'});
    for (const it of rows) {
      const row = sessionRow(it, now);
      const bars = el('div', {cls: 'bars'});
      for (const b of row.bars) bars.appendChild(bar(b));
      list.appendChild(el('a', {cls: 'card session ' + row.state, attrs: {href: routeHash({view: 'session', sid: row.sid})}}, [
        el('div', {cls: 'card-head'}, [el('span', {cls: 'sid mono', text: row.short}),
                                         el('span', {cls: 'pill ' + row.state, text: row.stateText})]),
        el('div', {text: row.profile + (row.endpoint ? ' on ' + row.endpoint : '')}),
        el('div', {cls: 'muted small', text: (row.created ? 'started ' + row.created.replace('T', ' ').slice(0, 19) : '') +
                                            (row.reexecutes ? ' · re-executes ' + row.reexecutes.slice(0, 8) : '')}),
        bars]));
    }
    const nodes = [startForm()];
    if (!rows.length) nodes.push(el('p', {cls: 'muted', text: S.me && S.me.can && !S.me.can.start
      ? 'Sessions are shown to the person who started them. You have none.' : 'No sessions yet.'}));
    nodes.push(list);
    if (S.before) nodes.push(el('button', {text: 'Older sessions', on: {click: () => viewSessions(true)}}));
    setMain('Sessions', nodes);
  }
  function bar(b) {
    const meter = el('div', {cls: 'meter' + (b.over ? ' over' : '')});
    const fill = el('div', {cls: 'fill'});
    if (b.frac !== null) fill.style.width = Math.round(b.frac * 100) + '%';    // CSSOM, allowed under the CSP
    meter.appendChild(fill);
    return el('div', {cls: 'bar'}, [el('span', {cls: 'small', text: b.label + ': ' + b.text}), meter]);
  }
  function startForm() {
    if (S.me && S.me.can && S.me.can.start === false) {
      return el('p', {cls: 'muted', text: 'Your role may read sessions but not start one. Sessions are shown to the person who started them.'});
    }
    const profiles = S.profiles && Array.isArray(S.profiles.profiles) ? S.profiles.profiles : null;
    const endpoints = (S.profiles && Array.isArray(S.profiles.endpoints) ? S.profiles.endpoints : null) ||
                      (S.listing && Array.isArray(S.listing.endpoints) ? S.listing.endpoints : []);
    if (!profiles) return el('p', {cls: 'muted', text: 'The profile list is not available yet; start sessions with medcea-agent from a notebook.'});
    const psel = el('select', {attrs: {id: 'start-profile'}});
    for (const p of profiles) psel.appendChild(el('option', {text: p.name + ' (' + p.backend + ')', attrs: {value: p.name}}));
    const esel = el('select', {attrs: {id: 'start-endpoint'}});
    esel.appendChild(el('option', {text: "the profile's own", attrs: {value: ''}}));
    for (const e of endpoints) {
      esel.appendChild(el('option', {text: e.name + ' · ' + (e.model || '') + ' · ' + (e.context || '?') + ' tokens',
                                     attrs: {value: e.name}}));
    }
    const why = el('p', {cls: 'err small'});
    const go = el('button', {cls: 'primary', text: 'Start'});
    const check = () => {
      const p = profiles.find((x) => x.name === psel.value);
      const pr = startProblems(p, esel.value || null, endpoints);
      why.textContent = pr.join(' ');
      go.disabled = pr.length > 0;
      esel.disabled = !!p && p.backend === 'scripted';
      if (esel.disabled) esel.value = '';
    };
    psel.addEventListener('change', check);
    esel.addEventListener('change', check);
    go.addEventListener('click', async () => {
      go.disabled = true;
      const body = {profile: psel.value};
      if (esel.value) body.endpoint = esel.value;
      const r = await api('start', {}, {body: body});
      if (r.status === 201 && isObj(r.body) && SID_RE.test(String(r.body.sid))) { location.hash = routeHash({view: 'session', sid: r.body.sid}); return; }
      failed(r);
      check();
    });
    check();
    return el('section', {cls: 'panel start'}, [el('h3', {text: 'Start a session'}),
      el('label', {text: 'Profile '}, [psel]), el('label', {text: 'Model '}, [esel]), go, why]);
  }

  // ── view 2: one session
  async function loadAll(sid, gen, sink) {     // the whole trace, page by page (cap 100000: "trace cut")
    let after = 0, cut = false;
    for (;;) {
      const r = await api('events', {sid: sid}, {query: {after: after}});
      if (gen !== S.gen) return null;
      if (r.status !== 200) return {error: r};
      const got = isObj(r.body) && Array.isArray(r.body.events) ? r.body.events : [];
      sink.push.apply(sink, got);
      if (got.length) after = got[got.length - 1].event_id;
      if (got.length < EVENTS_PAGE) break;
      if (sink.length >= EVENTS_CAP) { cut = true; break; }
    }
    return {after: after, cut: cut};
  }

  async function viewSession(sid, eventId) {
    const gen = S.gen;
    const cur = {sid: sid, events: [], byId: {}, model: emptyModel(), info: null, selected: eventId || null,
                 filter: null, view: null, poll: pollStart(), abort: null, timer: null, loop: 0};
    S.cur = cur;
    setMain(null, [el('p', {cls: 'muted', text: 'Loading the session…'})]);
    const ir = await api('session', {sid: sid});
    if (gen !== S.gen) return;
    if (ir.status !== 200) { setMain('Session', [el('p', {cls: 'err', text: errorText(ir.status, ir.body).text}), back()]); return; }
    cur.info = ir.body;
    const got = await loadAll(sid, gen, cur.events);
    if (got === null) return;
    if (got.error) { setMain('Session', [el('p', {cls: 'err', text: errorText(got.error.status, got.error.body).text}), back()]); return; }
    cur.after = got.after;
    cur.cut = got.cut;
    for (const e of cur.events) cur.byId[e.event_id] = e;
    cur.model = foldEvents(cur.events);
    buildSession(cur);
    cur.select = (id) => { cur.selected = id || null; drawInspector(cur); drawLanes(cur); };
    // One long-poll at a time (§3.3): a kick supersedes the running loop (its token changes, its request is
    // aborted), so a decision during a held request never leaves two loops behind.
    cur.kick = () => {
      cur.loop += 1;
      if (cur.abort) cur.abort.abort();
      if (cur.timer) { clearTimeout(cur.timer); cur.timer = null; }
      schedule(cur, gen, 0, POLL.LONG_WAIT_S);
    };
    const st = pollNext(cur.poll, {ok: true, active: !!cur.info.active, got: 0}, Date.now());
    cur.poll = st.state;
    if (st.delay !== null) schedule(cur, gen, st.delay, st.wait);
  }
  function back() { return el('p', {}, [el('a', {text: '← All sessions', attrs: {href: '#/'}})]); }
  function schedule(cur, gen, delay, wait) {
    const me = cur.loop;
    cur.timer = setTimeout(() => tick(cur, gen, wait, me), delay);
  }
  async function tick(cur, gen, wait, me) {
    const gone = () => gen !== S.gen || me !== cur.loop;   // another view, or a kick started a newer loop
    if (gone()) return;
    cur.timer = null;
    if (document.hidden) { cur.poll = pollNext(cur.poll, {hidden: true}, Date.now()).state; return; }   // kicked on return
    cur.abort = new AbortController();
    const t0 = Date.now();
    let r;
    try {
      r = await api('events', {sid: cur.sid}, {query: {after: cur.after, wait: wait || null}, signal: cur.abort.signal});
    } catch (e) { return; }
    if (gone()) return;
    const ok = r.status === 200 && isObj(r.body) && Array.isArray(r.body.events);
    const got = ok ? r.body.events : [];
    if (got.length) {
      const fresh = got.filter((e) => isObj(e) && isInt(e.event_id) && e.event_id > cur.after);
      for (const e of fresh) { cur.events.push(e); cur.byId[e.event_id] = e; }
      if (fresh.length) {
        cur.after = fresh[fresh.length - 1].event_id;
        cur.model = foldEvents(fresh, cur.model);
      }
    }
    const ending = got.some((e) => e.event === 'session_revoked') || (cur.model.stop && !cur.info.active);
    if (got.length || ending) {
      const ir = await api('session', {sid: cur.sid});
      if (gone()) return;
      if (ir.status === 200) cur.info = ir.body;
      refresh(cur);
    }
    const expS = cur.info && isNum(cur.info.exp) ? cur.info.exp - Date.now() / 1000 : null;
    const st = pollNext(cur.poll, {ok: ok, active: !!(cur.info && cur.info.active), got: got.length,
                                   elapsed: Date.now() - t0, expS: expS}, Date.now());
    cur.poll = st.state;
    if (!ok && r.status === 404) return;         // the session is not this person's (any more)
    if (gone()) return;
    if (st.delay !== null) schedule(cur, gen, st.delay, st.wait);
  }

  function buildSession(cur) {
    const header = el('section', {cls: 'panel head', attrs: {id: 'sess-head'}});
    const graph = el('section', {cls: 'panel'}, [el('h3', {text: 'Agents'}),
      el('p', {cls: 'muted small', text: 'Click an agent to show only its lanes; click the background to show all.'}),
      el('div', {cls: 'graph', attrs: {id: 'graph', role: 'img', 'aria-label': 'Agent graph'}})]);
    const zin = el('button', {text: 'Zoom in'}), zout = el('button', {text: 'Zoom out'}), zall = el('button', {text: 'Whole session'});
    const lanesBox = el('div', {cls: 'lanes', attrs: {id: 'lanes'}});
    const lanesPanel = el('section', {cls: 'panel'}, [el('h3', {text: 'Timeline'}),
      el('div', {cls: 'toolbar'}, [zin, zout, zall, el('span', {cls: 'muted small', attrs: {id: 'lane-filter'}})]), lanesBox]);
    const insp = el('section', {cls: 'panel', attrs: {id: 'inspector'}});
    const side = el('section', {cls: 'panel', attrs: {id: 'work'}});
    setMain(null, [back(), header, el('div', {cls: 'grid2'}, [graph, side]), lanesPanel, insp]);
    zin.addEventListener('click', () => { cur.view = zoomView(cur.view, lanes(cur.model, nowFor(cur)), 0.5); drawLanes(cur); });
    zout.addEventListener('click', () => { cur.view = zoomView(cur.view, lanes(cur.model, nowFor(cur)), 2); drawLanes(cur); });
    zall.addEventListener('click', () => { cur.view = null; drawLanes(cur); });
    let drag = null;
    lanesBox.addEventListener('pointerdown', (e) => { drag = {x: e.clientX, view: cur.view}; });
    window.addEventListener('pointerup', () => { drag = null; });
    lanesBox.addEventListener('pointermove', (e) => {
      if (!drag || !drag.view || !cur.scale) return;
      const per = (cur.scale.to - cur.scale.from) / Math.max(1, cur.scale.right - cur.scale.left);
      cur.view = panView(drag.view, lanes(cur.model, nowFor(cur)), -(e.clientX - drag.x) * per);
      drawLanes(cur);
    });
    lanesBox.addEventListener('click', (e) => {
      const t = e.target && e.target.getAttribute ? e.target.getAttribute('data-event') : null;
      if (t && /^[0-9]+$/.test(t)) location.hash = routeHash({view: 'session', sid: cur.sid, event: +t});
    });
    refresh(cur);
  }
  function nowFor(cur) { return cur.info && cur.info.active ? Date.now() : null; }
  function refresh(cur) {
    drawHead(cur);
    drawGraph(cur);
    drawLanes(cur);
    drawWork(cur);
    drawInspector(cur);
  }
  function drawHead(cur) {
    const h = $('sess-head');
    if (!h) return;
    const i = cur.info || {}, m = cur.model;
    const st = sessionState(i, Date.now());
    const acts = actionsFor(i, S.me, m);
    const buttons = el('div', {cls: 'toolbar'});
    if (acts.stop) buttons.appendChild(el('button', {cls: 'danger', text: 'Stop', on: {click: () => doStop(cur)}}));
    if (acts.replay) buttons.appendChild(el('a', {cls: 'button', text: 'Replay', attrs: {href: routeHash({view: 'replay', sid: cur.sid})}}));
    if (acts.reexecute) buttons.appendChild(el('button', {text: 'Re-execute', on: {click: () => doReexecute(cur)}}));
    const prevContent = $('otel-content');   // the header is redrawn on every live update: keep the tick
    const content = el('input', {attrs: {type: 'checkbox', id: 'otel-content'}});
    content.checked = !!(prevContent && prevContent.checked);
    buttons.appendChild(el('button', {text: 'Download OTel', on: {click: () => doOtel(cur, content.checked)}}));
    buttons.appendChild(el('label', {cls: 'small', text: ' with content'}, [content]));
    const reex = i.reexecutes || (m.mint && m.mint.reexecutes);
    const bars = el('div', {cls: 'bars'});
    const wall = {start: parseAt(i.created_at || '') || (m.mint ? m.mint.at : null),
                  end: isNum(i.exp) ? i.exp * 1000 : parseAt(String(i.exp || '')), now: Date.now()};
    for (const b of budgetBars(i.budget, i.spent, wall)) bars.appendChild(bar(b));
    h.replaceChildren(
      el('h2', {}, [el('span', {text: (i.profile || (m.mint && m.mint.profile) || 'Session') + ' '}),
                    el('span', {cls: 'pill ' + st.state, text: st.text})]),
      el('p', {cls: 'muted small mono', text: cur.sid}),
      el('p', {cls: 'small', text: 'Model: ' + (i.backend || (m.mint && m.mint.backend) || '') +
              (m.mint && m.mint.code_commit ? ' · code ' + m.mint.code_commit : '') +
              (i.sup_username ? ' · supervisor ' + i.sup_username + (i.sup_role ? ' (' + i.sup_role + ')' : '') : '') +
              (m.stop ? ' · the lead stopped: ' + m.stop.reason : '') + (cur.cut ? ' · trace cut at ' + EVENTS_CAP + ' events' : '')}),
      reex ? el('p', {cls: 'small'}, [el('span', {text: 'Re-executes '}),
        el('a', {text: String(reex).slice(0, 8), attrs: {href: routeHash({view: 'session', sid: reex})}}),
        el('span', {text: ' · '}), el('a', {text: 'compare turn by turn', attrs: {href: routeHash({view: 'compare', a: reex, b: cur.sid})}})]) : null,
      bars, buttons);
  }

  function graphStyle() {
    const ink = token('--ink'), line = token('--line'), panel = token('--panel'), accent = token('--accent');
    return [
      {selector: 'node', style: {'label': 'data(label)', 'text-wrap': 'wrap', 'text-valign': 'center', 'text-halign': 'center',
        'font-size': 11, 'color': ink, 'background-color': panel, 'border-width': 2, 'border-color': line,
        'shape': 'round-rectangle', 'width': 120, 'height': 42}},
      {selector: 'node.server', style: {'shape': 'ellipse', 'width': 110, 'height': 34, 'border-style': 'dashed'}},
      {selector: 'node.running', style: {'border-color': token('--ok')}},
      {selector: 'node.waiting', style: {'border-color': token('--warn'), 'border-width': 3}},
      {selector: 'node.stopped', style: {'border-color': token('--muted')}},
      {selector: 'node:selected', style: {'border-color': accent, 'border-width': 4}},
      {selector: 'edge', style: {'width': 1.5, 'line-color': line, 'target-arrow-color': line, 'target-arrow-shape': 'triangle',
        'curve-style': 'bezier', 'label': 'data(label)', 'font-size': 9, 'color': token('--muted'), 'text-wrap': 'ellipsis',
        'text-max-width': 140, 'text-background-color': token('--bg'), 'text-background-opacity': 0.8}},
      {selector: 'edge.delegate', style: {'width': 2.5, 'line-color': accent, 'target-arrow-color': accent}},
    ];
  }
  function styleGraph() { if (S.cy) S.cy.style(graphStyle()); }
  function drawGraph(cur) {
    const box = $('graph');
    if (!box) return;
    if (typeof cytoscape !== 'function') { box.textContent = 'The graph library did not load.'; return; }
    const g = graphElements(cur.model);
    const key = g.nodes.map((n) => n.data.id).join('|') + '#' + g.edges.map((x) => x.data.id).join('|');
    if (!S.cy) {
      S.cy = cytoscape({container: box, elements: [], style: graphStyle(), userZoomingEnabled: true, wheelSensitivity: 0.3,
                        boxSelectionEnabled: false, autoungrabify: true});
      S.cy.on('tap', 'node', (ev) => {
        const ag = ev.target.data('agent');
        cur.filter = ag || null;
        drawLanes(cur);
      });
      S.cy.on('tap', (ev) => { if (ev.target === S.cy) { cur.filter = null; drawLanes(cur); } });
      cur.graphKey = null;
    }
    if (cur.graphKey !== key) {
      S.cy.elements().remove();
      S.cy.add(g.nodes.concat(g.edges));
      S.cy.layout({name: 'breadthfirst', directed: true, roots: S.cy.getElementById('agent:a0'), spacingFactor: 1.1,
                   padding: 12}).run();
      cur.graphKey = key;
    } else {
      for (const n of g.nodes.concat(g.edges)) {
        const x = S.cy.getElementById(n.data.id);
        x.data(n.data);
        x.classes(n.classes);
      }
    }
  }

  function drawLanes(cur) {
    const box = $('lanes');
    if (!box) return;
    const lz = lanes(cur.model, nowFor(cur));
    const d = laneSvg(lz, Math.max(640, box.clientWidth || 800), cur.view, cur.filter);
    cur.scale = d.scale;
    const svg = svgFrom(d);
    if (cur.selected) {
      for (const n of svg.querySelectorAll('[data-event="' + Number(cur.selected) + '"]')) n.classList.add('selected');
    }
    box.replaceChildren(svg);
    const f = $('lane-filter');
    if (f) f.textContent = cur.filter ? 'Showing ' + cur.filter + ' and its specialists' : '';
  }

  function drawInspector(cur) {
    const box = $('inspector');
    if (!box) return;
    const e = cur.selected ? cur.byId[cur.selected] : null;
    if (!e) {
      box.replaceChildren(el('h3', {text: 'Inspector'}), el('p', {cls: 'muted', text: 'Click a span or a marker in the timeline to read its event.'}));
      return;
    }
    const v = inspect(e, cur.model, cur.info);
    const tbl = el('table', {cls: 'kv'});
    for (const r of v.rows) tbl.appendChild(el('tr', {}, [el('th', {text: r[0]}), el('td', {cls: 'mono', text: String(r[1])})]));
    const blocks = v.blocks.map((b) => el('details', {attrs: b.title === 'Payload' ? {} : {open: ''}},
                                          [el('summary', {text: b.title}), el('pre', {text: b.text})]));
    box.replaceChildren(el('h3', {text: 'Inspector: ' + v.title}), tbl, ...blocks);
  }

  function drawWork(cur) {               // gates, campaigns and proposals of the session
    const box = $('work');
    if (!box) return;
    const m = cur.model, i = cur.info || {};
    const acts = actionsFor(i, S.me, m);
    // redrawn only when what it shows changes, so a note or a cap being typed survives the live updates
    const key = canonical([acts, isObj(i.spent) ? i.spent.cpu_hours : null, Object.keys(m.campaigns).map((k) => {
      const c = m.campaigns[k];
      return [k, c.state, c.gate, c.cpu_hours, c.decided_by, c.agent];
    }), Object.keys(m.proposals).map((k) => [k, !!m.proposals[k].decided])]);
    if (cur.workKey === key) return;
    cur.workKey = key;
    const nodes = [el('h3', {text: 'Gates, campaigns and proposals'})];
    const cids = Object.keys(m.campaigns);
    if (!cids.length && !Object.keys(m.proposals).length) nodes.push(el('p', {cls: 'muted', text: 'Nothing yet.'}));
    for (const cid of cids) {
      const c = m.campaigns[cid];
      const g = gateView(c, i.budget, i.spent);
      const card = el('div', {cls: 'card'}, [
        el('div', {cls: 'card-head'}, [el('a', {cls: 'mono', text: 'campaign ' + cid, attrs: {href: routeHash({view: 'campaign', sid: cur.sid, cid: cid})}}),
                                         el('span', {cls: 'pill ' + c.state, text: c.state})]),
        el('div', {cls: 'small', text: 'estimate ' + fmt(c.estimate_h) + ' CPU-h, cap ' + fmt(c.cap_h) +
                                       (c.runs !== null ? ', ' + c.runs + ' runs' : '') + (c.cpu_hours !== null ? ', used ' + fmt(c.cpu_hours) : '') +
                                       (c.agent ? ' · by ' + c.agent : '')})]);
      if (c.gate && c.gate !== 'pending') {
        card.appendChild(el('div', {cls: 'small muted', text: 'gate ' + c.gate + (c.decided_by ? ' by ' + c.decided_by : '') +
                                                               (c.approved_cap_h !== null ? ', cap ' + fmt(c.approved_cap_h) : '') +
                                                               (c.note ? ': ' + c.note : '')}));
      }
      if (g && g.pending) card.appendChild(gateForm(cur, g, acts.decideGates));
      nodes.push(card);
    }
    for (const pid of Object.keys(m.proposals)) nodes.push(proposalCard(cur, proposalView(m.proposals[pid]), acts.decideProposals));
    box.replaceChildren(...nodes);
  }
  function gateForm(cur, g, allowed) {
    const wrap = el('div', {cls: 'gate'}, [el('p', {cls: 'small', text: 'Waiting for you: approve with a cap of at most ' +
      fmt(g.limit) + ' CPU-hours (the server\'s cap' + (isNum(g.remaining) ? ', ' + fmt(g.remaining) + ' left in the session' : '') + '), or deny.'})]);
    if (!allowed) { wrap.appendChild(el('p', {cls: 'muted small', text: 'Your role does not decide gates.'})); return wrap; }
    const cap = el('input', {attrs: {type: 'number', step: '0.001', min: '0.001', value: g.suggested === null ? '' : g.suggested, 'aria-label': 'Cap in CPU-hours'}});
    const note = el('input', {attrs: {type: 'text', maxlength: '500', placeholder: 'note (recorded)', 'aria-label': 'Note'}});
    const why = el('p', {cls: 'err small'});
    const ok = el('button', {cls: 'primary', text: 'Approve'}), no = el('button', {cls: 'danger', text: 'Deny'});
    const check = () => { const pr = capProblems(cap.value, g, g.remaining); why.textContent = pr.join(' '); ok.disabled = pr.length > 0; };
    cap.addEventListener('input', check);
    const send = async (decision) => {
      ok.disabled = no.disabled = true;
      const body = {decision: decision, note: note.value};
      if (decision === 'approve') body.approved_cap_h = Number(cap.value);
      const r = await api('gate', {sid: cur.sid, gid: g.gid}, {body: body});
      if (r.status === 200) { toast('Gate ' + (decision === 'approve' ? 'approved' : 'denied') + '.'); cur.kick(); }
      else { failed(r); ok.disabled = no.disabled = false; check(); }
    };
    ok.addEventListener('click', () => send('approve'));
    no.addEventListener('click', () => send('deny'));
    check();
    wrap.append(el('label', {cls: 'small', text: 'Cap (CPU-h) '}, [cap]), note, ok, no, why);
    return wrap;
  }
  function checkTable(v) {
    if (!v) return el('p', {cls: 'muted small', text: 'No check in the document.'});
    const t = el('table', {cls: 'grid'});
    t.appendChild(el('tr', {}, ['Compared with', 'runs', 'proposed mean', 'its mean', 'outcome'].map((x) => el('th', {text: x}))));
    for (const r of v.rows) {
      t.appendChild(el('tr', {cls: r.better ? 'ok' : ''}, [el('td', {cls: 'mono', text: r.code + ' ' + r.params}),
        el('td', {text: String(r.runs)}), el('td', {text: fmt(r.proposed)}), el('td', {text: fmt(r.other)}), el('td', {text: String(r.outcome)})]));
    }
    return el('div', {}, [el('p', {cls: 'small', text: 'Criterion ' + v.criterion + (v.lowerIsBetter ? ' (lower is better)' : '') +
                                                       ': mean ' + fmt(v.proposedMean) + ' over ' + v.proposedRuns + ' run(s). Checked by ' + v.by +
                                                       (v.more ? ' · ' + v.more + ' more not listed' : '')}), t]);
  }
  function proposalCard(cur, v, allowed) {
    const card = el('div', {cls: 'card'}, [
      el('div', {cls: 'card-head'}, [el('span', {cls: 'mono', text: 'proposal ' + v.pid}), el('span', {cls: 'pill ' + v.state, text: v.state})]),
      el('div', {cls: 'mono small', text: (v.code || '') + ' ' + v.params + ' · from ' + v.agent}),
      v.rationale ? el('blockquote', {cls: 'small', text: v.rationale}) : null,
      el('div', {cls: 'small'}, v.evidence.map((x) => el('a', {cls: 'mono', text: x.cid + ' ', attrs: {href: routeHash({view: 'campaign', sid: cur.sid, cid: x.cid})}}))),
      checkTable(v.check)]);
    if (v.decided) card.appendChild(el('p', {cls: 'small muted', text: v.state + (v.decided.by ? ' by ' + v.decided.by : '') + (v.decided.note ? ': ' + v.decided.note : '')}));
    else if (allowed) {
      const note = el('input', {attrs: {type: 'text', maxlength: '500', placeholder: 'note (recorded)', 'aria-label': 'Note'}});
      const send = async (decision, btns) => {
        btns.forEach((b) => { b.disabled = true; });
        const r = await api('proposal', {sid: cur.sid, pid: v.pid}, {body: {decision: decision, note: note.value}});
        if (r.status === 200) { toast('Proposal ' + (decision === 'approve' ? 'accepted' : 'discarded') + '.'); cur.kick(); }
        else { failed(r); btns.forEach((b) => { b.disabled = false; }); }
      };
      const a = el('button', {cls: 'primary', text: 'Accept'}), d = el('button', {cls: 'danger', text: 'Discard'});
      a.addEventListener('click', () => send('approve', [a, d]));
      d.addEventListener('click', () => send('deny', [a, d]));
      card.append(note, a, d);
    }
    return card;
  }

  async function doStop(cur) {
    if (!confirm('Stop this session? Its agent and simulation Jobs end now.')) return;
    const r = await api('stop', {sid: cur.sid}, {body: {}});
    if (r.status === 200) { toast('The session is stopped.'); cur.kick(); } else failed(r);
  }
  async function doReexecute(cur) {
    const r = await api('reexecute', {sid: cur.sid}, {body: {}});
    if (r.status === 201 && isObj(r.body) && SID_RE.test(String(r.body.sid))) location.hash = routeHash({view: 'session', sid: r.body.sid});
    else failed(r);
  }
  async function doOtel(cur, content) {
    const r = await api('otel', {sid: cur.sid}, {query: {content: content ? 1 : null}, raw: true});
    if (!r.blob) { failed(r); return; }
    const url = URL.createObjectURL(r.blob);
    const a = el('a', {attrs: {href: url, download: 'session-' + cur.sid + '-otel' + (content ? '-content' : '') + '.json'}});
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  }

  // ── view 4: a campaign and a run's chamber series
  async function sessionEvents(sid, gen) {
    const evs = [];
    const got = await loadAll(sid, gen, evs);
    return got && !got.error ? evs : null;
  }
  async function viewCampaign(sid, cid) {
    const gen = S.gen;
    setMain('Campaign ' + cid, [el('p', {cls: 'muted', text: 'Loading…'})]);
    const [cr, evs] = await Promise.all([api('campaign', {sid: sid, cid: cid}, {query: {limit: 50}}), sessionEvents(sid, gen)]);
    if (gen !== S.gen) return;
    const m = evs ? foldEvents(evs) : emptyModel();
    const c = m.campaigns[cid] || null;
    const nodes = [el('p', {}, [el('a', {text: '← the session', attrs: {href: routeHash({view: 'session', sid: sid})}})])];
    if (c) nodes.push(el('p', {cls: 'small', text: 'state ' + c.state + ' · estimate ' + fmt(c.estimate_h) + ' · cap ' + fmt(c.cap_h) +
                                                   ' · used ' + fmt(c.cpu_hours) + ' CPU-h · result digest ' + (c.result_digest || '–')}));
    let table = null, runs = null, series = null;
    const after = [];
    if (cr.status === 200 && isObj(cr.body)) {
      const pending = {running: 'The campaign is still running.',
                       approved: 'The gate is approved; the simulation has not started yet.',
                       waiting: 'The gate waits for the supervisor.'}[cr.body.state];
      if (pending) nodes.push(el('p', {cls: 'muted', text: pending}));
      table = isObj(cr.body.by_setting) ? cr.body.by_setting : null;
      runs = isObj(cr.body.runs) ? cr.body.runs : null;
      series = cr.body.series || null;
      if (isObj(cr.body.manifest)) nodes.push(el('details', {}, [el('summary', {text: 'Manifest'}), el('pre', {text: JSON.stringify(cr.body.manifest, null, 2)})]));
    } else {
      nodes.push(el('p', {cls: 'muted small', text: errorText(cr.status, cr.body).text + (c && c.by_setting ? ' The table below is what sim.results answered the agent.' : '')}));
      table = c ? c.by_setting : null;
    }
    const prop = Object.keys(m.proposals).map((k) => m.proposals[k]).find((p) => p.doc && Array.isArray(p.doc.evidence) &&
                                                                              p.doc.evidence.some((x) => isObj(x) && x.cid === cid));
    if (table) {
      const crit = criteriaOf(table);
      const sel = el('select', {attrs: {'aria-label': 'Criterion'}});
      for (const k of crit) sel.appendChild(el('option', {text: k, attrs: {value: k}}));
      const want = prop && prop.doc.check && prop.doc.check.criterion;
      if (want && crit.indexOf(want) >= 0) sel.value = want;
      const box = el('div', {cls: 'plot'});
      const draw = () => {
        const d = bySettingPlot(table, sel.value, {width: Math.max(480, box.clientWidth || 640),
          proposed: prop ? {code: prop.doc.algorithm_code, params: prop.doc.params} : null});
        box.replaceChildren(d.problems.length ? el('p', {cls: 'err', text: d.problems.join(' ')}) : svgFrom(d));
      };
      sel.addEventListener('change', draw);
      nodes.push(el('section', {cls: 'panel'}, [el('h3', {text: 'Settings'}), el('label', {text: 'Criterion '}, [sel]),
        el('p', {cls: 'muted small', text: (table.means_of || '') + (prop ? ' · the proposed setting is marked' : '')}), box]));
      after.push(draw);                 // once the box is in the page (its width)
    }
    if (runs && Array.isArray(runs.rows)) {
      const t = el('table', {cls: 'grid'});
      t.appendChild(el('tr', {}, ['#', 'scenario', 'code', 'params', 'seed', 'valid', 'energy_wh', 'loops'].map((x) => el('th', {text: x}))));
      runs.rows.forEach((r, k) => {
        const n = (runs.offset || 0) + k;
        const link = series ? el('a', {text: String(n), attrs: {href: routeHash({view: 'run', sid: sid, cid: cid, n: n})}}) : el('span', {text: String(n)});
        t.appendChild(el('tr', {}, [el('td', {}, [link]), el('td', {text: String(r.scenario || '')}), el('td', {text: String(r.code || '')}),
          el('td', {cls: 'mono', text: canonical(r.params || {})}), el('td', {text: String(r.seed)}), el('td', {text: String(r.valid)}),
          el('td', {text: fmt(r.energy_wh)}), el('td', {cls: 'mono small', text: canonical(r.loops || {})})]));
      });
      nodes.push(el('section', {cls: 'panel'}, [el('h3', {text: 'Runs (' + runs.total + ')'}), t]));
    }
    setMain('Campaign ' + cid, nodes);
    for (const f of after) f();
  }
  async function viewRun(sid, cid, n) {
    const gen = S.gen;
    setMain('Run ' + n + ' of ' + cid, [el('p', {cls: 'muted', text: 'Loading the series…'})]);
    const r = await api('series', {sid: sid, cid: cid, n: n}, {query: {points: 2000}});
    if (gen !== S.gen) return;
    const nodes = [el('p', {}, [el('a', {text: '← the campaign', attrs: {href: routeHash({view: 'campaign', sid: sid, cid: cid})}})])];
    if (r.status !== 200 || !isObj(r.body)) { setMain('Run ' + n, nodes.concat([el('p', {cls: 'err', text: errorText(r.status, r.body).text})])); return; }
    const rr = await api('run', {sid: sid, cid: cid, n: n});
    if (gen !== S.gen) return;
    if (rr.status === 200 && isObj(rr.body)) nodes.push(el('details', {}, [el('summary', {text: 'The result row'}), el('pre', {text: JSON.stringify(rr.body, null, 2)})]));
    const width = Math.max(480, ($('main').clientWidth || 800) - 40);
    const u = seriesToUplot(decimate(r.body, width), null);
    nodes.push(el('p', {cls: 'small muted', text: u.points + ' points every ' + u.every_s + ' s; ' + u.changes + ' switches kept whole' +
                                                   (u.metricsFromH !== null ? '; metrics from ' + fmt(u.metricsFromH, 3) + ' h' : '') +
                                                   (u.error ? '; the recorder stopped: ' + u.error.reason : '')}));
    const boxes = u.panels.map((p) => { const b = el('div', {cls: 'plot'}); nodes.push(el('section', {cls: 'panel'}, [el('h3', {text: p.title}), b])); return [p, b]; });
    setMain('Run ' + n + ' of ' + cid, nodes);
    if (typeof uPlot !== 'function') return;
    const colours = {truth: token('--accent'), value: token('--ok'), band: token('--muted'), energy: token('--warn'),
                     cmd: token('--bad'), light: token('--warn'), relays: token('--accent')};
    for (const [p, b] of boxes) {
      const series = [{label: 'hours'}].concat(p.series.map((s) => ({label: s.label, stroke: colours[s.cls] || token('--ink'), width: 1.5,
        paths: p.step ? uPlot.paths.stepped({align: 1}) : undefined, dash: s.cls === 'band' ? [4, 4] : undefined})));
      const opts = {width: Math.max(320, b.clientWidth || width), height: p.step ? 160 : 220, series: series,
        axes: [{stroke: token('--muted'), grid: {stroke: token('--line')}}, {stroke: token('--muted'), grid: {stroke: token('--line')}}],
        bands: p.band ? [{series: p.band, fill: token('--band')}] : undefined, legend: {live: false}};
      S.plots.push(new uPlot(opts, p.data, b));
    }
  }

  // ── view 5: replay
  async function viewReplay(sid) {
    const gen = S.gen;
    setMain('Replay', [el('p', {cls: 'muted', text: 'Starting the replay…'})]);
    const evs = await sessionEvents(sid, gen);
    if (gen !== S.gen) return;
    const deadline = Date.now() + 600000;
    for (;;) {
      const r = await api('replay', {sid: sid}, {body: {}});
      if (gen !== S.gen) return;
      if (r.status === 202) {
        setMain('Replay', [el('p', {text: replayView(evs, {state: 'running'}).text})]);
        if (Date.now() > deadline) { setMain('Replay', [el('p', {cls: 'err', text: 'The replay did not finish within 10 minutes.'})]); return; }
        await new Promise((res) => setTimeout(res, 5000));
        continue;
      }
      if (r.status !== 200) { setMain('Replay', [el('p', {cls: 'err', text: errorText(r.status, r.body).text}), back()]); return; }
      const v = replayView(evs || [], r.body);
      const list = el('ol', {cls: 'record', attrs: {start: '0'}});
      let target = null;
      agentRecord(evs || []).forEach((e, k) => {
        const li = el('li', {cls: k === v.index ? 'mismatch' : ''}, [el('span', {cls: 'mono', text: '#' + e.event_id + ' '}),
          el('span', {text: e.event + ' ' + agentOf(e.payload) + ' '}), el('span', {cls: 'muted small', text: short(JSON.stringify(e.payload), 140)})]);
        if (k === v.index) target = li;
        list.appendChild(li);
      });
      const nodes = [el('p', {}, [el('a', {text: '← the session', attrs: {href: routeHash({view: 'session', sid: sid})}})]),
                     el('p', {cls: v.state === 'ok' ? 'ok' : 'err', text: v.text})];
      if (v.state === 'mismatch') {
        const t = el('table', {cls: 'kv'});
        for (const [k, val] of [['Agent', v.agent], ['Event', v.event], ['Field', v.field], ['Recorded', v.recorded], ['Replayed', v.replayed]]) {
          t.appendChild(el('tr', {}, [el('th', {text: k}), el('td', {cls: 'mono', text: val === null ? '' : String(val)})]));
        }
        nodes.push(t);
      }
      nodes.push(el('h3', {text: 'The record'}), list);
      setMain('Replay', nodes);
      if (target) target.scrollIntoView({block: 'center'});
      return;
    }
  }

  // ── view 6: re-execution compared turn by turn
  async function viewCompare(a, b) {
    const gen = S.gen;
    setMain('Re-execution', [el('p', {cls: 'muted', text: 'Loading both sessions…'})]);
    const [ea, eb] = await Promise.all([sessionEvents(a, gen), sessionEvents(b, gen)]);
    if (gen !== S.gen) return;
    if (!ea || !eb) { setMain('Re-execution', [el('p', {cls: 'err', text: 'Both sessions must be yours and readable.'}), back()]); return; }
    const c = compareTurns(ea, eb);
    const ta = turnsOf(ea), tb = turnsOf(eb);
    const t = el('table', {cls: 'grid'});
    t.appendChild(el('tr', {}, ['turn', 'request', 'first answer', 'second answer', 'seconds'].map((x) => el('th', {text: x}))));
    const turns = Object.keys(ta).filter((k) => tb[k] !== undefined).map(Number).sort((x, y) => x - y);
    for (const n of turns) {
      const diff = n === c.first_different_answer || (c.ended && c.ended.turn === n);
      t.appendChild(el('tr', {cls: diff ? 'mismatch' : ''}, [el('td', {text: String(n)}),
        el('td', {cls: 'mono small', text: ta[n][0] === tb[n][0] ? 'same' : 'differs'}),
        el('td', {cls: 'mono small', text: String(ta[n][1] || '').slice(0, 12)}), el('td', {cls: 'mono small', text: String(tb[n][1] || '').slice(0, 12)}),
        el('td', {text: fmt(ta[n][2], 3) + ' / ' + fmt(tb[n][2], 3)})]));
    }
    setMain('Re-execution', [el('p', {}, [el('a', {text: a.slice(0, 8), attrs: {href: routeHash({view: 'session', sid: a})}}), el('span', {text: ' and '}),
                                          el('a', {text: b.slice(0, 8), attrs: {href: routeHash({view: 'session', sid: b})}})]),
      el('p', {text: c.turns_compared + ' turn(s) compared, ' + c.same_answers + ' with the same answer' + (c.rate !== null ? ' (rate ' + c.rate + ')' : '') +
                     (c.first_different_answer !== null ? '; the first different answer at turn ' + c.first_different_answer : '') +
                     (c.ended ? '; the comparison ends at turn ' + c.ended.turn + ': ' + c.ended.why : '')}), t]);
  }

  if (typeof document !== 'undefined') document.addEventListener('DOMContentLoaded', boot);
})();
