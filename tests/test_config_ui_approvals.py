#!/usr/bin/env python3
"""Approvals in the Configuration UI, offline (apps/frontend/html/index.html).

- The approvals-logic block (pure functions between /* approvals-logic:begin */ and
  /* approvals-logic:end */) runs under node (skipped without node): every queue kind maps
  to its approval RPC and argument names, return/withdraw likewise; each refusal the
  database raises maps to its plain-words text, and every source message is checked
  against the RAISE in apps/database/medcea_db_migrations.sql (a reworded RAISE breaks
  this test); every why_not_code approval_queue() returns has its own text;
  describeChange (I/U/D, recipe and step, JSON params), jsonKeyDiff, statusBadge, the
  history filters and the parameter-set form; a completed run (kind 'run', qp) maps to
  release_run(run, note), its refusals to their own texts, and its summary (runSummary)
  shows recipe, parameter set, creator, executors, attempts and cycles, never a log.
- Static: every /rpc/<fn> the page calls exists in the migration, is a function member of
  defaults.yaml and is held by a person role (the golden), with the expected holders for
  the approval functions; each RPC body's argument names match one overload exactly
  (PostgREST picks it by name); friendlyDbError no longer maps the shared approval
  refusals to the Q-table text; the page never PATCHes a status but to 'retired' and
  never DELETEs a recipe, step or parameter set; frozen definitions are guarded; the
  Scheduler's retention reminder links to the Approvals tab and its run list shows the
  Released badge from run_release.

Run: python3 tests/test_config_ui_approvals.py
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX = os.path.join(ROOT, "apps", "frontend", "html", "index.html")
MIG = os.path.join(ROOT, "apps", "database", "medcea_db_migrations.sql")
GOLDEN = os.path.join(ROOT, "tests", "iam-grants.golden.json")
POLICY = os.path.join(ROOT, "apps", "iam", "policy", "defaults.yaml")
NODE = shutil.which("node")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def logic_block(html):
    m = re.search(r"/\* approvals-logic:begin \*/(.*?)/\* approvals-logic:end \*/", html, re.S)
    assert m, "approvals-logic block missing"
    return m.group(1)


def friendly_db_error(html):
    m = re.search(r"(    function friendlyDbError\(msg\) \{.*?\n    \})\n", html, re.S)
    assert m, "friendlyDbError missing"
    return m.group(1)


# A refusal as the database words it (the RAISE format with its % filled in), the
# RAISE format it comes from (must be in the migration verbatim), and the text the
# page shows (a fragment).
REFUSALS = [
    ("not_own_author: p-qa changed medcea.recipe 5 since its last approval",
     "'not_own_author: % changed % % since its last approval'", "You changed this item"),
    ("not_own_author: p-qa proposed change 12",
     "'not_own_author: % proposed change %'", "You proposed this change. Another qa person"),
    ("not_own_author: p-qa proposed change 12; withdraw it instead",
     "'not_own_author: % proposed change %; withdraw it instead'", "withdraw it under My proposals"),
    ("unattributed changes: 2 change(s) to medcea.recipe 5 have no person; re-create it to approve it",
     "'unattributed changes: % change(s) to % % have no person; re-create it to approve it'", "copy it into a new draft"),
    ("role engineer holds no approval on recipes",
     "'role % holds no approval on %'", "Your role cannot approve recipes; qa approves."),
    ("approvals are made by a person signed in through the API, not by person via svc_scheduler",
     "'approvals are made by a person signed in through the API, not by %'", "your own sign-in at the database"),
    ("the approver's token carries no person_id",
     "'the approver''s token carries no person_id'", "no person_id"),
    ("parameter set 3: its algorithm 2 is not approved",
     "'parameter set %: its algorithm % is not approved'", "Approve its control algorithm first."),
    ("medcea.recipe 5 is approved, not a draft",
     "'% % is %, not a draft'", "Already approved or retired meanwhile"),
    ("approve_change: no pending change 12",
     "'approve_change: no pending change %'", "no longer exists; the list was refreshed"),
    ("return_change: no pending change 12",
     "'return_change: no pending change %'", "no longer exists; the list was refreshed"),
    ("approve_change: change 12 is no longer pending",
     "'approve_change: change % is no longer pending'", "already applied, returned, withdrawn or replaced"),
    ("withdraw_change: change 12 is no longer pending",
     "'withdraw_change: change % is no longer pending'", "already applied, returned, withdrawn or replaced"),
    ("return_change: change 12 applied at once; review it (approve_change)",
     "'return_change: change % applied at once; review it (approve_change)'", "mark it reviewed"),
    ("withdraw_change: change 12 applied at once; propose the opposite instead",
     "'withdraw_change: change % applied at once; propose the opposite instead'", "propose the opposite"),
    ("withdraw_change: change 12 is not a proposal of yours",
     "'withdraw_change: change % is not a proposal of yours'", "Only the person who proposed it"),
    ("return_change: a reason is required",
     "'return_change: a reason is required'", "Give a reason."),
    ("return_change: medcea.recipe 5 was returned and has not changed since",
     "'return_change: % % was returned and has not changed since'", "Already returned"),
    ("retention: log_delete_days = 29 is below the minimum (log_compress_days >= 1, log_delete_days >= 30)",
     "'retention: %s = %s is below the minimum (log_compress_days >= 1, log_delete_days >= 30)'", "Below the minimum retention"),
    ("approve_change: change 12 changes nothing: unit UNIT01 is already on",
     "'approve_change: change % changes nothing: unit % is already %'", "would change nothing"),
    ("commissioning: unit UNIT01 has run 7 in R; flag it when no run is running or scheduled",
     "'commissioning: unit %s has run %s in %s; flag it when no run is running or scheduled'",
     "commissioning: unit UNIT01 has run 7 in R"),
    ("approval_queue: read it in the Configuration UI with your own sign-in",
     "'approval_queue: read it in the Configuration UI with your own sign-in'", "your own sign-in only"),
    ("not_own_author: p-qp created, changed or executed run 9",
     "'not_own_author: % created, changed or executed run %'", "You created, changed or executed this run"),
    ("unattributed changes: 1 change(s) to run 9 have no person",
     "'unattributed changes: % change(s) to run % have no person'", "it cannot be released and stays unreleased"),
    ("no attributed history: no recorded person created or started run 9",
     "'no attributed history: no recorded person created or started run %'", "predates attribution"),
    ("release_run: run 9 is F, not completed",
     "'release_run: run % is %, not completed'", "not completed (status F)"),
    ("release_run: run 9 is missing, not completed",
     "'release_run: run % is %, not completed'", "no longer exists"),
    ("release_run: run 9 is already released",
     "'release_run: run % is already released'", "Already released meanwhile"),
    ("role qa holds no approval on runs",
     "'role % holds no approval on %'", "Your role cannot release runs; qp releases."),
    ("permission denied for function release_run", None, "Your role cannot release runs; qp releases."),
    ("permission denied for function approve_recipe", None, "Your role cannot approve or return this."),
    ("permission denied for function return_change", None, "Your role cannot approve or return this."),
]

RPC_ROWS = [
    {"kind": "recipe", "target": "medcea.recipe", "id": 5},
    {"kind": "algorithm", "target": "medcea.control_algorithm", "id": 2},
    {"kind": "params", "target": "medcea.unit_algorithm_params", "id": 3},
    {"kind": "setting", "target": "medcea.pending_change", "id": 12},
    {"kind": "commissioning", "target": "medcea.pending_change", "id": 13},
    {"kind": "run", "target": "medcea.recipe_run", "id": 9},
]

# A completed run as approval_queue() lists it for qp (kind 'run').
RUN_ROW = {
    "kind": "run", "target": "medcea.recipe_run", "id": 9, "label": "Lettuce on UNIT01", "state": "waiting",
    "may_approve": False, "why_not_code": "own_author", "may_return": False,
    "detail": {"run_id": 9, "status": "C", "unit_code": "UNIT01", "recipe_name": "Lettuce", "recipe_status": "approved",
               "recipe_approved_now": True, "recipe_approval_id": 41, "params_id": 3, "params_name": "PID gentle",
               "params_status": "retired", "params_approved_now": False, "params_approval_id": 44,
               "created_by": "pm", "created_by_role": "production_manager", "created_at": "2026-10-30T08:00:00Z",
               "executed_by": "op2", "executed_by_role": "operator",
               "executors": [{"by_name": "op1", "by_role": "operator", "at": "2026-10-30T09:00:00Z"},
                             {"by_name": "op2", "by_role": "operator", "at": "2026-10-30T12:00:00Z"}],
               "attempts": 2, "cycles": {"total": 5, "by_status": {"C": 4, "F": 1}},
               "start": "2026-10-30T12:00:00Z", "end": "2026-10-31T06:00:00Z"},
}

CHANGES = [
    {"change_id": 1, "target": "medcea.recipe", "row_key": [5], "op": "I",
     "new": {"recipe_id": 5, "recipe_name": "Lettuce", "is_active": "Y", "created_by_name": "eng"},
     "by_name": "eng", "by_role": "engineer", "by_source": "token", "at": "2026-10-31T10:00:00Z", "authors": True},
    {"change_id": 2, "target": "medcea.recipe_line", "row_key": [5, 3], "op": "U",
     "old": {"cycle_number": 7}, "new": {"cycle_number": 9},
     "by_name": "eng", "by_role": "engineer", "by_source": "token", "at": "2026-10-31T10:05:00Z", "authors": True},
    {"change_id": 3, "target": "medcea.recipe_line", "row_key": [5, 4], "op": "D",
     "old": {"recipe_id": 5, "recipe_item_seq_id": 4, "light_type": "RED"},
     "by_name": None, "by_role": None, "by_source": "db", "at": "2026-10-31T10:06:00Z", "authors": True},
    {"change_id": 4, "target": "medcea.unit_algorithm_params", "row_key": [3], "op": "U",
     "old": {"params": {"kp": 1, "ki": 0.1}}, "new": {"params": {"kp": 2, "kd": 0.5}},
     "by_name": "eng", "by_role": "engineer", "by_source": "token", "at": "2026-10-31T10:07:00Z", "authors": True},
    {"change_id": 5, "target": "medcea.recipe", "row_key": [5], "op": "U",
     "old": {"status": "approved"}, "new": {"status": "draft"},
     "by_name": "eng", "by_role": "engineer", "by_source": "token", "at": "2026-10-31T10:08:00Z", "authors": False},
]

HARNESS = r"""
const fs = require('fs');
const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const out = {};
out.rpc = input.rows.map(r => approvalRpc(r, '  checked  '));
out.rpcEmpty = approvalRpc(input.rows[0], '   ');
out.ret = input.rows.map(r => returnRpc(r, ' wrong limits '));
out.withdraw = [withdrawRpc(12, ''), withdrawRpc(12, ' not needed ')];
out.refusals = input.refusals.map(m => friendlyApprovalError(m));
out.whyNot = input.codes.map(c => approvalWhyNot(c, { kind: 'recipe', detail: { blocking_run_id: 7, blocking_run_status: 'R' } }));
out.whyNotPending = input.codes.map(c => approvalWhyNot(c, { kind: 'commissioning', detail: { blocking_run_id: 7, blocking_run_status: 'S' } }));
out.changes = input.changes.map(describeChange);
out.steps = [...changedSteps(input.changes)].sort();
out.diff = jsonKeyDiff({a: 1, b: 2, c: {x: 1}}, {b: 3, c: {x: 1}, d: null});
out.badges = ['draft', 'approved', 'retired', undefined].map(statusBadge);
out.frozen = ['draft', 'approved', 'retired'].map(isFrozen);
out.history = Object.keys(HISTORY_FILTERS).map(k => historyQuery(k, null));
out.historyItem = historyQuery('all', { target: 'medcea.recipe', id: 5 });
out.historyLabel = [historyLabel({ target: 'medcea.recipe', row_key: [5] }, { 'medcea.recipe': { 5: 'Recipe “L”' } }),
                    historyLabel({ target: 'medcea.recipe', row_key: [6] }, {})];
out.ps = [paramSetPayload({ name: ' PID gentle ', algorithm_id: '2', unit_id: '', params: '{"kp": 2}' }),
          paramSetPayload({ name: 'x', algorithm_id: '2', unit_id: '4', params: '' }),
          paramSetPayload({ name: '', algorithm_id: '2', unit_id: '', params: '{}' }),
          paramSetPayload({ name: 'x', algorithm_id: '', unit_id: '', params: '{}' }),
          paramSetPayload({ name: 'x', algorithm_id: '2', unit_id: '', params: '[1]' }),
          paramSetPayload({ name: 'x', algorithm_id: '2', unit_id: '', params: '{bad' })];
out.psDup = [paramSetPayload({ name: 'PID gentle', algorithm_id: '2', unit_id: '', params: '{}' }, input.sets, null),
             paramSetPayload({ name: 'PID gentle', algorithm_id: '2', unit_id: '', params: '{}' }, input.sets, 3),
             paramSetPayload({ name: 'pid gentle', algorithm_id: '2', unit_id: '', params: '{}' }, input.sets, null),
             paramSetPayload({ name: 'x'.repeat(121), algorithm_id: '2', unit_id: '', params: '{}' }, [], null),
             paramSetPayload({ name: 'x'.repeat(120), algorithm_id: '2', unit_id: '', params: '{}' }, [], null)];
out.copyName = [paramSetCopyName('PID gentle', ['PID gentle']),
                paramSetCopyName('PID gentle', ['PID gentle', 'PID gentle (copy)', 'PID gentle (copy 2)']),
                paramSetCopyName('y'.repeat(118), [])];
out.unitOpts = [paramSetUnitOptions([{ unit_id: 1, unit_code: 'U01' }], 7),
                paramSetUnitOptions([{ unit_id: 1, unit_code: 'U01' }], 1),
                paramSetUnitOptions([{ unit_id: 1, unit_code: 'U01' }], null)];
out.count = [approvalCount(
  [{ may_approve: true, state: 'waiting' }, { may_approve: true, state: 'returned', kind: 'recipe' },
   { may_approve: false, state: 'waiting' }, { may_approve: true, state: 'review', kind: 'commissioning' }],
  [{ state: 'returned', kind: 'recipe' }, { state: 'returned', kind: 'setting' }, { state: 'returned', kind: 'commissioning' },
   { state: 'waiting', kind: 'params' }]), approvalCount(null, null)];
out.pending = [pendingSummary({ kind: 'commissioning', state: 'waiting', detail: { current: false, proposed: true } }),
               pendingSummary({ kind: 'commissioning', state: 'waiting', detail: { current: true, proposed: true } }),
               pendingSummary({ kind: 'setting', state: 'waiting', detail: { current: '7', proposed: 14 } })];
out.retire = [retireError('role engineer holds no approval on controllers_state'), retireError('other')];
out.friendlyDb = input.dbMessages.map(m => friendlyDbError(m));
out.myState = ['waiting', 'returned', 'applied_review_pending', 'withdrawn', 'superseded'].map(myStateText);
out.run = runSummary(input.run);
out.runOk = runSummary(Object.assign({}, input.run, { may_approve: true, why_not_code: null,
  detail: Object.assign({}, input.run.detail, { params_id: null, executors: [], attempts: 0 }) }));
out.runLabel = approvalLabel(input.run);
out.runWhy = ['own_author', 'unattributed', 'no_person', 'no_attribution'].map(c => approvalWhyNot(c, input.run));
out.runCount = approvalCount([Object.assign({}, input.run, { may_approve: true }), input.run], []);
out.runChange = describeChange({ target: 'medcea.recipe_run', row_key: [9], op: 'U', old: { recipe_run_status: 'R' },
                                 new: { recipe_run_status: 'C' }, by_name: 'op2', at: '2026-10-31T06:00:00Z', authors: true });
console.log(JSON.stringify(out));
"""


@unittest.skipUnless(NODE, "node is not installed")
class ApprovalsLogicUnderNode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        html = read(INDEX)
        cls.mig = read(MIG)
        # the why_not codes approval_queue() can return
        q = cls.mig[cls.mig.index("FUNCTION medcea.approval_queue("):]
        q = q[:q.index("END $$;")]
        cases = "".join(re.findall(r"why_not_code := CASE(.*?) END;", q, re.S))
        cls.codes = sorted(set(re.findall(r"THEN '([a-z_]+)'", cases)))
        tmp = tempfile.mkdtemp()
        cls.addClassCleanup(shutil.rmtree, tmp)
        js = os.path.join(tmp, "harness.js")
        with open(js, "w", encoding="utf-8") as f:
            f.write(logic_block(html) + "\n" + friendly_db_error(html) + "\n" + HARNESS)
        data = os.path.join(tmp, "input.json")
        with open(data, "w", encoding="utf-8") as f:
            json.dump({"run": RUN_ROW, "sets": [{"params_id": 3, "name": "PID gentle"}], "rows": RPC_ROWS, "refusals": [r[0] for r in REFUSALS], "codes": cls.codes, "changes": CHANGES,
                       "dbMessages": ["approvals are made by a person signed in through the API, not by db",
                                      "role engineer holds no approval on controllers_state",
                                      "permission denied for function retire_algorithm_state"]}, f)
        subprocess.run([NODE, "--check", js], check=True, capture_output=True)
        r = subprocess.run([NODE, js, data], capture_output=True, text=True, timeout=30)
        if r.returncode:
            raise AssertionError(r.stderr)
        cls.out = json.loads(r.stdout)

    def test_codes_found(self):
        self.assertEqual(set(self.codes), {"algorithm_not_approved", "no_person", "no_role", "own_author", "unattributed",
                                           "retention_minimum", "no_change", "run_in_progress", "no_attribution"})

    def test_rpc_mapping(self):
        rpc = self.out["rpc"]
        self.assertEqual(rpc[0], {"path": "/rpc/approve_recipe", "body": {"p_recipe_id": 5, "p_note": "checked"}})
        self.assertEqual(rpc[1], {"path": "/rpc/approve_algorithm", "body": {"p_algorithm_id": 2, "p_note": "checked"}})
        self.assertEqual(rpc[2], {"path": "/rpc/approve_params", "body": {"p_params_id": 3, "p_note": "checked"}})
        for i, cid in ((3, 12), (4, 13)):
            self.assertEqual(rpc[i], {"path": "/rpc/approve_change",
                                      "body": {"p_target": "medcea.pending_change", "p_id": cid, "p_note": "checked"}})
        # a run: the 2-argument release_run, its note in run_release.note and approval.note
        self.assertEqual(rpc[5], {"path": "/rpc/release_run", "body": {"p_run_id": 9, "p_note": "checked"}})
        # an empty note is sent as null, so the 2-argument overload is still the one called
        self.assertEqual(self.out["rpcEmpty"]["body"], {"p_recipe_id": 5, "p_note": None})
        for row, ret in zip(RPC_ROWS, self.out["ret"]):
            self.assertEqual(ret, {"path": "/rpc/return_change",
                                   "body": {"p_target": row["target"], "p_id": row["id"], "p_reason": "wrong limits"}})
        self.assertEqual(self.out["withdraw"][0], {"path": "/rpc/withdraw_change", "body": {"p_id": 12, "p_reason": None}})
        self.assertEqual(self.out["withdraw"][1]["body"]["p_reason"], "not needed")

    def test_refusals_map_and_exist_in_migration(self):
        for (msg, raise_fmt, want), got in zip(REFUSALS, self.out["refusals"]):
            self.assertIn(want, got, msg)
            if raise_fmt:
                self.assertIn(raise_fmt, self.mig, f"the migration no longer raises {raise_fmt}")

    def test_why_not_texts(self):
        for code, text, ptext in zip(self.codes, self.out["whyNot"], self.out["whyNotPending"]):
            self.assertTrue(text and text != code, code)
            self.assertNotEqual(ptext, code)
        by = dict(zip(self.codes, self.out["whyNot"]))
        byp = dict(zip(self.codes, self.out["whyNotPending"]))
        self.assertIn("You changed this item", by["own_author"])
        self.assertIn("You proposed this change", byp["own_author"])
        self.assertIn("Run 7 is running", by["run_in_progress"])
        self.assertIn("Run 7 is scheduled", byp["run_in_progress"])
        self.assertIn("whole number of days", by["retention_minimum"])

    def test_describe_change(self):
        ins, upd, dele, js, status = self.out["changes"]
        self.assertEqual((ins["verb"], ins["subject"]), ("Created", "recipe"))
        self.assertNotIn("created_by_name", [f["label"] for f in ins["fields"]])
        self.assertIn({"label": "Name", "new": "Lettuce"}, [{k: f[k] for k in ("label", "new")} for f in ins["fields"]])
        self.assertEqual((upd["verb"], upd["subject"]), ("Changed", "step 3"))
        self.assertEqual(upd["fields"], [{"label": "Cycles", "old": 7, "new": 9}])
        self.assertIn("eng · engineer · token", upd["who"])
        self.assertEqual((dele["verb"], dele["subject"]), ("Removed", "step 4"))
        self.assertIn("no person", dele["who"])
        self.assertEqual([f["label"] for f in js["fields"]], ["Params.kd", "Params.ki", "Params.kp"])
        self.assertFalse(status["authors"])
        self.assertEqual(self.out["steps"], [3, 4])

    def test_run_summary(self):
        s = dict(self.out["run"])
        self.assertEqual(s["Run"], "#9 — completed")
        self.assertEqual(s["Unit"], "UNIT01")
        self.assertEqual(s["Recipe"], "Lettuce — approved; approval #41 in effect at its start")
        self.assertEqual(s["Parameter set"], "PID gentle — retired (not approved now); approval #44 in effect at its start")
        self.assertIn("pm (production_manager)", s["Created by"])
        self.assertIn("op1 (operator), 2026-10-30 09:00 UTC; op2 (operator), 2026-10-30 12:00 UTC", s["Executed by"])
        self.assertEqual(s["Attempts"], "2")
        self.assertEqual(s["Cycles"], "5 (4 completed, 1 failed)")
        self.assertEqual((s["Started"], s["Ended"]), ("2026-10-30 12:00 UTC", "2026-10-31 06:00 UTC"))
        self.assertIn("You cannot release it: You created, changed or executed this run", s["Release"])
        self.assertNotIn("log", " ".join(k.lower() for k in s))      # qp holds R on runs only: no run log
        ok = dict(self.out["runOk"])
        self.assertIn("You may release it: a recorded person created and started it", ok["Release"])
        self.assertEqual(ok["Parameter set"], "none recorded for this run")
        self.assertEqual(ok["Executed by"], "op2 (operator)")         # no recorded start: the run's column
        self.assertEqual(self.out["runLabel"], "Run #9 (Lettuce on UNIT01)")
        own, unattr, noperson, legacy = self.out["runWhy"]
        self.assertIn("predates attribution", legacy)
        self.assertIn("cannot be released", legacy)
        self.assertIn("Another qp person must release it", own)
        self.assertIn("cannot be released", unattr)
        self.assertIn("person_id", noperson)
        self.assertEqual(self.out["runCount"], 1)
        self.assertEqual(self.out["runChange"]["subject"], "run")
        self.assertEqual(self.out["runChange"]["fields"], [{"label": "recipe_run_status", "old": "R", "new": "C"}])

    def test_json_key_diff(self):
        self.assertEqual(self.out["diff"], [{"key": "a", "old": 1}, {"key": "b", "old": 2, "new": 3}, {"key": "d", "new": None}])

    def test_badges(self):
        self.assertEqual([b["cls"] for b in self.out["badges"]], ["badge-draft", "badge-y", "badge-retired", "badge-retired"])
        self.assertIn("waits for qa", self.out["badges"][0]["text"])
        self.assertEqual(self.out["frozen"], [False, True, True])

    def test_history(self):
        h = dict(zip(["all", "recipes", "algorithms", "params", "pending", "reviews", "releases", "qtables"], self.out["history"]))
        self.assertNotIn("target=", h["all"])
        self.assertIn("target=in.(medcea.recipe)", h["recipes"])
        self.assertIn("medcea.cea_unit", h["reviews"])
        self.assertIn("medcea.recipe_run", h["releases"])
        self.assertIn("medcea.algorithm_state", h["qtables"])
        for q in self.out["history"]:
            self.assertTrue(q.startswith("/approval?select="), q)
        self.assertIn("target=eq.medcea.recipe&row_key=eq.%5B5%5D", self.out["historyItem"])
        self.assertEqual(self.out["historyLabel"], ["Recipe “L”", "Recipe #6"])
        # every action the approval CHECK allows is one the history may show; the
        # targets the approval functions write are covered by a filter
        for t in re.findall(r"INSERT INTO medcea\.approval[^;]*?VALUES \('(medcea\.[a-z_]+)'", self.mig, re.S):
            self.assertTrue(any(t in q for q in self.out["history"][1:]), t)

    def test_param_set_payload(self):
        ok, ok2, noname, noalg, arr, bad = self.out["ps"]
        self.assertEqual(ok, {"body": {"name": "PID gentle", "algorithm_id": 2, "unit_id": None, "params": {"kp": 2}}})
        self.assertEqual(ok2["body"]["unit_id"], 4)
        self.assertEqual(ok2["body"]["params"], {})
        for r in (noname, noalg, arr, bad):
            self.assertIn("error", r)

    def test_param_set_name_rules(self):
        dup, own, case, long, edge = self.out["psDup"]
        self.assertIn("already exists", dup["error"])
        self.assertEqual(own["body"]["name"], "PID gentle")           # its own name, editing itself
        self.assertEqual(case["body"]["name"], "pid gentle")         # UNIQUE compares as stored
        self.assertIn("at most 120", long["error"])
        self.assertEqual(len(edge["body"]["name"]), 120)
        first, third, cut = self.out["copyName"]
        self.assertEqual(first, "PID gentle (copy)")
        self.assertEqual(third, "PID gentle (copy 3)")
        self.assertEqual(len(cut), 120)
        self.assertTrue(cut.endswith(" (copy)"))
        self.assertIn("uap_name_uk", self.mig)

    def test_param_set_unit_kept(self):
        gone, present, anyu = self.out["unitOpts"]
        self.assertEqual(gone[-1], {"value": "7", "label": "#7 (deleted unit)"})
        self.assertEqual(present, [{"value": "", "label": "Any unit"}, {"value": "1", "label": "U01"}])
        self.assertEqual(anyu, present)

    def test_approval_count(self):
        # queue: the approvable waiting row and the review, not the returned draft;
        # mine: the returned draft, never a returned (closed) proposal
        self.assertEqual(self.out["count"], [3, 0])

    def test_pending_and_states(self):
        self.assertEqual(self.out["pending"], ["commissioning off → on", "no change (already on)", "7 → 14 days"])
        self.assertEqual(self.out["myState"][1], "Returned by qa")

    def test_retire_mapping_is_narrow(self):
        self.assertIn("Retiring learned state", self.out["retire"][0])
        self.assertEqual(self.out["retire"][1], "other")
        approvals, retire_role, retire_fn = self.out["friendlyDb"]
        self.assertNotIn("Retiring", approvals)          # the generic approval refusal stays itself
        self.assertNotIn("Retiring", retire_role)
        self.assertIn("Retiring", retire_fn)


class ApprovalsStatic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = read(INDEX)
        cls.mig = read(MIG)
        cls.policy = read(POLICY)
        cls.golden = json.loads(read(GOLDEN))

    def holders(self, fn):
        return {r for r, t, o, p in self.golden["privileges"] if t == "function" and o.startswith(f"medcea.{fn}(") and p == "EXECUTE"}

    def signatures(self, fn):
        """The IN argument names of each overload of medcea.<fn> (with/without defaults)."""
        out = []
        for m in re.finditer(rf"CREATE (?:OR REPLACE )?FUNCTION medcea\.{fn}\(([^)]*)\)", self.mig):
            names, required = [], []
            for a in [x.strip() for x in m.group(1).split(",") if x.strip()]:
                if a.startswith("OUT "):
                    continue
                n = a.split()[0]
                names.append(n)
                if " DEFAULT " not in a.upper():
                    required.append(n)
            out.append((set(names), set(required)))
        return out

    def test_every_rpc_is_a_held_policy_function(self):
        fns = sorted(set(re.findall(r"/rpc/([a-z_]+)", self.html)))
        self.assertIn("approval_queue", fns)
        for fn in fns:
            self.assertTrue(self.signatures(fn), f"{fn} is not created by the migration")
            self.assertRegex(self.policy, rf'function: "medcea\.{fn}\(', f"{fn} is no function member of defaults.yaml")
            people = {r for r in self.holders(fn) if r.startswith("rr_")}
            self.assertTrue(people, f"no person role may execute {fn}")
        for fn in ("approve_recipe", "approve_algorithm", "approve_params", "approve_change", "return_change",
                   "retire_algorithm_state"):
            self.assertEqual({r for r in self.holders(fn) if r.startswith("rr_")}, {"rr_qa"}, fn)
        self.assertIn("release_run", fns)
        self.assertEqual(self.holders("release_run"), {"rr_qp"})
        self.assertEqual({r for r in self.holders("approval_queue") if r.startswith("rr_")}, {"rr_qa", "rr_qp", "rr_auditor"})
        self.assertIn("rr_engineer", self.holders("my_approvals"))
        self.assertIn("rr_admin", self.holders("withdraw_change"))
        if "propose_commissioning" in fns:
            self.assertEqual({r for r in self.holders("propose_commissioning") if r.startswith("rr_")}, {"rr_engineer"})

    def test_rpc_bodies_pick_one_overload(self):
        bodies = {
            "approve_recipe": {"p_recipe_id", "p_note"}, "approve_algorithm": {"p_algorithm_id", "p_note"},
            "approve_params": {"p_params_id", "p_note"}, "approve_change": {"p_target", "p_id", "p_note"},
            "return_change": {"p_target", "p_id", "p_reason"}, "withdraw_change": {"p_id", "p_reason"},
            "release_run": {"p_run_id", "p_note"},
        }
        for fn, keys in bodies.items():
            match = [s for s in self.signatures(fn) if s[1] <= keys <= s[0]]
            self.assertEqual(len(match), 1, f"{fn}{sorted(keys)} matches {len(match)} overloads")
            for k in keys:
                self.assertIn(k + ":", self.html.replace(" ", ""), f"{fn}: the page never sends {k}")
        # the probe's GET argument
        self.assertIn("/rpc/approval_queue?p_changes=false", self.html)
        self.assertTrue(any("p_changes" in s[0] and "p_changes" not in s[1] for s in self.signatures("approval_queue")))

    def test_friendly_db_error_narrowed(self):
        f = friendly_db_error(self.html)
        self.assertNotIn("approvals are made by a person", f)
        self.assertNotIn("holds no approval on controllers_state", f)
        self.assertIn("permission denied for function retire_algorithm_state", f)
        self.assertIn("retireError(e.raw || e.message)", self.html)
        self.assertIn("err.raw = msg", self.html)

    def test_no_status_patch_but_retire_and_no_delete(self):
        for m in re.finditer(r"api\('PATCH',[^;]*?\{([^}]*)\}", self.html):
            if "status" in m.group(1):
                self.assertRegex(m.group(1), r"^\s*status:\s*'retired'\s*$", m.group(0))
        self.assertNotRegex(self.html, r"status:\s*'(approved|draft)'")
        self.assertNotRegex(self.html, r"api\('DELETE',\s*'/(recipe|recipe_line|unit_algorithm_params)\b")
        self.assertNotIn("function deleteRecipe(", self.html)
        self.assertNotIn("function deleteRecipeLine(", self.html)

    def test_frozen_guards(self):
        freeze = self.html[self.html.index("function renderRecipeFreeze("):]
        freeze = freeze[:freeze.index("\n    }\n")]
        for el in ("recipe-save-btn", "recipe-addstep-btn", "recipe-del-btn", "el.disabled = frozen"):
            self.assertIn(el, freeze)
        self.assertIn("if (currentRecipeFrozen())", self.html)          # the step modal
        self.assertIn("(isFrozen(r.status) ? 'View' : 'Edit')", self.html)  # the list's header form
        self.assertIn("isFrozen(a.status)", self.html)                   # algorithm Save
        self.assertIn("ps-save-btn').classList.toggle('hidden', frozen)", self.html)

    def test_probe_never_reauths_and_tab_deep_link(self):
        probe = self.html[self.html.index("async function apprProbe("):]
        probe = probe[:probe.index("\n    }\n")]
        self.assertNotIn("api(", probe)
        self.assertNotIn("oauth2/start", probe)
        self.assertIn("PGRST202", probe)
        self.assertIn("location.hash === '#approvals'", self.html)
        self.assertIn("'approvals'].forEach", self.html)

    def test_page_configmap_is_not_applied(self):
        # kubectl apply copies the page into last-applied (256 KiB max): the 31 Oct 2026
        # deploy failed with "metadata.annotations: Too long"; replace/create has no limit
        # but ConfigMap's 1 MiB
        deploy = read(os.path.join(ROOT, "apps", "frontend", "deploy.sh"))
        step = deploy[deploy.index("create configmap config-ui-html"):]
        step = step[:step.index("\nfi\n")]
        self.assertNotIn("apply", step.split("--dry-run=client -o yaml)")[1])
        self.assertIn("replace -f -", step)
        self.assertLess(len(self.html.encode()), 900 * 1024)

    def test_return_confirm_and_badge(self):
        self.assertNotIn("leaves the queue until its author changes it", self.html)
        self.assertIn("stays in the queue, marked returned, until its author changes it", self.html)
        self.assertIn("const n = approvalCount(queue, mine);", self.html)
        self.assertIn("paramSetPayload({ name: f['name'].value", self.html)
        self.assertIn("}, paramSets, psModal.id);", self.html)
        self.assertIn("paramSetUnitOptions(psUnits, src ? src.unit_id : null)", self.html)
        self.assertIn("paramSetCopyName(src.name, paramSets.map(x => x.name))", self.html)
        self.assertNotIn("src.name + ' (copy)'", self.html)
        self.assertIn("A parameter set with that name already exists.", friendly_db_error(self.html))

    def test_scheduler_links_the_queue(self):
        sched = read(os.path.join(ROOT, "apps", "scheduler", "html", "scheduler.html"))
        self.assertIn("https://$CONFIG_DOMAIN/#approvals", sched)
        self.assertIn("showRetentionProposal(d)", sched)
        # a reminder per signed-in person that claims no live status
        self.assertIn("RETENTION_KEY + ':' + _retentionUser", sched)
        self.assertIn("fetch('/_account/api/me'", sched)
        self.assertNotIn("waits for a qa person other than you; the values above stay in force", sched)
        self.assertNotIn("localStorage.setItem(RETENTION_KEY,", sched)
        deploy = read(os.path.join(ROOT, "apps", "scheduler", "deploy.sh"))
        self.assertIn("html.replace('\\$CONFIG_DOMAIN', sys.argv[4])", deploy)

    def test_scheduler_released_badge(self):
        # the Released badge (who, when) on the completed runs and the run detail, from
        # run_release through the scheduler's own run reads; the page releases nothing
        sched = read(os.path.join(ROOT, "apps", "scheduler", "html", "scheduler.html"))
        self.assertIn("${statusBadge(r.recipe_run_status)}${releasedBadge(r)}", sched)
        self.assertIn("statusBadge(r.recipe_run_status) + releasedBadge(r)", sched)
        badge = sched[sched.index("function releasedBadge("):]
        badge = badge[:badge.index("\n}\n")]
        self.assertIn("escHtml(who)", badge)
        for col in ("released_at", "released_by_name", "released_by_role"):
            self.assertIn(col, badge)
        self.assertNotIn("release_run", sched)
        api = read(os.path.join(ROOT, "apps", "scheduler", "scheduler-api.py"))
        self.assertIn('LEFT JOIN medcea.run_release rl ON rl.recipe_run_id = rr.recipe_run_id', api)
        self.assertEqual(api.count("{_RELEASE_JOIN}"), 2)                # GET /api/runs and /api/runs/<id>

    def test_run_release_in_the_tab(self):
        self.assertIn("ab.textContent = r.kind === 'run' ? 'Release'", self.html)
        self.assertIn("A release is final", self.html)
        self.assertIn("'Release note (optional, recorded with the release).'", self.html)
        # the run's summary is approval_queue's detail: the page reads no run log
        self.assertNotIn("run_logs", self.html.split("/* approvals-logic:begin */")[1].split("/* approvals-logic:end */")[0])
        self.assertIn("'/recipe_run?select=recipe_run_id,unit_id'", self.html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
