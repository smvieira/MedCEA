#!/usr/bin/env python3
"""Commissioning (test mode) in the Configuration UI's Units tab, offline
(apps/frontend/html/index.html).

- The commissioning-logic block (between /* commissioning-logic:begin */ and
  /* commissioning-logic:end */) runs under node with the approvals-logic block (skipped
  without node): the cell per role and state (engineer off/on/run running or
  scheduled/own proposal/someone else's; qa pending, own pending, an "off" waiting for
  review; operator without names, reason or run; the read-only fallback), the history
  outcomes (applied, reviewed, returned, withdrawn, replaced, waiting), the RPC bodies
  and history paths, and each refusal in plain words: every source message is checked
  against the RAISE in apps/database/medcea_db_migrations.sql, and no commissioning
  refusal ever gets the Q-table retire text.
- Static: the page reads /rpc/unit_commissioning with its own catch (the tab still loads
  when it fails), proposes through /rpc/propose_commissioning with the argument names of
  its one overload, approves/returns through the Approvals tab's modal (approval_queue),
  withdraws with withdraw_change, never sends commissioning in a form, PATCH or import,
  and percent-encodes the jsonb row_key filters; the decision rows of
  codeplan decisions-approve are in the manual's decision record.

Run: python3 tests/test_config_ui_commissioning.py
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
COMPLIANCE = os.path.join(ROOT, "docs", "manual", "chapters", "compliance.html")
NODE = shutil.which("node")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def block(html, name, begin="begin"):
    m = re.search(rf"/\* {name}:{begin} \*/(.*?)/\* {name}:end \*/", html, re.S)
    assert m, f"{name} block missing"
    return m.group(1)


# The database's message (RAISE with % filled), the RAISE format (verbatim in the
# migration, or None for a PostgreSQL message) and a fragment of what the page shows.
REFUSALS = [
    ("propose_commissioning: unit UNIT01 is already on",
     "'propose_commissioning: unit % is already %'", "Nothing to change: UNIT01 is already flagged"),
    ("propose_commissioning: unit UNIT01 is already off",
     "'propose_commissioning: unit % is already %'", "UNIT01 is already out of commissioning"),
    ("propose_commissioning: change 12 for unit UNIT01 already waits for qa",
     "'propose_commissioning: change % for unit % already waits for qa'", "Proposal #12 for UNIT01 already waits"),
    ("propose_commissioning: a reason is required",
     "'propose_commissioning: a reason is required'", "Give a reason."),
    ("propose_commissioning: no unit 9",
     "'propose_commissioning: no unit %'", "no longer exists"),
    ("propose_commissioning: your token carries no person_id",
     "'propose_commissioning: your token carries no person_id'", "no person_id"),
    ("commissioning: unit UNIT01 has run 7 in S; flag it when no run is running or scheduled",
     "'commissioning: unit %s has run %s in %s; flag it when no run is running or scheduled'",
     "commissioning: unit UNIT01 has run 7 in S"),
    ("approve_change: unit 4 no longer exists",
     "'approve_change: unit % no longer exists'", "no longer exists"),
    ("not_own_author: p-qa proposed change 12",
     "'not_own_author: % proposed change %'", "You proposed this change. Another qa person"),
    ("approve_change: change 12 is no longer pending",
     "'approve_change: change % is no longer pending'", "replaced by a newer one"),
    ("withdraw_change: change 12 is not a proposal of yours",
     "'withdraw_change: change % is not a proposal of yours'", "Only the person who proposed it"),
    ("approvals are made by a person signed in through the API, not by person via svc_scheduler",
     "'approvals are made by a person signed in through the API, not by %'", "your own sign-in"),
    ("role engineer holds no approval on master_data",
     "'role % holds no approval on %'", "Your role cannot approve master_data"),
    ("permission denied for function propose_commissioning", None, "Only an engineer proposes"),
    ("permission denied for function unit_commissioning", None, "IAM_DB_ROLES=true"),
]

BASE = {"unit_id": 4, "unit_code": "UNIT01", "commissioning": False, "blocking_run_id": None,
        "blocking_run_status": None, "pending_change_id": None, "pending_value": None, "pending_reason": None,
        "pending_by": None, "pending_at": None, "pending_mine": False, "review_change_id": None,
        "last_change_id": None, "last_value": None, "last_changed_at": None, "last_proposed_by": None,
        "last_approved_by": None, "can_propose": False, "can_approve": False, "can_read_history": False}
ENG = {"can_propose": True}
QA = {"can_approve": True, "can_read_history": True}
PENDING = {"pending_change_id": 12, "pending_value": True, "pending_reason": "pump test",
           "pending_by": "Eng One", "pending_at": "2026-10-31T10:00:00Z"}
CASES = {
    "eng_off": {**BASE, **ENG},
    "eng_run_r": {**BASE, **ENG, "blocking_run_id": 7, "blocking_run_status": "R"},
    "eng_run_s": {**BASE, **ENG, "blocking_run_id": 8, "blocking_run_status": "S"},
    "eng_own_pending": {**BASE, **ENG, **PENDING, "pending_mine": True},
    "eng_other_pending": {**BASE, **ENG, **PENDING},
    "eng_on": {**BASE, **ENG, "commissioning": True, "last_change_id": 11, "last_value": True,
               "last_changed_at": "2026-10-30T09:00:00Z", "last_proposed_by": "Eng One"},
    "qa_pending": {**BASE, **QA, **PENDING},
    "qa_own_pending": {**BASE, **QA, **PENDING, "pending_mine": True},
    "qa_review": {**BASE, **QA, "review_change_id": 13, "last_change_id": 13, "last_value": False,
                  "last_changed_at": "2026-10-31T11:00:00Z", "last_proposed_by": "Eng One"},
    "operator": {**BASE, "commissioning": True, "pending_change_id": 12, "pending_value": False},
}

HIST_CHANGES = [
    {"change_id": 10, "new_value": True, "reason": "first", "proposed_by_name": "Eng One", "proposed_by_role": "engineer",
     "proposed_at": "2026-10-01T10:00:00Z", "applied_at": None},
    {"change_id": 11, "new_value": True, "reason": "again", "proposed_by_name": "Eng One", "proposed_by_role": "engineer",
     "proposed_at": "2026-10-02T10:00:00Z", "applied_at": None},
    {"change_id": 12, "new_value": False, "reason": "done", "proposed_by_name": "Eng Two", "proposed_by_role": "engineer",
     "proposed_at": "2026-10-03T10:00:00Z", "applied_at": "2026-10-03T10:00:00Z"},
    {"change_id": 13, "new_value": True, "reason": "x", "proposed_by_name": "Eng One", "proposed_by_role": "engineer",
     "proposed_at": "2026-10-04T10:00:00Z", "applied_at": None},
    {"change_id": 14, "new_value": True, "reason": "y", "proposed_by_name": "Eng One", "proposed_by_role": "engineer",
     "proposed_at": "2026-10-05T10:00:00Z", "applied_at": None},
    {"change_id": 15, "new_value": False, "reason": "z", "proposed_by_name": "Eng One", "proposed_by_role": "engineer",
     "proposed_at": "2026-10-06T10:00:00Z", "applied_at": "2026-10-06T10:00:00Z"},
    {"change_id": 16, "new_value": True, "reason": "w", "proposed_by_name": "Eng One", "proposed_by_role": "engineer",
     "proposed_at": "2026-10-07T10:00:00Z", "applied_at": None},
]
HIST_APPROVALS = [
    {"row_key": [10], "action": "return", "note": "not now", "approved_by_name": "QA One", "approved_at": "2026-10-01T12:00:00Z"},
    {"row_key": [11], "action": "apply", "note": None, "approved_by_name": "QA One", "approved_at": "2026-10-02T12:00:00Z"},
    {"row_key": [12], "action": "review", "note": "ok", "approved_by_name": "QA Two", "approved_at": "2026-10-03T12:00:00Z"},
    {"row_key": [13], "action": "withdraw", "note": "typo", "approved_by_name": "Eng One", "approved_at": "2026-10-04T12:00:00Z"},
]

HARNESS = r"""
const fs = require('fs');
const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const out = { cells: {} };
for (const k of Object.keys(input.cases)) out.cells[k] = commissioningCell(input.cases[k], false);
out.fallback = commissioningCell({ unit_id: 4, commissioning: true }, true);
out.fallbackOff = commissioningCell(null, true);
out.refusals = input.refusals.map(commissioningError);
out.reviewId = [commissioningReviewId(input.cases.qa_pending), commissioningReviewId(input.cases.qa_review), commissioningReviewId({})];
out.propose = [commissioningProposeRpc(4, true, '  pump test '), commissioningProposeRpc(4, false, 'done')];
out.paths = [commissioningHistoryPaths(4, []), commissioningHistoryPaths(4, [10, 11])];
out.history = commissioningHistory(input.changes, input.approvals);
console.log(JSON.stringify(out));
"""


@unittest.skipUnless(NODE, "node is not installed")
class CommissioningLogicUnderNode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        html = read(INDEX)
        cls.mig = read(MIG)
        tmp = tempfile.mkdtemp()
        cls.addClassCleanup(shutil.rmtree, tmp)
        js = os.path.join(tmp, "harness.js")
        with open(js, "w", encoding="utf-8") as f:
            f.write(block(html, "approvals-logic") + "\n" + block(html, "commissioning-logic") + "\n" + HARNESS)
        data = os.path.join(tmp, "input.json")
        with open(data, "w", encoding="utf-8") as f:
            json.dump({"cases": CASES, "refusals": [r[0] for r in REFUSALS],
                       "changes": HIST_CHANGES, "approvals": HIST_APPROVALS}, f)
        subprocess.run([NODE, "--check", js], check=True, capture_output=True)
        r = subprocess.run([NODE, js, data], capture_output=True, text=True, timeout=30)
        if r.returncode:
            raise AssertionError(r.stderr)
        cls.out = json.loads(r.stdout)

    def acts(self, case):
        return {a["id"]: a for a in self.out["cells"][case]["actions"]}

    def text(self, case):
        return " | ".join(l["text"] for l in self.out["cells"][case]["lines"])

    def test_engineer(self):
        a = self.acts("eng_off")
        self.assertEqual(set(a), {"propose_on"})
        self.assertTrue(a["propose_on"]["enabled"])
        self.assertEqual(a["propose_on"]["label"], "Flag for commissioning…")
        self.assertEqual(self.out["cells"]["eng_off"]["badge"]["text"], "Off")
        for case, word in (("eng_run_r", "Run #7 is running"), ("eng_run_s", "Run #8 is scheduled")):
            a = self.acts(case)
            self.assertFalse(a["propose_on"]["enabled"], case)
            self.assertIn(word, a["propose_on"]["title"])
            self.assertIn(word, self.text(case))
        a = self.acts("eng_own_pending")
        self.assertEqual(set(a), {"withdraw"})
        self.assertIn("(your proposal)", self.text("eng_own_pending"))
        self.assertIn("Reason: pump test", self.out["cells"]["eng_own_pending"]["lines"][0]["title"])
        self.assertEqual(self.acts("eng_other_pending"), {})
        self.assertIn("Waiting for qa: flag on — proposed by Eng One", self.text("eng_other_pending"))
        a = self.acts("eng_on")
        self.assertEqual(set(a), {"propose_off"})
        self.assertIn("at once", a["propose_off"]["title"])
        self.assertEqual(self.out["cells"]["eng_on"]["badge"]["text"], "Commissioning")
        self.assertIn("Last change 2026-10-30 09:00 UTC: on, proposed by Eng One", self.text("eng_on"))

    def test_qa(self):
        a = self.acts("qa_pending")
        self.assertEqual(set(a), {"review", "history"})
        self.assertTrue(a["review"]["enabled"])
        a = self.acts("qa_own_pending")
        self.assertFalse(a["review"]["enabled"])
        self.assertIn("another qa person", a["review"]["title"])
        self.assertIn("withdraw", a)
        a = self.acts("qa_review")
        self.assertTrue(a["review"]["enabled"])
        self.assertIn("reviewed", a["review"]["title"])
        self.assertIn("waits for qa's review", self.text("qa_review"))
        self.assertEqual(self.out["reviewId"], [12, 13, None])

    def test_operator_sees_flag_only(self):
        c = self.out["cells"]["operator"]
        self.assertEqual(c["actions"], [])
        self.assertEqual(self.text("operator"), "Waiting for qa: end commissioning")
        self.assertNotIn("Run #", self.text("operator"))
        self.assertFalse(c["lines"][0].get("title"))

    def test_fallback(self):
        for c, badge in ((self.out["fallback"], "Commissioning"), (self.out["fallbackOff"], "Off")):
            self.assertEqual(c["badge"]["text"], badge)
            self.assertEqual(c["actions"], [])
            self.assertIn("IAM_DB_ROLES=true", c["lines"][0]["text"])

    def test_rpc_and_paths(self):
        self.assertEqual(self.out["propose"][0], {"path": "/rpc/propose_commissioning",
                                                  "body": {"p_unit_id": 4, "p_value": True, "p_reason": "pump test"}})
        self.assertFalse(self.out["propose"][1]["body"]["p_value"])
        p0, p1 = self.out["paths"]
        self.assertIn("&row_key=eq.%5B4%5D&", p0["changes"])
        self.assertIn("column_name=eq.commissioning", p0["changes"])
        self.assertIsNone(p0["approvals"])
        self.assertIn("&row_key=in.(%22%5B10%5D%22,%22%5B11%5D%22)", p1["approvals"])
        self.assertNotIn("[", p1["approvals"] + p0["changes"])

    def test_history(self):
        h = {x["change_id"]: x for x in self.out["history"]}
        self.assertEqual([x["change_id"] for x in self.out["history"]], [16, 15, 14, 13, 12, 11, 10])
        self.assertEqual(h[16]["state"], "waiting")
        self.assertEqual(h[15]["state"], "review_pending")
        self.assertEqual(h[14]["state"], "superseded")
        self.assertIn("Replaced by #15", h[14]["outcome"])
        self.assertEqual(h[13]["state"], "withdrawn")
        self.assertIn("“typo”", h[13]["outcome"])
        self.assertEqual(h[12]["state"], "reviewed")
        self.assertIn("by QA Two: “ok”", h[12]["outcome"])
        self.assertEqual(h[11]["state"], "applied")
        self.assertEqual(h[10]["state"], "returned")
        self.assertEqual((h[12]["value"], h[11]["value"]), ("off", "on"))

    def test_refusals_map_and_exist_in_migration(self):
        for (msg, fmt, want), got in zip(REFUSALS, self.out["refusals"]):
            self.assertIn(want, got, msg)
            self.assertNotIn("Retiring learned state", got, msg)
            if fmt:
                self.assertIn(fmt, self.mig, f"the migration no longer raises {fmt}")


class CommissioningStatic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = read(INDEX)
        cls.mig = read(MIG)

    def test_reads_with_own_catch(self):
        self.assertRegex(self.html, r"api\('GET', '/rpc/unit_commissioning'\)\.catch\(")

    def test_propose_body_matches_the_overload(self):
        m = re.search(r"FUNCTION medcea\.propose_commissioning\(([^)]*)\)", self.mig)
        names = {a.split()[0] for a in m.group(1).split(",")}
        self.assertEqual(names, {"p_unit_id", "p_value", "p_reason"})
        logic = block(self.html, "commissioning-logic")
        for n in names:
            self.assertIn(n + ":", logic)

    def test_review_through_the_queue(self):
        self.assertIn("api('GET', '/rpc/approval_queue?p_changes=false')", self.html)
        self.assertIn("openApprovalModal(i)", self.html)
        self.assertIn("withdrawRpc(changeId, reason)", self.html)
        f = self.html[self.html.index("async function refreshAfterApproval() {"):]
        self.assertIn("loadUnits()", f[:f.index("\n    }\n")])

    def test_never_writes_the_flag(self):
        self.assertNotRegex(self.html, r'name="commissioning"')
        self.assertNotRegex(self.html, r"commissioning\s*:\s*(true|false)")
        for fields in re.findall(r"const unitFields = \[([^\]]*)\]", self.html):
            self.assertNotIn("commissioning", fields)

    def test_no_raw_jsonb_filter(self):
        self.assertNotRegex(self.html, r"row_key=eq\.\[")
        self.assertNotRegex(self.html, r"row_key=in\.\(\[")

    def test_colspans(self):
        render = self.html[self.html.index("function renderUnitTable()"):]
        render = render[:render.index("\n    }\n")]
        self.assertEqual(render.count("<th>"), 8)
        self.assertEqual(set(re.findall(r'colspan="(\d+)"', render)), {"8"})

    def test_decision_record(self):
        c = read(COMPLIANCE)
        self.assertTrue("No commissioning screen" not in c, "compliance.html still lists the commissioning screen as a gap")
        self.assertTrue("(none today)" not in c, "compliance.html still says no unit is flagged")
        for key in ("Return and Withdraw", "Parameter-set editor and Retire", "Commissioning while a run",
                    "Ending commissioning", "Approval status for authors", "After-the-fact reviews",
                    "Who sees commissioning proposals", "Applying commissioning makes no author",
                    "Commissioning in the policy history", "Waiting changes in the health check",
                    "Proofs for approvals and commissioning", "Manual for approvals and commissioning"):
            self.assertTrue(key in c, f"no decision row {key!r} in compliance.html")


if __name__ == "__main__":
    unittest.main()
