"""The Policy UI's page, offline (apps/iam/html/policy.html, IAM 4.3).

- The policy-logic block (pure functions between /* policy-logic:begin */ and
  /* policy-logic:end */) runs under node (skipped without node): cell classes (none, red
  for a checker message naming the role and group, amber for a waiver), level chips in the
  levels' order with their constraints, the Confirm button only with the attestation ticked
  and a note, Dispute with a note, the record's status line (intact, broken, cannot verify),
  the versions waiting for confirmation, and the reach tuples in words.
- Every refusal the page translates is a RAISE of iam_policy._qa, confirm_applied or
  dispute_applied in apps/database/medcea_db_migrations.sql (a reworded RAISE breaks this
  test), and the attestation the page sends is exactly confirm_applied's.
- Static: no CDN, no inline event handler; the user menu; the tabs are the three /api/me
  `can` keys of policy_api.PolicyAdmin.me().

Run: python3 tests/test_policy_ui.py
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "apps", "iam", "html", "policy.html")
API = os.path.join(ROOT, "apps", "iam", "policy_api.py")
MIG = os.path.join(ROOT, "apps", "database", "medcea_db_migrations.sql")
NODE = shutil.which("node")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def logic_block():
    m = re.search(r"/\* policy-logic:begin \*/(.*?)/\* policy-logic:end \*/", read(PAGE), re.S)
    assert m, "policy-logic block missing"
    return m.group(1)


def run_node(expr):
    """Evaluate a JSON-producing expression after the logic block."""
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(logic_block() + "\nconsole.log(JSON.stringify(" + expr + "));\n")
        path = f.name
    try:
        out = subprocess.run([NODE, path], capture_output=True, text=True, timeout=30)
    finally:
        os.unlink(path)
    if out.returncode:
        raise AssertionError(out.stderr)
    return json.loads(out.stdout)


@unittest.skipUnless(NODE, "node is not installed")
class Logic(unittest.TestCase):
    def test_cell_class(self):
        waivers = [{"subject": "engineer", "group": "flows"}]
        errors = ["I10 svc ceiling ['U'] on regulated group runs without a waiver", "I4 operator holds A on runs"]
        got = run_node("""[cellClass(null, 'qa', 'runs', [], []),
            cellClass({levels: ['R']}, 'engineer', 'flows', %s, %s),
            cellClass({levels: ['A']}, 'operator', 'runs', %s, %s),
            cellClass({levels: ['R']}, 'qa', 'runs', %s, %s)]""" % ((json.dumps(waivers), json.dumps(errors)) * 3))
        self.assertEqual(got, ["none", "amber", "red", ""])

    def test_chips(self):
        got = run_node("chips({levels: ['O', 'R'], constraints: {O: 'assigned_run'}})")
        self.assertEqual(got, [{"level": "R", "constraint": None}, {"level": "O", "constraint": "assigned_run"}])
        self.assertEqual(run_node("chips(null)"), [])

    def test_buttons(self):
        got = run_node("[confirmEnabled(true, 'ok'), confirmEnabled(false, 'ok'), confirmEnabled(true, '  '), "
                       "confirmEnabled('true', 'ok'), disputeEnabled('why'), disputeEnabled('')]")
        self.assertEqual(got, [True, False, False, False, True, False])

    def test_own_claim_cannot_confirm(self):
        got = run_node("[ownClaim({claimed_by_person: 'p1'}, {person: 'p1'}), ownClaim({claimed_by_person: 'p1'}, {person: 'p2'}), "
                       "ownClaim({claimed_by_person: null}, {person: null}), confirmEnabled(true, 'ok', true), confirmEnabled(true, 'ok', false)]")
        self.assertEqual(got, [True, False, False, False, True])

    def test_chain_status(self):
        got = run_node("[chainStatus({ok: true, events: 50, head: '0123456789abcdef'}).cls, "
                       "chainStatus({ok: false, first_bad_event: 7, detail: 'hash'}).text, "
                       "chainStatus({ok: null, detail: 'cannot verify: x'}).cls, chainStatus(null).cls]")
        self.assertEqual(got[0], "green")
        self.assertIn("event 7", got[1])
        self.assertEqual(got[2:], ["grey", "grey"])

    def test_pending(self):
        got = run_node("pendingVersions([{version: 1, needs_confirmation: true}, {version: 2, needs_confirmation: false}])"
                       ".map(v => v.version)")
        self.assertEqual(got, [1])

    def test_reach_words(self):
        got = run_node("[describeReach(['db', 'medcea.confirm_policy(integer,text,text)', 'EXECUTE', null]), "
                       "describeReach(['host', 'POLICY_DOMAIN', null]), describeReach(['route', 'iam', 'GET /api/policy', null])]")
        self.assertEqual(got, ["database: EXECUTE on medcea.confirm_policy(integer,text,text)",
                               "sign-in to POLICY_DOMAIN", "API: iam GET /api/policy"])

    def test_refusals_in_plain_words(self):
        cases = {
            "apply.sh recorded you as running version 1: another qa person confirms it": "You applied version 1 yourself",
            "version 1 is already confirmed ": "already confirmed",
            "version 3 is no applied bootstrap or rollback version": "not a bootstrap or rollback version",
            'confirming needs the attestation "I did not run apply.sh for this version."': "Tick the statement",
            "a note is required": "Write a note",
            "your access changed since you signed in: reload the page": "Reload the page",
            "approve access-policy versions in the Policy UI": "did not come through the Policy UI",
            "something new": "something new",
        }
        got = run_node("[" + ", ".join("friendlyRefusal(%s)" % json.dumps(k) for k in cases) + "]")
        for (src, want), text in zip(cases.items(), got):
            self.assertIn(want, text, src)


class Sources(unittest.TestCase):
    def test_every_translated_refusal_is_raised(self):
        mig = read(MIG)
        qa = mig[mig.index("FUNCTION iam_policy._qa("):]
        qa = qa[:qa.index("CREATE OR REPLACE FUNCTION iam_policy.why_not")]
        for lead in ("apply.sh recorded you as running version %", "version % is already %",
                     "version % is no applied bootstrap or rollback version", "confirming needs the attestation",
                     "a note is required", "your access changed since you signed in", "approve access-policy versions in the Policy UI"):
            self.assertIn("RAISE EXCEPTION '" + lead, qa, lead)

    def test_attestation_is_confirm_applieds(self):
        mig = read(MIG)
        body = mig[mig.index("FUNCTION iam_policy.confirm_applied("):]
        body = body[:body.index("END $$")]
        api = read(API)
        attest = re.search(r"^ATTEST = '([^']+)'", api, re.M).group(1)
        self.assertIn("'" + attest + "'", body)

    def test_static(self):
        page = read(PAGE)
        self.assertNotRegex(page, r"<script src=\"https?://")
        self.assertNotRegex(page, r"<link[^>]+href=\"https?://")
        self.assertNotRegex(page, r"\son[a-z]+=\"")
        self.assertIn('<script src="/_account/user-menu.js" defer></script>', page)
        tabs = set(re.findall(r'data-view="(\w+)"', page))
        api = read(API)
        me = api[api.index("    def me(self):"):]
        me = me[:me.index("\n\n")]
        self.assertEqual(tabs, set(re.findall(r"'(\w+)': self\.can\(", me)))


if __name__ == "__main__":
    unittest.main()
