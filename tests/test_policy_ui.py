"""The Policy UI's page, offline (apps/iam/html/policy.html, IAM 4.3–4.5).

- The policy-logic block (pure functions between /* policy-logic:begin */ and
  /* policy-logic:end */) runs under node (skipped without node): cell classes (none, red
  for a checker message naming the role and group, amber for a waiver), level chips in the
  levels' order with their constraints, the Confirm button only with the attestation ticked
  and a note, Dispute with a note, the record's status line (intact, broken, cannot verify),
  the versions waiting for confirmation, and the reach tuples in words.
- IAM 4.4 (design §14.7.4): the cell editor (closeImplied, constraintOnUnheld, the whole
  cell as levelsPayload), submitEnabled, the approval's hash (hex of crypto.subtle's
  SHA-256 over the exact bytes equals Python's hashlib over source.canonical of a
  diff_document-shaped fixture, and the document is parsed from the same buffer),
  ownWidening (the viewer's role and the roles it includes), approveEnabled (each refusal,
  a skeleton version without the attestation), whyNotText for every why_not code,
  describeTuple for every reach and system tuple kind, makersOf (a skeleton version's
  claimed person, never its fixed created_by_name).
- IAM 4.5 (design §14.8.12): the apply state per version in words (statusText: "applied —
  rollout incomplete", "approved — a previous apply was reverted"), what the host operator
  does about it (applyStateNote), and the version a rollback restores with its reason
  (rollbackTarget, the Confirm card); the stale "IAM 4.5" texts are gone, and the states the
  page knows are exactly policy_api.apply_state's.
- Every refusal the page translates is a RAISE of the author functions, iam_policy._qa,
  approve, return_version, confirm_applied, dispute_applied, _evidence,
  medcea_auth._approver or _person_actor in apps/database/medcea_db_migrations.sql (a
  reworded RAISE breaks this test), or iam-api's own text in apps/iam/policy_api.py; the
  attestations the page sends are exactly confirm_applied's and approve's.
- Static: no CDN, no inline event handler; the user menu; the tabs are the eight /api/me
  `can` keys of policy_api.PolicyAdmin.me(), and the page's ME.acts uses are ACTS' keys.

Run: python3 tests/test_policy_ui.py
"""
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "apps", "iam", "html", "policy.html")
API = os.path.join(ROOT, "apps", "iam", "policy_api.py")
MIG = os.path.join(ROOT, "apps", "database", "medcea_db_migrations.sql")
NODE = shutil.which("node")
sys.path.insert(0, os.path.join(ROOT, "apps", "iam"))
SKELETON_ATTEST = "I did not run apply.sh --propose-skeleton for this version."


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


def run_node_async(expr):
    """Evaluate an awaited JSON-producing expression after the logic block."""
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(logic_block() + "\n(async () => { console.log(JSON.stringify(await (" + expr + "))); })()"
                ".catch(e => { console.error(e); process.exit(1); });\n")
        path = f.name
    try:
        out = subprocess.run([NODE, path], capture_output=True, text=True, timeout=30)
    finally:
        os.unlink(path)
    if out.returncode:
        raise AssertionError(out.stderr)
    return json.loads(out.stdout)


def sha(c):
    return hashlib.sha256(c.encode()).hexdigest()


# A diff_document (design §14.7.3) of a change version, with non-ASCII text in a waiver.
DIFF_DOC = {
    "schema": 1, "kind": "change", "version": 7, "against": "applied", "entries_digest": sha("e"), "skeleton": None,
    "cells": [{"group": "runs", "role": "engineer", "before": {"R": None}, "after": {"R": None, "O": "assigned_run"}}],
    "waivers": {"added": [{"id": "W9", "invariant": "I11", "subject": "engineer", "group": "flows",
                           "rationale": "Node-RED → ingest — revisé"}], "removed": []},
    "roles": {"engineer": {"added": [["level", "runs", "O", ["assigned_run"]]], "removed": []},
              "auditor": {"added": [["route", "iam", "GET /api/policy/history", None]], "removed": []}},
    "system": {"added": [], "removed": []},
}


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

    # ── IAM 4.4 ──────────────────────────────────────────────────────────────────────
    LEVELS = json.dumps([{"key": "N", "implies": []}, {"key": "R", "implies": []}, {"key": "X", "implies": ["R"]},
                         {"key": "C", "implies": ["R"]}, {"key": "U", "implies": ["C", "R"]}, {"key": "A", "implies": ["R"]},
                         {"key": "O", "implies": ["R"]}, {"key": "K", "implies": []}, {"key": "D", "implies": []}])

    def test_close_implied(self):
        got = run_node("[closeImplied(['U'], %s), closeImplied(['O', 'K'], %s), closeImplied([], %s), closeImplied(['N', 'R'], %s)]"
                       % ((self.LEVELS,) * 4))
        self.assertEqual(got, [["R", "C", "U"], ["R", "O", "K"], [], ["R"]])

    def test_whole_cell_payload(self):
        got = run_node("[levelsPayload(['O', 'R'], {O: 'assigned_run', C: 'own_unit'}), levelsPayload([], {}), "
                       "constraintOnUnheld(['R'], {R: null, O: 'assigned_run'}), constraintOnUnheld(['R', 'O'], {O: 'assigned_run'})]")
        self.assertEqual(got[0], {"R": None, "O": "assigned_run"})
        self.assertEqual(list(got[0]), ["R", "O"])
        self.assertEqual(got[1:], [{}, ["O"], []])

    def test_submit_enabled(self):
        v = {"version": 5, "kind": "change", "status": "draft"}
        ok = {"version": 5, "checker": {"errors": []}}
        got = run_node("[submitEnabled(%s, %s), submitEnabled(%s, %s), submitEnabled(%s, %s), submitEnabled(%s, %s), "
                       "submitEnabled(%s, %s), submitEnabled(null, %s)]" % (
                           json.dumps(ok), json.dumps(v),
                           json.dumps({"version": 5, "checker": {"errors": ["I1 …"]}}), json.dumps(v),
                           json.dumps({"version": 4, "checker": {"errors": []}}), json.dumps(v),
                           json.dumps(ok), json.dumps(dict(v, status="submitted")),
                           json.dumps(ok), json.dumps(dict(v, kind="skeleton")), json.dumps(v)))
        self.assertEqual(got, [True, False, False, False, False, False])

    def test_hash_of_the_exact_bytes(self):
        """The browser's digest of the response bytes equals hashlib over source.canonical."""
        from compiler import source
        docs = [DIFF_DOC]
        try:
            from compiler import explain, model
        except ImportError:
            explain = None
        if explain is not None and hasattr(explain, "diff_document"):
            import copy
            p = model.load_defaults()
            data = copy.deepcopy(p.data)
            data["matrix"].setdefault("runs", {})["engineer"] = ["R", "O"]
            doc = explain.diff_document("change", 7, "applied", sha("e"), p, model.Policy(data))
            self.assertTrue(doc["cells"], "the fixture's cell change is in the diff")
            docs.append(doc)
        for doc in docs:
            data = source.canonical(doc)
            want = hashlib.sha256(data).hexdigest()
            b64 = base64.b64encode(data).decode()
            got = run_node_async("(async () => { const b = new Uint8Array(Buffer.from(%s, 'base64')); "
                                 "const buf = b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength); "
                                 "const d = parseDiff(buf); return [await digestOf(buf), d.entries_digest, d.waivers.added.map(w => w.rationale)]; })()"
                                 % json.dumps(b64))
            self.assertEqual(got[0], want)
            self.assertEqual(got[1], doc["entries_digest"])
            self.assertEqual(got[2], [w.get("rationale") for w in doc["waivers"]["added"]])
        self.assertEqual(run_node("hex(new Uint8Array([0, 15, 16, 255]))"), "000f10ff")

    def test_own_widening(self):
        got = run_node("[ownWidening(%s, 'qa', ['auditor']), ownWidening(%s, 'admin', []), ownWidening(%s, 'engineer', null), "
                       "ownWidening({roles: {qa: {added: [], removed: [['host', 'X', null]]}}}, 'qa', ['auditor'])]"
                       % ((json.dumps(DIFF_DOC),) * 3))
        self.assertEqual(got, [["auditor"], [], ["engineer"], []])

    def _approve(self, v, ds, note, attest, me):
        return run_node("approveEnabled(%s, %s, %s, %s, %s)" % tuple(json.dumps(x) for x in (v, ds, note, attest, me)))

    def test_approve_enabled(self):
        acc, sk2 = sha("accepted"), sha("proposed")
        doc = dict(DIFF_DOC, roles={"engineer": DIFF_DOC["roles"]["engineer"]})
        v = {"version": 7, "kind": "change", "status": "submitted", "why_not": {"may_approve": True, "why_not_code": None, "needs_token_path": True}}
        ds = {"doc": doc, "digest": sha("d"), "headerDigest": sha("d"), "skeletonDigest": acc, "accepted": acc}
        qa = {"role": "qa", "includes": ["auditor"]}
        self.assertEqual(self._approve(v, ds, "looked at it", False, qa), {"ok": True, "why": ""})
        cases = [
            (v, dict(ds, digest=sha("x")), "n", False, qa, "did not load intact"),
            (v, dict(ds, headerDigest=None), "n", False, qa, "has not loaded"),
            (v, None, "n", False, qa, "has not loaded"),
            (v, dict(ds, doc=DIFF_DOC), "n", False, qa, "widens a role you hold (auditor)"),
            (v, dict(ds, skeletonDigest=sk2), "n", False, qa, "./apps/iam/deploy.sh"),
            (v, dict(ds, doc=dict(doc, version=8)), "n", False, qa, "not the one of this version"),
            (dict(v, why_not={"may_approve": False, "why_not_code": "own_author"}), ds, "n", False, qa, "author"),
            (dict(v, why_not=None), ds, "n", False, qa, "no verdict"),
            (v, ds, "  ", False, qa, "Write a note"),
            (dict(v, status="approved"), ds, "n", False, qa, "Only a submitted version"),
        ]
        for vv, dd, note, att, me, want in cases:
            with self.subTest(want=want):
                got = self._approve(vv, dd, note, att, me)
                self.assertFalse(got["ok"])
                self.assertIn(want, got["why"])
        # a skeleton version: the header is the proposed skeleton, and the attestation is required
        skv = dict(v, kind="skeleton", skeleton_digest=sk2)
        skd = dict(ds, doc=dict(doc, kind="skeleton", skeleton={"from": acc, "to": sk2, "sections": []}), skeletonDigest=sk2)
        got = self._approve(skv, skd, "looked at it", False, qa)
        self.assertFalse(got["ok"])
        self.assertIn("propose-skeleton", got["why"])
        self.assertTrue(self._approve(skv, skd, "looked at it", True, qa)["ok"])
        self.assertFalse(self._approve(skv, skd, "looked at it", "true", qa)["ok"])

    def test_why_not_words(self):
        codes = ["no_token", "no_person", "not_approver", "changed_since", "no_version", "not_submitted", "no_applied",
                 "stale_base", "own_author", "entries_changed", "break_glass_open", "stale_skeleton", "own_widening"]
        got = run_node("[" + ", ".join("whyNotText(%s)" % json.dumps(c) for c in codes) + ", whyNotText('later_code'), whyNotText(null)]")
        for c, text in zip(codes, got):
            self.assertNotIn(c, text, c)
        self.assertIn("later_code", got[-2])

    def test_why_not_codes_are_the_databases(self):
        mig = read(MIG)
        body = sql_between(mig, "FUNCTION iam_policy.why_not(", "END $$")
        sql = set(re.findall(r"THEN '(\w+)'", body))
        page = logic_block()
        table = page[page.index("const WHY_NOT = {"):]
        js = set(re.findall(r"^  (\w+):", table[:table.index("};")], re.M))
        self.assertLessEqual(sql, js)
        self.assertEqual(js - sql - {"break_glass_open", "stale_skeleton", "own_widening"}, set())

    def test_tuples_in_words(self):
        ts = [["db", "medcea.recipe", "UPDATE", None], ["public", "access-public", "POST /api/register"],
              ["shared", "access", "/_account/"], ["serves", "POLICY_DOMAIN", "iam"], ["azp", "POLICY_DOMAIN", "policy"],
              ["ingress", "iam", 8083, "proxy:POLICY_DOMAIN"], ["unproxied", "ONBOARD_DOMAIN", "node"],
              ["client", "notebooks", "egress", "config-api", 3000], ["client", "notebooks", "token_client", "workbench-notebook"],
              ["client", "notebooks", "writes"], ["only_rpc", "iam-approvals", "approve_policy"], ["token_client", "workbench-notebook"],
              ["svc", "svc_iam", "table", "iam_policy.version", "SELECT"], ["svc-member", "rr_admin", "rr_admin_login", True, False],
              ["rls", "medcea.measurement", "rr_operator", "SELECT", "x", None], ["section", "invariants"]]
        got = run_node("%s.map(describeTuple)" % json.dumps(ts))
        self.assertEqual(got[0], "database: UPDATE on medcea.recipe")
        self.assertEqual(got[7], "client notebooks may connect to config-api on port 3000")
        self.assertEqual(got[12], "service svc_iam: SELECT on iam_policy.version")
        self.assertEqual(got[15], "skeleton section invariants changed")
        for t, text in zip(ts, got):
            self.assertNotIn("undefined", text, t)
            self.assertNotIn("null", text, t)
        groups = run_node("groupTuples(%s).map(([l, ts]) => [l, ts.length])" % json.dumps(
            [["route", "iam", "GET /x", None], ["db", "a", "SELECT", None], ["section", "x"], ["db", "b", "SELECT", None]]))
        self.assertEqual(groups, [["Database privileges", 2], ["API routes", 1], ["Other", 1]])

    def test_makers(self):
        got = run_node("""[makersOf({kind: 'change', authors: [{name: 'admin', person: 'p1'}, {name: 'admin2', person: 'p2'}, {name: 'admin', person: 'p1'}],
                                     submitted_by_name: 'admin'}),
                           makersOf({kind: 'skeleton', created_by_name: 'apply.sh --by (claimed)', submitted_by_name: 'apply.sh --by (claimed)',
                                     created_by_person: 'p9', authors: [{name: null, person: 'p9', claimed: true}]}),
                           makersOf({kind: 'skeleton', created_by_person: 'p9', authors: []}),
                           cellWords({O: 'assigned_run', R: null}), cellWords({}),
                           draftSources([{version: 2, status: 'applied'}, {version: 3, status: 'draft'}, {version: 1, status: 'superseded'}])]""")
        self.assertEqual(got[0], ["admin", "admin2"])
        self.assertEqual(got[1], ["person p9 (claimed by apply.sh --by)"])
        self.assertEqual(got[2], ["person p9 (claimed by apply.sh --by)"])
        self.assertEqual(got[3:5], ["R, O (if assigned_run)", "nothing"])
        self.assertEqual(run_node("cellWords({R: null, O: ['assigned_run', 'own_unit']})"), "R, O (if assigned_run or own_unit)")
        self.assertEqual(got[5], ["applied", "defaults", "2", "1"])
        for x in got[1] + got[2]:
            self.assertNotIn("apply.sh --by (claimed)", x)

    def test_44_refusals_in_plain_words(self):
        cases = {
            "version 4 is still open: take it through or withdraw it first": "Version 4 is still open",
            "the approver's token carries no person_id": "no person_id",
            "role engineer holds no approval on iam_policy": "may not approve on iam_policy",
            "role admin holds no U on iam_policy": "holds no U on iam_policy",
            "a policy break-glass is open (event 51): approvals wait until a normal deploy of infra, iam ends it": "of infra, iam ends it",
            "version 9 was proposed against skeleton abcdef012345, the accepted one is now 0123456789ab: return it and propose again": "0123456789ab",
            "version 9 widens role auditor, which you hold: you may not approve it": "widens role auditor",
            "no policy version is applied yet: the host operator runs ./apps/iam/apply.sh --bootstrap first": "--bootstrap",
            "no policy version is applied": "No policy version is applied on this host.",
            "no policy version 12": "no policy version 12",
            "version 3 is being applied (apply_started): wait": "being applied (apply_started)",
        }
        got = run_node("[" + ", ".join("friendlyRefusal(%s)" % json.dumps(k) for k in cases) + "]")
        for (src, want), text in zip(cases.items(), got):
            self.assertIn(want, text, src)

    def test_apply_state_words(self):
        """§14.8.12: the Changes tab and the version selectors."""
        got = run_node("""[statusText({status: 'applied', apply_state: 'rollout incomplete'}),
            statusText({status: 'approved', apply_state: 'reverted'}),
            statusText({status: 'withdrawn', apply_state: 'reverted'}),
            statusText({status: 'superseded', apply_state: null}), statusText({status: 'draft'}), statusText(null)]""")
        self.assertEqual(got, ["applied — rollout incomplete", "approved — a previous apply was reverted",
                               "withdrawn", "superseded", "draft", ""])

    def test_apply_state_notes(self):
        got = run_node("""[applyStateNote({version: 8, status: 'applied', apply_state: 'rollout incomplete'}),
            applyStateNote({version: 9, status: 'approved', apply_state: 'reverted'}),
            applyStateNote({version: 9, status: 'withdrawn', apply_state: 'reverted'}),
            applyStateNote({version: 1, status: 'applied', apply_state: null}), applyStateNote(null)]""")
        self.assertIn("./apps/iam/apply.sh --resume", got[0])
        self.assertIn("Version 8", got[0])
        self.assertIn("./apps/iam/apply.sh 9 again", got[1])
        self.assertIn("No draft can start while it is open", got[1])
        self.assertEqual(got[2:], ["", "", ""])

    def test_rollback_target(self):
        vs = [{"version": 9, "kind": "rollback", "rollback_of": 1, "reason": "E19"},
              {"version": 7, "kind": "change", "rollback_of": None, "reason": "narrow qc"},
              {"version": 1, "kind": "bootstrap", "reason": "the factory policy"},
              {"version": 10, "kind": "rollback", "rollback_of": 4, "reason": "x"}]
        got = run_node("(vs => [rollbackTarget(vs[0], vs), rollbackTarget(vs[1], vs), rollbackTarget(vs[3], vs), "
                       "rollbackTarget(vs[0], null), rollbackTarget(null, vs)])(%s)" % json.dumps(vs))
        self.assertEqual(got, [{"version": 1, "reason": "the factory policy"}, None, {"version": 4, "reason": None},
                               {"version": 1, "reason": None}, None])


# The RAISE leads of design §14.7.12 the page translates, as the SQL writes them.
LEADS_43 = ("apply.sh recorded you as running version %", "version % is already %",
            "version % is no applied bootstrap or rollback version", "confirming needs the attestation",
            "a note is required", "your access changed since you signed in", "approve access-policy versions in the Policy UI")
LEADS_AUTHOR = ("a reason is required", "no policy version is applied yet", "version % is being applied (%)",
                "version % is still open: take it through or withdraw it first", "no policy version %",
                "a draft starts from applied, defaults or a version number, not %", "version % is not a draft",
                "no role % or group % in the accepted skeleton", "levels must be an object {level: constraint or null}",
                "version % does not pass the checker: fix the errors it lists first",
                "this host has accepted no platform skeleton yet", "version % is not open")
LEADS_APPROVE = ("version % is not submitted", "no policy version is applied",
                 "version % was drafted on version %, but version % is applied now: return it",
                 "you are an author of version %: another qa person approves it",
                 "version % changed since you opened it: reload the page",
                 "the Policy service shows another platform skeleton than this host accepted: run ./apps/iam/deploy.sh, then reload",
                 "the approval names no diff digest",
                 "the diff you saw is not the one the host stored for version %: reload the page",
                 "you are an author of version %: another qa person returns it",
                 "version %: % needs the signed token as evidence: use the Policy UI")
LEADS_44 = ("a policy break-glass is open (event %)", "version % was proposed against skeleton %",
            "approving a skeleton version needs the attestation", "version % widens role %, which you hold")
LEADS_PERSON = ("policy changes are made in the Policy UI by a signed-in person, not by %",
                "your token carries no person_id", "role % holds no % on %")
LEADS_APPROVER = ("approvals are made by a person signed in through the API, not by %",
                  "the approver''s token carries no person_id", "role % holds no approval on %")
LEADS_IAM_API = ("the diff you approved is not the one the Policy service computes now",
                 "version % fails the checker now", "version % changed while it was checked",
                 "only a change or skeleton version has an approval diff", "version % widens role %, which you hold")


def sql_between(text, start, end):
    body = text[text.index(start):]
    return body[:body.index(end)]


def lead_sample(lead):
    """A message the lead would raise: each % filled with a plausible value, '' undoubled."""
    out = lead.replace("''", "'").replace("is already %", "is already confirmed")
    out = re.sub(r"(version |event |\()%", r"\g<1>7", out)
    out = re.sub(r"skeleton %", "skeleton abcdef012345", out)
    return out.replace("%", "engineer")


class Sources(unittest.TestCase):
    def test_every_translated_refusal_is_raised(self):
        mig = read(MIG)
        qa = sql_between(mig, "FUNCTION iam_policy._qa(", "CREATE OR REPLACE FUNCTION iam_policy.why_not")
        for lead in LEADS_43:
            self.assertIn("RAISE EXCEPTION '" + lead, qa, lead)

    def test_the_44_refusals_are_raised(self):
        """§14.7.12: the author functions through why_not, _evidence, _approver, _person_actor."""
        mig = read(MIG)
        policy = sql_between(mig, "FUNCTION iam_policy._evidence(", "CREATE OR REPLACE FUNCTION iam_policy.audit_versions")
        person = sql_between(mig, "FUNCTION medcea_auth._person_actor(", "END $$")
        approver = sql_between(mig, "FUNCTION medcea_auth._approver(", "END $$")
        for leads, body in ((LEADS_AUTHOR + LEADS_APPROVE + LEADS_44, policy), (LEADS_PERSON, person),
                            (LEADS_APPROVER, approver)):
            for lead in leads:
                with self.subTest(lead=lead):
                    self.assertIn("RAISE EXCEPTION '" + lead, body, lead)

    def test_iam_apis_own_refusals(self):
        api = read(API)
        for lead in LEADS_IAM_API:
            with self.subTest(lead=lead):
                pat = r"".join(re.escape(x) if x != "%" else r"(?:%[sdr]|\{[^}]*\}|'\s*\+[^+]+\+\s*')" for x in re.split(r"(%)", lead))
                self.assertRegex(api, pat, lead)

    @unittest.skipUnless(NODE, "node is not installed")
    def test_every_lead_is_translated(self):
        """Each lead has its own REFUSALS entry: friendlyRefusal never answers it with the raw text."""
        leads = LEADS_43 + LEADS_AUTHOR + LEADS_APPROVE + LEADS_44 + LEADS_PERSON + LEADS_APPROVER + LEADS_IAM_API
        samples = [lead_sample(x) for x in leads]
        got = run_node("[" + ", ".join("friendlyRefusal(%s)" % json.dumps(x) for x in samples) + "]")
        for src, text in zip(samples, got):
            self.assertNotEqual(src, text, src)

    def test_skeleton_attestation_is_approves(self):
        mig = read(MIG)
        body = sql_between(mig, "FUNCTION iam_policy.approve(", "END $$")
        self.assertIn(SKELETON_ATTEST, body)
        self.assertIn("const SKELETON_ATTEST = " + json.dumps(SKELETON_ATTEST).replace('"', "'") + ";", read(PAGE))
        self.assertIn(SKELETON_ATTEST, read(API))

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
        self.assertEqual(tabs, {"matrix", "changes", "approval", "whocan", "identities", "breakglass", "history", "confirm"})
        api = read(API)
        me = api[api.index("    def me(self):"):]
        me = me[:me.index("\n\n")]
        self.assertEqual(tabs, set(re.findall(r"'(\w+)': self\.can\(", me)))

    def test_acts_are_the_apis(self):
        """The write capabilities that are not tabs: the page uses exactly ACTS' keys (§14.7.2)."""
        api = read(API)
        m = re.search(r"^ACTS = \{(.*?)^\}", api, re.M | re.S) or re.search(r"^ACTS = \{(.*?)\}$", api, re.M | re.S)
        self.assertTrue(m, "policy_api.py has no ACTS")
        acts = set(re.findall(r"'(\w+)':", m.group(1)))
        self.assertEqual(acts, {"draft", "edit", "submit", "withdraw", "approve", "return"})
        self.assertEqual(set(re.findall(r"ME\.acts\.(\w+)", read(PAGE))), acts)

    def test_45_texts(self):
        """§14.8.12: the stale "IAM 4.5" texts are gone; the apply states shown are iam-api's;
        every version list the page renders goes through statusText; the Confirm card names
        the rollback's target."""
        page = read(PAGE)
        shown = re.sub(r"^\s*//.*$", "", page, flags=re.M)     # the logic block's comments name the slice
        self.assertNotIn("IAM 4.5", shown)
        self.assertNotIn("arrives with", shown)
        self.assertIn("Nothing approved is applied until the host operator runs <code>./apps/iam/apply.sh N</code>", page)
        self.assertIn("your other accounts are checked when the version is applied.", page)
        self.assertIn("It is applied when the host operator runs ./apps/iam/apply.sh ${n}.", page)
        self.assertNotRegex(page, r"\$\{esc\((?:v|open|meta)\.status\)\}")
        self.assertNotIn("meta.status ||", page)
        api = read(API)
        body = api[api.index("def apply_state("):]
        body = body[:body.index("\n\n\n")]
        self.assertEqual(set(re.findall(r"return '([a-z ]+)'", body)), {"rollout incomplete", "reverted"})
        logic = logic_block()
        for state in ("rollout incomplete", "reverted"):
            self.assertIn("v.apply_state === '%s'" % state, logic)
        pending = page[page.index("async function loadPending("):]
        pending = pending[:pending.index("\n}\n")]
        self.assertIn("rollbackTarget(v, VERSIONS)", pending)
        self.assertIn("rollback to version ${rb.version}", pending)

    def test_diff_is_hashed_from_the_bytes(self):
        """fetchDiff hashes the response's ArrayBuffer and parses the same buffer (§14.7.3)."""
        page = read(PAGE)
        body = page[page.index("async function fetchDiff("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("await r.arrayBuffer()", body)
        self.assertIn("parseDiff(buf)", body)
        self.assertIn("digestOf(buf)", body)
        self.assertIn("X-Medcea-Skeleton-Digest", body)
        self.assertIn("X-Medcea-Diff-Digest", body)
        self.assertNotIn(".json()", body)


if __name__ == "__main__":
    unittest.main()
