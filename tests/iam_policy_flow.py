#!/usr/bin/env python3
"""tests/iam_policy_flow.py — IAM 4.4's drafting and approval through the Policy UI with real
tokens (design §14.7.8). Called by tests/iam-policy.sh, which creates the throwaway accounts
and passes them on stdin as JSON:

  {"users": {"admin": {...}, "admin2": {...}, "qa": {...}, "qa2": {...}},
   "cacert": PATH-or-null, "out": PATH}
  each user: {"id": KEYCLOAK_ID, "username": U, "password": P, "person_id": PID, "role": R}

  tests/iam_policy_flow.py run        steps 0-12 (13, health, is the shell's)
  tests/iam_policy_flow.py withdraw   the trap's first step: test-admin withdraws the version
                                      this run created ("out"), when it is still open

Every account signs in the way a browser does (tests/iam_signin_flow.py's sign_in: host →
Keycloak's form → the proxy's callback) and then calls iam-api :8083 with its session cookie,
as the page does: JSON bodies, Content-Type application/json and Origin https://POLICY_DOMAIN.
The cells it edits are chosen offline with the checker (compiler/invariants.py) from the
applied policy (model.load(), the host file the read-only init pointed at): a harmless
narrowing of a role outside qa's closure (so step 10's own-widening check passes) and a cell
that breaks I16 (step 4). The version number goes to "out" as soon as it exists, so the trap
can withdraw it. Step 8 runs psql as iam_svc in the PostgreSQL pod (KUBECTL, NAMESPACE,
POSTGRES_DB and IAM_SVC_DB_PASS from the environment; the password on stdin). Prints one line
per step; exit 1 on any failure. Passwords and tokens are never printed.
"""
import copy
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "apps", "iam"))
sys.path.insert(0, os.path.join(REPO, "tests"))

from compiler import invariants, model  # noqa: E402
from iam_signin_flow import opener, sign_in  # noqa: E402

DOMAIN = os.environ.get("POLICY_DOMAIN", "")
ORIGIN = "https://%s" % DOMAIN
HEX64 = re.compile(r"^[0-9a-f]{64}$")
OPEN = ("draft", "submitted", "approved")
FAILS = []


def ok(step, msg):
    print("  PASS  %-4s %s" % (step, msg))


def bad(step, msg):
    print("  FAIL  %-4s %s" % (step, msg))
    FAILS.append(step)


def request(op, method, path, body=None):
    """(status, headers, raw bytes) of one call with the account's session; an HTTP error is
    a result, not a raise. Writes carry the page's Content-Type and Origin."""
    h = {"Accept": "application/json"}
    data = None
    if method in ("POST", "PUT"):
        h.update({"Content-Type": "application/json", "Origin": ORIGIN})
        data = json.dumps(body or {}).encode()
    req = urllib.request.Request("https://%s%s" % (DOMAIN, path), data=data, headers=h, method=method)
    try:
        with op.open(req, timeout=60) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return 0, {}, str(e).encode()


def call(op, method, path, body=None):
    """(status, json-or-text)."""
    status, _, raw = request(op, method, path, body)
    text = raw.decode("utf-8", "replace")
    try:
        return status, json.loads(text)
    except ValueError:
        return status, text[:200]


def err(r):
    return r.get("error") if isinstance(r, dict) else r


def verdict(r):
    return (r.get("verdict") or {}) if isinstance(r, dict) else {}


def version_row(op, v):
    """(GET /api/policy document, the version's row or {})."""
    _, doc = call(op, "GET", "/api/policy")
    if not isinstance(doc, dict):
        return {}, {}
    return doc, next((x for x in doc.get("versions", []) if x.get("version") == v), {})


def fetch_diff(op, v):
    """What the Approval screen does (§14.7.3): the raw bytes, hashed as received, the
    document parsed from the same bytes, the skeleton from the header."""
    status, headers, raw = request(op, "GET", "/api/policy/%d/diff?against=applied" % v)
    if status != 200:
        return status, None
    try:
        doc = json.loads(raw.decode("utf-8"))
    except ValueError:
        return status, None
    return status, {"doc": doc, "diff_digest": hashlib.sha256(raw).hexdigest(),
                    "header_digest": headers.get("X-Medcea-Diff-Digest"),
                    "skeleton_digest": headers.get("X-Medcea-Skeleton-Digest"),
                    "entries_digest": doc.get("entries_digest")}


def approval_body(d, note):
    return {"note": note, "entries_digest": d["entries_digest"], "diff_digest": d["diff_digest"],
            "skeleton_digest": d["skeleton_digest"]}


# ── the cells, chosen offline with the checker ──────────────────────────────────────────
def cell_yaml(p, levels, cons):
    order = list(p.levels)
    lv = sorted(levels, key=order.index)
    c = {l: cons[l] for l in lv if cons.get(l)}
    return {"levels": lv, "constraint": c} if c else lv


def with_cell(p, g, r, levels, cons):
    d = copy.deepcopy(p.data)
    d["matrix"].setdefault(g, {})[r] = cell_yaml(p, levels, cons)
    return model.Policy(d)


def payload(p, levels, cons):
    """PUT …/entry's whole-cell map {level: constraint or null}."""
    return {l: cons.get(l) for l in sorted(levels, key=list(p.levels).index)}


def pick_cells(p):
    """(harmless, red): harmless = (group, role, before, after) — one top level dropped from a
    cell of a role outside qa's closure, closed under implies, the checker green; red = the
    same cell (after the harmless change) without a level another of its levels implies, which
    the checker refuses (I16). (None, None) when the policy offers neither."""
    skip = p.effective_roles("qa") | {"qa"}
    order = list(p.levels)
    for g in p.matrix:
        if g in ("iam_policy", "iam_users"):
            continue
        for r in sorted(p.matrix[g]):
            if r in skip or p.cell(g, r) is None:
                continue
            lv, cons, _ = p.cell(g, r)
            for top in reversed(order):
                new = lv - {top}
                if top not in lv or not new or p.closure(new) != new:
                    continue
                if invariants.check(with_cell(p, g, r, new, cons))[0]:
                    continue
                for x in new:
                    for y in p.levels[x]["implies"]:
                        if y in new and invariants.check(with_cell(p, g, r, new - {y}, cons))[0]:
                            return (g, r, (lv, cons), (new, cons)), (new - {y}, cons)
    return None, None


# ── step 8: iam_svc in the PostgreSQL pod ───────────────────────────────────────────────
def iam_svc_approve(v, qa):
    """psql as iam_svc, set_actor as the qa person, then medcea.approve_policy: (rc, output)."""
    kubectl = shlex.split(os.environ.get("KUBECTL") or "microk8s kubectl")
    pw = os.environ.get("IAM_SVC_DB_PASS", "")
    if not pw:
        return None, "IAM_SVC_DB_PASS is not set in config.env"
    sql = ("\\set VERBOSITY verbose\n"
           "BEGIN;\n"
           "SELECT medcea_auth.set_actor('%s', '%s', '%s', 'qa');\n"
           "SELECT medcea.approve_policy(%d, 'test: iam-policy.sh step 8', repeat('0', 64), repeat('0', 64), repeat('0', 64));\n"
           "ROLLBACK;\n") % (qa["id"], qa["person_id"], qa["username"], v)
    cmd = kubectl + ["exec", "-i", "-n", os.environ.get("NAMESPACE", "medcea"), "rdbms-postgresql-0", "--",
                     "sh", "-c", 'read -r PGPASSWORD; export PGPASSWORD; '
                     'exec psql -X -q -v ON_ERROR_STOP=1 -h 127.0.0.1 -U iam_svc -d "$0"',
                     os.environ.get("POSTGRES_DB", "medcea_db")]
    r = subprocess.run(cmd, input=pw + "\n" + sql, capture_output=True, text=True, timeout=60)
    return r.returncode, (r.stdout + r.stderr).strip()


# ── the steps ───────────────────────────────────────────────────────────────────────────
def steps(data, ops):
    us = data["users"]
    for k in ("admin", "admin2", "qa", "qa2"):
        ops[k] = opener(data.get("cacert"))
        status, url, _ = sign_in(ops[k], DOMAIN, us[k])
        if status != 200 or urllib.parse.urlsplit(url).hostname != DOMAIN:
            bad("sign", "%s could not open the Policy UI: HTTP %s at %s" % (k, status, url[:80]))
            return
        ok("sign", "%s opened the Policy UI" % k)
    adm, adm2, qa, qa2 = ops["admin"], ops["admin2"], ops["qa"], ops["qa2"]

    # 0 — what each role is offered (the 4.3 page's GETs, folded in: §14.7.8)
    for k, want_can, want_acts in (("admin", {"changes": True, "approval": False}, {"draft": True, "approve": False}),
                                   ("qa", {"changes": True, "approval": True}, {"draft": False, "approve": True})):
        status, me = call(ops[k], "GET", "/api/me")
        can = me.get("can", {}) if isinstance(me, dict) else {}
        acts = me.get("acts", {}) if isinstance(me, dict) else {}
        good = status == 200 and all(bool(can.get(x)) == w for x, w in want_can.items()) \
            and all(bool(acts.get(x)) == w for x, w in want_acts.items())
        (ok if good else bad)("0", "%s's /api/me: can %s, acts %s" % (
            k, sorted(x for x, y in can.items() if y), sorted(x for x, y in acts.items() if y)))
    for path in ("/api/policy/who-can", "/api/policy/service-identities", "/api/policy/break-glass"):
        status, r = call(adm, "GET", path)
        (ok if status == 200 and isinstance(r, dict) else bad)("0", "admin GET %s: HTTP %s" % (path, status))

    p = model.load()
    harmless, red = pick_cells(p)
    if not harmless:
        bad("2", "the applied policy offers no harmless cell to edit (a narrowing the checker accepts)")
        return
    g, r, (lv0, cons0), (lv1, cons1) = harmless
    print("  ....       the harmless cell: %s on %s, %s → %s" % (
        r, g, "".join(sorted(lv0, key=list(p.levels).index)), "".join(sorted(lv1, key=list(p.levels).index))))

    # 1 — a draft from applied, its verdict recorded at creation
    status, d = call(adm, "POST", "/api/policy/draft", {"from": "applied", "reason": "test: iam-policy.sh step 1"})
    v = d.get("version") if isinstance(d, dict) else None
    if status != 201 or not isinstance(v, int):
        bad("1", "draft from applied: %s %s" % (status, err(d)))
        return
    with open(data["out"], "w") as f:
        json.dump({"version": v}, f)
    _, row = version_row(adm, v)
    (ok if verdict(d).get("ok") is True and row.get("status") == "draft" and row.get("kind") == "change"
     else bad)("1", "admin drafted version %s from applied (%s, %s, checker %s)" % (
        v, row.get("kind"), row.get("status"), verdict(d).get("ok")))

    def put(op, levels, cons, step, reason):
        return call(op, "PUT", "/api/policy/%d/entry" % v, {"role": r, "group": g, "levels": payload(p, levels, cons),
                                                            "reason": "test: iam-policy.sh step %s, %s" % (step, reason)})

    # 2 — one harmless cell, and back
    s1, a = put(adm, lv1, cons1, 2, "a harmless narrowing")
    s2, b = put(adm, lv0, cons0, 2, "back as it was")
    (ok if s1 == 200 and s2 == 200 and verdict(a).get("ok") is True and verdict(b).get("ok") is True else bad)(
        "2", "admin saved the cell and saved it back: %s/%s, checker %s/%s" % (
            s1, s2, verdict(a).get("ok", err(a)), verdict(b).get("ok", err(b))))

    # 3 — admin2 saves it again: a co-author
    s3, c = put(adm2, lv1, cons1, 3, "a harmless narrowing (co-author)")
    (ok if s3 == 200 and verdict(c).get("ok") is True else bad)(
        "3", "admin2 saved the cell: %s, checker %s" % (s3, verdict(c).get("ok", err(c))))

    # 4 — a red save still saves; submit refuses it with the checker's errors; reverted
    if red:
        s4, e = put(adm2, red[0], red[1], 4, "a cell the checker refuses")
        (ok if s4 == 200 and verdict(e).get("ok") is False and verdict(e).get("errors") else bad)(
            "4", "admin2's red save is saved with ok false: %s, %d error(s)" % (s4, len(verdict(e).get("errors") or [])))
        s5, f = call(adm, "POST", "/api/policy/%d/submit" % v, {"reason": "test: iam-policy.sh step 4"})
        (ok if s5 == 409 and isinstance(f, dict) and f.get("errors") else bad)(
            "4", "submit while red: %s %s" % (s5, err(f)))
        s6, e = put(adm2, lv1, cons1, 4, "reverted")
        (ok if s6 == 200 and verdict(e).get("ok") is True else bad)("4", "admin2 reverted it: %s" % s6)
    else:
        bad("4", "the applied policy offers no cell that breaks I16 from the harmless one")

    # 5 — submitted
    s, sub = call(adm, "POST", "/api/policy/%d/submit" % v, {"reason": "test: iam-policy.sh step 5"})
    _, row = version_row(adm, v)
    if s == 200 and HEX64.match(str(sub.get("entries_digest") if isinstance(sub, dict) else "")) \
            and row.get("status") == "submitted":
        ok("5", "admin submitted version %s" % v)
    else:
        bad("5", "submit: %s %s (status %s)" % (s, err(sub), row.get("status")))
        return

    # 6 — admin's token on approve: the route table refuses it
    s, d6 = fetch_diff(qa, v)
    if s != 200 or not d6:
        bad("6", "qa could not fetch the diff: HTTP %s" % s)
        return
    s, x = call(adm, "POST", "/api/policy/%d/approve" % v, approval_body(d6, "test: iam-policy.sh step 6"))
    (ok if s == 403 else bad)("6", "admin approving: %s %s" % (s, err(x)))

    # 7 — test-qa2 is admin2's person, an author
    s, q2 = fetch_diff(qa2, v)
    s, x = call(qa2, "POST", "/api/policy/%d/approve" % v, approval_body(q2 or d6, "test: iam-policy.sh step 7"))
    (ok if s == 403 and "author" in str(err(x)) else bad)("7", "test-qa2 (admin2's person) approving: %s %s" % (s, err(x)))

    # 8 — iam_svc may not call the wrapper (only config-api's path, as the qa role)
    rc, out = iam_svc_approve(v, us["qa"])
    (ok if rc not in (None, 0) and "42501" in out and "permission denied" in out else bad)(
        "8", "iam_svc calling medcea.approve_policy: %s" % (
            next((l.strip() for l in out.splitlines() if "ERROR" in l), out.splitlines()[-1] if out else rc)))

    # 9 — a wrong diff digest: iam-api refuses before forwarding
    wrong = dict(approval_body(d6, "test: iam-policy.sh step 9"), diff_digest="0" * 64)
    s, x = call(qa, "POST", "/api/policy/%d/approve" % v, wrong)
    _, row = version_row(qa, v)
    (ok if s == 409 and row.get("status") == "submitted" else bad)(
        "9", "test-qa approving a diff it did not see: %s %s; version %s" % (s, err(x), row.get("status")))

    # 10 — the diff qa hashed, approved
    s, d10 = fetch_diff(qa, v)
    if s != 200 or not d10:
        bad("10", "qa could not fetch the diff: HTTP %s" % s)
        return
    cells = [(c.get("group"), c.get("role")) for c in d10["doc"].get("cells") or []]
    (ok if d10["diff_digest"] == d10["header_digest"] and (g, r) in cells else bad)(
        "10", "the diff loaded intact (sha256 = X-Medcea-Diff-Digest: %s) and lists %s on %s" % (
            d10["diff_digest"] == d10["header_digest"], r, g))
    s, x = call(qa, "POST", "/api/policy/%d/approve" % v, approval_body(d10, "test: iam-policy.sh step 10"))
    doc, row = version_row(qa, v)
    good = (s == 200 and row.get("status") == "approved" and row.get("diff_digest") == d10["diff_digest"]
            and row.get("approved_skeleton_digest") == doc.get("accepted_skeleton_digest") == d10["skeleton_digest"])
    (ok if good else bad)("10", "test-qa approved version %s: %s %s; %s, diff %s, skeleton %s" % (
        v, s, err(x) if s != 200 else "", row.get("status"), (row.get("diff_digest") or "")[:12],
        "accepted" if row.get("approved_skeleton_digest") == doc.get("accepted_skeleton_digest") else "NOT the accepted one"))

    # 11 — the chain: approved, with its evidence
    s, h = call(qa, "GET", "/api/policy/history?version=%d" % v)
    ev = [e for e in (h.get("events") or [] if isinstance(h, dict) else []) if e.get("event") == "approved"]
    pl = (ev[0].get("payload") or {}) if ev else {}
    (ok if ev and pl.get("diff_digest") == d10["diff_digest"] and HEX64.match(str(pl.get("jws_sha256") or ""))
     else bad)("11", "the chain holds approved (event %s) with the token's evidence" % (ev[0].get("event_id") if ev else None))
    s, c = call(qa, "GET", "/api/policy/chain")
    (ok if s == 200 and isinstance(c, dict) and c.get("ok") is True else bad)(
        "11", "verify_chain: %s" % (c.get("detail") or c.get("ok") if isinstance(c, dict) else c))

    # 12 — withdrawn by an admin
    s, x = call(adm, "POST", "/api/policy/%d/withdraw" % v, {"reason": "test: iam-policy.sh step 12"})
    _, row = version_row(adm, v)
    (ok if s == 200 and row.get("status") == "withdrawn" else bad)(
        "12", "admin withdrew version %s: %s; %s" % (v, s, row.get("status")))


def run(data):
    ops = {}
    steps(data, ops)
    return 1 if FAILS else 0


def withdraw(data):
    """The trap's first step: test-admin withdraws the run's version, if it is still open."""
    try:
        with open(data["out"]) as f:
            v = json.load(f).get("version")
    except (OSError, ValueError):
        return 0
    if not isinstance(v, int):
        return 0
    op = opener(data.get("cacert"))
    status, url, _ = sign_in(op, DOMAIN, data["users"]["admin"])
    if status != 200:
        print("  ....  test-admin could not sign in to withdraw version %s (HTTP %s)" % (v, status))
        return 1
    _, row = version_row(op, v)
    if row and row.get("status") not in OPEN:
        return 0
    s, x = call(op, "POST", "/api/policy/%d/withdraw" % v, {"reason": "test: iam-policy.sh aborted"})
    print("  ....  test-admin withdrew version %s left open (HTTP %s%s)" % (v, s, "" if s == 200 else ", %s" % err(x)))
    return 0 if s == 200 else 1


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("run", "withdraw"):
        print("usage: tests/iam_policy_flow.py run|withdraw  (accounts JSON on stdin)", file=sys.stderr)
        return 2
    data = json.load(sys.stdin)
    return run(data) if sys.argv[1] == "run" else withdraw(data)


if __name__ == "__main__":
    sys.exit(main())
