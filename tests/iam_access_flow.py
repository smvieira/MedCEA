#!/usr/bin/env python3
"""tests/iam_access_flow.py — IAM 2.7's account decisions through the User Manager with real
tokens. Called by tests/iam-access.sh, which creates the throwaway accounts and passes them
on stdin as JSON:

  {"users": {"admin": {...}, "qa": {...}, "qa2": {...}, "operator": {...}},
   "cacert": PATH-or-null, "with_review": bool, "out": PATH}
  each user: {"id": KEYCLOAK_ID, "username": U, "password": P, "person_id": PID}

Every account signs in the way a browser does (tests/iam_signin_flow.py's sign_in: host →
Keycloak's form → the proxy's callback) and then calls the API with its session cookie, as
the page does: JSON bodies, Content-Type application/json and Origin https://ACCESS_DOMAIN.
The steps (spec 8.3):
  1  admin proposes operator → engineer for the operator account: a widening (the pairs are
     routes.json's widening.operator.engineer, read from apps/iam), so 202 and pending_qa
  2  qa confirms it: 200, and GET /api/users shows the account with role engineer
  3  (--with-review) qa2 creates this quarter's access review: the qa account's last_login
     is not null. Off by default: the review is permanent and one per quarter
  4  admin proposes a person_id for the qa account: 202
  5  qa may not confirm it (the subject): 403
  6  qa2 confirms it: 200, and GET /api/users shows the new person_id
  7a qa may not deactivate the operator (POST /api/users/<id>/status is admin's): 403
  7  admin deactivates the operator (signed in to the portal first): 200; iam-access.sh then
     checks Keycloak holds no session of it
  8  admin proposes the admin's own person_id for qa2: 409 (I17)
  9  a cross-site form POST with qa's cookie to confirm a pending decision: 415 or 403, and
     the decision is still pending (admin withdraws it afterwards)
A decision this run left pending is withdrawn before exit. Writes {"operator_id": …} to
"out" for the session check. Prints one line per step; exit 1 on any failure. Passwords are
never printed.
"""
import json
import os
import sys
import urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "apps", "iam"))
sys.path.insert(0, os.path.join(REPO, "tests"))

from compiler import model, routes  # noqa: E402
from iam_signin_flow import fetch, opener, sign_in  # noqa: E402

DOMAIN = os.environ.get("ACCESS_DOMAIN", "")
PORTAL = os.environ.get("PORTAL_DOMAIN", "")
ORIGIN = "https://%s" % DOMAIN
FAILS = []
OPEN = []          # decision ids this run made that may still be pending


def ok(step, msg):
    print("  PASS  %-4s %s" % (step, msg))


def bad(step, msg):
    print("  FAIL  %-4s %s" % (step, msg))
    FAILS.append(step)


def call(op, method, path, body=None, headers=None):
    """(status, json-or-text) of one API call with the account's session."""
    h = {"Accept": "application/json"}
    data = None
    if method == "POST":
        h.update({"Content-Type": "application/json", "Origin": ORIGIN})
        data = json.dumps(body or {}).encode()
    h.update(headers or {})
    if headers and "Content-Type" in headers and isinstance(body, str):
        data = body.encode()
    status, _, text = fetch(op, "https://%s%s" % (DOMAIN, path), data, h)
    try:
        return status, json.loads(text)
    except ValueError:
        return status, text[:200]


def decision_id(resp):
    d = resp.get("decision") if isinstance(resp, dict) else None
    if isinstance(d, dict):
        return d.get("decision_id") or d.get("id")
    return d


def users_of(op):
    status, data = call(op, "GET", "/api/users")
    if isinstance(data, dict):
        data = data.get("users", [])
    return status, {u.get("id"): u for u in data or [] if isinstance(u, dict)}


def decision(op, did):
    status, data = call(op, "GET", "/api/decisions?status=all&limit=500")
    for d in (data.get("decisions", []) if isinstance(data, dict) else []):
        if d.get("decision_id") == did:
            return d
    return None


def steps(data, ops):
    us = data["users"]
    for k in ("admin", "qa", "qa2", "operator"):
        ops[k] = opener(data.get("cacert"))
        if k == "operator":
            # the operator has no access to the User Manager; a portal session for step 7
            status, url, _ = sign_in(ops[k], PORTAL, us[k])
            (ok if status == 200 else bad)("sign", "operator signed in to the portal (HTTP %s)" % status)
            continue
        status, url, _ = sign_in(ops[k], DOMAIN, us[k])
        if status != 200 or urllib.parse.urlsplit(url).hostname != DOMAIN:
            bad("sign", "%s could not open the User Manager: HTTP %s at %s" % (k, status, url[:80]))
            return
        ok("sign", "%s opened the User Manager" % k)
    adm, qa, qa2 = ops["admin"], ops["qa"], ops["qa2"]
    op_id, qa_id, qa2_id = us["operator"]["id"], us["qa"]["id"], us["qa2"]["id"]

    # 1 — a widening waits
    pairs = routes.compile(model.load()).get("widening", {}).get("operator", {}).get("engineer", [])
    if not pairs:
        bad("1", "operator -> engineer is not a widening in this policy (routes.json widening)")
        return
    status, r = call(adm, "POST", "/api/users/%s/role" % op_id, {"role": "engineer", "reason": "iam-access step 1"})
    d1 = decision_id(r)
    if status == 202 and d1:
        OPEN.append(d1)
        ok("1", "admin's operator -> engineer is decision #%s, waiting for qa (202)" % d1)
        row = decision(qa, d1) or {}
        got = sorted(tuple(p) for p in row.get("widening") or [])
        want = sorted(tuple(p) for p in pairs)
        if got == want:
            ok("1", "its widening equals routes.json's (%d pair(s))" % len(want))
        else:
            bad("1", "widening %s, routes.json %s" % (got, want))
    else:
        bad("1", "expected 202 with a decision, got %s %s" % (status, r))
        return

    # 2 — qa confirms; Keycloak (through the API) shows the new role
    status, r = call(qa, "POST", "/api/decisions/%s/confirm" % d1, {"note": "iam-access step 2"})
    if status == 200:
        OPEN.remove(d1)
        ok("2", "qa confirmed #%s" % d1)
    else:
        bad("2", "confirm: %s %s" % (status, r))
    _, users = users_of(adm)
    roles = (users.get(op_id) or {}).get("roles")
    (ok if roles == ["engineer"] else bad)("2", "the operator account now holds %s" % roles)

    # 3 — the review snapshot (permanent, one per quarter: only on request)
    if data.get("with_review"):
        status, r = call(qa2, "POST", "/api/review", {})
        rid = r.get("review") if isinstance(r, dict) else None
        if isinstance(rid, dict):
            rid = rid.get("review_id")
        if status in (200, 201) and rid:
            _, full = call(qa2, "GET", "/api/review/%s" % rid)
            snap = (full.get("snapshot") if isinstance(full, dict) else None) or {}
            acct = [a for a in snap.get("accounts", []) if a.get("id") == qa_id]
            (ok if acct and acct[0].get("last_login") else bad)(
                "3", "review #%s: the qa account's last_login is %s" % (rid, acct[0].get("last_login") if acct else "absent"))
        else:
            bad("3", "create review: %s %s" % (status, r))
    else:
        print("  NOTE  3    the access review step is skipped (--with-review creates this quarter's review for good)")

    # 4-6 — a person_id change waits, the subject may not confirm it, another qa does
    new_pid = us["qa"]["person_id"] + "-moved"
    status, r = call(adm, "POST", "/api/users/%s/person" % qa_id, {"person_id": new_pid, "reason": "iam-access step 4"})
    d4 = decision_id(r)
    if status == 202 and d4:
        OPEN.append(d4)
        ok("4", "admin's person_id change for the qa account is decision #%s (202)" % d4)
        status, r = call(qa, "POST", "/api/decisions/%s/confirm" % d4, {"note": "iam-access step 5"})
        (ok if status == 403 else bad)("5", "the qa account confirming its own person_id: %s %s" % (status, r.get("error") if isinstance(r, dict) else r))
        status, r = call(qa2, "POST", "/api/decisions/%s/confirm" % d4, {"note": "iam-access step 6"})
        if status == 200:
            OPEN.remove(d4)
            _, users = users_of(adm)
            pid = (users.get(qa_id) or {}).get("person_id")
            (ok if pid == new_pid else bad)("6", "qa2 confirmed #%s; the qa account declares %s" % (d4, pid))
        else:
            bad("6", "qa2's confirm: %s %s" % (status, r))
    else:
        bad("4", "expected 202 with a decision, got %s %s" % (status, r))

    # 7a — qa holds no K on iam_users: the Admin port refuses its deactivation (route check)
    status, r = call(qa, "POST", "/api/users/%s/status" % op_id, {"active": False, "reason": "iam-access step 7a"})
    (ok if status == 403 else bad)("7a", "qa deactivating the operator: %s %s" % (
        status, r.get("error") if isinstance(r, dict) else r))

    # 7 — deactivation applies at once and ends the sessions (checked in iam-access.sh)
    status, r = call(adm, "POST", "/api/users/%s/status" % op_id, {"active": False, "reason": "iam-access step 7"})
    (ok if status == 200 else bad)("7", "admin deactivated the operator: %s%s" % (
        status, " (warning: %s)" % r.get("warning") if isinstance(r, dict) and r.get("warning") else ""))

    # 8 — I17: the admin's person on a qa account
    status, r = call(adm, "POST", "/api/users/%s/person" % qa2_id,
                     {"person_id": us["admin"]["person_id"], "reason": "iam-access step 8"})
    (ok if status == 409 else bad)("8", "the admin's person_id on qa2: %s %s" % (status, r.get("error") if isinstance(r, dict) else r))
    if status in (200, 202) and decision_id(r):
        OPEN.append(decision_id(r))

    # 9 — a forged cross-site form POST changes nothing
    status, r = call(adm, "POST", "/api/users/%s/person" % qa2_id,
                     {"person_id": us["qa2"]["person_id"] + "-x", "reason": "iam-access step 9"})
    d9 = decision_id(r)
    if status == 202 and d9:
        OPEN.append(d9)
        status, _ = call(qa, "POST", "/api/decisions/%s/confirm" % d9, "note=forged",
                         headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://evil.invalid"})
        (ok if status in (403, 415) else bad)("9", "a cross-site form POST with qa's cookie: HTTP %s" % status)
        row = decision(adm, d9) or {}
        (ok if row.get("status") == "pending_qa" else bad)("9", "decision #%s is still %s" % (d9, row.get("status")))
    else:
        bad("9", "could not make a pending decision for the forgery: %s %s" % (status, r))
    return


def main():
    data = json.load(sys.stdin)
    ops = {}
    # The decisions left pending are withdrawn however the steps end (Ctrl-C, an
    # exception): iam-access.sh deletes the accounts next, and a pending decision on a
    # deleted account stays in production's iam.account_decision.
    try:
        steps(data, ops)
    except BaseException:
        finish(ops, data)
        raise
    return finish(ops, data)


def finish(ops, data):
    for did in list(OPEN):
        try:
            status, r = call(ops["admin"], "POST", "/api/decisions/%s/withdraw" % did, {"reason": "iam-access clean-up"})
        except Exception as e:                   # noqa: BLE001 — report and go on
            status = "failed: %s" % e
        print("  ....  withdrew #%s left pending (HTTP %s)" % (did, status))
        if status not in (200, 409):
            print("  ....  withdraw decision #%s in the User Manager (Decisions tab) by hand" % did)
        else:
            OPEN.remove(did)
    if data.get("out"):
        with open(data["out"], "w") as f:
            json.dump({"operator_id": data["users"]["operator"]["id"]}, f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
