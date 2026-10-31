#!/usr/bin/env python3
"""tests/iam_workbench_flow.py — the AI workbench's hub administrator cannot enter another
person's server (IAM plan 3.2). Called by tests/iam-workbench.sh, which creates the two
throwaway accounts and passes them on stdin as JSON:

  {"admin": {"username": U, "password": P}, "bio": {...}, "cacert": PATH-or-null}

  python3 tests/iam_workbench_flow.py run      W1-W6, W9
  python3 tests/iam_workbench_flow.py refused W7|W8
                                               one fresh sign-in of "bio", which must not get in:
                                               W7 after its role was removed (the hub's 403 with
                                               the policy's text), W8 after the account was
                                               disabled (Keycloak refuses)

  W1  bio signs in and starts its own server through the hub API; it becomes ready
  W2  admin signs in: /hub/admin and /hub/api/users answer 200; admin is a hub admin, bio not
  W3  admin's GET /user/<bio>/lab and /user/<bio>/api/contents never answer 200 there
  W4  admin cannot mint a token for bio that opens bio's server (403, or a token refused)
  W9  admin's GET /hub/api/users/<bio> carries no stored Keycloak token (no auth_state)
  W5  admin stops bio's server (202/204): K is administration
  W6  admin removes hub user bio (204); iam-workbench.sh then checks the home volume is kept
  W7  (refused W7) with its realm role removed, bio's next sign-in is refused
  W8  (refused W8) with the account disabled, bio's next sign-in does not get in

Every sign-in starts at /hub/login?next=/hub/home (iam_signin_flow.HUB_START), so nothing is
spawned but W1's server. Exit 1 on any failure. Passwords are never printed.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from iam_signin_flow import HUB_START, fetch, opener, sign_in  # noqa: E402

FAILS = []


def check(code, ok, what):
    print(f"  {'PASS' if ok else 'FAIL'}  {code:3} {what}")
    if not ok:
        FAILS.append(code)


def xsrf(op, domain):
    jar = next(h.cookiejar for h in op.handlers if isinstance(h, urllib.request.HTTPCookieProcessor))
    return next((c.value for c in jar if c.name == "_xsrf" and c.domain.lstrip(".") == domain), "")


def api(op, domain, method, path, body=None):
    """(status, parsed JSON or text) of a hub API call with the session's cookie and _xsrf."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"https://{domain}/hub/api{path}", data=data, method=method,
                                 headers={"X-XSRFToken": xsrf(op, domain), "Content-Type": "application/json",
                                          "Referer": f"https://{domain}/hub/home"})
    try:
        with op.open(req, timeout=30) as r:
            raw = r.read().decode("utf-8", "replace")
            status = r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read().decode("utf-8", "replace"), e.code
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return 0, str(e)
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, raw


def signed_in(op, domain, user):
    status, url, _ = sign_in(op, domain, user, HUB_START)
    return status == 200 and urllib.parse.urlsplit(url).path.startswith("/hub/home")


def wait_server(op, domain, name, ready, timeout=420):
    """Poll the user model until the default server is ready (or gone)."""
    end = time.time() + timeout
    while time.time() < end:
        _, u = api(op, domain, "GET", f"/users/{name}")
        srv = (u or {}).get("servers", {}).get("", {}) if isinstance(u, dict) else {}
        if (ready and srv.get("ready")) or (not ready and not srv):
            return True
        time.sleep(5)
    return False


def run(data, domain):
    ca = data.get("cacert")
    bio, admin = data["bio"], data["admin"]
    b, a = opener(ca), opener(ca)
    name = bio["username"]

    ok = signed_in(b, domain, bio)
    check("W1", ok, "bio signs in to /hub/home")
    if not ok:
        return
    code, _ = api(b, domain, "POST", f"/users/{name}/server", {})
    ok = code in (201, 202) and wait_server(b, domain, name, True)
    check("W1", ok, f"bio's own server started (POST {code}) and became ready")
    if not ok:
        return

    ok = signed_in(a, domain, admin)
    check("W2", ok, "admin signs in to /hub/home")
    if not ok:
        return
    status, _, _ = fetch(a, f"https://{domain}/hub/admin")
    check("W2", status == 200, f"admin opens /hub/admin ({status})")
    code, users = api(a, domain, "GET", "/users")
    check("W2", code == 200, f"admin lists the hub users ({code})")
    flags = {u.get("name"): u.get("admin") for u in users} if isinstance(users, list) else {}
    check("W2", flags.get(admin["username"]) is True and flags.get(name) is False,
          f"admin flag: {admin['username']}={flags.get(admin['username'])}, {name}={flags.get(name)}")

    for path in (f"/user/{name}/lab", f"/user/{name}/api/contents"):
        status, url, _ = fetch(a, f"https://{domain}{path}")
        inside = urllib.parse.urlsplit(url).path.startswith(f"/user/{name}/")
        check("W3", not (status == 200 and inside), f"admin's GET {path} ends {status} at {urllib.parse.urlsplit(url).path}")

    code, tok = api(a, domain, "POST", f"/users/{name}/tokens", {"expires_in": 300, "note": "iam-workbench W4"})
    if code in (200, 201) and isinstance(tok, dict) and tok.get("token"):
        plain = opener(ca)
        status, _, _ = fetch(plain, f"https://{domain}/user/{name}/api/contents",
                             headers={"Authorization": f"token {tok['token']}"})
        check("W4", status != 200, f"a token the admin minted for bio opens bio's server: {status}")
        api(a, domain, "DELETE", f"/users/{name}/tokens/{tok.get('id', '')}")
    else:
        check("W4", code == 403, f"admin may not mint a token for bio ({code})")

    code, u = api(a, domain, "GET", f"/users/{name}?include_stopped_servers")
    leaked = isinstance(u, dict) and bool(u.get("auth_state"))
    check("W9", code == 200 and not leaked, f"bio's user model shows the admin no stored tokens ({code})")

    code, _ = api(a, domain, "DELETE", f"/users/{name}/server")
    ok = code in (202, 204) and wait_server(a, domain, name, False)
    check("W5", ok, f"admin stops bio's server ({code})")

    code, _ = api(a, domain, "DELETE", f"/users/{name}")
    check("W6", code == 204, f"admin removes hub user {name} ({code})")


def refused(data, domain, step):
    op = opener(data.get("cacert"))
    status, url, body = sign_in(op, domain, data["bio"], HUB_START)
    got_in = status == 200 and urllib.parse.urlsplit(url).hostname == domain and "/hub/home" in url
    if step == "W7":
        check(step, status == 403 and "No access to AI Workbench" in body,
              f"bio without its role: {status} at {url[:80]} (want the hub's 403 naming the roles)")
    else:
        check(step, not got_in, f"bio disabled: a fresh sign-in ends {status} at {url[:80]}")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "run"
    data = json.load(sys.stdin)
    domain = os.environ["WORKBENCH_DOMAIN"]
    if mode == "run":
        run(data, domain)
    else:
        refused(data, domain, sys.argv[2] if len(sys.argv) > 2 else "W7")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
