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
  W2  admin signs in: /hub/admin and /hub/api/users answer 200; admin holds the hub role
      workbench-admin, proved by its scopes in /hub/api/user (admin-ui, list:users,
      read:users, servers, delete:users, unfiltered: under IAM_GATES=true the role comes
      through the hub group, and the model's "roles" lists direct roles only), not the
      built-in admin role, and no tokens, access:servers, shares, admin:users or groups
      scope beyond its own (!user=<admin>); nobody is a built-in hub admin (both admin
      flags false); bio's /hub/admin is 403
  W3  admin's GET /user/<bio>/lab ends 403 at /hub/api/oauth2/authorize (a 200 there is
      the consent page, served only to someone who holds access:servers on bio's server:
      one click on "Authorize" and the admin is in, so it FAILS); the authorize URL asked
      directly is 403 too; /user/<bio>/api/contents is 403 where it is (jupyter_server's
      API answers 403 and never redirects: a sanity check, not a regression guard)
  W4  admin may not mint a token for bio: POST /hub/api/users/<bio>/tokens must be 403.
      A token that comes back FAILS whether or not bio's server takes it (it would be bio's
      own token, inheriting bio's access), and is deleted at once. Reading bio's tokens and
      bio's shares is refused (403, or 404: needs_scope answers 404 when the admin holds the
      scope filtered to itself, as everyone does through the default `user` role); changing
      bio's user record is 403
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

# Never the hub administrator's beyond its own resources (scopes filtered !user=<itself>,
# from JupyterHub's default `user` role): any of these over other people opens their server.
NEVER = {"tokens", "read:tokens", "access:servers", "shares", "users:shares", "admin:users",
         "groups", "admin:groups", "admin:auth_state"}


# workbench-admin's decided scopes (WORKBENCH_ADMIN_ROLE_SCOPES), as /hub/api/user reports
# them expanded and unfiltered.
ADMIN_SCOPES = {"admin-ui", "list:users", "read:users", "servers", "delete:users"}


def foreign(scopes, me):
    """The scopes in NEVER that reach beyond the user's own resources."""
    return sorted(x for x in scopes if x.split("!")[0] in NEVER and x.partition("!")[2] != f"user={me}")


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
    check("W2", flags.get(admin["username"]) is False and flags.get(name) is False,
          f"nobody is a built-in hub admin: {admin['username']}={flags.get(admin['username'])}, "
          f"{name}={flags.get(name)} (want False, False)")
    code, me = api(a, domain, "GET", "/user")
    me = me if isinstance(me, dict) else {}
    # The hub role workbench-admin is held through the hub group (IAM_GATES=true: groups,
    # users []) or by name (false); the user model's "roles" lists direct roles only
    # (user_model: user.roles), so the role is proved by its effective scopes, unfiltered.
    held = me.get("roles") or []
    have = set(me.get("scopes") or [])
    missing = sorted(ADMIN_SCOPES - have)
    check("W2", code == 200 and not missing and "admin" not in held,
          f"admin holds workbench-admin's scopes over every user (missing: {missing or 'none'}) and "
          f"not the built-in admin role (direct roles {sorted(held)}, groups {sorted(me.get('groups') or [])}) ({code})")
    extra = foreign(have, admin["username"])
    check("W2", code == 200 and bool(me.get("scopes")) and not extra,
          f"admin holds no token, server-access, sharing or user-admin scope over others: {extra or 'none'}")
    status, _, _ = fetch(b, f"https://{domain}/hub/admin")
    check("W2", status == 403, f"bio's /hub/admin is refused ({status})")

    # The consent page (200 at /hub/api/oauth2/authorize) is ACCESS: the hub shows it only
    # to someone holding access:servers on bio's server, and one click opens it.
    status, url, _ = fetch(a, f"https://{domain}/user/{name}/lab")
    at = urllib.parse.urlsplit(url).path
    check("W3", status == 403 and at.startswith("/hub/api/oauth2/authorize"),
          f"admin's GET /user/{name}/lab ends {status} at {at} (want 403 at /hub/api/oauth2/authorize)")
    q = urllib.parse.urlencode({"client_id": f"jupyterhub-user-{name}", "response_type": "code",
                                "redirect_uri": f"/user/{name}/oauth_callback"})
    status, url, _ = fetch(a, f"https://{domain}/hub/api/oauth2/authorize?{q}")
    check("W3", status == 403, f"admin's direct authorize for bio's server ends {status} at "
                               f"{urllib.parse.urlsplit(url).path} (want 403)")
    status, url, _ = fetch(a, f"https://{domain}/user/{name}/api/contents")
    at = urllib.parse.urlsplit(url).path
    check("W3", status == 403 and at == f"/user/{name}/api/contents",
          f"admin's GET /user/{name}/api/contents ends {status} at {at} (want 403 there)")

    code, tok = api(a, domain, "POST", f"/users/{name}/tokens", {"expires_in": 300, "note": "iam-workbench W4"})
    if code in (200, 201) and isinstance(tok, dict) and tok.get("token"):
        plain = opener(ca)
        status, _, _ = fetch(plain, f"https://{domain}/user/{name}/api/contents",
                             headers={"Authorization": f"token {tok['token']}"})
        gone, _ = api(a, domain, "DELETE", f"/users/{name}/tokens/{tok.get('id', '')}")
        check("W4", False, f"admin minted a token for bio ({code}); bio's server answered it {status}; "
                           f"deleted: {gone} (want the mint refused, 403)")
    else:
        check("W4", code == 403, f"admin may not mint a token for bio ({code}, want 403)")
    # Every user holds read:tokens and read:shares filtered to itself (the default `user`
    # role's 'self'), and needs_scope answers 404 ("No access to resources or resources not
    # found") rather than 403 when the requester holds the scope in a filtered form that
    # does not cover the resource. Both are refusals; only a 200 is access.
    code, _ = api(a, domain, "GET", f"/users/{name}/tokens")
    check("W4", code in (403, 404), f"admin may not list bio's tokens ({code}, want 403 or 404)")
    code, _ = api(a, domain, "GET", f"/shares/{name}/")
    check("W4", code in (403, 404), f"admin may not see or grant shares of bio's server ({code}, want 403 or 404)")
    code, _ = api(a, domain, "PATCH", f"/users/{name}", {"admin": False})
    check("W4", code == 403, f"admin may not change bio's user record, admin flag included ({code}, want 403)")

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
