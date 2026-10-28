#!/usr/bin/env python3
"""tests/iam_signin_flow.py — sign in to every gated host as each test account, the way a
browser does, and compare who gets in with the access policy. Called by tests/iam-signin.sh,
which creates the accounts and passes them on stdin as JSON:

  {"users": [{"role": R, "username": U, "password": P}, ...], "cacert": PATH-or-null}

Host names come from the environment (config.env, exported). For every host the compiler
marks [compiled] (plus ACCESS_DOMAIN, admin only until Phase 2.7) and every role:
  open https://<host>/ → Keycloak's login form → post the credentials → follow the
  redirects back through the proxy's callback.
One cookie jar per account, so after the first host Keycloak's session signs it in without
the form, as it would in a browser. The outcome is
  in       2xx on the host itself
  refused  403 with the gate's explanation ("No access to <host label>"; the portal's
           own page says "No access yet")
  error    anything else (Keycloak's form again, a required action, a 5xx, a timeout)
and it must equal the policy: a role is admitted exactly when the host's compiled gate lists
it. Prints the matrix; exit 1 on any mismatch or error. Passwords are never printed.
"""
import html
import http.cookiejar
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "apps", "iam"))

from compiler import model, proxies  # noqa: E402

PRE_POLICY = ["operator", "qa", "auditor", "admin"]   # IAM_GATES=false (lib-oauth2-proxy.sh)
FORM = re.compile(r'<form id="kc-form-login"[^>]*\baction="([^"]+)"')


def gated_hosts(p):
    """[(VAR, domain, label, expected roles)] for the hosts whose gate is deployed."""
    out = []
    for var, status in proxies.ENFORCEMENT.items():
        if status == "compiled":
            want = PRE_POLICY if os.environ.get("IAM_GATES", "true") == "false" else proxies.admitted(p, var)
        elif status.startswith("admin only until"):
            want = ["admin"]
        else:
            continue
        domain = os.environ.get(var, "")
        if domain:
            out.append((var, domain, p.hosts[var]["label"], set(want)))
    return out


def opener(cacert):
    ctx = ssl.create_default_context(cafile=cacert) if cacert else ssl._create_unverified_context()
    # The platform CA (deploy-infra.sh, .ca/) has no keyUsage extension. Browsers and
    # curl accept it; Python 3.13's default VERIFY_X509_STRICT does not. Chain, expiry
    # and host name are still verified.
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),
                                       urllib.request.HTTPSHandler(context=ctx))


def fetch(op, url, data=None):
    """(status, final url, body) — following redirects; an HTTP error is a result, not a raise."""
    try:
        with op.open(urllib.request.Request(url, data=data), timeout=20) as r:
            return r.status, r.geturl(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.geturl(), e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return 0, url, str(e)


def sign_in(op, domain, user):
    status, url, body = fetch(op, f"https://{domain}/")
    m = FORM.search(body)
    if m:  # Keycloak's form: no session yet in this jar
        form = urllib.parse.urlencode({"username": user["username"], "password": user["password"],
                                       "credentialId": ""}).encode()
        status, url, body = fetch(op, html.unescape(m.group(1)), form)
    return status, url, body


def classify(domain, label, status, url, body):
    host = urllib.parse.urlsplit(url).hostname
    if 200 <= status < 300 and host == domain:
        return "in", ""
    if status == 403 and ("No access yet" in body or f"No access to {html.escape(label)}" in body):
        return "refused", ""
    if FORM.search(body):
        return "error", "Keycloak showed the login form again (wrong password or account disabled?)"
    title = re.search(r"<title>(.*?)</title>", body, re.S)
    return "error", f"HTTP {status} at {url[:90]}" + (f" — {title.group(1).strip()[:60]}" if title else "")


def main():
    data = json.load(sys.stdin)
    p = model.load()
    hosts = gated_hosts(p)
    users = data["users"]
    fails = []
    results = {}
    for u in users:
        op = opener(data.get("cacert"))
        for var, domain, label, want in hosts:
            got, why = classify(domain, label, *sign_in(op, domain, u))
            expect = "in" if u["role"] in want else "refused"
            results[(u["role"], var)] = (got, expect)
            if got != expect:
                fails.append(f"{u['role']:18} {domain:24} expected {expect}, got {got}" + (f": {why}" if why else ""))

    cols = [v for v, *_ in hosts]
    short = {v: v.replace("_DOMAIN", "").lower()[:8] for v in cols}
    print(f"{'role':18} " + " ".join(f"{short[c]:>8}" for c in cols))
    mark = {("in", "in"): "in", ("refused", "refused"): "·"}
    for u in users:
        row = [mark.get(results[(u["role"], c)], "✗ " + results[(u["role"], c)][0]) for c in cols]
        print(f"{u['role']:18} " + " ".join(f"{x:>8}" for x in row))
    print()
    print(f"{len(users)} roles × {len(cols)} hosts = {len(users) * len(cols)} sign-ins; "
          f"in = admitted, · = refused with the gate's explanation, ✗ = not what the policy says")
    for f in fails:
        print("  FAIL", f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
