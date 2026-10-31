#!/usr/bin/env python3
"""tests/iam_signin_flow.py — sign in to every gated host as each test account, the way a
browser does, and compare who gets in with the access policy. Called by tests/iam-signin.sh,
which creates the accounts and passes them on stdin as JSON:

  {"users": [{"role": R, "username": U, "password": P}, ...], "cacert": PATH-or-null,
   "probes_out": PATH-or-null}

Host names come from the environment (config.env, exported). For every host the compiler
marks [compiled] (ACCESS_DOMAIN too, since IAM 2.7) and every role:
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

Grafana (IAM 3.1, status [tool …]) signs people in itself: there is no gate page. After the
sign-in, GET /api/user is 200 (in) or 401 (refused: Grafana's own login page with the role
error, role_attribute_strict); a redirect loop (auto-login after a refusal) is an error.
Where in, /api/user/orgs must give the role tools.settings compiles (Editor for engineer,
Viewer for the others) and /api/access-control/user/actions must hold datasources:explore
for Editor only (a viewer cannot open Explore). IAM_GATES=false: every enabled account is
in, as Viewer (the test accounts hold no grafana_* role). The role "none" (iam-signin.sh's
account without a platform role) is refused everywhere, Grafana included.

Node-RED (IAM 3.3) keeps its proxy gate; past it, each admitted account completes the
editor's own sign-in (/auth/strategy, silent through the Keycloak session), and GET
/settings with the editor token must show the rights cli.py compile node-red gives its role,
and POST /nodes (a palette install) must be 401. The token is revoked, never printed.
IAM_GATES=false keeps Node-RED's and the MQTT Explorer's compiled lists.

The AI workbench (IAM 3.2, JupyterHub, also [tool …]) starts at
/hub/login?next=/hub/home, so the flow never follows a redirect into /hub/spawn or /user/
and starts no server: "in" is 200 on /hub/home, "refused" JupyterHub's 403 page with the
policy's text ("No access to AI Workbench", custom_403_message). Every account that got
in is a hub user afterwards; the throwaway admin account removes them through the hub API
(DELETE /hub/api/users/<name>, its own session and _xsrf cookie). It cannot remove itself,
so test-admin-<hex> stays as a hub user without a home (delete_pvc false, nothing spawned).

The onboarding wizard (IAM 3.4, [tool …]) signs in like a proxied host (/ → Keycloak → its
own /oauth2/callback); a role outside the policy's onboarding list gets the wizard's 403
("… required to provision hardware", naming the roles), which counts as refused. Nothing is
started. pgAdmin (IAM 3.4) shows its login page: the flow reads the CSRF token from it, posts
/authenticate/login with oauth2_button=keycloak, then Keycloak's form; ending on /browser/
is in, pgAdmin's "not authorized … claims" message is refused. pgAdmin creates a user for
each account it admits (OAUTH2_AUTO_CREATE_USER): only the throwaway admin, and it is gone
when the pod restarts (no volume). The pgAdmin form fields follow pgAdmin 9 and may need
updating after an image update (`dpage/pgadmin4:9`). IAM_GATES=false: the wizard expects
EDGE_WIZARD_ROLE (empty: every account, the role-less one included), pgAdmin admin.

Where it got in, the account then calls one API of each service behind the host (PROBES)
with its session, so the access token goes through the proxy to the service's
medcea_iam.check(). The calls go to "probes_out" with whether the route table lets that
role call the route; `iam_signin_flow.py --compare PROBES LOGS` then checks the services'
logs: a "would refuse" (or, enforcing, "refused") line naming the account for exactly the
calls the table refuses, and none saying the token could not be verified (IAM plan 1.2).
The status must agree too (IAM 2.6): a "refused" call answered 401/403, and an allowed
one never 401 or 503 (a 403 may be the database's own refusal under IAM_DB_ROLES).

With IAM_POSTGREST_JWT=true (Phase 2b) every account the Config UI admits also reads
/api/cea_unit?limit=1 through it, so its access token reaches PostgREST as Bearer: 200 is
expected, a 401 means the proxy forwarded a stale token (cookie_refresh vs the realm's
access token lifespan). Once per account the same call carries forged credentials — a
client Authorization and X-Forwarded-Access-Token, X-Forwarded-Preferred-Username and
-Groups headers — which the proxy and nginx must replace or drop: still 200, never 401.
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

from compiler import model, proxies, routes, tools  # noqa: E402

PRE_POLICY = ["operator", "qa", "auditor", "admin"]   # IAM_GATES=false (lib-oauth2-proxy.sh)
# host variable -> [(browser path, service, path the service sees)]: read-only GETs, one
# real route per service behind the host, plus one path in no route table (SENTINEL), which
# every service must refuse — so a hook that never loaded cannot pass as "allowed".
SENTINEL = "__iam_probe__"
PROBES = {
    "PORTAL_DOMAIN": [("/_account/api/me", "access-profile", "/_account/api/me"),
                      (f"/_account/api/{SENTINEL}", "access-profile", f"/_account/api/{SENTINEL}")],
    "CONFIG_DOMAIN": [("/scheduler-api/units", "scheduler", "/api/units"),
                      (f"/scheduler-api/{SENTINEL}", "scheduler", f"/api/{SENTINEL}"),
                      ("/platform-api/devices/", "platform-api", "/devices/"),
                      (f"/platform-api/{SENTINEL}/x", "platform-api", f"/{SENTINEL}/x")],
    "SCHEDULER_DOMAIN": [("/api/runs", "scheduler", "/api/runs")],
    "MONITOR_DOMAIN": [("/api/runs", "monitor", "/api/runs"),
                       (f"/api/{SENTINEL}", "monitor", f"/api/{SENTINEL}")],
    # IAM 2.6: dbmgmt enforces always (enforce=True), so its log says "refused" too
    "DBMGMT_DOMAIN": [("/api/objects", "dbmgmt", "/objects"),
                      (f"/api/{SENTINEL}", "dbmgmt", f"/{SENTINEL}")],
    # IAM 2.7: every admitted role (admin, qa, qp, auditor) opens the page; the Decisions
    # and review lists and the Users list are refused per route (the Admin port enforces
    # always, so its log says "refused")
    "ACCESS_DOMAIN": [("/api/me", "access", "/api/me"),
                      ("/api/decisions", "access", "/api/decisions"),
                      ("/api/review", "access", "/api/review"),
                      ("/api/users", "access", "/api/users"),
                      (f"/api/{SENTINEL}", "access", f"/api/{SENTINEL}")],
    "MQTTX_DOMAIN": [("/_account/api/me", "access-profile", "/_account/api/me")],
}
FORM = re.compile(r'<form id="kc-form-login"[^>]*\baction="([^"]+)"')


def gated_hosts(p):
    """[(VAR, domain, label, expected roles)] for the hosts whose gate is deployed."""
    out = []
    for var, status in proxies.ENFORCEMENT.items():
        if status != "compiled" and not status.startswith("tool"):
            continue
        if os.environ.get("IAM_GATES", "true") == "false":
            # apps/access/deploy.sh: admin only, never the portal's pre-policy list;
            # Grafana's pre-3.1 setting: any enabled account, with or without a role
            # Node-RED and the MQTT Explorer keep their compiled list (IAM 3.3 decision)
            # the wizard: EDGE_WIZARD_ROLE (empty: any signed-in account); pgAdmin: admin
            legacy = [r.strip() for r in os.environ.get("EDGE_WIZARD_ROLE", "").split(",") if r.strip()]
            want = (["admin"] if var in ("ACCESS_DOMAIN", "PGADMIN_DOMAIN") else
                    proxies.admitted(p, var) if var in ("NODE_RED_DOMAIN", "MQTTX_DOMAIN") else
                    (legacy or list(p.roles) + ["none"]) if var == "ONBOARD_DOMAIN" else
                    list(p.roles) + ["none"] if status.startswith("tool") else PRE_POLICY)
        else:
            want = proxies.admitted(p, var)
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


def fetch(op, url, data=None, headers=None):
    """(status, final url, body) — following redirects; an HTTP error is a result, not a raise."""
    try:
        with op.open(urllib.request.Request(url, data=data, headers=headers or {}), timeout=20) as r:
            return r.status, r.geturl(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.geturl(), e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return 0, url, str(e)


def sign_in(op, domain, user, path="/"):
    status, url, body = fetch(op, f"https://{domain}{path}")
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
    if status == 403 and host == domain and "required to provision hardware" in body:
        return "refused", ""   # the onboarding wizard's own refusal (IAM 3.4)
    if FORM.search(body):
        return "error", "Keycloak showed the login form again (wrong password or account disabled?)"
    title = re.search(r"<title>(.*?)</title>", body, re.S)
    return "error", f"HTTP {status} at {url[:90]}" + (f" — {title.group(1).strip()[:60]}" if title else "")


PGADMIN_CSRF = re.compile(r'"csrfToken":\s*"([^"]+)"')


def pgadmin_sign_in(op, domain, user):
    """pgAdmin 9's own OAuth2 sign-in: its login page, the MedCEA button, Keycloak."""
    status, url, body = fetch(op, f"https://{domain}/login")
    m = PGADMIN_CSRF.search(body)
    if not m:
        return status, url, body
    form = urllib.parse.urlencode({"csrf_token": m.group(1), "oauth2_button": "keycloak"}).encode()
    status, url, body = fetch(op, f"https://{domain}/authenticate/login", form,
                              headers={"Referer": f"https://{domain}/login"})
    m = FORM.search(body)
    if m:  # Keycloak's form: no session yet in this jar
        form = urllib.parse.urlencode({"username": user["username"], "password": user["password"],
                                       "credentialId": ""}).encode()
        status, url, body = fetch(op, html.unescape(m.group(1)), form)
    return status, url, body


def classify_pgadmin(domain, status, url, body):
    parts = urllib.parse.urlsplit(url)
    if 200 <= status < 300 and parts.hostname == domain and parts.path.startswith("/browser"):
        return "in", ""
    if parts.hostname == domain and "not authorized" in body:
        return "refused", ""
    if FORM.search(body):
        return "error", "Keycloak showed the login form again (wrong password or account disabled?)"
    if parts.hostname == domain and parts.path.startswith("/login"):
        return "error", "back on pgAdmin's login page without its claims message (CSRF or form fields changed?)"
    return "error", f"HTTP {status} at {url[:90]}"


def grafana_role(p, role):
    """The Grafana org role the policy gives a platform role (None: refused)."""
    if os.environ.get("IAM_GATES", "true") == "false":
        return "Viewer"
    return next((setting for setting, roles in tools.settings(p, "dashboards") if role in roles), None)


def classify_grafana(op, domain, status, url, body):
    """(outcome, why, org role or None) for Grafana, which shows no gate page."""
    if 300 <= status < 400:
        return "error", f"HTTP {status} at {url[:90]}: a redirect loop (auto-login after a refusal?)", None
    if FORM.search(body):
        return "error", "Keycloak showed the login form again (wrong password or account disabled?)", None
    code, _, me = fetch(op, f"https://{domain}/api/user")
    if code == 401:
        return "refused", "", None
    if code != 200:
        return "error", f"GET /api/user answered {code}", None
    code, _, orgs = fetch(op, f"https://{domain}/api/user/orgs")
    try:
        role = json.loads(orgs)[0]["role"]
    except (ValueError, LookupError, TypeError):
        return "error", f"GET /api/user/orgs answered {code}: {orgs[:80]}", None
    return "in", "", role


def grafana_checks(op, domain, p, user_role, got_role):
    """The org role is the compiled one, and only an Editor may open Explore."""
    out = []
    want = grafana_role(p, user_role)
    if got_role != want:
        out.append(f"{user_role:18} {domain:24} Grafana role {got_role}, the policy gives {want}")
    code, _, body = fetch(op, f"https://{domain}/api/access-control/user/actions")
    try:
        explore = "datasources:explore" in json.loads(body)
    except ValueError:
        out.append(f"{user_role:18} {domain:24} GET /api/access-control/user/actions answered {code}")
        return out
    if explore != (got_role == "Editor"):
        out.append(f"{user_role:18} {domain:24} {got_role} {'may' if explore else 'may not'} open Explore")
    return out


def node_red_checks(op, domain, p, user_role):
    """IAM 3.3: past the proxy, Node-RED's editor signs the account in again (adminAuth,
    autoLogin, silent through the Keycloak session) and gives the compiled rights. The
    editor token is never printed, and is revoked afterwards."""
    status, url, _ = fetch(op, f"https://{domain}/auth/strategy")
    parts = urllib.parse.urlsplit(url)
    token = (urllib.parse.parse_qs(parts.query).get("access_token") or [None])[0]
    if not token:
        return [f"{user_role:18} {domain:24} Node-RED's own sign-in gave no editor token (HTTP {status} at {parts.path})"]
    bearer = {"Authorization": f"Bearer {token}"}
    out = []
    code, _, body = fetch(op, f"https://{domain}/settings", headers=bearer)
    try:
        got = (json.loads(body).get("user") or {}).get("permissions")
    except ValueError:
        got = f"HTTP {code}"
    want = tools.node_red_permissions(p)["permissions"].get(user_role)
    if sorted(got or []) != sorted(want or []):
        out.append(f"{user_role:18} {domain:24} Node-RED editor rights {got}, the policy gives {want}")
    code, _, _ = fetch(op, f"https://{domain}/nodes", data=b'{"module":"__iam_probe__"}',
                       headers={**bearer, "Content-Type": "application/json"})
    if code != 401:
        out.append(f"{user_role:18} {domain:24} installing a palette module answered {code}, not 401 (packages.txt only)")
    fetch(op, f"https://{domain}/auth/revoke", data=urllib.parse.urlencode({"token": token}).encode(), headers=bearer)
    return out


HUB_START = "/hub/login?next=%2Fhub%2Fhome"   # never /hub/ (redirect_to_server spawns)


def hub_cleanup(op, domain, names):
    """Remove the hub users the sign-ins created, as the throwaway admin (its session)."""
    jar = next(h.cookiejar for h in op.handlers if isinstance(h, urllib.request.HTTPCookieProcessor))
    xsrf = next((c.value for c in jar if c.name == "_xsrf" and c.domain.lstrip(".") == domain), None)
    if not xsrf:
        return [f"{domain}: no _xsrf cookie in the admin's session; remove the hub users {', '.join(names)} by hand"]
    out = []
    for n in names:
        req = urllib.request.Request(f"https://{domain}/hub/api/users/{urllib.parse.quote(n)}", method="DELETE",
                                     headers={"X-XSRFToken": xsrf, "Referer": f"https://{domain}/hub/admin"})
        try:
            with op.open(req, timeout=20) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            code = str(e)
        if code not in (204, 404):
            out.append(f"{domain}: could not remove hub user {n} ({code}); remove it on the hub's admin page")
    return out


def _library():
    """apps/iam/lib/medcea_iam.py, for its route matcher (the same one the services use)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("medcea_iam", os.path.join(REPO, "apps", "iam", "lib", "medcea_iam.py"))
    lib = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lib)
    return lib


def compare(probes_file, logs_file):
    """Each probe the table refuses has a "would refuse" line in its service's log, and no
    probe it allows has one; a "refused" probe answered 401/403, an allowed one neither
    401 nor 503. Exit 1 otherwise."""
    with open(probes_file) as f:
        probes = json.load(f)
    with open(logs_file) as f:
        logs = f.read().splitlines()
    bad = []
    for pr in probes:
        tail = f" GET {pr['seen']} on {pr['service']} for "
        lines = [l for l in logs if ("medcea_iam: would refuse" + tail in l or "medcea_iam: refused" + tail in l)]
        hit = [l for l in lines if tail + pr["user"] + ":" in l]
        anon = [l for l in lines if tail + "-:" in l]   # the token itself was not verified
        if anon and not hit:
            bad.append(f"{pr['role']:18} {pr['host']}{pr['path']}: the service could not verify the token:"
                       f"{anon[0].split(':', 2)[-1]}")
        elif pr["allowed"] and hit:
            bad.append(f"{pr['role']:18} {pr['host']}{pr['path']}: the table allows it, but{hit[0].split(':', 2)[-1]}")
        elif not pr["allowed"] and not hit:
            bad.append(f"{pr['role']:18} {pr['host']}{pr['path']}: the table refuses it, but nothing was logged")
        elif hit and "medcea_iam: refused" in hit[0] and pr.get("status") not in (401, 403):
            bad.append(f"{pr['role']:18} {pr['host']}{pr['path']}: refused in the log but answered {pr.get('status')}")
        elif pr["allowed"] and pr.get("status") in (401, 503):
            bad.append(f"{pr['role']:18} {pr['host']}{pr['path']}: the table allows it, but it answered {pr['status']}")
    n_ref = sum(not p["allowed"] for p in probes)
    print(f"{len(probes)} API calls through the proxies ({len(probes) - n_ref} allowed by the route table, "
          f"{n_ref} refused); the services' checks agree on {len(probes) - len(bad)}")
    for b in bad:
        print("  FAIL", b)
    return 1 if bad or not probes else 0


FORGED = {"Authorization": "Bearer x.y.z", "X-Forwarded-Access-Token": "x.y.z",
          "X-Forwarded-Preferred-Username": "mallory", "X-Forwarded-Groups": "admin"}


def postgrest_probes(op, domain, role):
    """Phase 2b: PostgREST behind the Config UI answers with the proxy's fresh token."""
    out = []
    url = f"https://{domain}/api/cea_unit?limit=1"
    status, _, body = fetch(op, url)
    if status == 401:
        out.append(f"{role:18} {domain}/api/cea_unit: 401 — the proxy forwarded an expired or "
                   f"unverifiable token (freshness: cookie_refresh vs accessTokenLifespan): {body[:100]}")
    elif status != 200:
        out.append(f"{role:18} {domain}/api/cea_unit: HTTP {status}, expected 200: {body[:100]}")
    status, _, body = fetch(op, url, headers=FORGED)
    if status != 200:
        out.append(f"{role:18} {domain}/api/cea_unit with forged Authorization/identity headers: "
                   f"HTTP {status}, expected 200 (the proxy and nginx replace them): {body[:100]}")
    return out


def main():
    if sys.argv[1:2] == ["--compare"]:
        return compare(sys.argv[2], sys.argv[3])
    data = json.load(sys.stdin)
    p = model.load()
    hosts = gated_hosts(p)
    users = data["users"]
    table = routes.compile(p)
    lib = _library()
    fails = []
    results = {}
    probes = []
    hub_users, hub_admin = [], None
    for u in users:
        op = opener(data.get("cacert"))
        for var, domain, label, want in hosts:
            if var == "WORKBENCH_DOMAIN":
                got, why = classify(domain, label, *sign_in(op, domain, u, HUB_START))
            elif var == "GRAFANA_DOMAIN":
                got, why, gf_role = classify_grafana(op, domain, *sign_in(op, domain, u))
            elif var == "PGADMIN_DOMAIN":
                got, why = classify_pgadmin(domain, *pgadmin_sign_in(op, domain, u))
            else:
                got, why = classify(domain, label, *sign_in(op, domain, u))
            expect = "in" if u["role"] in want else "refused"
            results[(u["role"], var)] = (got, expect)
            if got != expect:
                fails.append(f"{u['role']:18} {domain:24} expected {expect}, got {got}" + (f": {why}" if why else ""))
            if got != "in":
                continue
            if var == "WORKBENCH_DOMAIN":
                if u["role"] == "admin" and os.environ.get("IAM_GATES", "true") != "false":
                    hub_admin = (op, domain)
                else:
                    hub_users.append(u["username"])
                continue
            if var == "GRAFANA_DOMAIN":
                fails.extend(grafana_checks(op, domain, p, u["role"], gf_role))
                continue
            if var == "NODE_RED_DOMAIN":
                fails.extend(node_red_checks(op, domain, p, u["role"]))
            if var == "CONFIG_DOMAIN" and os.environ.get("IAM_POSTGREST_JWT", "false") == "true":
                fails.extend(postgrest_probes(op, domain, u["role"]))
            for path, service, seen in PROBES.get(var, []):
                status, _, _ = fetch(op, f"https://{domain}{path}")
                svc = table["services"][service]
                key = lib.match(svc["routes"], "GET", seen)
                probes.append({"user": u["username"], "role": u["role"], "host": domain, "path": path,
                               "service": service, "seen": seen, "status": status,
                               "allowed": bool(key) and u["role"] in svc["routes"][key]["roles"]})
    if hub_users and hub_admin:
        print(f"Removing {len(hub_users)} hub user(s) the sign-ins created on the AI workbench")
        for msg in hub_cleanup(*hub_admin, hub_users):
            print("  NOTE", msg)
    elif hub_users:
        print(f"  NOTE the throwaway admin is no hub admin here: remove hub users {', '.join(hub_users)} by hand")
    if data.get("probes_out"):
        with open(data["probes_out"], "w") as f:
            json.dump(probes, f)

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
