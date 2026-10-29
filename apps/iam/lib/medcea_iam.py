"""medcea_iam — the access-policy check every MedCEA service runs on every request
(codeplan IAM plan 1.2, Section 3.1). Shipped in ConfigMap medcea-iam-lib next to the
route table, mounted at /iam/; standard library plus PyJWT (pyjwt[crypto]).

    d = check(service, method, path, headers)    # never raises

  1. the route table (/iam/routes.json, compiler/routes.py) and settings (/iam/settings.json:
     issuer, audience, enforce) are read lazily and re-read when the kubelet updates the
     mount, so a new table or an enforcement switch needs no restart;
  2. a public route (`public_routes`) passes without a token;
  3. the access token is X-Forwarded-Access-Token (oauth2-proxy pass_access_token) or
     Authorization: Bearer; RS256 against the realm's keys (/jwks/jwks.json, Secret
     medcea-jwks; re-read on an unknown key id), iss = the realm URL, aud ∋ medcea-api,
     typ = Bearer, azp ∈ the clients of the hosts that serve this service;
  4. roles = groups claim ∩ platform roles; the route is the most specific "METHOD /path"
     in the service's table (literal segments beat <placeholders>); a route missing from
     the table is refused;
  5. allowed if one of the person's roles may call the route. A route whose only grant
     to them carries a constraint (own_unit, assigned_run …) passes here: the constraint
     is enforced where the data is (Phase 2), and Decision.constraints names it.

Decision.allow is the verdict. While enforce is false (IAM_ENFORCE, Phase 1) the wrappers
let every request through and log "would refuse …"; when true they answer 401/403/503.
Nothing logged contains a token.

actor_role(decision) is the person's own platform role for the database actor
(medcea_auth.set_actor): the roles in the token minus every role another one of them
includes (routes.json role_includes, the database's _own_role() rule) — exactly one, or
None (no role, two own roles, or a route table without role_includes).

Wrappers, called by each service on every request (the service loads this file itself
from /iam/ and reloads it when the mount changes, so a missing ConfigMap heals and a new
version needs no restart):
    flask_check(service)                    from a before_request hook; None or a response
    http_check(handler, service) -> bool    from BaseHTTPRequestHandler.parse_request;
                                            False means a refusal has been sent
"""
import json
import os
import sys
import threading
import time

ROUTES_FILE = os.environ.get("MEDCEA_IAM_ROUTES", "/iam/routes.json")
SETTINGS_FILE = os.environ.get("MEDCEA_IAM_SETTINGS", "/iam/settings.json")
JWKS_FILE = os.environ.get("MEDCEA_IAM_JWKS", "/jwks/jwks.json")
LEEWAY = 30  # seconds of clock skew allowed on exp/iat/nbf

_lock = threading.Lock()
_cache = {}  # path -> (mtime, parsed)


class Decision:
    __slots__ = ("allow", "status", "reason", "who", "route", "group", "constraints")

    def __init__(self, allow, status, reason, who=None, route=None, group=None, constraints=None):
        self.allow, self.status, self.reason = allow, status, reason
        self.who, self.route, self.group, self.constraints = who, route, group, constraints or []

    def __repr__(self):
        return f"Decision({self.allow}, {self.status}, {self.reason!r}, route={self.route!r})"


def _load(path):
    """Parsed JSON of a mounted file, re-read when its mtime changes; None if absent."""
    try:
        mtime = os.stat(path).st_mtime
    except OSError:
        return None
    with _lock:
        hit = _cache.get(path)
        if hit and hit[0] == mtime:
            return hit[1]
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    with _lock:
        _cache[path] = (mtime, data)
    return data


def settings():
    return _load(SETTINGS_FILE) or {}


def enforcing():
    """settings.json's switch; the pod's IAM_ENFORCE if the file has none, so a missing
    settings file cannot quietly turn an enforcing service into a reporting one."""
    s = settings()
    if "enforce" in s:
        return s["enforce"] is True
    return os.environ.get("IAM_ENFORCE") == "true"


# ── routes ──────────────────────────────────────────────────────────────────────────
def _split(path):
    return path.split("?", 1)[0].split("#", 1)[0].split("/")


def match(table, method, path):
    """The most specific key of `table` ("METHOD /path") for this request, or None.
    HEAD is matched as GET. A <x> segment matches any one non-empty segment. A path
    with a trailing slash that matches nothing is tried once without it (/devices/ is
    the list the Config UI asks for; the table says /devices)."""
    key = _match(table, "GET" if method == "HEAD" else method, _split(path))
    want = _split(path)
    if key is None and len(want) > 2 and want[-1] == "":
        key = _match(table, "GET" if method == "HEAD" else method, want[:-1])
    return key


def _match(table, m, want):
    best, best_score = None, -1
    for key in table:
        km, _, kp = key.partition(" ")
        if km != m:
            continue
        segs = kp.split("/")
        if len(segs) != len(want):
            continue
        score = 0
        for s, w in zip(segs, want):
            if s.startswith("<") and s.endswith(">"):
                if not w:
                    break
            elif s == w:
                score += 1
            else:
                break
        else:
            if score > best_score:
                best, best_score = key, score
    return best


# ── tokens ──────────────────────────────────────────────────────────────────────────
def _token(headers):
    t = headers.get("X-Forwarded-Access-Token")
    if t:
        return t.strip()
    a = headers.get("Authorization") or ""
    if a[:7].lower() == "bearer ":
        return a[7:].strip()
    return None


def _key(jwt, kid):
    for attempt in (0, 1):
        jwks = _load(JWKS_FILE)
        if jwks is None:
            return None, "the realm's keys (/jwks/jwks.json) are missing"
        for k in jwks.get("keys", []):
            if k.get("kid") == kid and k.get("alg", "RS256") == "RS256" and k.get("use", "sig") == "sig":
                return jwt.PyJWK(k, algorithm="RS256").key, None
        if attempt == 0:  # rotated: drop the cache and read the mount again
            with _lock:
                _cache.pop(JWKS_FILE, None)
    return None, f"no realm key with id {kid}"


def verify(token, clients):
    """(claims, None) or (None, reason)."""
    try:
        import jwt  # PyJWT
    except ImportError:
        return None, "PyJWT is not installed in this service"
    s = settings()
    if not s.get("issuer"):
        return None, "no issuer in /iam/settings.json"
    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except jwt.PyJWTError:
        return None, "the token is not a JWT"
    key, why = _key(jwt, kid)
    if key is None:
        return None, why
    try:
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=s.get("audience", "medcea-api"),
                            issuer=s["issuer"], leeway=LEEWAY, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
    except jwt.PyJWTError as e:
        return None, f"token refused: {e}"
    if claims.get("typ") != "Bearer":
        return None, f"token type {claims.get('typ')!r} is not Bearer"
    if claims.get("azp") not in clients:
        return None, f"token issued to client {claims.get('azp')!r}, which does not serve this service"
    return claims, None


# ── the check ───────────────────────────────────────────────────────────────────────
def check(service, method, path, headers):
    try:
        return _check(service, method, path, headers)
    except Exception as e:  # a bug here must not take the service down
        return Decision(False, 503, f"check failed: {type(e).__name__}: {e}")


def _check(service, method, path, headers):
    table = _load(ROUTES_FILE)
    if table is None:
        return Decision(False, 503, "the route table (/iam/routes.json) is missing")
    public = table.get("public", {})
    for scope in ("*", service):
        if match({r: 1 for r in public.get(scope, [])}, method, path):
            return Decision(True, 200, "public route")
    svc = table.get("services", {}).get(service)
    if svc is None:
        if service not in public:  # unknown, not merely public-only (access-public)
            return Decision(False, 503, f"service {service!r} is not in the route table")
        svc = {"clients": [], "routes": {}}

    token = _token(headers)
    if not token:
        return Decision(False, 401, "no access token")
    claims, why = verify(token, set(svc.get("clients", [])))
    if claims is None:
        return Decision(False, 401, why)
    platform = set(table.get("roles", []))
    roles = sorted(set(claims.get("groups") or []) & platform)
    who = {"sub": claims.get("sub"), "person_id": claims.get("person_id"),
           "username": claims.get("preferred_username"), "roles": roles, "azp": claims.get("azp")}

    key = match(svc["routes"], method, path)
    if key is None:
        return Decision(False, 403, f"{method} {path.split('?', 1)[0]} is not in {service}'s route table", who)
    route = svc["routes"][key]
    grants = [route["roles"][r] for r in roles if r in route["roles"]]
    if not grants:
        return Decision(False, 403, f"roles {roles or '(none)'} do not hold {'/'.join(route['levels'])} on "
                                    f"{route['group']}", who, key, route["group"])
    if any(g is None for g in grants):
        return Decision(True, 200, "allowed", who, key, route["group"])
    cons = sorted({c for g in grants for c in g})
    return Decision(True, 200, f"allowed subject to {', '.join(cons)}", who, key, route["group"], cons)


def actor_role(decision):
    """The one own platform role of a verified person, or None. Composites collapse to
    the including role (production_manager + operator -> production_manager); two own
    roles, no role, or a table compiled before role_includes give None."""
    who = getattr(decision, "who", None) or {}
    roles = set(who.get("roles") or [])
    table = _load(ROUTES_FILE) or {}
    includes = table.get("role_includes")
    if not roles or not isinstance(includes, dict):
        return None
    covered = {inc for r in roles for inc in (includes.get(r) or [])}
    own = sorted(roles - covered)
    return own[0] if len(own) == 1 else None


def _log(service, method, path, d, enforced):
    user = (d.who or {}).get("username") or "-"
    verb = "refused" if enforced else "would refuse"
    print(f"medcea_iam: {verb} {method} {path.split('?', 1)[0]} on {service} for {user}: "
          f"{d.status} {d.reason}", file=sys.stderr, flush=True)


# ── wrappers ────────────────────────────────────────────────────────────────────────
def flask_check(service):
    """For a Flask before_request hook: None to go on, or the refusal to return."""
    from flask import g, jsonify, request

    d = check(service, request.method, request.path, request.headers)
    g.medcea_iam = d
    if d.allow:
        return None
    enforced = enforcing()
    _log(service, request.method, request.path, d, enforced)
    if enforced:
        return jsonify(error=d.reason), d.status
    return None


def http_check(handler, service):
    """For BaseHTTPRequestHandler.do_*: True to go on; False when a refusal was sent."""
    d = check(service, handler.command, handler.path, handler.headers)
    handler.medcea_iam = d
    if d.allow:
        return True
    enforced = enforcing()
    _log(service, handler.command, handler.path, d, enforced)
    if not enforced:
        return True
    body = json.dumps({"error": d.reason}).encode()
    handler.send_response(d.status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
    return False


if __name__ == "__main__":  # self-test of the matcher: python3 medcea_iam.py
    t = {"GET /api/runs/<id>": 1, "GET /api/runs/active": 1, "GET /<file>": 1, "GET /devices": 1}
    assert match(t, "GET", "/api/runs/active") == "GET /api/runs/active"
    assert match(t, "GET", "/api/runs/7?x=1") == "GET /api/runs/<id>"
    assert match(t, "HEAD", "/devices") == "GET /devices"
    assert match(t, "GET", "/x.json") == "GET /<file>"
    assert match(t, "GET", "/api/runs/") is None          # <id> needs a non-empty segment
    assert match(t, "GET", "/devices/") == "GET /devices"   # trailing slash, tried without
    assert match({"GET /_account/": 1}, "GET", "/_account/") == "GET /_account/"
    assert match(t, "POST", "/devices") is None
    print("ok", time.strftime("%H:%M:%S"))
