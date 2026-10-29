#!/usr/bin/env python3
"""tests/iam_postgrest_flow.py — the HTTP side of tests/iam-postgrest.sh (IAM Phase 2b).

Never run on its own against production: the shell script points it at config-api in
the throwaway namespace medcea-iamtest, whose realm keys are a throwaway RSA key made
here. Tokens are signed here and never printed; each token's signature segment is
appended to DIR/token-sigs (mode 600) so the shell can prove no log holds one.

  keygen DIR NAME                  DIR/NAME.pem (mode 600) and DIR/NAME.jwks.json: a
                                   Keycloak-shaped set (the RS256 key with x5c, plus an
                                   RSA-OAEP "enc" key that infra/jwks-sig.py drops)
  cases MODE BASE DIR NAME [NGINX] P1–P11, P15 and, with NGINX (the JWT nginx in front of
                                   config-api), P16; MODE = IAM_DB_ROLES (false|true)
  rotated BASE DIR NEW OLD         P14: a token of NEW is served, one of OLD refused
  get BASE PATH [DIR NAME]         "STATUS CODE" of one GET, with a valid token of NAME
                                   (operator) when given — for the shell's switch checks

Prints PASS/FAIL lines like the other IAM tests; exit 1 on any FAIL. Needs pyjwt and
cryptography (as tests/test_medcea_iam.py).
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "apps", "iam"))

import jwt  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from compiler import grants, model  # noqa: E402

FAILS = []
UNIT = "IAMP01"


def ok(case, msg):
    print("  PASS  %-9s %s" % (case, msg))


def bad(case, msg):
    print("  FAIL  %-9s %s" % (case, msg))
    FAILS.append(case)


def check(case, cond, msg, detail=""):
    if cond:
        ok(case, msg)
    else:
        bad(case, msg + (" — " + detail if detail else ""))


# ── keys and tokens ──────────────────────────────────────────────────────────────
def _b64(n):
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def keygen(d, name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    path = os.path.join(d, name + ".pem")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    pub = key.public_key().public_numbers()
    enc = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_numbers()
    jwks = {"keys": [
        {"kid": name + "-enc", "kty": "RSA", "alg": "RSA-OAEP", "use": "enc",
         "n": _b64(enc.n), "e": _b64(enc.e), "x5c": ["MIIBfake"], "x5t": "x", "x5t#S256": "y"},
        {"kid": name, "kty": "RSA", "alg": "RS256", "use": "sig",
         "n": _b64(pub.n), "e": _b64(pub.e), "x5c": ["MIIBfake"], "x5t": "x", "x5t#S256": "y"},
    ]}
    with open(os.path.join(d, name + ".jwks.json"), "w") as f:
        json.dump(jwks, f)


class Signer:
    def __init__(self, d, name):
        self.d, self.name = d, name
        with open(os.path.join(d, name + ".pem"), "rb") as f:
            self.key = f.read()

    def token(self, groups=("operator",), azp="config", aud=("medcea-api", "account"),
              typ="Bearer", exp_in=240, sub=None, alg="RS256", extra=None, key=None):
        now = int(time.time())
        user = "iamp-" + "-".join(groups) if groups else "iamp-norole"
        claims = {"iss": "https://keycloak.iamtest/realms/medcea", "aud": list(aud), "typ": typ,
                  "azp": azp, "sub": sub or str(uuid.uuid5(uuid.NAMESPACE_URL, "iamp:" + user)),
                  "preferred_username": user, "person_id": "P-" + user, "groups": list(groups),
                  "iat": now - 5, "exp": now + exp_in}
        claims.update(extra or {})
        tok = jwt.encode(claims, key or self.key, algorithm=alg, headers={"kid": self.name})
        fd = os.open(os.path.join(self.d, "token-sigs"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(tok.rsplit(".", 1)[-1] + "\n")
        return tok, claims


# ── HTTP ─────────────────────────────────────────────────────────────────────────
def req(base, path, token=None, method="GET", body=None, headers=None):
    """(status, parsed body or text). An HTTP error is a result."""
    h = dict(headers or {})
    if token:
        h["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
        h.setdefault("Prefer", "return=representation")
    r = urllib.request.Request(base.rstrip("/") + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            raw = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        status = e.code
    except (urllib.error.URLError, OSError) as e:
        return 0, str(e)
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, raw


def code(body):
    return body.get("code", "") if isinstance(body, dict) else ""


def message(body):
    return body.get("message", "") if isinstance(body, dict) else str(body)[:120]


# ── roles from the policy (no role name hard-coded beyond the obvious ones) ──────
def roles_for_unit():
    p = model.load()
    group = grants.member_objects(p)["medcea.cea_unit"]
    readers = sorted(r for r in p.roles if "R" in p.direct(group, r)[1])
    writers = sorted(r for r in p.roles if {"R", "U"} <= p.direct(group, r)[1])
    return readers, writers


# ── the cases ────────────────────────────────────────────────────────────────────
def cases(mode, base, d, name, nginx=None):
    s = Signer(d, name)
    enforcing = mode == "true"
    readers, writers = roles_for_unit()
    reader = "operator" if "operator" in readers else readers[0]
    writer = writers[0] if writers else None
    q = "/cea_unit?unit_code=eq.%s&select=unit_id,unit_code,description,updated_by_sub,updated_by_source,updated_by_role" % UNIT

    # P1: no token — anon as today (false) or refused by pre_request (true)
    st, b = req(base, q)
    if enforcing:
        check("P1", st == 403 and "no token" in message(b), "no token: 403 'no token' (IAM_DB_ROLES=true)", "%s %s" % (st, b))
    else:
        check("P1", st == 200 and isinstance(b, list) and len(b) == 1, "no token: 200 as anon, as before 2b", "%s %s" % (st, b))

    # P2: a valid access token reads
    tok, _ = s.token((reader,))
    st, b = req(base, q, tok)
    check("P2", st == 200 and isinstance(b, list) and len(b) == 1, "valid %s token: 200, row visible" % reader, "%s %s" % (st, b))

    # P3: a token signed by another key is refused, never served as anon
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    tok, _ = s.token((reader,), key=other)
    st, b = req(base, q, tok)
    check("P3", st == 401 and code(b) in ("PGRST301", "PGRST303"), "foreign signature: 401", "%s %s" % (st, b))
    st, b = req(base, q, "x.y.z")
    check("P3", st == 401, "garbage token: 401", "%s %s" % (st, b))

    # P4: audience without medcea-api
    tok, _ = s.token((reader,), aud=("account",))
    st, b = req(base, q, tok)
    check("P4", st == 401, "audience without medcea-api: 401", "%s %s" % (st, b))

    # P5: expiry. PostgREST allows a little clock skew: 10 s left is served, a token
    # that expired 60 s ago is not. The proxy forwards tokens with >= 60 s left.
    tok, _ = s.token((reader,), exp_in=10)
    st, b = req(base, q, tok)
    check("P5", st == 200, "token with 10 s left: 200", "%s %s" % (st, b))
    tok, _ = s.token((reader,), exp_in=-60)
    st, b = req(base, q, tok)
    check("P5", st == 401 and "expired" in message(b).lower(), "token expired 60 s ago: 401 'expired'", "%s %s" % (st, b))

    # P6: algorithm confusion — HS256 keyed with the public key, and alg none
    # (built by hand: pyjwt rightly refuses to sign either)
    with open(os.path.join(d, name + ".jwks.json")) as f:
        pub = json.dumps(json.load(f)).encode()
    _, claims = s.token((reader,))
    enc = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    signing = enc({"alg": "HS256", "typ": "JWT", "kid": name}) + "." + enc(claims)
    mac = base64.urlsafe_b64encode(hmac.new(pub, signing.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    st, b = req(base, q, signing + "." + mac)
    check("P6", st == 401, "HS256 keyed with the public JWKS: 401", "%s %s" % (st, b))
    st, b = req(base, q, enc({"alg": "none", "typ": "JWT"}) + "." + enc(dict(claims, groups=["admin"])) + ".")
    check("P6", st == 401, "alg none: 401", "%s %s" % (st, b))

    # P7: a "role" claim chooses nothing: the role claim key is .medcea_pgrst_role
    tok, _ = s.token((reader,), extra={"role": "postgres"})
    st, b = req(base, "/rpc/iamtest_whoami", tok, method="POST", body={})
    who = b if isinstance(b, dict) else {}
    want = "anon" if not enforcing else "rr_" + reader
    check("P7", st == 200 and who.get("current_user") == want,
          "role claim 'postgres' ignored: runs as %s" % want, "%s %s" % (st, b))

    # P8: a write is attributed to the verified person (stamp_actor, source token)
    if enforcing and writer is None:
        bad("P8", "no role holds U on cea_unit's group; cannot test attribution")
    else:
        who_role = writer if enforcing else reader
        tok, claims = s.token((who_role,))
        st, b = req(base, "/cea_unit?unit_code=eq.%s" % UNIT, tok, method="PATCH",
                    body={"description": "iam-postgrest P8 %d" % time.time()})
        row = b[0] if isinstance(b, list) and b else {}
        check("P8", st == 200 and row.get("updated_by_source") == "token" and row.get("updated_by_sub") == claims["sub"]
              and row.get("updated_by_role") == who_role,
              "PATCH as %s: stamped source=token, sub and role from the token" % who_role, "%s %s" % (st, b))
        if not enforcing:
            st, b = req(base, "/cea_unit?unit_code=eq.%s" % UNIT, None, method="PATCH",
                        body={"description": "iam-postgrest P8 anon %d" % time.time()})
            row = b[0] if isinstance(b, list) and b else {}
            check("P8", st == 200 and row.get("updated_by_sub") == "db:authenticator",
                  "PATCH without a token: stamped db:authenticator, as before", "%s %s" % (st, b))
        else:
            tok, _ = s.token((reader,)) if reader != writer else s.token(("auditor",))
            st, b = req(base, "/cea_unit?unit_code=eq.%s" % UNIT, tok, method="PATCH", body={"description": "x"})
            check("P8", st in (401, 403) or (st == 200 and b == []),
                  "PATCH by a role without U on master_data: refused or nothing changed", "%s %s" % (st, b))

    # P9–P11: tokens that verify but must not stand for a person
    for case, kw, refusal in (("P9", {"azp": "portal"}, "may not use the API"),
                              ("P10", {"groups": ()}, "no platform role"),
                              ("P11", {"groups": ("operator", "qa")}, "two own roles"),
                              ("P11", {"typ": "ID"}, "not an access token")):
        groups = kw.pop("groups", (reader,))
        tok, _ = s.token(groups, **kw)
        if enforcing:
            st, b = req(base, q, tok)
            check(case, st == 403 and refusal in message(b), "%s: 403 '%s'" % (kw or groups, refusal), "%s %s" % (st, b))
        else:
            st, b = req(base, "/cea_unit?unit_code=eq.%s" % UNIT, tok, method="PATCH",
                        body={"description": "iam-postgrest %s %d" % (case, time.time())})
            row = b[0] if isinstance(b, list) and b else {}
            check(case, st == 200 and row.get("updated_by_sub") == "db:authenticator",
                  "%s: served as anon, not attributed to anyone (db:authenticator)" % (kw or list(groups)),
                  "%s %s" % (st, b))
    # a composite pair has one own role (production_manager includes operator): which
    # role is chosen, not only that the request is served (a read passes as anon or
    # as any rr_ role with R on master_data)
    tok, claims = s.token(("production_manager", "operator"))
    if enforcing:
        st, b = req(base, "/rpc/iamtest_whoami", tok, method="POST", body={})
        who = b if isinstance(b, dict) else {}
        check("P11", st == 200 and who.get("current_user") == "rr_production_manager",
              "production_manager + operator: runs as rr_production_manager", "%s %s" % (st, b))
    else:
        st, b = req(base, "/cea_unit?unit_code=eq.%s" % UNIT, tok, method="PATCH",
                    body={"description": "iam-postgrest P11 composite %d" % time.time()})
        row = b[0] if isinstance(b, list) and b else {}
        check("P11", st == 200 and row.get("updated_by_role") == "production_manager"
              and row.get("updated_by_source") == "token" and row.get("updated_by_sub") == claims["sub"],
              "production_manager + operator: stamped as production_manager (source token)", "%s %s" % (st, b))

    # P15: the readiness probe's anonymous GET / is answered in both modes
    st, b = req(base, "/")
    check("P15", st == 200, "anonymous GET / (readiness probe): 200", "%s %s" % (st, str(b)[:80]))

    # P16: through the JWT nginx, only the proxy's token speaks for the caller
    if nginx:
        tok, claims = s.token((reader,))
        forged, _ = s.token(("admin",))
        st, b = req(nginx, "/api/rpc/iamtest_whoami", None, method="POST", body={}, headers={
            "X-Forwarded-Access-Token": tok, "Authorization": "Bearer " + forged,
            "X-Forwarded-Preferred-Username": "mallory", "X-Forwarded-Groups": "admin",
            "Cookie": "_oauth2_proxy=stolen"})
        h = (b.get("headers") or {}) if isinstance(b, dict) else {}
        check("P16", st == 200 and h.get("authorization") == "Bearer " + tok,
              "nginx: Authorization is the proxy's token, the client's is replaced", "%s" % st)
        check("P16", not any(k in h for k in ("x-forwarded-preferred-username", "x-forwarded-groups",
                                              "x-forwarded-access-token", "cookie", "x-forwarded-user",
                                              "x-forwarded-email")),
              "nginx: identity headers and the cookie never reach PostgREST", ",".join(sorted(h)))
        check("P16", isinstance(b, dict) and not (b.get("cookies") or {}), "nginx: request.cookies is empty")
        st, b = req(nginx, "/api/rpc/iamtest_whoami", None, method="POST", body={},
                    headers={"Authorization": "Bearer " + forged})
        h = (b.get("headers") or {}) if isinstance(b, dict) else {}
        want = 403 if enforcing else 200
        check("P16", st == want and "authorization" not in h,
              "nginx without the proxy's token: a client Authorization is dropped (%d)" % want, "%s %s" % (st, h))

        # R16: /scheduler-api/ is the Config UI's way to the scheduler, whose token
        # check reads X-Forwarded-Access-Token: it must arrive unchanged (copying
        # /api/'s blanking here would make every algorithm or schedule edit
        # person-less). Answered by the echo stand-in of tests/k8s/iam-postgrest-nginx.yaml.
        st, b = req(nginx, "/scheduler-api/algorithms/1", None, method="PUT", body={"default_params": {}},
                    headers={"X-Forwarded-Access-Token": tok})
        e = b if isinstance(b, dict) else {}
        eh = e.get("headers") or {}
        check("R16", st == 200 and e.get("method") == "PUT" and e.get("path") == "/api/algorithms/1",
              "nginx: PUT /scheduler-api/algorithms/1 reaches the scheduler as PUT /api/algorithms/1",
              "%s %s %s" % (st, e.get("method"), e.get("path")))
        check("R16", eh.get("x-forwarded-access-token") == tok,
              "nginx: the scheduler receives the proxy's X-Forwarded-Access-Token", ",".join(sorted(eh)))


def rotated(base, d, new, old):
    st, b = req(base, "/cea_unit?limit=1", Signer(d, new).token(("operator",))[0])
    check("P14", st == 200, "after the roll: a token of the new key is served", "%s %s" % (st, b))
    st, b = req(base, "/cea_unit?limit=1", Signer(d, old).token(("operator",))[0])
    check("P14", st == 401, "after the roll: a token of the removed key is refused", "%s %s" % (st, b))


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cmd = argv[0]
    if cmd == "keygen":
        keygen(argv[1], argv[2])
        return 0
    if cmd == "cases":
        cases(argv[1], argv[2], argv[3], argv[4], argv[5] if len(argv) > 5 and argv[5] else None)
    elif cmd == "rotated":
        rotated(argv[1], argv[2], argv[3], argv[4])
    elif cmd == "get":
        tok = Signer(argv[3], argv[4]).token(("operator",))[0] if len(argv) > 4 else None
        st, b = req(argv[1], argv[2], tok)
        print(st, code(b) or "-")
        return 0
    else:
        print("unknown command " + cmd, file=sys.stderr)
        return 2
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
