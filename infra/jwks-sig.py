#!/usr/bin/env python3
"""infra/jwks-sig.py — the realm's signing keys as PostgREST's jwt-secret.

    curl …/protocol/openid-connect/certs | python3 infra/jwks-sig.py > jwks-sig.json

Reads a JWKS (Keycloak's certs endpoint) on stdin and writes the RS256 signature
keys only, each reduced to kty, kid, use, alg, n and e, sorted by kid, as compact
JSON with sorted keys. Keycloak also publishes an RSA-OAEP encryption key and an
x5c chain per key; PostgREST takes the whole set as candidate verification keys,
so the set is narrowed to what can sign an access token. The output is
byte-stable for the same keys: deploy-infra.sh writes it into Secret medcea-jwks
(key jwks-sig.json) and its sha256 is config-api's pod annotation, so a new
checksum means the realm's keys changed and config-api must restart.

Exit 1, with a message on stderr and nothing on stdout, when no signing key is
left — an empty set would make PostgREST refuse every token. Stdlib only.
"""
import json
import sys

FIELDS = ("kty", "kid", "use", "alg", "n", "e")


def signing_keys(jwks):
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    out = []
    for k in keys if isinstance(keys, list) else []:
        if not isinstance(k, dict):
            continue
        if k.get("alg") != "RS256" or k.get("use") != "sig" or k.get("kty") != "RSA":
            continue
        if not all(isinstance(k.get(f), str) and k.get(f) for f in FIELDS):
            continue
        out.append({f: k[f] for f in FIELDS})
    return sorted(out, key=lambda k: k["kid"])


def main():
    try:
        jwks = json.load(sys.stdin)
    except ValueError as e:
        print("jwks-sig: the input is not JSON (%s)" % e, file=sys.stderr)
        return 1
    keys = signing_keys(jwks)
    if not keys:
        print("jwks-sig: no RS256 signing key in the realm's JWKS", file=sys.stderr)
        return 1
    sys.stdout.write(json.dumps({"keys": keys}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
