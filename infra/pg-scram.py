#!/usr/bin/env python3
"""infra/pg-scram.py — a PostgreSQL SCRAM-SHA-256 verifier for a password on stdin.

  printf '%s' "$PASS" | python3 infra/pg-scram.py
  -> SCRAM-SHA-256$4096:<salt>$<StoredKey>:<ServerKey>

ALTER ROLE … PASSWORD '<verifier>' stores it as is, so the plaintext never reaches the
server, its log or pg_stat_activity (RFC 5802 / RFC 7677, as PostgreSQL computes it).
The password is read from stdin only (never an argument: it would show in ps); one
trailing newline is dropped; empty input is refused. Passwords here are generated from
[A-Za-z0-9._~-] (infra/configure.sh), where SASLprep changes nothing.
"""
import base64
import hashlib
import hmac
import os
import sys

ITERATIONS = 4096


def verifier(password: str, salt: bytes = None, iterations: int = ITERATIONS) -> str:
    salt = salt if salt is not None else os.urandom(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = lambda b: base64.b64encode(b).decode("ascii")  # noqa: E731
    return f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"


def main():
    data = sys.stdin.read()
    if data.endswith("\n"):
        data = data[:-1]
    if not data:
        print("pg-scram.py: empty password on stdin", file=sys.stderr)
        return 1
    print(verifier(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
