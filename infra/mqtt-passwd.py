#!/usr/bin/env python3
"""Mosquitto 2.x password hashes without the mosquitto_passwd binary.

    printf '%s' "$password" | python3 infra/mqtt-passwd.py            -> prints the hash
    printf '%s' "$password" | python3 infra/mqtt-passwd.py --verify H -> exit 0 if H matches

The password comes in on stdin only, never as an argument, so it is not in `ps`.
Output format is what mosquitto_passwd writes by default (src/password_mosq.c):
`$7$<iterations>$<salt b64>$<hash b64>`, hash type 7 = PBKDF2-HMAC-SHA512,
101 iterations, a 12-byte salt and a 64-byte derived key. Mosquitto reads the
iteration count from the field, so the value here is a default, not a contract.

Used by deploy-infra.sh (service accounts) and edge/flash-device.sh (one
password per board). Standard library only: it runs on a clean Ubuntu host.
"""
import base64
import hashlib
import hmac
import os
import sys

ITERATIONS = 101
SALT_LEN = 12
KEY_LEN = 64


def mosquitto_hash(password: str, salt: bytes | None = None, iterations: int = ITERATIONS) -> str:
    salt = salt or os.urandom(SALT_LEN)
    key = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, iterations, KEY_LEN)
    return "$7$%d$%s$%s" % (iterations, base64.b64encode(salt).decode(), base64.b64encode(key).decode())


def verify(password: str, stored: str) -> bool:
    try:
        _, kind, iterations, salt, key = stored.split("$")
        if kind != "7":
            return False
        salt_b = base64.b64decode(salt)
        expected = base64.b64decode(key)
    except (ValueError, TypeError):
        return False
    got = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt_b, int(iterations), len(expected))
    return hmac.compare_digest(got, expected)


def main(argv: list[str]) -> int:
    password = sys.stdin.read().rstrip("\n")
    if not password:
        sys.exit("mqtt-passwd: empty password on stdin")
    if argv[1:2] == ["--verify"]:
        if len(argv) != 3:
            sys.exit("usage: mqtt-passwd.py --verify HASH  (password on stdin)")
        return 0 if verify(password, argv[2]) else 1
    if argv[1:]:
        sys.exit("usage: mqtt-passwd.py [--verify HASH]  (password on stdin)")
    print(mosquitto_hash(password))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
