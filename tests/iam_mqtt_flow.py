#!/usr/bin/env python3
"""tests/iam_mqtt_flow.py — the MQTT Explorer's personal credentials (IAM plan 3.5), the
browser side. Called by tests/iam-mqtt.sh, which creates the throwaway accounts and passes
them on stdin as JSON:

  {"engineer": {"username": U, "password": P, "id": SUB}, "operator": {...}, "admin": {...},
   "cacert": PATH-or-null, "out": FILE}

  python3 tests/iam_mqtt_flow.py issue        M1, M2: the operator is refused (gate or 403),
                                              the engineer gets a credential whose rows are
                                              `cli.py compile mqtt`'s for engineer; written
                                              to FILE (mode 600) for the probe pod, never
                                              printed
  python3 tests/iam_mqtt_flow.py checks       M10: 415 without JSON, 403 from another Origin
  python3 tests/iam_mqtt_flow.py deactivate   M6: the admin deactivates the engineer in the
                                              User Manager (an applied decision: permanent,
                                              as tests/iam-access.sh's); then M7: the
                                              engineer's old session gets no new credential

Every sign-in goes through the host's oauth2-proxy and Keycloak's form, as a browser does
(iam_signin_flow.sign_in). Exit 1 on any failure.
"""
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from iam_signin_flow import fetch, opener, sign_in  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOMAIN = os.environ.get("MQTTX_DOMAIN", "")
ACCESS = os.environ.get("ACCESS_DOMAIN", "")
ROOT = os.environ.get("PROJECT_NAME", "medcea")
FAILS = []
NAME = re.compile(r"^explorer-[A-Za-z0-9._-]+-[0-9a-f]{6}$")


def check(code, ok, what):
    print(f"  {'PASS' if ok else 'FAIL'}  {code:4} {what}")
    if not ok:
        FAILS.append(code)


def post(op, domain, path, body="{}", ctype="application/json", origin=None):
    h = {"Accept": "application/json", "Content-Type": ctype, "Origin": origin or f"https://{domain}"}
    status, _, text = fetch(op, f"https://{domain}{path}", body.encode(), h)
    try:
        return status, json.loads(text)
    except ValueError:
        return status, text[:200]


def compiled_rows():
    out = subprocess.run([sys.executable, os.path.join(REPO, "apps", "iam", "compiler", "cli.py"), "compile", "mqtt"],
                         capture_output=True, text=True, check=True).stdout
    rows = json.loads(out)["roles"].get("engineer") or []
    return (sorted(f"{ROOT}/{r['topic']}" for r in rows if r["access"] == "read"),
            sorted(f"{ROOT}/{r['topic']}" for r in rows if r["access"] == "write"))


def session(data, who, domain):
    op = opener(data.get("cacert"))
    status, url, _ = sign_in(op, domain, data[who])
    return op, status, url


def issue(data):
    op, status, url = session(data, "operator", DOMAIN)
    if status == 403:
        check("M1", True, "operator: the Explorer's gate refuses (403)")
    else:
        s, r = post(op, DOMAIN, "/_mqtt-credential")
        check("M1", s in (401, 403), f"operator: POST /_mqtt-credential answered {s}, not 401/403")
    op, status, url = session(data, "engineer", DOMAIN)
    check("M2a", status == 200 and url.startswith(f"https://{DOMAIN}"), f"engineer signed in to the Explorer ({status})")
    s, r = post(op, DOMAIN, "/_mqtt-credential")
    if s != 200 or not isinstance(r, dict):
        check("M2b", False, f"engineer: POST /_mqtt-credential answered {s} {r if not isinstance(r, dict) else r.get('error')}")
        return
    reads, writes = compiled_rows()
    check("M2b", NAME.match(r.get("username") or "") is not None, f"credential issued: {r.get('username')}")
    check("M2c", sorted(r.get("read") or []) == reads and sorted(r.get("write") or []) == writes,
          f"its rows are the compiled engineer rows (read {len(reads)}, write {len(writes)})")
    fd = os.open(data["out"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({"username": r["username"], "password": r["password"]}, fh)


def checks(data):
    op, _, _ = session(data, "engineer", DOMAIN)
    s, _ = post(op, DOMAIN, "/_mqtt-credential", body="x=1", ctype="application/x-www-form-urlencoded")
    check("M10a", s == 415, f"a form POST answers {s}, not 415")
    s, _ = post(op, DOMAIN, "/_mqtt-credential", origin="https://evil.invalid")
    check("M10b", s == 403, f"a POST from another Origin answers {s}, not 403")


def deactivate(data):
    eng, _, _ = session(data, "engineer", DOMAIN)       # its session, kept across the deactivation
    adm, status, _ = session(data, "admin", ACCESS)
    s, r = post(adm, ACCESS, f"/api/users/{data['engineer']['id']}/status",
                json.dumps({"active": False, "reason": "tests/iam-mqtt.sh M6"}))
    check("M6a", s == 200, f"the admin deactivated the engineer in the User Manager ({s})")
    s, r = post(eng, DOMAIN, "/_mqtt-credential")
    # the proxy may still forward the old token (up to 300 s): iam-api's re-issue guard refuses it
    check("M7", not (s == 200 and isinstance(r, dict) and r.get("username")),
          f"the engineer's old session gets no new credential ({s} {r.get('error') if isinstance(r, dict) else ''})")


def main():
    data = json.load(sys.stdin)
    {"issue": issue, "checks": checks, "deactivate": deactivate}[sys.argv[1]](data)
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
