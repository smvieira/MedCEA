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
  python3 tests/iam_mqtt_flow.py commission_on   M11a-c (iam-mqtt.sh --commissioning UNIT;
                                              stdin also carries "unit", "work" and a "qa"
                                              account): through the Configuration UI's
                                              /api/rpc the engineer proposes test mode for
                                              UNIT, may not approve it (401/403, 42501), a
                                              qa person approves it; WORK/comm-on marks the
                                              unit flagged
  python3 tests/iam_mqtt_flow.py commission_off  M11e, M11g: the engineer ends it (applies at
                                              once), qa reviews the end
  python3 tests/iam_mqtt_flow.py commission_end  the exit trap's end of a unit left flagged

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
CONFIG = os.environ.get("CONFIG_DOMAIN", "")
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
    check("M10a", s == 415, f"a form POST answers {s} (want 415)")
    s, _ = post(op, DOMAIN, "/_mqtt-credential", origin="https://evil.invalid")
    check("M10b", s == 403, f"a POST from another Origin answers {s} (want 403)")


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


def unit_row(op, code):
    """UNIT's row of medcea.unit_commissioning(), through the Config UI's API."""
    s, rows = post(op, CONFIG, "/api/rpc/unit_commissioning")
    if s != 200 or not isinstance(rows, list):
        return s, None
    return s, next((r for r in rows if (r.get("unit_code") or "").lower() == code.lower()), None)


def commission_on(data):
    code = data["unit"]
    eng, status, _ = session(data, "engineer", CONFIG)
    qa, qstatus, _ = session(data, "qa", CONFIG)
    s, row = unit_row(eng, code)
    if row is None:
        check("M11a", False, f"unit {code}: unit_commissioning answered {s} without it")
        return
    if row.get("commissioning") or row.get("pending_change_id") or row.get("blocking_run_id"):
        check("M11a", False, f"unit {code} is flagged, has a waiting proposal or a run running or scheduled: pick another")
        return
    s, chg = post(eng, CONFIG, "/api/rpc/propose_commissioning",
                  json.dumps({"p_unit_id": row["unit_id"], "p_value": True, "p_reason": "tests/iam-mqtt.sh M11"}))
    check("M11a", s == 200 and isinstance(chg, int), f"the engineer proposed test mode for {code} ({s}, change {chg})")
    if not (s == 200 and isinstance(chg, int)):
        return
    body = json.dumps({"p_target": "medcea.pending_change", "p_id": chg, "p_note": "tests/iam-mqtt.sh M11"})
    s, r = post(eng, CONFIG, "/api/rpc/approve_change", body)
    check("M11b", s in (401, 403) and isinstance(r, dict) and r.get("code") == "42501",
          f"the engineer may not approve it ({s} {r.get('code') if isinstance(r, dict) else ''})")
    s, r = post(qa, CONFIG, "/api/rpc/approve_change", body)
    check("M11c", s == 200, f"a qa person approved it ({s}{'' if s == 200 else ' ' + str(r)[:120]})")
    if s == 200:
        open(os.path.join(data["work"], "comm-on"), "w").close()


def end_commissioning(data, code_end, code_review):
    code = data["unit"]
    eng, _, _ = session(data, "engineer", CONFIG)
    s, row = unit_row(eng, code)
    if not row or not row.get("commissioning"):
        check(code_end, row is not None, f"{code} is not flagged any more ({s})")
        return
    s, chg = post(eng, CONFIG, "/api/rpc/propose_commissioning",
                  json.dumps({"p_unit_id": row["unit_id"], "p_value": False, "p_reason": "tests/iam-mqtt.sh M11 end"}))
    check(code_end, s == 200 and isinstance(chg, int), f"the engineer ended test mode for {code}, at once ({s})")
    if s != 200:
        return
    try:
        os.remove(os.path.join(data["work"], "comm-on"))
    except OSError:
        pass
    qa, _, _ = session(data, "qa", CONFIG)
    s, _ = post(qa, CONFIG, "/api/rpc/approve_change",
                json.dumps({"p_target": "medcea.pending_change", "p_id": chg, "p_note": "tests/iam-mqtt.sh M11 review"}))
    check(code_review, s == 200, f"a qa person reviewed the end ({s})")


def main():
    data = json.load(sys.stdin)
    {"issue": issue, "checks": checks, "deactivate": deactivate, "commission_on": commission_on,
     "commission_off": lambda d: end_commissioning(d, "M11e", "M11g"),
     "commission_end": lambda d: end_commissioning(d, "M11x", "M11y")}[sys.argv[1]](data)
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
