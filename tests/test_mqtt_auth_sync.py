#!/usr/bin/env python3
"""tests/test_mqtt_auth_sync.py — the broker's auth sidecar (k8s/mosquitto/mqtt-auth-sync.py)
and the broker's two confs, offline (IAM 3.5). Stdlib only; no database, no broker.

  - IAM_MQTT_PERSON=false: passwd/acl exactly as before 3.5 for services and boards (golden
    text below), and the conf ConfigMap is tests/golden/mosquitto-conf.yaml byte for byte
  - true: no explorer- name in passwd (1883), only explorer- names in passwd-ws; a '+' write
    row expands to flagged units without a running run only; a concrete unit that is not
    flagged, or has a run in R, or is unknown, is dropped; expired credentials are dropped;
    a unit code with a space, '/', '+' or '#' is never expanded; an unparseable topic is
    skipped; a failed read keeps reads and drops every write, and serves no person once
    PERSON_GRACE has passed since the last good read; no credential gives the
    explorer-none placeholder; a credential without rows still connects
  - the broker waits for passwd-ws only in person mode; the person conf has per-listener auth
  - status.json's content carries no hash

Run from the repository root:  python3 tests/test_mqtt_auth_sync.py
"""
import datetime
import importlib.util
import os
import re
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load():
    spec = importlib.util.spec_from_file_location("mqtt_auth_sync", os.path.join(REPO, "k8s", "mosquitto", "mqtt-auth-sync.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.log = lambda *a: None
    return mod


S = load()
NOW = datetime.datetime(2026, 10, 31, 12, 0, tzinfo=datetime.timezone.utc)
LATER = NOW + datetime.timedelta(hours=8)
H = "$7$101$c2FsdHNhbHRzYWx0$aGFzaA=="
SERVICES_P = "node-red:%s\nscheduler:%s\nmqtt-explorer:%s" % (H, H, H)
SERVICES_A = ("user node-red\ntopic read medcea/#\n\nuser scheduler\ntopic read medcea/+/+/sense/#\n"
              "topic write medcea/+/+/control/#\n\nuser mqtt-explorer\ntopic readwrite medcea/#")
BOARDS = [("unit01-s-zone01", H, "SENSE", "medcea/UNIT01/ZONE01"),
          ("unit01-c-zone01", H, "CONTROL", "medcea/UNIT01/ZONE01"),
          ("bad name", H, "SENSE", "medcea/X/Y")]
# What the sidecar wrote before IAM 3.5 for these inputs (render() at c380ddb).
GOLDEN_PASSWD = SERVICES_P + "\nunit01-s-zone01:%s\nunit01-c-zone01:%s\n" % (H, H)
GOLDEN_ACL = (SERVICES_A + "\n\nuser unit01-s-zone01\ntopic write medcea/UNIT01/ZONE01/sense/#\n\n"
              "user unit01-c-zone01\ntopic read medcea/UNIT01/ZONE01/control/#\n"
              "topic write medcea/UNIT01/ZONE01/control_setpoint/#\n")
UNITS = [("UNIT01", True, False), ("UNIT02", True, True), ("UNIT03", False, False),
         ("UNIT 4", True, False), ("U/5", True, False)]


def person(name, rows, expires=LATER):
    if not rows:
        return [(name, H, expires, None, None)]
    return [(name, H, expires, a, t) for a, t in rows]


ENG = person("explorer-eve-a1b2c3", [("read", "medcea/+/+/sense/#"), ("read", "medcea/+/+/control/#"),
                                      ("write", "medcea/+/+/control/#")])


def users(text):
    return [l.split(":", 1)[0] for l in text.splitlines() if l]


def acl_of(acl, user):
    out, on = [], False
    for l in acl.splitlines():
        if l.startswith("user "):
            on = l == "user " + user
        elif on and l:
            out.append(l)
    return out


class SharedMode(unittest.TestCase):
    def test_golden_false_mode(self):
        p, a, n = S.render(SERVICES_P, SERVICES_A, BOARDS)
        self.assertEqual((p, a, n), (GOLDEN_PASSWD, GOLDEN_ACL, 2))

    def test_conf_is_the_old_one(self):
        with open(os.path.join(REPO, "k8s", "mosquitto", "mosquitto-conf.yaml")) as fh:
            body = "".join(l for l in fh if not l.startswith("#"))
        with open(os.path.join(REPO, "tests", "golden", "mosquitto-conf.yaml")) as fh:
            self.assertEqual(body, fh.read())


class PersonMode(unittest.TestCase):
    def test_1883_has_no_person_name(self):
        p, a, n = S.render(SERVICES_P + "\nexplorer-x:" + H, SERVICES_A, BOARDS + [("explorer-y", H, "SENSE", "medcea/A/B")],
                           S.PERSON_PREFIX)
        self.assertFalse([u for u in users(p) if u.startswith("explorer-")])
        self.assertIn("unit01-s-zone01", users(p))

    def test_websocket_has_only_person_names(self):
        p, a, st = S.render_persons(ENG, UNITS, "medcea", True, NOW)
        self.assertEqual(users(p), ["explorer-eve-a1b2c3"])
        self.assertEqual(st["credentials"], 1)

    def test_plus_write_expands_to_idle_flagged_units_only(self):
        p, a, st = S.render_persons(ENG, UNITS, "medcea", True, NOW)
        writes = [l for l in acl_of(a, "explorer-eve-a1b2c3") if l.startswith("topic write")]
        self.assertEqual(writes, ["topic write medcea/UNIT01/+/control/#"])   # not UNIT02 (run), 03, 'UNIT 4', 'U/5'
        reads = [l for l in acl_of(a, "explorer-eve-a1b2c3") if l.startswith("topic read")]
        self.assertEqual(reads, ["topic read medcea/+/+/sense/#", "topic read medcea/+/+/control/#"])

    def test_concrete_units(self):
        rows = person("explorer-eve-a1b2c3", [("write", "medcea/UNIT01/Z1/control/#"), ("write", "medcea/UNIT02/+/control/#"),
                                              ("write", "medcea/UNIT03/+/control/#"), ("write", "medcea/UNIT09/+/control/#")])
        p, a, st = S.render_persons(rows, UNITS, "medcea", True, NOW)
        self.assertEqual(acl_of(a, "explorer-eve-a1b2c3"), ["topic write medcea/UNIT01/Z1/control/#"])
        self.assertEqual(st["dropped"]["run_in_progress"], 1)       # dies when a run starts
        self.assertEqual(st["dropped"]["not_commissioning"], 1)
        self.assertEqual(st["dropped"]["unknown_unit"], 1)

    def test_expired_dropped(self):
        rows = ENG + person("explorer-old-000000", [("read", "medcea/+/+/sense/#")], NOW - datetime.timedelta(seconds=1))
        p, a, st = S.render_persons(rows, UNITS, "medcea", True, NOW)
        self.assertNotIn("explorer-old-000000", users(p))

    def test_unparseable_and_foreign_root_skipped(self):
        rows = person("explorer-eve-a1b2c3", [("read", "medcea/+/+/telemetry/#"), ("read", "other/+/+/sense/#"),
                                              ("read", "medcea/a b/+/sense/#"), ("read", "medcea/+/+/sense/x")])
        p, a, st = S.render_persons(rows, UNITS, "medcea", True, NOW)
        self.assertEqual(acl_of(a, "explorer-eve-a1b2c3"), [])
        self.assertIn("explorer-eve-a1b2c3", users(p))      # connected, no rights
        self.assertEqual(st["dropped"]["unparseable"], 3)  # 'a b' is unusable before parsing

    def test_db_failure_keeps_reads_drops_writes(self):
        p, a, st = S.render_persons(ENG, UNITS, "medcea", False, NOW)
        lines = acl_of(a, "explorer-eve-a1b2c3")
        self.assertFalse([l for l in lines if "write" in l])
        self.assertEqual(len(lines), 2)
        self.assertEqual(st["dropped"]["db_unavailable"], 1)

    def test_failed_reads_end_reads_after_the_grace(self):
        ok = NOW - datetime.timedelta(seconds=20)
        self.assertEqual(S.kept_persons(ENG, ok, NOW, grace=30), ENG)
        self.assertEqual(S.kept_persons(ENG, ok, NOW, grace=10), [])
        self.assertEqual(S.kept_persons(ENG, None, NOW, grace=30), [])
        self.assertEqual(S.PERSON_GRACE, 2 * S.POLL)
        p, a, st = S.render_persons(S.kept_persons(ENG, ok, NOW, grace=10), UNITS, "medcea", False, NOW,
                                    placeholder="$7$101$AAAA$BBBB")
        self.assertEqual(users(p), ["explorer-none"])  # a revoked credential cannot keep reading

    def test_placeholder_without_persons(self):
        p, a, st = S.render_persons([], UNITS, "medcea", True, NOW, placeholder="$7$101$AAAA$BBBB")
        self.assertEqual(p, "explorer-none:$7$101$AAAA$BBBB\n")
        self.assertTrue(a.strip())                     # never an empty file
        h = S.placeholder_hash()
        self.assertRegex(h, r"^\$7\$101\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$")
        self.assertNotEqual(h, S.placeholder_hash())

    def test_credential_without_rows(self):
        p, a, st = S.render_persons(person("explorer-n-000001", []), UNITS, "medcea", True, NOW)
        self.assertEqual(users(p), ["explorer-n-000001"])
        self.assertEqual(acl_of(a, "explorer-n-000001"), [])


class Manifests(unittest.TestCase):
    def read(self, *p):
        with open(os.path.join(REPO, *p)) as fh:
            return fh.read()

    def test_broker_waits_for_passwd_ws_only_in_person_mode(self):
        m = self.read("k8s", "mosquitto", "mosquitto.yaml")
        self.assertIn('until [ -s /mosquitto/auth/passwd ] && { [ \\"$MQTT_PERSON\\" != true ] || [ -s /mosquitto/auth/passwd-ws ]; }', m)
        for v in ("${IAM_MQTT_PERSON}", "${PROJECT_NAME}", "${POSTGRES_DB}", "${NAMESPACE}"):
            self.assertIn(v, m)
        infra = self.read("deploy-infra.sh")
        self.assertIn('render "$SCRIPT_DIR/k8s/mosquitto/mosquitto.yaml" NAMESPACE POSTGRES_DB PROJECT_NAME IAM_MQTT_PERSON', infra)
        self.assertNotIn("kind: ConfigMap", m)

    def test_person_conf_per_listener(self):
        c = self.read("k8s", "mosquitto", "mosquitto-conf-person.yaml")
        conf = c.split("mosquitto.conf: |", 1)[1]
        self.assertIn("per_listener_settings true", conf)
        l1883, l9001 = conf.split("listener 9001")
        self.assertIn("password_file /mosquitto/auth/passwd\n", l1883)
        self.assertIn("password_file /mosquitto/auth/passwd-ws", l9001)
        self.assertIn("acl_file /mosquitto/auth/acl-ws", l9001)
        self.assertEqual(conf.count("allow_anonymous false"), 2)

    def test_shared_account_only_while_false(self):
        infra = self.read("deploy-infra.sh")
        block = infra[infra.index('if [[ "$IAM_MQTT_PERSON" == "false" ]]; then\n    _H_EX='):]
        self.assertLess(block.index("mqtt-explorer:${_H_EX}"), block.index("fi\n"))

    def test_status_has_no_hash(self):
        p, a, st = S.render_persons(ENG, UNITS, "medcea", True, NOW)
        self.assertNotIn("$7$", repr(st))


if __name__ == "__main__":
    unittest.main()
