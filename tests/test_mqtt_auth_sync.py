#!/usr/bin/env python3
"""tests/test_mqtt_auth_sync.py — the broker's auth sidecar (k8s/mosquitto/mqtt-auth-sync.py)
and the broker's two confs, offline (IAM 3.5). Stdlib only; no database, no broker.

  - IAM_MQTT_PERSON=false: passwd/acl exactly as before 3.5 for services and boards (golden
    text below), and the conf ConfigMap is tests/golden/mosquitto-conf.yaml byte for byte
    (the pre-3.5 conf plus the boards' TLS listener 8883, 5 Nov 2026);
    the shared mqtt-explorer account is gone from deploy-infra's service Secret in both modes
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
import shutil
import subprocess
import tempfile
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
# The service Secret as deploy-infra writes it since the shared mqtt-explorer account was
# removed (1 Nov 2026). The sidecar copies it verbatim, so dropping that account from the
# input moves the golden text below with it; render() itself is unchanged.
SERVICES_P = "node-red:%s\nscheduler:%s" % (H, H)
SERVICES_A = ("user node-red\ntopic read medcea/#\n\nuser scheduler\ntopic read medcea/+/+/sense/#\n"
              "topic write medcea/+/+/control/#")
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

    def test_conf_is_the_golden_one(self):
        """The pre-3.5 conf plus, since 5 Nov 2026, the boards' TLS listener 8883 (and only that)."""
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
        l1883, rest = conf.split("listener 9001")
        l9001, l8883 = rest.split("listener 8883")
        self.assertIn("password_file /mosquitto/auth/passwd\n", l1883)
        self.assertIn("password_file /mosquitto/auth/passwd-ws", l9001)
        self.assertIn("acl_file /mosquitto/auth/acl-ws", l9001)
        # the boards' TLS listener: services and boards, never a person credential
        self.assertIn("password_file /mosquitto/auth/passwd\n", l8883)
        self.assertIn("acl_file /mosquitto/auth/acl\n", l8883)
        self.assertNotIn("-ws", l8883)
        self.assertEqual(conf.count("allow_anonymous false"), 3)

    def test_boards_reach_the_broker_over_tls_only(self):
        """5 Nov 2026: the LAN NodePort is 31884 on listener 8883 (TLS); 1883 is in-cluster
        only (no NodePort 31883); the certificate is Secret mosquitto-tls from the CA."""
        m = self.read("k8s", "mosquitto", "mosquitto.yaml")
        docs = m.split("\n---\n")
        svc = {d.split("name: ", 1)[1].split("\n", 1)[0]: d for d in docs if "kind: Service\n" in d}
        self.assertIn("type: ClusterIP", svc["mosquitto"])
        self.assertNotIn("nodePort", svc["mosquitto"])
        self.assertIn("type: NodePort", svc["mosquitto-tls"])
        self.assertIn("targetPort: 8883", svc["mosquitto-tls"])
        self.assertIn("nodePort: 31884", svc["mosquitto-tls"])
        self.assertNotIn("nodePort: 31883", m)
        self.assertIn("secretName: mosquitto-tls", m)
        self.assertIn("mountPath: /mosquitto/certs", m)
        for f in ("mosquitto-conf.yaml", "mosquitto-conf-person.yaml"):
            c = self.read("k8s", "mosquitto", f)
            tls = c.split("listener 8883", 1)[1]
            self.assertIn("certfile /mosquitto/certs/tls.crt", tls)
            self.assertIn("keyfile /mosquitto/certs/tls.key", tls)
        infra = self.read("deploy-infra.sh")
        self.assertIn('MQTT_TLS_NAME="mqtt.${DOMAIN}"', infra)
        self.assertIn("kubectl create secret tls mosquitto-tls", infra)
        # issued before the broker is deployed
        self.assertLess(infra.index("create secret tls mosquitto-tls"), infra.index('k8s/mosquitto/mosquitto.yaml"'))

    def test_no_shared_account(self):
        # removed after the IAM_MQTT_PERSON trial: no mode hashes it, writes it or keeps it
        infra = self.read("deploy-infra.sh")
        block = infra[infra.index("_MQ_PASSWD="):infra.index("kubectl create secret generic mosquitto-service-auth")]
        self.assertNotIn("mqtt-explorer", block)
        for f in (("deploy-infra.sh",), ("config.env.example",), ("apps", "mqtt-explorer", "deploy.sh"),
                  ("apps", "mqtt-explorer", "html", "index.html"), ("guide.sh",)):
            text = self.read(*f)
            for line in text.splitlines():
                if "MQTT_EXPLORER_PASS" in line:
                    self.assertTrue(line.lstrip().startswith(("#", "echo", "//")) or "ignored" in line, (f, line))
        page = self.read("apps", "mqtt-explorer", "html", "index.html")
        self.assertNotIn("__MQTT_USER__", page)
        self.assertNotIn("__MQTT_PASS__", page)

    def test_status_has_no_hash(self):
        p, a, st = S.render_persons(ENG, UNITS, "medcea", True, NOW)
        self.assertNotIn("$7$", repr(st))


def _health_fn(name):
    """One check function of health-check.sh, as text (run under bash with fakes)."""
    with open(os.path.join(REPO, "health-check.sh")) as fh:
        src = fh.read()
    return re.search(r"(?ms)^%s\(\) \{.*?^\}" % name, src).group(0)


class HealthChecks(unittest.TestCase):
    """check_iammqtt and check_pvc against a fake kubectl (offline)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_check(self, fn, call, kubectl, env=None):
        k = os.path.join(self.tmp, "kubectl")
        with open(k, "w") as fh:
            fh.write("#!/bin/sh\n" + kubectl + "\n")
        os.chmod(k, 0o755)
        script = (f'_record() {{ echo "$1|$2|$3"; }}\nTIMEOUT=5\nKUBECTL="{k}"\nNAMESPACE=medcea\n'
                  f"{_health_fn(fn)}\n{call}\n")
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                           env=dict(os.environ, **(env or {})))
        return r.stdout.strip()

    @staticmethod
    def deploy_mode(switch):
        """The page mode apps/mqtt-explorer/deploy.sh renders for IAM_MQTT_PERSON=switch."""
        with open(os.path.join(REPO, "apps", "mqtt-explorer", "deploy.sh")) as fh:
            src = fh.read()
        block = src[src.index('case "${IAM_MQTT_PERSON:-false}" in'):]
        return re.search(r"(?m)^\s*%s\)\s*\n\s*_MODE=(\w+)" % switch, block).group(1)

    def broker(self, mode, users, page):
        conf = "per_listener_settings true" if mode == "true" else "listener 1883"
        return f"""case "$*" in
  *"annotations.medcea/mqtt-mode"*) printf %s {mode} ;;
  *MQTT_PERSON_CREDENTIALS*) printf %s {mode} ;;
  *"configmap mosquitto-config"*) printf '%s\\n' '{conf}' ;;
  *"configmap mqtt-explorer-html"*) printf '%s\\n' '<html data-mqtt-mode="{page}">' ;;
  *"/mosquitto/auth/passwd-ws"*) printf 'explorer-eng-abc123\\n' ;;
  *"/mosquitto/auth/passwd"*) printf '{users}' ;;
  *status.json*) exit 1 ;;
  *"get deployment iam-api"*) exit 0 ;;
  *"deployment/iam-api"*) printf '%s' '{{"mode": true, "mqtt_digest": "x"}}' ;;
  *) exit 1 ;;
esac"""

    def test_deploy_and_check_agree_on_page_modes(self):
        self.assertEqual(self.deploy_mode("false"), "off")
        self.assertEqual(self.deploy_mode("true"), "person")

    def test_iammqtt_false_off_page(self):
        page = self.deploy_mode("false")
        r = self.run_check("check_iammqtt", "check_iammqtt MQTT medcea",
                           self.broker("false", "node-red\\nscheduler\\n", page), {"IAM_MQTT_PERSON": "false"})
        self.assertTrue(r.startswith("WARN|MQTT|IAM_MQTT_PERSON=false"), r)
        self.assertNotIn("Explorer page", r)

    def test_iammqtt_shared_account_fails_in_both_modes(self):
        for mode, extra in (("false", {}), ("true", {"IAM_DB_ROLES": "true"})):
            r = self.run_check("check_iammqtt", "check_iammqtt MQTT medcea",
                               self.broker(mode, "node-red\\nmqtt-explorer\\nscheduler\\n", self.deploy_mode(mode)),
                               dict({"IAM_MQTT_PERSON": mode}, **extra))
            self.assertTrue(r.startswith("FAIL|MQTT|"), (mode, r))
            self.assertIn("mqtt-explorer account is still in the broker's password file", r)

    def test_iammqtt_true_ok(self):
        r = self.run_check("check_iammqtt", "check_iammqtt MQTT medcea",
                           self.broker("true", "node-red\\nscheduler\\n", self.deploy_mode("true")),
                           {"IAM_MQTT_PERSON": "true", "IAM_DB_ROLES": "true"})
        self.assertTrue(r.startswith("OK|MQTT|"), r)

    def pvc(self, phase, mode=None):
        d = os.path.join(self.tmp, "medcea-grafana-pvc-g")
        os.makedirs(d, exist_ok=True)
        if mode is not None:
            os.chmod(d, mode)
        return f"""case "$*" in
  "get pvc grafana -n medcea -o jsonpath={{.status.phase}} {{.status.capacity.storage}}") printf '%s' '{phase} 2Gi' ;;
  "get pvc grafana -n medcea -o jsonpath={{.spec.volumeName}}") printf pvc-g ;;
  "get pv pvc-g -o jsonpath={{.spec.hostPath.path}}") printf '%s' '{d}' ;;
  *) exit 1 ;;
esac"""

    def test_pvc(self):
        r = self.run_check("check_pvc", "check_pvc Vol medcea/grafana", self.pvc("Bound", 0o700))
        self.assertTrue(r.startswith("OK|Vol|pvc/grafana (medcea): Bound, 2Gi, root mode 700"), r)
        r = self.run_check("check_pvc", "check_pvc Vol medcea/grafana", self.pvc("Bound", 0o777))
        self.assertTrue(r.startswith("WARN|Vol|") and "mode 777, not 700" in r, r)
        r = self.run_check("check_pvc", "check_pvc Vol medcea/grafana", self.pvc("Pending"))
        self.assertTrue(r.startswith("WARN|Vol|pvc/grafana (medcea) is Pending"), r)
        r = self.run_check("check_pvc", "check_pvc Vol medcea/grafana", "exit 1")
        self.assertTrue(r.startswith("WARN|Vol|no PVC grafana in medcea"), r)
        for bad in ("grafana", "/grafana", "medcea/"):
            r = self.run_check("check_pvc", f"check_pvc Vol {bad}", "exit 1")
            self.assertTrue(r.startswith("FAIL|Vol|Invalid pvc target"), (bad, r))


if __name__ == "__main__":
    unittest.main()
