#!/usr/bin/env python3
"""The host's test-message sender (edge/src/host/mqtt_test.py), offline, against a fake
TLS MQTT broker in this process: a throwaway CA and a broker certificate made with
openssl the way deploy-infra.sh makes the platform's (no keyUsage on the CA, no
authorityKeyIdentifier on the broker's), so the relaxed strict-mode flag is exercised.

It checks the bytes the broker receives (CONNECT with the board's credential, PUBLISH
QoS 1 on the board's own _test topic, DISCONNECT), the payload's fields, the exit codes
and their one JSON line, and that no secret of the record shows up in stdout, stderr or
an exception text, nor is ever taken on argv. Skipped without openssl."""
import datetime
import importlib.util
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "edge", "src", "host", "mqtt_test.py")
TLS_NAME = "mqtt.medcea-test"

_spec = importlib.util.spec_from_file_location("mqtt_test", SCRIPT)
mt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mt)


def _openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def make_pki(d):
    """ca.crt, a second unrelated other-ca.crt, and broker.{crt,key} for TLS_NAME."""
    for ca in ("ca", "other-ca"):
        _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", ca + ".key", cwd=d)
        _openssl("req", "-x509", "-new", "-key", ca + ".key", "-sha256", "-days", "2",
                 "-subj", "/CN=Test CA %s/O=CEA" % ca, "-out", ca + ".crt", cwd=d)
    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "broker.key", cwd=d)
    _openssl("req", "-new", "-key", "broker.key", "-subj", "/CN=" + TLS_NAME, "-out", "broker.csr", cwd=d)
    with open(os.path.join(d, "ext.cnf"), "w") as f:
        f.write("subjectAltName=DNS:%s,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n"
                "keyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n" % TLS_NAME)
    _openssl("x509", "-req", "-in", "broker.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
             "-CAcreateserial", "-days", "2", "-sha256", "-out", "broker.crt",
             "-extfile", "ext.cnf", cwd=d)


# ---- a fake broker: one thread, one connection at a time ------------------------
def _read_exact(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise EOFError
        buf += c
    return buf


def _read_packet(s):
    first = _read_exact(s, 1)[0]
    length, mult = 0, 1
    while True:
        b = _read_exact(s, 1)[0]
        length += (b & 0x7F) * mult
        mult *= 128
        if not b & 0x80:
            break
    return first, _read_exact(s, length)


def _str_at(body, i):
    n = struct.unpack("!H", body[i:i + 2])[0]
    return body[i + 2:i + 2 + n].decode(), i + 2 + n


def parse_connect(body):
    proto, i = _str_at(body, 0)
    level, flags = body[i], body[i + 1]
    keepalive = struct.unpack("!H", body[i + 2:i + 4])[0]
    i += 4
    cid, i = _str_at(body, i)
    user, i = _str_at(body, i)
    pw, i = _str_at(body, i)
    return {"proto": proto, "level": level, "flags": flags, "keepalive": keepalive,
            "client_id": cid, "username": user, "password": pw, "rest": body[i:]}


class FakeBroker:
    def __init__(self, pki, connack_rc=0, puback=True):
        self.connack_rc, self.puback = connack_rc, puback
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(os.path.join(pki, "broker.crt"), os.path.join(pki, "broker.key"))
        self.lsock = socket.socket()
        self.lsock.bind(("127.0.0.1", 0))
        self.lsock.listen(4)
        self.port = self.lsock.getsockname()[1]
        self.packets = []           # (first byte, body) as received
        self.handshake_errors = 0
        self.done = threading.Event()
        self.t = threading.Thread(target=self._serve, daemon=True)
        self.t.start()

    def _serve(self):
        try:
            raw, _ = self.lsock.accept()
        except OSError:
            return
        raw.settimeout(10)
        try:
            s = self.ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            self.handshake_errors += 1
            raw.close()
            self.done.set()
            return
        try:
            first, body = _read_packet(s)
            self.packets.append((first, body))
            s.sendall(bytes([0x20, 2, 0, self.connack_rc]))
            if self.connack_rc:
                return
            first, body = _read_packet(s)
            self.packets.append((first, body))
            if self.puback and first >> 4 == 3:
                topic, i = _str_at(body, 0)
                s.sendall(b"\x40\x02" + body[i:i + 2])
            elif not self.puback:
                self.done.wait(15)   # hold the line open and say nothing
                return
            first, body = _read_packet(s)
            self.packets.append((first, body))
        except (EOFError, OSError):
            pass
        finally:
            s.close()
            self.done.set()

    def close(self):
        self.done.set()
        self.lsock.close()
        self.t.join(5)


@unittest.skipUnless(shutil.which("openssl"), "openssl is not installed")
class MqttTestSender(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="mqtt-test-")
        make_pki(cls.tmp)
        cls.ca = os.path.join(cls.tmp, "ca.crt")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.secret_pw = "pw-" + secrets.token_hex(12)
        self.secret_psk = "psk-" + secrets.token_hex(12)
        self.secret_repl = "repl-" + secrets.token_hex(6)
        self.broker = None

    def tearDown(self):
        if self.broker:
            self.broker.close()

    def record(self, role="SENSE", **over):
        rec = {
            "state": "REGISTERED", "role": role, "unit_code": "UNIT02", "zone_code": "ZONE01",
            "zone_id": 3, "platform_device_id": 9,
            "mqtt": {"host": "192.0.2.1", "port": 31884, "tls_name": TLS_NAME, "topic_root": "medcea",
                     "username": "unit02-s-zone01", "password": self.secret_pw},
            "hostname": "unit02-s-zone01", "mac": "34:B7:DA:0A:1B:2C",
            "micropython": "3.4.0; MicroPython v1.29.0 on 2026-08-24",
            "wifi_ssid": "lab", "wifi_psk": self.secret_psk, "webrepl_password": self.secret_repl,
            "ip_at_provision": "192.168.1.57",
        }
        rec.update(over)
        return rec

    def write(self, rec):
        path = os.path.join(self.tmp, "rec-%s.json" % secrets.token_hex(3))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(rec, f)
        return path

    def run_cli(self, rec_path, port, tls_name=TLS_NAME, ca=None, extra=(), timeout="5"):
        argv = [sys.executable, SCRIPT, "--record", rec_path, "--host", "127.0.0.1",
                "--port", str(port), "--tls-name", tls_name, "--ca", ca or self.ca,
                "--source", "cli", "--timeout", timeout, *extra]
        for s in (self.secret_pw, self.secret_psk, self.secret_repl):
            self.assertNotIn(s, " ".join(argv))
        p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        self.assert_no_secret(p.stdout + p.stderr)
        self.assertEqual(p.stderr, "")
        lines = p.stdout.splitlines()
        self.assertEqual(len(lines), 1, p.stdout)
        return p.returncode, json.loads(lines[0])

    def assert_no_secret(self, text):
        for s in (self.secret_pw, self.secret_psk, self.secret_repl):
            self.assertNotIn(s, text)

    # ---- success ----------------------------------------------------------------
    def test_sense_success_bytes_and_payload(self):
        self.broker = FakeBroker(self.tmp)
        before = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        rc, out = self.run_cli(self.write(self.record()), self.broker.port,
                               extra=("--note", "bench check"))
        after = datetime.datetime.now(datetime.timezone.utc)
        self.assertEqual(rc, 0, out)
        self.assertEqual(set(out), {"ok", "topic", "client_id", "timestamp", "msg_type"})
        self.assertIs(out["ok"], True)
        self.assertEqual(out["msg_type"], "TS")
        self.assertEqual(out["topic"], "medcea/UNIT02/ZONE01/sense/_test")
        self.assertRegex(out["client_id"], r"^unit02-s-zone01-test-[0-9a-f]{4}$")
        self.broker.done.wait(5)

        (c_first, c_body), (p_first, p_body), (d_first, d_body) = self.broker.packets
        conn = parse_connect(c_body)
        self.assertEqual(c_first, 0x10)
        self.assertEqual((conn["proto"], conn["level"], conn["flags"], conn["keepalive"]),
                         ("MQTT", 4, 0xC2, 30))
        self.assertEqual(conn["client_id"], out["client_id"])
        self.assertEqual((conn["username"], conn["password"]), ("unit02-s-zone01", self.secret_pw))
        self.assertEqual(conn["rest"], b"")

        self.assertEqual(p_first, 0x32)            # PUBLISH, QoS 1, no retain, no dup
        topic, i = _str_at(p_body, 0)
        self.assertEqual(topic, out["topic"])
        self.assertNotEqual(struct.unpack("!H", p_body[i:i + 2])[0], 0)
        msg = json.loads(p_body[i + 2:])
        self.assertEqual((d_first, d_body), (0xE0, b""))

        self.assertEqual(list(msg), ["unit_code", "zone_code", "msg_type", "timestamp", "device_id",
                                     "device_dns", "tag", "ip", "mac", "source", "firmware",
                                     "sent_from", "note"])
        self.assertEqual(msg["unit_code"], "UNIT02")
        self.assertEqual(msg["zone_code"], "ZONE01")
        self.assertEqual(msg["msg_type"], "TS")
        self.assertEqual(msg["tag"], "_test")
        self.assertEqual(msg["device_id"], "34b7da0a1b2c")   # = config.py device_id / serial_number
        self.assertEqual(msg["mac"], "34:b7:da:0a:1b:2c")
        self.assertEqual(msg["device_dns"], "unit02-s-zone01")
        self.assertEqual(msg["ip"], "192.168.1.57")
        self.assertEqual(msg["source"], "cli")
        # os.uname().release's form, as the board sends it, not the record's sys.version.
        self.assertEqual(msg["firmware"], "1.29.0")
        self.assertEqual(msg["sent_from"], "host")
        self.assertEqual(msg["note"], "bench check")
        self.assertNotIn("value", msg)
        self.assertNotIn("UoM", msg)
        # ef.get_timestamp()'s format, in UTC, and the one reported.
        self.assertRegex(msg["timestamp"], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
        self.assertEqual(msg["timestamp"], out["timestamp"])
        ts = datetime.datetime.strptime(msg["timestamp"], "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=datetime.timezone.utc)
        self.assertTrue(before <= ts <= after, (before, ts, after))
        self.assert_no_secret(json.dumps(msg))

    def test_control_goes_to_control_setpoint_and_nulls(self):
        self.broker = FakeBroker(self.tmp)
        rec = self.record(role="CONTROL", hostname="unit02-c-zone01", ip_at_provision=None)
        del rec["micropython"]
        result = mt.send_test(rec, "127.0.0.1", self.broker.port, TLS_NAME, self.ca, "wizard", timeout=5)
        self.assertEqual(result["topic"], "medcea/UNIT02/ZONE01/control_setpoint/_test")
        self.broker.done.wait(5)
        _, p_body = self.broker.packets[1]
        topic, i = _str_at(p_body, 0)
        msg = json.loads(p_body[i + 2:])
        self.assertEqual(msg["source"], "wizard")
        self.assertIsNone(msg["ip"])
        self.assertIsNone(msg["firmware"])
        self.assertNotIn("note", msg)
        self.assertEqual(msg["device_dns"], "unit02-c-zone01")

    def test_firmware_is_the_boards_release_form(self):
        self.assertEqual(mt.firmware_of({"micropython": "3.4.0; MicroPython v1.29.0 on 2026-08-24"}),
                         "1.29.0")
        self.assertEqual(mt.firmware_of({"micropython": "unknown"}), "unknown")
        self.assertIsNone(mt.firmware_of({"micropython": ""}))
        self.assertIsNone(mt.firmware_of({}))

    def test_timestamp_format_matches_the_board(self):
        t = datetime.datetime(2026, 1, 2, 3, 4, 5, 999, tzinfo=datetime.timezone.utc)
        board = '{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}'.format(2026, 1, 2, 3, 4, 5)
        self.assertEqual(mt.timestamp(t), board)
        # Another zone is converted to UTC, as the board's NTP clock is.
        lis = datetime.timezone(datetime.timedelta(hours=1))
        self.assertEqual(mt.timestamp(t.astimezone(lis)), board)
        with open(os.path.join(ROOT, "edge", "src", "app", "cea_edge_functions.py")) as f:
            self.assertIn("'{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}'.format(t[0], t[1], t[2], t[3], "
                          "t[4], t[5])", f.read())

    # ---- refusals ------------------------------------------------------------------
    def test_connack_not_authorised_exit_1(self):
        self.broker = FakeBroker(self.tmp, connack_rc=5)
        rc, out = self.run_cli(self.write(self.record()), self.broker.port)
        self.assertEqual(rc, 1)
        self.assertIs(out["ok"], False)
        self.assertIn("not authorised", out["error"])
        self.assertEqual(len(self.broker.packets), 1)     # nothing published

    def test_no_puback_times_out_exit_1(self):
        self.broker = FakeBroker(self.tmp, puback=False)
        rc, out = self.run_cli(self.write(self.record()), self.broker.port, timeout="1")
        self.assertEqual(rc, 1)
        self.assertEqual(out, {"ok": False, "error": "timed out waiting for PUBACK"})

    def test_tls_name_mismatch_exit_1(self):
        self.broker = FakeBroker(self.tmp)
        rc, out = self.run_cli(self.write(self.record()), self.broker.port, tls_name="mqtt.elsewhere")
        self.assertEqual(rc, 1)
        self.assertIn("TLS", out["error"])
        self.assertEqual(self.broker.packets, [])       # no CONNECT, so no password sent

    def test_wrong_ca_exit_1(self):
        self.broker = FakeBroker(self.tmp)
        rc, out = self.run_cli(self.write(self.record()), self.broker.port,
                               ca=os.path.join(self.tmp, "other-ca.crt"))
        self.assertEqual(rc, 1)
        self.assertIn("certificate", out["error"])
        self.assertEqual(self.broker.packets, [])

    def test_connection_refused_exit_1(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        rc, out = self.run_cli(self.write(self.record()), port)
        self.assertEqual(rc, 1)
        self.assertIn("cannot connect", out["error"])

    def test_bad_records_exit_2(self):
        no_pw = self.record()
        no_pw["mqtt"] = dict(no_pw["mqtt"], password="")
        no_mqtt = self.record(mqtt=None)
        unreg = self.record(state="UNREGISTERED")
        bad_role = self.record(role="GATEWAY")
        no_role = self.record(role=None)
        bad_mac = self.record(mac="not-a-mac")
        wild = self.record(unit_code="UNIT+")
        for name, rec in (("no password", no_pw), ("no mqtt", no_mqtt), ("unregistered", unreg),
                          ("unknown role", bad_role), ("no role", no_role), ("bad mac", bad_mac),
                          ("wildcard unit", wild)):
            with self.subTest(name):
                rc, out = self.run_cli(self.write(rec), 1)    # never reaches the port
                self.assertEqual(rc, 2, out)
                self.assertIs(out["ok"], False)
                self.assertEqual(set(out), {"ok", "error"})

    def test_unreadable_and_not_json_exit_2(self):
        rc, out = self.run_cli(os.path.join(self.tmp, "missing.json"), 1)
        self.assertEqual(rc, 2)
        path = os.path.join(self.tmp, "broken.json")
        with open(path, "w") as f:
            f.write('{"mqtt": {"password": "%s"' % self.secret_pw)   # truncated, holds a secret
        rc, out = self.run_cli(path, 1)
        self.assertEqual(rc, 2)
        self.assertIn("not valid JSON", out["error"])

    def test_usage_errors_exit_2_one_json_line(self):
        rec = self.write(self.record())
        for extra in (("--note", "x" * 201), ("--note", "two\nlines"), ("--note", "it's"),
                      ("--note", 'a "b"'), ("--timeout", "0"), ("--source", "explorer")):
            with self.subTest(extra):
                rc, out = self.run_cli(rec, 1, extra=extra)
                self.assertEqual(rc, 2, out)
                self.assertIs(out["ok"], False)
        rc, out = self.run_cli(rec, 1, ca=os.path.join(self.tmp, "no-such-ca.crt"))
        self.assertEqual(rc, 2)
        self.assertIn("CA", out["error"])

    def test_password_is_never_an_option(self):
        rc, out = self.run_cli(self.write(self.record()), 1, extra=("--password", "x"))
        self.assertEqual(rc, 2)
        self.assertIn("unrecognized", out["error"])
        with open(SCRIPT) as f:
            src = f.read()
        options = re.findall(r'add_argument\("(--[a-z-]+)"', src)
        self.assertEqual(sorted(options), sorted(["--record", "--host", "--port", "--tls-name", "--ca",
                                                  "--source", "--note", "--timeout"]))
        self.assertNotRegex(src, r"environ|getenv")   # nor through the environment

    # ---- the redaction itself --------------------------------------------------------
    def test_errors_never_quote_a_secret(self):
        rec = self.record()
        known = mt._secrets_of(rec)
        self.assertEqual(sorted(known), sorted([self.secret_pw, self.secret_psk, self.secret_repl]))
        text = mt._redact("boom %s / %s / %s" % (self.secret_pw, self.secret_psk, self.secret_repl), known)
        self.assert_no_secret(text)
        # Exceptions raised by send_test for a bad record or a refusal carry no secret.
        for rec2 in (self.record(state="UNREGISTERED"), self.record(role="X"),
                     self.record(mac="zz")):
            with self.assertRaises(mt.UsageError) as cm:
                mt.send_test(rec2, "127.0.0.1", 1, TLS_NAME, self.ca, "cli")
            self.assert_no_secret(str(cm.exception))
        self.broker = FakeBroker(self.tmp, connack_rc=4)
        with self.assertRaises(mt.SendError) as cm:
            mt.send_test(rec, "127.0.0.1", self.broker.port, TLS_NAME, self.ca, "cli", timeout=5)
        self.assertIn("bad user name or password", str(cm.exception))
        self.assert_no_secret(str(cm.exception))

    def test_remaining_length_encoding(self):
        for n, b in ((0, b"\x00"), (127, b"\x7f"), (128, b"\x80\x01"), (16383, b"\xff\x7f"),
                     (16384, b"\x80\x80\x01")):
            self.assertEqual(mt._remaining_length(n), b)


if __name__ == "__main__":
    unittest.main()
