#!/usr/bin/env python3
"""The boards' TLS to the broker (5 Nov 2026), offline, under CPython with fake MicroPython
modules: cea_edge_functions builds a context that accepts only the platform CA's
certificate named mqtt.<domain>, refuses to try with an unset clock, and umqtt.simple
wraps its socket with that context; the broker's NodePort for boards is TLS only (see
tests/test_mqtt_auth_sync.py); onboarding writes the name and copies the CA.

The real handshake (right CA and name connect; a wrong name, a wrong CA, an expired
certificate and a clock at 2000 are refused) was run on an ESP32-S3 with MicroPython
1.29 against a throwaway CA when this was built; it needs a board, so it is not here."""
import ast
import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "edge", "src", "app")


def read(*p):
    with open(os.path.join(ROOT, *p)) as f:
        return f.read()


def functions(path, names):
    """The source of the named top-level functions and assignments of a module."""
    src = read(path)
    tree = ast.parse(src)
    out = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            out.append(ast.get_source_segment(src, node))
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) in names for t in node.targets):
            out.append(ast.get_source_segment(src, node))
    return "\n\n".join(out)


class FakeCtx:
    def __init__(self, proto):
        self.proto, self.verify_mode, self.cadata, self.wrapped = proto, None, None, None

    def load_verify_locations(self, cadata=None):
        self.cadata = cadata

    def wrap_socket(self, sock, **kw):
        self.wrapped = (sock, kw)
        return sock


def fake_ssl():
    m = types.ModuleType("ssl")
    m.PROTOCOL_TLS_CLIENT, m.CERT_REQUIRED = 16, 2
    m.SSLContext = FakeCtx
    return m


class ConnectMqttTest(unittest.TestCase):
    def namespace(self, tls_name, years, refuse=None):
        calls = {"client": None, "ntp": 0}
        years = list(years)

        class MQTTException(Exception):
            pass

        class Client:
            def __init__(self, *a, **kw):
                calls["client"] = (a, kw)

            def connect(self):
                if refuse is not None:
                    raise MQTTException(refuse)
                calls["connected"] = True

        def localtime():
            return (years[0] if len(years) == 1 else years.pop(0), 1, 1, 0, 0, 0, 0, 0)

        def set_device_time():
            calls["ntp"] += 1
            return False

        cfg = types.SimpleNamespace(client_id="unit01-s-zone01-x", mqtt_server="192.168.1.207",
                                    mqtt_port=31884, mqtt_user="unit01-s-zone01", mqtt_pass="p",
                                    message_interval=30, mqtt_tls_name=tls_name)
        tmp = os.path.join(os.environ.get("TMPDIR", "/tmp"), "board-tls-%d" % os.getpid())
        os.makedirs(tmp, exist_ok=True)
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        with open(os.path.join(tmp, "mqtt_ca.der"), "wb") as f:
            f.write(b"\x30\x82CA")
        ns = {"cfg": cfg, "MQTTClient": Client, "MQTTException": MQTTException, "utime": types.SimpleNamespace(localtime=localtime),
              "set_device_time": set_device_time, "client_id": None, "mqtt_server": None}
        sys.modules["ssl"] = fake_ssl()
        self.addCleanup(sys.modules.pop, "ssl", None)
        code = functions(os.path.join("edge", "src", "app", "cea_edge_functions.py"),
                         {"connect_mqtt", "_tls_context", "MQTT_CA_FILE"})
        exec(code, ns)
        ns["MQTT_CA_FILE"] = os.path.join(tmp, "mqtt_ca.der")
        return ns, calls

    def test_tls_with_the_ca_and_the_name(self):
        ns, calls = self.namespace("mqtt.medcea", [2026])
        ns["connect_mqtt"]()
        args, kw = calls["client"]
        self.assertEqual(args[1:3], ("192.168.1.207", 31884))
        ctx = kw["ssl"]
        self.assertEqual((ctx.proto, ctx.verify_mode, ctx.cadata), (16, 2, b"\x30\x82CA"))
        self.assertEqual(kw["ssl_params"], {"server_hostname": "mqtt.medcea"})
        self.assertEqual(calls["ntp"], 0)

    def test_an_unset_clock_is_tried_once_then_refused(self):
        ns, calls = self.namespace("mqtt.medcea", [2000])
        with self.assertRaises(OSError) as e:
            ns["connect_mqtt"]()
        self.assertIn("clock not set", str(e.exception))
        self.assertEqual(calls["ntp"], 1)
        self.assertIsNone(calls["client"])          # never tries the broker

    def test_ntp_answering_late_is_enough(self):
        ns, calls = self.namespace("mqtt.medcea", [2000, 2026])
        ns["connect_mqtt"]()
        self.assertEqual(calls["ntp"], 1)
        self.assertIn("ssl", calls["client"][1])

    def test_a_refused_login_is_an_oserror(self):
        """The callers restart the board only on OSError; a refused CONNACK (rc 5, not
        authorised: the credential not synced yet, an inactive device) used to escape as
        MQTTException and leave the board at the REPL."""
        ns, calls = self.namespace("mqtt.medcea", [2026], refuse=5)
        with self.assertRaises(OSError) as e:
            ns["connect_mqtt"]()
        self.assertIn("broker refused the connection: 5", str(e.exception))

    def test_a_board_without_a_tls_name_tries_plain(self):
        ns, calls = self.namespace(None, [2026])
        ns["connect_mqtt"]()
        self.assertNotIn("ssl", calls["client"][1])


class UmqttTest(unittest.TestCase):
    def client(self, ssl, params):
        mods = {}
        sock = types.SimpleNamespace(connect=lambda a: None)
        mods["usocket"] = types.SimpleNamespace(socket=lambda: sock,
                                                getaddrinfo=lambda h, p: [(0, 0, 0, "", (h, p))])
        mods["ustruct"] = __import__("struct")
        mods["ubinascii"] = __import__("binascii")
        old = {k: sys.modules.get(k) for k in mods}
        sys.modules.update(mods)
        self.addCleanup(lambda: [sys.modules.pop(k, None) if v is None else sys.modules.__setitem__(k, v)
                                 for k, v in old.items()])
        ns = {}
        exec(read("edge", "src", "app", "umqtt", "simple.py"), ns)
        c = ns["MQTTClient"]("id", "192.168.1.207", 31884, ssl=ssl, ssl_params=params)

        class Stop(Exception):
            pass

        def write(b, *a):
            raise Stop()
        sock.write = write
        try:
            c.connect()
        except Stop:
            pass
        return sock

    def test_an_ssl_context_wraps_the_socket(self):
        ctx = FakeCtx(16)
        sock = self.client(ctx, {"server_hostname": "mqtt.medcea"})
        self.assertIs(ctx.wrapped[0], sock)
        self.assertEqual(ctx.wrapped[1], {"server_hostname": "mqtt.medcea"})


class ControlKeepaliveTest(unittest.TestCase):
    def test_the_control_loop_pings(self):
        """A CONTROL board publishes only on a command; without a PINGREQ the broker drops it
        after 1.5 x keepalive and the board turns every relay off and reboots."""
        src = read("edge", "src", "app", "cea_control.py")
        loop = src[src.index("ping_every ="):src.index("except OSError as e:", src.index("ping_every ="))]
        self.assertIn("client.keepalive", loop)
        self.assertIn("client.ping()", loop)
        self.assertIn("client.check_msg()", loop)
        for name in ("cea_sense.py", "cea_control.py"):
            caller = read("edge", "src", "app", name)
            self.assertIn("client = ef.connect_mqtt()\n    except OSError:", caller)


class OnboardingTest(unittest.TestCase):
    def test_flash_device_writes_the_name_and_copies_the_ca(self):
        s = read("edge", "flash-device.sh")
        self.assertIn('MQTT_PORT="${MQTT_PORT:-31884}"', s)
        self.assertIn('MQTT_TLS_NAME="${MQTT_TLS_NAME:-${DOMAIN:+mqtt.$DOMAIN}}"', s)
        self.assertIn('MQTT_CA="$REPO_ROOT/.ca/ca.crt"', s)
        self.assertIn('-outform der -out "$STAGE/mqtt_ca.der"', s)
        self.assertIn('for f in "$STAGE"/*.py "$STAGE"/*.json "$STAGE"/*.der; do', s)
        self.assertIn('"mqtt_tls_name": e["MQTT_TLS_NAME"]', s)
        self.assertNotIn("31883", s)
        # a registered board without a name or a CA would never connect: refused up front
        self.assertIn('die "no broker certificate name', s)
        self.assertIn('die "the platform CA $MQTT_CA is missing', s)
        t = read("edge", "src", "host", "device_template.py")
        self.assertIn('"MQTT_TLS_NAME": spec.get("mqtt_tls_name", "")', t)
        self.assertIn('mqtt_tls_name = getattr(_d, "MQTT_TLS_NAME", "") or None',
                      read("edge", "src", "app", "config.py"))


if __name__ == "__main__":
    unittest.main()
