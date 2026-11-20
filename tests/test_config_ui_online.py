"""The Configuration page's device online check and its fallback to the last reported
address (20 Nov 2026), offline.

- The online-logic block (between /* online-logic:begin */ and /* online-logic:end */ in
  apps/frontend/html/index.html) runs under node (skipped without node):
  isIPv4, lastAddressQuery, lastAddressFrom, onlineView (green only for the name itself;
  amber for an answer at the last reported address; red otherwise).
- Static: checkDeviceOnline asks for the last address only after an 'unresolved' answer,
  through api() (a refused read gives no fallback); the query matches the partial index
  in medcea_db_008b_index.sql (device_dns, newest timestamp, msg_type HB/TS).
- platform-api's check_host (from the recipe-fileserver ConfigMap), with the resolver
  replaced: a definite no-such-name answer is 'unresolved', a resolver failure is
  'timeout', and a stuck lookup returns within the check's timeout.

Run: python3 tests/test_config_ui_online.py
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX = os.path.join(ROOT, "apps", "frontend", "html", "index.html")
SERVER = os.path.join(ROOT, "apps", "frontend", "k8s", "recipe-fileserver.yaml")
INDEX_SQL = os.path.join(ROOT, "apps", "database", "medcea_db_008b_index.sql")
NODE = shutil.which("node")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def block():
    m = re.search(r"/\* online-logic:begin \*/(.*?)/\* online-logic:end \*/", read(INDEX), re.S)
    assert m, "online-logic block missing"
    return m.group(1)


def run_node(expr):
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(block() + "\nconsole.log(JSON.stringify(" + expr + "));\n")
        path = f.name
    try:
        out = subprocess.run([NODE, path], capture_output=True, text=True, timeout=30)
    finally:
        os.unlink(path)
    if out.returncode:
        raise AssertionError(out.stderr)
    return json.loads(out.stdout)


@unittest.skipUnless(NODE, "node is not installed")
class Logic(unittest.TestCase):
    def test_ipv4(self):
        got = run_node("['192.168.1.225','10.0.0.1','256.1.1.1','1.2.3','01.2.3.4','a.b.c.d','',null,"
                       "'192.168.1.225; rm -rf /','::1'].map(isIPv4)")
        self.assertEqual(got, [True, True, False, False, False, False, False, False, False, False])

    def test_query(self):
        q = run_node("lastAddressQuery('unit01-c-zone01')")
        self.assertEqual(q, "/measurement?select=timestamp,ip:msg->>ip&device_dns=eq.unit01-c-zone01"
                            "&msg_type=in.(HB,TS)&msg->>ip=not.is.null&msg->>sent_from=is.null"
                            "&order=timestamp.desc&limit=1")
        # a value is percent-encoded, never quoted (PostgREST keeps quotes)
        self.assertIn("device_dns=eq.a%26b", run_node("lastAddressQuery('a&b')"))

    def test_last_address(self):
        got = run_node("[lastAddressFrom([{timestamp:'t1', ip:'192.168.1.225'}]), lastAddressFrom([]),"
                       " lastAddressFrom(null), lastAddressFrom([{timestamp:'t', ip:'evil.example'}])]")
        self.assertEqual(got, [{"ip": "192.168.1.225", "at": "t1"}, None, None, None])

    def test_view(self):
        fb = "{ip:'192.168.1.225', at:'2026-11-20T15:50:54Z'}"
        got = run_node("["
                       "onlineView({online:true, ms:12}, null, null),"
                       "onlineView({online:false, error:'timeout'}, null, null),"
                       "onlineView({online:false, error:'unreachable'}, null, null),"
                       "onlineView({online:false, error:'unresolved'}, null, null),"
                       "onlineView({online:false, error:'unresolved'}, " + fb + ", {online:true}),"
                       "onlineView({online:false, error:'unresolved'}, " + fb + ", {online:false, error:'timeout'})"
                       "].map(v => v.colour)")
        self.assertEqual(got, ["green", "red", "red", "red", "amber", "red"])
        amber = run_node("onlineView({online:false, error:'unresolved'}, " + fb + ", {online:true}).title")
        self.assertIn("192.168.1.225", amber)
        self.assertIn("router", amber)
        # a timeout on the name itself never tries a fallback, whatever it is given
        self.assertEqual(run_node("onlineView({online:false, error:'timeout'}, " + fb + ", {online:true}).colour"), "red")


class Static(unittest.TestCase):
    def test_a_failed_check_is_grey_not_amber(self):
        text = read(INDEX)
        fn = text[text.index("async function checkDeviceOnline("):text.index("async function checkAllDevicesOnline(")]
        catch = fn[fn.index("} catch(e) {"):]
        self.assertIn("#94a3b8", catch)
        self.assertNotIn("#f59e0b", catch)

    def test_fallback_only_after_unresolved(self):
        text = read(INDEX)
        fn = text[text.index("async function checkDeviceOnline("):text.index("async function checkAllDevicesOnline(")]
        self.assertIn("result.error === 'unresolved'", fn)
        self.assertIn("api('GET', lastAddressQuery(dnsName))", fn)
        self.assertLess(fn.index("result.error === 'unresolved'"), fn.index("lastAddressQuery"))

    def test_partial_index_matches_the_query(self):
        sql = read(INDEX_SQL)
        self.assertRegex(sql, r"CREATE INDEX CONCURRENTLY IF NOT EXISTS measurement_status_idx ON medcea\.measurement "
                              r"\(device_dns, \"timestamp\"\)\s+WHERE msg_type IN \('HB', 'TS'\);")
        # rebuilt when an interrupted build left it invalid, as the first index
        self.assertIn("DROP INDEX medcea.measurement_status_idx;", sql)


class Server(unittest.TestCase):
    """check_host with the resolver replaced, so no test depends on the host's DNS."""

    @staticmethod
    def load(getaddrinfo):
        import socket as real
        import time
        import types
        doc = yaml.safe_load(read(SERVER))
        src = doc["data"]["server.py"]
        src = src[:src.index("class H(")]   # check_host and helpers, no server start
        fake = types.SimpleNamespace(**{k: getattr(real, k) for k in dir(real) if not k.startswith("__")})
        fake.getaddrinfo = getaddrinfo
        ns = {}
        exec(compile(src, "server.py", "exec"), ns)
        ns["socket"] = fake
        ns["_NO_NAME"] = {getattr(real, n) for n in ("EAI_NONAME", "EAI_NODATA") if hasattr(real, n)}
        ns["time"] = time
        return ns

    def test_no_such_name_is_unresolved(self):
        import socket

        def gai(*a, **k):
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        ns = self.load(gai)
        self.assertEqual(ns["check_host"]("unit01-c-zone01", 80, timeout=1), (False, None, "unresolved"))

    def test_resolver_failure_is_a_timeout_not_unresolved(self):
        import socket

        def gai(*a, **k):
            raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")
        ns = self.load(gai)
        self.assertEqual(ns["check_host"]("unit01-c-zone01", 80, timeout=1), (False, None, "timeout"))

    def test_a_stuck_resolver_is_bounded(self):
        import threading
        import time
        release = threading.Event()

        def gai(*a, **k):
            release.wait(30)
            return []
        ns = self.load(gai)
        t0 = time.monotonic()
        try:
            got = ns["check_host"]("unit01-c-zone01", 80, timeout=1)
        finally:
            release.set()
        self.assertEqual(got, (False, None, "timeout"))
        self.assertLess(time.monotonic() - t0, 3.0)


if __name__ == "__main__":
    unittest.main()
