#!/usr/bin/env python3
"""The SENSE wiring screen: its logic under node, and the wizard's /api/parts.

The block between /* wiring-logic:begin */ and /* wiring-logic:end */ in
edge/src/host/ui/wiring.js mirrors edge/src/host/wiring.py. Every fixture in
tests/fixtures/wiring/ is run through it with the spec `device_template.py
wiring-spec` prints for the fixture's variant, and must give exactly the
fixture's (level, code, where) set, which is also what Python gives
(tests/test_sense_wiring.py). The node tests skip when node is missing.

    python3 -m unittest tests.test_wiring_ui
"""

import glob
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST_DIR = os.path.join(REPO, "edge", "src", "host")
UI_JS = os.path.join(HOST_DIR, "ui", "wiring.js")
FIXTURES = os.path.join(REPO, "tests", "fixtures", "wiring")
DT = os.path.join(HOST_DIR, "device_template.py")
NODE = shutil.which("node")
PYTHON = sys.executable or shutil.which("python3")

# Reads {"op", ...} cases on stdin, answers one JSON list.
HARNESS = r"""
const L = module.exports;
let raw = ""; process.stdin.on("data", c => raw += c).on("end", () => {
  const out = JSON.parse(raw).map(c => {
    if (c.op === "validate") return L.validate(c.doc, c.spec, c.variant);
    if (c.op === "fromDrawflow") return L.fromDrawflow(c.export, c.nodeData);
    if (c.op === "roundtrip") {
      const g = L.toDrawflow(c.doc, c.spec), nd = {};
      Object.keys(g.drawflow.Home.data).forEach(k => { nd[k] = g.drawflow.Home.data[k].data; });
      return L.fromDrawflow(g, nd);
    }
    throw new Error("unknown op " + c.op);
  });
  process.stdout.write(JSON.stringify(out));
});
"""


def logic_block():
    with open(UI_JS, encoding="utf-8") as f:
        src = f.read()
    m = re.search(r"/\* wiring-logic:begin \*/(.*?)/\* wiring-logic:end \*/", src, re.S)
    if not m:
        raise AssertionError("wiring.js has no wiring-logic block")
    return m.group(1)


_SPECS = {}


def spec_for(variant):
    if variant not in _SPECS:
        r = subprocess.run([PYTHON, DT, "wiring-spec", "SENSE", variant],
                           capture_output=True, text=True, cwd=REPO, timeout=60)
        if r.returncode != 0:
            raise AssertionError("wiring-spec %s: %s" % (variant, r.stderr[-400:]))
        _SPECS[variant] = json.loads(r.stdout)
    return _SPECS[variant]


def fixtures():
    return sorted(glob.glob(os.path.join(FIXTURES, "*.json")))


def triples(findings):
    return {(f["level"], f["code"], f["where"]) for f in findings}


@unittest.skipUnless(NODE, "node is not installed")
class LogicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.js = os.path.join(cls.tmp, "logic.js")
        with open(cls.js, "w", encoding="utf-8") as f:
            f.write("var module = {exports: {}};\n" + logic_block() + "\n" + HARNESS)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_js(self, cases):
        r = subprocess.run([NODE, self.js], input=json.dumps(cases), capture_output=True,
                           text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        return json.loads(r.stdout)

    def test_the_block_needs_no_dom(self):
        hits = re.findall(r"\bdocument\.[a-zA-Z]+\(|\bwindow\.|new\s+Drawflow\b", logic_block())
        self.assertEqual(hits, [])

    def test_parity_with_every_fixture(self):
        files = fixtures()
        if not files:
            self.skipTest("no wiring fixtures yet")
        cases, names = [], []
        for path in files:
            with open(path, encoding="utf-8") as f:
                fx = json.load(f)
            # No variant: the document's own is checked, as wiring.validate does; its
            # spec when the variant is one, else any spec (the verdict is E_VARIANT).
            sv = fx["variant"]
            if sv is None:
                board = fx["doc"].get("board") if isinstance(fx["doc"], dict) else None
                sv = (board or {}).get("variant") if isinstance(board, dict) else None
                if sv not in {v["id"] for v in spec_for("esp32s3")["variants"]}:
                    sv = "esp32s3"
            cases.append({"op": "validate", "doc": fx["doc"], "spec": spec_for(sv),
                          "variant": fx["variant"]})
            names.append((os.path.basename(path), fx["expect"]))
        for (name, expect), got in zip(names, self.run_js(cases)):
            with self.subTest(fixture=name):
                self.assertEqual(triples(got), {tuple(e) for e in expect})
                for f in got:
                    self.assertTrue(f["message"], f)

    def test_the_reference_board_is_clean(self):
        spec = spec_for("esp32s3")
        ref = [t for t in spec["templates"] if t["slug"] == "sense-hub-sht45-scd30-lux"]
        self.assertEqual(len(ref), 1)
        got = self.run_js([{"op": "validate", "doc": ref[0]["wiring"], "spec": spec,
                            "variant": "esp32s3"}])[0]
        self.assertEqual([f for f in got if f["level"] == "error"], [])

    def reference(self):
        return json.loads(json.dumps(
            [t for t in spec_for("esp32s3")["templates"]
             if t["slug"] == "sense-hub-sht45-scd30-lux"][0]["wiring"]))

    def test_from_drawflow_builds_the_document_from_the_wires(self):
        def node(i, d, ins, outs, x, y, inc=None, outc=None):
            return {"id": i, "name": d["kind"], "data": d, "class": "", "typenode": False,
                    "html": "<img src='data:image/svg+xml;utf8,big'>",
                    "inputs": {"input_%d" % k: {"connections": (inc or {}).get(k, [])}
                               for k in range(1, ins + 1)},
                    "outputs": {"output_%d" % k: {"connections": (outc or {}).get(k, [])}
                                for k in range(1, outs + 1)},
                    "pos_x": x, "pos_y": y}
        bus = {"id": "i2c0", "kind": "i2c", "sda": 8, "scl": 9, "freq": 100000,
               "impl": "soft", "pullups": "external"}
        tags = [{"q": "temperature", "tag": "air_temperature"},
                {"q": "humidity", "tag": "air_humidity"}]
        data = {
            "1": node(1, {"kind": "board", "board": {"variant": "esp32s3",
                                                     "part": "esp32-s3-devkitc-1"},
                          "buses": [bus]}, 0, 1, 40.4, 30,
                      outc={1: [{"node": "2", "output": "input_1"},
                                {"node": "4", "output": "input_1"}]}),
            "2": node(2, {"kind": "hub", "hub": {"id": "mux0", "kind": "tca9548a",
                                                 "addr": 112}}, 1, 8, 400, 30.6,
                      inc={1: [{"node": "1", "input": "output_1"}]},
                      outc={3: [{"node": "3", "output": "input_1"}]}),
            "3": node(3, {"kind": "sensor", "sensor": {"id": "sht45_1", "driver": "sht4x",
                                                       "addr": 68, "params": {},
                                                       "tags": tags}}, 1, 0, 760, 30,
                      inc={1: [{"node": "2", "input": "output_3"}]}),
            "4": node(4, {"kind": "sensor", "sensor": {"id": "lux_1", "driver": "sen0562",
                                                       "addr": 35, "params": {},
                                                       "tags": [{"q": "lux",
                                                                 "tag": "light_intensity"}]}},
                      1, 0, 760, 260, inc={1: [{"node": "1", "input": "output_1"}]}),
            "5": node(5, {"kind": "sensor", "sensor": {"id": "scd30_1", "driver": "scd30",
                                                       "addr": 97, "params": {},
                                                       "tags": []}}, 1, 0, 760, 480),
        }
        got = self.run_js([{"op": "fromDrawflow", "export": {"drawflow": {"Home": {"data": data}}},
                            "nodeData": None}])[0]
        self.assertEqual(got, {
            "version": 1, "board": {"variant": "esp32s3", "part": "esp32-s3-devkitc-1"},
            "buses": [bus],
            "hubs": [{"id": "mux0", "kind": "tca9548a", "addr": 112, "bus": "i2c0"}],
            "sensors": [
                {"id": "sht45_1", "driver": "sht4x", "bus": "i2c0", "hub": "mux0",
                 "channel": 2, "addr": 68, "params": {}, "tags": tags},
                {"id": "lux_1", "driver": "sen0562", "bus": "i2c0", "hub": None,
                 "channel": None, "addr": 35, "params": {},
                 "tags": [{"q": "lux", "tag": "light_intensity"}]},
                {"id": "scd30_1", "driver": "scd30", "bus": None, "hub": None,
                 "channel": None, "addr": 97, "params": {}, "tags": []}],
            "layout": {"board": [40, 30], "mux0": [400, 31], "sht45_1": [760, 30],
                       "lux_1": [760, 260], "scd30_1": [760, 480]}})
        self.assertNotIn("html", json.dumps(got))

    def test_round_trip_keeps_the_reference_board(self):
        ref = self.reference()
        got = self.run_js([{"op": "roundtrip", "doc": ref, "spec": spec_for("esp32s3")}])[0]
        norm = lambda s: {k: v for k, v in s.items() if v is not None or k not in ("hub", "channel")}
        self.assertEqual(got["board"], ref["board"])
        self.assertEqual(got["buses"], ref["buses"])
        self.assertEqual([sorted(h.items()) for h in got["hubs"]],
                         [sorted(h.items()) for h in ref["hubs"]])
        self.assertEqual([norm(s) for s in got["sensors"]],
                         [norm(dict(s, params=s.get("params", {}))) for s in ref["sensors"]])
        for k, v in (ref.get("layout") or {}).items():
            self.assertEqual(got["layout"][k], v)

    def test_the_answer_for_the_reference_board_is_small(self):
        ref = self.reference()
        doc = self.run_js([{"op": "roundtrip", "doc": ref, "spec": spec_for("esp32s3")}])[0]
        answer = json.dumps({"wiring": doc, "variant": "esp32s3",
                             "save_as": {"slug": "sense-x", "title": "T" * 120,
                                         "description": "D" * 400, "replace": False}})
        self.assertLess(len(answer.encode()), 16 * 1024)


# ----------------------------------------------------------- /api/parts --
def load_wizard():
    spec = importlib.util.spec_from_file_location("wizard_server_wiring_t",
                                                  os.path.join(HOST_DIR, "wizard_server.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class PartsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = load_wizard()

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.ws._PARTS.clear()
        self.addCleanup(self.ws._PARTS.clear)
        self.real_dir = self.ws.PARTS_DIR
        self.addCleanup(setattr, self.ws, "PARTS_DIR", self.real_dir)
        self.ws.STATE.update({"auth": "keycloak", "token": "tok", "sessions": {},
                              "pending": {}, "dir": self.tmp})

    def get(self, path, headers=None):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), self.ws.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            req = urllib.request.Request("http://127.0.0.1:%d%s" % (srv.server_address[1], path),
                                         headers=headers or {})
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    return r.status, dict(r.headers), r.read()
            except urllib.error.HTTPError as e:
                with e:
                    return e.code, dict(e.headers), e.read()
        finally:
            srv.shutdown()
            srv.server_close()

    def cookie(self):
        sid = self.ws.new_session({"sub": "u-alice", "preferred_username": "alice"}, "", None)
        return {"Cookie": "%s=%s" % (self.ws.COOKIE, sid)}

    def write_part(self, pid, svg):
        with open(os.path.join(self.tmp, pid + ".json"), "w") as f:
            json.dump({"id": pid, "title": pid, "svg": pid + ".svg", "size": [10, 10],
                       "connectors": {"SDA": {"fx": 0.5, "fy": 0.5}},
                       "functions": {"SDA": ["SDA"]}}, f)
        with open(os.path.join(self.tmp, pid + ".svg"), "w") as f:
            f.write(svg)

    def test_parts_need_a_session(self):
        self.assertEqual(self.get("/api/parts")[0], 401)
        self.ws.STATE["auth"] = "token"
        self.assertEqual(self.get("/api/parts")[0], 403)
        self.assertEqual(self.get("/api/parts?t=tok")[0], 200)

    def test_etag_and_304(self):
        self.ws.PARTS_DIR = self.tmp
        self.write_part("good", '<svg xmlns="http://www.w3.org/2000/svg"><use href="#a"/></svg>')
        status, hdr, body = self.get("/api/parts", self.cookie())
        self.assertEqual(status, 200)
        self.assertEqual(hdr["Cache-Control"], "private, max-age=3600")
        etag = hdr["ETag"]
        self.assertTrue(etag.startswith('"'))
        self.assertIn("good", json.loads(body)["parts"])
        status, hdr, body = self.get("/api/parts", dict(self.cookie(), **{"If-None-Match": etag}))
        self.assertEqual((status, body), (304, b""))
        self.assertEqual(hdr["ETag"], etag)
        status, _h, _b = self.get("/api/parts", dict(self.cookie(), **{"If-None-Match": '"other"'}))
        self.assertEqual(status, 200)

    def test_a_picture_that_reaches_out_is_not_served(self):
        self.ws.PARTS_DIR = self.tmp
        self.write_part("good", "<svg><rect/></svg>")
        self.write_part("script", "<svg><script>alert(1)</script></svg>")
        self.write_part("handler", '<svg onload="x()"></svg>')
        self.write_part("remote", '<svg><image href="https://example.org/x.png"/></svg>')
        with open(os.path.join(self.tmp, "escape.json"), "w") as f:
            json.dump({"id": "escape", "svg": "../escape.svg"}, f)
        _s, _h, body = self.get("/api/parts", self.cookie())
        self.assertEqual(sorted(json.loads(body)["parts"]), ["good"])

    def test_the_shipped_parts_are_all_served_and_safe(self):
        names = sorted(n[:-5] for n in os.listdir(self.real_dir) if n.endswith(".json")) \
            if os.path.isdir(self.real_dir) else []
        if not names:
            self.skipTest("no parts yet")
        _s, _h, body = self.get("/api/parts", self.cookie())
        parts = json.loads(body)["parts"]
        self.assertEqual(sorted(parts), names)
        text = body.decode()
        self.assertNotRegex(text, r"(?i)<\s*script|\son[a-z]+\s*=")
        for p in parts.values():
            for href in re.findall(r"""href\s*=\s*["']([^"']*)""", p["svg"]):
                self.assertTrue(href.startswith("#") or href.startswith("data:image/"), href)

    def test_the_page_inlines_the_wiring_assets(self):
        self.ws.STATE["onboard_url"] = "#"
        _s, _h, body = self.get("/", self.cookie())
        page = body.decode()
        for ph in ("__DRAWFLOW_CSS__", "__DRAWFLOW_JS__", "__WIRING_CSS__", "__WIRING_JS__"):
            self.assertNotIn(ph, page)
        self.assertIn("window.Wiring", page.replace("root.Wiring", "window.Wiring"))
        self.assertIn("Drawflow", page)
        for name in ("vendor/drawflow.min.js", "vendor/drawflow.min.css", "wiring.js", "wiring.css"):
            asset = self.ws.ui_asset(name)
            self.assertNotIn("not found in", asset[:80], name)
            self.assertNotIn("</script", asset.lower(), name)
            self.assertNotIn("</style", asset.lower(), name)


if __name__ == "__main__":
    unittest.main()
