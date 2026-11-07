#!/usr/bin/env python3
"""The wiring screen's device pictures (edge/templates/parts/), offline.

Every part the SENSE template names (driver, hub and board `part` keys) has its
json and svg; the pictures stay within the size budget and are inert (no script,
no event attribute, no reference outside the file), since the page shows them as
<img> data URIs; every json carries its attribution and licence, and each
function names connectors that have a position. import-fritzing.py is run on a
small synthetic .fzpz whose connectors sit under translate, matrix, rotate and
scale transforms."""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARTS = os.path.join(ROOT, "edge", "templates", "parts")
SENSE = os.path.join(ROOT, "edge", "templates", "esp32-sense.json")
IMPORTER = os.path.join(ROOT, "edge", "tools", "import-fritzing.py")
# The contract's list, used while the template does not name its parts yet.
CONTRACT_PARTS = {"esp32-s3-devkitc-1", "adafruit-tca9548a", "adafruit-sht4x",
                  "adafruit-scd30", "dfrobot-sen0562"}
MAX_SVG = 60 * 1024
MAX_TOTAL = 350 * 1024


def referenced_parts():
    with open(SENSE) as f:
        tpl = json.load(f)
    names = set()
    for key in ("drivers", "hubs", "boards"):
        items = tpl.get(key) or []
        if isinstance(items, dict):
            items = items.values()
        names.update(i["part"] for i in items if isinstance(i, dict) and i.get("part"))
    return names or CONTRACT_PARTS


def load(pid):
    with open(os.path.join(PARTS, pid + ".json")) as f:
        meta = json.load(f)
    with open(os.path.join(PARTS, meta["svg"]), encoding="utf-8") as f:
        return meta, f.read()


class PartsTest(unittest.TestCase):
    def test_every_referenced_part_exists(self):
        parts = referenced_parts()
        self.assertTrue(CONTRACT_PARTS <= parts | CONTRACT_PARTS)
        for pid in sorted(parts | CONTRACT_PARTS):
            with self.subTest(part=pid):
                meta, _ = load(pid)
                self.assertEqual(meta["id"], pid)
                self.assertEqual(meta["svg"], pid + ".svg")

    def test_size_budget(self):
        total = 0
        for name in sorted(os.listdir(PARTS)):
            if name.endswith(".svg"):
                size = os.path.getsize(os.path.join(PARTS, name))
                self.assertLessEqual(size, MAX_SVG, name)
                total += size
        self.assertLessEqual(total, MAX_TOTAL)

    def test_pictures_are_inert(self):
        for name in sorted(os.listdir(PARTS)):
            if not name.endswith(".svg"):
                continue
            with open(os.path.join(PARTS, name), encoding="utf-8") as f:
                svg = f.read()
            with self.subTest(svg=name):
                self.assertNotIn("<script", svg.lower())
                self.assertNotIn("<foreignobject", svg.lower())
                self.assertIsNone(re.search(r"\son[a-z]+\s*=", svg, re.I))
                for href in re.findall(r"href\s*=\s*[\"']([^\"']*)", svg):
                    self.assertTrue(href.startswith("#"), href)
                self.assertIsNone(re.search(r"url\(\s*['\"]?(?!#)", svg))
                self.assertNotIn("<!ENTITY", svg)

    def test_attribution_and_functions(self):
        with open(os.path.join(PARTS, "ATTRIBUTION.md")) as f:
            credits = f.read()
        for name in sorted(os.listdir(PARTS)):
            if not name.endswith(".json"):
                continue
            pid = name[:-5]
            meta, svg = load(pid)
            with self.subTest(part=pid):
                a = meta["attribution"]
                for key in ("source", "url", "commit", "file", "author", "licence", "changes"):
                    self.assertIn(key, a)
                self.assertTrue(a["licence"].startswith("CC BY-SA 3.0"))
                self.assertIn(meta["drawn"], ("fritzing", "medcea"))
                if meta["drawn"] == "fritzing":
                    self.assertRegex(a["commit"], r"^[0-9a-f]{40}$")
                self.assertIn("`%s.svg`" % pid, credits)
                w, h = meta["size"]
                self.assertIn('viewBox="0 0 ', svg)
                self.assertTrue(w > 0 and h > 0)
                self.assertTrue(meta["functions"])
                for fn, conns in meta["functions"].items():
                    self.assertTrue(conns, fn)
                    for c in conns:
                        pos = meta["connectors"].get(c)
                        self.assertIsNotNone(pos, "%s: %s" % (fn, c))
                        self.assertTrue(0 <= pos["fx"] <= 1 and 0 <= pos["fy"] <= 1, c)
                for need in ("SDA", "SCL", "GND"):
                    if pid != "esp32-s3-devkitc-1":
                        self.assertIn(need, meta["functions"])

    def test_board_and_hub_functions(self):
        board, _ = load("esp32-s3-devkitc-1")
        fx = board["functions"]
        # DevKitC-1 v1.1: 44 header pins, 4 GND, 2 3V3, TX/RX are GPIO43/44
        self.assertEqual(len(board["connectors"]), 44)
        self.assertEqual(len(fx["GND"]), 4)
        self.assertEqual(len(fx["3V3"]), 2)
        for g in (0, 1, 2, 3, 4, 8, 9, 17, 18, 38, 43, 44, 46, 48):
            self.assertIn("GPIO%d" % g, fx)
        for g in (22, 26, 33, 34):   # not on the headers
            self.assertNotIn("GPIO%d" % g, fx)
        # GPIO8 and GPIO9 are on J1 (left), 3 pitches apart
        p8, p9 = board["connectors"]["GPIO8"], board["connectors"]["GPIO9"]
        self.assertEqual(p8["fx"], p9["fx"])
        self.assertLess(p8["fx"], 0.5)
        hub, _ = load("adafruit-tca9548a")
        for ch in range(8):
            self.assertEqual(len(hub["functions"]["ch%d" % ch]), 2)
            self.assertIn("SD%d" % ch, hub["functions"])
            self.assertIn("SC%d" % ch, hub["functions"])


FZP = """<?xml version="1.0" encoding="UTF-8"?>
<module moduleId="test_1"><title>Test Part</title><author>someone</author>
<views><breadboardView><layers image="breadboard/test_breadboard.svg">
<layer layerId="breadboard"/></layers></breadboardView></views>
<connectors>
 <connector id="connector0" name="SDA"><views><breadboardView>
  <p layer="breadboard" svgId="connector0pin"/></breadboardView></views></connector>
 <connector id="connector1" name="SCL"><views><breadboardView>
  <p layer="breadboard" svgId="connector1pin"/></breadboardView></views></connector>
 <connector id="connector2" name="GND"><views><breadboardView>
  <p layer="breadboard" svgId="connector2pin"/></breadboardView></views></connector>
 <connector id="connector3" name="VCC"><views><breadboardView>
  <p layer="breadboard" svgId="connector3pin"/></breadboardView></views></connector>
 <connector id="connector4" name="GND"><views><breadboardView>
  <p layer="breadboard" svgId="connector4pin"/></breadboardView></views></connector>
 <connector id="connector5" name="0SDA"><views><breadboardView>
  <p layer="breadboard" svgId="nowhere"/></breadboardView></views></connector>
</connectors></module>
"""

SVG = """<?xml version="1.0" encoding="UTF-8"?>
<!-- a comment -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"
     xmlns:sodipodi="http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd"
     width="1.3889in" height="0.6944in" viewBox="0 0 100 50" onload="alert(1)">
 <metadata><x>y</x></metadata>
 <sodipodi:namedview id="nv"/>
 <script>alert(1)</script>
 <desc>drop me</desc>
 <rect x="0" y="0" width="100" height="50" fill="#123456" onclick="x()" inkscape:label="pcb"/>
 <g transform="translate(10,5)">
  <rect id="connector0pin" x="0.333333" y="0" width="2" height="2"/>
 </g>
 <g transform="matrix(1 0 0 1 20 10)"><g transform="scale(2)">
  <circle id="connector1pin" cx="5" cy="5" r="1"/>
 </g></g>
 <g transform="rotate(90 50 25)">
  <line id="connector2pin" x1="49" y1="20" x2="51" y2="20"/>
 </g>
 <path id="connector3pin" d="M80,40 h4 v4 h-4 z"/>
 <use xlink:href="#connector3pin"/>
 <use xlink:href="http://example.com/x.svg#a"/>
 <image href="http://example.com/a.png" width="1" height="1"/>
 <rect id="connector4pin" x="1.2.5" y="0" width="1" height="1" style="fill:url(http://evil/x)"/>
</svg>
"""


class ImportFritzingTest(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            fzpz = os.path.join(tmp, "Test Part.fzpz")
            with zipfile.ZipFile(fzpz, "w") as z:
                z.writestr("part.test_1.fzp", FZP)
                z.writestr("svg.breadboard.test_breadboard.svg", SVG)
            out = os.path.join(tmp, "out")
            os.mkdir(out)
            r = subprocess.run(
                [sys.executable, "-I", IMPORTER, fzpz, "--id", "test-part", "--out", out,
                 "--source", "https://example.org/x", "--commit", "0" * 40,
                 "--file", "parts/Test Part.fzpz"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("unresolved connector 0SDA (nowhere)", r.stderr)
            with open(os.path.join(out, "test-part.json")) as f:
                meta = json.load(f)
            with open(os.path.join(out, "test-part.svg")) as f:
                svg = f.read()

        c = meta["connectors"]
        # translate(10,5) of a 2x2 rect at (0.33, 0) → centre (11.33, 6)
        self.assertAlmostEqual(c["SDA"]["fx"], 11.3333 / 100, places=3)
        self.assertAlmostEqual(c["SDA"]["fy"], 6 / 50, places=3)
        # matrix translate(20,10) · scale(2) of a circle at (5,5) → (30, 20)
        self.assertAlmostEqual(c["SCL"]["fx"], 0.30, places=3)
        self.assertAlmostEqual(c["SCL"]["fy"], 0.40, places=3)
        # rotate 90° about (50,25) of (50,20) → (55, 25)
        self.assertAlmostEqual(c["GND"]["fx"], 0.55, places=3)
        self.assertAlmostEqual(c["GND"]["fy"], 0.50, places=3)
        # a closed path's bbox centre (82, 42)
        self.assertAlmostEqual(c["VCC"]["fx"], 0.82, places=3)
        self.assertAlmostEqual(c["VCC"]["fy"], 0.84, places=3)
        # the second GND gets its own key; "1.2.5" is x=1.2 (".5" is the next number)
        self.assertAlmostEqual(c["GND_2"]["fx"], 1.7 / 100, places=3)
        self.assertIsNone(c["0SDA"])
        self.assertEqual(meta["functions"]["GND"], ["GND", "GND_2"])
        self.assertEqual(meta["functions"]["SD0"], ["0SDA"])
        self.assertEqual(meta["size"], [100.0, 50.0])
        self.assertEqual(meta["drawn"], "fritzing")
        self.assertEqual(meta["attribution"]["licence"], "CC BY-SA 3.0")
        self.assertEqual(meta["attribution"]["author"], "someone")
        self.assertEqual(meta["attribution"]["commit"], "0" * 40)

        low = svg.lower()
        for gone in ("<script", "onload", "onclick", "metadata", "namedview", "<desc",
                     "inkscape", "sodipodi", "example.com", "evil", "<!--", "<image"):
            self.assertNotIn(gone, low)
        self.assertIn('xlink:href="#connector3pin"', svg)
        self.assertIn('id="connector0pin"', svg)
        self.assertIn('x="0.33"', svg)            # rounded
        self.assertIn('viewBox="0 0 100 50"', svg)
        # still well-formed XML
        import xml.etree.ElementTree as ET
        ET.fromstring(svg)

    def test_refuses_entities(self):
        with tempfile.TemporaryDirectory() as tmp:
            fzpz = os.path.join(tmp, "bad.fzpz")
            with zipfile.ZipFile(fzpz, "w") as z:
                z.writestr("part.bad.fzp", '<?xml version="1.0"?><!DOCTYPE m [<!ENTITY a "b">]><module/>')
            r = subprocess.run([sys.executable, "-I", IMPORTER, fzpz, "--id", "bad-part",
                                "--out", tmp], capture_output=True, text=True, timeout=60)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("entities", r.stderr + r.stdout)
            self.assertFalse(os.path.exists(os.path.join(tmp, "bad-part.svg")))

    def test_refuses_entities_in_any_encoding(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("import_fritzing", IMPORTER)
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)
        # A byte search for "<!ENTITY" does not see UTF-16 or UTF-32.
        doc = ('<?xml version="1.0" encoding="%s"?><!DOCTYPE a [<!ENTITY e "' + "A" * 1000
               + '"><!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">]><a>&f;&f;</a>')
        for enc in ("UTF-16", "UTF-16-LE", "UTF-32"):
            with self.subTest(enc):
                data = (doc % enc).encode(enc.lower())
                with self.assertRaises(SystemExit) as ctx:
                    self.mod.parse_xml(data)
                self.assertIn("refused", str(ctx.exception))
        # A plain DOCTYPE without declarations (Illustrator's SVG 1.1 line) still parses.
        ok = ('<?xml version="1.0"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" '
              '"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg/>').encode("utf-8")
        self.assertEqual(self.mod.parse_xml(ok).tag, "svg")


if __name__ == "__main__":
    unittest.main()
