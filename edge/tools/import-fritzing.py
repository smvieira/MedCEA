#!/usr/bin/env python3
"""Turn a Fritzing part (.fzpz) into a wiring-screen picture.

    python3 -I edge/tools/import-fritzing.py PART.fzpz --id ID --out edge/templates/parts/ \
        [--title T] [--source URL --commit SHA --file NAME]

Writes ID.svg (the breadboard view, minified and made inert) and ID.json:
{id, title, svg, size, connectors {name: {fx, fy} | null}, functions, drawn,
attribution}. A connector's position is the centre of its breadboard svgId
element, after every transform above it, as fractions of the viewBox. A
connector the script cannot place is null and reported on stderr; the screen
then draws no pad for it.

The download is untrusted: stdlib only, no entity expansion (ElementTree
refuses external entities), nothing in the archive is executed or written
anywhere but the two output files. Run it with `python3 -I`.
"""

import argparse
import json
import math
import os
import re
import sys
import tempfile
import xml.etree.ElementTree as ET
from xml.parsers import expat
import zipfile

SVG_NS = "http://www.w3.org/2000/svg"
XLINK_NS = "http://www.w3.org/1999/xlink"
XML_NS = "http://www.w3.org/XML/1998/namespace"

MAX_MEMBER = 4 * 1024 * 1024   # one file inside the archive
LICENCE = "CC BY-SA 3.0"

# Elements dropped with everything inside them.
DROP_TAGS = {"script", "metadata", "desc", "title", "foreignObject", "image",
             "a", "animate", "animateMotion", "animateTransform", "set"}
# Attributes whose values are numbers (or number lists): rounded.
NUMERIC_ATTRS = {"d", "points", "transform", "x", "y", "width", "height", "cx",
                 "cy", "r", "rx", "ry", "x1", "y1", "x2", "y2", "stroke-width",
                 "font-size", "viewBox", "stroke-miterlimit", "offset",
                 "fx", "fy", "gradientTransform"}
DROP_ATTRS = {"gorn", "enable-background", "connectorname", "fritzing"}

NUM_RE = re.compile(r"-?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")


def local(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def ns_of(tag):
    return tag[1:].split("}", 1)[0] if tag.startswith("{") else ""


# --- geometry ---------------------------------------------------------------

def mat_mul(a, b):
    """a·b for affine matrices stored as (a, b, c, d, e, f)."""
    return (a[0] * b[0] + a[2] * b[1], a[1] * b[0] + a[3] * b[1],
            a[0] * b[2] + a[2] * b[3], a[1] * b[2] + a[3] * b[3],
            a[0] * b[4] + a[2] * b[5] + a[4], a[1] * b[4] + a[3] * b[5] + a[5])


IDENTITY = (1.0, 0.0, 0.0, 1.0, 0.0, 0.0)


def parse_transform(text):
    m = IDENTITY
    for name, args in re.findall(r"([a-zA-Z]+)\s*\(([^)]*)\)", text or ""):
        v = [float(x) for x in NUM_RE.findall(args)]
        name = name.lower()
        if name == "matrix" and len(v) == 6:
            t = tuple(v)
        elif name == "translate" and v:
            t = (1, 0, 0, 1, v[0], v[1] if len(v) > 1 else 0.0)
        elif name == "scale" and v:
            t = (v[0], 0, 0, v[1] if len(v) > 1 else v[0], 0, 0)
        elif name == "rotate" and v:
            r = math.radians(v[0])
            c, s = math.cos(r), math.sin(r)
            t = (c, s, -s, c, 0, 0)
            if len(v) == 3:
                t = mat_mul(mat_mul((1, 0, 0, 1, v[1], v[2]), t),
                            (1, 0, 0, 1, -v[1], -v[2]))
        elif name == "skewx" and v:
            t = (1, 0, math.tan(math.radians(v[0])), 1, 0, 0)
        elif name == "skewy" and v:
            t = (1, math.tan(math.radians(v[0])), 0, 1, 0, 0)
        else:
            raise ValueError("transform %s(%s)" % (name, args))
        m = mat_mul(m, t)
    return m


def apply(m, x, y):
    return m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5]


def fnum(el, name, default=0.0):
    v = el.get(name)
    if v is None:
        return default
    found = NUM_RE.match(v.strip())
    if not found:
        raise ValueError("%s=%r" % (name, v))
    return float(found.group(0))


def path_points(d):
    """Endpoints and control points of a path: a bounding box good enough
    for a pad, which is what svgIds name. Arcs count only their ends."""
    toks = re.findall(r"[MmLlHhVvCcSsQqTtAaZz]|" + NUM_RE.pattern, d or "")
    pts, i, cmd = [], 0, None
    x = y = sx = sy = 0.0
    arity = {"M": 2, "L": 2, "T": 2, "H": 1, "V": 1, "C": 6, "S": 4, "Q": 4,
             "A": 7, "Z": 0}
    while i < len(toks):
        if re.match(r"[A-Za-z]", toks[i]):
            cmd = toks[i]
            i += 1
            if cmd in "Zz":
                x, y = sx, sy
                continue
        if cmd is None:
            raise ValueError("path data without a command")
        n = arity[cmd.upper()]
        vals = [float(t) for t in toks[i:i + n]]
        if len(vals) < n:
            raise ValueError("short path data")
        i += n
        rel = cmd.islower()
        u = cmd.upper()
        if u == "H":
            x = vals[0] + (x if rel else 0)
            pts.append((x, y))
        elif u == "V":
            y = vals[0] + (y if rel else 0)
            pts.append((x, y))
        elif u == "A":
            x, y = vals[5] + (x if rel else 0), vals[6] + (y if rel else 0)
            pts.append((x, y))
        else:
            ox, oy = (x, y) if rel else (0.0, 0.0)
            for k in range(0, n, 2):
                pts.append((vals[k] + ox, vals[k + 1] + oy))
            x, y = pts[-1]
        if u == "M":
            sx, sy = x, y
            cmd = "l" if rel else "L"   # implicit lineto after a moveto
    return pts


def local_points(el):
    """Points whose transformed bounding box is the element's."""
    t = local(el.tag)
    if t == "rect":
        x, y = fnum(el, "x"), fnum(el, "y")
        w, h = fnum(el, "width"), fnum(el, "height")
        return [(x, y), (x + w, y), (x, y + h), (x + w, y + h)]
    if t in ("circle", "ellipse"):
        cx, cy = fnum(el, "cx"), fnum(el, "cy")
        rx = fnum(el, "r") if t == "circle" else fnum(el, "rx")
        ry = fnum(el, "r") if t == "circle" else fnum(el, "ry")
        return [(cx - rx, cy - ry), (cx + rx, cy - ry), (cx - rx, cy + ry),
                (cx + rx, cy + ry)]
    if t == "line":
        return [(fnum(el, "x1"), fnum(el, "y1")), (fnum(el, "x2"), fnum(el, "y2"))]
    if t in ("polygon", "polyline"):
        v = [float(n) for n in NUM_RE.findall(el.get("points", ""))]
        return list(zip(v[0::2], v[1::2]))
    if t == "path":
        return path_points(el.get("d"))
    if t == "g":
        pts = []
        for child in el:
            if ns_of(child.tag) not in ("", SVG_NS) or local(child.tag) in DROP_TAGS:
                continue
            m = parse_transform(child.get("transform"))
            pts += [apply(m, *p) for p in local_points(child)]
        return pts
    return []


def centre_of(el, parents):
    pts = local_points(el)
    if not pts:
        return None
    m = parse_transform(el.get("transform"))
    p = parents.get(el)
    while p is not None:
        m = mat_mul(parse_transform(p.get("transform")), m)
        p = parents.get(p)
    xs, ys = zip(*(apply(m, *q) for q in pts))
    return (min(xs) + max(xs)) / 2, (min(ys) + max(ys)) / 2


# --- minify and make inert ----------------------------------------------------

def fmt(v, places=2):
    s = ("%." + str(places) + "f") % v
    s = s.rstrip("0").rstrip(".") if "." in s else s
    return "0" if s in ("-0", "") else s


def round_numbers(text, places=2):
    """Round every number in TEXT, keeping a separator wherever the original
    relied on a decimal point to end the previous number ("1.2.5")."""
    out, last = [], 0
    for m in NUM_RE.finditer(text):
        out.append(text[last:m.start()])
        s = fmt(float(m.group(0)), places)
        prev = text[m.start() - 1] if m.start() else ""
        if prev and (prev.isdigit() or prev == "."):
            s = " " + s
        out.append(s)
        last = m.end()
    out.append(text[last:])
    return "".join(out)


def esc(s, attr=False):
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return s.replace('"', "&quot;") if attr else s


EXT_URL = re.compile(r"url\(\s*['\"]?(?!#)[^)]*\)")


def clean_style(s):
    s = re.sub(r"@import[^;]*;?", "", s)
    return EXT_URL.sub("none", s)


def referenced_ids(root):
    ids = set()
    for el in root.iter():
        for v in el.attrib.values():
            ids.update(re.findall(r"url\(\s*['\"]?#([^)'\"\s]+)", v))
            if v.startswith("#"):
                ids.add(v[1:])
        if local(el.tag) == "style" and el.text:
            ids.update(re.findall(r"url\(\s*['\"]?#([^)'\"\s]+)", el.text))
    return ids


def serialise(root, keep_ids, vb):
    out = []

    def attrs(el, is_root):
        res = []
        for k, v in el.attrib.items():
            ns, name = ns_of(k), local(k)
            if ns == XLINK_NS and name == "href":
                if not v.startswith("#"):
                    continue
                res.append(("xlink:href", v))
                continue
            if ns == XML_NS and name == "space":
                res.append(("xml:space", v))
                continue
            if ns or name in DROP_ATTRS or name.lower().startswith("on"):
                continue
            if name == "href" and not v.startswith("#"):
                continue
            if name == "id" and v not in keep_ids:
                continue
            if is_root and name in ("x", "y", "width", "height", "version",
                                    "baseProfile", "viewBox"):
                continue
            if name == "style":
                v = clean_style(v)
            elif name in NUMERIC_ATTRS:
                v = round_numbers(v, 3 if name in ("transform", "gradientTransform") else 2)
            elif EXT_URL.search(v):
                v = EXT_URL.sub("none", v)
            res.append((name, v))
        if is_root:
            res = [("xmlns", SVG_NS), ("xmlns:xlink", XLINK_NS),
                   ("viewBox", " ".join(fmt(n, 3) for n in vb)),
                   ("width", fmt(vb[2], 3)), ("height", fmt(vb[3], 3))] + res
        return "".join(' %s="%s"' % (k, esc(v, True)) for k, v in res)

    def walk(el, is_root=False):
        tag = local(el.tag)
        if ns_of(el.tag) not in ("", SVG_NS) or tag in DROP_TAGS:
            return
        out.append("<%s%s" % (tag, attrs(el, is_root)))
        text = (el.text or "").strip() if tag not in ("text", "tspan", "style") else (el.text or "")
        if tag == "style":
            text = clean_style(text)
        kids = list(el)
        if not text and not kids:
            out.append("/>")
        else:
            out.append(">" + esc(text))
            for child in kids:
                walk(child)
                if tag in ("text", "tspan") and child.tail:
                    out.append(esc(child.tail))
            out.append("</%s>" % tag)

    walk(root, True)
    return "".join(out)


# --- the part ---------------------------------------------------------------

def unique_names(conns):
    """Connector names repeat (a header pin and two STEMMA QT sockets are
    all SDA): the first keeps the name, the next ones get _2, _3 ..."""
    seen = {}
    for c in conns:
        n = seen.get(c["name"], 0) + 1
        seen[c["name"]] = n
        c["key"] = c["name"] if n == 1 else "%s_%d" % (c["name"], n)
    return conns


def function_of(name):
    """The wiring screen's name for a connector, or None."""
    n = name.strip().upper().replace(" ", "")
    m = re.fullmatch(r"(\d)(SDA|SCL)", n)
    if m:   # a hub channel: SD<n>/SC<n> as printed on the TCA9548A
        return ("SD" if m.group(2) == "SDA" else "SC") + m.group(1)
    table = {"INPUTSDA": "SDA", "INPUTSCL": "SCL", "SDA": "SDA", "SCL": "SCL",
             "VCC": "VCC", "VIN": "VCC", "GND": "GND", "3.3V": "3V3_OUT",
             "3VO": "3V3_OUT"}
    return table.get(n, re.sub(r"[^A-Z0-9_]", "_", n) or None)


def functions_for(conns):
    fx = {}
    for c in conns:
        f = function_of(c["name"])
        if f:
            fx.setdefault(f, []).append(c["key"])
    for ch in range(8):   # a hub's channels, as pairs
        sd, sc = fx.get("SD%d" % ch), fx.get("SC%d" % ch)
        if sd and sc:
            fx["ch%d" % ch] = sd + sc
    return fx


def read_member(z, name):
    info = z.getinfo(name)
    if info.file_size > MAX_MEMBER:
        raise SystemExit("%s: %d bytes, refused" % (name, info.file_size))
    return z.read(info)


def _refuse_entities(*_a):
    raise SystemExit("refused: the file declares XML entities")


def parse_xml(data):
    """The member as an Element, refused when it declares any entity.

    A byte search for <!ENTITY sees only ASCII-compatible encodings: a UTF-16
    or UTF-32 file passed it while ElementTree expanded its entities. Fritzing
    writes UTF-8, so anything else is refused first; then expat reads the file,
    in whatever encoding it declares, with every entity declaration (internal,
    external, parameter, unparsed) refused. The C ElementTree parser does not
    expose its expat handlers, hence the separate pass."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff") or b"\x00" in data:
        raise SystemExit("refused: the file is not UTF-8 (UTF-16 or UTF-32)")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise SystemExit("refused: the file is not UTF-8 (%s)" % e)
    if b"<!ENTITY" in data:
        _refuse_entities()
    p = expat.ParserCreate()
    p.EntityDeclHandler = _refuse_entities
    p.UnparsedEntityDeclHandler = _refuse_entities
    p.ExternalEntityRefHandler = _refuse_entities
    try:
        p.Parse(data, True)
    except (expat.ExpatError, ValueError) as e:
        raise SystemExit("refused: not well-formed XML (%s)" % e)
    return ET.fromstring(data)


def import_part(fzpz, part_id, title=None, source=None, commit=None, fname=None,
                report=sys.stderr):
    with zipfile.ZipFile(fzpz) as z:
        names = z.namelist()
        fzps = [n for n in names if n.endswith(".fzp")]
        if len(fzps) != 1:
            raise SystemExit("expected one .fzp in %s, found %d" % (fzpz, len(fzps)))
        fzp = parse_xml(read_member(z, fzps[0]))
        bb = fzp.find("./views/breadboardView/layers")
        if bb is None or not bb.get("image"):
            raise SystemExit("no breadboard view in %s" % fzps[0])
        member = "svg.breadboard." + os.path.basename(bb.get("image"))
        if member not in names:
            raise SystemExit("%s is not in the archive" % member)
        svg = parse_xml(read_member(z, member))

    conns = []
    for c in fzp.iter("connector"):
        layer = c.find("./views/breadboardView/p")
        conns.append({"name": c.get("name") or c.get("id"), "id": c.get("id"),
                      "svgId": layer.get("svgId") if layer is not None else None})
    unique_names(conns)

    vb = [float(n) for n in NUM_RE.findall(svg.get("viewBox", ""))]
    if len(vb) != 4 or vb[2] <= 0 or vb[3] <= 0:
        raise SystemExit("the breadboard SVG has no usable viewBox")
    parents = {child: p for p in svg.iter() for child in p}
    by_id = {el.get("id"): el for el in svg.iter() if el.get("id")}

    connectors, unresolved = {}, []
    for c in conns:
        el = by_id.get(c["svgId"]) if c["svgId"] else None
        pos, why = None, "no such element" if el is None else "no geometry"
        if el is not None:
            try:
                pos = centre_of(el, parents)
            except ValueError as e:
                why = str(e)
        if pos is None:
            unresolved.append("%s (%s): %s" % (c["key"], c["svgId"], why))
            connectors[c["key"]] = None
            continue
        connectors[c["key"]] = {"fx": round((pos[0] - vb[0]) / vb[2], 4),
                                "fy": round((pos[1] - vb[1]) / vb[3], 4)}
    for line in unresolved:
        print("%s: unresolved connector %s" % (part_id, line), file=report)

    keep = referenced_ids(svg) | {c["svgId"] for c in conns if c["svgId"]}
    text = serialise(svg, keep, vb)
    meta = {
        "id": part_id,
        "title": title or (fzp.findtext("title") or part_id).strip(),
        "svg": part_id + ".svg",
        "size": [round(vb[2], 3), round(vb[3], 3)],
        "connectors": connectors,
        "functions": functions_for(conns),
        "drawn": "fritzing",
        "attribution": {
            "source": "Fritzing part " + (fzp.findtext("title") or "").strip(),
            "url": source or "",
            "commit": commit or "",
            "file": fname or os.path.basename(fzpz),
            "author": (fzp.findtext("author") or "").strip(),
            "licence": LICENCE,
            "changes": "breadboard view only; metadata, ids and editor attributes "
                       "removed, numbers rounded, scripts and external references "
                       "stripped; connector centres computed by import-fritzing.py",
        },
    }
    return meta, text, unresolved


def write_atomic(path, data):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".import-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("fzpz")
    ap.add_argument("--id", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--title")
    ap.add_argument("--source", help="URL the .fzpz came from")
    ap.add_argument("--commit")
    ap.add_argument("--file", help="the file's name in its repository")
    a = ap.parse_args(argv)
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,63}", a.id):
        ap.error("--id must match [a-z][a-z0-9-]{1,63}")
    meta, svg, unresolved = import_part(a.fzpz, a.id, a.title, a.source, a.commit, a.file)
    write_atomic(os.path.join(a.out, a.id + ".svg"), svg + "\n")
    write_atomic(os.path.join(a.out, a.id + ".json"),
                 json.dumps(meta, indent=1, ensure_ascii=False) + "\n")
    print("%s: %d connectors (%d unresolved), svg %d bytes" % (
        a.id, len(meta["connectors"]), len(unresolved), len(svg.encode())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
