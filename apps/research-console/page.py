#!/usr/bin/env python3
"""apps/research-console/page.py — the research console's page as ConfigMap research-console-html
(research Phase 4e, codeplan/rs4e-design.md §1, §4.1). Run by apps/research-console/deploy.sh;
stdlib only, nothing touches a cluster.

    python3 apps/research-console/page.py configmap NAMESPACE SIGNOUT   the ConfigMap as JSON on stdout
    python3 apps/research-console/page.py manifest SIGNOUT              MANIFEST.json alone
    python3 apps/research-console/page.py sha SIGNOUT                   sha256 of MANIFEST.json

Every file under html/ (dot files left out) becomes one ConfigMap key and one MANIFEST.json entry:

  static name  its path under html/ with a leading vendor/ dropped (html/vendor/uplot/uPlot.min.js is
               served as /static/uplot/uPlot.min.js), so every name fits console.py's NAME (at most
               one '/'; the route table's <file> placeholders match one segment each)
  key          the static name with '/' as '__' (a ConfigMap key holds no '/'); console.py reads
               /srv/<key> for the name the manifest lists, nothing else
  sha256       of the file's bytes (health rsconsole compares the vendor files with VERSION)

MANIFEST.json = {"schema": 1, "signout": SIGNOUT, "files": {name: {key, sha256}}}, canonical JSON
(sorted keys, no spaces), so its sha256 (the ConfigMap's annotation medcea/console-sha256 and the
pod's medcea/html-sha256) moves exactly when the page or the Sign out address changes. A text file
is `data`, anything not UTF-8 `binaryData`. Refused (exit 3): a name console.py would not serve, two
files on one key, a page over LIMIT bytes (the ConfigMap holds 1 MiB; design: refuse at 900 KiB).
Exit 2: usage.
"""
import base64
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HTML = os.path.join(HERE, "html")
NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}(/[A-Za-z0-9._-]{1,64})?$")   # = console.py's
LIMIT = 900 * 1024
CONFIGMAP = "research-console-html"


class PageError(Exception):
    pass


def static_name(rel):
    """html/-relative path -> the name console.py serves under /static/."""
    rel = rel.replace(os.sep, "/")
    return rel[len("vendor/"):] if rel.startswith("vendor/") else rel


def files(html=HTML):
    """{static name: bytes} for every file under html/ (dot files and directories left out)."""
    out, keys = {}, {}
    for d, dirs, names in os.walk(html):
        dirs[:] = sorted(x for x in dirs if not x.startswith("."))
        for n in sorted(names):
            if n.startswith("."):
                continue
            rel = os.path.relpath(os.path.join(d, n), html)
            name = static_name(rel)
            if not NAME.match(name) or any(seg in (".", "..") for seg in name.split("/")) or name == "MANIFEST.json":
                raise PageError("html/%s: its name %r is not one console.py serves (at most one '/' after vendor/, "
                                "[A-Za-z0-9._-], 64 characters a segment)" % (rel, name))
            key = name.replace("/", "__")
            if key in keys:
                raise PageError("html/%s and html/%s land on one ConfigMap key %s" % (keys[key], rel, key))
            keys[key] = rel
            with open(os.path.join(d, n), "rb") as f:
                out[name] = f.read()
    if "index.html" not in out:
        raise PageError("html/index.html is missing")
    return out


def manifest(signout, html=HTML):
    """(MANIFEST.json bytes, {static name: bytes})."""
    if not isinstance(signout, str) or not signout.startswith("https://"):
        raise PageError("the Sign out address must be https://… (research_console_logout_url)")
    fs = files(html)
    doc = {"schema": 1, "signout": signout,
           "files": {n: {"key": n.replace("/", "__"), "sha256": hashlib.sha256(b).hexdigest()} for n, b in fs.items()}}
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode(), fs


def configmap(namespace, signout, html=HTML):
    raw, fs = manifest(signout, html)
    data, binary = {"MANIFEST.json": raw.decode()}, {}
    for n, b in fs.items():
        k = n.replace("/", "__")
        try:
            data[k] = b.decode("utf-8")
        except UnicodeDecodeError:
            binary[k] = base64.b64encode(b).decode()
    size = sum(len(v.encode()) for v in data.values()) + sum(len(v) for v in binary.values())
    if size > LIMIT:
        raise PageError("the page is %d bytes, over %d: move the vendor files to their own ConfigMap (design §4.2)"
                        % (size, LIMIT))
    cm = {"apiVersion": "v1", "kind": "ConfigMap",
          "metadata": {"name": CONFIGMAP, "namespace": namespace,
                       "labels": {"app": "research-console", "app.kubernetes.io/part-of": "medcea-research-console"},
                       "annotations": {"medcea/console-sha256": hashlib.sha256(raw).hexdigest()}},
          "data": data}
    if binary:
        cm["binaryData"] = binary
    return cm


def main(argv):
    try:
        if len(argv) == 3 and argv[0] == "configmap":
            print(json.dumps(configmap(argv[1], argv[2]), sort_keys=True))
        elif len(argv) == 2 and argv[0] == "manifest":
            sys.stdout.write(manifest(argv[1])[0].decode() + "\n")
        elif len(argv) == 2 and argv[0] == "sha":
            print(hashlib.sha256(manifest(argv[1])[0]).hexdigest())
        else:
            print("usage: page.py configmap NAMESPACE SIGNOUT | manifest SIGNOUT | sha SIGNOUT", file=sys.stderr)
            return 2
    except (PageError, OSError) as e:
        print("page.py: %s" % e, file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
