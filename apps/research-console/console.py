#!/usr/bin/env python3
"""apps/research-console/console.py — the research console's page server (research Phase 4e,
codeplan/rs4e-design.md §1, OD-4e-9: its own pod, never the orchestrator).

A static server and nothing else: no Kubernetes token, no Secret, no egress. It serves the page
from ConfigMap research-console-html, mounted read-only at /srv (RS_CONSOLE_DIR) and written by
apps/research-console/deploy.sh with MANIFEST.json beside the files:

    {"schema": 1, "signout": "<the console's Sign out URL>",
     "files": {"<static name>": {"key": "<ConfigMap key>", "sha256": "<hex>"}, ...}}

  GET /healthz                 answered before any check (the policy's `*` exemption, rule 4):
                               {service, manifest_sha256, files}; nothing about the person
  GET /                        the manifest's index.html
  GET /static/MANIFEST.json    the manifest itself (the page reads `signout` from it)
  GET /static/<name>           a file the manifest lists, <name> matching NAME (at most one '/'),
                               served from /srv/<key>; anything else 404, no path is ever joined
                               from the request (the key comes from the manifest and must be a
                               plain ConfigMap key: no '/', never the mount's ..data entries)

Every request but /healthz is checked with medcea_iam.check("research-console", …) and refused
(401/403/503) whatever IAM_ENFORCE says, as every research service: the person's token arrives
as X-Forwarded-Access-Token from the console's oauth2-proxy and must carry the audience the
route table names for this service (medcea-research, the console pod's `audience` key). The
library is loaded from /iam/medcea_iam.py (MEDCEA_IAM_LIB) and reloaded when it changes, so a
late ConfigMap heals without a restart. Every answer carries the console's headers (CSP,
nosniff, no-referrer, no-cache). Only GET and HEAD; logs method, status and a cut path, never a
header or token.

    python3 apps/research-console/console.py      (port RS_CONSOLE_PORT, default 8080)
"""
import hashlib
import importlib.util
import json
import os
import re
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVICE = "research-console"
ROOT = os.environ.get("RS_CONSOLE_DIR", "/srv")
IAM_LIB = os.environ.get("MEDCEA_IAM_LIB", "/iam/medcea_iam.py")
NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}(/[A-Za-z0-9._-]{1,64})?$")
KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")   # a ConfigMap key; never "..data" or a path
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
         ".css": "text/css; charset=utf-8", ".json": "application/json", ".svg": "image/svg+xml",
         ".png": "image/png", ".woff2": "font/woff2", ".txt": "text/plain; charset=utf-8",
         "": "text/plain; charset=utf-8"}   # LICENSE and VERSION files have no extension
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
HEADERS = (("Content-Security-Policy", CSP), ("X-Content-Type-Options", "nosniff"),
           ("Referrer-Policy", "no-referrer"), ("Cache-Control", "no-cache"))

_IAM = {}


def medcea_iam():
    """/iam/medcea_iam.py, reloaded when its mtime changes; None while it cannot be loaded."""
    try:
        mtime = os.stat(IAM_LIB).st_mtime_ns
        if mtime != _IAM.get("mtime"):
            spec = importlib.util.spec_from_file_location("medcea_iam", IAM_LIB)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            _IAM.update(mtime=mtime, mod=mod)
    except Exception as e:  # noqa: BLE001 - a missing mount must not stop the server
        if not _IAM.get("warned"):
            sys.stderr.write("research-console: medcea_iam not loaded from %s (%s)\n" % (IAM_LIB, type(e).__name__))
            _IAM["warned"] = True
    return _IAM.get("mod")


def manifest(root=None):
    """(the manifest's bytes, its parsed document) or (None, None) when absent or malformed."""
    try:
        with open(os.path.join(root or ROOT, "MANIFEST.json"), "rb") as f:
            raw = f.read()
        doc = json.loads(raw)
    except (OSError, ValueError):
        return None, None
    if not isinstance(doc, dict) or not isinstance(doc.get("files"), dict):
        return None, None
    return raw, doc


def content_type(name):
    base = name.rsplit("/", 1)[-1]
    ext = os.path.splitext(base)[1].lower()
    return TYPES.get(ext)


def lookup(name, root=None):
    """(bytes, content type) of a static name the manifest lists, else None. The file read is
    root/<key> for the manifest's key: nothing of the request reaches the path."""
    if name == "MANIFEST.json":
        raw, _doc = manifest(root)
        return (raw, TYPES[".json"]) if raw is not None else None
    if not NAME.match(name) or any(seg in (".", "..") for seg in name.split("/")):
        return None
    _raw, doc = manifest(root)
    if doc is None:
        return None
    entry = doc["files"].get(name)
    ctype = content_type(name)
    if not isinstance(entry, dict) or ctype is None:
        return None
    key = entry.get("key")
    if not isinstance(key, str) or not KEY.match(key) or ".." in key:
        return None
    try:
        with open(os.path.join(root or ROOT, key), "rb") as f:
            return f.read(), ctype
    except OSError:
        return None


def healthz(root=None):
    raw, doc = manifest(root)
    return {"service": SERVICE, "manifest_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
            "files": len(doc["files"]) if doc is not None else 0}


class Handler(BaseHTTPRequestHandler):
    server_version = "research-console"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):   # never a header, a query or a token
        pass

    def _log(self, code):
        sys.stderr.write("%s %d %s\n" % (self.command, code, urllib.parse.urlsplit(self.path).path[:60]))

    def answer(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if self.command not in ("GET", "HEAD"):
            self.close_connection = True   # its body is never read
            self.send_header("Connection", "close")
        for k, v in HEADERS:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self._log(code)

    def route(self):
        path = urllib.parse.urlsplit(self.path).path
        if self.command in ("GET", "HEAD") and path == "/healthz":
            return self.answer(200, healthz())
        iam = medcea_iam()
        if iam is None:
            return self.answer(503, {"error": "the access library (/iam/medcea_iam.py) is missing"})
        d = iam.check(SERVICE, self.command, self.path, self.headers)
        if not d.allow:   # research services refuse whatever IAM_ENFORCE says
            return self.answer(d.status, {"error": d.reason})
        if self.command not in ("GET", "HEAD"):
            return self.answer(405, {"error": "method not allowed"})
        if path == "/":
            found = lookup("index.html")
        elif path.startswith("/static/"):
            found = lookup(urllib.parse.unquote(path[len("/static/"):]))
        else:
            found = None
        if found is None:
            return self.answer(404, {"error": "not found"})
        return self.answer(200, found[0], found[1])

    def _safe(self):
        try:
            self.route()
        except Exception as e:  # noqa: BLE001 - one bad request must not end the server
            sys.stderr.write("research-console: error %s\n" % type(e).__name__)
            try:
                self.answer(500, {"error": "Something went wrong on our side."})
            except Exception:  # noqa: BLE001 - the connection may be gone
                pass

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = _safe


def make_server(host="0.0.0.0", port=8080):
    return ThreadingHTTPServer((host, port), Handler)


def main():
    srv = make_server(port=int(os.environ.get("RS_CONSOLE_PORT", "8080")))
    sys.stderr.write("research-console: port %d, page from %s\n" % (srv.server_address[1], ROOT))
    srv.serve_forever()


if __name__ == "__main__":
    main()
