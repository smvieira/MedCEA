#!/usr/bin/env python3
"""apps/research-model/fetch_model.py — fetch pinned GGUF files into the model folder
(research Phase 4b step 0, codeplan/rs4-design.md R28). Stdlib only: it runs in Job
research-model-fetch on the pinned python:3.14.4-slim image (which has no curl), as the
folder's owner, and is tested offline against a local HTTP server.

    python3 -I fetch_model.py --dir /models --pins models.json [--verify-only]

models.json: {"<key>": {"url": ..., "sha256": ..., "size_bytes": ..., "file": ..., ...}}.

For each model: <sha256>.gguf already there and its hash matches → kept. Otherwise the
body is streamed into <sha256>.gguf.partial, resuming with a Range request from the
partial's size (the bytes already there are hashed first; a server that answers 200
instead of 206 restarts it from zero), following Hugging Face's redirects (urllib keeps
the Range header across them). Only when the whole file's sha256 equals the pin is it
renamed to <sha256>.gguf (and <sha256>.json written beside it, the provenance); a
mismatch removes the partial and exits 1, so the next try starts clean. Nothing is
printed but sizes, rates and hashes.

Exit 0 every model present and verified; 1 a mismatch or a size over the pin; 2 usage,
the network or the folder.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

CHUNK = 1 << 20
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
USER_AGENT = "medcea-research-model-fetch/1"


class FetchError(Exception):
    def __init__(self, msg, code=2):
        super().__init__(msg)
        self.code = code


def log(msg):
    print("fetch: %s" % msg, flush=True)


def sha256_file(path, h=None):
    h = h or hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                return h
            h.update(b)


def _open(url, start, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    if start > 0:
        req.add_header("Range", "bytes=%d-" % start)
    return urllib.request.urlopen(req, timeout=timeout)


def fetch_one(key, pin, folder, timeout=60, verify_only=False, opener=_open):
    """Fetch one pinned model into FOLDER; returns the final path."""
    sha = pin["sha256"]
    if not SHA_RE.match(sha):
        raise FetchError("%s: the pin's sha256 is not 64 hex digits" % key)
    size = int(pin["size_bytes"])
    final = os.path.join(folder, sha + ".gguf")
    partial = final + ".partial"
    if os.path.exists(final):
        log("%s: %s present, checking its sha256" % (key, os.path.basename(final)))
        got = sha256_file(final).hexdigest()
        if got == sha:
            log("%s: verified %s" % (key, sha))
            _provenance(folder, key, pin)
            return final
        raise FetchError("%s: %s has sha256 %s, not the pinned %s: remove it by hand and fetch again"
                         % (key, final, got, sha), 1)
    if verify_only:
        raise FetchError("%s: %s is not there (fetch first)" % (key, final), 1)

    have = os.path.getsize(partial) if os.path.exists(partial) else 0
    if have > size:
        os.remove(partial)
        have = 0
    h = hashlib.sha256()
    if have:
        sha256_file(partial, h)
        log("%s: resuming at %d of %d bytes" % (key, have, size))
    if have < size:
        try:
            resp = opener(pin["url"], have, timeout)
        except urllib.error.HTTPError as e:
            if e.code == 416 and have == size:
                resp = None
            else:
                raise FetchError("%s: HTTP %d from %s" % (key, e.code, pin["url"].split("?")[0])) from None
        except (urllib.error.URLError, OSError) as e:
            raise FetchError("%s: cannot reach %s (%s)" % (key, pin["url"].split("?")[0], e)) from None
        if resp is not None:
            status = getattr(resp, "status", 200)
            if have and status != 206:
                log("%s: the server answered %d to the range request: starting from zero" % (key, status))
                have, h = 0, hashlib.sha256()
                mode = "wb"
            else:
                if have:
                    cr = resp.headers.get("Content-Range", "")
                    m = re.match(r"^bytes (\d+)-", cr)
                    if not m or int(m.group(1)) != have:
                        raise FetchError("%s: the server resumed at %r, not byte %d" % (key, cr, have))
                mode = "ab" if have else "wb"
            t0, done, last = time.monotonic(), have, time.monotonic()
            with resp, open(partial, mode) as out:
                while True:
                    try:
                        b = resp.read(CHUNK)
                    except (OSError, urllib.error.URLError) as e:
                        raise FetchError("%s: the download broke at byte %d (%s): run the fetch again, "
                                         "it resumes" % (key, done, e)) from None
                    if not b:
                        break
                    done += len(b)
                    if done > size:
                        out.close()
                        os.remove(partial)
                        raise FetchError("%s: more than the pinned %d bytes: refused, partial removed"
                                         % (key, size), 1)
                    h.update(b)
                    out.write(b)
                    now = time.monotonic()
                    if now - last >= 30:
                        rate = (done - have) / max(now - t0, 1e-6) / 1e6
                        log("%s: %d of %d bytes (%.1f MB/s)" % (key, done, size, rate))
                        last = now
            have = done
    if have != size:
        raise FetchError("%s: %d of %d bytes so far: run the fetch again, it resumes" % (key, have, size))
    got = h.hexdigest()
    if got != sha:
        os.remove(partial)
        raise FetchError("%s: sha256 %s is not the pinned %s: refused, partial removed" % (key, got, sha), 1)
    os.replace(partial, final)
    log("%s: verified %s, %d bytes, renamed to %s" % (key, sha, size, os.path.basename(final)))
    _provenance(folder, key, pin)
    return final


def _provenance(folder, key, pin):
    path = os.path.join(folder, pin["sha256"] + ".json")
    if os.path.exists(path):
        return
    doc = {k: pin.get(k) for k in ("name", "repo", "revision", "file", "url", "size_bytes", "sha256", "licence")}
    doc["key"] = key
    doc["fetched_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fetch_model.py")
    ap.add_argument("--dir", required=True)
    ap.add_argument("--pins", required=True)
    ap.add_argument("--verify-only", action="store_true")
    ap.add_argument("--timeout", type=float, default=60)
    a = ap.parse_args(argv)
    if not os.path.isdir(a.dir) or not os.access(a.dir, os.W_OK | os.X_OK):
        print("fetch: %s is not a writable folder" % a.dir, file=sys.stderr)
        return 2
    with open(a.pins, encoding="utf-8") as f:
        pins = json.load(f)
    rc = 0
    for key in sorted(pins):
        try:
            fetch_one(key, pins[key], a.dir, a.timeout, a.verify_only)
        except FetchError as e:
            print("fetch: %s" % e, file=sys.stderr)
            rc = max(rc, e.code)
    return rc


if __name__ == "__main__":
    sys.exit(main())
