#!/usr/bin/env python3
"""List MicroPython firmware builds for one board from micropython.org.

Runs on the provisioning HOST (not the board) — flash-device.sh calls it to work
out whether anything newer than the local images exists upstream.

There is no JSON API. https://micropython.org/api/v2/... is a 404 and
/download/<BOARD>/?json returns the same HTML as without it, so this scrapes the
server-rendered download page. The link format is strictly regular, which is
what makes that safe:

    /resources/firmware/ESP32_GENERIC_S3-20260824-v1.29.0.bin
    /resources/firmware/ESP32_GENERIC_S3-SPIRAM_OCT-20260824-v1.29.0.bin
    /resources/firmware/ESP32_GENERIC_S3-20260827-v1.30.0-preview.8.gf668077be2.bin
                        └─ board ──────┘ └variant┘ └ date ┘ └ ver ┘ └─ preview ─┘

Preview builds carry a later date than the newest stable, so they must be
filtered out *before* taking "newest by date" or every run offers a nightly.

Output is TSV, newest first, one build per line:

    variant<TAB>date<TAB>version<TAB>filename<TAB>url

`variant` is "-" for the plain build. Exit 3 means the page could not be
fetched; the caller falls back to whatever is on disk.
"""

import argparse
import re
import sys
import urllib.error
import urllib.request

BASE = "https://micropython.org"
UA = "medcea-edge-provisioning/1.0 (+flash-device.sh)"


def build_pattern(board):
    return re.compile(
        r"^" + re.escape(board) + r"(?:-(?P<variant>[A-Z][A-Z0-9_]*))?"
        r"-(?P<date>\d{8})"
        r"-v(?P<version>\d+\.\d+(?:\.\d+)?)"
        r"(?P<preview>-preview\.\d+\.g[0-9a-f]+)?"
        r"\.bin$"
    )


def fetch(board, timeout):
    url = "{}/download/{}/".format(BASE, board)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def parse(html, board, include_preview):
    pat = build_pattern(board)
    seen = {}
    for name in re.findall(r"/resources/firmware/([A-Za-z0-9_.\-]+\.bin)", html):
        m = pat.match(name)
        if not m:
            continue  # another board, or .uf2 / .app-bin / .meta.zip
        if m.group("preview") and not include_preview:
            continue
        seen[name] = (
            m.group("variant") or "-",
            m.group("date"),
            m.group("version") + (m.group("preview") or ""),
            name,
            "{}/resources/firmware/{}".format(BASE, name),
        )
    # Date is YYYYMMDD and monotonic with release order, so it sorts as a string.
    return sorted(seen.values(), key=lambda r: (r[1], r[2]), reverse=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--board", required=True, help="e.g. ESP32_GENERIC_S3")
    ap.add_argument("--include-preview", action="store_true",
                    help="also list -preview.N.g<sha> nightly builds")
    ap.add_argument("--variant", default=None,
                    help='only this variant; "-" for the plain build')
    ap.add_argument("--newest-per-variant", action="store_true",
                    help="one line per variant, the newest build of each")
    ap.add_argument("--limit", type=int, default=0, help="cap the number of lines")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--html-file", default=None,
                    help="parse this file instead of fetching (for testing)")
    a = ap.parse_args()

    if a.html_file:
        with open(a.html_file, encoding="utf-8", errors="replace") as f:
            html = f.read()
    else:
        try:
            html = fetch(a.board, a.timeout)
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            print("could not reach {}: {}".format(BASE, e), file=sys.stderr)
            return 3

    rows = parse(html, a.board, a.include_preview)
    if a.variant is not None:
        rows = [r for r in rows if r[0] == a.variant]
    if a.newest_per_variant:
        best = {}
        for r in rows:
            if r[0] not in best:  # rows are already newest-first
                best[r[0]] = r
        # plain build first, then variants alphabetically
        rows = sorted(best.values(), key=lambda r: (r[0] != "-", r[0]))
    if a.limit:
        rows = rows[: a.limit]

    if not rows:
        print("no matching builds for board {}".format(a.board), file=sys.stderr)
        return 4
    for r in rows:
        print("\t".join(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
