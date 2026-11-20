"""python3 -m research.calib <command> (or apps/research/calibrate.sh, which supplies MEDCEA_LAKE).

    snapshots [--lake URL]
        every snapshot: id, cut, readings, held out, contract, lineage, verified
    fetch --snapshot N --expect-lineage HEX --unit U --zone Z --out DIR [--page-size N] [--lake URL]
        writes DIR/dataset.jsonl, DIR/extract.yaml and DIR/fetch-log.json (copy the
        extract into research/calib/extracts/<its committed name> to commit it)
    verify FILE
        a dataset (.jsonl) or a snapshot extract: its schema and every sha256 and digest

The lake URL is --lake, else MEDCEA_LAKE. Exit codes: 0 done; 2 usage, I/O, network, a
lake refusal (its message), a lineage, digest or hash mismatch. Every error goes to
stderr as "calib: <message>". Nothing here writes the lake or the repository (only the
folder --out names).
"""
from __future__ import annotations

import argparse
import os
import re
import sys

from . import dataset, extract
from .lake import MAX_LIMIT, PAGE_SIZE, LakeClient, LakeError

CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class Usage(Exception):
    pass


def _client(args):
    url = args.lake or os.environ.get("MEDCEA_LAKE")
    if not url:
        raise Usage("no lake URL: give --lake URL or set MEDCEA_LAKE (apps/research/calibrate.sh sets it)")
    return LakeClient(url)


def cmd_snapshots(args):
    rows = _client(args).snapshots()
    if not rows:
        print("no snapshot in the lake yet: the nightly export has not run (./apps/research-export/deploy.sh)")
        return 0
    print("%-4s %-27s %9s %9s %8s %-64s %s" % ("id", "cut_at", "readings", "held_out", "contract", "lineage",
                                                "verified"))
    for r in rows:
        counts = r.get("rows") or {}
        print("%-4d %-27s %9s %9s %8s %-64s %s" % (
            r["snapshot_id"], dataset.pgtext.norm_ts(r.get("cut_at")), counts.get("measurement", "?"),
            counts.get("held_out", "?"), r.get("contract_version"), r.get("lineage"),
            "yes" if r.get("lineage_verified") else "NO"))
    return 0


def cmd_fetch(args):
    for what, v in (("--unit", args.unit), ("--zone", args.zone)):
        if not CODE_RE.match(v):
            raise Usage("%s %r: a code is letters, digits, _ and -, starting with a letter or digit" % (what, v))
    if args.snapshot < 1:
        raise Usage("--snapshot must be a snapshot id (1 or more)")
    out = args.out
    targets = [os.path.join(out, f) for f in (dataset.FILE, extract.FILE, dataset.FETCH_LOG)]
    there = [t for t in targets if os.path.exists(t)]
    if there:
        raise Usage("%s already exists: choose another --out (a fetch never overwrites one)" % there[0])
    client = _client(args)
    if not 1 <= args.page_size <= MAX_LIMIT:
        raise Usage("--page-size must be between 1 and %d" % MAX_LIMIT)
    header, rows, holds, pinned = dataset.fetch(client, args.snapshot, args.expect_lineage, args.unit, args.zone,
                                                page_size=args.page_size)
    doc = extract.fetch(client, pinned)
    os.makedirs(out, exist_ok=True)
    dataset.write(targets[0], header, rows)
    extract.write(targets[1], doc)
    dataset.write_fetch_log(targets[2], client.base, header, holds)
    lake = header["lake"]
    print("snapshot %d (cut %s), lineage %s: verified" % (lake["snapshot_id"], lake["cut_at"], lake["lineage"]))
    for s in lake["snapshots"]:
        if s["complete"]:
            print("  snapshot %d: %d readings, complete, measurement digest recomputes" % (s["id"], s["rows_fetched"]))
        else:
            print("  snapshot %d: %d of %d readings (%s), digest not checked"
                  % (s["id"], s["rows_fetched"], s["rows_measurement"], s["why"]))
    print("dataset %s: %d readings in %d page(s), content_sha256 %s"
          % (targets[0], header["rows"], header["query"]["pages"], header["content_sha256"]))
    for k, n in header["series"].items():
        print("  %s: %d" % (k, n))
    print("extract %s: %s (commit it as research/calib/extracts/%s)"
          % (targets[1], ", ".join("%s %d" % (fn, len(doc[fn])) for fn in extract.SETS),
             extract.file_name(lake["snapshot_id"], lake["lineage"])))
    print("fetch log %s: %d hold(s), none crossed" % (targets[2], len(holds)))
    return 0


def cmd_verify(args):
    path = args.file
    if path.endswith(".jsonl"):
        lines = dataset.verify(path)
    else:
        doc = extract.load(path)
        if isinstance(doc, dict) and "medcea_extract" in doc:
            lines = extract.verify(path)
        else:
            raise Usage("%s is neither a dataset (.jsonl) nor a snapshot extract" % path)
    for line in lines:
        print(line)
    return 0


def parser():
    p = argparse.ArgumentParser(prog="python3 -m research.calib",
                                description="Calibrate the research sandbox's models from the lake's snapshots "
                                            "(research Phase 3).")
    sub = p.add_subparsers(dest="cmd", metavar="command")
    sub.required = True
    s = sub.add_parser("snapshots", help="list the lake's snapshots with their lineage")
    s.add_argument("--lake", help="lake-api's URL (default: MEDCEA_LAKE)")
    s.set_defaults(fn=cmd_snapshots)
    f = sub.add_parser("fetch", help="fetch one (unit, zone)'s readings and the extract, pinned by lineage")
    f.add_argument("--snapshot", type=int, required=True, help="the snapshot id")
    f.add_argument("--expect-lineage", required=True, help="the lineage you recorded (64 hex)")
    f.add_argument("--unit", required=True)
    f.add_argument("--zone", required=True)
    f.add_argument("--out", required=True, help="the folder to write (created when missing)")
    f.add_argument("--page-size", type=int, default=PAGE_SIZE,
                   help="readings per lake-api call (default %(default)s; a 50,000-row page runs lake-api out "
                        "of memory)")
    f.add_argument("--lake", help="lake-api's URL (default: MEDCEA_LAKE)")
    f.set_defaults(fn=cmd_fetch)
    v = sub.add_parser("verify", help="verify a dataset or a snapshot extract offline")
    v.add_argument("file")
    v.set_defaults(fn=cmd_verify)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        return args.fn(args)
    except (Usage, LakeError, dataset.DatasetError, extract.ExtractError, ValueError) as e:
        print("calib: %s" % e, file=sys.stderr)
        return 2
    except OSError as e:
        print("calib: %s: %s" % (getattr(e, "filename", "") or "", e.strerror or e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
