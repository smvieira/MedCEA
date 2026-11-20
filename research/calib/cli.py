"""python3 -m research.calib <command> (or apps/research/calibrate.sh, which supplies MEDCEA_LAKE).

    snapshots [--lake URL]
        every snapshot: id, cut, readings, held out, contract, lineage, verified
    fetch --snapshot N --expect-lineage HEX --unit U --zone Z --out DIR [--page-size N] [--lake URL]
        writes DIR/dataset.jsonl, DIR/extract.yaml and DIR/fetch-log.json (copy the
        extract into research/calib/extracts/<its committed name> to commit it)
    fit-sensors DATASET --map sht45=sht45_1,scd30=scd30_1 --name NAME --out FILE.yaml
                [--reference sht45] [--humidity-model constant_offset|self_heating]
                [--report FILE.txt] [--allow-dirty]
        fits the sensor model to a dataset and writes the calibration file
    fit-plant DATASET [--report FILE.txt] [--allow-dirty]
        the plant constants' identifiability; refuses (exit 3) while nothing is identifiable
    verify FILE
        a dataset (.jsonl), a snapshot extract or a calibration file: its schema and every
        sha256 and digest

The lake URL is --lake, else MEDCEA_LAKE (only snapshots and fetch read the lake). Exit
codes: 0 done; 2 usage, I/O, network, a lake refusal (its message), a lineage, digest or
hash mismatch, a dirty research/ without --allow-dirty; 3 not identifiable or not enough
data: the fit refused, every reason printed, nothing written. Every error goes to stderr as
"calib: <message>". Nothing here writes the lake or the repository (only the files --out
and --report name).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

from . import calibfile, dataset, extract, plant_fit, segments, sensor_fit
from .lake import MAX_LIMIT, PAGE_SIZE, LakeClient, LakeError

CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class Usage(Exception):
    pass


class Refused(Exception):
    """The fit refused (exit 3): every reason is in the message."""


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


def _read_dataset(path):
    """(header, rows) of a dataset, checked as verify checks it (fetch-log.json's holds when
    it sits beside the file)."""
    dataset.verify(path)
    log = os.path.join(os.path.dirname(os.path.abspath(path)), dataset.FETCH_LOG)
    holds = None
    if os.path.exists(log):
        with open(log, encoding="utf-8") as f:
            holds = json.load(f).get("holds")
    return dataset.read(path, holds=holds)


def _no_clobber(*paths):
    for p in paths:
        if p and os.path.exists(p):
            raise Usage("%s already exists: choose another path (a fit never overwrites one)" % p)


def _write_report(path, lines):
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")


def _entry_line(name, e):
    if e.get("applied"):
        extra = ""
        if e.get("ci95"):
            extra = " [%s, %s]" % tuple(e["ci95"])
        return "  %-36s %-12s %s%s (%s)" % (name, e["value"], "applied", extra, e["source"])
    v = (" %s" % e["value"]) if "value" in e else ""
    return "  %-36s%s not applied (%s): %s" % (name, v, e["source"], e.get("why", ""))


def fit_report(doc):
    lines = ["calibration %s: dataset %s, snapshot %s, lineage %s" % (
        doc["name"], doc["source"]["dataset_content_sha256"], doc["source"]["lake"]["snapshot_id"],
        doc["source"]["lake"]["lineage"]),
        "window %s .. %s, %d segment(s), %d outage(s)" % (doc["source"]["window"]["from"],
                                                          doc["source"]["window"]["to"],
                                                          len(doc["source"]["segments"]),
                                                          len(doc["source"]["outages"])),
        "reference %s; sensor map %s" % (doc["reference"]["sensor"],
                                          ", ".join("%s=%s" % kv for kv in sorted(doc["sensor_map"].items())))]
    for model in sorted(doc["sensors"]):
        fields = doc["sensors"][model]
        lines.append("%s:" % model)
        if "source" in fields:
            lines.append("  %s (%s)" % (fields.get("note", ""), fields["source"]))
            continue
        for field in sorted(fields):
            e = fields[field]
            if field in calibfile.NON_FIELDS:
                lines.append("  %-36s %s (%s)" % (field, e["value"], e["source"]))
            elif field in sensor_fit.DICT_FIELDS:
                for tag in sorted(e):
                    lines.append(_entry_line("%s.%s" % (field, tag), e[tag]))
            else:
                lines.append(_entry_line(field, e))
    for model, rel in sorted(doc["relative"].items()):
        lines.append("%s against %s: dT %s, dRH %s; slope of dRH on RH %s (self-heating predicts %s); residual "
                     "median: self-heating %s, constant offset %s; humidity_model %s" % (
                         model, rel["relative_to"], rel["dT"]["value"], rel["dRH"]["value"],
                         rel["slope_dRH_vs_RH"]["observed"], rel["slope_dRH_vs_RH"]["self_heating"],
                         rel["residual_median"]["self_heating"], rel["residual_median"]["constant_offset"],
                         rel["humidity_model"]))
    for tag, (lo, hi) in sorted(doc["validity"].items()):
        lines.append("validity: %s within [%s, %s] (a scenario outside it needs extrapolate)" % (tag, lo, hi))
    lines.append("unmodelled:")
    for u in doc["unmodelled"]:
        lines.append("  " + ", ".join("%s=%s" % (k, u[k]) for k in sorted(u) if not isinstance(u[k], (dict, list))))
    lines.append("plant: every constant stays the model's assumption (the fit refuses them: fit-plant)")
    return lines


def cmd_fit_sensors(args):
    if not args.name or not CODE_RE.match(args.name):
        raise Usage("--name %r: letters, digits, _ and -, starting with a letter or digit" % args.name)
    _no_clobber(args.out, args.report)
    code = calibfile.code_state(allow_dirty=args.allow_dirty)
    sensor_map = sensor_fit.parse_map(args.map)
    header, rows = _read_dataset(args.dataset)
    fit = sensor_fit.fit(header, rows, sensor_map, reference=args.reference, humidity_model=args.humidity_model)
    if fit["refused_sensors"]:
        lines = []
        for model in fit["refused_sensors"]:
            for name, e in _flat(fit["sensors"][model]):
                lines.append("%s.%s: %s" % (model, name, e.get("why", e.get("source"))))
        raise Refused("every fitted field of %s was refused; nothing written:\n  %s"
                      % (", ".join(fit["refused_sensors"]), "\n  ".join(lines)))
    doc = calibfile.build(header, fit, args.name, sensor_map, args.reference, code, rows)
    sha = calibfile.dump(doc, args.out)
    lines = fit_report(doc)
    _write_report(args.report, lines)
    for line in lines:
        print(line)
    print("calibration %s written, sha256 %s (pin it in a scenario: calibration: {path, sha256})" % (args.out, sha))
    return 0


def _flat(fields):
    for field in sorted(fields):
        e = fields[field]
        if field in calibfile.NON_FIELDS:
            continue
        if field in sensor_fit.DICT_FIELDS:
            for tag in sorted(e):
                yield "%s.%s" % (field, tag), e[tag]
        else:
            yield field, e


def cmd_fit_plant(args):
    _no_clobber(args.report)
    calibfile.code_state(allow_dirty=args.allow_dirty)
    header, rows = _read_dataset(args.dataset)
    verdicts = plant_fit.identifiability(header, rows)
    lines = ["plant constants of dataset %s (snapshot %s, lake contract %s):" % (
        header["content_sha256"], header["lake"]["snapshot_id"], header["lake"]["contract_version"])]
    lines += plant_fit.table(verdicts)
    ok = [f for f, v in verdicts.items() if v.ok]
    if ok:
        lines.append("identifiable: %s. Phase 3 applies no plant fit (a calibration file refuses a fitted plant "
                     "entry): change an assumption in a scenario's plant.overrides." % ", ".join(ok))
    for line in lines:
        print(line)
    if not ok:
        raise Refused("no plant constant is identifiable from this dataset; nothing written")
    _write_report(args.report, lines)
    return 0


def cmd_verify(args):
    path = args.file
    if path.endswith(".jsonl"):
        lines = dataset.verify(path)
    else:
        doc = extract.load(path)
        if isinstance(doc, dict) and "medcea_extract" in doc:
            lines = extract.verify(path)
        elif isinstance(doc, dict) and "medcea_calibration" in doc:
            lines = calibfile.verify(path)
        else:
            raise Usage("%s is neither a dataset (.jsonl), a snapshot extract nor a calibration file" % path)
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
    fs = sub.add_parser("fit-sensors", help="fit the sensor model to a dataset and write the calibration file")
    fs.add_argument("dataset")
    fs.add_argument("--map", required=True, help="model sensor = lake sensor, e.g. sht45=sht45_1,scd30=scd30_1")
    fs.add_argument("--reference", default="sht45", help="the model sensor offsets are relative to (default "
                    "%(default)s)")
    fs.add_argument("--humidity-model", default="constant_offset", choices=sensor_fit.HUMIDITY_MODELS,
                    help="how the other sensor's humidity offset is modelled (default %(default)s)")
    fs.add_argument("--name", required=True, help="the calibration's name (e.g. unit01-zone01-s1)")
    fs.add_argument("--out", required=True, help="the calibration file to write (never overwritten)")
    fs.add_argument("--report", help="also write the report to this file")
    fs.add_argument("--allow-dirty", action="store_true", help="fit although research/ differs from HEAD "
                    "(recorded as dirty in the file)")
    fs.set_defaults(fn=cmd_fit_sensors)
    fp = sub.add_parser("fit-plant", help="which plant constants the dataset identifies (refuses while none)")
    fp.add_argument("dataset")
    fp.add_argument("--report", help="also write the table to this file")
    fp.add_argument("--allow-dirty", action="store_true", help="run although research/ differs from HEAD")
    fp.set_defaults(fn=cmd_fit_plant)
    v = sub.add_parser("verify", help="verify a dataset, a snapshot extract or a calibration file offline")
    v.add_argument("file")
    v.set_defaults(fn=cmd_verify)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        return args.fn(args)
    except Refused as e:
        print("calib: %s" % e, file=sys.stderr)
        return 3
    except (Usage, LakeError, dataset.DatasetError, extract.ExtractError, calibfile.CalibError,
            sensor_fit.FitError, segments.DataError, ValueError) as e:
        print("calib: %s" % e, file=sys.stderr)
        return 2
    except OSError as e:
        print("calib: %s: %s" % (getattr(e, "filename", "") or "", e.strerror or e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
