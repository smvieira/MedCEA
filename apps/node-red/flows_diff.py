#!/usr/bin/env python3
"""apps/node-red/flows_diff.py — the flows in git against the flows Node-RED runs (IAM 3.3).

  flows_diff.py render FILE < VALUES       print FILE with its placeholders filled
  flows_diff.py diff --git DIR --values VALUES < LIVE_FLOWS_JSON

VALUES is "PLACEHOLDER value" lines (infra/lib-node-red.sh nr_flow_values). The secret
placeholders are never on a command line: `render` reads them from the environment
(NR_MQTT_PASS, NR_PG_USER, NR_PG_PASS; apps/node-red/deploy.sh sets them) and refuses a
placeholder it cannot fill. `diff` is not given them at all: every field whose git value
holds one is left out on both sides, with `credentials` (Node-RED keeps those in
flows_cred.json) and the layout keys x, y, w, h. The database user is checked by
health-check.sh dbclients instead.

`diff` is waiver W1's control, health-check.sh noderedflows:
  FAIL  a git node is missing, or a key git has is missing or different live
        ("changed <type> <id> "<name>": keys a, b"); no flows at all
  WARN  a git node carries keys git does not have (the editor writes its defaults when it
        deploys), or nodes outside git run (flows built in the editor, by tab)
It prints ids, types, names, key names and tab labels, never a value, so the ingest
password in flows.json cannot leak. Exit 0 OK, 1 WARN, 2 FAIL, 3 unreadable input.
Standard library only; health-check.sh runs it with python3 -I.
"""
import argparse
import glob
import json
import os
import re
import sys

PLACEHOLDER = re.compile(r"__[A-Z][A-Z0-9_]*__")
SECRET_ENV = {"__MQTT_PASS__": "NR_MQTT_PASS", "__PG_USER__": "NR_PG_USER", "__PG_PASS__": "NR_PG_PASS"}
IGNORED = {"x", "y", "w", "h", "credentials"}
EMPTY_HINT = "Node-RED runs no flows (a new volume, or flows deleted): run ./apps/node-red/deploy.sh"


def read_values(stream):
    out = {}
    for line in stream.read().splitlines():
        if line.strip():
            k, _, v = line.strip().partition(" ")
            out[k] = v.strip()
    return out


def fill(text, values):
    return PLACEHOLDER.sub(lambda m: values.get(m.group(0), m.group(0)), text)


def render(path, values):
    """The flow file with every placeholder filled; ValueError on one it cannot fill."""
    values = dict(values)
    for ph, var in SECRET_ENV.items():
        if os.environ.get(var):
            values[ph] = os.environ[var]
    with open(path) as f:
        text = f.read()
    left = sorted(set(PLACEHOLDER.findall(text)) - set(values))
    if left:
        raise ValueError(f"{os.path.basename(path)}: no value for {', '.join(left)}")
    out = fill(text, values)
    json.loads(out)   # still a flow after filling
    return out


def _masked(value, values):
    """True when a git value holds a placeholder `diff` was not given (a secret)."""
    return any(ph not in values for ph in PLACEHOLDER.findall(json.dumps(value)))


def git_nodes(directory, values):
    """({id: node}, {id: masked keys}) of every flow file: the non-secret placeholders
    filled, the keys holding a secret one left out of the node and named in the second."""
    nodes, masked = {}, {}
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        with open(path) as f:
            for n in json.load(f):
                masked[n["id"]] = {k for k, v in n.items() if _masked(v, values)}
                kept = {k: v for k, v in n.items() if k not in IGNORED and k not in masked[n["id"]]}
                nodes[n["id"]] = json.loads(fill(json.dumps(kept), values))
    return nodes, masked


def diff(git, live, masked=None):
    """(exit code, lines)."""
    masked = masked or {}
    if not live:
        return 2, [f"FAIL {EMPTY_HINT}"]
    by_id = {n.get("id"): n for n in live if isinstance(n, dict)}
    fails, warns, extra_keys = [], [], []
    for nid, g in git.items():
        label = f'{g.get("type")} {nid}' + (f' "{g["name"]}"' if g.get("name") else "")
        n = by_id.get(nid)
        if n is None:
            fails.append(f"FAIL missing {label}")
            continue
        changed = sorted(k for k, v in g.items() if k not in n or n[k] != v)
        if changed:
            fails.append(f"FAIL changed {label}: keys {', '.join(changed)}")
        added = sorted(k for k in n if k not in g and k not in IGNORED and k not in masked.get(nid, ()))
        if added:
            extra_keys.append(f"{nid} ({', '.join(added)})")
    if extra_keys:
        warns.append("WARN keys git does not have (editor defaults? commit the flow as the editor exports it): "
                     + "; ".join(extra_keys))
    tabs = {n.get("id"): n.get("label") or n.get("id") for n in live if isinstance(n, dict) and n.get("type") == "tab"}
    outside = [n for n in live if isinstance(n, dict) and n.get("id") not in git]
    if outside:
        where = sorted({tabs.get(n.get("z")) or (tabs.get(n.get("id")) if n.get("type") == "tab" else None)
                        or "(config nodes)" for n in outside})
        warns.append(f"WARN not in git: {len(outside)} node(s) on " + ", ".join(f'"{t}"' for t in where))
    if fails:
        return 2, fails + warns
    return (1, warns) if warns else (0, [f"OK {len(git)} node(s) from git run unchanged"])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("render")
    r.add_argument("file")
    d = sub.add_parser("diff")
    d.add_argument("--git", required=True)
    d.add_argument("--values", required=True)
    args = ap.parse_args(argv)
    if args.cmd == "render":
        try:
            sys.stdout.write(render(args.file, read_values(sys.stdin)))
        except (OSError, ValueError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        return 0
    try:
        with open(args.values) as f:
            values = read_values(f)
        git, masked = git_nodes(args.git, values)
        text = sys.stdin.read()
        live = json.loads(text) if text.strip() else []
        if not isinstance(live, list):
            raise ValueError("the live flows are not a JSON array")
    except (OSError, ValueError, KeyError) as e:
        print(f"UNREADABLE {type(e).__name__}", file=sys.stdout)
        return 3
    code, lines = diff(git, live, masked)
    print("\n".join(lines))
    return code


if __name__ == "__main__":
    sys.exit(main())
