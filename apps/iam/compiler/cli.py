#!/usr/bin/env python3
"""apps/iam/compiler/cli.py — the host-side entry point of the policy compiler.

  cli.py check [--file F]               matrix invariants; exit 1 on any violation
  cli.py compile proxy HOST [--file F]  allowed_groups for a host variable, e.g. CONFIG_DOMAIN,
                                        printed as ["a", "b"] for an oauth2-proxy values file
  cli.py compile routes [--file F]      the route table (routes.json of ConfigMap medcea-iam-lib)
  cli.py compile netpol --namespace NS --node-ip IP [--node-ip IP ...]
                                        the NetworkPolicies of `network:` as a JSON List
  cli.py hosts [--file F]               every host and the roles it admits (for review)
  cli.py describe-gate HOST ROLES       for a gate's 403 page: the host's label, a tab, and the
                                        labels of ROLES (the deployed list, ["a", "b"]),
                                        HTML-escaped

Reads apps/iam/policy/defaults.yaml unless --file is given. From Phase 1 on it reads the
applied version from the database when one exists (plan Section 3.3); until then the
defaults are the policy in force.
"""
import argparse
import html
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler import invariants, model, netpol, proxies, routes  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cli.py", description=__doc__.splitlines()[0])
    ap.add_argument("--file", help="policy file (default: apps/iam/policy/defaults.yaml)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    sub.add_parser("hosts")
    desc = sub.add_parser("describe-gate")
    desc.add_argument("host")
    desc.add_argument("roles")
    comp = sub.add_parser("compile")
    comp.add_argument("target", choices=["proxy", "routes", "netpol"])
    comp.add_argument("host", nargs="?")
    comp.add_argument("--namespace")
    comp.add_argument("--node-ip", action="append", default=[])
    args = ap.parse_args(argv)

    p = model.load(args.file)

    if args.cmd == "check":
        errors, notes = invariants.check(p)
        cells = sum(len(v) for v in p.matrix.values())
        print(f"{len(p.roles)} roles, {len(p.groups)} groups, {cells} cells, "
              f"{len(p.data['invariants'])} invariants, {len(p.waivers)} waivers")
        for n in notes:
            print("  note:", n)
        for e in errors:
            print("  FAIL:", e)
        print("OK" if not errors else f"{len(errors)} violation(s)")
        return 1 if errors else 0

    if args.cmd == "hosts":
        for h in p.hosts:
            status = proxies.ENFORCEMENT.get(h, "unknown")
            print(f"{h:18} [{status}] {' '.join(proxies.admitted(p, h))}")
        return 0

    if args.cmd == "describe-gate":
        try:
            label, roles = proxies.describe(p, args.host, json.loads(args.roles))
        except (KeyError, ValueError) as e:
            print(f"ERROR: {e.args[0]}", file=sys.stderr)
            return 2
        print(html.escape(label) + "\t" + html.escape(", ".join(roles)))
        return 0

    if args.cmd == "compile":
        errors, _ = invariants.check(p)
        if errors:
            print(f"refusing to compile: the policy has {len(errors)} violation(s); run cli.py check", file=sys.stderr)
            return 1
    if args.cmd == "compile" and args.target == "netpol":
        if not args.namespace:
            print("ERROR: compile netpol needs --namespace", file=sys.stderr)
            return 2
        try:
            print(json.dumps(netpol.compile(p, args.namespace, args.node_ip), indent=1))
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        return 0
    if args.cmd == "compile" and args.target == "routes":
        try:
            print(routes.dumps(routes.compile(p, os.path.basename(args.file) if args.file else "defaults.yaml")))
        except routes.RouteError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        return 0
    if args.cmd == "compile" and args.target == "proxy":
        if not args.host:
            print("ERROR: compile proxy needs a host variable, e.g. CONFIG_DOMAIN", file=sys.stderr)
            return 2
        try:
            print(proxies.toml_list(proxies.admitted(p, args.host)))
        except KeyError as e:
            print(f"ERROR: {e.args[0]}", file=sys.stderr)
            return 2
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
