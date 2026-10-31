#!/usr/bin/env python3
"""apps/iam/compiler/cli.py — the host-side entry point of the policy compiler.

  cli.py check [--file F]               matrix invariants; exit 1 on any violation
  cli.py compile proxy HOST [--file F]  allowed_groups for a host variable, e.g. CONFIG_DOMAIN,
                                        printed as ["a", "b"] for an oauth2-proxy values file
  cli.py compile routes [--file F]      the route table (routes.json of ConfigMap medcea-iam-lib)
  cli.py compile netpol --namespace NS --node-ip IP [--node-ip IP ...]
                                        the NetworkPolicies of `network:` as a JSON List
  cli.py compile grafana [--file F]     Grafana's role_attribute_path (Editor, Viewer or '' = refused,
                                        role_attribute_strict) from the dashboards group's `tool:` block
  cli.py compile jupyterhub --setting allowed_groups|admin_groups [--file F]
                                        the AI workbench's JupyterHub setting, as ["a", "b"] (IAM 3.2)
  cli.py compile grants --mode additive|enforce|verify [--format sql|json] [--part body|assert|all|functions] [--smoke]
                         [--service-logins ROLE,...]  (additive: login roles allowed to log in, IAM Phase 2.5)
                         [--without-iam]  (schema iam and access_svc absent: leave both out, IAM 2.7)
                                        the database side (grants.py): the psql text the IAM_DB_ROLES
                                        bundle of apps/database/lib-db-apply.sh runs, or its JSON form
  cli.py db-roles --names|--passwords|--logins
                                        the database roles grants.py manages (plus mqtt_auth),
                                        "<role> <config.env variable>" for each generated password, or
                                        the login roles (services and rr_admin_login, IAM Phase 2.5)
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

from compiler import grants, invariants, model, netpol, proxies, routes, tools  # noqa: E402


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
    comp.add_argument("target", choices=["proxy", "routes", "netpol", "grants", "grafana", "jupyterhub"])
    comp.add_argument("host", nargs="?")
    comp.add_argument("--namespace")
    comp.add_argument("--setting", choices=["allowed_groups", "admin_groups"], help="compile jupyterhub: which list")
    comp.add_argument("--node-ip", action="append", default=[])
    comp.add_argument("--mode", choices=["additive", "enforce", "verify"])
    comp.add_argument("--format", choices=["sql", "json"], default="sql")
    comp.add_argument("--part", choices=["body", "assert", "all", "functions"], default="all")
    comp.add_argument("--smoke", action="store_true", help="accept the iam-test client's tokens (IAM_SMOKE)")
    comp.add_argument("--service-logins", default="",
                      help="grants --mode additive: comma-separated login roles that may log in (IAM_DB_SERVICE_ROLES)")
    comp.add_argument("--without-iam", action="store_true",
                      help="grants: leave schema iam and access_svc out (the access component is not installed)")
    dbr = sub.add_parser("db-roles")
    g = dbr.add_mutually_exclusive_group(required=True)
    g.add_argument("--names", action="store_true")
    g.add_argument("--passwords", action="store_true")
    g.add_argument("--logins", action="store_true")
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

    if args.cmd == "db-roles":
        if args.names:
            print("\n".join(grants.managed(p) + ["mqtt_auth"]))
        elif args.logins:
            print("\n".join(grants.login_roles(p)))
        else:
            print("\n".join(f"{r} {v}" for r, v in grants.passwords(p)))
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
    if args.cmd == "compile" and args.target == "grants":
        try:
            if args.format == "json":
                print(json.dumps(grants.document(p, args.smoke, args.without_iam), indent=1, sort_keys=True))
            elif not args.mode:
                print("ERROR: compile grants needs --mode additive|enforce|verify", file=sys.stderr)
                return 2
            else:
                # the same source name as `compile routes`, so role_widening() carries routes.json's digest
                print(grants.sql(p, args.mode, args.smoke, args.part,
                                 [r for r in args.service_logins.split(",") if r], args.without_iam,
                                 os.path.basename(args.file) if args.file else "defaults.yaml"), end="")
        except grants.GrantsError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        return 0
    if args.cmd == "compile" and args.target == "grafana":
        try:
            print(tools.grafana_role_path(p))
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        return 0
    if args.cmd == "compile" and args.target == "jupyterhub":
        if not args.setting:
            print("ERROR: compile jupyterhub needs --setting allowed_groups|admin_groups", file=sys.stderr)
            return 2
        try:
            print(proxies.toml_list(tools.jupyterhub_groups(p, args.setting)))
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
