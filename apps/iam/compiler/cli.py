#!/usr/bin/env python3
"""apps/iam/compiler/cli.py — the host-side entry point of the policy compiler.

  cli.py check [--file F]               matrix invariants; exit 1 on any violation
  cli.py compile proxy HOST [--file F]  allowed_groups for a host variable, e.g. CONFIG_DOMAIN,
                                        printed as ["a", "b"] for an oauth2-proxy values file
  cli.py compile routes [--file F]      the route table (routes.json of ConfigMap medcea-iam-lib)
  cli.py compile netpol --namespace NS --node-ip IP [--node-ip IP ...]
                                        the NetworkPolicies of `network:` as a JSON List
  cli.py compile egress CLIENT [--file F]
                                        the egress hops of network.clients.CLIENT, a JSON list of
                                        NetworkPolicyEgressRules on one line (the workbench chart's
                                        singleuser.networkPolicy.egress for `notebooks`, IAM 3.2b)
  cli.py compile grafana [--file F]     Grafana's role_attribute_path (Editor, Viewer or '' = refused,
                                        role_attribute_strict) from the dashboards group's `tool:` block
  cli.py compile jupyterhub --setting allowed_groups|admin_groups [--file F]
                                        the AI workbench's JupyterHub setting, as ["a", "b"] (IAM 3.2)
  cli.py compile node-red [--file F]    Node-RED adminAuth's permissions.json (ConfigMap node-red-auth,
                                        IAM 3.3) from the flows group's `tool:` block
  cli.py compile edge-wizard [--file F] the onboarding wizard's --required-role, comma-separated (IAM 3.4)
  cli.py compile pgadmin [--file F]     pgAdmin's OAUTH2_ADDITIONAL_CLAIMS, a Python literal (IAM 3.4)
  cli.py compile mqtt [--file F]        the MQTT Explorer's per-person credential rows (mqtt.json of ConfigMap
                                        medcea-iam-lib, read by iam-api; IAM 3.5), canonical, one line
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

Where the policy comes from (compiler/source.py, IAM Phase 4; one rule for every command):
  --file F       an offline draft or a test (never a deploy script; its label is the file
                 name, with a warning, unless --label is given)
  --defaults     apps/iam/policy/defaults.yaml, whatever this host has applied (the offline
                 tests and the iam-db fixture)
  otherwise      MEDCEA_POLICY_FILE, only with MEDCEA_POLICY_BREAK_GLASS=<reason> (exit 2
                 without it); else the host applied file state/policy-applied.yaml (written
                 from the database's applied version, from slice 4.2a; a header that does not
                 match its body is exit 2); else apps/iam/policy/defaults.yaml
  --label L      the source name routes.json and role_widening() record (default: by source:
                 version-N, break-glass:<reason>, the --file name, or defaults.yaml)
db-roles and describe-gate read only the skeleton (role names, passwords' variables, labels):
they take the git tree's defaults.yaml unless --file is given, so they work with no source at
all (apps/database/uninstall.sh --purge-data). Exit 2 for a source error.
"""
import argparse
import html
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler import grants, invariants, model, mqtt, netpol, proxies, routes, source, tools  # noqa: E402


# Commands that read only the skeleton: no source, no database (F-15).
SKELETON_ONLY = ("db-roles", "describe-gate")


def source_label(src, given=None):
    """The one source label (routes.json `source`, role_widening()'s digest comment)."""
    return source.label(src, given, warn=lambda m: print(m, file=sys.stderr))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cli.py", description=__doc__.splitlines()[0])
    ap.add_argument("--file", help="an offline policy file (never in a deploy script)")
    ap.add_argument("--defaults", action="store_true", help="read apps/iam/policy/defaults.yaml, whatever is applied")
    ap.add_argument("--label", help="the source name routes.json and role_widening() record")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    sub.add_parser("hosts")
    desc = sub.add_parser("describe-gate")
    desc.add_argument("host")
    desc.add_argument("roles")
    comp = sub.add_parser("compile")
    comp.add_argument("target", choices=["proxy", "routes", "netpol", "egress", "grants", "grafana", "jupyterhub", "node-red",
                                         "edge-wizard", "pgadmin", "mqtt"])
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

    try:
        if args.cmd in SKELETON_ONLY and not args.file:
            src = source.Source("defaults", source.DEFAULTS, source.factory())
        else:
            src = source.resolve(args.file, args.defaults)
    except source.SourceError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    p = model.Policy(src.data)

    if args.cmd == "check":
        errors, notes = invariants.check(p)
        cells = sum(len(v) for v in p.matrix.values())
        print(source.describe(src))
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
    if args.cmd == "compile" and args.target == "egress":
        try:
            print(json.dumps(netpol.egress(p, args.host or ""), sort_keys=True, separators=(",", ":")))
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
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
                                 source_label(src, args.label)), end="")
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
    if args.cmd == "compile" and args.target == "node-red":
        try:
            print(json.dumps(tools.node_red_permissions(p), sort_keys=True))
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        return 0
    if args.cmd == "compile" and args.target in ("edge-wizard", "pgadmin"):
        try:
            print(",".join(tools.edge_wizard_roles(p)) if args.target == "edge-wizard" else tools.pgadmin_claims(p))
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        return 0
    if args.cmd == "compile" and args.target == "mqtt":
        print(mqtt.dumps(mqtt.compile(p)))
        return 0
    if args.cmd == "compile" and args.target == "routes":
        try:
            print(routes.dumps(routes.compile(p, source_label(src, args.label))))
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
