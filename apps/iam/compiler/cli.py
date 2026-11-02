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
  cli.py skeleton-gate (--state F | --against-git REV) [--check]
                                        the skeleton gate (IAM 4.2a, design §14.4.5): the git
                                        skeleton against the accepted one of policy_db_state's
                                        document F (or REV's defaults.yaml, offline: --check
                                        implied); one JSON line on stdout (verdict equal |
                                        narrowing | widening, the added reach per role, _system
                                        and _sections; the git body only for a narrowing
                                        without --check), the message on stderr; exit 0 equal
                                        or narrowing, 3 widening, 2 a bad state or compile error,
                                        or a narrowing (--state) whose skeleton composed with the
                                        applied rows fails the checker (verdict "refused": never
                                        accepted)
  cli.py write-applied --state F [--if-different]
                                        compose the applied version of F with the git skeleton
                                        (which the gate made the accepted one) and write
                                        state/policy-applied.yaml under the verified deploy lock
                                        (--if-different: only when absent or different); one line
  cli.py export-applied                 defaults.yaml's text with only its top-level matrix: and
                                        waivers: blocks replaced by the applied ones (from the host
                                        file); writes nothing; exit 2 without a host file
  cli.py bootstrap-targets --out DIR [--source host] [--state F]
                                        apply.sh --bootstrap's proof (apps/iam/apply_check.py): every
                                        target compiled from --defaults, from the composed version 1
                                        and from a simulated host file, byte-identical (routes minus
                                        source/applied_version), else exit 1; --source host compiles
                                        the written state/policy-applied.yaml against DIR's --defaults

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
all (apps/database/uninstall.sh --purge-data); so does skeleton-gate (the git skeleton and the
state document only). write-applied reads the state document and the git skeleton, never the
host file it replaces; export-applied reads the host file only; bootstrap-targets names its
sources itself (MEDCEA_POLICY_* stripped). Exit 2 for a source error.
"""
import argparse
import datetime
import html
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler import explain, grants, invariants, model, mqtt, netpol, proxies, routes, source, tools  # noqa: E402


# Commands that read only the skeleton: no source, no database (F-15).
SKELETON_ONLY = ("db-roles", "describe-gate", "skeleton-gate")
# Commands that never resolve a source: they build or read the host file themselves.
OWN_SOURCE = ("skeleton-gate", "write-applied", "export-applied", "bootstrap-targets")


def _load_state(path):
    try:
        with open(path) as f:
            state = json.load(f)
    except (OSError, ValueError) as e:
        raise source.SourceError(f"cannot read the state document {path}: {e}") from None
    if not isinstance(state, dict):
        raise source.SourceError(f"the state document {path} is not an object")
    return state


def cmd_skeleton_gate(args):
    git = source.factory()
    if args.against_git:
        if not re.fullmatch(r"[A-Za-z0-9._/~^-]+", args.against_git):
            raise source.SourceError(f"bad revision {args.against_git!r}")
        r = subprocess.run(["git", "-C", source.REPO_ROOT, "show", f"{args.against_git}:apps/iam/policy/defaults.yaml"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise source.SourceError(f"git show {args.against_git}: {r.stderr.strip()}")
        import yaml
        accepted = yaml.safe_load(r.stdout)
        if not isinstance(accepted, dict):
            raise source.SourceError(f"{args.against_git}:apps/iam/policy/defaults.yaml is not a policy")
        acc_digest, ew, check = source.skeleton_digest(accepted), source.entries_and_waivers(accepted), True
    else:
        state = _load_state(args.state)
        acc = source._need_version(state)
        accepted, acc_digest, ew, check = acc["body"], acc["digest"], source.state_rows(state), args.check
    git_digest = source.skeleton_digest(git)
    if git_digest == acc_digest:
        g = {"verdict": "equal", "git_digest": git_digest, "accepted_digest": acc_digest, "added": {},
             "narrowed": [], "unchanged": []}
    else:
        g = explain.gate(accepted, git, ew)
        g["accepted_digest"] = acc_digest
        if g["verdict"] == "equal":   # the stored body does not hash to its digest: compare as different
            g["verdict"] = "narrowing"
    g["commit"] = source.git_commit()
    g["compiler_digest"] = source.compiler_digest()
    if g["verdict"] == "narrowing" and not args.against_git:
        # a narrowing is accepted with no review: it must pass the checker first, composed
        # with the applied rows as the deploys will compile it (review 4.2a)
        errors = explain.checker_errors(git, ew)
        if errors:
            g["verdict"], g["checker"] = "refused", errors
            print(json.dumps(g, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
            print(f"ERROR: the git skeleton {git_digest[:12]} with the applied matrix fails the checker "
                  f"({len(errors)} violation(s)); it is not accepted and nothing was changed:", file=sys.stderr)
            for e in errors:
                print(f"  FAIL: {e}", file=sys.stderr)
            print("Fix the change in git (python3 apps/iam/compiler/cli.py --file <draft> check).", file=sys.stderr)
            return 2
    if g["verdict"] == "narrowing" and not check:
        g["body"] = source.skeleton(git)
    print(json.dumps(g, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    if g["verdict"] == "widening":
        print(explain.gate_message(g), file=sys.stderr)
        return 3
    if g["verdict"] == "narrowing":
        print(f"[policy] skeleton {git_digest[:12]} narrows or changes no access over the accepted {acc_digest[:12]}"
              f" (narrowed: {', '.join(g['narrowed']) or 'none: help text or unused keys'})", file=sys.stderr)
    return 0


def cmd_write_applied(args):
    state = _load_state(args.state)
    what = source.host_file_differs(state)
    v, kind = int(state["version"]), state["kind"]
    if what is None and args.if_different:
        print(f"[policy] state/policy-applied.yaml: version {v} ({kind}) unchanged")
        return 0
    text = source.host_file_text(state, source.git_commit(),
                                 datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    source.write_host_file(source.HOST_FILE, text)
    print(f"[policy] state/policy-applied.yaml: version {v} ({kind}) "
          + ("rewritten: it differed from the database" if what == "different" else "written"))
    return 0


def _top_blocks(lines):
    """{key: (start, end)} of the top-level YAML blocks of defaults.yaml's lines: from the
    key's line to the next top-level key, without the comment and blank lines before it."""
    starts = [(i, l.split(":", 1)[0]) for i, l in enumerate(lines) if re.match(r"[A-Za-z_][A-Za-z0-9_]*:", l)]
    out = {}
    for n, (i, key) in enumerate(starts):
        end = starts[n + 1][0] if n + 1 < len(starts) else len(lines)
        while end > i + 1 and (not lines[end - 1].strip() or lines[end - 1].startswith("#")):
            end -= 1
        out[key] = (i, end)
    return out


def export_applied_text(host_data, defaults_text):
    """defaults.yaml's text with only its top-level matrix: and waivers: blocks replaced by
    host_data's (yaml.safe_dump of each block, at the same place)."""
    import yaml
    lines = defaults_text.splitlines(keepends=True)
    blocks = _top_blocks(lines)
    for key in ("matrix", "waivers"):
        if key not in blocks:
            raise source.SourceError(f"defaults.yaml has no top-level {key}: block")
    for key in sorted(("matrix", "waivers"), key=lambda k: -blocks[k][0]):
        a, b = blocks[key]
        dumped = yaml.safe_dump({key: host_data.get(key) or ({} if key == "matrix" else [])},
                                sort_keys=False, allow_unicode=True, width=1000)
        lines[a:b] = dumped.splitlines(keepends=True)
    return "".join(lines)


def cmd_export_applied(args):
    host = source.read_host_file()
    if host is None:
        print("ERROR: no applied version on this host (no state/policy-applied.yaml)", file=sys.stderr)
        return 2
    with open(source.DEFAULTS) as f:
        print(export_applied_text(host.data, f.read()), end="")
    return 0


def cmd_bootstrap_targets(args):
    """A thin wrapper over apps/iam/apply_check.py bootstrap-targets (design §14.4.13)."""
    import apply_check
    return apply_check.bootstrap_targets(args.out, args.source == "host", state_path=args.state)


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
    sg = sub.add_parser("skeleton-gate")
    sgs = sg.add_mutually_exclusive_group(required=True)
    sgs.add_argument("--state", help="policy_db_state's JSON document")
    sgs.add_argument("--against-git", help="a git revision whose defaults.yaml is the accepted side (offline)")
    sg.add_argument("--check", action="store_true", help="never print the body (read-only callers)")
    wa = sub.add_parser("write-applied")
    wa.add_argument("--state", required=True, help="policy_db_state's JSON document")
    wa.add_argument("--if-different", action="store_true", help="write only when absent or different")
    sub.add_parser("export-applied")
    bt = sub.add_parser("bootstrap-targets")
    bt.add_argument("--out", required=True, help="the staging directory (apply.sh's, mode 700)")
    bt.add_argument("--source", choices=["host"], help="compile the written host file against DIR's reference (or --defaults)")
    bt.add_argument("--state", help="--resume: the committed version's state document is the reference")
    dbr = sub.add_parser("db-roles")
    g = dbr.add_mutually_exclusive_group(required=True)
    g.add_argument("--names", action="store_true")
    g.add_argument("--passwords", action="store_true")
    g.add_argument("--logins", action="store_true")
    args = ap.parse_args(argv)

    if args.cmd in OWN_SOURCE:
        if args.file or args.defaults or args.label:
            print(f"ERROR: {args.cmd} takes no --file, --defaults or --label", file=sys.stderr)
            return 2
        try:
            return {"skeleton-gate": cmd_skeleton_gate, "write-applied": cmd_write_applied,
                    "export-applied": cmd_export_applied, "bootstrap-targets": cmd_bootstrap_targets}[args.cmd](args)
        except source.SourceError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
        except (KeyError, TypeError, ValueError, grants.GrantsError, routes.RouteError) as e:
            print(f"ERROR: {args.cmd}: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
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
            print(routes.dumps(routes.compile(p, source_label(src, args.label),
                                              src.version if src.kind == "host" else None)))
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
