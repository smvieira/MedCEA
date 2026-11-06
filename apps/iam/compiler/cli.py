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
  cli.py compile superset [--file F]    Superset's AUTH_ROLES_MAPPING, {role: [FAB role, ...]} as one JSON
                                        line, sorted keys (Superset stage B); exit 1 "no group has a
                                        superset tool block" while the policy has none (stage C adds it)
  cli.py has-tool KIND [--file F]       exit 0 when exactly one group carries a `tool:` block of KIND,
                                        1 when none does, 2 when several do, KIND is unknown or the
                                        policy fails its checks; prints nothing on stdout
                                        (policy_tool superset's "not applied yet")
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
  cli.py audit-version --record F       re-check one applied version offline (IAM 4.5, design
                                        §14.8.10) from apply.sh --audit's document F: its entries
                                        digest, audit_versions() and the chain, the approval's JWS
                                        against the JWK its applied event recorded (change and
                                        skeleton versions), and every artefact digest recompiled
                                        from its rows with the skeleton (git show of the recorded
                                        commit) and, when it differs from the tree's, the compiler
                                        of that commit; one line per check; exit 0 all match,
                                        1 a mismatch, 2 cannot reproduce (a -dirty or unknown
                                        commit, a commit git does not have, a document lacking a
                                        part)

Where the policy comes from (compiler/source.py, IAM Phase 4; one rule for every command):
  --file F       an offline draft or a test (never a deploy script; its label is the file
                 name, with a warning, unless --label is given)
  --defaults     apps/iam/policy/defaults.yaml, whatever this host has applied (the offline
                 tests and the iam-db fixture)
  --staged F     the staged host file of the version apps/iam/apply.sh applies (IAM 4.5,
                 design §14.8.4.1): every header check of the host file, and exit 2 unless
                 its sha256 is MEDCEA_POLICY_STAGED_SHA256; label version-N. Only
                 dba_policy_bundle passes it, for the run that holds the verified lock, and
                 apply.sh's checker step; never with MEDCEA_POLICY_FILE
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
sources itself (MEDCEA_POLICY_* stripped); audit-version composes the recorded version itself
(git show of its commit, --file to the compiler in a subprocess). Exit 2 for a source error.
"""
import argparse
import base64
import datetime
import hashlib
import hmac
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compiler import explain, grants, invariants, model, mqtt, netpol, proxies, routes, source, tools  # noqa: E402


# Commands that read only the skeleton: no source, no database (F-15).
SKELETON_ONLY = ("db-roles", "describe-gate", "skeleton-gate")
# Commands that never resolve a source: they build or read the host file themselves.
OWN_SOURCE = ("skeleton-gate", "write-applied", "export-applied", "bootstrap-targets", "audit-version")


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
    # IAM 4.5 (design §14.8.4): an approved skeleton version whose digest HEAD carries is named
    # in the refusal (policy_db_state's approved_skeleton_versions; none with --against-git)
    approved = [] if args.against_git else [
        a.get("version") for a in (state.get("approved_skeleton_versions") or [])
        if isinstance(a, dict) and a.get("skeleton_digest") == git_digest and isinstance(a.get("version"), int)]
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
    if g["verdict"] == "widening" and approved:
        g["approved_version"] = max(approved)
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


# ── audit-version (IAM 4.5, design §14.8.10) ────────────────────────────────────────
# apply.sh --audit's document (one READ ONLY transaction, apps/iam/apply.sh; every part
# required unless said):
#   version          the version row: version, kind, entries_digest, groups, roles, based_on,
#                    approved_by_sub, approved_by_person, approved_at, approved_iat
#   entries, waivers its rows (policy_db_state's shapes)
#   apply_started    the payload of its latest apply_started (commit, skeleton_digest,
#                    compiler_digest: _mark_applied's)
#   applied          {event, event_id, payload}: its applied (or bootstrap_applied) record
#   approval         change/skeleton: {event: {event_id, payload}, evidence: {jws, claims},
#                    other_approved_jti: [...]}: the approved event, its approval_evidence
#                    row and every other version's approved jti (§14.8.5)
#   previous         change/skeleton: the version applied before it, {version, kind, entries,
#                    waivers, apply_started}: whose policy names the approval's azp and
#                    approver roles (the rule qa approved under)
#   audit_findings   audit_versions()' rows for the version; chain: {ok} of verify_chain()
#   issuer           https://<KEYCLOAK_DOMAIN>/realms/<KEYCLOAK_REALM>
ARTEFACT_KEYS = ("routes", "mqtt", "grants_document", "netpol", "proxy", "tools")
LEEWAY = 30                                   # medcea_iam.LEEWAY, seconds
_SEG = re.compile(r"[A-Za-z0-9_-]+")
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


class Unreproducible(Exception):
    """audit-version cannot reproduce the record (exit 2)."""


def _b64url(seg):
    if not _SEG.fullmatch(seg or ""):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def rs256_problem(jws, jwk):
    """None when `jws` (compact, as stored, never re-encoded) carries a valid RS256 signature
    by `jwk` {kid, n, e}; else why not. PKCS#1 v1.5 compared as whole bytes against the
    expected encoding, never parsed (design §14.8.5)."""
    parts = (jws or "").split(".")
    if len(parts) != 3:
        return "the approval's token is not a compact JWS"
    try:
        header = json.loads(_b64url(parts[0]))
        sig = _b64url(parts[2])
        n = int.from_bytes(_b64url(jwk.get("n")), "big")
        e = int.from_bytes(_b64url(jwk.get("e")), "big")
    except (ValueError, TypeError, AttributeError):
        return "the approval's token or the recorded key does not decode"
    if not isinstance(header, dict) or header.get("alg") != "RS256":
        return "the approval's token is not RS256"
    if not header.get("kid") or header.get("kid") != jwk.get("kid"):
        return f"the approval's token names kid {header.get('kid')!r}, the applied event recorded {jwk.get('kid')!r}"
    k = (n.bit_length() + 7) // 8
    if k < len(_SHA256_DIGEST_INFO) + 32 + 11 or e < 3:
        return "the recorded key is not an RSA signing key"
    s = int.from_bytes(sig, "big")
    if len(sig) != k or s >= n:
        return "the approval's signature is malformed"
    digest = hashlib.sha256((parts[0] + "." + parts[1]).encode("ascii")).digest()
    want = b"\x00\x01" + b"\xff" * (k - 3 - len(_SHA256_DIGEST_INFO) - 32) + b"\x00" + _SHA256_DIGEST_INFO + digest
    if not hmac.compare_digest(pow(s, e, n).to_bytes(k, "big"), want):
        return "the approval's signature does not verify against the recorded key"
    return None


def _git_policy(commit):
    """defaults.yaml at a recorded commit (Unreproducible for -dirty, unknown, or a commit
    git does not have)."""
    import yaml
    if not re.fullmatch(r"[0-9a-f]{7,40}", str(commit or "")):
        raise Unreproducible(f"commit {commit!r} cannot be reproduced (a -dirty or unknown commit)")
    r = subprocess.run(["git", "-C", source.REPO_ROOT, "show", f"{commit}:apps/iam/policy/defaults.yaml"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise Unreproducible(f"git has no commit {commit} (git show: {r.stderr.strip()[:200]})")
    data = yaml.safe_load(r.stdout)
    if not isinstance(data, dict):
        raise Unreproducible(f"{commit}:apps/iam/policy/defaults.yaml is not a policy")
    return data


def _recorded_policy(rec, what):
    """(policy dict, dropped) of a recorded version: its rows composed with the skeleton of
    its commit's defaults.yaml, which must carry the skeleton digest its apply_started names
    (ValueError naming the mismatch otherwise)."""
    started = rec.get("apply_started")
    if not isinstance(started, dict):
        raise Unreproducible(f"the record of {what} has no apply_started payload")
    data = _git_policy(started.get("commit"))
    if source.skeleton_digest(data) != started.get("skeleton_digest"):
        raise ValueError(f"{what}: the skeleton of commit {started.get('commit')} is not the recorded "
                         f"{str(started.get('skeleton_digest'))[:12]}")
    rows = source.state_rows({"entries": rec.get("entries") or [], "waivers": rec.get("waivers") or []})
    return source.compose_counted(source.skeleton(data), rows, policy_version=data.get("policy_version"),
                                  drop_unknown=True)


_DRIVER = r"""
import contextlib, io, json, sys
sys.path.insert(0, sys.argv[1])
from compiler import cli
out = {}
for name, argv in json.load(sys.stdin):
    o, e = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
        try:
            rc = cli.main(argv)
        except SystemExit as x:
            rc = x.code if isinstance(x.code, int) else 2
    out[name] = [rc, o.getvalue(), e.getvalue()]
json.dump(out, sys.stdout)
"""


def _compile_targets(iam_dir, policy_file, label, names_argv):
    """{target: (rc, stdout, stderr)}: each cli.py argv of names_argv run with --file
    policy_file --label label by the compiler under iam_dir, in one subprocess (no
    MEDCEA_POLICY_* inherited; an archived compiler is never imported into this process)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("MEDCEA_POLICY_")}
    job = [[n, ["--file", policy_file, "--label", label] + a] for n, a in names_argv]
    r = subprocess.run([sys.executable, "-I", "-c", _DRIVER, iam_dir], input=json.dumps(job),
                       capture_output=True, text=True, env=env, cwd=os.path.dirname(policy_file))
    if r.returncode != 0:
        raise Unreproducible(f"the compiler under {iam_dir} did not run: {r.stderr.strip()[-300:]}")
    return {n: tuple(v) for n, v in json.loads(r.stdout).items()}


def _claims_problems(doc, v, p_prev):
    """The approval's claim checks of design §14.8.5 against the record: [why]."""
    out = []
    ap = doc.get("approval")
    if not isinstance(ap, dict) or not isinstance(ap.get("event"), dict) or not isinstance(ap.get("evidence"), dict):
        return ["no approval with token evidence is recorded"]
    ev = ap["event"].get("payload") or {}
    jws, stored = ap["evidence"].get("jws") or "", ap["evidence"].get("claims")
    sub = str(v.get("approved_by_sub") or "").lower()
    if ev.get("source") != "token" or str(ev.get("sub") or "").lower() != sub or not sub:
        out.append("the approved event is not a token approval by approved_by_sub")
    if hashlib.sha256(jws.encode("utf-8")).hexdigest() != ev.get("jws_sha256"):
        out.append("sha256 of the stored token is not the approved event's jws_sha256")
    jwk = ((doc.get("applied") or {}).get("payload") or {}).get("jwk")
    if not isinstance(jwk, dict):
        return out + ["the applied event records no jwk"]
    bad = rs256_problem(jws, jwk)
    if bad:
        return out + [bad]
    claims = json.loads(_b64url(jws.split(".")[1]))
    if isinstance(stored, str):
        try:
            stored = json.loads(stored)
        except ValueError:
            stored = None
    if not source.claims_recorded(claims, stored):
        return out + ["the token's payload is not the stored claims"]
    if str(claims.get("sub") or "").lower() != sub:
        out.append("the token's sub is not approved_by_sub")
    if claims.get("person_id") != v.get("approved_by_person"):
        out.append("the token's person_id is not approved_by_person")
    if claims.get("jti") != ev.get("jti") or not claims.get("jti"):
        out.append("the token's jti is not the approved event's")
    iat = claims.get("iat")
    if not isinstance(iat, (int, float)) or iat != ev.get("iat") or iat != v.get("approved_iat"):
        out.append("the token's iat is not approved_iat and the event's")
    clients = sorted(c for c, fns in grants.only_rpc_clients(p_prev).items() if "approve_policy" in fns)
    if len(clients) != 1:
        out.append("the applied policy names no single client for approve_policy")
    elif claims.get("azp") != clients[0]:
        out.append(f"the token's azp {claims.get('azp')!r} is not {clients[0]!r}")
    aud = claims.get("aud")
    if "medcea-api" not in (aud if isinstance(aud, list) else [aud]):
        out.append("the token's aud lacks medcea-api")
    if claims.get("typ") != "Bearer":
        out.append("the token's typ is not Bearer")
    if not doc.get("issuer") or claims.get("iss") != doc.get("issuer"):
        out.append("the token's iss is not the realm's issuer")
    try:
        at = datetime.datetime.fromisoformat(str(v.get("approved_at"))).timestamp()
        if not (claims["iat"] - LEEWAY <= at <= claims["exp"] + LEEWAY):
            out.append("approved_at is outside the token's lifetime")
    except (KeyError, TypeError, ValueError):
        out.append("approved_at or the token's iat/exp cannot be read")
    table = routes.compile(p_prev)
    includes = table.get("role_includes") or {}
    held = set(claims.get("groups") or []) & set(p_prev.roles)
    own = sorted(held - {i for r in held for i in (includes.get(r) or [])})
    approvers = ((table.get("dual_control") or {}).get("iam_policy") or {}).get("approver_roles") or []
    if len(own) != 1 or own[0] != ev.get("role") or own[0] not in approvers:
        out.append(f"the token's own role {own} is not the event's {ev.get('role')!r} among the approvers {approvers}")
    if claims.get("jti") in (ap.get("other_approved_jti") or []):
        out.append("the approval token was also used to approve another version")
    return out


def audit_version(doc):
    """(rc, [(OK|FAIL|CANNOT, line)]) of design §14.8.10's checks on apply.sh --audit's
    document; rc 0 all match, 1 a mismatch, 2 cannot reproduce."""
    import apply_check
    lines = []

    def say(code, text):
        lines.append((code, text))
    v = doc.get("version") if isinstance(doc, dict) else None
    if not isinstance(v, dict) or not isinstance(v.get("version"), int) or v.get("kind") not in source.KINDS:
        return 2, [("CANNOT", "the record has no version row")]
    n, kind = v["version"], v["kind"]
    started = doc.get("apply_started") or {}
    applied = (doc.get("applied") or {}).get("payload")
    if not isinstance(applied, dict) or not isinstance(started, dict) or not started:
        return 2, [("CANNOT", f"version {n} has no apply_started and applied record")]
    # 1. the entries digest from the rows
    rows = source.state_rows({"entries": doc.get("entries") or [], "waivers": doc.get("waivers") or []})
    d = source.entries_digest(kind, v.get("groups"), v.get("roles"), rows["entries"], rows["waivers"])
    say("OK" if d == v.get("entries_digest") else "FAIL",
        f"entries digest recomputed from the rows: {d[:12]} (stored {str(v.get('entries_digest'))[:12]})")
    # 2. audit_versions() and the chain
    findings = doc.get("audit_findings") or []
    say("OK" if not findings else "FAIL", f"audit_versions(): {len(findings)} finding(s) for version {n}")
    say("OK" if (doc.get("chain") or {}).get("ok") is True else "FAIL", "verify_chain()")
    try:
        # 3. the approval, against the key the applied event recorded
        if kind in ("change", "skeleton"):
            prev = doc.get("previous")
            if not isinstance(prev, dict):
                raise Unreproducible(f"version {n}'s record names no previous version")
            p_prev = model.Policy(_recorded_policy(prev, f"version {prev.get('version')}")[0])
            probs = _claims_problems(doc, v, p_prev)
            for why in probs:
                say("FAIL", f"approval: {why}")
            if not probs:
                say("OK", "approval: the token verifies against the recorded jwk "
                          f"(kid {((applied.get('jwk') or {}).get('kid'))}) and its claims are the record's")
        # 4. recompile with the recorded skeleton and compiler
        if applied.get("git_commit") not in (None, started.get("commit")):
            say("FAIL", f"the applied event's commit {applied.get('git_commit')} is not apply_started's {started.get('commit')}")
        composed, dropped = _recorded_policy(doc, f"version {n}")
        p = model.Policy(composed)
        errors = invariants.check(p)[0]
        say("OK" if not errors else "FAIL", f"the checker on version {n}: {len(errors)} violation(s)")
        commit, want_cd = started["commit"], started.get("compiler_digest")
        tmp = tempfile.mkdtemp(prefix="medcea-audit-")
        try:
            iam_dir = os.path.dirname(source.HERE)
            if want_cd != source.compiler_digest():
                r = subprocess.run(f'git -C "{source.REPO_ROOT}" archive {commit} apps/iam/compiler | tar -x -C "{tmp}"',
                                   shell=True, capture_output=True, text=True)
                if r.returncode != 0:
                    raise Unreproducible(f"git archive {commit} apps/iam/compiler: {r.stderr.strip()[:200]}")
                iam_dir = os.path.join(tmp, "apps", "iam")
                have_cd = source.compiler_digest(os.path.join(iam_dir, "compiler"))
                if have_cd != want_cd:
                    say("FAIL", f"the compiler of commit {commit} is {have_cd[:12]}, the record names {str(want_cd)[:12]}")
                    return max(1, _rc(lines)), lines
            say("OK", f"compiled with the compiler of {'this tree' if iam_dir == os.path.dirname(source.HERE) else commit} "
                      f"({str(want_cd)[:12]}), skeleton {str(started.get('skeleton_digest'))[:12]} of {commit}"
                      + (f", {dropped} row(s) dropped" if dropped else ""))
            pf = os.path.join(tmp, "composed.yaml")
            import yaml
            with open(pf, "w", encoding="utf-8") as f:
                yaml.safe_dump(composed, f, sort_keys=False, allow_unicode=True, width=1000)
            outs = _compile_targets(iam_dir, pf, f"version-{n}", apply_check.targets(p))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        # 5. the digests against the applied event's artefacts
        have = apply_check.digests_of(outs, commit)
        want = applied.get("artefacts") or {}
        for k in ARTEFACT_KEYS:
            if k not in want:
                say("FAIL", f"artefact {k}: not in the applied event")
            elif have.get(k) != want.get(k):
                say("FAIL", f"artefact {k}: recompiled {_short(have.get(k))}, recorded {_short(want.get(k))}")
            else:
                say("OK", f"artefact {k}: {_short(want.get(k))}")
    except Unreproducible as e:
        say("CANNOT", str(e))
    except ValueError as e:
        say("FAIL", str(e))
    return _rc(lines), lines


def _short(x):
    if isinstance(x, str):
        return x[:12]
    if isinstance(x, dict):
        return hashlib.sha256(source.canonical(x)).hexdigest()[:12] + f" ({len(x)} entries)"
    return repr(x)


def _rc(lines):
    codes = {c for c, _ in lines}
    return 2 if "CANNOT" in codes else 1 if "FAIL" in codes else 0


def cmd_audit_version(args):
    rc, lines = audit_version(_load_state(args.record))
    for code, text in lines:
        print(f"{code:6} {text}")
    print({0: "version reproduced: every check matches", 1: "MISMATCH: the record does not reproduce (above)",
           2: "cannot reproduce this record (above)"}[rc])
    return rc


def source_label(src, given=None):
    """The one source label (routes.json `source`, role_widening()'s digest comment)."""
    return source.label(src, given, warn=lambda m: print(m, file=sys.stderr))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cli.py", description=__doc__.splitlines()[0])
    ap.add_argument("--file", help="an offline policy file (never in a deploy script)")
    ap.add_argument("--defaults", action="store_true", help="read apps/iam/policy/defaults.yaml, whatever is applied")
    ap.add_argument("--staged", help="apply.sh's staged host file (sha256 pinned by MEDCEA_POLICY_STAGED_SHA256)")
    ap.add_argument("--label", help="the source name routes.json and role_widening() record")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    sub.add_parser("hosts")
    ht = sub.add_parser("has-tool")
    ht.add_argument("kind")
    desc = sub.add_parser("describe-gate")
    desc.add_argument("host")
    desc.add_argument("roles")
    comp = sub.add_parser("compile")
    comp.add_argument("target", choices=["proxy", "routes", "netpol", "egress", "grants", "grafana", "jupyterhub", "node-red",
                                         "edge-wizard", "pgadmin", "mqtt", "superset"])
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
    av = sub.add_parser("audit-version")
    av.add_argument("--record", required=True, help="apply.sh --audit's document")
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
        if args.file or args.defaults or args.label or args.staged:
            print(f"ERROR: {args.cmd} takes no --file, --defaults, --staged or --label", file=sys.stderr)
            return 2
        try:
            return {"skeleton-gate": cmd_skeleton_gate, "write-applied": cmd_write_applied,
                    "export-applied": cmd_export_applied, "bootstrap-targets": cmd_bootstrap_targets,
                    "audit-version": cmd_audit_version}[args.cmd](args)
        except source.SourceError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
        except (KeyError, TypeError, ValueError, grants.GrantsError, routes.RouteError) as e:
            print(f"ERROR: {args.cmd}: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
    if args.staged and args.cmd in SKELETON_ONLY:
        print(f"ERROR: {args.cmd} reads only the skeleton: it takes no --staged", file=sys.stderr)
        return 2
    try:
        if args.cmd in SKELETON_ONLY and not args.file:
            src = source.Source("defaults", source.DEFAULTS, source.factory())
        else:
            src = source.resolve(args.file, args.defaults, staged=args.staged)
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

    if args.cmd == "has-tool":
        if args.kind not in tools.KINDS:
            print(f"ERROR: unknown tool kind {args.kind}; known: {', '.join(sorted(tools.KINDS))}", file=sys.stderr)
            return 2
        errors, _ = invariants.check(p)
        if errors:
            print(f"refusing to answer: the policy has {len(errors)} violation(s); run cli.py check", file=sys.stderr)
            return 2
        found = tools.groups(p, args.kind)
        if len(found) > 1:
            print(f"ERROR: {len(found)} groups carry a {args.kind} tool block: {', '.join(found)}", file=sys.stderr)
            return 2
        return 0 if found else 1

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
    if args.cmd == "compile" and args.target == "superset":
        if not tools.groups(p, "superset"):
            print("ERROR: no group has a superset tool block: Superset is not in this access policy "
                  "(found 0 groups; stage C adds it)", file=sys.stderr)
            return 1
        try:
            print(json.dumps(tools.superset_roles_mapping(p), sort_keys=True))
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
                                              src.version if src.kind in ("host", "staged") else None)))
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
