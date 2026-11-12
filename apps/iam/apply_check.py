#!/usr/bin/env python3
"""apps/iam/apply_check.py — the offline half of apps/iam/apply.sh (IAM Phase 4, slices 4.2a
and 4.4; design §14.4.10, §14.7.6). stdlib + PyYAML; fed JSON files (never a secret), so every decision here is
tested without a cluster (tests/test_apply.py), as units_bootstrap.py is for units.sh.

  can-approve --dual-control D --accounts A
        D: routes.json's dual_control (or a whole routes.json); A: [{sub, username, enabled,
        roles, person_id}] (`accounts`). Prints one problem per line for iam_policy and
        iam_users (no approver, no approver of another person than every maker, no maker);
        exit 0 always: the caller decides (a WARNING in the bootstrap, OA-b; a refusal, 4.5)
  accounts --dir DIR
        Keycloak's direct holders of each platform role (DIR/<role>.json, one
        GET roles/<role>/users answer each; DIR/users/<id>.json the full representation,
        which carries person_id) as A above, roles expanded by the git skeleton's `includes`
        (Keycloak composites)
  by-user --in F --username U
        the --by account from Keycloak's users?username=U&exact=true answer: prints
        "<sub>\\t<person_id>"; exit 2 with the reason (unknown, disabled, no person_id)
  seed-fact --history H --sub S
        the recorded account_seeded facts of S in a --full state document H (`seeded`):
        "<event_id> <fact> <username> <role> <person_id>" per fact, or nothing
  seed-build --fact created|person_id_set|observed --username U --sub S [--role R]
             [--person-id P] [--by NAME]
        one account_seeded fact as a JSON line (design §14.4.12), fact_id the content hash
  seed-queue --in FILE
        append FILE's facts to state/seed-facts.jsonl under the verified deploy lock
        (state/ 700, the file 600); prints the count
  simulate-state --out F
        the state document version 1 would have once committed: the factory entries and
        waivers round-tripped through JSON as psql returns them, the git skeleton accepted
  bundle-sql --kind bootstrap --state F --by-sub U --by-person P --log L --out DIR
             [--commit C] [--digests D]
        DIR/pre.sql and DIR/post.sql of the bootstrap bundle (apps/database/lib-db-apply.sh
        dba_policy_bundle): PRE accepts and syncs the git skeleton, builds version 1 (\\gset v)
        and asserts its entries digest; POST marks it applied. Every value travels base64 in
        a psql variable, never quoted into the SQL text
  apply-record --event bootstrap_applied|applied --state F --by-sub U --by-person P --log L
               --commit C --chain-head ID:HASH [--digests D] [--resumed] --out SQL
        the step-10 record (_record as system:apply), printing its event id when run
  bootstrap-targets --out DIR [--source host]
        every target of TARGETS compiled from --defaults (DIR/defaults), from the composed
        v1 (DIR/v1.yaml, --label version-1: DIR/v1) and from the simulated host file
        (DIR/host.yaml from simulate-state: DIR/sim); each byte-identical (routes as JSON
        minus source/applied_version), else exit 1 naming the first difference. Writes
        DIR/digests.json (the artefact digests _mark_applied records). --source host:
        compiles from the written state/policy-applied.yaml (MEDCEA_POLICY_* stripped) and
        compares it with DIR/reference when present, else DIR/defaults (exit 1 on a
        difference). --state F (apply.sh --resume): the reference is the committed version
        of F itself (its rows with the git skeleton, through a simulated host file), saved in
        DIR/reference with DIR/digests.json from it, never the current defaults.yaml
  health --state F --host-file PATH --holders PIDS --policy-port true|false|absent
        STATUS|detail lines of health's iampolicy (design §14.4.14)
  status --state F [--gate G --gate-rc N] [--live-routes D] [--live-mqtt D]
        apply.sh --status's report (read-only)
  owners [--deploys | --scoped]
        HOST_OWNER and the other targets' owning commands (§6.7); --deploys: the full deploys
        that re-render them, in order; --scoped: every scoped mode once, in the order
        apply.sh --resume runs them (IAM 4.2b)
  deferred-record --state F --target T --reason R --command C --out SQL
        the apply_deferred record (system:apply) of a target --resume could not re-render (4.2b)
  propose --state F --rev REV --commit C --by-sub U --by-person P --reason-file R --version N
          [--out SQL]
        apply.sh --propose-skeleton's step 4 (IAM 4.4, design §14.7.6): the skeleton gate of
        REV's defaults.yaml over the accepted one (equal, narrowing, a checker failure or an
        open change or skeleton version: exit 1), then skeleton version N's diff document
        (explain.diff_document), its canonical digest, the summary, and in SQL the one
        transaction that submits it (_propose_skeleton, version and entries digest asserted)
  open-version --state F
        the open change or skeleton version of a --full state document, tab-separated
        (version, kind, status, reason, authors), or nothing
  withdraw-sql --version N --reason-file R --out SQL
        apply.sh --withdraw-open's transaction: _withdraw_open, asserted to withdraw N
  maker-warn --dual-control D --roles F --username U
        a warning line when U's realm roles (Keycloak's role-mappings/realm/composite answer
        F) hold no maker role of iam_policy (dual_control); nothing otherwise

IAM 4.5 (design §14.8: apply.sh <N>, --rollback-to K, --audit N):
  approval-sql --version N [--audit] --out SQL
        the version read of step 3 (one READ ONLY transaction): its row, the SQL entries
        digest, the approved event and its evidence, every other version's approved jti,
        _authors(), its rows, its diff, the skeletons it names, apply_started, audit_versions()
        and the pending account decisions; --audit adds the applied record, the version
        applied before it and verify_chain() (cli.py audit-version's document)
  audit-doc --in F --issuer I --out F    apply.sh --audit's document from that answer
  gate --state S --doc D --gate G --gate-rc RC --mode apply|rollback --version N [--head-has]
        step 2.4: the skeleton gate, and its exception for exactly an approved skeleton
        version's digest (exit 0 go on, 1 refused, 2 deploy first)
  state-check --state S --doc D --version N
        step 3 (exit 1 refused, 2 a bootstrap or rollback version): approved, based on the
        applied version, nothing unfinished, no break-glass, no audit finding, the entries
        digest in SQL, stored, approved and recomputed, no pending account decision (S-E5)
  account-skeleton --state S [--doc D] --out F
        the skeleton whose roles Keycloak's holders are read for (with a skeleton version:
        accepted and proposed includes merged)
  host-file --state S [--check-only]
        step 2.3: state/policy-applied.yaml rewritten as the applied version's when absent
        or different, composed with the accepted skeleton (not HEAD's); --check-only
        composes it and writes nothing
  stage --state S --doc D --out DIR --commit C [--rollback K --next V]
        step 5: the staged host file bound to the rows, the checker, its compile, the
        applied version's file from the state document and its compile, the targets that
        change, the artefact digests (DIR/stage.json, DIR/digests.json)
  diff-check --state S --doc D --stage DIR
        step 6: the recomputed diff is byte for byte the approved one; the summary
  check-approval --doc D --kc DIR --jwks F --stage DIR --issuer I --mode apply|rollback
                 --version N [--state S] [--out F]
        step 4: the JWS (verify_rs256, stdlib), its claims, the approver's eligibility now
        (OA-b, I17), Keycloak's composites, S-B4, someone can still approve (S-E2); one
        REFUSED line each (exit 1), --rollback-to only the last, as WARNINGs
  signing-keys --in JWKS --out F   the realm's RS256 signing keys (infra/jwks-sig.py)
  rollback-check --state S --doc D --jwks F --version K
        §14.8.7 step 3 and the bound (OA-c): K is a rollback target and today's skeleton with
        its rows grants no role more than the skeleton it was approved under
  rollback-diff --state S --stage DIR    the rollback's diff against the applied version
  verify-conf --out F [--drop T]   step 9's conf (nine checks)
  classify-sql [--without-iam]     health-check iamgrants' tail after the verify SQL (Phase 5,
        G4): the assertion set that ran, and under IAM_DB_ROLES=false I15's classification as a
        read-only query (a WARN there); never part of a compiled target or a bundle
  health-results --in LOG --out F  {check: OK|WARN|FAIL|SKIP} from health-check.sh's output
  verify-judge --baseline B --now N [--drop T]
        the checks FAIL now and not in step 6b's baseline (revert-driving)
  verify-host --reference DIR      the written host file compiles to exactly DIR
  deferred-check --command C       the step-9 check a deferred scoped command drops
  deferred-reason --command C      why it deferred (line 1) and when --resume closes it (line 2)
  bundle-sql --kind change|skeleton|rollback --stage DIR --doc D ... | --kind revert --stage DIR
        step 7's PRE and POST, and the revert bundle's (§14.8.6)
"""
import argparse
import base64
import contextlib
import copy
import datetime
import hashlib
import hmac
import io
import json
import os
import pwd
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from compiler import explain, model, source, tools  # noqa: E402

# Host → the command that owns its gate (design §6.7). The scoped modes (--policy-only,
# --gate-only, IAM 4.2b) re-render only what drifted; apply.sh --resume runs them all
# (owners --scoped), each a no-op where nothing drifted.
HOST_OWNER = {
    "PORTAL_DOMAIN": "./deploy-infra.sh --policy-only",
    "NODE_RED_DOMAIN": "./deploy-infra.sh --policy-only",
    "GRAFANA_DOMAIN": "./deploy-infra.sh --policy-only",
    "PGADMIN_DOMAIN": "./deploy-infra.sh --policy-only",
    "WORKBENCH_DOMAIN": "./infra/deploy-workbench.sh --policy-only",
    "CONFIG_DOMAIN": "./apps/frontend/deploy.sh --gate-only",
    "DBMGMT_DOMAIN": "./apps/frontend/deploy.sh --gate-only",
    "SCHEDULER_DOMAIN": "./apps/scheduler/deploy.sh --gate-only",
    "MONITOR_DOMAIN": "./apps/monitor/deploy.sh --gate-only",
    "MQTTX_DOMAIN": "./apps/mqtt-explorer/deploy.sh --gate-only",
    "ACCESS_DOMAIN": "./apps/access/deploy.sh --gate-only",
    "POLICY_DOMAIN": "./apps/iam/deploy.sh --gate-only",
    "ONBOARD_DOMAIN": "./apps/edge-wizard/deploy.sh --gate-only",
    "SUPERSET_DOMAIN": "./apps/superset/deploy.sh --gate-only",   # Superset stage C
}
# The other targets (not a host's gate) and their owners.
TARGET_OWNER = {
    "routes": "./deploy-infra.sh --policy-only", "mqtt": "./deploy-infra.sh --policy-only",
    "netpol": "./deploy-infra.sh --policy-only", "grafana": "./deploy-infra.sh --policy-only",
    "node-red": "./deploy-infra.sh --policy-only", "pgadmin": "./deploy-infra.sh --policy-only",
    "egress-notebooks": "./infra/deploy-workbench.sh --policy-only",
    "jupyterhub-allowed": "./infra/deploy-workbench.sh --policy-only",
    "jupyterhub-admin": "./infra/deploy-workbench.sh --policy-only",
    "edge-wizard": "./apps/edge-wizard/deploy.sh --gate-only",
    "superset": "./apps/superset/deploy.sh --gate-only",
    "grants": "./apps/database/deploy.sh",
}
NETPOL_ARGS = ["--namespace", "medcea", "--node-ip", "192.0.2.1"]   # a fixed placeholder, both sides
ROUTES_UNCOMPARED = ("source", "applied_version")
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
ACTORS = ("system:apply",)


def die(msg, code=2):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        die(f"cannot read {path}: {e}")


def os_user():
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return str(os.getuid())


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ── one YAML parse per file and run (pure-Python PyYAML takes ~0.4 s per read) ─────────
_YAML = {}
_read_yaml = source._read_yaml


def _cached_read_yaml(path, what):
    try:
        st = os.stat(path)
        key = (os.path.realpath(path), st.st_mtime_ns, st.st_size)
    except OSError:
        return _read_yaml(path, what)
    if key not in _YAML:
        _YAML[key] = _read_yaml(path, what)
    text, data = _YAML[key]
    return text, copy.deepcopy(data)


source._read_yaml = _cached_read_yaml


def full_deploys():
    """The full deploys owning every target, deploy-infra first (design §14.4.9 step 8)."""
    cmds = {re.sub(r" --(policy|gate)-only$", "", c) for c in list(HOST_OWNER.values()) + list(TARGET_OWNER.values())}
    first = ["./deploy-infra.sh", "./infra/deploy-workbench.sh", "./apps/database/deploy.sh"]
    return [c for c in first if c in cmds] + sorted(cmds - set(first))


# ── Keycloak accounts and who can approve ─────────────────────────────────────────────
def accounts_from_dir(d, skel=None):
    """[{sub, username, enabled, roles, person_id}] from DIR/<role>.json (the direct holders
    of each platform role), roles expanded by the skeleton's includes."""
    skel = skel or source.skeleton(source.factory())
    roles = skel.get("roles") or {}
    acc = {}
    for role in roles:
        path = os.path.join(d, f"{role}.json")
        if not os.path.exists(path):
            continue
        users = load_json(path)
        if not isinstance(users, list):
            die(f"{path} is not a list of users")
        for u in users:
            full = os.path.join(d, "users", f"{u.get('id')}.json")
            if re.fullmatch(r"[0-9A-Fa-f-]{36}", str(u.get("id"))) and os.path.exists(full):
                u = load_json(full)   # the full representation (a brief one has no person_id)
            a = acc.setdefault(u["id"], {"sub": u["id"], "username": u.get("username"),
                                         "enabled": bool(u.get("enabled")), "roles": set(),
                                         "person_id": ((u.get("attributes") or {}).get("person_id") or [None])[0]})
            a["roles"].add(role)
    for a in acc.values():
        out, todo = set(a["roles"]), list(a["roles"])
        while todo:
            for inc in (roles.get(todo.pop()) or {}).get("includes") or []:
                if inc not in out:
                    out.add(inc)
                    todo.append(inc)
        a["roles"] = sorted(out)
    return sorted(acc.values(), key=lambda a: (a["username"] or "", a["sub"]))


def can_approve(dual, accounts):
    """Problems (strings) with who can approve the two dual-control groups."""
    if "dual_control" in dual:
        dual = dual["dual_control"]
    out = []
    enabled = [a for a in accounts if a.get("enabled")]

    def person(a):
        return (a.get("person_id") or a["sub"]).lower()
    for g in ("iam_policy", "iam_users"):
        d = dual.get(g)
        if d is None:
            continue
        approvers = [a for a in enabled if set(a.get("roles") or ()) & set(d["approver_roles"])]
        makers = [a for a in enabled if set(a.get("roles") or ()) & set(d["maker_roles"])]
        if not approvers:
            out.append(f"no enabled account holds an approver role of {g} ({', '.join(d['approver_roles']) or 'none'})")
        elif not [a for a in approvers if person(a) not in {person(m) for m in makers}]:
            out.append(f"no enabled approver whose person_id is not an enabled maker's ({g}: approvers "
                       f"{', '.join(a['username'] or a['sub'] for a in approvers)})")
        if not makers:
            out.append(f"no enabled account holds a maker role of {g} ({', '.join(d['maker_roles']) or 'none'})")
    return out


def by_user(users, username):
    """(sub, person_id) of the exact, enabled --by account, else SystemExit 2."""
    if isinstance(users, dict):
        users = [users]
    hits = [u for u in users if isinstance(u, dict) and u.get("username", "").lower() == username.lower()]
    if not hits:
        die(f"--by {username}: no such account in Keycloak (the exact username of the person who applies)")
    u = hits[0]
    if not u.get("enabled"):
        die(f"--by {username}: the account is disabled")
    pid = ((u.get("attributes") or {}).get("person_id") or [""])[0]
    if not pid:
        die(f"--by {username}: the account has no person_id (./deploy-infra.sh sets one on every enabled account)")
    if not UUID.fullmatch(u.get("id", "")):
        die(f"--by {username}: Keycloak's id {u.get('id')!r} is not a uuid")
    return u["id"], pid


# ── seed facts (account_seeded, design §14.4.12) ──────────────────────────────────────
def seed_fact(fact, username, sub, role=None, person_id=None, by="deploy-infra.sh", at=None, user=None):
    if fact not in ("created", "person_id_set", "observed"):
        die(f"--fact must be created, person_id_set or observed, not {fact!r}")
    if not username or not sub:
        die("a seed fact names its username and sub")
    f = {"fact": fact, "created": fact == "created", "observed": fact == "observed",
         "person_id_set": fact == "person_id_set", "username": username, "sub": sub,
         "role": role or None, "person_id": person_id or None, "by": by,
         "os_user": user or os_user(), "at": at or now()}
    f["fact_id"] = source.fact_id(f)
    return f


def seed_queue(lines, path=None):
    """Append facts to state/seed-facts.jsonl under the verified lock; returns the count."""
    path = path or source.SEED_FILE
    facts = []
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            f = json.loads(line)
        except ValueError:
            f = None
        if (not isinstance(f, dict) or f.get("fact") not in ("created", "person_id_set", "observed")
                or f.get("fact_id") != source.fact_id(f)):
            raise source.SourceError(f"line {n} is not a seed fact")
        facts.append(f)
    if not facts:
        return 0
    source.verify_lock()
    d = source._state_dir(os.path.dirname(path))
    try:
        st = os.stat(path)
        if st.st_uid != os.getuid():
            raise source.SourceError(f"{path} belongs to uid {st.st_uid}: run as the account that deploys the platform")
    except FileNotFoundError:
        pass
    fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    try:
        os.write(fd, "".join(json.dumps(f, sort_keys=True, ensure_ascii=False) + "\n" for f in facts).encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    dfd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return len(facts)


def queued_count(path):
    try:
        with open(path, encoding="utf-8") as f:
            return sum(1 for l in f if l.strip())
    except FileNotFoundError:
        return 0
    except OSError:
        return -1


# ── the bootstrap: the simulated state, the bundle SQL ────────────────────────────────
def _pg_round_trip(row):
    """A row as psql's json_build_object returns it (dates as YYYY-MM-DD strings)."""
    return json.loads(json.dumps(row, default=str))


def simulate_state(data=None, commit=None):
    """The state document of version 1 once committed (design §14.4.10), from the git tree."""
    data = data or source.factory()
    skel = source.skeleton(data)
    ew = source.entries_and_waivers(data)
    entries = sorted(({"role": e["role"], "group_code": e["group_code"], "level": e["level"],
                       "constraint_name": e["constraint_name"]} for e in ew["entries"]),
                     key=lambda e: (source._bytes(e["role"]), source._bytes(e["group_code"]), source._bytes(e["level"])))
    waivers = sorted((source.waiver_row(w) for w in ew["waivers"]), key=lambda w: source._bytes(w["id"]))
    groups = sorted(skel.get("resource_groups") or {}, key=source._bytes)
    roles = sorted(skel.get("roles") or {}, key=source._bytes)
    return {"state": "version-1", "version": 1, "kind": "bootstrap", "status": "applied",
            "entries_digest": source.policy_entries_digest(data, "bootstrap"),
            "groups": groups, "roles": roles, "based_on": None, "confirmed_at": None, "disputed_at": None,
            "claimed_by_person": None,
            "accepted": {"digest": source.skeleton_digest(skel), "body": json.loads(source.canonical(skel)),
                         "git_commit": commit or "unknown"},
            "entries": [_pg_round_trip(e) for e in entries], "waivers": [_pg_round_trip(w) for w in waivers],
            "last_apply_event": None, "break_glass_open": [],
            "system_functions": {"system_as": True, "record": True}}


def _b64(obj):
    return source._b64(obj)


def _set(name, value):
    if not re.fullmatch(r"[a-z_][a-z0-9_]*", name):
        raise ValueError(name)
    return f"\\set {name} '{_b64(value)}'"


def bundle_sql(state, by_sub, by_person, log, commit=None, digests=None, data=None):
    """(pre, post) of the bootstrap bundle (design §14.4.9 step 7)."""
    data = data or source.factory()
    skel = source.skeleton(data)
    digest = source.skeleton_digest(skel)
    want = source.policy_entries_digest(data, "bootstrap")
    acc = (state.get("accepted") or {}) if isinstance(state, dict) else {}
    if acc.get("digest") != digest:
        die("the state document's skeleton is not the git tree's: run simulate-state again")
    if state.get("entries_digest") != want:
        die("the state document's entries digest is not defaults.yaml's: run simulate-state again")
    if not UUID.fullmatch(by_sub or ""):
        die(f"--by-sub {by_sub!r} is not a uuid")
    if not (by_person or "").strip():
        die("--by-person is empty")
    commit = commit or source.git_commit()
    ew = source.entries_and_waivers(data)
    entries = [{"role": e["role"], "group_code": e["group_code"], "level": e["level"],
                "constraint_name": e["constraint_name"]} for e in ew["entries"]]
    waivers = [source.waiver_row(w) for w in ew["waivers"]]
    summary = {"narrowed": [], "unchanged": [], "reviewed_by_version": None}
    digests = digests if digests is not None else {}
    digests = dict(digests, git_commit=commit, compiler_digest=source.compiler_digest(), skeleton_digest=digest)
    J, T = source._jsonb, source._text
    pre = "\n".join([
        "-- apps/iam/apply.sh --bootstrap: PRE (apply_check.py bundle-sql; design §14.4.9 step 7)",
        f"\\set skel_digest '{digest}'",
        _set("skel_body", source.canonical(skel).decode("utf-8")),
        _set("skel_commit", commit),
        _set("skel_compiler", source.compiler_digest()),
        _set("skel_summary", summary),
        _set("v1_entries", entries),
        _set("v1_waivers", waivers),
        _set("v1_reason", f"version 1: the factory policy (defaults.yaml) at {commit}"),
        f"\\set v1_want '{want}'",
        f"SELECT iam_policy._accept_skeleton(:'skel_digest', {J('skel_body')}, {T('skel_commit')}, "
        f"{T('skel_compiler')}, {J('skel_summary')}) \\g /dev/null",
        f"SELECT iam_policy._sync_skeleton({J('skel_body')}, {T('skel_commit')}) \\g /dev/null",
        f"SELECT iam_policy._build_version('bootstrap', {J('v1_entries')}, {J('v1_waivers')}, NULL, NULL, "
        f"{T('v1_reason')}) AS v \\gset",
        "SELECT pg_catalog.set_config('medcea.bootstrap_version', :'v', true),",
        "       pg_catalog.set_config('medcea.bootstrap_want', :'v1_want', true) \\g /dev/null",
        "DO $boot$",
        "BEGIN",
        "    IF iam_policy.entries_digest(pg_catalog.current_setting('medcea.bootstrap_version')::integer)",
        "       IS DISTINCT FROM pg_catalog.current_setting('medcea.bootstrap_want') THEN",
        "        RAISE EXCEPTION 'version % does not store the entries of defaults.yaml (entries digest %, want %)',",
        "            pg_catalog.current_setting('medcea.bootstrap_version'),",
        "            iam_policy.entries_digest(pg_catalog.current_setting('medcea.bootstrap_version')::integer),",
        "            pg_catalog.current_setting('medcea.bootstrap_want');",
        "    END IF;",
        "END $boot$;",
        ""])
    post = "\n".join([
        "-- apps/iam/apply.sh --bootstrap: POST (apply_check.py bundle-sql); :v is PRE's \\gset",
        _set("v1_digests", digests),
        _set("v1_os_user", os_user()),
        f"\\set v1_by_sub '{by_sub.lower()}'",
        _set("v1_by_person", by_person),
        _set("v1_log", log or ""),
        f"SELECT iam_policy._mark_applied(:v, {J('v1_digests')}, {T('v1_os_user')}, :'v1_by_sub'::uuid, "
        f"{T('v1_by_person')}, NULLIF({T('v1_log')}, '')) \\g /dev/null",
        ""])
    return pre, post


def record_sql(event, payload, actor="system:apply"):
    if event not in ("bootstrap_applied", "applied", "apply_deferred", "partial_apply"):
        die(f"apply-record records bootstrap_applied, applied, apply_deferred or partial_apply, not {event!r}")
    if actor not in ACTORS:
        die(f"bad actor {actor!r}")
    return "\n".join([
        _set("payload", payload),
        f"SELECT medcea_auth._set_internal_actor('{actor}') \\g /dev/null",
        f"SELECT iam_policy._record('{event}', {source._jsonb('payload')});",
        ""])


def apply_payload(state, by_sub, by_person, log, commit, chain_head, digests, resumed=False, extra=None):
    """The step-10 record (design §2.5). extra (IAM 4.5, §14.8.6 step 10): the fields of a
    change, skeleton or rollback apply (rollback_of, approved_by, changed, deferred, jwk,
    attempts, pre_failing, apply_log_sha256, reason, reverted_from, outcome …), last."""
    p = _apply_payload(state, by_sub, by_person, log, commit, chain_head, digests, resumed)
    p.update(extra or {})
    return p


def log_sha256(log):
    """(sha256, "copy at record") of a copy of the live log taken now (tee keeps writing the
    live one, §14.4.21 sec-13c); (None, None) without a log."""
    if not log or not os.path.isfile(log):
        return None, None
    with open(log, "rb") as f:
        data = f.read()
    return hashlib.sha256(data).hexdigest(), "copy at record"


def _apply_payload(state, by_sub, by_person, log, commit, chain_head, digests, resumed=False):
    hid, _, hhash = (chain_head or "").partition(":")
    return {"version": int(state["version"]), "kind": state["kind"], "os_user": os_user(),
            "claimed_by_sub": by_sub.lower(), "claimed_by_person": by_person, "git_commit": commit,
            "skeleton_digest": (state.get("accepted") or {}).get("digest"),
            "compiler_digest": source.compiler_digest(), "based_on": state.get("based_on"), "rollback_of": None,
            "artefacts": digests or {}, "changed": [], "deferred": [], "apply_log": log or None,
            "chain_head_before": {"id": int(hid) if hid.isdigit() else None, "hash": hhash or None},
            "reason": (f"version {state['version']} ({state['kind']}): its apply finished by --resume" if resumed
                       else f"version {state['version']}: the factory policy, bootstrapped"),
            **({"resumed": True} if resumed else {})}


def deferred_payload(state, target, reason, command):
    """apply_deferred (IAM 4.2b): a target apply.sh --resume could not re-render now; open
    until the version's next applied/bootstrap_applied (a later --resume)."""
    return {"version": int(state["version"]), "target": target, "reason": reason, "command": command,
            "os_user": os_user()}


def scoped_commands():
    """Every scoped mode, once, in the order apply.sh --resume runs them: deploy-infra's,
    the workbench's, then the apps' (alphabetical). grants has none (the bundle applies it)."""
    seen, out = set(), []
    cmds = list(TARGET_OWNER.values()) + list(HOST_OWNER.values())
    rank = lambda c: (0 if c.startswith("./deploy-infra") else 1 if c.startswith("./infra/") else 2, c)
    for c in sorted(cmds, key=rank):
        if (c.endswith("--policy-only") or c.endswith("--gate-only")) and c not in seen:
            seen.add(c)
            out.append(c)
    return out


# ── a skeleton proposal and the host withdraw (IAM 4.4, design §14.7.6) ───────────────
ATTEST_ROLES_GROUP = "iam_policy"
OPEN_KINDS = ("change", "skeleton")
_ISOLATION_SQL = "\n".join([
    "DO $iso$",
    "BEGIN",
    "    IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN",
    "        RAISE EXCEPTION 'apply.sh needs READ COMMITTED (is %)', pg_catalog.current_setting('transaction_isolation');",
    "    END IF;",
    "END $iso$;"])


def open_version(state):
    """The open change or skeleton version of a --full state document, or None (one in flight)."""
    opens = [o for o in state.get("open_versions") or [] if o.get("kind") in OPEN_KINDS]
    return opens[0] if opens else None


def git_policy(rev):
    """apps/iam/policy/defaults.yaml at a git revision (validated as cli.py skeleton-gate
    --against-git does); SourceError when it cannot be read."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/~^-]*", rev or ""):
        raise source.SourceError(f"bad revision {rev!r}")
    r = subprocess.run(["git", "-C", source.REPO_ROOT, "show", f"{rev}:apps/iam/policy/defaults.yaml"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise source.SourceError(f"git show {rev}: {r.stderr.strip()}")
    data = source.yaml.safe_load(r.stdout)
    if not isinstance(data, dict):
        raise source.SourceError(f"{rev}:apps/iam/policy/defaults.yaml is not a policy")
    return data


def _composed(acc_body, git, ew):
    """(p_old, p_new, acc_skel, git_skel) composed exactly as explain.gate composes them: the
    accepted body (jsonb, keys sorted) takes the git level order, rows naming a key a
    skeleton lacks dropped."""
    acc_skel, git_skel = copy.deepcopy(source.skeleton(acc_body)), source.skeleton(git)
    if isinstance(acc_skel.get("levels"), dict) and isinstance(git_skel.get("levels"), dict):
        order = [l for l in git_skel["levels"] if l in acc_skel["levels"]]
        order += sorted(l for l in acc_skel["levels"] if l not in order)
        acc_skel["levels"] = {l: acc_skel["levels"][l] for l in order}
    return (model.Policy(source.compose(acc_skel, ew, drop_unknown=True)),
            model.Policy(source.compose(git_skel, ew, drop_unknown=True)), acc_skel, git_skel)


def closure(roles, role):
    """role and every role it includes (Keycloak composites), from a skeleton's roles."""
    out, todo = {role}, [role]
    while todo:
        for inc in (roles.get(todo.pop()) or {}).get("includes") or []:
            if inc not in out:
                out.add(inc)
                todo.append(inc)
    return out


def barred_approvers(roles, added):
    """The roles whose holders may not approve a skeleton version (byte order): the role, or
    one it includes, gains reach (`added` = explain.gate's, `_system` and other `_` keys
    left out). --propose-skeleton prints them; the approval rule refuses them."""
    widened = {r for r in added if not r.startswith("_")}
    return sorted((r for r in roles if closure(roles, r) & widened), key=source._bytes)


def propose(state, git, by_sub, by_person, reason, commit, version):
    """apply.sh --propose-skeleton's step 4 (design §14.7.6): (rc, lines, sql). rc 1 refuses
    (lines say why), 0 builds the diff document of skeleton version `version` and the one
    psql transaction that submits it (sql)."""
    acc = source._need_version(state)
    rows = source.state_rows(state)
    git_digest = source.skeleton_digest(git)
    if git_digest == acc["digest"]:
        return 1, ["nothing to approve: this skeleton is the accepted one"], None
    try:
        g = explain.gate(acc["body"], git, rows)
    except Exception as e:   # a compile error
        return 1, [f"the skeleton gate could not be computed: {type(e).__name__}: {e}"], None
    if g["verdict"] != "widening":
        return 1, ["nothing to approve: it adds no access; deploy as usual, the deploy accepts it"], None
    errors = explain.checker_errors(git, rows)
    if errors:
        return 1, ["the proposed skeleton fails the checker with the applied matrix:"] + [f"  FAIL: {e}" for e in errors], None
    o = open_version(state)
    if o:
        return 1, [f"version {o.get('version')} ({o.get('kind')}, {o.get('status')}) is still open: take it through or "
                   "withdraw it first (the Policy UI, or ./apps/iam/apply.sh --withdraw-open)"], None
    if not UUID.fullmatch(by_sub or ""):
        die(f"--by-sub {by_sub!r} is not a uuid")
    if not (by_person or "").strip() or not (reason or "").strip():
        die("a skeleton proposal needs the proposer's person and a reason")
    body = source.skeleton(git)
    p_old, p_new, acc_skel, git_skel = _composed(acc["body"], git, rows)
    groups, roles = sorted(body.get("resource_groups") or {}, key=source._bytes), sorted(body.get("roles") or {}, key=source._bytes)
    entries_digest = source.entries_digest("skeleton", groups, roles, rows["entries"], rows["waivers"])
    skel = {"from": acc["digest"], "to": git_digest, "sections": explain.sections(acc_skel, git_skel)}
    doc = explain.diff_document("skeleton", int(version), int(state["version"]), entries_digest, p_old, p_new, skeleton=skel)
    diff_bytes, diff_digest = explain.diff_bytes(doc), explain.diff_digest(doc)   # source.canonical (§14.7.3)
    barred = barred_approvers(body.get("roles") or {}, g["added"])
    lines = [f"skeleton version {version}: skeleton {git_digest[:12]} (commit {commit}) over the accepted "
             f"{acc['digest'][:12]}, with the entries of applied version {state['version']}; it adds:"]
    lines += [l for l in explain.gate_message(g).splitlines() if l.startswith("  ")]
    lines += [f"diff digest {diff_digest}", f"entries digest {entries_digest}",
              "no one holding these roles may approve it (they, or a role they include, gain access): "
              + (", ".join(barred) or "none")]
    T, J = source._text, source._jsonb
    sql = "\n".join([
        "-- apps/iam/apply.sh --propose-skeleton (apply_check.py propose; design §14.7.6)",
        f"\\set digest '{git_digest}'",
        _set("body", source.canonical(body).decode("utf-8")),
        _set("commit", commit),
        _set("diff", diff_bytes.decode("utf-8")),
        f"\\set diff_digest '{diff_digest}'",
        f"\\set by_sub '{by_sub.lower()}'",
        _set("by_person", by_person),
        _set("reason", reason),
        f"\\set want_version '{int(version)}'",
        f"\\set want_entries '{entries_digest}'",
        "SELECT medcea_auth._set_internal_actor('system:apply') \\g /dev/null",
        _ISOLATION_SQL,
        "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('iam_policy.version')) \\g /dev/null",
        "SELECT pg_catalog.set_config('medcea.propose_want', :'want_version', true),",
        "       pg_catalog.set_config('medcea.propose_entries', :'want_entries', true) \\g /dev/null",
        "DO $next$",
        "BEGIN",
        "    IF (SELECT coalesce(max(x.version), 0) + 1 FROM iam_policy.version x)",
        "       <> pg_catalog.current_setting('medcea.propose_want')::integer THEN",
        "        RAISE EXCEPTION 'another version was created meanwhile (the diff names version %): run apply.sh again',",
        "            pg_catalog.current_setting('medcea.propose_want');",
        "    END IF;",
        "END $next$;",
        f"SELECT iam_policy._propose_skeleton(:'digest', {J('body')}, {T('commit')}, {J('diff')}, :'diff_digest', "
        f":'by_sub'::uuid, {T('by_person')}, {T('reason')}) AS v \\gset",
        "SELECT pg_catalog.set_config('medcea.propose_version', :'v', true) \\g /dev/null",
        "DO $chk$",
        "BEGIN",
        "    IF pg_catalog.current_setting('medcea.propose_version') <> pg_catalog.current_setting('medcea.propose_want') THEN",
        "        RAISE EXCEPTION 'another version was created meanwhile (got %, the diff names %): run apply.sh again',",
        "            pg_catalog.current_setting('medcea.propose_version'), pg_catalog.current_setting('medcea.propose_want');",
        "    END IF;",
        "    IF iam_policy.entries_digest(pg_catalog.current_setting('medcea.propose_version')::integer)",
        "       IS DISTINCT FROM pg_catalog.current_setting('medcea.propose_entries') THEN",
        "        RAISE EXCEPTION 'version % does not store the entries the diff names (entries digest %, want %)',",
        "            pg_catalog.current_setting('medcea.propose_version'),",
        "            iam_policy.entries_digest(pg_catalog.current_setting('medcea.propose_version')::integer),",
        "            pg_catalog.current_setting('medcea.propose_entries');",
        "    END IF;",
        "END $chk$;",
        "SELECT :v;",
        ""])
    return 0, lines, sql


def withdraw_sql(version, reason):
    """apply.sh --withdraw-open's one transaction: _withdraw_open as system:apply, then the
    number it withdrew asserted against the one shown (else rolled back); prints it."""
    if not (reason or "").strip():
        die("a reason is required")
    return "\n".join([
        "-- apps/iam/apply.sh --withdraw-open (apply_check.py withdraw-sql; design §14.7.6)",
        _set("reason", reason),
        f"\\set want_version '{int(version)}'",
        "SELECT medcea_auth._set_internal_actor('system:apply') \\g /dev/null",
        _ISOLATION_SQL,
        "SELECT pg_catalog.set_config('medcea.withdraw_want', :'want_version', true) \\g /dev/null",
        f"SELECT pg_catalog.set_config('medcea.withdraw_got', coalesce(iam_policy._withdraw_open({source._text('reason')})::text, ''), true) \\g /dev/null",
        "DO $chk$",
        "BEGIN",
        "    IF pg_catalog.current_setting('medcea.withdraw_got') <> pg_catalog.current_setting('medcea.withdraw_want') THEN",
        "        RAISE EXCEPTION 'another version was opened meanwhile (withdrawn: %, shown: %): nothing was withdrawn',",
        "            nullif(pg_catalog.current_setting('medcea.withdraw_got'), ''), pg_catalog.current_setting('medcea.withdraw_want');",
        "    END IF;",
        "END $chk$;",
        "SELECT pg_catalog.current_setting('medcea.withdraw_got');",
        ""])


def maker_warning(dual, role_names, username, group=ATTEST_ROLES_GROUP):
    """A warning (or None) when --by holds no maker role of `group` (dual_control, §1.3)."""
    if "dual_control" in dual:
        dual = dual["dual_control"]
    makers = (dual.get(group) or {}).get("maker_roles") or []
    if set(role_names) & set(makers):
        return None
    return (f"--by {username} holds no maker role of {group} ({', '.join(makers) or 'none'}): the proposal is "
            "recorded with that claim all the same")


# ── IAM 4.5: applying an approved version (design §14.8) ──────────────────────────────
LEEWAY = 30                   # seconds of clock skew, medcea_iam.LEEWAY (apps/iam/lib/medcea_iam.py)
AUDIENCE = "medcea-api"
APPROVE_RPC = "approve_policy"
# DigestInfo of SHA-256 (RFC 8017 §9.2): the fixed prefix of an RS256 signature's encoding
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
# Step 9 (design §14.8.6): the checks of what a version changes, through health-check.sh -c
VERIFY_CHECKS = (("iamgrants", "$POSTGRES_DB"), ("iamenforce", "$NAMESPACE"), ("grafanarole", "$NAMESPACE"),
                 ("iamworkbench", "$NAMESPACE"), ("onboardroles", ""), ("pgadminroles", "$NAMESPACE"),
                 ("noderedauth", "$NAMESPACE"), ("iamartefacts", "$NAMESPACE"), ("supersetroles", "$NAMESPACE"))
# A scoped command's exit 4 (deferred) drops the check that would FAIL on the old setting
DEFER_CHECK = {"./apps/edge-wizard/deploy.sh --gate-only": "onboardroles",
               "./apps/superset/deploy.sh --gate-only": "supersetroles"}
# ... and why it deferred (apply_deferred's reason), and when --resume can close it
DEFER_REASON = {"./apps/edge-wizard/deploy.sh --gate-only":
                ("an onboarding run is in progress", "once the onboarding run has finished"),
                "./apps/superset/deploy.sh --gate-only":
                ("Superset's wheel cache is incomplete", "once ./apps/superset/deploy.sh has filled the wheel cache")}
RESULT = re.compile(r"\[\s*(OK|WARN|FAIL|SKIP)\s*\]\s+step9:([a-z]+)")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


class JwsError(Exception):
    """The stored approval token does not verify (a refusal)."""


class UnknownKid(JwsError):
    """The realm no longer publishes the key that signed the approval."""

    def __init__(self, kid):
        super().__init__(kid)
        self.kid = kid


def _b64url(seg):
    if not isinstance(seg, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", seg):
        raise JwsError("the approval's token is not base64url")
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def verify_rs256(jws, jwks):
    """(header, payload, jwk) of a compact JWS that carries a valid RS256 signature by one of
    `jwks`' keys ({keys: [...]} or a list); JwsError (UnknownKid) otherwise. Stdlib only
    (design §14.8.5): the stored token split as stored, never re-encoded; the signature as a
    k-byte integer below n; m = s^e mod n compared as whole bytes with the expected PKCS#1
    v1.5 encoding (00 01 FF..FF 00 DigestInfo sha256), never parsed."""
    parts = jws.split(".") if isinstance(jws, str) else []
    if len(parts) != 3:
        raise JwsError("the approval's token is not a compact JWS")
    try:
        header = json.loads(_b64url(parts[0]))
        payload = json.loads(_b64url(parts[1]))
    except (ValueError, UnicodeDecodeError):
        raise JwsError("the approval's token does not decode") from None
    if not isinstance(header, dict) or header.get("alg") != "RS256":
        raise JwsError("the approval's token is not RS256")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise JwsError("the approval's token names no key (kid)")
    keys = jwks.get("keys") if isinstance(jwks, dict) else jwks
    jwk = next((k for k in keys or [] if isinstance(k, dict) and k.get("kid") == kid), None)
    if jwk is None:
        raise UnknownKid(kid)
    n, e = int.from_bytes(_b64url(jwk.get("n")), "big"), int.from_bytes(_b64url(jwk.get("e")), "big")
    k = (n.bit_length() + 7) // 8
    if k < len(SHA256_DIGEST_INFO) + 32 + 11 or e < 3:
        raise JwsError(f"the realm key {kid} is not an RSA signing key")
    sig = _b64url(parts[2])
    s = int.from_bytes(sig, "big")
    if len(sig) != k or s >= n:
        raise JwsError("the approval's signature is malformed (its length, or not below the modulus)")
    digest = hashlib.sha256((parts[0] + "." + parts[1]).encode("ascii")).digest()
    want = b"\x00\x01" + b"\xff" * (k - 3 - len(SHA256_DIGEST_INFO) - 32) + b"\x00" + SHA256_DIGEST_INFO + digest
    if not hmac.compare_digest(pow(s, e, n).to_bytes(k, "big"), want):
        raise JwsError(f"the approval's signature does not verify against the realm key {kid}")
    if not isinstance(payload, dict):
        raise JwsError("the approval's token carries no claims object")
    return header, payload, {"kid": kid, "n": jwk["n"], "e": jwk["e"]}


def signing_keys(jwks):
    """The realm's RS256 signing keys: infra/jwks-sig.py's signing_keys() (the filter
    deploy-infra applies to Secret medcea-jwks), loaded by path (its name has a hyphen)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("jwks_sig", os.path.join(source.REPO_ROOT, "infra", "jwks-sig.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return {"keys": mod.signing_keys(jwks)}


# ── the version read (step 3) and apply.sh --audit's document ─────────────────────────
def approval_doc_sql(version, audit=False):
    """One READ ONLY transaction (as postgres, through apply.sh's q) printing the JSON
    document of version `version` (design §14.8.4 step 3): its row, the SQL entries digest,
    the latest approved event, its approval_evidence row, every other version's approved
    jti, _authors(), its rows, its version_diff, the skeletons it names, its latest
    apply_started, the applied version, audit_versions() and the pending account
    decisions (null without iam.account_decision). audit adds what cli.py audit-version
    reads (§14.8.10): the applied record, the version applied before it, the chain."""
    v = int(version)
    rows = lambda x: (  # noqa: E731 — the rows of a version, as policy_db_state reads them
        f"'entries', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('role', e.role, "
        f"'group_code', e.group_code, 'level', e.level::text, 'constraint_name', e.constraint_name) "
        f"ORDER BY e.role COLLATE \"C\", e.group_code COLLATE \"C\", e.level::text COLLATE \"C\") "
        f"FROM iam_policy.entry e WHERE e.version = {x}), '[]'),\n"
        f"  'waivers', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(w) - 'version' ORDER BY w.id COLLATE \"C\") "
        f"FROM iam_policy.waiver w WHERE w.version = {x}), '[]')")
    started = lambda x: (  # noqa: E731
        f"(SELECT h.payload FROM iam_policy.history h WHERE h.version = {x} AND h.event = 'apply_started' "
        f"ORDER BY h.event_id DESC LIMIT 1)")
    audit_sql = ""
    if audit:
        prev = f"(SELECT (h.payload ->> 'previous')::int FROM iam_policy.history h WHERE h.version = {v} " \
               f"AND h.event = 'apply_started' AND h.payload ->> 'previous' ~ '^[0-9]+$' ORDER BY h.event_id DESC LIMIT 1)"
        audit_sql = f""",
  'applied', (SELECT pg_catalog.jsonb_build_object('event', h.event, 'event_id', h.event_id, 'payload', h.payload)
                FROM iam_policy.history h WHERE h.version = {v} AND h.event IN ('applied', 'bootstrap_applied')
                 AND NOT (h.payload ? 'reverted_from') ORDER BY h.event_id DESC LIMIT 1),
  'previous', (SELECT pg_catalog.jsonb_build_object('version', p.version, 'kind', p.kind,
                {rows('p.version')},
                'apply_started', {started('p.version')})
                 FROM iam_policy.version p WHERE p.version = {prev}),
  'chain', (SELECT pg_catalog.jsonb_build_object('ok', vc.ok) FROM iam_policy.verify_chain() vc)"""
    return f"""BEGIN TRANSACTION READ ONLY;
-- apply_check.py approval-doc (design §14.8.4 step 3; --audit: §14.8.10)
SELECT pg_catalog.to_regclass('iam.account_decision') IS NOT NULL AS has_decisions \\gset
\\if :has_decisions
SELECT coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('decision_id', d.decision_id, 'kind', d.kind,
        'username', d.username, 'made_at', d.made_at) ORDER BY d.decision_id)
        FROM iam.account_decision d WHERE d.status = 'pending_qa'), '[]')::text AS pending \\gset
\\else
SELECT 'null' AS pending \\gset
\\endif
SELECT (pg_catalog.jsonb_build_object(
  'version', (SELECT pg_catalog.to_jsonb(x) - 'apply_log' FROM iam_policy.version x WHERE x.version = {v}),
  'entries_digest_sql', iam_policy.entries_digest({v}),
  'applied_version', (SELECT x.version FROM iam_policy.version x WHERE x.status = 'applied'),
  'approval', (SELECT pg_catalog.jsonb_build_object(
        'event', pg_catalog.jsonb_build_object('event_id', h.event_id, 'payload', h.payload, 'actor_name', h.actor_name),
        'evidence', (SELECT pg_catalog.jsonb_build_object('jws', e.jws, 'claims', e.claims) FROM iam_policy.approval_evidence e
                      WHERE e.version = {v} AND e.history_id = h.event_id AND e.event = 'approved'),
        'other_approved', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('version', o.version,
                                    'jti', o.claims ->> 'jti') ORDER BY o.version)
                                    FROM iam_policy.approval_evidence o WHERE o.event = 'approved' AND o.version <> {v}), '[]'),
        'other_approved_jti', coalesce((SELECT pg_catalog.jsonb_agg(o.claims ->> 'jti' ORDER BY o.version)
                                    FROM iam_policy.approval_evidence o WHERE o.event = 'approved' AND o.version <> {v}), '[]'))
        FROM iam_policy.history h WHERE h.version = {v} AND h.event = 'approved' ORDER BY h.event_id DESC LIMIT 1),
  'authors', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('sub', a.sub, 'person', a.person))
                         FROM iam_policy._authors({v}) a), '[]'),
  {rows(v)},
  'diff', (SELECT pg_catalog.jsonb_build_object('diff', x.diff::text, 'diff_digest', x.diff_digest)
             FROM iam_policy.version_diff x WHERE x.version = {v}),
  'skeletons', coalesce((SELECT pg_catalog.jsonb_object_agg(s.digest, pg_catalog.jsonb_build_object('body', s.body,
                   'git_commit', s.git_commit)) FROM iam_policy.skeleton s
                  WHERE s.digest IN (SELECT x.skeleton_digest FROM iam_policy.version x WHERE x.version = {v}
                                     UNION SELECT x.approved_skeleton_digest FROM iam_policy.version x WHERE x.version = {v}
                                     UNION SELECT {started(v)} ->> 'skeleton_digest')), '{{}}'),
  'apply_started', {started(v)},
  'audit_findings', coalesce((SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(a)) FROM iam_policy.audit_versions() a
                               WHERE a.version = {v} OR a.version = (SELECT x.version FROM iam_policy.version x
                                                                       WHERE x.status = 'applied')), '[]'),
  'pending', :'pending'::jsonb{audit_sql}
))::text;
COMMIT;
"""


def load_doc(path):
    """apply.sh's approval document (psql's output: the last line is the JSON object)."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = [l for l in f.read().splitlines() if l.strip()]
        d = json.loads(lines[-1])
        if not isinstance(d, dict):
            raise ValueError("not an object")
        return d
    except (OSError, ValueError, IndexError) as e:
        die(f"cannot read the version document {path}: {e}")


def _claims_of(x):
    return json.loads(x) if isinstance(x, str) else x


def claims_recorded(token_claims, stored):
    """source.claims_recorded on the stored value as read (jsonb text or an object)."""
    return source.claims_recorded(token_claims, _claims_of(stored))


# ── step 2.4: the skeleton gate and its exception for an approved skeleton version ──────
def gate_decision(state, doc, gate, gate_rc, mode, version, head_has=None):
    """(rc, lines): the gate of design §14.8.4 step 2.4 (`<N>`) or §14.8.7 step 2
    (--rollback-to). rc 0 go on, 1 refused, 2 a precondition; lines start ERROR/WARNING."""
    verdict = (gate or {}).get("verdict")
    v = doc.get("version") or {}
    if gate_rc == 0 and verdict == "equal":
        if mode == "apply" and v.get("kind") == "skeleton":
            return 1, [f"ERROR: version {version} proposes skeleton {str(v.get('skeleton_digest'))[:12]}; HEAD carries "
                       f"the accepted one: check out the proposal's commit "
                       f"{((doc.get('skeletons') or {}).get(v.get('skeleton_digest')) or {}).get('git_commit') or '?'} "
                       "(or a merge of it), then re-run"]
        return 0, []
    if gate_rc == 0 and verdict == "narrowing":
        if mode == "rollback":
            return 2, ["ERROR: the git skeleton narrows over the accepted one: deploy first (./apps/iam/deploy.sh accepts "
                       "it), then roll back"]
        return 2, ["ERROR: the git skeleton narrows over the accepted one: a deploy accepts it first (./apps/iam/deploy.sh), "
                   f"then re-run apply.sh {version}; step 6 compares the diff on the new skeleton"]
    if gate_rc != 3 or mode == "rollback":
        return 1, ["ERROR: the skeleton gate refuses the git skeleton (above): nothing was changed"
                   + ("; a rollback never widens the skeleton" if gate_rc == 3 else "")]
    # rc 3, a widening: only exactly the approved skeleton version's digest goes on (§4 step 5)
    acc = state.get("accepted") or {}
    git = source.factory()
    git_digest = source.skeleton_digest(git)
    why = None
    body = ((doc.get("skeletons") or {}).get(v.get("skeleton_digest")) or {}).get("body")
    diff = (doc.get("diff") or {}).get("diff")
    try:
        frm = (json.loads(diff).get("skeleton") or {}).get("from") if isinstance(diff, str) else None
    except ValueError:
        frm = None
    if not v or v.get("kind") != "skeleton":
        why = f"version {version} is not a skeleton version"
    elif v.get("status") != "approved":
        why = f"skeleton version {version} is {v.get('status')}, not approved"
    elif v.get("based_on") != state.get("version"):
        why = f"skeleton version {version} was approved on version {v.get('based_on')}, version {state.get('version')} is applied"
    elif git_digest != v.get("skeleton_digest"):
        why = f"HEAD's skeleton {git_digest[:12]} is not the one version {version} proposes ({str(v.get('skeleton_digest'))[:12]})"
    elif not isinstance(body, dict) or source.canonical(source.skeleton(git)) != source.canonical(body):
        why = f"HEAD's skeleton is not the body stored for version {version}"
    elif frm != acc.get("digest"):
        return 1, [f"ERROR: version {version} was proposed against {str(frm)[:12]}, the accepted one is now "
                   f"{str(acc.get('digest'))[:12]}: withdraw it and propose again"]
    if why:
        return 1, [f"ERROR: the git skeleton widens over the accepted one (above), and {why}: nothing was changed"]
    lines = [f"the git skeleton widens: admitted as skeleton version {version} (approved, digest {git_digest[:12]})"]
    commit = ((doc.get("skeletons") or {}).get(v.get("skeleton_digest")) or {}).get("git_commit")
    if head_has is False:
        lines.append(f"WARNING: the proposal's commit {commit} is not an ancestor of HEAD: the digest is the binding, "
                     "not the commit; keep the change on the deployed branch")
    return 0, lines


# ── step 3: the state ──────────────────────────────────────────────────────────────────
def state_problems(state, doc, version):
    """(rc, lines) of design §14.8.4 step 3 for `<N>` (the chain is apply.sh's check_chain)."""
    out, rc = [], 0
    v = doc.get("version")
    a = state.get("version")
    if not isinstance(v, dict):
        return 1, [f"ERROR: no policy version {version}"]
    if v.get("kind") in ("bootstrap", "rollback"):
        return 2, [f"ERROR: version {version} is a {v['kind']} version: apply.sh applies change and skeleton versions; "
                   "see --rollback-to"]
    if v.get("status") != "approved":
        return 1, [f"ERROR: version {version} is {v.get('status')}: nothing to apply"]
    if v.get("based_on") != a:
        out.append(f"ERROR: version {version} was approved on version {v.get('based_on')}, but version {a} is applied: "
                   "withdraw it and draft again")
    last = (state.get("last_apply_event") or {}).get("event")
    if last in ("apply_started", "partial_apply"):
        out.append(f"ERROR: finish version {a} first ({last}): ./apps/iam/apply.sh --resume --by <you>")
    for b in state.get("break_glass_open") or []:
        out.append(f"ERROR: a policy break-glass is open (event {b.get('event_id')}) for {', '.join(b.get('open') or [])}: "
                   "deploy them again without MEDCEA_POLICY_FILE")
    for f in doc.get("audit_findings") or []:
        if f.get("version") in (int(version), a):
            out.append(f"ERROR: audit_versions(): version {f.get('version')} {f.get('finding')}")
    ev = ((doc.get("approval") or {}).get("event") or {}).get("payload") or {}
    rows = source.state_rows(doc)
    py = source.entries_digest(v.get("kind"), v.get("groups"), v.get("roles"), rows["entries"], rows["waivers"])
    if not (doc.get("entries_digest_sql") == v.get("entries_digest") == ev.get("entries_digest") == py):
        out.append(f"ERROR: version {version}'s entries digest does not hold (SQL {str(doc.get('entries_digest_sql'))[:12]}, "
                   f"stored {str(v.get('entries_digest'))[:12]}, approved {str(ev.get('entries_digest'))[:12]}, "
                   f"recomputed {py[:12]}): nothing was changed")
    out += pending_problems(doc, refuse=True)
    acc = state.get("accepted") or {}
    body = acc.get("body") or {}
    if v.get("kind") == "skeleton":
        body = ((doc.get("skeletons") or {}).get(v.get("skeleton_digest")) or {}).get("body") or {}
    keys = (sorted(body.get("resource_groups") or {}, key=source._bytes), sorted(body.get("roles") or {}, key=source._bytes))
    for what, mine, theirs in (("groups", v.get("groups") or [], keys[0]), ("roles", v.get("roles") or [], keys[1])):
        only_v, only_s = sorted(set(mine) - set(theirs)), sorted(set(theirs) - set(mine))
        if not (only_v or only_s):
            continue
        if v.get("kind") == "skeleton":
            out.append(f"ERROR: skeleton version {version}'s {what} are not its proposed skeleton's: nothing was changed")
        else:
            out.append(f"note: version {version}'s {what} snapshot differs from the accepted skeleton (only the version: "
                       f"{', '.join(only_v) or '-'}; only the skeleton: {', '.join(only_s) or '-'}): rows naming a "
                       "retired key are dropped, step 6's diff decides")
    if any(l.startswith("ERROR") for l in out):
        rc = 1
    return rc, out


def pending_problems(doc, refuse):
    """S-E5: the account decisions waiting for qa (null: no iam.account_decision)."""
    pend = doc.get("pending") or []
    if not pend:
        return []
    head = (f"ERROR: {len(pend)} account decision(s) wait for qa (the User Manager's Decisions tab): they were "
            "classified under the applied matrix; confirm, refuse or withdraw them first" if refuse else
            f"{len(pend)} account decision(s) wait for qa (the User Manager's Decisions tab): listed, not refused")
    return [head] + [f"  #{p.get('decision_id')} {p.get('kind')} {p.get('username')} {str(p.get('made_at'))[:19]}"
                     for p in pend]


# ── step 5: the checker and the staged compile ─────────────────────────────────────────
def git_skeleton_of(digest, body, commit):
    """A policy dict whose skeleton is `digest`, in its YAML key order when it can be had:
    (a) defaults.yaml at `commit` (a clean commit) when its skeleton digest is `digest`;
    (b) else the stored jsonb body with the factory's level order, then the rest sorted,
    never unreordered (jsonb sorts keys, §14.8.7). explain.bound_skeleton decides, so the
    rollback bound and every composition here use one rule."""
    k_yaml = None
    if isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{7,40}", commit):
        try:
            k_yaml = git_policy(commit)
        except source.SourceError:
            pass
    return explain.bound_skeleton(digest, k_yaml, body, ref=source.factory())[0]


def host_file_first(state, check_only=False):
    """Step 2.3 (design §14.8.4): (line, text or None) — the host file of the applied version
    A when it is absent or different, composed with the accepted skeleton in its YAML order
    (git_skeleton_of), never HEAD's: for a skeleton version HEAD carries the proposed one,
    which compose_applied refuses. --check-only composes it too and writes nothing."""
    v, kind = int(state["version"]), state["kind"]
    what = source.host_file_differs(state)
    if what is None:
        return f"[policy] state/policy-applied.yaml: version {v} ({kind}) unchanged", None
    acc = source._need_version(state)
    data = None
    if source.skeleton_digest(source.factory()) != acc["digest"]:
        data = git_skeleton_of(acc["digest"], acc.get("body"), acc.get("git_commit"))
    text = source.host_file_text(state, source.git_commit(), now(), data)
    if check_only:
        return f"WARNING: state/policy-applied.yaml is not version {v}'s ({what}): the apply rewrites it first", None
    return (f"[policy] state/policy-applied.yaml: version {v} ({kind}) "
            + ("rewritten: it differed from the database" if what == "different" else "written")), text


def sim_state(doc, state, kind=None, version=None, accepted=None, rows=None, groups=None, roles=None):
    """The state document version N would have once committed (step 5.1): its rows, its key
    snapshot, its stored entries digest; accepted the skeleton it applies under."""
    v = doc.get("version") or {}
    kind = kind or v.get("kind")
    rows = rows if rows is not None else {"entries": doc.get("entries") or [], "waivers": doc.get("waivers") or []}
    groups = groups if groups is not None else v.get("groups")
    roles = roles if roles is not None else v.get("roles")
    version = int(version if version is not None else v.get("version"))
    if kind == "rollback":
        r = source.state_rows(rows)
        ed = source.entries_digest("rollback", groups, roles, r["entries"], r["waivers"])
    else:
        ed = v.get("entries_digest")
    return {"state": f"version-{version}", "version": version, "kind": kind, "status": "applied",
            "entries_digest": ed, "groups": groups, "roles": roles, "based_on": state.get("version"),
            "accepted": accepted or state.get("accepted"), "entries": rows["entries"], "waivers": rows["waivers"],
            "last_apply_event": None, "break_glass_open": []}


def _write_private(path, text):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def compare_all(base, other):
    """Every target that differs between two compiles (compare() stops at the first)."""
    return sorted(n for n in set(base) | set(other) if compare({n: base[n]} if n in base else {},
                                                               {n: other[n]} if n in other else {}))


def stage(state, doc, out, commit, written_at=None, sim=None, prev_data=None):
    """(rc, lines) of design §14.8.4 step 5 into the directory `out` (mode 700): the staged
    host file of version N (staged/policy-applied.yaml) bound to the database rows, the
    checker on it whatever checker_verdict says, its compile (staged-outs), the applied
    version's file built from the state document (prev.yaml, bound the same way) and its
    compile (prev), the targets that differ, the artefact digests (digests.json) and
    stage.json {version, kind, staged_sha256, prev_sha256, changed, skeleton_digest}."""
    from compiler import invariants
    strip_policy_env()
    written_at = written_at or now()
    v = doc.get("version") or {}
    if sim is None:
        acc = state.get("accepted")
        if v.get("kind") == "skeleton":
            sk = (doc.get("skeletons") or {}).get(v.get("skeleton_digest")) or {}
            acc = {"digest": v.get("skeleton_digest"), "body": sk.get("body"), "git_commit": sk.get("git_commit")}
        sim = sim_state(doc, state, accepted=acc)
        if v.get("kind") == "skeleton":
            prev_data = git_skeleton_of(state["accepted"]["digest"], state["accepted"].get("body"),
                                        state["accepted"].get("git_commit"))
    os.makedirs(out, mode=0o700, exist_ok=True)
    os.chmod(out, 0o700)
    staged = os.path.join(out, "staged", "policy-applied.yaml")
    prev = os.path.join(out, "prev.yaml")
    _write_private(staged, source.host_file_text(sim, commit, written_at))
    bad = source.body_binding(sim, staged)
    if bad:
        return 1, [f"internal: the staged file of version {sim['version']} is not its rows ({bad}): nothing was changed"]
    errors = invariants.check(model.Policy(source.read_host_file(staged).data))[0]
    if errors:
        return 1, [f"version {sim['version']} fails the checker now: withdraw it"] + [f"  FAIL: {e}" for e in errors]
    _write_private(prev, source.host_file_text(state, commit, written_at, prev_data))
    bad = source.body_binding(state, prev)
    if bad:
        return 1, [f"internal: the applied version's file is not its rows ({bad}): nothing was changed"]
    outs = compile_all([], host_file=staged)
    save(os.path.join(out, "staged-outs"), outs)
    base = compile_all([], host_file=prev)
    save(os.path.join(out, "prev"), base)
    changed = compare_all(base, outs)
    acc_digest = sim["accepted"]["digest"]
    with open(os.path.join(out, "digests.json"), "w", encoding="utf-8") as f:
        json.dump(digests_of(outs, commit, skeleton_digest=acc_digest), f, sort_keys=True)
    with open(os.path.join(out, "prev-digests.json"), "w", encoding="utf-8") as f:   # a revert's record
        json.dump(digests_of(base, commit, skeleton_digest=state["accepted"]["digest"]), f, sort_keys=True)
    meta = {"version": sim["version"], "kind": sim["kind"], "entries_digest": sim["entries_digest"],
            "staged_sha256": source.file_sha256(staged), "prev_sha256": source.file_sha256(prev),
            "prev_version": int(state["version"]), "prev_entries_digest": state.get("entries_digest"),
            "changed": changed, "skeleton_digest": acc_digest, "rollback_of": sim.get("rollback_of")}
    with open(os.path.join(out, "stage.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, sort_keys=True)
    with open(os.path.join(out, "sim-state.json"), "w", encoding="utf-8") as f:
        json.dump(sim, f)
    return 0, [f"version {sim['version']} ({sim['kind']}) staged and bound to its rows; the checker passes; "
               f"{len(changed)} of {len(outs)} targets change: {', '.join(changed) or 'none'}"]


# ── step 6: the diff qa saw ────────────────────────────────────────────────────────────
def change_doc(state, doc):
    """iam-api's change diff (policy_api.change_diff) recomputed on the host: both sides
    composed with the tree's skeleton exactly as compose_rows composes them."""
    v = doc["version"]
    skel = source.skeleton(source.factory())

    def composed(entries, waivers):
        ew = {"entries": [dict(e, level=str(e["level"]).strip()) for e in entries],
              "waivers": [source.waiver_from_row(w) for w in waivers]}
        return model.Policy(source.compose_counted(skel, ew, drop_unknown=True)[0])
    return explain.diff_document("change", int(v["version"]), int(state["version"]), v["entries_digest"],
                                 composed(state.get("entries") or [], state.get("waivers") or []),
                                 composed(doc.get("entries") or [], doc.get("waivers") or []))


def skeleton_doc(state, doc):
    """A skeleton version's diff recomputed as apply.sh --propose-skeleton built it."""
    v = doc["version"]
    acc = source._need_version(state)
    git = source.factory()
    rows = source.state_rows(doc)
    p_old, p_new, acc_skel, git_skel = _composed(acc["body"], git, rows)
    body = source.skeleton(git)
    groups = sorted(body.get("resource_groups") or {}, key=source._bytes)
    roles = sorted(body.get("roles") or {}, key=source._bytes)
    ed = source.entries_digest("skeleton", groups, roles, rows["entries"], rows["waivers"])
    skel = {"from": acc["digest"], "to": source.skeleton_digest(git), "sections": explain.sections(acc_skel, git_skel)}
    return explain.diff_document("skeleton", int(v["version"]), int(state["version"]), ed, p_old, p_new, skeleton=skel)


def _widening_roles(prev_routes, staged_routes):
    """The roles whose row of routes.json's widening moves ({old or "-": {new: pairs}}): a
    grant into a role (from "-") adds exactly that role's pairs, so a role moved when its
    "-" entry did."""
    a = (prev_routes.get("widening") or {}).get("-") or {}
    b = (staged_routes.get("widening") or {}).get("-") or {}
    return sorted(r for r in set(a) | set(b) if a.get(r) != b.get(r))


def summary_lines(stage_dir, doc_diff=None):
    """Step 6's summary: per target changed/unchanged, each role's reach, the 503 window."""
    with open(os.path.join(stage_dir, "stage.json"), encoding="utf-8") as f:
        meta = json.load(f)
    prev, staged = load_saved(os.path.join(stage_dir, "prev")), load_saved(os.path.join(stage_dir, "staged-outs"))
    out = [f"  {n:28} {'changed' if n in meta['changed'] else 'unchanged'}" for n in sorted(staged)]
    out += _changed_detail(prev, staged, meta["changed"])
    for r, d in sorted(((doc_diff or {}).get("roles") or {}).items()):
        out.append(f"  role {r}: {len(d.get('added') or [])} added, {len(d.get('removed') or [])} removed"
                   + "".join(f"\n    + {explain._describe(t)}" for t in (d.get("added") or [])[:10])
                   + "".join(f"\n    - {explain._describe(t)}" for t in (d.get("removed") or [])[:10]))
    try:
        wid = _widening_roles(json.loads(prev["routes"][1]), json.loads(staged["routes"][1]))
    except (KeyError, ValueError):
        wid = []
    if wid:
        out.append(f"  access-api answers 503 to account decisions that change into or out of {', '.join(wid)} for "
                   "about a minute after the commit (design §6.4)")
    return out


TOOL_TARGETS = ("grafana", "jupyterhub-allowed", "jupyterhub-admin", "node-red", "edge-wizard", "pgadmin",
                "superset", "egress-notebooks")


def _changed_detail(prev, staged, changed):
    """Step 6's before → after of the changed targets a person reads (design §14.8.4): each
    host's admitted roles, the tools' settings, the MQTT rows per role, the NetworkPolicies
    that differ. A target that does not parse is shown only as changed."""
    def text(outs, n):
        return (outs.get(n) or (1, "", ""))[1].strip()

    def load(outs, n):
        try:
            return json.loads(text(outs, n))
        except ValueError:
            return None
    out = []
    for n in sorted(changed):
        if n.startswith("proxy-"):
            a, b = load(prev, n), load(staged, n)
            if isinstance(a, list) and isinstance(b, list):
                out.append(f"  host {n[6:]}: {', '.join(a) or 'nobody'} → {', '.join(b) or 'nobody'}"
                           + "".join(f" (+{r})" for r in b if r not in a) + "".join(f" (-{r})" for r in a if r not in b))
        elif n in TOOL_TARGETS:
            a, b = text(prev, n), text(staged, n)
            cut = lambda x: x if len(x) <= 300 else x[:297] + "..."
            out.append(f"  tool {n}: {cut(a) or '(none)'}\n    → {cut(b) or '(none)'}")
        elif n == "mqtt":
            a, b = load(prev, n) or {}, load(staged, n) or {}
            rows = lambda d, r: {(x.get("access"), x.get("topic"), x.get("constraint")) for x in (d.get("roles") or {}).get(r) or []}
            for r in sorted(set(a.get("roles") or {}) | set(b.get("roles") or {})):
                ra, rb = rows(a, r), rows(b, r)
                for sign, ts in (("+", sorted(rb - ra, key=str)), ("-", sorted(ra - rb, key=str))):
                    out += [f"  mqtt {r}: {sign} {acc} {top}" + (f" ({con})" if con else "") for acc, top, con in ts]
        elif n == "netpol":
            a, b = load(prev, n) or {}, load(staged, n) or {}
            pol = lambda d: {(i.get("metadata") or {}).get("name"): i for i in d.get("items") or []}
            pa, pb = pol(a), pol(b)
            for name in sorted(set(pa) | set(pb), key=str):
                if pa.get(name) != pb.get(name):
                    out.append(f"  netpol {name}: " + ("added" if name not in pa else "removed" if name not in pb else "changed"))
    return out


def diff_check(state, doc, stage_dir):
    """(rc, lines) of design §14.8.4 step 6: the recomputed diff of version N is byte for
    byte the one qa approved (a change: iam-api's composition; a skeleton version: the
    proposal's document, also = version_diff's digest)."""
    v = doc["version"]
    n = v["version"]
    try:
        d = skeleton_doc(state, doc) if v["kind"] == "skeleton" else change_doc(state, doc)
    except (source.SourceError, ValueError, KeyError) as e:
        return 1, [f"the diff of version {n} cannot be recomputed: {e}"]
    digest = explain.diff_digest(d)
    ev = ((doc.get("approval") or {}).get("event") or {}).get("payload") or {}
    want = {v.get("diff_digest"), ev.get("diff_digest")}
    if v["kind"] == "skeleton":
        want.add((doc.get("diff") or {}).get("diff_digest"))
    if want != {digest}:
        if v["kind"] == "skeleton":
            return 1, [f"the diff of skeleton version {n} is not the one qa approved (recomputed {digest[:12]}, approved "
                       f"{str(v.get('diff_digest'))[:12]}: a compiler change since the proposal): withdraw it and propose again"]
        return 1, [f"the diff of version {n} is not the one qa approved (recomputed {digest[:12]}, approved "
                   f"{str(v.get('diff_digest'))[:12]}; a skeleton or compiler change since the approval alters what it "
                   "grants): withdraw it and draft again"]
    return 0, [f"the diff of version {n} is the one qa approved ({digest[:12]}):"] + summary_lines(stage_dir, d)


# ── step 4 (§14.8.5): the evidence, the approver now, dual control ─────────────────────
def expected_azp(grants_doc):
    """The one client whose only_rpc names approve_policy in a grants-json document."""
    hits = sorted(c for c, fns in (grants_doc.get("only_rpc") or {}).items() if APPROVE_RPC in (fns or []))
    return hits[0] if len(hits) == 1 else None


def own_roles(groups, includes):
    """The held platform roles minus every role another held one includes (access-api's
    own_roles, SQL _own_role)."""
    held = {g for g in groups or [] if isinstance(g, str) and g in includes}
    covered = {i for r in held for i in (includes.get(r) or [])}
    return sorted(held - covered)


def evidence_problems(doc, jwks, prev_routes, prev_grants, issuer, version):
    """(refusals, jwk) of step 4.1: the approved event, its stored JWS verified against the
    realm's keys fetched now, and the claims of §14.8.5."""
    v = doc.get("version") or {}
    ap = doc.get("approval") or {}
    ev = (ap.get("event") or {}).get("payload") or {}
    evid = ap.get("evidence") or {}
    out = []
    sub = str(v.get("approved_by_sub") or "").lower()
    if ev.get("source") != "token":
        return [f"version {version}'s approval is not from a token (source {ev.get('source')!r}): withdraw it and draft again"], None
    if str(ev.get("sub") or "").lower() != sub or not sub:
        out.append(f"version {version}'s approved event names sub {ev.get('sub')}, the version {sub or '-'}")
    jws = evid.get("jws") or ""
    if not jws or hashlib.sha256(jws.encode("utf-8")).hexdigest() != ev.get("jws_sha256"):
        return out + [f"version {version}'s stored approval token is not the one its approved event hashed"], None
    try:
        _, claims, jwk = verify_rs256(jws, jwks)
    except UnknownKid as e:
        return out + [f"the realm key that signed the approval (kid {e.kid}) is no longer published: withdraw version "
                      f"{version} and draft again"], None
    except JwsError as e:
        return out + [str(e)], None
    if not claims_recorded(claims, evid.get("claims")):
        return out + ["the approval token's claims are not the ones recorded with it"], jwk
    if str(claims.get("sub") or "").lower() != sub:
        out.append("the approval token's sub is not approved_by_sub")
    if claims.get("person_id") != v.get("approved_by_person"):
        out.append("the approval token's person_id is not approved_by_person")
    if not claims.get("jti") or claims.get("jti") != ev.get("jti"):
        out.append("the approval token's jti is not the approved event's")
    if claims.get("iat") != ev.get("iat") or claims.get("iat") != v.get("approved_iat"):
        out.append("the approval token's iat is not approved_iat and the event's")
    azp = expected_azp(prev_grants)
    if azp is None:
        raise source.SourceError("the applied policy names no single client for approve_policy")
    if claims.get("azp") != azp:
        out.append(f"the approval token's azp is {claims.get('azp')!r}, not the policy host's client {azp!r}")
    aud = claims.get("aud")
    if AUDIENCE not in (aud if isinstance(aud, list) else [aud]):
        out.append(f"the approval token's aud lacks {AUDIENCE}")
    if claims.get("typ") != "Bearer":
        out.append(f"the approval token's typ is {claims.get('typ')!r}, not Bearer")
    if claims.get("iss") != issuer:
        out.append(f"the approval token's iss is {claims.get('iss')!r}, not {issuer}")
    try:
        at = datetime.datetime.fromisoformat(str(v.get("approved_at"))).timestamp()
        if not (float(claims["iat"]) - LEEWAY <= at <= float(claims["exp"]) + LEEWAY):
            out.append("the approval was recorded outside its token's lifetime (iat - 30 s .. exp + 30 s)")
    except (KeyError, TypeError, ValueError):
        out.append("approved_at or the token's iat/exp cannot be read")
    approvers = ((prev_routes.get("dual_control") or {}).get("iam_policy") or {}).get("approver_roles") or []
    own = own_roles(claims.get("groups"), prev_routes.get("role_includes") or {})
    if len(own) != 1 or own[0] != ev.get("role") or own[0] not in approvers:
        out.append(f"the approval token's own role {own} is not the event's {ev.get('role')!r} among the approver "
                   f"roles {approvers}")
    for o in ap.get("other_approved") or []:
        if o.get("jti") and o.get("jti") == claims.get("jti"):
            out.append(f"the approval token of version {version} was also used to approve version {o.get('version')}")
    return out, jwk


def _kc_json(d, *p):
    path = os.path.join(d, *p)
    return load_json(path) if os.path.exists(path) else None


def _pid(u):
    return ((u.get("attributes") or {}).get("person_id") or [None])[0] if isinstance(u, dict) else None


def eligibility_problems(doc, kc, accounts, prev_routes, version):
    """Step 4.2 (OA-b): by approved_by_sub, Keycloak's account now: enabled, an approver
    role of the applied policy (effective, composites included), the approved person_id, no
    author's person, no enabled maker's person (I17). No account decision is consulted."""
    v = doc.get("version") or {}
    person = str(v.get("approved_by_person") or "")
    u = _kc_json(kc, "approver.json")
    if not isinstance(u, dict):
        return [f"the approver's account ({v.get('approved_by_sub')}) no longer exists in Keycloak"]
    out = []
    dual = prev_routes.get("dual_control") or {}
    approvers = (dual.get("iam_policy") or {}).get("approver_roles") or []
    makers = (dual.get("iam_policy") or {}).get("maker_roles") or []
    name = u.get("username") or v.get("approved_by_sub")
    if not u.get("enabled"):
        out.append(f"the approver {name} is disabled now")
    held = {r.get("name") for r in (_kc_json(kc, "approver-roles.json") or []) if isinstance(r, dict)}
    if not held & set(approvers):
        out.append(f"the approver {name} no longer holds an approver role of iam_policy ({', '.join(approvers)})")
    if (_pid(u) or "") != person or not person:
        out.append(f"the approver {name}'s person_id is not the approved person ({person or '-'})")
    low = person.lower()
    for a in doc.get("authors") or []:
        cur = _pid(_kc_json(kc, "authors", f"{a.get('sub')}.json"))
        if str(a.get("person") or "").lower() == low or str(a.get("sub") or "").lower() == str(v.get("approved_by_sub")).lower() \
                or (cur and cur.lower() == low):
            out.append(f"the approver's person is an author of version {version} (another qa person approves it)")
            break
    for a in accounts:
        if a.get("enabled") and set(a.get("roles") or ()) & set(makers) and str(a.get("person_id") or "").lower() == low:
            out.append(f"the approver's person also holds the enabled maker account {a.get('username')} (I17): "
                       "another qa person approves it, or disable that account")
    return out


def composite_problems(kc, accepted_skel, proposed_skel=None):
    """Step 4.3: Keycloak's composites are the accepted skeleton's includes; a skeleton
    version does not change includes (owner decision 4: not applied in 4.5)."""
    out = []
    roles = accepted_skel.get("roles") or {}
    for r, d in sorted(roles.items()):
        inc = sorted((d or {}).get("includes") or [])
        comps = _kc_json(kc, "composites", f"{r}.json")
        names = sorted(c.get("name") for c in comps or [] if isinstance(c, dict) and not c.get("clientRole"))
        if inc and names != inc:
            out.append(f"Keycloak's role {r} includes {names or 'nothing'}, the accepted skeleton {inc}: "
                       "./deploy-infra.sh adds the composites")
    if proposed_skel is not None:
        pr = proposed_skel.get("roles") or {}
        if any(sorted((pr.get(r) or {}).get("includes") or []) != sorted((roles.get(r) or {}).get("includes") or [])
               for r in set(pr) | set(roles)):
            out.append("this skeleton version changes role composites, which no apply step sets yet (deploy-infra only "
                       "adds them): not applied in 4.5")
    return out


def person_widening_problems(doc, accounts, p_applied, p_n, version):
    """Step 4.4 (S-B4): no role held by an enabled account of the approver's person (its
    includes expanded) gains reach in version N. A role version N adds counts too: its whole
    reach is new (explain.reach of an absent role is empty)."""
    low = str((doc.get("version") or {}).get("approved_by_person") or "").lower()
    out = []
    for a in accounts:
        if not a.get("enabled") or str(a.get("person_id") or "").lower() != low:
            continue
        for r in sorted(a.get("roles") or []):
            if r in p_n.roles and model.widening_between(p_applied, p_n, r):
                out.append(f"version {version} widens role {r}, which {a.get('username')} (an enabled account of the "
                           "approver's person) holds: another qa person approves it")
    return out


def account_skeleton(state, doc=None):
    """The skeleton whose roles fetch_accounts lists and whose includes expand them: the
    accepted one; for a skeleton version the union of accepted and proposed includes."""
    skel = copy.deepcopy(source.skeleton((state.get("accepted") or {}).get("body") or source.factory()))
    v = (doc or {}).get("version") or {}
    if v.get("kind") == "skeleton":
        body = ((doc.get("skeletons") or {}).get(v.get("skeleton_digest")) or {}).get("body") or {}
        roles = skel.setdefault("roles", {})
        for r, d in (body.get("roles") or {}).items():
            cur = roles.setdefault(r, {})
            cur["includes"] = sorted(set(cur.get("includes") or []) | set((d or {}).get("includes") or []))
    return skel


def check_approval(doc, kc, jwks, stage_dir, issuer, mode, version, state=None):
    """(refusals, warnings, notes, info) of design §14.8.4 step 4 for `<N>` (mode apply) or
    only its item 5 for --rollback-to (problems there are warnings, S-C4)."""
    def outs(d):
        return load_saved(os.path.join(stage_dir, d))
    prev, staged = outs("prev"), outs("staged-outs")
    prev_routes, staged_routes = json.loads(prev["routes"][1]), json.loads(staged["routes"][1])
    prev_grants = json.loads(prev["grants-json"][1])
    skel = load_json(os.path.join(kc, "skeleton.json")) if os.path.exists(os.path.join(kc, "skeleton.json")) else None
    accounts = accounts_from_dir(kc, skel)
    refusals, warnings, notes, info = [], [], [], {}
    if mode == "apply":
        v = doc.get("version") or {}
        ev, jwk = evidence_problems(doc, jwks, prev_routes, prev_grants, issuer, version)
        refusals += ev
        info["jwk"] = jwk
        info["event_id"] = ((doc.get("approval") or {}).get("event") or {}).get("event_id")
        refusals += eligibility_problems(doc, kc, accounts, prev_routes, version)
        acc_body = source.skeleton(((state or {}).get("accepted") or {}).get("body") or source.factory())
        proposed = None
        if v.get("kind") == "skeleton":
            proposed = ((doc.get("skeletons") or {}).get(v.get("skeleton_digest")) or {}).get("body") or {}
        refusals += composite_problems(kc, acc_body, proposed)
        p_applied = model.Policy(source.read_host_file(os.path.join(stage_dir, "prev.yaml")).data)
        p_n = model.Policy(source.read_host_file(os.path.join(stage_dir, "staged", "policy-applied.yaml")).data)
        refusals += person_widening_problems(doc, accounts, p_applied, p_n, version)
        for f in ((state or {}).get("seeded") or {}).get(str(v.get("approved_by_sub")).lower()) or []:
            notes.append(f"the approver's account fact: event {f.get('event_id')} {f.get('fact')} {f.get('username')} "
                         f"{f.get('role') or '-'} {f.get('person_id') or '-'}")
    probs = can_approve(staged_routes, accounts)
    if mode == "apply":
        refusals += [f"after version {version}: {p}" for p in probs]
    else:
        warnings += [f"after this rollback: {p}" for p in probs]
    return refusals, warnings, notes, info


# ── --rollback-to K (§14.8.7): K eligible, and the bound (OA-c) ───────────────────────
def rollback_problems(doc, state, jwks, k):
    """(refusals, warnings) of §14.8.7 step 3: K is a target."""
    v = doc.get("version")
    if not isinstance(v, dict):
        return [f"version {k} cannot be rolled back to: there is no version {k}"], []
    out, warn = [], []
    if v.get("status") != "superseded":
        out.append(f"it is {v.get('status')}, not superseded (only a version once applied)")
    if v.get("disputed_at"):
        out.append("qa disputed it")
    if v.get("kind") in ("change", "skeleton"):
        ap = doc.get("approval") or {}
        ev = (ap.get("event") or {}).get("payload") or {}
        jws = (ap.get("evidence") or {}).get("jws")
        if ev.get("source") != "token" or not jws:
            out.append("its approval has no token evidence")
        else:
            try:
                _, claims, _ = verify_rs256(jws, jwks)
                if not claims_recorded(claims, (ap.get("evidence") or {}).get("claims")):
                    out.append("its approval token's claims are not the ones recorded")
            except UnknownKid:
                warn.append(f"version {k}'s realm key is no longer published: the approval stands on its record")
            except JwsError as e:
                out.append(f"its approval token does not verify ({e})")
    elif not v.get("confirmed_at"):
        out.append(f"this {v.get('kind')} version was never confirmed by qa")
    for f in doc.get("audit_findings") or []:
        if f.get("version") == k:
            out.append(f"audit_versions(): {f.get('finding')}")
    last = (state.get("last_apply_event") or {}).get("event")
    pre = []
    if last in ("apply_started", "partial_apply"):
        pre.append(f"finish version {state.get('version')} first ({last}): ./apps/iam/apply.sh --resume --by <you>")
    return pre + [f"version {k} cannot be rolled back to: {why}" for why in out], warn


def rollback_skeleton_digest(doc):
    v = doc.get("version") or {}
    if v.get("kind") == "change":
        return v.get("approved_skeleton_digest")
    if v.get("kind") == "skeleton":
        return v.get("skeleton_digest")
    return (doc.get("apply_started") or {}).get("skeleton_digest")


def rollback_bound(doc, k):
    """(refusals, notes) of the bound (OA-c), explain.rollback_bound's (the one rule,
    RollbackBoundTest): every person role reaches under today's skeleton S with K's rows no
    more than under the skeleton K was approved under, S_K, with K's rows. A row naming a key
    S retired is dropped (counted), never refused."""
    d_k = rollback_skeleton_digest(doc)
    sk = (doc.get("skeletons") or {}).get(d_k) or {}
    commit = (doc.get("apply_started") or {}).get("commit")
    try:
        s_k = git_skeleton_of(d_k, sk.get("body"), commit)
    except source.SourceError as e:
        return [f"version {k}'s skeleton cannot be composed: {e}"], []
    bound = explain.rollback_bound(source.factory(), s_k, source.state_rows(doc))
    msg = explain.rollback_refusal(k, bound)
    dropped = bound["dropped"]["today"]
    notes = [f"{dropped} row(s) of version {k} name a group or role today's skeleton retired: dropped"] if dropped else []
    return ([msg] if msg else []), notes


def rollback_sim(state, doc, next_version, k):
    """The state document of the rollback version `_build_version('rollback', …)` creates:
    K's rows, the accepted skeleton's keys, the entries digest it will store."""
    acc = source._need_version(state)
    groups = sorted(acc["body"].get("resource_groups") or {}, key=source._bytes)
    roles = sorted(acc["body"].get("roles") or {}, key=source._bytes)
    sim = sim_state(doc, state, kind="rollback", version=next_version, accepted=state["accepted"],
                    rows={"entries": doc.get("entries") or [], "waivers": doc.get("waivers") or []},
                    groups=groups, roles=roles)
    sim["rollback_of"] = int(k)
    return sim


def rollback_diff_lines(state, stage_dir):
    """The rollback's diff against the applied version (the change shape, not hashed)."""
    p_from = model.Policy(source.read_host_file(os.path.join(stage_dir, "prev.yaml")).data)
    p_to = model.Policy(source.read_host_file(os.path.join(stage_dir, "staged", "policy-applied.yaml")).data)
    d = explain.diff(p_from, p_to)
    return [f"rollback diff against version {state.get('version')}: {len(d['cells'])} cell(s) differ"] + \
        summary_lines(stage_dir, d)


# ── step 6b/9: the verify conf and its results ────────────────────────────────────────
def verify_conf(drop=()):
    lines = ["# apps/iam/apply.sh step 9 (design §14.8.6): what a policy version changes"]
    for t, target in VERIFY_CHECKS:
        if t not in drop:
            lines.append(f"step9:{t} | {t} | {target} |")
    return "\n".join(lines) + "\n"


def health_results(text):
    """{check type: OK|WARN|FAIL|SKIP} from health-check.sh's output of verify_conf()."""
    out = {}
    for line in ANSI.sub("", text).splitlines():
        m = RESULT.search(line)
        if m:
            out[m.group(2)] = m.group(1)
    return out


def verify_judge(baseline, now_, expected):
    """The checks that count as failed (design §14.8.6 step 9): FAIL now (or no result)
    and not FAIL in the baseline of step 6b."""
    return [t for t in expected if now_.get(t, "FAIL") == "FAIL" and baseline.get(t) != "FAIL"]


# ── step 7: the bundle's PRE and POST for a change, skeleton, rollback or revert ──────
def _assert_sql(tag, body):
    return "\n".join([f"DO ${tag}$", "BEGIN", body, f"END ${tag}$;"])


def apply_bundle_sql(kind, meta, by_sub, by_person, log, commit, digests, diff_digest=None, skeleton=None,
                     rollback=None):
    """(pre, post) of `<N>`'s or --rollback-to's bundle (design §14.8.4 step 7, §14.8.7
    step 7): every value base64 in a psql variable; PRE re-reads the version FOR UPDATE and
    asserts what was approved (change, skeleton) or builds the rollback version from K's rows
    read in SQL; POST marks it applied and asserts the staged header's entries digest."""
    if not UUID.fullmatch(by_sub or ""):
        die(f"--by-sub {by_sub!r} is not a uuid")
    if not (by_person or "").strip():
        die("--by-person is empty")
    ed = meta["entries_digest"]
    if not re.fullmatch(r"[0-9a-f]{64}", ed or ""):
        die("the staged version has no entries digest")
    J, T = source._jsonb, source._text
    pre = [f"-- apps/iam/apply.sh {'--rollback-to' if kind == 'rollback' else meta['version']}: PRE "
           "(apply_check.py bundle-sql; design §14.8.4 step 7)",
           f"\\set want_entries '{ed}'"]
    if kind in ("change", "skeleton"):
        if not re.fullmatch(r"[0-9a-f]{64}", diff_digest or ""):
            die("the approved diff digest is missing")
        pre += [f"\\set v '{int(meta['version'])}'",
                f"\\set want_diff '{diff_digest}'",
                "SELECT pg_catalog.set_config('medcea.apply_version', :'v', true),",
                "       pg_catalog.set_config('medcea.apply_entries', :'want_entries', true),",
                "       pg_catalog.set_config('medcea.apply_diff', :'want_diff', true) \\g /dev/null",
                "SELECT x.version FROM iam_policy.version x WHERE x.version = :v FOR UPDATE \\g /dev/null",
                _assert_sql("pre", "\n".join([
                    "    IF (SELECT x.status FROM iam_policy.version x",
                    "         WHERE x.version = pg_catalog.current_setting('medcea.apply_version')::integer) IS DISTINCT FROM 'approved' THEN",
                    "        RAISE EXCEPTION 'version % is not approved any more: nothing was applied',",
                    "            pg_catalog.current_setting('medcea.apply_version');",
                    "    END IF;",
                    "    IF iam_policy.entries_digest(pg_catalog.current_setting('medcea.apply_version')::integer)",
                    "       IS DISTINCT FROM pg_catalog.current_setting('medcea.apply_entries')",
                    "       OR (SELECT x.entries_digest FROM iam_policy.version x",
                    "            WHERE x.version = pg_catalog.current_setting('medcea.apply_version')::integer)",
                    "       IS DISTINCT FROM pg_catalog.current_setting('medcea.apply_entries') THEN",
                    "        RAISE EXCEPTION 'version % does not store the entries of the staged file: nothing was applied',",
                    "            pg_catalog.current_setting('medcea.apply_version');",
                    "    END IF;",
                    "    IF (SELECT x.diff_digest FROM iam_policy.version x",
                    "         WHERE x.version = pg_catalog.current_setting('medcea.apply_version')::integer)",
                    "       IS DISTINCT FROM pg_catalog.current_setting('medcea.apply_diff') THEN",
                    "        RAISE EXCEPTION 'version % carries another diff digest than the one checked: nothing was applied',",
                    "            pg_catalog.current_setting('medcea.apply_version');",
                    "    END IF;"]))]
    if kind == "skeleton":
        digest, body, scommit = skeleton
        summary = {"narrowed": [], "unchanged": [], "reviewed_by_version": int(meta["version"])}
        pre += [f"\\set skel_digest '{digest}'",
                _set("skel_body", source.canonical(body).decode("utf-8")),
                _set("skel_commit", scommit),
                _set("skel_compiler", source.compiler_digest()),
                _set("skel_summary", summary),
                f"SELECT iam_policy._accept_skeleton(:'skel_digest', {J('skel_body')}, {T('skel_commit')}, "
                f"{T('skel_compiler')}, {J('skel_summary')}) \\g /dev/null",
                f"SELECT iam_policy._sync_skeleton({J('skel_body')}, {T('skel_commit')}) \\g /dev/null",
                _assert_sql("acc", "\n".join([
                    "    IF iam_policy._accepted() IS DISTINCT FROM (SELECT x.skeleton_digest FROM iam_policy.version x",
                    "         WHERE x.version = pg_catalog.current_setting('medcea.apply_version')::integer) THEN",
                    "        RAISE EXCEPTION 'the accepted skeleton is not version %''s', pg_catalog.current_setting('medcea.apply_version');",
                    "    END IF;"]))]
    if kind == "rollback":
        k, applied, reason = rollback
        pre += [f"\\set k '{int(k)}'",
                f"\\set applied '{int(applied)}'",
                f"\\set want_version '{int(meta['version'])}'",
                _set("rb_reason", reason),
                _set("rb_withdraw", f"withdrawn by rollback to version {int(k)}: {reason}"),
                f"SELECT iam_policy._withdraw_open({T('rb_withdraw')}) \\g /dev/null",
                "SELECT iam_policy._build_version('rollback',",
                "    (SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('role', e.role, 'group_code', e.group_code,",
                "             'level', e.level::text, 'constraint_name', e.constraint_name)), '[]'::jsonb)",
                "       FROM iam_policy.entry e WHERE e.version = :k),",
                "    (SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(w) - 'version'), '[]'::jsonb)",
                "       FROM iam_policy.waiver w WHERE w.version = :k),",
                f"    :applied, :k, {T('rb_reason')}) AS v \\gset",
                "SELECT pg_catalog.set_config('medcea.apply_version', :'v', true),",
                "       pg_catalog.set_config('medcea.apply_want', :'want_version', true),",
                "       pg_catalog.set_config('medcea.apply_entries', :'want_entries', true) \\g /dev/null",
                _assert_sql("rb", "\n".join([
                    "    IF pg_catalog.current_setting('medcea.apply_version') <> pg_catalog.current_setting('medcea.apply_want') THEN",
                    "        RAISE EXCEPTION 'another version was created meanwhile (got %, staged %): nothing was applied',",
                    "            pg_catalog.current_setting('medcea.apply_version'), pg_catalog.current_setting('medcea.apply_want');",
                    "    END IF;",
                    "    IF iam_policy.entries_digest(pg_catalog.current_setting('medcea.apply_version')::integer)",
                    "       IS DISTINCT FROM pg_catalog.current_setting('medcea.apply_entries') THEN",
                    "        RAISE EXCEPTION 'version % does not store the entries of the staged file: nothing was applied',",
                    "            pg_catalog.current_setting('medcea.apply_version');",
                    "    END IF;"]))]
    digests = dict(digests or {}, git_commit=commit, compiler_digest=source.compiler_digest(),
                   skeleton_digest=meta["skeleton_digest"])
    post_checks = [
        "    IF (SELECT x.status FROM iam_policy.version x",
        "         WHERE x.version = pg_catalog.current_setting('medcea.apply_version')::integer) IS DISTINCT FROM 'applied'",
        "       OR iam_policy.entries_digest(pg_catalog.current_setting('medcea.apply_version')::integer)",
        "          IS DISTINCT FROM pg_catalog.current_setting('medcea.apply_entries') THEN",
        "        RAISE EXCEPTION 'version % is not applied with the staged entries', pg_catalog.current_setting('medcea.apply_version');",
        "    END IF;"]
    if kind == "skeleton":
        post_checks += [
            "    IF iam_policy._accepted() IS DISTINCT FROM (SELECT x.skeleton_digest FROM iam_policy.version x",
            "         WHERE x.version = pg_catalog.current_setting('medcea.apply_version')::integer) THEN",
            "        RAISE EXCEPTION 'the accepted skeleton is not version %''s', pg_catalog.current_setting('medcea.apply_version');",
            "    END IF;"]
    post = [f"-- apps/iam/apply.sh: POST (apply_check.py bundle-sql, {kind}); :v is the version",
            _set("apply_digests", digests),
            _set("apply_os_user", os_user()),
            f"\\set apply_by_sub '{by_sub.lower()}'",
            _set("apply_by_person", by_person),
            _set("apply_log", log or ""),
            f"SELECT iam_policy._mark_applied(:v, {J('apply_digests')}, {T('apply_os_user')}, :'apply_by_sub'::uuid, "
            f"{T('apply_by_person')}, NULLIF({T('apply_log')}, '')) \\g /dev/null",
            _assert_sql("post", "\n".join(post_checks))]
    return "\n".join(pre + [""]), "\n".join(post + [""])


def revert_bundle_sql(prev_header, reverted, why, failed):
    """(pre, post) of the revert bundle (design §14.8.6): PRE binds prev.yaml to the
    database (its header's version is the one `reverted` superseded, its entries digest the
    stored one); POST puts it back (_mark_reverted), asserts it, and files partial_apply
    {outcome: reverting} under it, so the unfinished revert is visible from its COMMIT on."""
    prev, ed = int(prev_header["version"]), prev_header["entries_digest"]
    if not re.fullmatch(r"[0-9a-f]{64}", ed or ""):
        die("prev.yaml's header has no entries digest")
    J, T = source._jsonb, source._text
    pre = ["-- apps/iam/apply.sh: the revert's PRE (apply_check.py bundle-sql --kind revert; design §14.8.6)",
           f"\\set prev '{prev}'",
           f"\\set rv '{int(reverted)}'",
           f"\\set want_entries '{ed}'",
           "SELECT pg_catalog.set_config('medcea.revert_prev', :'prev', true),",
           "       pg_catalog.set_config('medcea.revert_version', :'rv', true),",
           "       pg_catalog.set_config('medcea.apply_entries', :'want_entries', true) \\g /dev/null",
           _assert_sql("rpre", "\n".join([
               "    IF (SELECT h.payload ->> 'previous' FROM iam_policy.history h",
               "         WHERE h.version = pg_catalog.current_setting('medcea.revert_version')::integer AND h.event = 'apply_started'",
               "         ORDER BY h.event_id DESC LIMIT 1) IS DISTINCT FROM pg_catalog.current_setting('medcea.revert_prev') THEN",
               "        RAISE EXCEPTION 'version % did not supersede version %: the revert file is another version''s',",
               "            pg_catalog.current_setting('medcea.revert_version'), pg_catalog.current_setting('medcea.revert_prev');",
               "    END IF;",
               "    IF iam_policy.entries_digest(pg_catalog.current_setting('medcea.revert_prev')::integer)",
               "       IS DISTINCT FROM pg_catalog.current_setting('medcea.apply_entries')",
               "       OR (SELECT x.entries_digest FROM iam_policy.version x",
               "            WHERE x.version = pg_catalog.current_setting('medcea.revert_prev')::integer)",
               "       IS DISTINCT FROM pg_catalog.current_setting('medcea.apply_entries') THEN",
               "        RAISE EXCEPTION 'version % does not store the entries of the revert file', pg_catalog.current_setting('medcea.revert_prev');",
               "    END IF;"])), ""]
    payload = {"version": prev, "outcome": "reverting", "reverted_version": int(reverted),
               "failed_targets": list(failed or []), "os_user": os_user()}
    post = ["-- apps/iam/apply.sh: the revert's POST",
            _set("revert_why", why),
            _set("revert_payload", payload),
            f"SELECT iam_policy._mark_reverted(:rv, :prev, {T('revert_why')}) \\g /dev/null",
            _assert_sql("rpost", "\n".join([
                "    IF (SELECT x.status FROM iam_policy.version x",
                "         WHERE x.version = pg_catalog.current_setting('medcea.revert_prev')::integer) IS DISTINCT FROM 'applied'",
                "       OR iam_policy.entries_digest(pg_catalog.current_setting('medcea.revert_prev')::integer)",
                "          IS DISTINCT FROM pg_catalog.current_setting('medcea.apply_entries') THEN",
                "        RAISE EXCEPTION 'version % is not back with the revert file''s entries', pg_catalog.current_setting('medcea.revert_prev');",
                "    END IF;"])),
            f"SELECT iam_policy._record('partial_apply', {J('revert_payload')}) \\g /dev/null", ""]
    return "\n".join(pre), "\n".join(post)


def apply_extra(doc, meta, mode, attempts, check=None, deferred=(), pre_failing=(), reason=None):
    """The applied event's fields beyond the bootstrap's (design §14.8.6 step 10)."""
    v = doc.get("version") or {}
    out = {"rollback_of": meta.get("rollback_of"), "changed": list(meta.get("changed") or []),
           "deferred": list(deferred), "attempts": int(attempts), "pre_failing": list(pre_failing)}
    if mode == "apply":
        out["approved_by"] = {"sub": v.get("approved_by_sub"), "person": v.get("approved_by_person"),
                              "event_id": (check or {}).get("event_id")}
        out["jwk"] = (check or {}).get("jwk")
        out["reason"] = f"version {meta['version']} ({meta['kind']}) applied, approved by {v.get('approved_by_name')}"
    else:
        out["reason"] = reason or f"version {meta['version']}: rollback to version {meta.get('rollback_of')}"
    return out


def verify_host(ref_dir):
    """The written host file compiles to exactly the reference compile (design §14.8.4,
    after the COMMIT: bootstrap-targets --source host generalised)."""
    strip_policy_env()
    if source.read_host_file() is None:
        die("no state/policy-applied.yaml to compile", 1)
    host = compile_all([], host_file=source.HOST_FILE)
    diff = compare(load_saved(ref_dir), host)
    if diff:
        print(f"state/policy-applied.yaml compiles differently from the staged version: {diff[0]} ({diff[1]})",
              file=sys.stderr)
        return 1
    print(f"[policy] state/policy-applied.yaml compiles to exactly the staged version ({len(host)} targets)")
    return 0


# ── the targets (design §14.4.10) ──────────────────────────────────────────────────────
def targets(p):
    """[(name, cli argv)] of every target, describe-gate excluded (it needs the proxy list)."""
    t = [("routes", ["compile", "routes"]), ("mqtt", ["compile", "mqtt"]),
         ("netpol", ["compile", "netpol"] + NETPOL_ARGS),
         ("egress-notebooks", ["compile", "egress", "notebooks"]),
         ("grafana", ["compile", "grafana"]),
         ("jupyterhub-allowed", ["compile", "jupyterhub", "--setting", "allowed_groups"]),
         ("jupyterhub-admin", ["compile", "jupyterhub", "--setting", "admin_groups"]),
         ("node-red", ["compile", "node-red"]), ("edge-wizard", ["compile", "edge-wizard"]),
         ("pgadmin", ["compile", "pgadmin"])]
    # Superset (stage C) only while its group gives some role a setting: a policy without the
    # tool, or with the block but no cell, compiles exactly the targets (and digests) it did
    # before, so versions 1-14 audit as recorded (F3)
    if tools.groups(p, "superset") and tools.admits_anyone(p, "superset"):
        t.append(("superset", ["compile", "superset"]))
    t += [(f"proxy-{h}", ["compile", "proxy", h]) for h in p.hosts]
    for iam in ([], ["--without-iam"]):
        tag = "-without-iam" if iam else ""
        for mode in ("additive", "enforce", "verify"):
            t.append((f"grants-{mode}{tag}", ["compile", "grants", "--mode", mode, "--part", "all"] + iam))
        t.append((f"grants-json{tag}", ["compile", "grants", "--format", "json"] + iam))
    t.append(("hosts", ["hosts"]))
    return t


def _cli(argv):
    from compiler import cli
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(argv)
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 2
    return rc, out.getvalue(), err.getvalue()


def compile_all(src_args, host_file=None):
    """{target: (rc, stdout, stderr)} from one source: src_args for cli.py (--defaults, or
    --file F --label L), or host_file: the source rule with that file as the host file."""
    saved = source.HOST_FILE
    if host_file:
        source.HOST_FILE = host_file
    try:
        if host_file:
            src = source.resolve(env={})
            if src.kind != "host":
                die(f"{host_file} is not read as a host applied file")
            p = model.Policy(src.data)
        else:
            rc, _, err = _cli(src_args + ["check"])
            if rc != 0:
                print(err, file=sys.stderr, end="")
                die(f"cli.py {' '.join(src_args)} check failed", 1)
            p = model.Policy(source.resolve(*(_src_args_for_resolve(src_args))).data)
        out = {}
        for name, argv in targets(p):
            out[name] = _cli(src_args + argv)
        for h in p.hosts:
            rc, text, _ = out[f"proxy-{h}"]
            if rc == 0:
                out[f"describe-gate-{h}"] = _cli(src_args + ["describe-gate", h, text.strip()])
        return out
    finally:
        source.HOST_FILE = saved


def _src_args_for_resolve(src_args):
    if "--defaults" in src_args:
        return (None, True, {})
    return (src_args[src_args.index("--file") + 1], False, {})


def _routes_doc(text):
    d = json.loads(text)
    return {k: v for k, v in d.items() if k not in ROUTES_UNCOMPARED}


def compare(base, other):
    """(target, first differing line) of the first difference, else None."""
    for name in sorted(set(base) | set(other)):
        if name not in base or name not in other:
            return name, "compiled from one source only"
        (rc1, a, _), (rc2, b, err2) = base[name], other[name]
        if rc1 != rc2:
            return name, f"exit {rc1} against {rc2}: {err2.strip()[:200]}"
        if name == "routes" and rc1 == 0:
            if _routes_doc(a) != _routes_doc(b):
                da, db = _routes_doc(a), _routes_doc(b)
                k = next(k for k in sorted(set(da) | set(db)) if da.get(k) != db.get(k))
                return name, f"field {k} differs"
            continue
        if a != b:
            la, lb = a.splitlines(), b.splitlines()
            for i, (x, y) in enumerate(zip(la, lb), 1):
                if x != y:
                    return name, f"line {i}: {x[:120]!r} against {y[:120]!r}"
            return name, f"line {min(len(la), len(lb)) + 1}: one output is longer"
    return None


def save(d, outs):
    os.makedirs(d, mode=0o700, exist_ok=True)
    for name, (rc, text, err) in outs.items():
        with open(os.path.join(d, f"{name}.out"), "w", encoding="utf-8") as f:
            f.write(text)
        with open(os.path.join(d, f"{name}.rc"), "w") as f:
            f.write(f"{rc}\n")


def load_saved(d):
    outs = {}
    for fn in sorted(os.listdir(d)):
        if fn.endswith(".out"):
            name = fn[:-4]
            with open(os.path.join(d, fn), encoding="utf-8") as f:
                text = f.read()
            with open(os.path.join(d, f"{name}.rc")) as f:
                rc = int(f.read().strip())
            outs[name] = (rc, text, "")
    return outs


def digests_of(outs, commit=None, skeleton_digest=None):
    """_mark_applied's p_digests from compiled outputs (design §14.4.9). skeleton_digest: the
    skeleton the version is applied under (IAM 4.5, design §14.8.4 step 5.8; default the git
    tree's, which the bootstrap applies)."""
    def h(name):
        rc, text, _ = outs.get(name, (1, "", ""))
        return sha(text) if rc == 0 else None
    routes_doc = json.loads(outs["routes"][1])
    mqtt_doc = json.loads(outs["mqtt"][1])
    return {"git_commit": commit or source.git_commit(), "compiler_digest": source.compiler_digest(),
            "skeleton_digest": skeleton_digest or source.skeleton_digest(source.factory()),
            "routes": routes_doc.get("digest"), "mqtt": mqtt_doc.get("digest"),
            "grants_document": h("grants-json"), "netpol": h("netpol"),
            "proxy": {n[len("proxy-"):]: h(n) for n in sorted(outs) if n.startswith("proxy-")},
            "tools": {"grafana": h("grafana"), "jupyterhub_allowed": h("jupyterhub-allowed"),
                      "jupyterhub_admin": h("jupyterhub-admin"), "node_red": h("node-red"),
                      "edge_wizard": h("edge-wizard"), "pgadmin": h("pgadmin"),
                      **({"superset": h("superset")} if "superset" in outs else {})}}


def strip_policy_env():
    for k in [k for k in os.environ if k.startswith("MEDCEA_POLICY_")]:
        del os.environ[k]


def committed_targets(d, state_path, commit=None):
    """--resume's reference (review 4.2a): every target compiled from the committed version
    itself (the state document's rows composed with the git skeleton, which the resume's gate
    found equal to the accepted one, through a simulated host file), saved in DIR/reference;
    DIR/digests.json from that compile. Never from the current defaults.yaml: git may lag."""
    strip_policy_env()
    os.makedirs(d, mode=0o700, exist_ok=True)
    state = load_json(state_path)
    host_path = os.path.join(d, "committed.yaml")
    try:
        with open(host_path, "w", encoding="utf-8") as f:
            f.write(source.host_file_text(state, commit or "unknown", now()))
        base = compile_all([], host_file=host_path)
    except source.SourceError as e:
        print(f"the committed version cannot be composed: {e}", file=sys.stderr)
        return 1
    save(os.path.join(d, "reference"), base)
    dg = digests_of(base, commit)
    with open(os.path.join(d, "digests.json"), "w", encoding="utf-8") as f:
        json.dump(dg, f, sort_keys=True)
    print(json.dumps({"targets": len(base), "routes_digest": dg["routes"], "entries_digest": state.get("entries_digest"),
                      "skeleton_digest": (state.get("accepted") or {}).get("digest")}, sort_keys=True))
    return 0


def bootstrap_targets(d, from_host=False, commit=None, state_path=None):
    strip_policy_env()
    if state_path and not from_host:
        return committed_targets(d, state_path, commit)
    if from_host:
        ref = os.path.join(d, "reference")
        base_dir = ref if os.path.isdir(ref) else os.path.join(d, "defaults")
        what = "the committed version" if base_dir == ref else "defaults.yaml"
        if not os.path.isdir(base_dir):
            die(f"{base_dir} is missing: run bootstrap-targets --out {d} first")
        if source.read_host_file() is None:
            die("no state/policy-applied.yaml to compile", 1)
        host = compile_all([], host_file=source.HOST_FILE)
        save(os.path.join(d, "host"), host)
        diff = compare(load_saved(base_dir), host)
        if diff:
            print(f"the version is committed but state/policy-applied.yaml compiles differently from {what}: "
                  f"{diff[0]} ({diff[1]})", file=sys.stderr)
            return 1
        print(f"[policy] state/policy-applied.yaml compiles to exactly what {what} compiles to ({len(host)} targets)")
        return 0
    os.makedirs(d, mode=0o700, exist_ok=True)
    data = source.factory()
    v1 = source.compose(source.skeleton(data), source.entries_and_waivers(data))
    v1_path = os.path.join(d, "v1.yaml")
    with open(v1_path, "w", encoding="utf-8") as f:
        f.write(source.yaml.safe_dump(v1, sort_keys=False, allow_unicode=True, width=1000))
    state = simulate_state(data, commit)
    with open(os.path.join(d, "sim-state.json"), "w", encoding="utf-8") as f:
        json.dump(state, f)
    host_path = os.path.join(d, "host.yaml")
    with open(host_path, "w", encoding="utf-8") as f:
        f.write(source.host_file_text(state, commit or "unknown", now(), data))
    base = compile_all(["--defaults"])
    save(os.path.join(d, "defaults"), base)
    for label, how in (("version 1 composed (v1.yaml)", lambda: compile_all(["--file", v1_path, "--label", "version-1"])),
                       ("the simulated host file", lambda: compile_all([], host_file=host_path))):
        try:
            outs = how()
        except source.SourceError as e:
            print(f"v1 must compile to exactly what defaults.yaml compiles to: {label} cannot be read: {e}", file=sys.stderr)
            return 1
        diff = compare(base, outs)
        if diff:
            print(f"v1 must compile to exactly what defaults.yaml compiles to: {diff[0]} differs ({label}): {diff[1]}",
                  file=sys.stderr)
            return 1
    dg = digests_of(base, commit)
    with open(os.path.join(d, "digests.json"), "w", encoding="utf-8") as f:
        json.dump(dg, f, sort_keys=True)
    print(json.dumps({"targets": len(base), "routes_digest": dg["routes"], "entries_digest": state["entries_digest"],
                      "skeleton_digest": state["accepted"]["digest"]}, sort_keys=True))
    return 0


# ── health's iampolicy (design §14.4.14) ──────────────────────────────────────────────
def _apply_running(holders):
    for pid in re.findall(r"\d+", holders or ""):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                if b"apps/iam/apply.sh" in f.read():
                    return True
        except OSError:
            continue
    return False


def _gate_against(acc_body, git, rows):
    try:
        return explain.gate(acc_body, git, rows)
    except Exception as e:   # a compile error: reported, never fatal to health
        return {"verdict": "error", "error": f"{type(e).__name__}: {e}"}


def classify_sql(p, without_iam=False):
    """health-check iamgrants' tail (Phase 5, G4), run in the verify session after `grants
    verified`, so :iam_enforcing is the verify SQL's own. Prints `mode|t|f`, and under
    IAM_DB_ROLES=false `unclassified|<count>|<objects>` when a relation of the member schemas
    is in no group: I15's classification query of grants._enforce_asserts, but a row, never an
    exception (a WARN; under true the verify SQL already raises it). Read-only."""
    from compiler import grants
    members = grants._array(sorted(o for o in grants.member_objects(p) if not (without_iam and grants._iam(o))))
    return f"""-- health-check iamgrants (Phase 5, G4): read-only, after the verify SQL
SELECT 'mode|' || :'iam_enforcing';
\\if :iam_enforcing
\\else
SELECT 'unclassified|' || pg_catalog.count(*) || '|'
       || pg_catalog.string_agg(pg_catalog.quote_ident(n.nspname) || '.' || pg_catalog.quote_ident(c.relname), ', '
                                ORDER BY n.nspname, c.relname)
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname IN ({grants._in_list(grants.member_schemas(without_iam))}) AND c.relkind IN ('r', 'v', 'm', 'p', 'f')
       AND NOT (c.oid = ANY (SELECT pg_catalog.to_regclass(x) FROM pg_catalog.unnest({members}) x WHERE pg_catalog.to_regclass(x) IS NOT NULL))
    HAVING pg_catalog.count(*) > 0;
\\endif
"""


def health(state, host_file, holders="", policy_port="absent", today=None, live=None):
    """[(STATUS, detail)] for iampolicy. live: iam-api's /healthz on :8083 (IAM 4.3) when
    policy_port is "true": its applied_version must be the database's (FAIL), its
    skeleton_digest the accepted one (WARN: the pod ships another skeleton)."""
    today = today or datetime.date.today()
    st = state.get("state") if isinstance(state, dict) else None
    if st == "none" or st is None:
        return [("SKIP", (state or {}).get("detail") or "no migration 008c: ./apps/database/deploy.sh")]
    if st == "unreachable":
        return [("FAIL", f"PostgreSQL is not Ready: {state.get('detail') or ''}".strip())]
    out = []
    if st == "partial":
        out.append(("FAIL", "policy versions exist but none is applied: ./apps/iam/apply.sh --status"))
    for level, detail in source.host_file_problems(state, host_file):
        out.append((level, detail))
    sysas = bool((state.get("system_functions") or {}).get("system_as"))
    q = queued_count(os.path.join(os.path.dirname(host_file), "seed-facts.jsonl"))
    if q > 0 and sysas:
        out.append(("WARN", f"{q} account fact(s) not yet recorded: the next deploy flushes them"))
    if st == "empty":
        out.append(("FAIL", "no applied version: a widening git change is not gated until version 1 exists; "
                            "./apps/iam/deploy.sh bootstraps it"))
        return out
    if not str(st).startswith("version-"):
        return out
    v = state.get("version")
    git = source.factory()
    acc = state.get("accepted") or {}
    rows = source.state_rows(state)
    opens = [o for o in state.get("open_versions") or [] if o.get("kind") in OPEN_KINDS]
    if source.skeleton_digest(git) != acc.get("digest"):
        g = _gate_against(acc.get("body") or {}, git, rows)
        if g["verdict"] == "widening":
            # IAM 4.4: still a FAIL (a deploy refuses it), even when a version proposes it
            prop = [o for o in opens if o.get("kind") == "skeleton" and o.get("skeleton_digest") == source.skeleton_digest(git)]
            # health-check.sh cuts a detail at 160 characters: with a proposal the base is shorter,
            # so the whole instruction fits up to version 99999 (tests/test_health_policy.py).
            # IAM 4.5 (design §14.8.8): an approved proposal is applied by apply.sh N, whose
            # gate exception admits exactly this digest
            if prop and prop[0].get("status") == "approved":
                n = prop[0].get("version")
                out.append(("FAIL", f"the git skeleton widens: a deploy refuses it (approved as version {n}: "
                                    f"./apps/iam/apply.sh {n} --by <you>)"))
            else:
                out.append(("FAIL", (
                    f"the git skeleton widens: a deploy refuses it (proposed as version {prop[0].get('version')}, "
                    f"{prop[0].get('status')}: put HEAD back at the accepted skeleton; the proposal waits on its branch)"
                    if prop else "the git skeleton widens over the accepted one: a deploy would refuse it (cli.py skeleton-gate)")))
        elif g["verdict"] == "error":
            out.append(("FAIL", f"the skeleton gate could not be computed: {g['error']}"))
        else:
            try:
                errs = explain.checker_errors(git, rows)
            except Exception as e:   # reported, never fatal to health
                errs = [f"{type(e).__name__}: {e}"]
            if errs:
                out.append(("FAIL", f"the git skeleton narrows but fails the checker with the applied matrix "
                                    f"({len(errs)} violation(s): {errs[0]}): a deploy would refuse it"))
            elif acc.get("reviewed_by_version") is not None:
                # IAM 4.5 (design §14.8.4 step 2): the accepted skeleton is an applied skeleton
                # version; HEAD back at the older one would be accepted with no review
                out.append(("WARN", f"git skeleton narrows: a deploy would undo skeleton version "
                                    f"{acc.get('reviewed_by_version')}; keep its commit on the deployed branch"))
            else:
                out.append(("WARN", "the git skeleton narrows: accepted at the next deploy"))
    for a in state.get("accepts") or []:
        # IAM 4.5 (design §14.8.8): an accept names the skeleton version qa approved only when
        # that version really is one, applied (or since superseded), proposing exactly this
        # digest; a forged summary is recomputed like any other accept
        if (a.get("reviewed_by_version") is not None and a.get("rv_kind") == "skeleton"
                and a.get("rv_status") in ("applied", "superseded") and a.get("rv_skeleton") == a.get("to")):
            continue
        if not isinstance(a.get("from_body"), dict) or not isinstance(a.get("to_body"), dict):
            out.append(("FAIL", f"skeleton {str(a.get('to'))[:12]} accepted at event {a.get('event_id')}: "
                                "a body is missing, the accept cannot be recomputed"))
            continue
        g = _gate_against(a["from_body"], a["to_body"],
                          source.state_rows({"entries": a.get("entries") or [], "waivers": a.get("waivers") or []}))
        if g["verdict"] in ("widening", "error"):
            out.append(("FAIL", f"skeleton {str(a.get('to'))[:12]} was accepted at event {a.get('event_id')} "
                                f"but widens over {str(a.get('from'))[:12]}"))
    last = state.get("last_apply_event") or {}
    running = False
    if last.get("event") == "apply_started":
        running = _apply_running(holders)
        if running:
            out.append(("WARN", "an apply is in progress"))
        else:
            out.append(("FAIL", f"version {v} was committed but its apply did not record its end "
                                "(./apps/iam/apply.sh --resume --by <you>)"))
    elif last.get("event") == "partial_apply":
        # IAM 4.5 (design §14.8.6): the revert bundle files partial_apply {reverting} under the
        # version it put back; until the revert's rollout and records finish, it is unfinished
        if last.get("outcome") == "reverting":
            out.append(("FAIL", f"version {v}: a revert is unfinished (./apps/iam/apply.sh --resume --by <you>)"))
        else:
            out.append(("FAIL", f"version {v}: partial_apply (./apps/iam/apply.sh --resume --by <you>)"))
    for x in state.get("disputed_not_superseded") or []:
        out.append(("FAIL", f"version {x} is disputed and not superseded"))
    for b in state.get("break_glass_open") or []:
        out.append(("FAIL", f"policy break-glass event {b.get('event_id')} ({b.get('reason')}) still open for "
                            f"{', '.join(b.get('open') or [])}: deploy them again without MEDCEA_POLICY_FILE"))
    for f in state.get("audit_findings") or []:
        # IAM 4.5 (design §14.8.8): while apply.sh runs, the applied version's events are
        # apply_started without its applied yet, which audit_versions() reports as 'sequence';
        # "an apply is in progress" already says it (partial_apply keeps both FAILs)
        if running and f.get("finding") == "sequence" and f.get("version") == v:
            continue
        out.append(("FAIL", f"audit_versions(): version {f.get('version')} {f.get('finding')}"))
    if state.get("chain_ok") is False:
        out.append(("FAIL", "verify_chain() is false: the policy history was altered"))
    for w in state.get("waivers_review") or []:
        try:
            rb = datetime.date.fromisoformat(str(w.get("review_by"))[:10])
        except ValueError:
            continue
        if rb < today:
            out.append(("FAIL", f"waiver {w.get('id')}: review_by {rb} has passed"))
        elif rb <= today + datetime.timedelta(days=30):
            out.append(("WARN", f"waiver {w.get('id')}: review_by {rb} is within 30 days"))
    for e in state.get("last_events") or []:
        if e.get("event") in ("apply_started", "applied", "bootstrap_applied", "apply_reverted"):
            if e.get("version") != v:
                out.append(("FAIL", f"the latest apply event ({e.get('event')} {e.get('event_id')}) names version "
                                    f"{e.get('version')}, the applied one is {v}"))
            break
    unconfirmed = [u for u in state.get("unconfirmed") or [] if u.get("version") == v]
    if policy_port == "true" and isinstance(live, dict):
        if live.get("applied_version") != v:
            out.append(("FAIL", f"the Policy UI (iam-api :8083) reports applied version {live.get('applied_version')}, "
                                f"the database {v} (kubectl -n medcea logs deployment/iam-api)"))
        if live.get("skeleton_digest") != acc.get("digest"):
            out.append(("WARN", f"the Policy UI ships skeleton {str(live.get('skeleton_digest'))[:12]}, the accepted one "
                                f"is {str(acc.get('digest'))[:12]} (./apps/iam/deploy.sh)"))
        # Phase 5 (G8): the compiler the Policy UI runs (ConfigMap iam-compiler) against this
        # checkout's; applied_version above is a database read, not proof of a loaded routes.json
        # (that is health-check iamloaded's)
        if live.get("compiler_digest") and live.get("compiler_digest") != source.compiler_digest():
            out.append(("WARN", f"the Policy UI compiles with compiler {str(live.get('compiler_digest'))[:12]}, this "
                                f"checkout's is {source.compiler_digest()[:12]} (./apps/iam/deploy.sh)"))
    if unconfirmed and policy_port == "true":
        out.append(("WARN", f"version {v} ({state.get('kind')}) is not confirmed by qa yet (the Policy UI)"))
    for o in state.get("open_versions") or []:
        if (o.get("age_days") or 0) > 7:
            out.append(("WARN", f"version {o.get('version')} is {o.get('status')} for {o.get('age_days')} days"))
    for o in opens:   # IAM 4.5 (design §14.8.8): an approved version waits for the host operator
        if o.get("status") == "approved":
            n = o.get("version")
            out.append(("WARN", f"version {n} ({o.get('kind')}) is approved again after a reverted apply: "
                                f"./apps/iam/apply.sh {n} --by <you>" if o.get("reverted") else
                                f"version {n} ({o.get('kind')}) is approved: ./apps/iam/apply.sh {n} --by <you> applies it"))
        if o.get("kind") == "skeleton" and o.get("diff_from") and o.get("diff_from") != acc.get("digest"):
            out.append(("WARN", f"skeleton version {o.get('version')} was proposed against skeleton "
                                f"{str(o.get('diff_from'))[:12]}, the accepted one is now {str(acc.get('digest'))[:12]}: "
                                "return it and propose again"))
    if state.get("apply_deferred_open"):
        out.append(("WARN", f"{len(state['apply_deferred_open'])} deferred apply target(s) open "
                            "(./apps/iam/apply.sh --resume --by <you> re-renders them)"))
    for r in state.get("reverted_unreviewed") or []:
        # §14.4.14: a pure narrowing access-api applied while the reverted version was live
        # stays applied after the revert; qa reviews it in the User Manager's Decisions tab
        out.append(("WARN", f"{r.get('unreviewed')} account decision(s) made while version {r.get('version')} was "
                            f"applied are not reviewed by qa yet (reverted at event {r.get('event_id')}: "
                            "the User Manager's Decisions tab)"))
    fac = source.entries_and_waivers(git)
    if source.entries_digest(state.get("kind"), state.get("groups"), state.get("roles"),
                             fac["entries"], fac["waivers"]) != state.get("entries_digest"):
        out.append(("WARN", "git may lag: defaults.yaml's matrix is not the applied one (cli.py export-applied)"))
    if not out:
        if unconfirmed and policy_port != "true":
            out.append(("OK", f"version {v} ({state.get('kind')}), qa confirms it in the Policy UI once it exists (IAM 4.3)"))
        else:
            out.append(("OK", f"version {v} ({state.get('kind')}), skeleton {str(acc.get('digest'))[:12]}, host file matches"))
    return out


# ── --status ───────────────────────────────────────────────────────────────────────────
def status_text(state, gate=None, gate_rc=None, live_routes=None, live_mqtt=None, host_file=None):
    host_file = host_file or source.HOST_FILE
    L = []
    st = state.get("state")
    L.append(f"state: {st}" + (f" ({state.get('detail')})" if state.get("detail") else ""))
    if str(st).startswith("version-"):
        v = state.get("version")
        if state.get("confirmed_at"):
            conf = f"confirmed {state['confirmed_at']}"
        elif state.get("disputed_at"):
            conf = f"DISPUTED {state['disputed_at']}"
        elif state.get("kind") in ("bootstrap", "rollback"):
            conf = "waiting for qa to confirm it (Policy UI → Confirm)"
        else:
            conf = "approved by qa"
        last = state.get("last_apply_event") or {}
        L.append(f"applied: version {v} ({state.get('kind')}), claimed by person {state.get('claimed_by_person') or '-'}, "
                 f"{conf}; last apply event {last.get('event', '-')} {last.get('event_id', '')} {last.get('at', '')}".rstrip())
        L.append(f"entries digest: {state.get('entries_digest')}")
    for o in state.get("open_versions") or []:
        L.append(f"open: version {o.get('version')} {o.get('kind')} {o.get('status')}, {o.get('age_days')} day(s)")
    if state.get("last_events"):
        L.append("last policy events:")
        for e in state["last_events"]:
            L.append(f"  {e.get('event_id'):>6} {str(e.get('at'))[:19]} {e.get('event')} "
                     f"v{e.get('version') if e.get('version') is not None else '-'} {e.get('actor') or ''}".rstrip())
    for f in state.get("audit_findings") or []:
        L.append(f"audit_versions(): version {f.get('version')} {f.get('finding')}")
    if "chain_ok" in state:
        L.append(f"verify_chain(): {'ok' if state.get('chain_ok') else 'FAILED'}")
    acc = state.get("accepted") or {}
    git_digest = source.skeleton_digest(source.factory())
    if acc.get("digest"):
        if gate is not None and gate.get("verdict"):
            verdict = gate["verdict"]
        elif gate_rc == 3:
            verdict = "widening"
        else:
            verdict = "equal" if git_digest == acc.get("digest") else "unknown"
        prop = [o for o in state.get("open_versions") or [] if o.get("kind") == "skeleton"]
        if prop and prop[0].get("status") == "approved" and prop[0].get("skeleton_digest") == git_digest:
            # IAM 4.5 (design §14.8.8): the approved version is what applies it
            n = prop[0].get("version")
            widening = (f"WIDENING: refused by every deploy; approved as skeleton version {n}: "
                        f"./apps/iam/apply.sh {n} --by <you> applies it")
        elif prop:
            widening = (f"WIDENING: refused until a skeleton version proposing it is approved and applied; skeleton "
                        f"version {prop[0].get('version')} ({prop[0].get('status')}) proposes "
                        f"{str(prop[0].get('skeleton_digest'))[:12]}")
        else:
            widening = ("WIDENING: refused until a skeleton version proposing it is approved and applied; propose it "
                        "from a commit: ./apps/iam/apply.sh --propose-skeleton --from-git <rev>")
        if acc.get("reviewed_by_version") is not None:
            narrowing = f"narrowing: a deploy would accept it and undo skeleton version {acc['reviewed_by_version']}"
        else:
            narrowing = "narrowing: accepted at the next deploy"
        word = {"equal": "equal", "narrowing": narrowing,
                "widening": widening,
                "refused": "REFUSED: it narrows, but fails the checker with the applied matrix (fix it in git)"}.get(verdict, verdict)
        L.append(f"skeleton: accepted {acc['digest'][:12]}, git {git_digest[:12]}: {word}")
    else:
        L.append(f"skeleton: none accepted yet, git {git_digest[:12]}")
    try:
        src = source.read_host_file(host_file)
        if src is None:
            L.append("host file: absent (state/policy-applied.yaml)")
        else:
            h = src.header
            L.append(f"host file: version {h['version']} ({h['kind']}), written {h['written_at']} at {h['git_commit']}")
            if str(st).startswith("version-"):
                probs = source.host_file_problems(state, host_file)
                L.append("host file: " + ("matches the database" if not probs else "; ".join(d for _, d in probs)))
    except source.SourceError as e:
        L.append(f"host file: FAILS its checks: {e}")
    if live_routes is not None or live_mqtt is not None:
        strip_policy_env()
        rc, text, _ = _cli(["compile", "routes"])
        crt = json.loads(text).get("digest") if rc == 0 else None
        rc, text, _ = _cli(["compile", "mqtt"])
        cmq = json.loads(text).get("digest") if rc == 0 else None
        for what, live, comp in (("routes", live_routes, crt), ("mqtt", live_mqtt, cmq)):
            if not live:
                L.append(f"live {what}: not deployed (no ConfigMap medcea-iam-lib)")
            else:
                L.append(f"live {what}: {live[:12]} " + ("= the compile" if live == comp else
                                                          f"differs from the compile {str(comp)[:12]}: ./deploy-infra.sh"))
    if str(st).startswith("version-"):
        fac = source.entries_and_waivers(source.factory())
        if source.entries_digest(state.get("kind"), state.get("groups"), state.get("roles"),
                                 fac["entries"], fac["waivers"]) != state.get("entries_digest"):
            L.append("git: may lag (defaults.yaml's matrix is not the applied one: cli.py export-applied)")
    for b in state.get("break_glass_open") or []:
        L.append(f"BREAK-GLASS open: event {b.get('event_id')} ({b.get('reason')}), components {', '.join(b.get('open') or [])}")
    seeded = state.get("seeded") or {}
    q = queued_count(os.path.join(os.path.dirname(host_file), "seed-facts.jsonl"))
    L.append(f"seed facts: {max(q, 0)} queued, {sum(len(v) for v in seeded.values())} recorded")
    return "\n".join(L)


# ── main ───────────────────────────────────────────────────────────────────────────────
def main(argv=None):
    ap = argparse.ArgumentParser(prog="apply_check.py", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("can-approve")
    c.add_argument("--dual-control", required=True)
    c.add_argument("--accounts", required=True)
    c = sub.add_parser("accounts")
    c.add_argument("--dir", required=True)
    c.add_argument("--skeleton", help="the skeleton (JSON) whose includes expand the roles (account-skeleton)")
    c = sub.add_parser("by-user")
    c.add_argument("--in", dest="inp", required=True)
    c.add_argument("--username", required=True)
    c = sub.add_parser("seed-fact")
    c.add_argument("--history", required=True)
    c.add_argument("--sub", required=True)
    c = sub.add_parser("seed-build")
    c.add_argument("--fact", required=True)
    c.add_argument("--username", required=True)
    c.add_argument("--sub", required=True)
    c.add_argument("--role", default="")
    c.add_argument("--person-id", default="")
    c.add_argument("--by", default="deploy-infra.sh")
    c = sub.add_parser("seed-queue")
    c.add_argument("--in", dest="inp", required=True)
    c = sub.add_parser("simulate-state")
    c.add_argument("--out", required=True)
    c.add_argument("--commit")
    c = sub.add_parser("bundle-sql")
    c.add_argument("--kind", required=True, choices=["bootstrap", "change", "skeleton", "rollback", "revert"])
    c.add_argument("--state", help="bootstrap: the simulated state document")
    c.add_argument("--stage", help="change, skeleton, rollback, revert: apply.sh's stage directory (stage)")
    c.add_argument("--doc", help="change, skeleton, rollback: the version document (approval-sql)")
    c.add_argument("--by-sub", default="")
    c.add_argument("--by-person", default="")
    c.add_argument("--log", default="")
    c.add_argument("--out", required=True)
    c.add_argument("--commit")
    c.add_argument("--digests")
    c.add_argument("--reason-file", help="rollback: the reason; revert: why")
    c.add_argument("--failed", default="", help="revert: the failed targets, one per line, in a file")
    c = sub.add_parser("approval-sql")
    c.add_argument("--version", type=int, required=True)
    c.add_argument("--audit", action="store_true")
    c.add_argument("--out", required=True)
    c = sub.add_parser("audit-doc")
    c.add_argument("--in", dest="inp", required=True)
    c.add_argument("--issuer", required=True)
    c.add_argument("--out", required=True)
    c = sub.add_parser("gate")
    c.add_argument("--state", required=True)
    c.add_argument("--doc", required=True)
    c.add_argument("--gate", required=True)
    c.add_argument("--gate-rc", type=int, required=True)
    c.add_argument("--mode", choices=["apply", "rollback"], required=True)
    c.add_argument("--version", type=int, required=True)
    c.add_argument("--head-has", choices=["yes", "no", "unknown"], default="unknown")
    c = sub.add_parser("state-check")
    c.add_argument("--state", required=True)
    c.add_argument("--doc", required=True)
    c.add_argument("--version", type=int, required=True)
    c = sub.add_parser("account-skeleton")
    c.add_argument("--state", required=True)
    c.add_argument("--doc")
    c.add_argument("--out", required=True)
    c = sub.add_parser("host-file")
    c.add_argument("--state", required=True)
    c.add_argument("--check-only", action="store_true")
    c = sub.add_parser("stage")
    c.add_argument("--state", required=True)
    c.add_argument("--doc", required=True)
    c.add_argument("--out", required=True)
    c.add_argument("--commit", required=True)
    c.add_argument("--rollback", type=int, help="K: stage the rollback version to K")
    c.add_argument("--next", type=int, help="with --rollback: the number the rollback version gets")
    c = sub.add_parser("diff-check")
    c.add_argument("--state", required=True)
    c.add_argument("--doc", required=True)
    c.add_argument("--stage", required=True)
    c = sub.add_parser("check-approval")
    c.add_argument("--doc", required=True)
    c.add_argument("--kc", required=True)
    c.add_argument("--jwks", required=True)
    c.add_argument("--stage", required=True)
    c.add_argument("--issuer", required=True)
    c.add_argument("--mode", choices=["apply", "rollback"], required=True)
    c.add_argument("--version", type=int, required=True)
    c.add_argument("--state")
    c.add_argument("--out")
    c = sub.add_parser("signing-keys")
    c.add_argument("--in", dest="inp", required=True)
    c.add_argument("--out", required=True)
    c = sub.add_parser("rollback-check")
    c.add_argument("--state", required=True)
    c.add_argument("--doc", required=True)
    c.add_argument("--jwks", required=True)
    c.add_argument("--version", type=int, required=True)
    c = sub.add_parser("rollback-diff")
    c.add_argument("--state", required=True)
    c.add_argument("--stage", required=True)
    c = sub.add_parser("verify-conf")
    c.add_argument("--out", required=True)
    c.add_argument("--drop", action="append", default=[])
    c = sub.add_parser("health-results")
    c.add_argument("--in", dest="inp", required=True)
    c.add_argument("--out", required=True)
    c = sub.add_parser("verify-judge")
    c.add_argument("--baseline", required=True)
    c.add_argument("--now", required=True)
    c.add_argument("--drop", action="append", default=[])
    c = sub.add_parser("verify-host")
    c.add_argument("--reference", required=True)
    c = sub.add_parser("deferred-check")
    c.add_argument("--command", required=True)
    c = sub.add_parser("deferred-reason")
    c.add_argument("--command", required=True)
    c = sub.add_parser("apply-extra")
    c.add_argument("--doc", required=True)
    c.add_argument("--stage", required=True)
    c.add_argument("--mode", choices=["apply", "rollback"], required=True)
    c.add_argument("--attempts", type=int, required=True)
    c.add_argument("--check")
    c.add_argument("--deferred", action="append", default=[])
    c.add_argument("--pre-failing", action="append", default=[])
    c.add_argument("--reason-file")
    c.add_argument("--set", action="append", default=[], help="KEY=JSON, merged last")
    c.add_argument("--out", required=True)
    c = sub.add_parser("apply-record")
    c.add_argument("--event", required=True)
    c.add_argument("--state", required=True)
    c.add_argument("--by-sub", required=True)
    c.add_argument("--by-person", required=True)
    c.add_argument("--log", default="")
    c.add_argument("--commit", required=True)
    c.add_argument("--chain-head", default="")
    c.add_argument("--digests")
    c.add_argument("--resumed", action="store_true")
    c.add_argument("--extra", help="IAM 4.5: a JSON object merged into the payload last")
    c.add_argument("--out", required=True)
    c = sub.add_parser("bootstrap-targets")
    c.add_argument("--out", required=True)
    c.add_argument("--source", choices=["host"])
    c.add_argument("--state", help="the committed version's state document: the reference (--resume)")
    c.add_argument("--commit")
    c = sub.add_parser("health")
    c.add_argument("--state", required=True)
    c.add_argument("--host-file", default=None)
    c.add_argument("--holders", default="")
    c.add_argument("--policy-port", choices=["true", "false", "absent"], default="absent")
    c.add_argument("--live", help="iam-api's /healthz JSON on :8083 (IAM 4.3)")
    c = sub.add_parser("classify-sql")
    c.add_argument("--without-iam", action="store_true")
    c = sub.add_parser("status")
    c.add_argument("--state", required=True)
    c.add_argument("--gate")
    c.add_argument("--gate-rc", type=int)
    c.add_argument("--live-routes")
    c.add_argument("--live-mqtt")
    c = sub.add_parser("owners")
    c.add_argument("--deploys", action="store_true")
    c.add_argument("--scoped", action="store_true")
    c = sub.add_parser("propose")
    c.add_argument("--state", required=True)
    c.add_argument("--rev", required=True)
    c.add_argument("--commit", required=True)
    c.add_argument("--by-sub", required=True)
    c.add_argument("--by-person", required=True)
    c.add_argument("--reason-file", required=True)
    c.add_argument("--version", type=int, required=True)
    c.add_argument("--out")
    c = sub.add_parser("open-version")
    c.add_argument("--state", required=True)
    c = sub.add_parser("withdraw-sql")
    c.add_argument("--version", type=int, required=True)
    c.add_argument("--reason-file", required=True)
    c.add_argument("--out", required=True)
    c = sub.add_parser("maker-warn")
    c.add_argument("--dual-control", required=True)
    c.add_argument("--roles", required=True)
    c.add_argument("--username", required=True)
    c = sub.add_parser("deferred-record")
    c.add_argument("--state", required=True)
    c.add_argument("--target", required=True)
    c.add_argument("--reason", required=True)
    c.add_argument("--command", required=True)
    c.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    try:
        if a.cmd == "can-approve":
            for line in can_approve(load_json(a.dual_control), load_json(a.accounts)):
                print(line)
            return 0
        if a.cmd == "accounts":
            print(json.dumps(accounts_from_dir(a.dir, load_json(a.skeleton) if a.skeleton else None), sort_keys=True))
            return 0
        if a.cmd == "by-user":
            sub_, pid = by_user(load_json(a.inp), a.username)
            print(f"{sub_}\t{pid}")
            return 0
        if a.cmd == "seed-fact":
            for f in (load_json(a.history).get("seeded") or {}).get(a.sub) or []:
                print(f"{f.get('event_id')} {f.get('fact')} {f.get('username')} {f.get('role') or '-'} {f.get('person_id') or '-'}")
            return 0
        if a.cmd == "seed-build":
            print(json.dumps(seed_fact(a.fact, a.username, a.sub, a.role, a.person_id, a.by), sort_keys=True))
            return 0
        if a.cmd == "seed-queue":
            with open(a.inp, encoding="utf-8") as f:
                print(seed_queue(f.read().splitlines()))
            return 0
        if a.cmd == "simulate-state":
            with open(a.out, "w", encoding="utf-8") as f:
                json.dump(simulate_state(commit=a.commit), f)
            return 0
        if a.cmd == "bundle-sql":
            digests = load_json(a.digests) if a.digests else None
            reason = ""
            if a.reason_file:
                with open(a.reason_file, encoding="utf-8") as f:
                    reason = f.read()
            if a.kind == "bootstrap":
                if not a.state:
                    die("bundle-sql --kind bootstrap needs --state")
                pre, post = bundle_sql(load_json(a.state), a.by_sub, a.by_person, a.log, a.commit, digests)
            elif a.kind == "revert":
                meta = load_json(os.path.join(a.stage, "stage.json"))
                hdr = source.read_host_file(os.path.join(a.stage, "prev.yaml")).header
                if int(hdr["version"]) != meta["prev_version"] or hdr["entries_digest"] != meta["prev_entries_digest"]:
                    die("prev.yaml is not the version the stage read as applied", 1)
                failed = []
                if a.failed:
                    with open(a.failed, encoding="utf-8") as f:
                        failed = [l.strip() for l in f if l.strip()]
                if not reason.strip():
                    die("the revert needs its reason")
                pre, post = revert_bundle_sql(hdr, meta["version"], reason, failed)
            else:
                meta = load_json(os.path.join(a.stage, "stage.json"))
                if meta.get("kind") != a.kind:
                    die(f"the stage holds a {meta.get('kind')} version, not {a.kind}", 1)
                hdr = source.read_host_file(os.path.join(a.stage, "staged", "policy-applied.yaml")).header
                if int(hdr["version"]) != meta["version"] or hdr["entries_digest"] != meta["entries_digest"]:
                    die("the staged file is not the staged version", 1)
                doc = load_doc(a.doc)
                v = doc.get("version") or {}
                skel = None
                if a.kind == "skeleton":
                    sk = (doc.get("skeletons") or {}).get(v.get("skeleton_digest")) or {}
                    skel = (v.get("skeleton_digest"), source.skeleton(sk.get("body") or {}), sk.get("git_commit") or "unknown")
                    if source.skeleton_digest(skel[1]) != skel[0]:
                        die("the stored body of the proposed skeleton does not hash to its digest", 1)
                rb = None
                if a.kind == "rollback":
                    if not reason.strip():
                        die("a rollback needs its reason")
                    rb = (meta["rollback_of"], meta["prev_version"], reason)
                pre, post = apply_bundle_sql(a.kind, meta, a.by_sub, a.by_person, a.log, a.commit, digests,
                                             v.get("diff_digest"), skel, rb)
            os.makedirs(a.out, mode=0o700, exist_ok=True)
            for name, text in (("pre.sql", pre), ("post.sql", post)):
                fd = os.open(os.path.join(a.out, name), os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(text)
            return 0
        if a.cmd == "apply-record":
            if not UUID.fullmatch(a.by_sub):
                die(f"--by-sub {a.by_sub!r} is not a uuid")
            digests = load_json(a.digests) if a.digests else {}
            extra = load_json(a.extra) if a.extra else None
            if extra is not None:
                if not isinstance(extra, dict):
                    die("--extra is not a JSON object")
                if not str(extra.get("reason") or "").strip():   # else the bootstrap's text goes into the chain
                    die(f"--extra of {a.event} has no reason: every 4.5 record says its own")
                sha, of = log_sha256(a.log)
                extra = dict({"apply_log_sha256": sha, "apply_log_sha256_of": of}, **extra)
            payload = apply_payload(load_json(a.state), a.by_sub, a.by_person, a.log, a.commit, a.chain_head,
                                    digests, a.resumed, extra)
            with open(a.out, "w", encoding="utf-8") as f:
                f.write(record_sql(a.event, payload))
            return 0
        if a.cmd == "approval-sql":
            _write_private(os.path.abspath(a.out), approval_doc_sql(a.version, a.audit))
            return 0
        if a.cmd == "audit-doc":
            d = load_doc(a.inp)
            n = (d.get("version") or {}).get("version")
            d["audit_findings"] = [f for f in d.get("audit_findings") or [] if f.get("version") == n]
            d["issuer"] = a.issuer
            _write_private(os.path.abspath(a.out), json.dumps(d))
            return 0
        if a.cmd == "gate":
            g = load_json(a.gate) if os.path.getsize(a.gate) else {}
            rc, lines = gate_decision(load_json(a.state), load_doc(a.doc), g, a.gate_rc, a.mode, a.version,
                                      {"yes": True, "no": False}.get(a.head_has))
            for l in lines:
                print(l, file=sys.stderr if l.startswith(("ERROR", "WARNING")) else sys.stdout)
            return rc
        if a.cmd == "state-check":
            rc, lines = state_problems(load_json(a.state), load_doc(a.doc), a.version)
            for l in lines:
                print(l, file=sys.stderr if l.startswith(("ERROR", "  #")) and rc else sys.stdout)
            return rc
        if a.cmd == "account-skeleton":
            _write_private(os.path.abspath(a.out), json.dumps(account_skeleton(load_json(a.state),
                                                                               load_doc(a.doc) if a.doc else None)))
            return 0
        if a.cmd == "host-file":
            line, text = host_file_first(load_json(a.state), a.check_only)
            if text is not None:
                source.write_host_file(source.HOST_FILE, text)
            print(line, file=sys.stderr if line.startswith("WARNING") else sys.stdout)
            return 0
        if a.cmd == "stage":
            state, doc = load_json(a.state), load_doc(a.doc)
            sim = None
            if a.rollback:
                if not a.next:
                    die("stage --rollback needs --next")
                sim = rollback_sim(state, doc, a.next, a.rollback)
            rc, lines = stage(state, doc, a.out, a.commit, sim=sim)
            for l in lines:
                print(("ERROR: " + l) if rc else l, file=sys.stderr if rc else sys.stdout)
            return rc
        if a.cmd == "diff-check":
            rc, lines = diff_check(load_json(a.state), load_doc(a.doc), a.stage)
            for l in lines:
                print(("ERROR: " + l) if rc else l, file=sys.stderr if rc else sys.stdout)
            return rc
        if a.cmd == "check-approval":
            refusals, warnings, notes, info = check_approval(load_doc(a.doc), a.kc, load_json(a.jwks), a.stage, a.issuer,
                                                             a.mode, a.version, load_json(a.state) if a.state else None)
            for l in notes:
                print(l)
            for l in warnings:
                print(f"WARNING: {l}", file=sys.stderr)
            for l in refusals:
                print(f"REFUSED: {l}", file=sys.stderr)
            if a.out:
                _write_private(os.path.abspath(a.out), json.dumps(info, sort_keys=True))
            return 1 if refusals else 0
        if a.cmd == "signing-keys":
            keys = signing_keys(load_json(a.inp))
            if not keys["keys"]:
                die("the realm publishes no RS256 signing key")
            _write_private(os.path.abspath(a.out), json.dumps(keys, sort_keys=True))
            return 0
        if a.cmd == "rollback-check":
            state, doc = load_json(a.state), load_doc(a.doc)
            refusals, warnings = rollback_problems(doc, state, load_json(a.jwks), a.version)
            if not refusals:
                more, notes = rollback_bound(doc, a.version)
                refusals += more
                warnings += notes
            for l in warnings:
                print(f"WARNING: {l}", file=sys.stderr)
            for l in pending_problems(doc, refuse=False):
                print(l if l.startswith("  #") else f"WARNING: {l}", file=sys.stderr)
            for l in refusals:
                print(f"ERROR: {l}", file=sys.stderr)
            return 1 if refusals else 0
        if a.cmd == "rollback-diff":
            for l in rollback_diff_lines(load_json(a.state), a.stage):
                print(l)
            return 0
        if a.cmd == "verify-conf":
            _write_private(os.path.abspath(a.out), verify_conf(a.drop))
            return 0
        if a.cmd == "health-results":
            with open(a.inp, encoding="utf-8", errors="replace") as f:
                res = health_results(f.read())
            _write_private(os.path.abspath(a.out), json.dumps(res, sort_keys=True))
            for t, s in sorted(res.items()):
                print(f"{t} {s}")
            return 0
        if a.cmd == "verify-judge":
            want = [t for t, _ in VERIFY_CHECKS if t not in a.drop]
            for t in verify_judge(load_json(a.baseline), load_json(a.now), want):
                print(t)
            return 0
        if a.cmd == "verify-host":
            return verify_host(a.reference)
        if a.cmd == "deferred-check":
            c = DEFER_CHECK.get(a.command)
            if c:
                print(c)
            return 0
        if a.cmd == "deferred-reason":
            print("\n".join(DEFER_REASON.get(a.command, ("its scoped mode deferred it (exit 4)",
                                                         "once that command succeeds"))))
            return 0
        if a.cmd == "apply-extra":
            reason = None
            if a.reason_file:
                with open(a.reason_file, encoding="utf-8") as f:
                    reason = f.read()
            x = apply_extra(load_doc(a.doc), load_json(os.path.join(a.stage, "stage.json")), a.mode, a.attempts,
                            load_json(a.check) if a.check else None, a.deferred, a.pre_failing, reason)
            for kv in a.set:
                k, _, val = kv.partition("=")
                x[k] = json.loads(val)
            _write_private(os.path.abspath(a.out), json.dumps(x, sort_keys=True))
            return 0
        if a.cmd == "deferred-record":
            with open(a.out, "w", encoding="utf-8") as f:
                f.write(record_sql("apply_deferred", deferred_payload(load_json(a.state), a.target, a.reason,
                                                                      a.command)))
            return 0
        if a.cmd == "propose":
            state = load_json(a.state)
            with open(a.reason_file, encoding="utf-8") as f:
                reason = f.read()
            git = git_policy(a.rev)
            if source.skeleton_digest(source.factory()) != (state.get("accepted") or {}).get("digest"):
                print("WARNING: this tree's skeleton is not the accepted one: deploys refuse a widening until HEAD "
                      "is back at the accepted skeleton", file=sys.stderr)
            rc, lines, sql = propose(state, git, a.by_sub, a.by_person, reason, a.commit, a.version)
            if rc:
                print("ERROR: " + "\n".join(lines) + "\nNothing was changed.", file=sys.stderr)
                return rc
            print("\n".join(lines))
            if a.out:
                fd = os.open(a.out, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(sql)
            return 0
        if a.cmd == "open-version":
            o = open_version(load_json(a.state))
            if o:
                print("\t".join(str(x) if x not in (None, "") else "-" for x in (
                    o.get("version"), o.get("kind"), o.get("status"), " ".join(str(o.get("reason") or "").split()),
                    ", ".join(o.get("authors") or []) + (f" (claimed --by person {o['claimed_by_person']})"
                                                         if o.get("claimed_by_person") else ""))))
            return 0
        if a.cmd == "withdraw-sql":
            with open(a.reason_file, encoding="utf-8") as f:
                text = withdraw_sql(a.version, f.read())
            fd = os.open(a.out, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
            return 0
        if a.cmd == "maker-warn":
            names = [r.get("name") for r in load_json(a.roles) if isinstance(r, dict)]
            w = maker_warning(load_json(a.dual_control), names, a.username)
            if w:
                print(w)
            return 0
        if a.cmd == "bootstrap-targets":
            return bootstrap_targets(a.out, a.source == "host", a.commit, a.state)
        if a.cmd == "classify-sql":
            sys.stdout.write(classify_sql(model.load(), a.without_iam))
            return 0
        if a.cmd == "health":
            live = None
            if a.live:
                try:
                    live = json.loads(a.live)
                except ValueError:
                    live = None
            for level, detail in health(load_json(a.state), a.host_file or source.HOST_FILE, a.holders, a.policy_port,
                                        live=live):
                print(f"{level}|{detail}")
            return 0
        if a.cmd == "status":
            gate = load_json(a.gate) if a.gate and os.path.getsize(a.gate) else None
            print(status_text(load_json(a.state), gate, a.gate_rc, a.live_routes, a.live_mqtt))
            return 0
        if a.cmd == "owners":
            if a.deploys:
                for cmd in full_deploys():
                    print(cmd)
                return 0
            if a.scoped:
                for cmd in scoped_commands():
                    print(cmd)
                return 0
            for k, v in sorted(HOST_OWNER.items()):
                print(f"{k}\t{v}")
            for k, v in sorted(TARGET_OWNER.items()):
                print(f"{k}\t{v}")
            return 0
    except source.SourceError as e:
        die(str(e))
    return 2


if __name__ == "__main__":
    sys.exit(main())
