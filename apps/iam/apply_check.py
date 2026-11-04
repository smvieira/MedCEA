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

Not in 4.4: the JWS verification, the eligibility rule and the version-widening check of an
approver's person (design §6.1 step 4 items 1-4: IAM 4.5).
"""
import argparse
import base64
import contextlib
import copy
import datetime
import hashlib
import io
import json
import os
import pwd
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from compiler import explain, model, source  # noqa: E402

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
    if event not in ("bootstrap_applied", "applied", "apply_deferred"):
        die(f"apply-record records bootstrap_applied, applied or apply_deferred, not {event!r}")
    if actor not in ACTORS:
        die(f"bad actor {actor!r}")
    return "\n".join([
        _set("payload", payload),
        f"SELECT medcea_auth._set_internal_actor('{actor}') \\g /dev/null",
        f"SELECT iam_policy._record('{event}', {source._jsonb('payload')});",
        ""])


def apply_payload(state, by_sub, by_person, log, commit, chain_head, digests, resumed=False):
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
    widened = {r for r in g["added"] if not r.startswith("_")}
    barred = sorted((r for r in (body.get("roles") or {}) if closure(body["roles"], r) & widened), key=source._bytes)
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


def digests_of(outs, commit=None):
    """_mark_applied's p_digests from compiled outputs (design §14.4.9)."""
    def h(name):
        rc, text, _ = outs.get(name, (1, "", ""))
        return sha(text) if rc == 0 else None
    routes_doc = json.loads(outs["routes"][1])
    mqtt_doc = json.loads(outs["mqtt"][1])
    return {"git_commit": commit or source.git_commit(), "compiler_digest": source.compiler_digest(),
            "skeleton_digest": source.skeleton_digest(source.factory()),
            "routes": routes_doc.get("digest"), "mqtt": mqtt_doc.get("digest"),
            "grants_document": h("grants-json"), "netpol": h("netpol"),
            "proxy": {n[len("proxy-"):]: h(n) for n in sorted(outs) if n.startswith("proxy-")},
            "tools": {"grafana": h("grafana"), "jupyterhub_allowed": h("jupyterhub-allowed"),
                      "jupyterhub_admin": h("jupyterhub-admin"), "node_red": h("node-red"),
                      "edge_wizard": h("edge-wizard"), "pgadmin": h("pgadmin")}}


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
            # so the whole instruction fits up to version 99999 (tests/test_health_policy.py)
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
            else:
                out.append(("WARN", "the git skeleton narrows: accepted at the next deploy"))
    for a in state.get("accepts") or []:
        if a.get("reviewed_by_version") is not None:
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
    if last.get("event") == "apply_started":
        if _apply_running(holders):
            out.append(("WARN", "an apply is in progress"))
        else:
            out.append(("FAIL", f"version {v} was committed but its apply did not record its end "
                                "(./apps/iam/apply.sh --resume --by <you>)"))
    elif last.get("event") == "partial_apply":
        out.append(("FAIL", f"version {v}: partial_apply (./apps/iam/apply.sh --resume --by <you>)"))
    for x in state.get("disputed_not_superseded") or []:
        out.append(("FAIL", f"version {x} is disputed and not superseded"))
    for b in state.get("break_glass_open") or []:
        out.append(("FAIL", f"policy break-glass event {b.get('event_id')} ({b.get('reason')}) still open for "
                            f"{', '.join(b.get('open') or [])}: deploy them again without MEDCEA_POLICY_FILE"))
    for f in state.get("audit_findings") or []:
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
    if unconfirmed and policy_port == "true":
        out.append(("WARN", f"version {v} ({state.get('kind')}) is not confirmed by qa yet (the Policy UI)"))
    for o in state.get("open_versions") or []:
        if (o.get("age_days") or 0) > 7:
            out.append(("WARN", f"version {o.get('version')} is {o.get('status')} for {o.get('age_days')} days"))
    for o in opens:   # IAM 4.4 (design §14.7.6): nothing approved is applied before 4.5
        if o.get("status") == "approved":
            out.append(("WARN", f"version {o.get('version')} ({o.get('kind')}) is approved; applying it arrives with "
                                f"IAM 4.5 (./apps/iam/apply.sh {o.get('version')})"))
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
            conf = "waiting for qa (4.3)"
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
        widening = "WIDENING: refused until an approved skeleton can be applied (4.5)"
        if prop:
            widening += (f"; skeleton version {prop[0].get('version')} ({prop[0].get('status')}) proposes "
                         f"{str(prop[0].get('skeleton_digest'))[:12]}")
        else:
            widening += "; propose it from a commit: ./apps/iam/apply.sh --propose-skeleton --from-git <rev>"
        word = {"equal": "equal", "narrowing": "narrowing: accepted at the next deploy",
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
    c.add_argument("--kind", required=True)
    c.add_argument("--state", required=True)
    c.add_argument("--by-sub", required=True)
    c.add_argument("--by-person", required=True)
    c.add_argument("--log", default="")
    c.add_argument("--out", required=True)
    c.add_argument("--commit")
    c.add_argument("--digests")
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
            print(json.dumps(accounts_from_dir(a.dir), sort_keys=True))
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
            if a.kind != "bootstrap":
                die(f"bundle-sql --kind {a.kind}: arrives with IAM 4.5")
            digests = load_json(a.digests) if a.digests else None
            pre, post = bundle_sql(load_json(a.state), a.by_sub, a.by_person, a.log, a.commit, digests)
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
            payload = apply_payload(load_json(a.state), a.by_sub, a.by_person, a.log, a.commit, a.chain_head,
                                    digests, a.resumed)
            with open(a.out, "w", encoding="utf-8") as f:
                f.write(record_sql(a.event, payload))
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
