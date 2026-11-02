"""apps/iam/compiler/source.py — where every compile reads the access policy (IAM Phase 4).

The policy is two parts. The **skeleton** (levels, roles, groups, members, routes, network,
tool blocks, constraints, invariants, help text) lives in git, in policy/defaults.yaml. The
**matrix and waivers** become numbered versions in the database; the version in force is
the *applied* one. The host keeps it, composed with the accepted skeleton, in
state/policy-applied.yaml (the **host applied file**), written only under the deploy lock
(infra/lib-policy-source.sh, apps/iam/apply.sh; from slice 4.2a).

resolve(path, defaults) picks the source, in this order (model.load and cli.py both use it):
  1. path (cli.py --file F)   an offline draft or a test; never a deploy script
  2. defaults=True            policy/defaults.yaml (cli.py --defaults, model.load_defaults():
                              the offline tests and the iam-db fixture)
  3. MEDCEA_POLICY_FILE       only with MEDCEA_POLICY_BREAK_GLASS=<reason>; without the reason
                              SourceError (cli.py exits 2). A deploy uses it only after
                              policy_source_init recorded it (break_glass_seen) and pointed it
                              at a snapshot under state/break-glass/; then the exported
                              MEDCEA_POLICY_BREAK_GLASS_SHA256 and MEDCEA_POLICY_ACCEPTED_SKELETON
                              are checked here at every compile (a file edited after the
                              record, or one with another skeleton, is SourceError)
  4. the host applied file    when present; its two header lines must match its own body
                              (skeleton digest, body digest, and the entries digest when no
                              row was dropped), else SourceError. A file this process cannot
                              read is a SourceError too: an unreadable state/ cannot tell "no
                              applied version" from "one we cannot see"
  5. otherwise                policy/defaults.yaml (no applied version on this host), unless
                              state/.policy-versioned exists (VERSIONED_MARK, written with the
                              first host file): a version was applied here, so an absent host
                              file is a SourceError, never a silent defaults.yaml

label(src, label) is the name the route table and role_widening() record (cli.py --label,
else by source: break-glass:<reason>, version-N, the file's basename, defaults.yaml).

The host applied file (IAM 4.2a, design §14.4.3), exactly:
  # medcea-applied: version=N kind=K entries_digest=<64 hex> skeleton_digest=<64 hex> git_commit=<c> written_at=<ts>
  # medcea-applied-body: body_digest=<64 hex> groups=<n> roles=<n> dropped=<n> keys=<64 hex>
  # Written by infra/lib-policy-source.sh (or apps/iam/apply.sh) under the deploy lock from the
  # database's applied version and the accepted skeleton. Do not edit: every compile checks it.
  <the composed policy, yaml.safe_dump>
body_digest covers {matrix, waivers}; groups/roles count the version's own keys; dropped
counts the entry rows the accepted skeleton has no key for; keys is the digest of the
version's sorted group and role keys, so the entries digest is recomputed from the body
whenever the body's keys are still the version's (and nothing was dropped).

The applied state (policy_db_state's JSON document, lib-policy-source.sh):
  state_rows(state)           its entries and waivers as entries_and_waivers() returns them
  waiver_from_row(row)        an iam_policy.waiver row as the YAML spells a waiver
  compose_applied(state)      (policy dict, dropped): the git skeleton (which the gate has
                              made the accepted one) + the applied rows
  expected_body(state)        (body, dropped): {matrix, waivers} the host file must carry,
                              dropped against the accepted body's keys (whatever git says)
  host_file_text(state, ...)  the file's text; host_file_differs(state, path) None|absent|different
  host_file_problems(...)     [(FAIL|WARN, detail)]: the read-only init and health
  write_host_file(path, text) atomic, mode 600 in state/ 700, under a verified lock
  verify_lock()               the Python twin of infra/lib-lock.sh medcea_lock_verify
  git_commit(), compiler_digest()
  break_glass_check(path, state), snapshot_break_glass(path)
  accept_sql/record_sql/seed_flush_sql
                              psql scripts with every value base64 in a psql variable

Pure functions on the YAML's dict form (no database reader yet):
  skeleton(data)              the policy minus matrix, waivers and policy_version
  skeleton_digest(data)       sha256 of the skeleton's canonical JSON (the only place it is
                              computed: the host, never the database or a pod)
  entries_and_waivers(data)   {"entries": [{role, group_code, level, constraint_name}],
                              "waivers": [...]}: one entry per level (iam_policy.entry's rows),
                              N is no row; waivers as in the YAML, `objects` included
  cells_to_yaml(rows, order)  one cell back in its canonical spelling: a list without a
                              constraint, {levels, constraint, applies_to} with one, else the
                              per-level map
  compose(skel, ew, version)  skeleton + entries + waivers -> the policy's dict; policy_version
                              stays the factory file's literal (the routes and MQTT digests do
                              not move for a version that changes nothing they contain)
  pg_jsonb_text(obj)          PostgreSQL's jsonb text output of a JSON value (keys ordered by
                              byte length, then bytes; separators ", " and ": "; non-ASCII kept)
  waiver_row(w)               a YAML waiver in iam_policy.waiver's shape (group -> group_code)
  entries_digest(kind, groups, roles, rows, waivers)
                              iam_policy.entries_digest(v) in Python (migration 008c): sha256 of
                              the jsonb text of {kind, groups, roles, entries, waivers}, entries
                              [role, group, level, constraint] in byte order, waivers by id
  policy_entries_digest(data, kind)
                              the same for a whole policy dict (its skeleton's group and role
                              keys, its matrix and waivers): what a bootstrap of it stores
"""
import base64
import copy
import datetime
import hashlib
import json
import os
import re
import stat
import subprocess

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULTS = os.path.normpath(os.path.join(HERE, "..", "policy", "defaults.yaml"))
REPO_ROOT = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
STATE_DIR = os.path.join(REPO_ROOT, "state")
HOST_FILE = os.path.join(STATE_DIR, "policy-applied.yaml")
SEED_FILE = os.path.join(STATE_DIR, "seed-facts.jsonl")
BREAK_GLASS_DIR = os.path.join(STATE_DIR, "break-glass")
# Written with the first host file and kept: "a version was applied on this host", so an
# absent host file is an error, never a silent defaults.yaml (review 4.2a). Moved only by
# policy_state_retire (purge-data, reset, uninstall, rollback: the database went with it)
# or by a write-mode init that found the database answering "no applied version".
VERSIONED_MARK = ".policy-versioned"
LOCK_FILE = os.path.join(REPO_ROOT, ".medcea.lock")

NOT_SKELETON = ("matrix", "waivers", "policy_version")
KINDS = ("bootstrap", "change", "skeleton", "rollback")
HEADER = "# medcea-applied:"
_HEADER_KEYS = ("version", "kind", "entries_digest", "skeleton_digest", "git_commit", "written_at")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
BODY_HEADER = "# medcea-applied-body:"
_BODY_KEYS = ("body_digest", "groups", "roles", "dropped", "keys")
HOST_COMMENT = ("# Written by infra/lib-policy-source.sh (or apps/iam/apply.sh) under the deploy lock from the\n"
                "# database's applied version and the accepted skeleton. Do not edit: every compile checks it.\n")
# Keys that only carry prose anywhere in the YAML: the skeleton gate ignores them when it
# compares a section (design §14.4.5), so a help-text change is never a widening.
TEXT_KEYS = ("help", "why", "summary", "label", "description", "title", "about")
# The groups whose cells decide who approves policy and account changes: break-glass may
# not touch them (design §3.5, critique sec-9).
DUAL_CONTROL_GROUPS = ("iam_policy", "iam_users")
RESTORE = "restore it with ./apps/iam/apply.sh --resume --by <you>"


class SourceError(Exception):
    """The policy's source is ambiguous or unsafe; cli.py prints it and exits 2."""


class Source:
    """Where a policy came from. kind: file | defaults | break-glass | host."""

    def __init__(self, kind, path, data, version=None, reason=None, header=None):
        self.kind, self.path, self.data = kind, path, data
        self.version, self.reason, self.header = version, reason, header


# ── reading ──────────────────────────────────────────────────────────────────────────
def _read_yaml(path, what):
    try:
        with open(path) as f:
            text = f.read()
    except OSError as e:
        raise SourceError(f"cannot read {what} {path}: {e.strerror}") from None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise SourceError(f"{what} {path} is not YAML: {e}") from None
    if not isinstance(data, dict):
        raise SourceError(f"{what} {path} is not a policy (a YAML mapping)")
    return text, data


def factory():
    """policy/defaults.yaml as a dict: the factory content."""
    return _read_yaml(DEFAULTS, "the factory policy")[1]


def parse_header(text):
    """{key: value} of the host file's first line, or SourceError."""
    first = text.split("\n", 1)[0]
    if not first.startswith(HEADER):
        raise SourceError(f"the host applied file has no '{HEADER}' header line")
    fields = {}
    for tok in first[len(HEADER):].split():
        k, eq, v = tok.partition("=")
        if not eq or k in fields:
            raise SourceError(f"the host applied file's header has a malformed field {tok!r}")
        fields[k] = v
    missing = [k for k in _HEADER_KEYS if not fields.get(k)]
    if missing:
        raise SourceError(f"the host applied file's header lacks {', '.join(missing)}")
    if not re.fullmatch(r"[1-9][0-9]*", fields["version"]):
        raise SourceError(f"the host applied file's header names version {fields['version']!r}")
    if fields["kind"] not in KINDS:
        raise SourceError(f"the host applied file's header names kind {fields['kind']!r}")
    for k in ("entries_digest", "skeleton_digest"):
        if not _HEX64.match(fields[k]):
            raise SourceError(f"the host applied file's header: {k} is not a sha256")
    return fields


def _host_file_present(path):
    """True/False, or SourceError when the file's directory cannot be searched."""
    try:
        os.stat(path)
        return True
    except FileNotFoundError:
        return False
    except NotADirectoryError:
        return False
    except PermissionError:
        raise SourceError(f"cannot tell whether {path} exists (permission denied on its directory): "
                          "run as the account that deploys the platform") from None


def parse_body_header(text):
    """{key: value} of the host file's second line, or SourceError."""
    lines = text.split("\n", 2)
    second = lines[1] if len(lines) > 1 else ""
    if not second.startswith(BODY_HEADER):
        raise SourceError(f"the host applied file has no '{BODY_HEADER}' line")
    fields = {}
    for tok in second[len(BODY_HEADER):].split():
        k, eq, v = tok.partition("=")
        if not eq or k in fields or k not in _BODY_KEYS:
            raise SourceError(f"the host applied file's body line has a malformed field {tok!r}")
        fields[k] = v
    missing = [k for k in _BODY_KEYS if not fields.get(k)]
    if missing:
        raise SourceError(f"the host applied file's body line lacks {', '.join(missing)}")
    for k in ("body_digest", "keys"):
        if not _HEX64.match(fields[k]):
            raise SourceError(f"the host applied file's body line: {k} is not a sha256")
    for k in ("groups", "roles", "dropped"):
        if not re.fullmatch(r"0|[1-9][0-9]*", fields[k]):
            raise SourceError(f"the host applied file's body line: {k} is not a count")
        fields[k] = int(fields[k])
    return fields


def body_digest(data):
    """sha256 of the canonical {matrix, waivers} of a policy dict or a body."""
    return hashlib.sha256(canonical({"matrix": data.get("matrix") or {},
                                     "waivers": data.get("waivers") or []})).hexdigest()


def keys_digest(groups, roles):
    """sha256 of a version's sorted group and role keys (line 2's `keys`)."""
    return hashlib.sha256(canonical({"groups": sorted(groups or [], key=_bytes),
                                     "roles": sorted(roles or [], key=_bytes)})).hexdigest()


def read_host_file(path=None):
    """The host applied file as a Source, None when there is none. Its two header lines are
    checked against its own body (design §14.4.3): any mismatch is a SourceError."""
    path = path or HOST_FILE
    if not _host_file_present(path):
        return None
    text, data = _read_yaml(path, "the host applied file")
    header = parse_header(text)
    bad = f"{path}: its header does not match its body (edited by hand, or truncated): {RESTORE}"
    if skeleton_digest(data) != header["skeleton_digest"]:
        raise SourceError(bad + " (skeleton_digest)")
    body = parse_body_header(text)
    if body_digest(data) != body["body_digest"]:
        raise SourceError(bad + " (body_digest)")
    if body["dropped"] == 0 and keys_digest(data.get("resource_groups"), data.get("roles")) == body["keys"]:
        ew = entries_and_waivers(data)
        if entries_digest(header["kind"], list(data.get("resource_groups") or {}), list(data.get("roles") or {}),
                          ew["entries"], ew["waivers"]) != header["entries_digest"]:
            raise SourceError(bad + " (entries_digest)")
    return Source("host", path, data, version=int(header["version"]), header=dict(header, **{"body": body}))


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve(path=None, defaults=False, env=None, host_file=None):
    """The Source of this compile (the order in the module docstring)."""
    env = os.environ if env is None else env
    if path and defaults:
        raise SourceError("--file and --defaults are two sources: give one")
    if path:
        return Source("file", path, _read_yaml(path, "policy file")[1])
    if defaults:
        return Source("defaults", DEFAULTS, factory())
    override = env.get("MEDCEA_POLICY_FILE", "")
    if override:
        reason = env.get("MEDCEA_POLICY_BREAK_GLASS", "").strip()
        if not reason:
            raise SourceError("MEDCEA_POLICY_FILE is a break-glass override: "
                              "set MEDCEA_POLICY_BREAK_GLASS=<reason>, or unset it")
        want = env.get("MEDCEA_POLICY_BREAK_GLASS_SHA256", "")
        if want:
            try:
                have = file_sha256(override)
            except OSError as e:
                raise SourceError(f"cannot read break-glass policy file {override}: {e.strerror}") from None
            if have != want:
                raise SourceError(f"break-glass policy file {override} is not the one recorded "
                                  f"(sha256 {have[:12]}, recorded {want[:12]}): it changed after its record; re-run the deploy")
        data = _read_yaml(override, "break-glass policy file")[1]
        acc = env.get("MEDCEA_POLICY_ACCEPTED_SKELETON", "")
        if acc and skeleton_digest(data) != acc:
            raise SourceError("break-glass changes only the matrix and the waivers; a skeleton change goes "
                              "through git and the skeleton gate")
        return Source("break-glass", override, data, reason=reason)
    host = read_host_file(host_file)
    if host:
        return host
    mark = os.path.join(os.path.dirname(host_file or HOST_FILE), VERSIONED_MARK)
    if _host_file_present(mark):
        raise SourceError(f"{host_file or HOST_FILE} is absent, but a policy version was applied on this host "
                          f"({os.path.basename(mark)} in its directory): nothing is compiled from defaults.yaml. "
                          "The next deploy writes the file again from the database (docs/manual, admin: Policy source)")
    return Source("defaults", DEFAULTS, factory())


def label(src, given=None, warn=None):
    """The source name recorded in routes.json and role_widening(). `warn` gets the stderr
    note for a --file without --label (a file name is no version)."""
    if given:
        return given
    if src.kind == "break-glass":
        return f"break-glass:{src.reason}"
    if src.kind == "host":
        return f"version-{src.version}"
    if src.kind == "file":
        if warn:
            warn("label from file name: not for deploys (give --label)")
        return os.path.basename(src.path)
    return "defaults.yaml"


def describe(src):
    """One line for a human: where this compile read the policy."""
    if src.kind == "host":
        return f"source: version {src.version} ({src.header['kind']}), {src.path}"
    if src.kind == "break-glass":
        return f"source: BREAK-GLASS {src.path} ({src.reason})"
    if src.kind == "file":
        return f"source: {src.path} (--file)"
    return "source: defaults.yaml (no applied version on this host)"


# ── skeleton, entries, compose ─────────────────────────────────────────────────────────
def canonical(obj):
    """Canonical JSON bytes (sorted keys, no spaces, UTF-8)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def skeleton(data):
    return {k: copy.deepcopy(v) for k, v in data.items() if k not in NOT_SKELETON}


def skeleton_digest(data):
    return hashlib.sha256(canonical(skeleton(data))).hexdigest()


def _cell_levels(c):
    """[(level, constraint or None)] of a YAML cell, as model.Policy.cell reads it."""
    if isinstance(c, list):
        return [(l, None) for l in c]
    con = c.get("constraint")
    if isinstance(con, dict):
        per = dict(con)
    elif con:
        per = {l: con for l in c.get("applies_to", c["levels"])}
    else:
        per = {}
    return [(l, per.get(l)) for l in c["levels"]]


def entries_and_waivers(data):
    entries = []
    for g, row in (data.get("matrix") or {}).items():
        for r, c in (row or {}).items():
            for l, con in _cell_levels(c):
                entries.append({"role": r, "group_code": g, "level": l, "constraint_name": con})
    return {"entries": entries, "waivers": copy.deepcopy(data.get("waivers") or [])}


def cells_to_yaml(rows, order):
    """One cell from its entry rows [(level, constraint or None)], levels in `order`."""
    rank = {l: i for i, l in enumerate(order)}
    rows = sorted(rows, key=lambda x: rank.get(x[0], len(rank)))
    levels = [l for l, _ in rows]
    cons = {l: c for l, c in rows if c}
    if not cons:
        return levels
    distinct = set(cons.values())
    if len(distinct) == 1:
        cell = {"levels": levels, "constraint": distinct.pop()}
        if len(cons) != len(levels):
            cell["applies_to"] = [l for l in levels if l in cons]
        return cell
    return {"levels": levels, "constraint": cons}


def _matrix(groups, roles, order, entries, drop_unknown=False):
    """(matrix, dropped) from entry rows: groups and roles in the given order, levels in
    `order`. A row naming a key outside groups/roles raises, or with drop_unknown is left
    out and counted."""
    by_cell = {}
    for e in entries:
        by_cell.setdefault((e["group_code"], e["role"]), []).append((e["level"], e["constraint_name"]))
    gs, rs = set(groups), set(roles)
    unknown = sorted(k for k in by_cell if k[0] not in gs or k[1] not in rs)
    dropped = 0
    if unknown:
        if not drop_unknown:
            raise SourceError(f"entries name keys the skeleton lacks: {unknown[:5]}")
        dropped = sum(len(by_cell[k]) for k in unknown)
    matrix = {}
    for g in groups:
        row = {r: cells_to_yaml(by_cell[(g, r)], order) for r in roles if (g, r) in by_cell}
        if row:
            matrix[g] = row
    return matrix, dropped


def compose_counted(skel, ew, policy_version=None, drop_unknown=False):
    """(policy dict, dropped): compose() that, with drop_unknown, leaves out and counts the
    entry rows naming a group or role the skeleton lacks instead of raising."""
    out = copy.deepcopy(skel)
    matrix, dropped = _matrix(list(skel.get("resource_groups") or {}), list(skel.get("roles") or {}),
                              list(skel.get("levels") or {}), ew["entries"], drop_unknown)
    out["policy_version"] = factory().get("policy_version") if policy_version is None else policy_version
    out["matrix"] = matrix
    out["waivers"] = copy.deepcopy(ew["waivers"])
    return out, dropped


def compose(skel, ew, policy_version=None, drop_unknown=False):
    """The policy dict of a skeleton and an entries_and_waivers() document. The matrix lists
    groups in the skeleton's resource_groups order and roles in its roles order. A row naming
    a key the skeleton lacks raises SourceError, unless drop_unknown (then it is left out)."""
    return compose_counted(skel, ew, policy_version, drop_unknown)[0]


# ── the entries digest (migration 008c, iam_policy.entries_digest) ────────────────────
def _pg_str(x):
    r"""A JSON string as PostgreSQL's escape_json() writes it: \" \\ \b \f \n \r \t, other
    control characters as \u00xx (lower-case hex), everything else (non-ASCII too) as is."""
    out = ['"']
    for ch in x:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def pg_jsonb_text(obj):
    """The text of `obj` as a PostgreSQL jsonb value prints (jsonb::text): object keys
    sorted by UTF-8 length, then bytes (jsonb's own key order), ", " and ": " separators.
    Integers only (no floats: the digest's documents hold none)."""
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, str):
        return _pg_str(obj)
    if isinstance(obj, (list, tuple)):
        return "[" + ", ".join(pg_jsonb_text(x) for x in obj) + "]"
    if isinstance(obj, dict):
        keys = sorted(obj, key=lambda k: (len(k.encode("utf-8")), k.encode("utf-8")))
        return "{" + ", ".join(f"{_pg_str(k)}: {pg_jsonb_text(obj[k])}" for k in keys) + "}"
    raise TypeError(f"pg_jsonb_text: unsupported {type(obj).__name__}")


def _iso(d):
    if d is None:
        return None
    return d.isoformat() if hasattr(d, "isoformat") else str(d)


def waiver_row(w):
    """A waiver as iam_policy.waiver stores it (every column but version): the YAML's
    `group` is the column group_code, levels and objects lists, review_by an ISO date."""
    return {"id": w.get("id"), "invariant": w.get("invariant"), "subject": w.get("subject"),
            "group_code": w.get("group_code", w.get("group")), "target": w.get("target"),
            "levels": list(w.get("levels") or []), "review_by": _iso(w.get("review_by")),
            "rationale": w.get("rationale"), "controls": w.get("controls"),
            "objects": list(w.get("objects") or [])}


def _bytes(x):
    return (x or "").encode("utf-8")


def entries_digest(kind, groups, roles, rows, waivers):
    """iam_policy.entries_digest(v) for a version of `kind` whose skeleton has the group and
    role keys `groups`, `roles` (None: unknown), entry rows [{role, group_code, level,
    constraint_name}] and waivers (YAML or table shape)."""
    ents = sorted(([r["role"], r["group_code"], r["level"], r.get("constraint_name")] for r in rows),
                  key=lambda e: (_bytes(e[0]), _bytes(e[1]), _bytes(e[2])))
    wvs = sorted((waiver_row(w) for w in waivers), key=lambda w: _bytes(w["id"]))
    doc = {"kind": kind,
           "groups": None if groups is None else sorted(groups, key=_bytes),
           "roles": None if roles is None else sorted(roles, key=_bytes),
           "entries": ents, "waivers": wvs}
    return hashlib.sha256(pg_jsonb_text(doc).encode("utf-8")).hexdigest()


def policy_entries_digest(data, kind="bootstrap"):
    """entries_digest() of a whole policy dict: what _build_version stores for it as a
    version of `kind` under its own skeleton."""
    ew = entries_and_waivers(data)
    return entries_digest(kind, list(data.get("resource_groups") or {}), list(data.get("roles") or {}),
                          ew["entries"], ew["waivers"])


# ── the applied state (IAM 4.2a: policy_db_state's document, design §14.4.3/§14.4.4) ──
def waiver_from_row(row):
    """An iam_policy.waiver row (psql's JSON: group_code, review_by 'YYYY-MM-DD', levels and
    objects arrays) as the YAML spells a waiver, in the YAML's key order."""
    rb = row.get("review_by")
    if isinstance(rb, (datetime.date, datetime.datetime)):
        rb = rb.isoformat()[:10]
    elif isinstance(rb, str):
        rb = rb[:10]
    return {"id": row.get("id"), "invariant": row.get("invariant"), "subject": row.get("subject"),
            "group": row.get("group_code", row.get("group")), "target": row.get("target"),
            "levels": [str(l).strip() for l in (row.get("levels") or [])],
            "objects": list(row.get("objects") or []), "review_by": rb,
            "rationale": row.get("rationale"), "controls": row.get("controls")}


def state_rows(state):
    """The applied version's rows of a state document, as entries_and_waivers() returns them:
    entries [{role, group_code, level, constraint_name}], waivers in YAML shape ordered by id
    in byte order."""
    entries = [{"role": e["role"], "group_code": e["group_code"], "level": str(e["level"]).strip(),
                "constraint_name": e.get("constraint_name") or None} for e in (state.get("entries") or [])]
    waivers = [waiver_from_row(w) for w in sorted(state.get("waivers") or [], key=lambda w: _bytes(w.get("id")))]
    return {"entries": entries, "waivers": waivers}


def _need_version(state):
    if not isinstance(state, dict) or not str(state.get("state", "")).startswith("version-"):
        raise SourceError(f"no applied version in the state document (state {state.get('state') if isinstance(state, dict) else None!r})")
    acc = state.get("accepted") or {}
    if not _HEX64.match(str(acc.get("digest") or "")) or not isinstance(acc.get("body"), dict):
        raise SourceError("the state document has no accepted skeleton")
    return acc


def compose_applied(state, data=None):
    """(policy dict, dropped) the host file holds: the git tree's skeleton (data, default
    factory()) with the applied version's rows. Only after the gate: the git skeleton's
    digest must be the accepted one (its key order is the YAML's; the database's jsonb body
    sorts keys, which could reorder compiled outputs)."""
    acc = _need_version(state)
    skel = skeleton(factory() if data is None else data)
    if skeleton_digest(skel) != acc["digest"]:
        raise SourceError("internal: compose before the gate (the git skeleton is not the accepted one)")
    return compose_counted(skel, state_rows(state), drop_unknown=True)


def expected_body(state):
    """({matrix, waivers}, dropped) the host file must carry for this state: the applied rows
    dropped against the accepted body's group and role keys (defined whatever git says).
    Levels in the factory's order (jsonb loses the YAML's)."""
    acc = _need_version(state)
    body = acc["body"]
    known = list(factory().get("levels") or {})
    order = known + sorted(l for l in (body.get("levels") or {}) if l not in known)
    rows = state_rows(state)
    matrix, dropped = _matrix(list(body.get("resource_groups") or {}), list(body.get("roles") or {}), order,
                              rows["entries"], drop_unknown=True)
    return {"matrix": matrix, "waivers": rows["waivers"]}, dropped


def host_file_text(state, git_commit, written_at, data=None):
    """The host applied file's text for a state document (design §14.4.3)."""
    composed, dropped = compose_applied(state, data)
    for k in ("version", "kind", "entries_digest"):
        if state.get(k) in (None, ""):
            raise SourceError(f"the state document lacks the applied version's {k}")
    if state["kind"] not in KINDS or not _HEX64.match(str(state["entries_digest"])):
        raise SourceError("the state document's applied version is malformed")
    if not re.fullmatch(r"[0-9a-f]{7,40}(-dirty)?|unknown", git_commit or ""):
        raise SourceError(f"git_commit {git_commit!r} is not a commit")
    groups, roles = state.get("groups") or [], state.get("roles") or []
    head = (f"{HEADER} version={int(state['version'])} kind={state['kind']} entries_digest={state['entries_digest']} "
            f"skeleton_digest={skeleton_digest(composed)} git_commit={git_commit} written_at={written_at}\n"
            f"{BODY_HEADER} body_digest={body_digest(composed)} groups={len(groups)} roles={len(roles)} "
            f"dropped={dropped} keys={keys_digest(groups, roles)}\n")
    return head + HOST_COMMENT + yaml.safe_dump(composed, sort_keys=False, allow_unicode=True, width=1000)


def host_file_differs(state, path=None):
    """None when the host file is this state's, else 'absent' or 'different' (line 1's
    version, kind, entries_digest or skeleton_digest, line 2's body_digest, or a file that
    fails its own checks). written_at and git_commit alone are no difference."""
    path = path or HOST_FILE
    try:
        src = read_host_file(path)
    except SourceError:
        if _host_file_present(path):
            return "different"
        raise
    if src is None:
        return "absent"
    h = src.header
    acc = _need_version(state)
    if (int(h["version"]) != int(state["version"]) or h["kind"] != state["kind"]
            or h["entries_digest"] != state["entries_digest"] or h["skeleton_digest"] != acc["digest"]
            or h["body"] != _body_line(state)):
        return "different"
    return None


def _body_line(state):
    """Line 2's fields (parse_body_header's shape) a host file of this state carries."""
    want, dropped = expected_body(state)
    groups, roles = state.get("groups") or [], state.get("roles") or []
    return {"body_digest": body_digest(want), "groups": len(groups), "roles": len(roles), "dropped": dropped,
            "keys": keys_digest(groups, roles)}


def host_file_problems(state, path=None):
    """[(FAIL|WARN, detail)] of the host file against a state document (the read-only init
    and health, design §14.4.14); never prints the body."""
    path = path or HOST_FILE
    st = state.get("state") if isinstance(state, dict) else None
    out = []
    try:
        present = _host_file_present(path)
    except SourceError as e:
        return [("FAIL", str(e))]
    if st in ("none", "empty"):
        if present:
            out.append(("FAIL", f"state/policy-applied.yaml exists but the database has no applied version ({st})"))
        elif os.path.lexists(os.path.join(os.path.dirname(path), VERSIONED_MARK)):
            out.append(("WARN", f"a version was applied on this host before (state/{VERSIONED_MARK}) but the database "
                                f"has none ({st}): compiles outside a deploy refuse until the next deploy retires the mark"))
        return out
    if not str(st or "").startswith("version-"):
        return out
    if not present:
        return [("FAIL", f"version {state.get('version')} is applied but state/policy-applied.yaml is absent: the next deploy writes it")]
    try:
        src = read_host_file(path)
    except SourceError as e:
        return [("FAIL", str(e))]
    h = src.header
    for k in ("version", "kind", "entries_digest"):
        if str(h[k]) != str(state.get(k)):
            out.append(("FAIL", f"state/policy-applied.yaml names {k} {h[k]}, the database {state.get(k)}"))
    acc = (state.get("accepted") or {}).get("digest")
    if h["skeleton_digest"] != acc:
        out.append(("FAIL", f"state/policy-applied.yaml's skeleton {h['skeleton_digest'][:12]} is not the accepted {str(acc)[:12]}"))
    want, dropped = expected_body(state)
    have = {"matrix": src.data.get("matrix") or {}, "waivers": src.data.get("waivers") or []}
    if have != want or h["body"]["body_digest"] != body_digest(want):
        out.append(("FAIL", "state/policy-applied.yaml differs from the applied version: the next deploy rewrites it; "
                            "until then edge compiles read it"))
    elif h["body"] != _body_line(state):
        out.append(("FAIL", "state/policy-applied.yaml's body line (groups, roles, dropped, keys) is not the applied "
                            "version's: the next deploy rewrites it"))
    if dropped:
        out.append(("WARN", f"{dropped} entry row(s) of version {state.get('version')} name a group or role the accepted skeleton dropped"))
    return out


# ── the deploy lock and the state directory ─────────────────────────────────────────
def _ppid(pid):
    with open(f"/proc/{pid}/stat") as f:
        text = f.read()
    return int(text[text.rindex(")") + 2:].split()[1])


def verify_lock(env=None, lock_file=None):
    """The Python twin of infra/lib-lock.sh medcea_lock_verify (without its flock probe,
    which bash has run): MEDCEA_LOCK_HELD names a live process that is this one or an
    ancestor and has the lock file open on fd 9. SourceError otherwise."""
    env = os.environ if env is None else env
    lock_file = os.path.realpath(lock_file or LOCK_FILE)
    held = env.get("MEDCEA_LOCK_HELD", "")
    why = f"the deploy lock is not held by this run (MEDCEA_LOCK_HELD={held or '(unset)'})"
    if not re.fullmatch(r"[1-9][0-9]*", held):
        raise SourceError(why)
    pid, p = int(held), os.getpid()
    try:
        while p != pid:
            if p <= 1:
                raise SourceError(why + ": not an ancestor of this process")
            p = _ppid(p)
        fd9 = os.readlink(f"/proc/{pid}/fd/9")
    except (OSError, ValueError, IndexError):
        raise SourceError(why + ": no live holder of " + lock_file) from None
    if os.path.realpath(fd9) != lock_file:
        raise SourceError(why + f": its fd 9 is not {lock_file}")


def _state_dir(d=None, create=True):
    """state/ (or a directory under it) owned by this uid with mode 700; created 700 when
    missing (never chmods one it did not create)."""
    d = d or STATE_DIR
    try:
        st = os.stat(d)
    except FileNotFoundError:
        if not create:
            return d
        os.mkdir(d, 0o700)
        os.chmod(d, 0o700)   # the umask may have narrowed mkdir's mode; this one is ours
        return d
    if not stat.S_ISDIR(st.st_mode):
        raise SourceError(f"{d} is not a directory")
    if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise SourceError(f"{os.path.relpath(d, REPO_ROOT)}/ belongs to uid {st.st_uid} or has mode "
                          f"{stat.S_IMODE(st.st_mode):o}: run as the account that deploys the platform, or fix it by hand")
    return d


def _write_new(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def write_host_file(path, text, env=None):
    """Write the host applied file atomically under a verified lock: state/ 700, the file
    600, a temp file then a rename, both fsynced; re-read and compared. Never prints it."""
    verify_lock(env)
    d = _state_dir(os.path.dirname(path))
    try:
        st = os.stat(path)
        if st.st_uid != os.getuid():
            raise SourceError(f"{path} belongs to uid {st.st_uid}: run as the account that deploys the platform")
    except FileNotFoundError:
        pass
    tmp = os.path.join(d, f".policy-applied.yaml.{os.getpid()}")
    try:
        _write_new(tmp, text.encode("utf-8"))
        os.replace(tmp, path)
    except FileExistsError:
        raise SourceError(f"{tmp} exists: another writer, or a leftover of a crash (remove it)") from None
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    dfd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    with open(path, encoding="utf-8") as f:
        if f.read() != text:
            raise SourceError(f"{path} does not read back as written")
    read_host_file(path)
    mark = os.path.join(d, VERSIONED_MARK)
    if not _host_file_present(mark):
        _write_new(mark, b"a policy version was applied on this host: an absent policy-applied.yaml is an error\n")


def snapshot_break_glass(path, env=None, now=None):
    """Copy a break-glass file into state/break-glass/<UTC ts>-<pid>.yaml (600, O_EXCL)
    under a verified lock: every compile of the run reads the copy. Returns its path."""
    verify_lock(env)
    _state_dir(STATE_DIR)
    d = _state_dir(BREAK_GLASS_DIR)
    with open(path, "rb") as f:
        data = f.read()
    ts = (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    out = os.path.join(d, f"{ts}-{os.getpid()}.yaml")
    _write_new(out, data)
    return out


def break_glass_check(path, state):
    """{sha256, skeleton_digest, entries_digest, problems} of a break-glass file against the
    applied state (design §3.5): its skeleton must be the accepted one, and its cells and
    waivers on the dual-control groups must be the applied version's."""
    data = _read_yaml(path, "break-glass policy file")[1]
    acc = _need_version(state)
    problems = []
    if skeleton_digest(data) != acc["digest"]:
        problems.append("break-glass changes only the matrix and the waivers; a skeleton change goes through git and "
                        "the skeleton gate (its skeleton is not the accepted one)")
    ew, rows = entries_and_waivers(data), state_rows(state)

    def cells(entries):
        return sorted((e["role"], e["group_code"], e["level"], e.get("constraint_name") or None)
                      for e in entries if e["group_code"] in DUAL_CONTROL_GROUPS)

    def waivers(ws):
        return sorted((json.dumps(waiver_row(w), sort_keys=True) for w in ws
                       if (w.get("group_code") or w.get("group")) in DUAL_CONTROL_GROUPS))
    if cells(ew["entries"]) != cells(rows["entries"]) or waivers(ew["waivers"]) != waivers(rows["waivers"]):
        problems.append("break-glass cannot change who approves policy or account changes (the cells and waivers of "
                        + " and ".join(DUAL_CONTROL_GROUPS) + " must stay the applied version's)")
    return {"sha256": file_sha256(path), "skeleton_digest": skeleton_digest(data),
            "entries_digest": policy_entries_digest(data, "change"), "problems": problems}


# ── provenance ─────────────────────────────────────────────────────────────────────
def git_commit(root=None):
    """HEAD of the repository, with -dirty when apps/iam has uncommitted changes; unknown
    without git or .git."""
    root = root or REPO_ROOT
    if not os.path.exists(os.path.join(root, ".git")):
        return "unknown"
    try:
        head = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=30)
        if head.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", head.stdout.strip()):
            return "unknown"
        dirty = subprocess.run(["git", "-C", root, "status", "--porcelain", "--", "apps/iam"],
                               capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return head.stdout.strip() + ("-dirty" if dirty.returncode != 0 or dirty.stdout.strip() else "")


def compiler_digest():
    """sha256 over the compiler's own sources (name and content of compiler/*.py)."""
    h = hashlib.sha256()
    for name in sorted(f for f in os.listdir(HERE) if f.endswith(".py")):
        h.update(name.encode() + b"\0")
        with open(os.path.join(HERE, name), "rb") as f:
            h.update(f.read() + b"\0")
    return h.hexdigest()


def fact_id(fact):
    """The content hash of an account_seeded fact (migration 008c _record): sha256 of the
    jsonb text of {fact, username, sub, role, person_id}, a missing key as null."""
    doc = {k: fact.get(k) for k in ("fact", "username", "sub", "role", "person_id")}
    return hashlib.sha256(pg_jsonb_text(doc).encode("utf-8")).hexdigest()


# ── psql scripts (values base64 in \set variables: no quoting, nothing on argv) ──────
def _b64(obj):
    text = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _jsonb(var):
    return f"pg_catalog.convert_from(pg_catalog.decode(:'{var}', 'base64'), 'UTF8')::jsonb"


def _text(var):
    return f"pg_catalog.convert_from(pg_catalog.decode(:'{var}', 'base64'), 'UTF8')"


def accept_sql(gate, commit, compiler):
    """The skeleton gate's accept as a deploy (system:deploy), one transaction (psql -1):
    _accept_skeleton then _sync_skeleton with the git skeleton's canonical body."""
    body = gate["body"]
    digest = hashlib.sha256(canonical(body)).hexdigest()
    if digest != gate["git_digest"]:
        raise SourceError("internal: the gate's body is not its digest")
    summary = {"narrowed": gate.get("narrowed") or [], "unchanged": gate.get("unchanged") or [],
               "reviewed_by_version": None}
    return "\n".join([
        f"\\set digest '{digest}'",
        f"\\set body '{_b64(canonical(body).decode('utf-8'))}'",
        f"\\set commit '{_b64(commit)}'",
        f"\\set compiler '{_b64(compiler)}'",
        f"\\set summary '{_b64(summary)}'",
        "SELECT medcea_auth._set_internal_actor('system:deploy') \\g /dev/null",
        f"SELECT iam_policy._accept_skeleton(:'digest', {_jsonb('body')}, {_text('commit')}, {_text('compiler')}, "
        f"{_jsonb('summary')}) \\g /dev/null",
        f"SELECT iam_policy._sync_skeleton({_jsonb('body')}, {_text('commit')}) \\g /dev/null",
        ""])


def record_sql(event, payload):
    """One _record(event, payload) as system:deploy; prints the event id."""
    if not re.fullmatch(r"[a-z][a-z0-9_]{2,62}", event):
        raise SourceError(f"bad event name {event!r}")
    return "\n".join([
        f"\\set payload '{_b64(payload)}'",
        "SELECT medcea_auth._set_internal_actor('system:deploy') \\g /dev/null",
        f"SELECT iam_policy._record('{event}', {_jsonb('payload')});",
        ""])


def seed_lines(path=None):
    """The queued account_seeded facts of state/seed-facts.jsonl: [dict]. SourceError naming
    the first line that is not a seed fact (the flush then stops and the queue stays)."""
    path = path or SEED_FILE
    out = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                fact = json.loads(line)
            except ValueError:
                fact = None
            if (not isinstance(fact, dict) or fact.get("fact") not in ("created", "person_id_set", "observed")
                    or not fact.get("username") or not fact.get("sub") or fact.get("fact_id") != fact_id(fact)):
                raise SourceError(f"line {n} of state/seed-facts.jsonl is not a seed fact")
            out.append(fact)
    return out


def seed_flush_sql(facts):
    """One transaction (psql -1): _record('account_seeded', fact + from_queue) per fact."""
    lines = ["SELECT medcea_auth._set_internal_actor('system:deploy') \\g /dev/null"]
    for i, fact in enumerate(facts):
        lines.append(f"\\set f{i} '{_b64(dict(fact, from_queue=True))}'")
        lines.append(f"SELECT iam_policy._record('account_seeded', {_jsonb(f'f{i}')}) \\g /dev/null")
    return "\n".join(lines + [""])
