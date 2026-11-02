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
                              SourceError (cli.py exits 2). A deploy refuses it until the
                              break-glass record exists (lib-policy-source.sh)
  4. the host applied file    when present; its header must name a version and the digest
                              of the skeleton in its own body, else SourceError. A file this
                              process cannot read is a SourceError too: an unreadable state/
                              cannot tell "no applied version" from "one we cannot see"
  5. otherwise                policy/defaults.yaml (no applied version on this host)
Slice 4.0 writes no host file, so every caller lands on 5, exactly as before.

label(src, label) is the name the route table and role_widening() record (cli.py --label,
else by source: break-glass:<reason>, version-N, the file's basename, defaults.yaml).

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
"""
import copy
import hashlib
import json
import os
import re

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULTS = os.path.normpath(os.path.join(HERE, "..", "policy", "defaults.yaml"))
REPO_ROOT = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
HOST_FILE = os.path.join(REPO_ROOT, "state", "policy-applied.yaml")

NOT_SKELETON = ("matrix", "waivers", "policy_version")
KINDS = ("bootstrap", "change", "skeleton", "rollback")
HEADER = "# medcea-applied:"
_HEADER_KEYS = ("version", "kind", "entries_digest", "skeleton_digest", "git_commit", "written_at")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


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


def read_host_file(path=None):
    """The host applied file as a Source, None when there is none."""
    path = path or HOST_FILE
    if not _host_file_present(path):
        return None
    text, data = _read_yaml(path, "the host applied file")
    header = parse_header(text)
    if skeleton_digest(data) != header["skeleton_digest"]:
        raise SourceError(f"{path}: its header's skeleton_digest does not match its body "
                          "(edited by hand, or truncated): restore it or ask the operator")
    return Source("host", path, data, version=int(header["version"]), header=header)


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
        return Source("break-glass", override, _read_yaml(override, "break-glass policy file")[1],
                      reason=reason)
    host = read_host_file(host_file)
    if host:
        return host
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


def compose(skel, ew, policy_version=None):
    """The policy dict of a skeleton and an entries_and_waivers() document. The matrix lists
    groups in the skeleton's resource_groups order and roles in its roles order."""
    out = copy.deepcopy(skel)
    order = list(skel.get("levels") or {})
    by_cell = {}
    for e in ew["entries"]:
        by_cell.setdefault((e["group_code"], e["role"]), []).append((e["level"], e["constraint_name"]))
    groups = list(skel.get("resource_groups") or {})
    roles = list(skel.get("roles") or {})
    unknown = sorted({k for k in by_cell if k[0] not in groups or k[1] not in roles})
    if unknown:
        raise SourceError(f"entries name keys the skeleton lacks: {unknown[:5]}")
    matrix = {}
    for g in groups:
        row = {r: cells_to_yaml(by_cell[(g, r)], order) for r in roles if (g, r) in by_cell}
        if row:
            matrix[g] = row
    out["policy_version"] = factory().get("policy_version") if policy_version is None else policy_version
    out["matrix"] = matrix
    out["waivers"] = copy.deepcopy(ew["waivers"])
    return out
