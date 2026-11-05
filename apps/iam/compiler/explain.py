"""apps/iam/compiler/explain.py — what a role can reach, as one comparable set (IAM Phase 4).

reach(p, role) is the one widening primitive behind the skeleton gate, rollback and
apply_check (design §7): a frozenset of tuples, each ending in its constraint (None when
unconstrained), built from the same functions the deploys compile with:
  ("db", object, privilege, constraint)    grants.document() privileges of the role's rr_
                                           role (constraint: the RLS `using` of a SELECT a
                                           constraint narrows), and ("db", granted_role,
                                           "MEMBER", None) for the roles it is a member of
  ("route", service, "METHOD /path", constraint)
                                           routes.compile(): constraint a sorted tuple of the
                                           constraints that must hold
  ("host", HOST, None)                     proxies.admitted()
  ("tool", group, setting, None)           tools.settings()
  ("mqtt", access, topic, constraint)      mqtt.rows() when the Explorer admits the role
  ("level", group, level, constraint)      model.Policy.holds(): every (group, level) held,
                                           composites, implies and tool reach expanded;
                                           constraint a sorted tuple, None when free (catches a
                                           constraint lost on a level that compiles to nothing
                                           else, e.g. not_own_author on an approval)
Losing a constraint shows as a new tuple with None (or a different constraint), so
reach(new) - reach(old) is what a change adds. A role the policy lacks reaches nothing.

system_reach(p) (IAM 4.2a, design §14.4.5, critique sec-1) is the same for what no person
role holds: anonymous routes, shared upstreams, what each host serves and its client, every
NetworkPolicy ingress source (symbolic, before any address is resolved), unproxied hosts,
the network clients' hops, token clients and only_rpc functions, the privileges and
memberships of every grantee that is not a person's rr_ role, and every RLS row.

What a symbolic tuple cannot show (how `ingress`, `proxy:H` and `pod:P` resolve: the ingress
namespace, the proxies' release names, the pods' and clients' selectors, carried ports,
only_rpc, no_shared_upstreams; database role names, MQTT logins, credential settings) is the
RESIDUE: every skeleton key path is classified (REACH_PATHS, PROSE_PATHS, the section keys,
RESIDUE_PATHS), and any change to a residue path, or to a path nobody classified, is a
widening ("section <path> changed").

gate(accepted, git, ew) is the skeleton gate's computation: both skeletons composed with the
applied rows (unknown keys dropped), person reach per role, system reach, and the sections
it cannot reduce to reach (sections()). verdict: widening when anything is added, narrowing
when nothing is but the digests differ, equal when they are equal. Called by
`cli.py skeleton-gate` (every deploy's policy_source_init, apply.sh, health).

diff(p_from, p_to) and diff_document(...) (IAM 4.4, design §14.7.3) are what a change or
skeleton version changes, the document qa approves: cells, waivers, reach per role and
system reach both ways. diff_bytes() is source.canonical() of it and diff_digest() its
sha256, the one serialisation iam-api serves, the browser hashes and apply.sh stores.
who_can(p, obj) (§14.7.5) is one object's holders, from the same tuples.

rollback_bound(today, k_skel, rows) (IAM 4.5, design §14.8.7, OA-c) is apply.sh
--rollback-to's limit: version K's rows under today's accepted skeleton may reach, per person
role, nothing they did not reach under the skeleton K was approved under. bound_skeleton()
picks that skeleton's body (the YAML at K's commit when it carries the digest, else the jsonb
body with the gate's level order, level_order()).
"""
import copy
import hashlib
import re

from compiler import grants, model, mqtt, proxies, routes, source, tools


def reach(p, role):
    if role not in p.roles:
        return frozenset()
    out = set()
    rr = grants.people(p)[role]
    doc = grants.document(p)
    narrowed = {(x["object"], x["role"]): x["using"] for x in doc["rls"]
                if x["cmd"] == "SELECT" and x["using"] not in (None, "true")}
    for grantee, _kind, obj, priv in doc["privileges"]:
        if grantee == rr:
            con = narrowed.get((obj, rr)) if priv == "SELECT" else None
            out.add(("db", obj, priv, con))
    for granted, member, _inherit, _set in doc["memberships"]:
        if member == rr:
            out.add(("db", granted, "MEMBER", None))
    for service, sd in routes.compile(p)["services"].items():
        for route, rd in sd["routes"].items():
            if role in rd["roles"]:
                cons = rd["roles"][role]
                out.add(("route", service, route, tuple(sorted(cons)) if cons else None))
    for host in p.hosts:
        if role in proxies.admitted(p, host):
            out.add(("host", host, None))
    for g in tools.groups(p):
        for setting, roles in tools.settings(p, g):
            if role in roles:
                out.add(("tool", g, setting, None))
    for (g, level), how in p.holds(role).items():
        out.add(("level", g, level, None if how == "free" else tuple(sorted(how))))
    if role in mqtt.admitted(p):
        for r in mqtt.rows(p, role):
            out.add(("mqtt", r["access"], r["topic"], r["constraint"]))
    return frozenset(out)


def system_reach(p):
    """The non-person dimensions of the skeleton gate, as one frozenset of tuples."""
    out = set()
    for service, rs in routes.compile(p)["public"].items():
        for r in rs:
            out.add(("public", service, r))
    for u in p.data.get("shared_upstreams") or []:
        out.add(("shared", u.get("service"), u.get("path")))
    for host, hd in (p.data.get("hosts") or {}).items():
        for svc in hd.get("serves") or []:
            out.add(("serves", host, svc))
        out.add(("azp", host, hd.get("client")))
    net = p.data.get("network") or {}
    for pod, pd in (net.get("pods") or {}).items():
        for ing in pd.get("ingress") or []:
            for src in ing.get("from") or []:
                out.add(("ingress", pod, ing.get("port"), src))
    for host, src in (net.get("unproxied") or {}).items():
        out.add(("unproxied", host, src if isinstance(src, str) else source.canonical(src).decode()))
    for name, cd in (net.get("clients") or {}).items():
        for hop in cd.get("egress") or []:
            target = hop.get("pod") or source.canonical(hop.get("selector")).decode()
            out.add(("client", name, "egress", target, hop.get("port")))
        if cd.get("token_client"):
            out.add(("client", name, "token_client", cd["token_client"]))
        if cd.get("read_only") is not True:
            out.add(("client", name, "writes"))
    for client, fns in grants.only_rpc_clients(p).items():
        for fn in fns:
            out.add(("only_rpc", client, fn))
    for azp in grants.token_clients(p):
        out.add(("token_client", azp))
    people = set(grants.people(p).values())
    doc = grants.document(p)
    for grantee, kind, obj, priv in doc["privileges"]:
        if grantee not in people:
            out.add(("svc", grantee, kind, obj, priv))
    for granted, member, inherit, setopt in doc["memberships"]:
        if member not in people:
            out.add(("svc-member", granted, member, inherit, setopt))
    for x in doc["rls"]:
        out.add(("rls", x["object"], x["role"], x["cmd"], x.get("using"), x.get("check")))
    return frozenset(out)


# Sections compared as a whole (prose keys removed): any change is a widening.
WHOLE_SECTIONS = ("break_glass", "db_roles", "levels", "resource_types", "classes", "constraints", "schema_version")

# Every skeleton key, by path (design §14.4.5, review 4.2a): a dict whose path is in
# ENTITY_MAPS has names as keys ("*" in a path); a list of dicts adds "[]". Each leaf path of
# the skeleton is in exactly one class:
#   REACH_PATHS     compiled into reach() or system_reach(): the tuple sets decide;
#   PROSE_PATHS     words only (besides source.TEXT_KEYS anywhere): ignored;
#   section keys    invariants, waivable and WHOLE_SECTIONS: sections() decides;
#   RESIDUE_PATHS   shapes what the compilers render but is not a reach tuple (selectors,
#                   release names, the ingress namespace, carried ports, only_rpc, database
#                   role names, MQTT logins, credential settings, …): ANY change is a widening.
# A path in none of them (a key added to defaults.yaml without a decision here) counts as
# RESIDUE too, so the gate fails closed; tests/test_policy_source.py Gate pins the set.
ENTITY_MAPS = frozenset((
    "levels", "resource_types", "classes", "hosts", "db_roles", "roles", "service_identities",
    "resource_groups", "constraints", "network.unproxied", "network.proxies", "network.pods",
    "network.clients", "network.pods.*.carries", "network.pods.*.selector", "network.clients.*.selector",
    "network.clients.*.egress[].selector", "service_identities.*.ceiling", "resource_groups.*.members[].routes",
    "resource_groups.*.reaches", "constraints.*.rls.using",
))
REACH_PATHS = frozenset((
    "hosts.*.serves", "hosts.*.client",
    "shared_upstreams[].service", "shared_upstreams[].path",
    "public_routes[].service", "public_routes[].route",
    "infrastructure_functions[].function", "infrastructure_functions[].execute", "infrastructure_functions[].rule",
    "network.unproxied.*",
    "network.pods.*.ingress[].from", "network.pods.*.ingress[].port",
    "network.clients.*.egress[].pod", "network.clients.*.egress[].port", "network.clients.*.egress[].selector.*",
    "network.clients.*.token_client", "network.clients.*.read_only",
    "roles.*.includes",
    "service_identities.*.ceiling.*",
    "resource_groups.*.members[].admit", "resource_groups.*.members[].function", "resource_groups.*.members[].host",
    "resource_groups.*.members[].level", "resource_groups.*.members[].object",
    "resource_groups.*.members[].person_write", "resource_groups.*.members[].routes.*",
    "resource_groups.*.members[].routes.*.levels", "resource_groups.*.members[].routes.*.unconstrained_only",
    "resource_groups.*.members[].service", "resource_groups.*.members[].service_only",
    "resource_groups.*.members[].topic", "resource_groups.*.members[].type", "resource_groups.*.members[].view",
    "resource_groups.*.members[].writes", "resource_groups.*.members[].written_by",
    "resource_groups.*.approval.functions",
    "resource_groups.*.reaches.*",
    "resource_groups.*.tool.host", "resource_groups.*.tool.kind", "resource_groups.*.tool.otherwise",
    "resource_groups.*.tool.service_identity", "resource_groups.*.tool.constraint_enforced_by",
    "resource_groups.*.tool.settings[].setting", "resource_groups.*.tool.settings[].levels",
))
PROSE_PATHS = frozenset((
    "roles.*.responsibilities", "resource_groups.*.members[].note", "resource_groups.*.why_this_class",
))
RESIDUE_PATHS = frozenset((
    "network.ingress_namespace", "network.no_shared_upstreams", "network.proxies.*",
    "network.pods.*.selector.*", "network.pods.*.carries.*",
    "network.clients.*.selector.*", "network.clients.*.only_rpc",
    "roles.*.db_role", "roles.*.availability", "roles.*.spec_role",
    "service_identities.*.db_role", "service_identities.*.db_password", "service_identities.*.managed_by",
    "service_identities.*.mqtt_user",
    "resource_groups.*.class", "resource_groups.*.risk", "resource_groups.*.mirrors",
    "resource_groups.*.approval.record", "resource_groups.*.approval.effect",
    "resource_groups.*.credential.listener", "resource_groups.*.credential.max_active",
    "resource_groups.*.credential.ttl_hours",
))
SECTION_KEYS = ("invariants", "waivable") + WHOLE_SECTIONS
# Entities whose removal as a whole only narrows (their reach tuples show what goes): their
# residue leaves gone with them are not a change. A network pod or client, a proxy or a
# service identity removed is still a widening (an unprotected pod, an unmanaged login).
REMOVABLE_ENTITIES = ("resource_groups", "roles")


def leaves(x, pattern="", concrete=""):
    """[(pattern, concrete, value)] for every leaf of a skeleton: pattern has "*" for the
    keys of ENTITY_MAPS and "[]" for list items; concrete has the names (no list index, so
    removing a list item does not move the others). A list of scalars is one leaf; prose
    keys (source.TEXT_KEYS) are left out."""
    out = []
    if isinstance(x, dict):
        for k, v in x.items():
            if k in source.TEXT_KEYS:
                continue
            seg = "*" if pattern in ENTITY_MAPS else str(k)
            out += leaves(v, f"{pattern}.{seg}" if pattern else seg, f"{concrete}.{k}" if concrete else str(k))
    elif isinstance(x, list) and any(isinstance(i, (dict, list)) for i in x):
        for v in x:
            out += leaves(v, pattern + "[]", concrete + "[]")
    else:
        out.append((pattern, concrete, x))
    return out


def path_class(pattern):
    """reach | prose | section | residue (residue also for a path nobody classified)."""
    top = pattern.split(".", 1)[0].split("[", 1)[0]
    if top in SECTION_KEYS:
        return "section"
    if pattern in REACH_PATHS:
        return "reach"
    if pattern in PROSE_PATHS:
        return "prose"
    return "residue"


def residue(skel):
    """The multiset of (concrete path, value) leaves the tuple sets do not cover."""
    out = {}
    for pattern, concrete, v in leaves(skel):
        if path_class(pattern) == "residue":
            key = (concrete, source.canonical(v).decode())
            out[key] = out.get(key, 0) + 1
    return out


def _prose_free(x):
    if isinstance(x, dict):
        return {k: _prose_free(v) for k, v in x.items() if k not in source.TEXT_KEYS}
    if isinstance(x, list):
        return [_prose_free(v) for v in x]
    return x


def sections(old, new):
    """[("section", name)] the gate counts as widening between two skeletons: an invariant
    removed or changed (adding one only tightens), an id added to `waivable`, any change to
    WHOLE_SECTIONS, and any change to a RESIDUE path (named by its concrete path, e.g.
    network.ingress_namespace or network.pods.iam.selector.app); prose keys
    (source.TEXT_KEYS) are ignored."""
    out = []
    oi = {i.get("code"): _prose_free(i) for i in old.get("invariants") or []}
    ni = {i.get("code"): _prose_free(i) for i in new.get("invariants") or []}
    if any(c not in ni or source.canonical(ni[c]) != source.canonical(v) for c, v in oi.items()):
        out.append(("section", "invariants"))
    if set(new.get("waivable") or []) - set(old.get("waivable") or []):
        out.append(("section", "waivable"))
    for k in WHOLE_SECTIONS:
        if source.canonical(_prose_free(old.get(k))) != source.canonical(_prose_free(new.get(k))):
            out.append(("section", k))
    ro, rn = residue(old), residue(new)
    gone = tuple(f"{m}.{name}." for m in REMOVABLE_ENTITIES for name in (old.get(m) or {})
                 if name not in (new.get(m) or {}))
    ro = {k: n for k, n in ro.items() if not k[0].startswith(gone)} if gone else ro
    for path in sorted({c for c, _ in ro} | {c for c, _ in rn}):
        if {k: n for k, n in ro.items() if k[0] == path} != {k: n for k, n in rn.items() if k[0] == path}:
            out.append(("section", path))
    return out


def _listed(ts):
    return [list(t) for t in sorted(ts, key=lambda t: source.canonical(list(t)))]


def gate(accepted, git, ew):
    """The skeleton gate between the accepted skeleton and the git one, both composed with
    the applied rows `ew` (entries_and_waivers shape; rows naming a key a skeleton lacks
    dropped). {verdict, git_digest, accepted_digest, added: {role|_system|_sections: [...]},
    narrowed, unchanged}. A compile error raises (callers exit 2)."""
    acc_skel, git_skel = source.skeleton(accepted), source.skeleton(git)
    out = {"git_digest": source.skeleton_digest(git_skel), "accepted_digest": source.skeleton_digest(acc_skel),
           "added": {}, "narrowed": [], "unchanged": []}
    if out["git_digest"] == out["accepted_digest"]:
        out["verdict"] = "equal"
        return out
    # the accepted body may come from jsonb (keys sorted): compose it with the git level order
    acc_skel = level_order(acc_skel, git_skel)
    p_old = model.Policy(source.compose(acc_skel, ew, drop_unknown=True))
    p_new = model.Policy(source.compose(git_skel, ew, drop_unknown=True))
    for role in sorted(set(p_old.roles) | set(p_new.roles)):
        before, after = reach(p_old, role), reach(p_new, role)
        if after - before:
            out["added"][role] = _listed(after - before)
        elif before - after:
            out["narrowed"].append(role)
        else:
            out["unchanged"].append(role)
    sys_added = system_reach(p_new) - system_reach(p_old)
    if sys_added:
        out["added"]["_system"] = _listed(sys_added)
    sec = sections(acc_skel, git_skel)
    if sec:
        out["added"]["_sections"] = _listed(sec)
    out["verdict"] = "widening" if out["added"] else "narrowing"
    return out


def level_order(skel, ref):
    """A copy of skeleton `skel` (a jsonb body: keys sorted) with its levels in `ref`'s order,
    then the rest sorted: the order feeds compose's cells, so a jsonb body is never composed
    unreordered (gate, rollback_bound; apply_check._composed does the same)."""
    skel = copy.deepcopy(skel)
    if isinstance(skel.get("levels"), dict) and isinstance(ref.get("levels"), dict):
        order = [l for l in ref["levels"] if l in skel["levels"]]
        order += sorted(l for l in skel["levels"] if l not in order)
        skel["levels"] = {l: skel["levels"][l] for l in order}
    return skel


def checker_errors(git, ew):
    """The checker's violations of the git skeleton composed with the applied rows `ew`, as
    the deploys would compile it: a narrowing is accepted only when this is empty."""
    from compiler import invariants
    composed, _ = source.compose_counted(source.skeleton(git), ew, drop_unknown=True)
    return invariants.check(model.Policy(composed))[0]


def _describe(t):
    kind = t[0]
    if kind == "route":
        return f"route {t[1]} {t[2]}" + (f" ({', '.join(t[3])})" if t[3] else "")
    if kind == "host":
        return f"host {t[1]}"
    if kind == "db":
        return f"db {t[2]} {t[1]}" + (f" (where {t[3]})" if t[3] else "")
    if kind == "tool":
        return f"tool {t[1]} {t[2]}"
    if kind == "level":
        return f"level {t[2]} on {t[1]}" + (f" ({', '.join(t[3])})" if t[3] else "")
    if kind == "mqtt":
        return f"mqtt {t[1]} {t[2]}"
    if kind == "section":
        return f"section {t[1]} changed"
    return " ".join(str(x) for x in t if x is not None)


def gate_message(g, first=10):
    """The refusal text (exit 3) of a widening gate (design §14.4.5; the proposal line since
    4.4, §14.7.6; since 4.5, §14.8.4, the way on names the approved skeleton version whose
    digest HEAD carries, g["approved_version"], when cli.py skeleton-gate found one)."""
    lines = [f"ERROR: this git change gives access that has not been approved "
             f"(skeleton {g['git_digest'][:12]} over the accepted {g['accepted_digest'][:12]}):"]
    for role, ts in g["added"].items():
        if role in ("_system", "_sections"):
            continue
        shown = "; ".join(_describe(t) for t in ts[:first])
        more = f" … and {len(ts) - first} more" if len(ts) > first else ""
        lines.append(f"  {role}: {len(ts)} new: {shown}{more}")
    if g["added"].get("_system"):
        ts = g["added"]["_system"]
        more = f" … and {len(ts) - first} more" if len(ts) > first else ""
        lines.append(f"  anonymous and services: {'; '.join(_describe(t) for t in ts[:first])}{more}")
    if g["added"].get("_sections"):
        lines.append("  checker: " + "; ".join(_describe(t) for t in g["added"]["_sections"]))
    if g.get("approved_version"):
        v = g["approved_version"]
        lines.append(f"This skeleton is approved as version {v}: run ./apps/iam/apply.sh {v} --by <you> to apply it "
                     "(deploys refuse it until then).")
    else:
        lines.append("This change needs a qa-approved skeleton version: put HEAD back at the accepted skeleton, keep "
                     "the change as a commit on a branch, and run ./apps/iam/apply.sh --propose-skeleton --by <you> "
                     "--reason \"<why>\" --from-git <commit>; once qa approves it, check that commit out and run "
                     "./apps/iam/apply.sh <version>.")
    lines += ["Break-glass (MEDCEA_POLICY_FILE) does not bypass this check: it changes the matrix, never the skeleton.",
              "Nothing was changed."]
    return "\n".join(lines)


# ── the rollback bound (IAM 4.5, design §14.8.7 step 5, OA-c) ──────────────────────────
def bound_skeleton(k_digest, k_yaml=None, k_body=None, ref=None):
    """(skeleton, how) of the skeleton version K was approved under, digest k_digest: K's
    commit's defaults.yaml (k_yaml, its own key order) when its skeleton digest is k_digest,
    how "yaml"; else the stored jsonb body k_body with its levels in ref's order (the git
    skeleton's: level_order), how "jsonb". SourceError when neither carries the digest."""
    if k_yaml is not None and source.skeleton_digest(k_yaml) == k_digest:
        return source.skeleton(k_yaml), "yaml"
    if isinstance(k_body, dict) and source.skeleton_digest(k_body) == k_digest:
        return level_order(source.skeleton(k_body), source.skeleton(ref or source.factory())), "jsonb"
    raise source.SourceError(f"no skeleton body carries the digest {str(k_digest)[:12]} version K was approved under")


def rollback_bound(today, k_skel, rows):
    """apply.sh --rollback-to's bound: {added: {role: [tuples]}, dropped: {today, k}}. K's
    rows `rows` (entries_and_waivers shape) composed with today's accepted skeleton `today`
    and with K's own skeleton `k_skel` (bound_skeleton), rows naming a key a skeleton lacks
    dropped and counted (never refused: retired keys stay in iam_policy's tables); added is,
    for every person role of today's skeleton, reach(today + K) - reach(K's + K)
    (model.widening_between). Empty added: the bound holds."""
    p_today, d_today = source.compose_counted(source.skeleton(today), rows, drop_unknown=True)
    p_k, d_k = source.compose_counted(source.skeleton(k_skel), rows, drop_unknown=True)
    p_today, p_k = model.Policy(p_today), model.Policy(p_k)
    added = {}
    for role in sorted(p_today.roles, key=_bytes):
        extra = model.widening_between(p_k, p_today, role)
        if extra:
            added[role] = _listed(extra)
    return {"added": added, "dropped": {"today": d_today, "k": d_k}}


def rollback_refusal(k, bound, first=3):
    """The refusal of a rollback past its bound (design §14.8.7 step 5), naming the first
    `first` roles and, for each, its first `first` tuples; None when the bound holds."""
    if not bound["added"]:
        return None
    parts = []
    for role, ts in list(bound["added"].items())[:first]:
        parts.append(f"{role}: " + "; ".join(_describe(t) for t in ts[:first]) + (" …" if len(ts) > first else ""))
    if len(bound["added"]) > first:
        parts.append(f"{len(bound['added']) - first} more role(s)")
    return (f"version {k} under today's skeleton grants more than was approved ({' | '.join(parts)}): draft from "
            f"version {k} in the Policy UI (Changes → New draft from version {k}) and have qa approve it")


# ── cell: one matrix cell explained (IAM 4.3, the Policy UI's "See more") ─────────────
def _without_cell(p, role, group):
    data = copy.deepcopy(p.data)
    (data.get("matrix") or {}).get(group, {}).pop(role, None)
    return model.Policy(data)


def _jsonable(t):
    return [list(x) if isinstance(x, tuple) else x for x in t]


def cell(p, p_applied, role, group):
    """What the cell (group, role) of policy p gives, as one JSON-ready dict: its levels and
    their constraints, the implied levels, what the role reaches only through this cell
    (reach with the cell minus reach without it: db objects, routes, hosts, tool settings,
    MQTT rows, held levels), the group's members with their type, the waivers and checker
    messages that name it, and its difference from the same cell in p_applied (None: no
    comparison). Pure: the same objects the compiled artefacts carry (ExplainParity)."""
    if role not in p.roles:
        raise KeyError(f"no role {role!r}")
    if group not in p.groups:
        raise KeyError(f"no resource group {group!r}")
    c = p.cell(group, role)
    levels, cons = (sorted(c[0]), c[1]) if c else ([], {})
    implied = sorted(p.closure(levels) - set(levels))
    with_ = reach(p, role)
    without = reach(_without_cell(p, role, group), role)
    gives = sorted(with_ - without, key=repr)
    hosts_with = sorted(h for k, h, *_ in with_ if k == "host")
    hosts_without = sorted(h for k, h, *_ in without if k == "host")
    g = p.groups[group]
    members = [{"type": m.get("type"), "name": m.get("object") or m.get("function") or m.get("service")
                or m.get("host") or m.get("topic") or m.get("tool"), "note": m.get("note") or m.get("why")}
               for m in g.get("members") or []]
    waivers = [w for w in p.waivers if w.get("subject") == role and w.get("group") == group]
    from compiler import invariants
    errors, notes = invariants.check(p)
    named = [m for m in errors + notes if f" {role} " in f" {m} " and group in m]
    out = {"role": role, "group": group, "levels": levels,
           "constraints": {l: {"name": n, "help": (p.constraints.get(n) or {}).get("help")
                                or (p.constraints.get(n) or {}).get("description")} for l, n in sorted(cons.items())},
           "implied": implied, "gives": [_jsonable(t) for t in gives],
           "hosts": {"with": hosts_with, "without": hosts_without},
           "members": members, "group_label": g.get("label"), "group_help": g.get("description"),
           "role_label": p.roles[role].get("label"), "waivers": waivers, "checker": named, "changed": None}
    if p_applied is not None:
        a = p_applied.cell(group, role) if group in p_applied.groups and role in p_applied.roles else None
        a_levels, a_cons = (sorted(a[0]), a[1]) if a else ([], {})
        ra = reach(p_applied, role) if role in p_applied.roles else frozenset()
        out["changed"] = {"applied_levels": a_levels, "applied_constraints": dict(sorted(a_cons.items())),
                          "same": (a_levels, dict(a_cons)) == (levels, dict(cons)),
                          "adds": [_jsonable(t) for t in sorted(with_ - ra, key=repr)],
                          "removes": [_jsonable(t) for t in sorted(ra - with_, key=repr)]}
    return out


# ── diff: what a version changes, as the bytes qa approves (IAM 4.4, design §14.7.3) ───
DIFF_SCHEMA = 1
DIFF_KINDS = ("change", "skeleton")


def _json(x):
    """Tuples as lists, all the way down: the diff equals its own JSON round trip."""
    if isinstance(x, (list, tuple)):
        return [_json(v) for v in x]
    if isinstance(x, dict):
        return {k: _json(v) for k, v in x.items()}
    return x


def _cell_map(p, group, role):
    """{level: constraint or None} of the direct cell (group, role), {} for N."""
    c = p.cell(group, role) if group in p.groups and role in p.roles else None
    if not c:
        return {}
    levels, cons, _ = c
    return {l: cons.get(l) for l in sorted(levels)}


def _bytes(x):
    return (x or "").encode("utf-8")


def diff(p_from, p_to):
    """What p_to changes against p_from, as one JSON-ready dict (pure, deterministic, and
    mode-independent: built on reach()/system_reach(), which read grants.document()):
      cells    the cells that differ, {group, role, before, after} ({level: constraint or
               None}; {} for N), sorted by the bytes of (group, role)
      waivers  {added, removed}: source.waiver_row forms compared by id (a changed waiver
               is removed and added), sorted by id bytes
      roles    {role: {added, removed}} for each role of either policy whose reach moved
      system   {added, removed}: system_reach() both ways
    Tuples are lists in _listed() order (the gate's)."""
    cells = []
    for g in sorted(set(p_from.groups) | set(p_to.groups), key=_bytes):
        for r in sorted(set(p_from.roles) | set(p_to.roles), key=_bytes):
            before, after = _cell_map(p_from, g, r), _cell_map(p_to, g, r)
            if before != after:
                cells.append({"group": g, "role": r, "before": before, "after": after})
    wf = {w["id"]: w for w in (source.waiver_row(x) for x in p_from.waivers)}
    wt = {w["id"]: w for w in (source.waiver_row(x) for x in p_to.waivers)}
    waivers = {"added": [wt[i] for i in sorted(wt, key=_bytes) if wf.get(i) != wt[i]],
               "removed": [wf[i] for i in sorted(wf, key=_bytes) if wt.get(i) != wf[i]]}
    roles = {}
    for r in sorted(set(p_from.roles) | set(p_to.roles), key=_bytes):
        before, after = reach(p_from, r), reach(p_to, r)
        if before != after:
            roles[r] = {"added": _listed(after - before), "removed": _listed(before - after)}
    sb, sa = system_reach(p_from), system_reach(p_to)
    return _json({"cells": cells, "waivers": waivers, "roles": roles,
                  "system": {"added": _listed(sa - sb), "removed": _listed(sb - sa)}})


def diff_document(kind, version, against, entries_digest, p_from, p_to, skeleton=None):
    """The approval diff of a version of kind change or skeleton: {schema, kind, version,
    against, entries_digest, skeleton, cells, waivers, roles, system}. `skeleton` is None
    for a change; for a skeleton version {from: accepted digest, to: proposed digest,
    sections: [...]} (sections listed by _listed when given as tuples). No compiler
    digest, commit, time or label: a commit that changes no compiled tuple leaves the
    bytes as they were (OPEN CHOICE 1, G8)."""
    if kind not in DIFF_KINDS:
        raise ValueError(f"only a change or skeleton version has an approval diff, not {kind!r}")
    if (kind == "skeleton") != (skeleton is not None):
        raise ValueError("a skeleton version's diff names its skeletons; a change's names none")
    sk = None
    if skeleton is not None:
        secs = skeleton.get("sections") or []
        sk = {"from": skeleton["from"], "to": skeleton["to"],
              "sections": _listed(secs) if any(isinstance(t, tuple) for t in secs) else _json(secs)}
    doc = {"schema": DIFF_SCHEMA, "kind": kind, "version": version, "against": against,
           "entries_digest": entries_digest, "skeleton": sk}
    doc.update(diff(p_from, p_to))
    return doc


def diff_bytes(doc):
    """The canonical bytes of a diff document, as served and hashed (source.canonical:
    sorted keys, no spaces, UTF-8 unescaped). One function on every side: iam-api, the
    host (apply_check.py) and, after jsonb, the re-serialised stored diff."""
    return source.canonical(doc)


def diff_digest(doc):
    """sha256 of diff_bytes(doc), 64 lower-case hex characters."""
    return hashlib.sha256(diff_bytes(doc)).hexdigest()


# ── who can: one object's holders (IAM 4.4, design §14.7.5) ──────────────────────────
_ROUTE_OBJ = re.compile(r"^(\S+) ([A-Z]+ /\S*)$")
NO_TUPLE_TYPES = ("code", "idp", "infra")      # members that compile to no reach tuple


def _member_names(m):
    """The who-can names of one member, as the skeleton writes it (functions normalised as
    grants.document() names them, an api member one name per route)."""
    t = m.get("type")
    if t == "api":
        return [f"{m['service']} {r}" for r in m.get("routes") or {}]
    if t == "ui":
        return [m["host"]]
    if t == "mqtt":
        return [m["topic"]]
    if m.get("function"):
        return [grants.norm_sig(m["function"])]
    return [m["object"]] if m.get("object") else []


def who_can_index(p):
    """{objects: [{name, type, groups}]}: every member name and tool of the skeleton,
    sorted by name bytes (the Who can… picker)."""
    idx = {}
    for g, gd in p.groups.items():
        for m in gd.get("members") or []:
            for n in _member_names(m):
                e = idx.setdefault(n, {"name": n, "type": m.get("type"), "groups": []})
                if g not in e["groups"]:
                    e["groups"].append(g)
        tool = gd.get("tool")
        if tool and tool.get("kind"):
            e = idx.setdefault(tool["kind"], {"name": tool["kind"], "type": "tool", "groups": []})
            e["groups"].append(g)
    for e in idx.values():
        e["groups"].sort(key=_bytes)
    return {"objects": [idx[n] for n in sorted(idx, key=_bytes)]}


def _who_levels(p, role, groups):
    """{level: None | constraint | [constraints]} the role holds on any of `groups`
    (holds(): composites, implies and tool reach expanded); free wins, alternatives
    from several cells are a sorted list."""
    out = {}
    for (g, l), how in p.holds(role).items():
        if g not in groups:
            continue
        if how == "free" or out.get(l, "") is None:
            out[l] = None
        else:
            out[l] = sorted(set(out.get(l) or []) | set(how))
    order = list(p.levels)
    return {l: (v if v is None or len(v) > 1 else v[0])
            for l, v in sorted(out.items(), key=lambda x: order.index(x[0]) if x[0] in order else len(order))}


def who_can(p, obj, level=None, cache=None):
    """Who holds `obj` (a member name as the skeleton writes it: a db object schema.name, a
    function signature, "service METHOD /path", a *_DOMAIN host, an MQTT topic, a tool
    kind; or group:<code>), as {object, groups, roles: [{role, levels, tuples}], services}.
    groups: the codes holding obj as a member; roles: each role with a reach() tuple naming
    obj (tuples, by _listed), and its levels on those groups (_who_levels); a role holding
    nothing relevant is left out (for code, idp and infra members, which compile to no
    tuple, holding a level on the group is relevant); `level` keeps the roles holding it.
    services: the system_reach() tuples naming obj. Pure; ExplainParity checks it against
    the route table, grants.document(), proxies.admitted() and mqtt.rows(). `cache`, a dict
    the caller keeps per Policy, holds the reach sets across calls (each costs a compile)."""
    cache = {} if cache is None else cache
    if "reach" not in cache:
        cache["reach"] = {r: reach(p, r) for r in p.roles}
        cache["system"] = system_reach(p)
    groups, kind = [], None
    if obj.startswith("group:"):
        code = obj[len("group:"):]
        if code not in p.groups:
            raise KeyError(f"no resource group {code!r}")
        groups, kind = [code], "group"
    else:
        if "(" in obj and not _ROUTE_OBJ.match(obj):
            try:
                obj = grants.norm_sig(obj)
            except grants.GrantsError:
                pass
        for g, gd in p.groups.items():
            for m in gd.get("members") or []:
                if obj in _member_names(m):
                    groups.append(g)
                    kind = kind or m.get("type")
            if (gd.get("tool") or {}).get("kind") == obj:
                groups.append(g)
                kind = kind or "tool"
        groups = sorted(set(groups), key=_bytes)
    rm = _ROUTE_OBJ.match(obj) if kind not in ("group", "tool") else None

    def names(t):
        if kind == "group":
            return t[0] in ("level", "tool") and t[1] == obj[len("group:"):]
        if kind == "tool":
            return t[0] == "tool" and t[1] in groups
        if rm:
            return t[0] in ("route", "public") and t[1] == rm.group(1) and t[2] == rm.group(2)
        if kind == "mqtt":
            return t[0] == "mqtt" and t[2] == obj.split("/", 1)[-1]
        return obj in t[1:]

    roles = []
    for r in sorted(p.roles, key=_bytes):
        ts = [t for t in cache["reach"][r] if names(t)]
        levels = _who_levels(p, r, set(groups))
        if not ts and not (kind in NO_TUPLE_TYPES and levels):
            continue
        if level is not None and level not in levels:
            continue
        roles.append({"role": r, "levels": levels, "tuples": _listed(ts)})
    services = [] if kind in ("group", "tool") else _listed(t for t in cache["system"] if names(t))
    return _json({"object": obj, "groups": groups, "roles": roles, "services": services})
