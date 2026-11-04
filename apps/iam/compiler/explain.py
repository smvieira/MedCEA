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
"""
import copy

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
    acc_skel = copy.deepcopy(acc_skel)
    if isinstance(acc_skel.get("levels"), dict) and isinstance(git_skel.get("levels"), dict):
        order = [l for l in git_skel["levels"] if l in acc_skel["levels"]]
        order += sorted(l for l in acc_skel["levels"] if l not in order)
        acc_skel["levels"] = {l: acc_skel["levels"][l] for l in order}
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
    """The refusal text (exit 3) of a widening gate, before IAM 4.5 (design §14.4.5)."""
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
    lines += ["It cannot deploy until policy approvals can be applied (IAM 4.5). Revert the change, or keep it on a branch.",
              "Break-glass (MEDCEA_POLICY_FILE) does not bypass this check: it changes the matrix, never the skeleton.",
              "Nothing was changed."]
    return "\n".join(lines)


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
