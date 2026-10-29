"""apps/iam/compiler/invariants.py — the one checker of the policy's matrix invariants.

check(policy) returns (errors, notes). It covers the structure of the file, the help the
Policy UI needs on every element, and the matrix invariants of defaults.yaml evaluated on
the effective matrix (composites, implies and tool reach expanded). iam-api calls it on
every save and apply.sh before every apply; the database only checks structure.
The workflow (I8, I17) and catalog (I9, I10 live, I15) invariants need Keycloak or
pg_catalog and run in apply.sh; the static part of I10 (ceilings vs waivers) runs here.
"""

PRODUCER = {"C", "U", "O"}
SCIENTISTS = ("bio_scientist", "control_scientist")
I5_GROUPS = ("runs", "schedules", "measurements", "mqtt_sense", "mqtt_control", "controllers_state")
# The only services that record an approval for a person whose token they verified (I10).
SERVICE_APPROVERS = {("svc_access", "iam_users"), ("svc_access", "zones"), ("svc_iam", "iam_policy")}


def _member_keys(m):
    if m["type"] == "api":
        return [("api", m["service"], route) for route in m["routes"]]
    if m.get("function"):
        from compiler import grants  # normalised, so int/integer spellings cannot hide a duplicate
        try:
            return [(m["type"], grants.norm_sig(m["function"]))]
        except grants.GrantsError:
            return [(m["type"], m["function"])]
    return [(m["type"], m.get("object") or m.get("host") or m.get("topic"))]


def _route_levels(lv):
    return lv if isinstance(lv, list) else [lv]


def _structure(p, err):
    d = p.data
    for k in ("levels", "roles", "resource_groups", "matrix", "invariants", "constraints", "classes", "hosts"):
        if k not in d:
            err(f"missing top-level key {k}")
    for g, row in p.matrix.items():
        if g not in p.groups:
            err(f"matrix row {g} is not a resource group")
            continue
        for r in row:
            if r not in p.roles:
                err(f"matrix {g}.{r}: unknown role")
    for g, gd in p.groups.items():
        if gd.get("class") not in p.classes:
            err(f"group {g}: class {gd.get('class')} not in classes")
        for m in gd["members"]:
            if m["type"] not in p.types:
                err(f"group {g}: member type {m['type']} unknown")
            if m["type"] == "ui" and m["host"] not in p.hosts:
                err(f"group {g}: ui host {m['host']} not in hosts")
            if m["type"] == "api":
                for route, lv in m["routes"].items():
                    for x in _route_levels(lv):
                        if x not in p.levels:
                            err(f"group {g}: route {route} level {x} unknown")
        for tg in (gd.get("reaches") or {}):
            if tg not in p.groups:
                err(f"group {g}: reaches unknown group {tg}")
        for tg in gd.get("mirrors") or []:
            if tg not in p.groups:
                err(f"group {g}: mirrors unknown group {tg}")
    for r, rd in p.roles.items():
        for inc in rd["includes"]:
            if inc not in p.roles:
                err(f"role {r}: includes unknown role {inc}")


def _help(p, err):
    """The Policy UI shows these fields; none may be empty."""
    for r, rd in p.roles.items():
        for f in ("label", "description", "responsibilities", "spec_role"):
            if not rd.get(f):
                err(f"role {r}: help field {f} empty")
    for l, ld in p.levels.items():
        for f in ("name", "summary", "help"):
            if not ld.get(f):
                err(f"level {l}: help field {f} empty")
        for t in ld.get("meaning") or {}:
            if t not in p.types:
                err(f"level {l}: meaning for unknown type {t}")
            elif l not in p.types[t]["levels"]:
                err(f"level {l}: has a meaning for type {t}, which does not support it")
        for t, td in p.types.items():
            if l != "N" and l in td["levels"] and t not in (ld.get("meaning") or {}):
                err(f"level {l}: type {t} supports it but has no meaning text")
    for g, gd in p.groups.items():
        for f in ("label", "description", "why_this_class", "risk"):
            if not gd.get(f):
                err(f"group {g}: help field {f} empty")
        if "approval" in gd and not gd["approval"].get("help"):
            err(f"group {g}: approval help empty")
    for c, cd in p.constraints.items():
        for f in ("summary", "effect", "enforced_by", "help"):
            if not cd.get(f):
                err(f"constraint {c}: field {f} empty")
    for inv in p.data["invariants"]:
        for f in ("code", "kind", "rule", "rationale", "cites"):
            if not inv.get(f):
                err(f"invariant {inv.get('code')}: field {f} empty")
    for t, td in p.types.items():
        for f in ("label", "enforced_by", "help"):
            if not td.get(f):
                err(f"resource type {t}: field {f} empty")
    shared = {u["service"] for u in p.data.get("shared_upstreams", [])}
    for h, hd in p.hosts.items():
        if shared & set(hd.get("serves", [])):
            err(f"host {h}: a shared upstream counts towards admission")
        for f in ("label", "client", "serves"):
            if not hd.get(f):
                err(f"host {h}: field {f} empty")
    for s, sd in p.services.items():
        for f in ("label", "description", "ceiling"):
            if not sd.get(f):
                err(f"service {s}: field {f} empty")
    waivable = set(p.data.get("waivable", []))
    for w in p.waivers:
        if w["invariant"] not in waivable:
            err(f"I14 waiver {w.get('id')} names non-waivable invariant {w['invariant']}")
        for f in ("id", "subject", "group", "target", "levels", "rationale", "controls", "review_by"):
            if not w.get(f):
                err(f"waiver {w.get('id')}: field {f} empty")


def _members(p, err):
    seen = {}
    for g, gd in p.groups.items():
        for m in gd["members"]:
            if m["type"] == "ui":
                continue  # one host may front several groups by design
            for k in _member_keys(m):
                if k in seen and seen[k] != g:
                    err(f"I14 member {k} in both {seen[k]} and {g}")
                seen[k] = g


def _cells(p, err):
    for g, row in p.matrix.items():
        if g not in p.groups:
            continue
        gd = p.groups[g]
        member_types = {m["type"] for m in gd["members"]}
        for r in row:
            lv, con, applies = p.cell(g, r)
            if lv != p.closure(lv):
                err(f"I16 {g}.{r}: {sorted(lv)} not closed under implies (needs {sorted(p.closure(lv))})")
            for l in lv:
                if l == "N":
                    err(f"{g}.{r}: N written explicitly")
                elif not any(l in p.types[t]["levels"] for t in member_types):
                    err(f"I14 {g}.{r}: level {l} compiles to no member type of the group ({sorted(member_types)})")
            if "A" in lv and "approval" not in gd:
                err(f"I14 {g}.{r}: A on a group without an approval rule")
            if con:
                if con not in p.constraints:
                    err(f"{g}.{r}: unknown constraint {con}")
                if not applies <= lv:
                    err(f"I14 {g}.{r}: constraint applies to levels the cell does not hold")


def _waived_i11(p, role, tool, target, levels):
    return any(w["invariant"] == "I11" and w["subject"] == role and w["group"] == tool
               and w["target"] == target and levels <= set(w["levels"]) for w in p.waivers)


def _matrix_invariants(p, err, note):
    approval = {g for g, gd in p.groups.items() if "approval" in gd}
    for r in p.roles:
        for g in p.groups:
            lv = p.effective(g, r)
            cls = p.group_class(g)
            if cls in ("regulated", "history") and lv & {"U", "D"}:
                err(f"I1 {r} holds {sorted(lv & {'U', 'D'})} on {cls} group {g}")
            if r == "admin" and cls in ("regulated", "history", "personal") and lv - {"K"}:
                err(f"I2 admin holds {sorted(lv - {'K'})} on {cls} group {g}")
            if r == "auditor" and lv - {"R", "X"}:
                err(f"I3 auditor holds {sorted(lv - {'R', 'X'})} on {g}")
            if g in approval and lv & PRODUCER and "A" in lv:
                err(f"I4 {r} holds producer {sorted(lv & PRODUCER)} and A on {g}")
            if r in SCIENTISTS and g in I5_GROUPS and lv:
                err(f"I5 {r} holds {sorted(lv)} on {g}")
            if r in ("operator", "production_manager") and g == "research_workbench" and lv:
                err(f"I6 {r} holds {sorted(lv)} on research_workbench")
            if r == "engineer" and g == "research_workbench" and lv - {"R"}:
                err(f"I6 engineer holds {sorted(lv)} on research_workbench")
            if r == "qp" and lv & PRODUCER:
                err(f"I7 qp holds {sorted(lv & PRODUCER)} on {g}")
            if r != "admin" and lv & {"K", "D"}:
                err(f"I13 {r} holds {sorted(lv & {'K', 'D'})} on {g}")
            if "D" in lv and g != "platform_admin":
                err(f"I13 D outside platform_admin ({g})")
    if "qp" in p.roles and "runs" in p.groups and "A" not in p.direct("runs", "qp")[0]:
        err("I7 qp holds no A on runs")

    for r in p.roles:
        for tool in p.groups:
            for target, lv in p.reach(tool, r).items():
                missing = lv - p.direct(target, r)[1]
                if not missing:
                    continue
                if _waived_i11(p, r, tool, target, missing):
                    note(f"waived I11: {r} → {target} {sorted(missing)} via {tool}")
                else:
                    err(f"I11 {r} reaches {sorted(missing)} on {target} through {tool} without holding it unconstrained")

    for g in ("iam_policy", "iam_users"):
        if g not in p.groups:
            continue
        approvers = [r for r in p.roles if "A" in p.direct(g, r)[0]]
        if not [r for r in approvers if r != "admin"]:
            err(f"I12 no non-admin role holds A on {g}")
        if "admin" in approvers:
            err(f"I12 admin holds A on {g}")

    for s, sd in p.services.items():
        for g, lv in (sd.get("ceiling") or {}).items():
            if g not in p.groups:
                err(f"service {s}: ceiling names unknown group {g}")
                continue
            if "A" in lv and (s, g) not in SERVICE_APPROVERS:
                err(f"I10 {s} holds A on {g}")
            bad = set(lv) & {"U", "D"}
            if p.group_class(g) in ("regulated", "history") and bad:
                if any(w["invariant"] == "I10" and w["subject"] == s and w["group"] == g
                       and bad <= set(w["levels"]) for w in p.waivers):
                    note(f"waived I10: {s} {sorted(bad)} on {g}")
                else:
                    err(f"I10 {s} ceiling {sorted(bad)} on {p.group_class(g)} group {g} without a waiver")


def check(p):
    """(errors, notes) for a loaded Policy."""
    from compiler import grants, netpol  # the database and network sections' own checkers
    errors, notes = [], []
    _structure(p, errors.append)
    if errors:
        return errors, notes  # the rest assumes a well-formed file
    errors.extend(netpol.check(p))
    errors.extend(grants.check(p))
    _help(p, errors.append)
    _members(p, errors.append)
    _cells(p, errors.append)
    _matrix_invariants(p, errors.append, notes.append)
    return errors, notes
