"""apps/iam/compiler/routes.py — the route table every service checks a request against.

compile(policy) returns the document deploy-infra.sh writes into ConfigMap medcea-iam-lib
as routes.json and medcea_iam.check() reads (plan Section 3.2). Per service:
  clients   the Keycloak clients whose tokens it accepts (the azp check): the client of
            every host that serves it; a shared upstream (/_account/) accepts them all
  routes    "METHOD /path" -> {group, levels, roles}. `levels` is the route's level, or
            the levels any of which opens it ([R, K]). `roles` maps every role that may
            call the route to null (unconstrained) or the constraints that must hold,
            composites and implies expanded, so check() needs no matrix logic of its own.
  public    routes that need no platform role (`public_routes`); "*" applies to every
            service
  roles     the platform roles: check() keeps only these from a token's groups claim
  role_includes
            {role: [the roles it includes, transitively]} (Keycloak composites):
            medcea_iam.actor_role() takes a person's own role the way the database's
            _own_role() does — the held roles minus every role another held one includes
  widening  {old role or "-": {new role: [[group, level], ...]}}: what a role change adds
            (model.Policy.widening, qa_dual_control), non-empty entries only. The database
            decides with medcea_auth.role_widening(), compiled from the same rule (grants.py)
            and stamped with this document's digest; the User Manager shows "waits for qa"
  waivers   [{id, invariant, subject, target, levels, review}] for the access review snapshot
A route missing from the table is refused. The body is canonical JSON, and `digest` is
its SHA-256, so two compiles of one policy are byte-identical.
"""
import hashlib
import json
import re

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
_ROUTE = re.compile(r"^(%s) (/[^\s]*)$" % "|".join(METHODS))
SCHEMA = 1


class RouteError(ValueError):
    pass


def _levels(lv):
    return lv if isinstance(lv, list) else [lv]


def _who(p, group, levels):
    """{role: None | [constraints]} for every role holding one of `levels` on the group.
    A role passes unconstrained if any effective role's cell holds a level outside the
    cell's applies_to (or the cell has no constraint)."""
    out = {}
    for r in p.roles:
        free, cons = False, set()
        for e in p.effective_roles(r):
            c = p.cell(group, e)
            if not c:
                continue
            lv, con, applies = c
            hit = p.closure(lv) & set(levels)
            if not hit:
                continue
            if not con or hit - applies:
                free = True
            else:
                cons |= {con[l] for l in hit}
        if free:
            out[r] = None
        elif cons:
            out[r] = sorted(cons)
    return out


def _clients(p):
    clients = {}
    for hd in p.hosts.values():
        for s in hd["serves"]:
            clients.setdefault(s, set()).add(hd["client"])
    every = {hd["client"] for hd in p.hosts.values()}
    for u in p.data.get("shared_upstreams", []):
        clients[u["service"]] = set(every)
    return clients


def widening_table(p):
    """{old or "-": {new: [[group, level], ...]}} over every pair of platform roles, from
    model.Policy.widening; an empty change is left out (missing means "adds nothing")."""
    out = {}
    for old in [None] + sorted(p.roles):
        row = {}
        for new in sorted(p.roles):
            w = p.widening(old, new)
            if w:
                row[new] = [[g, l] for g, l in w]
        if row:
            out["-" if old is None else old] = row
    return out


def compile(p, source="defaults.yaml"):
    """The route table document for a loaded Policy. Raises RouteError on a malformed
    route or a route that is both public and in a group."""
    services = {}
    for g, gd in p.groups.items():
        for m in gd["members"]:
            if m["type"] != "api":
                continue
            for route, lv in m["routes"].items():
                if not _ROUTE.match(route):
                    raise RouteError(f"group {g}: route {route!r} is not 'METHOD /path'")
                table = services.setdefault(m["service"], {})
                if route in table:
                    raise RouteError(f"route {m['service']} {route} is in {table[route]['group']} and {g}")
                levels = _levels(lv)
                table[route] = {"group": g, "levels": levels, "roles": _who(p, g, levels)}

    public = {}
    for pr in p.data.get("public_routes", []):
        if not _ROUTE.match(pr["route"]):
            raise RouteError(f"public route {pr['route']!r} is not 'METHOD /path'")
        public.setdefault(pr["service"], []).append(pr["route"])
        for s, table in services.items():
            if pr["service"] in ("*", s) and pr["route"] in table:
                raise RouteError(f"{s} {pr['route']} is public and in group {table[pr['route']]['group']}")

    clients = _clients(p)
    body = {
        "schema": SCHEMA,
        "policy_version": p.data.get("policy_version"),
        "source": source,
        "roles": sorted(p.roles),
        "role_includes": {r: sorted(p.effective_roles(r) - {r}) for r in sorted(p.roles)},
        "services": {s: {"clients": sorted(clients.get(s, ())), "routes": t} for s, t in services.items()},
        "public": {s: sorted(r) for s, r in public.items()},
        "widening": widening_table(p),
        "waivers": [{"id": w["id"], "invariant": w["invariant"], "subject": w["subject"], "target": w["target"],
                     "levels": list(w["levels"]), "review": w.get("review_by")} for w in p.waivers],
    }
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    body["digest"] = hashlib.sha256(canon.encode()).hexdigest()
    return body


def dumps(doc):
    """routes.json as written to the ConfigMap: canonical, one line."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"))
