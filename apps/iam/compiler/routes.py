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
A route missing from the table is refused. The body is canonical JSON, and `digest` is
its SHA-256, so two compiles of one policy are byte-identical.
"""
import hashlib
import json
import re

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
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
                cons.add(con)
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
        "services": {s: {"clients": sorted(clients.get(s, ())), "routes": t} for s, t in services.items()},
        "public": {s: sorted(r) for s, r in public.items()},
    }
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    body["digest"] = hashlib.sha256(canon.encode()).hexdigest()
    return body


def dumps(doc):
    """routes.json as written to the ConfigMap: canonical, one line."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"))
