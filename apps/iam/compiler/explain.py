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

Slice 4.0: pure functions; nothing in a deploy calls them yet.
"""
from compiler import grants, mqtt, proxies, routes, tools


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
