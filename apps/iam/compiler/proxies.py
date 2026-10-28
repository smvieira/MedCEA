"""apps/iam/compiler/proxies.py — which platform roles each signed-in host admits.

A host's allowed_groups is every role holding, on any group with a member served there,
a level that member admits: a `ui` member on the host (its `admit` list, or any level but
N), or an `api` member of a service the host serves (`hosts.<HOST>.serves`). Levels are
the role's own and inherited cells with implies expanded; tool reach does not admit
anyone to a host. Shared upstreams (/_account/) are not in `serves` and never count.
"""

ANY = None  # admit any level but N

# Hosts whose gate is compiled from the policy today, and when the others follow
# (codeplan/MedCEA_IAM_Implementation_Plan.md). `cli.py hosts` prints the status,
# so the policy's intent is never read as what is running.
ENFORCEMENT = {
    "PORTAL_DOMAIN": "compiled", "CONFIG_DOMAIN": "compiled", "SCHEDULER_DOMAIN": "compiled",
    "MONITOR_DOMAIN": "compiled", "DBMGMT_DOMAIN": "compiled", "MQTTX_DOMAIN": "compiled",
    "NODE_RED_DOMAIN": "compiled",
    "ACCESS_DOMAIN": "admin only until Phase 2.7",
    "GRAFANA_DOMAIN": "not yet (Phase 3.1)", "WORKBENCH_DOMAIN": "not yet (Phase 3.2)",
    "ONBOARD_DOMAIN": "not yet (Phase 3.4; EDGE_WIZARD_ROLE)", "PGADMIN_DOMAIN": "admin (pgAdmin's own OAuth2)",
    "POLICY_DOMAIN": "not deployed (Phase 4)",
}


def _gates(p, host):
    """(group, admit-set or ANY) pairs that open this host."""
    serves = set(p.hosts[host]["serves"])
    out = []
    for g, gd in p.groups.items():
        for m in gd["members"]:
            if m["type"] == "ui" and m["host"] == host:
                out.append((g, set(m["admit"]) if m.get("admit") else ANY))
            elif m["type"] == "api" and m["service"] in serves:
                out.append((g, ANY))
    return out


def admitted(p, host):
    """Sorted platform roles the host admits."""
    if host not in p.hosts:
        raise KeyError(f"unknown host variable {host}; known: {', '.join(p.hosts)}")
    gates = _gates(p, host)
    roles = set()
    for r in p.roles:
        for g, admit in gates:
            held = p.direct(g, r)[0] - {"N"}
            if held and (admit is ANY or held & admit):
                roles.add(r)
                break
    return sorted(roles)


def toml_list(roles):
    """The oauth2-proxy alpha-config spelling: ["a", "b"]."""
    return "[" + ", ".join(f'"{r}"' for r in roles) + "]"


def describe(p, host, roles):
    """(host label, role labels in the policy's order) for a gate's error page. `roles`
    is the list the gate was deployed with, not recomputed, so the page names exactly
    the roles that gate admits (IAM_GATES=false or a fixed list included)."""
    if host not in p.hosts:
        raise KeyError(f"unknown host variable {host}; known: {', '.join(p.hosts)}")
    unknown = sorted(set(roles) - set(p.roles))
    if unknown:
        raise KeyError(f"unknown role(s) {', '.join(unknown)}")
    return p.hosts[host]["label"], [p.roles[r]["label"] for r in p.roles if r in roles]
