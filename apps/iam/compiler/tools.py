"""apps/iam/compiler/tools.py — a tool's own role setting, compiled from a group's `tool:` block.

A tool that signs people in itself (Grafana in IAM 3.1, JupyterHub in 3.2, Node-RED's
editor in 3.3, the edge wizard and pgAdmin in 3.4) cannot read the route table, so its role
setting is compiled here. The level-to-setting mapping is policy data under the group
(schema_version 3), not a constant in this file:

  tool: {kind: grafana, host: GRAFANA_DOMAIN, service_identity: svc_grafana,
         settings: [{setting: Editor, levels: [U]}, {setting: Viewer, levels: [R]}],
         otherwise: refuse, help: ...}

A role gets the first setting whose levels it holds unconstrained on the group (its own
and inherited cells, implies expanded); a role with none is refused. check() keeps that
equal to the host's gate (proxies.admitted): every role the host admits gets a setting,
nobody else does. A tool cannot evaluate a constraint, so a constrained level on the group
is an error, and `reaches` must cover the datasource account's ceiling, so I11 sees
everything the tool's own credential reads (JupyterHub has none: a notebook holds no
platform credential). The one exception is `constraint_enforced_by`, on a tool with no
service identity: it writes with the person's own token, so the database still evaluates
the constraint, and a constrained level then counts (the edge wizard: maintenance's
existing_slot, refused at registration, after the erase).

The edge wizard's check (edge/src/host/edge_auth.has_role) also accepts a client role or
a `groups` entry with the same name; no client defines engineer or maintenance roles.
"""
import re

from compiler import proxies

# kind -> the settings the policy may name. Grafana's Admin and GrafanaAdmin are left out on
# purpose: only the local break-glass account holds them (allow_assign_grafana_admin false).
KINDS = {"grafana": {"Editor", "Viewer"}, "jupyterhub": {"admin", "user"}, "node-red": {"editor"},
         "edge-wizard": {"onboard"}, "pgadmin": {"sign_in"}}
# (kind, setting) -> the only levels that may give it. JupyterHub's admin is administration
# (K, which I13 keeps with admin): a hub admin given by R would be every notebook user.
# Node-RED's editor deploys code that runs with svc_ingest: Update, never Read.
# The edge wizard erases a board before it registers it: only who may register (C) or
# re-register (U). pgAdmin shows the whole schema: administration (K) only.
SETTING_LEVELS = {("jupyterhub", "admin"): {"K"}, ("node-red", "editor"): {"U"},
                  ("edge-wizard", "onboard"): {"C", "U"}, ("pgadmin", "sign_in"): {"K"}}
SERVICE_IDENTITY = {"grafana", "node-red"}   # kinds that read the platform with their own credential
# Node-RED adminAuth permissions per setting: every editor scope but nodes.write, so palette
# modules arrive only from apps/node-red/packages.txt in git (IAM 3.3 decision). Node-RED's
# own "read" is no setting on purpose: GET /flows returns the postgreSQLConfig password.
NODE_RED_PERMISSIONS = {"editor": ["read", "flows.write", "context.write", "library.write",
                                   "settings.write", "inject.write", "debug.write"]}
KEYS = {"kind", "host", "service_identity", "settings", "otherwise", "help", "constraint_enforced_by"}
ROLE_NAME = re.compile(r"^[a-z_]+$")   # spliced into JMESPath (Grafana) and config files


def groups(p, kind=None):
    """Sorted groups carrying a `tool:` block (of one kind, if given)."""
    return sorted(g for g, gd in p.groups.items()
                  if gd.get("tool") and (kind is None or gd["tool"].get("kind") == kind))


def settings(p, group):
    """[(setting, sorted roles)] in the policy's order: each role under the first setting
    whose levels it holds unconstrained on the group; a role with none is left out."""
    out, placed = [], set()
    which = 0 if p.groups[group]["tool"].get("constraint_enforced_by") else 1   # held, or free only
    for s in p.groups[group]["tool"]["settings"]:
        roles = sorted(r for r in p.roles if r not in placed and set(s["levels"]) & p.direct(group, r)[which])
        placed |= set(roles)
        out.append((s["setting"], roles))
    return out


def _one(p, kind):
    gs = groups(p, kind)
    if len(gs) != 1:
        raise ValueError(f"expected one group with a {kind} tool block, found {len(gs)}: {', '.join(gs) or 'none'}")
    return gs[0]


def grafana_role_path(p):
    """GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH over the `groups` claim. Ends in '', which
    role_attribute_strict refuses: no setting, no sign-in."""
    clauses = []
    for setting, roles in settings(p, _one(p, "grafana")):
        if roles:
            any_of = " || ".join(f"contains(groups[*], '{r}')" for r in roles)
            clauses.append(f"({any_of}) && '{setting}'")
    return " || ".join(clauses + ["''"])


def jupyterhub_groups(p, which):
    """JupyterHub's allowed_groups (every role given a setting: the host's gate) or
    admin_groups (the roles given `admin`: the members of the hub role workbench-admin,
    k8s/workbench/values.yaml hub.loadRoles; never OAuthenticator's admin_groups), sorted. allowed_groups is never empty:
    allow_all false would then lock everyone out."""
    given = settings(p, _one(p, "jupyterhub"))
    if which == "allowed_groups":
        roles = sorted(r for _, rs in given for r in rs)
        if not roles:
            raise ValueError("no role is given a JupyterHub setting: the hub would admit nobody")
        return roles
    if which == "admin_groups":
        return sorted(r for s, rs in given if s == "admin" for r in rs)
    raise ValueError(f"unknown JupyterHub setting {which}; known: allowed_groups, admin_groups")


def node_red_permissions(p):
    """ConfigMap node-red-auth's permissions.json: {"group", "policy_version", "permissions":
    {role: [scope, ...]}, "default": null}. k8s/node-red/settings.js reads it at every editor
    login; a role not listed gets no editor (adminAuth has no default user)."""
    g = _one(p, "node-red")
    perms = {r: NODE_RED_PERMISSIONS[s] for s, roles in settings(p, g) for r in roles}
    return {"group": g, "policy_version": p.data.get("policy_version"), "permissions": perms, "default": None}


def _admitted_roles(p, kind, what):
    """Sorted roles given any setting of the one `kind` tool; never empty (fail closed)."""
    roles = sorted(r for _, rs in settings(p, _one(p, kind)) for r in rs)
    if not roles:
        raise ValueError(f"no role is given a {kind} setting: {what}")
    return roles


def edge_wizard_roles(p):
    """The onboarding wizard's --required-role list (edge_auth.roles_of: any one admits).
    Never empty: an empty --required-role admits any signed-in account."""
    return _admitted_roles(p, "edge-wizard", "an empty --required-role would admit any signed-in account")


def pgadmin_claims(p):
    """pgAdmin's OAUTH2_ADDITIONAL_CLAIMS as a Python literal ({'groups': [...]}):
    PGADMIN_CONFIG_* is written verbatim into config_distro.py. Never empty."""
    return repr({"groups": _admitted_roles(p, "pgadmin", "pgAdmin would admit nobody")})


def check(p):
    """Errors in the `tool:` blocks, each starting with `tool <group>:`."""
    errors = []
    for g in groups(p):
        gd, t = p.groups[g], p.groups[g]["tool"]
        err = lambda m, g=g: errors.append(f"tool {g}: {m}")  # noqa: E731
        if set(t) - KEYS:
            err(f"unknown key(s) {', '.join(sorted(map(str, set(t) - KEYS)))}")
        kind = t.get("kind")
        if kind not in KINDS:
            err(f"unknown kind {kind}; known: {', '.join(sorted(KINDS))}")
            continue
        if not t.get("help"):
            err("help empty")
        if t.get("otherwise") != "refuse":
            err(f"otherwise must be refuse (no setting, no sign-in), not {t.get('otherwise')}")
        ui_hosts = {m["host"] for m in gd["members"] if m["type"] == "ui"}
        host = t.get("host")
        if host not in ui_hosts:
            err(f"host {host} is not a ui member of the group")
            continue
        entries = t.get("settings") or []
        if not entries:
            err("no settings")
        bad = False
        for s in entries:
            if s.get("setting") not in KINDS[kind]:
                err(f"setting {s.get('setting')} is not one the policy may give for {kind} "
                    f"({', '.join(sorted(KINDS[kind]))})")
                bad = True
            for lv in s.get("levels") or [None]:
                if lv == "N" or lv not in p.types["ui"]["levels"]:
                    err(f"setting {s.get('setting')}: level {lv} is not a ui level")
                    bad = True
                only = SETTING_LEVELS.get((kind, s.get("setting")))
                if only and lv not in only:
                    err(f"setting {s.get('setting')}: level {lv} cannot give {kind}'s {s.get('setting')} "
                        f"(only {', '.join(sorted(only))})")
                    bad = True
        if bad:
            continue
        for r in p.roles:
            if not ROLE_NAME.match(r):
                err(f"role name {r} cannot be spliced into a {kind} setting")
            held, free = p.direct(g, r)
            if held - free and not t.get("constraint_enforced_by"):
                err(f"{r} holds {sorted(held - free)} only under a constraint, which {kind} cannot evaluate")
        given = {r for _, roles in settings(p, g) for r in roles}
        admitted = set(proxies.admitted(p, host))
        if given != admitted:
            err(f"{host} admits {sorted(admitted)} but {kind} gives a role to {sorted(given)} "
                f"(missing: {sorted(admitted - given) or 'none'}; extra: {sorted(given - admitted) or 'none'})")
        sid = t.get("service_identity")
        if t.get("constraint_enforced_by") is not None and (kind in SERVICE_IDENTITY or sid is not None):
            err("constraint_enforced_by on a tool with its own credential: nothing downstream sees the person")
        if kind not in SERVICE_IDENTITY:
            if sid is not None:
                err(f"{kind} reads nothing with its own credential: no service_identity")
            continue
        if sid not in p.services:
            err(f"service_identity {sid} is not a service identity")
            continue
        reaches = gd.get("reaches") or {}
        for tg, lv in (p.services[sid].get("ceiling") or {}).items():
            short = set(lv) - p.closure(reaches.get(tg, []))
            if short:
                err(f"{sid} reads {sorted(short)} on {tg} but reaches does not list it, so I11 cannot see it")
    return errors
