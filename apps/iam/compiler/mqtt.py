"""apps/iam/compiler/mqtt.py — the MQTT Explorer's per-person credential, from the policy.

compile(policy) returns mqtt.json, which deploy-infra.sh writes into ConfigMap
medcea-iam-lib next to routes.json and iam-api (iam-mqttx, IAM 3.5) reads when it issues
a credential:
  tool        the group whose R admits a person (mqtt_explorer: `mirrors` the topic groups)
  ttl_hours, max_active, listener
              the group's `credential:` block (policy data, no constant here)
  roles       {role: [{access, topic, group, constraint}]} for every role holding R on the
              tool unconstrained (the roles POST /_mqtt-credential admits). R on a mirrored
              group gives a read row on each of its mqtt members, C or U a write row unless
              the member says `person_write: false`. `topic` has the root segment stripped
              (iam-api prefixes PROJECT_NAME); `constraint` is the level's (writes:
              commissioning_unit, which the broker's auth sidecar re-derives every sync)
  digest      SHA-256 of the canonical body, as routes.json
Its own ConfigMap key, so it never moves routes.json's digest (role_widening's stamp).

check(policy) returns the errors invariants.py adds on every check:
  - a person's C/U on a group with mqtt members without commissioning_unit for that
    level, or a constrained R there (the broker honours person write rows only for a
    commissioning unit, and evaluates nothing else)
  - an mqtt topic that is not medcea/<seg|+>/<seg|+>/(sense|control|control_setpoint)/#
  - a role admitted to the tool that would get no topic (an empty credential), or a
    constrained cell on the tool (iam-api cannot evaluate it)
  - a service identity whose mqtt_user starts with explorer- (person credentials' names)
  - a tool group without a usable `credential:` block
"""
import hashlib
import json
import re

TOOL = "mqtt_explorer"
SCHEMA = 1
WRITE_CONSTRAINT = "commissioning_unit"     # the one constraint the broker's sidecar evaluates
PERSON_PREFIX = "explorer-"                 # usernames of person credentials (iam-api)
TOPIC = re.compile(r"^medcea/(\+|[A-Za-z0-9_-]+)/(\+|[A-Za-z0-9_-]+)/(sense|control|control_setpoint)/#$")
CREDENTIAL_KEYS = {"ttl_hours", "max_active", "listener", "help"}
LISTENERS = {"websocket"}


def _mqtt_groups(p):
    return [g for g in (p.groups.get(TOOL, {}).get("mirrors") or [])
            if any(m["type"] == "mqtt" for m in p.groups[g]["members"])]


def _level(p, group, role, level):
    """None (not held), "free", or the sorted constraints under which the role holds the
    level on the group through its own cells (composites and implies expanded; never a
    tool's reach: the credential carries the person's own rights only)."""
    free, cons = False, set()
    for e in p.effective_roles(role):
        c = p.cell(group, e)
        if not c:
            continue
        lv, con, applies = c
        if level not in p.closure(lv):
            continue
        hit = {l for l in lv if level in p.closure({l})}
        if not con or hit - applies:
            free = True
        else:
            cons |= {con[l] for l in hit if l in con}
    if free:
        return "free"
    return sorted(cons) or None


def admitted(p):
    """Sorted roles holding R on the tool unconstrained."""
    return sorted(r for r in p.roles if _level(p, TOOL, r, "R") == "free")


def rows(p, role):
    """The role's [{access, topic, group, constraint}], sorted."""
    out = []
    for g in _mqtt_groups(p):
        read = _level(p, g, role, "R")
        write = next((w for w in (_level(p, g, role, l) for l in ("C", "U")) if w), None)
        for m in p.groups[g]["members"]:
            if m["type"] != "mqtt":
                continue
            topic = m["topic"].split("/", 1)[1]
            if read:
                out.append({"access": "read", "topic": topic, "group": g,
                            "constraint": None if read == "free" else ",".join(read)})
            if write and m.get("person_write", True) is not False:
                out.append({"access": "write", "topic": topic, "group": g,
                            "constraint": None if write == "free" else ",".join(write)})
    return sorted(out, key=lambda r: (r["access"], r["topic"]))


def compile(p):
    """mqtt.json for a loaded Policy (call check() first)."""
    cred = p.groups[TOOL]["credential"]
    body = {
        "schema": SCHEMA,
        "policy_version": p.data.get("policy_version"),
        "tool": TOOL,
        "ttl_hours": cred["ttl_hours"],
        "max_active": cred["max_active"],
        "listener": cred["listener"],
        "roles": {r: rows(p, r) for r in admitted(p)},
    }
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    body["digest"] = hashlib.sha256(canon.encode()).hexdigest()
    return body


def dumps(doc):
    """mqtt.json as written to the ConfigMap: canonical, one line."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"))


def check(p):
    errors = []
    err = errors.append
    for g, gd in p.groups.items():
        for m in gd["members"]:
            if m["type"] != "mqtt":
                continue
            if not TOPIC.match(m.get("topic") or ""):
                err(f"mqtt {g}: topic {m.get('topic')!r} is not medcea/<unit|+>/<zone|+>/(sense|control|control_setpoint)/#")
            if set(m) - {"type", "topic", "person_write"}:
                err(f"mqtt {g}: member {m.get('topic')!r} has keys other than type, topic, person_write")
        if not any(m["type"] == "mqtt" for m in gd["members"]):
            continue
        for r in p.roles:
            if _level(p, g, r, "R") not in (None, "free"):
                err(f"mqtt {g}.{r}: a constrained R; the broker evaluates no read constraint")
            for l in ("C", "U"):
                c = _level(p, g, r, l)
                if c and c != [WRITE_CONSTRAINT]:
                    err(f"mqtt {g}.{r}: {l} {'without a constraint' if c == 'free' else 'under ' + ', '.join(c)}; "
                        f"the broker honours person write rows only for a commissioning unit ({WRITE_CONSTRAINT})")
    for s, sd in p.services.items():
        if str(sd.get("mqtt_user") or "").startswith(PERSON_PREFIX):
            err(f"mqtt service {s}: mqtt_user {sd['mqtt_user']} is in the {PERSON_PREFIX} namespace of person credentials")
    gd = p.groups.get(TOOL)
    if not gd:
        return errors
    cred = gd.get("credential")
    if not isinstance(cred, dict):
        err(f"mqtt {TOOL}: no credential block (ttl_hours, max_active, listener, help)")
    else:
        if set(cred) - CREDENTIAL_KEYS:
            err(f"mqtt {TOOL}: credential has unknown key(s) {', '.join(sorted(map(str, set(cred) - CREDENTIAL_KEYS)))}")
        ttl, n = cred.get("ttl_hours"), cred.get("max_active")
        if not (isinstance(ttl, int) and not isinstance(ttl, bool) and 1 <= ttl <= 24):
            err(f"mqtt {TOOL}: credential ttl_hours {ttl!r} is not a whole number of hours from 1 to 24")
        if not (isinstance(n, int) and not isinstance(n, bool) and 1 <= n <= 10):
            err(f"mqtt {TOOL}: credential max_active {n!r} is not 1 to 10")
        if cred.get("listener") not in LISTENERS:
            err(f"mqtt {TOOL}: credential listener {cred.get('listener')!r} is not one of {', '.join(sorted(LISTENERS))}")
        if not cred.get("help"):
            err(f"mqtt {TOOL}: credential help empty")
    for r in p.roles:
        lv = _level(p, TOOL, r, "R")
        if lv not in (None, "free"):
            err(f"mqtt {TOOL}.{r}: a constrained cell; iam-api cannot evaluate it")
        elif lv == "free" and not rows(p, r):
            err(f"mqtt {TOOL}.{r}: admitted to the Explorer, but the credential would carry no topic")
    return errors
