#!/usr/bin/env python3
"""Platform database access for the onboarding wizard.

The wizard runs on the HOST, outside the cluster, but a device's identity comes
from the platform: a board is a SENSE or a CONTROL in one zone of one unit, and
those rows already exist in `medcea.cea_unit` / `medcea.cea_zone`. Typing a unit code
by hand is how a board ends up publishing to a topic nobody reads, so the wizard
offers only what the database actually has.

It reaches PostgREST (the `config-api` Service) by its ClusterIP. MicroK8s runs
kube-proxy on the host, so ClusterIPs are routable from here — no ingress, no
oauth2-proxy, no port-forward. The address is looked up with kubectl at call
time rather than cached in config.env, because a redeployed Service gets a new
one and a stale address would fail long after the deploy that caused it.

Three commands, all line-oriented so the shell stays the engine:

    slots           one line per (unit, zone, role) slot, free or taken
    board SERIAL    where a board (by serial = MAC hex) is registered, if anywhere
    register        read a device description on stdin, write it to the database

A unit/zone has one and only one SENSE and one and only one CONTROL. That rule
is enforced here, against the live table, rather than in the wizard's head.
"""

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 10
ROLES = ("SENSE", "CONTROL")
# A device has one name: its DHCP hostname, lower(unit)-<s|c>-lower(zone), e.g.
# unit02-c-zone02. It is dns_name in the database, device_dns in every MQTT
# payload and what DHCP registers. Built from the codes as they are in the
# database at onboarding; lowercasing is the only transformation, so a code a
# hostname cannot hold is refused with a reason rather than rewritten.
HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
# MicroPython's network hostname buffer (MICROPY_PY_NETWORK_HOSTNAME_MAX_LEN).
# Over it, the board keeps its default name and registers THAT with DHCP;
# flash-device.sh reads the name back after boot, so a wrong cap shows up loudly.
HOSTNAME_MAX = 32


class PlatformError(Exception):
    """The platform database could not be reached or refused the write."""


# ------------------------------------------------------------------ endpoint --
def _kubectl():
    """The kubectl that works for this user, or None.

    Plain `kubectl` when ~/.kube/config is set up, `microk8s kubectl` otherwise.
    Deliberately no sudo: the wizard runs as an unprivileged user service and
    must never sit waiting on a password prompt nobody can see.
    """
    for cmd in (["kubectl"], ["microk8s", "kubectl"]):
        try:
            subprocess.run(cmd + ["version", "--client"], timeout=15,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=True)
            return cmd
        except (OSError, subprocess.SubprocessError):
            continue
    return None


def api_base():
    """Base URL of the PostgREST service.

    CEA_CONFIG_API wins so a bench, a test, or a host that cannot run kubectl can
    point this somewhere else without touching the code.
    """
    override = os.environ.get("CEA_CONFIG_API", "").strip()
    if override:
        return override.rstrip("/")
    ns = os.environ.get("NAMESPACE", "medcea")
    kc = _kubectl()
    if kc is None:
        raise PlatformError(
            "no usable kubectl, and CEA_CONFIG_API is not set — cannot find the "
            "platform database")
    try:
        out = subprocess.run(
            kc + ["get", "svc", "config-api", "-n", ns,
                  "-o", "jsonpath={.spec.clusterIP}"],
            timeout=20, capture_output=True, text=True, check=True).stdout.strip()
    except subprocess.CalledProcessError as e:
        raise PlatformError(
            "kubectl could not find the config-api Service in namespace %s: %s"
            % (ns, (e.stderr or "").strip())) from e
    except (OSError, subprocess.SubprocessError) as e:
        raise PlatformError("kubectl failed: %s" % e) from e
    if not out or out == "None":
        raise PlatformError(
            "the config-api Service in namespace %s has no ClusterIP — is the "
            "frontend deployed? (apps/frontend/deploy.sh)" % ns)
    return "http://%s:3000" % out


def _request(base, path, method="GET", body=None, prefer=None):
    url = base + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if prefer:
        headers["Prefer"] = prefer
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            raw = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:400]
        raise PlatformError("%s %s -> HTTP %d %s" % (method, path, e.code, detail)) from e
    except (urllib.error.URLError, OSError) as e:
        raise PlatformError("cannot reach the platform database at %s: %s" % (url, e)) from e
    if not raw.strip():
        return []
    try:
        return json.loads(raw)
    except ValueError as e:
        raise PlatformError("the platform database returned unparseable JSON") from e


# ---------------------------------------------------------------- hostname ----
def slot_hostname(unit_code, role, zone_code):
    """(hostname, None) for a slot, or (None, reason) when the codes cannot form one.

    UNIT02 + CONTROL + ZONE02 -> unit02-c-zone02. Unique without any collision
    check: unit codes are unique ignoring case, zone codes are unique per unit
    ignoring case (migration 005), and the role letter tells SENSE from CONTROL.
    """
    name = "%s-%s-%s" % ((unit_code or "").lower(), role[0].lower(),
                         (zone_code or "").lower())
    if not HOSTNAME_RE.match(name):
        return None, ("'%s / %s' gives '%s', which is not a legal hostname (letters, digits and "
                      "inner hyphens only): rename the code in the Units tab"
                      % (unit_code, zone_code, name))
    if len(name) > HOSTNAME_MAX:
        return None, ("'%s / %s' gives '%s', %d characters; a board accepts at most %d: "
                      "shorten the code in the Units tab"
                      % (unit_code, zone_code, name, len(name), HOSTNAME_MAX))
    return name, None


# ------------------------------------------------------------------- slots ----
def slots(base):
    """Every (unit, zone, role) slot the platform knows about, with its occupant.

    Inactive units and zones are left out: a slot in a decommissioned chamber is
    not somewhere a board should be sent.
    """
    units = _request(base, "/cea_unit?select=unit_id,unit_code,unit_type,is_active"
                           "&order=unit_code")
    zones = _request(base, "/cea_zone?select=zone_id,unit_id,zone_code,zone_description,"
                           "is_active&order=zone_code")
    devices = _request(base, "/device?select=device_id,zone_id,device_type,dns_name,"
                             "serial_number,is_active")

    units = [u for u in units if (u.get("is_active") or "Y") == "Y"]
    zones = [z for z in zones if (z.get("is_active") or "Y") == "Y"]
    by_unit = {u["unit_id"]: u for u in units}

    # Who already holds each (zone, role). Inactive devices do not hold a slot —
    # that is how a retired board is replaced without editing the database first.
    held = {}
    for d in devices:
        if (d.get("is_active") or "Y") != "Y" or d.get("zone_id") is None:
            continue
        role = (d.get("device_type") or "").upper()
        if role in ROLES:
            held[(d["zone_id"], role)] = d

    out = []
    for z in zones:
        u = by_unit.get(z["unit_id"])
        if u is None:
            continue
        for role in ROLES:
            occupant = held.get((z["zone_id"], role))
            host, why = slot_hostname(u["unit_code"], role, z["zone_code"])
            out.append({
                "unit_id": u["unit_id"],
                "unit_code": u["unit_code"],
                "unit_type": u.get("unit_type") or "",
                "zone_id": z["zone_id"],
                "zone_code": z["zone_code"],
                "zone_description": z.get("zone_description") or "",
                "role": role,
                # "unnamed": the codes cannot form a hostname; occupant carries
                # the reason, so the wizard can say what to rename.
                "state": "taken" if occupant else ("free" if host else "unnamed"),
                "occupant": (occupant or {}).get("dns_name") or (why or ""),
                "occupant_serial": (occupant or {}).get("serial_number") or "",
                "device_dns": host or "",
                "hostname": host or "",
            })
    return out


def print_slots(base):
    rows = slots(base)
    for s in rows:
        # Tab-separated because a zone description may contain anything; the
        # shell reads it with IFS=$'\t'.
        print("SLOT\t%s" % "\t".join(str(s[k]).replace("\t", " ") for k in (
            "unit_code", "zone_code", "zone_id", "role", "state", "device_dns",
            "hostname", "occupant", "unit_type", "zone_description")))
    if not rows:
        print("NONE", file=sys.stderr)
    return 0


# ---------------------------------------------------------------- register ----
def register(base, spec):
    """Insert or update one device and replace its components.

    Re-flashing a board must not create a second row for the same slot, so this
    keys on the SLOT — zone_id + device_type, the most recent row, active or not —
    and updates it in place, dns_name included. Not on dns_name: that is built from
    the unit and zone codes, so renaming a code would make the next onboarding miss
    the slot's row and insert a second one. dns_name is the fallback for a spec
    without a zone. Components are replaced wholesale
    rather than merged: the pins the operator just chose ARE the component, and
    a half-updated pin map is worse than either version of it.
    """
    dns = spec["dns_name"]
    row = {k: spec[k] for k in (
        "zone_id", "device_type", "model", "manufacturer", "serial_number",
        "connection_type", "dns_name") if spec.get(k) is not None}
    row.setdefault("is_active", "Y")
    if spec.get("installation_date"):
        row["installation_date"] = spec["installation_date"]

    slot = spec.get("zone_id") is not None and spec.get("device_type")
    move_id = int(spec["move_device_id"]) if spec.get("move_device_id") else None

    if move_id:
        # A board moving to another slot (the operator said yes in the wizard):
        # its own row follows it, because serial_number is unique and a second
        # row for the same board is not an option. An older, inactive row still
        # in the target slot steps aside — renamed <name>-<id>, since dns_name
        # is unique too — so the moved row can take the slot's name.
        if slot:
            for o in _request(base, "/device?select=device_id,dns_name&zone_id=eq.%d"
                                    "&device_type=eq.%s&device_id=neq.%d"
                              % (int(spec["zone_id"]), _q(spec["device_type"]), move_id)):
                if o.get("dns_name") == dns:
                    _request(base, "/device?device_id=eq.%d" % o["device_id"], "PATCH",
                             {"dns_name": "%s-%d" % (dns, o["device_id"]), "is_active": "N"})
        target, action = move_id, "moved"
    else:
        found = []
        if slot:
            found = _request(base, "/device?select=device_id&zone_id=eq.%d&device_type=eq.%s"
                                   "&order=device_id.desc&limit=1"
                             % (int(spec["zone_id"]), _q(spec["device_type"])))
        if not found:
            found = _request(base, "/device?select=device_id&dns_name=eq." + _q(dns))
        target, action = (found[0]["device_id"], "updated") if found else (None, "created")

    if target is not None:
        device_id = target
        _request(base, "/device?device_id=eq.%d" % device_id, "PATCH", row)
        _request(base, "/component?device_id=eq.%d" % device_id, "DELETE")
    else:
        device_id = _insert_device(base, row)["device_id"]

    for c in spec.get("components", []):
        comp = {k: v for k, v in c.items() if k in (
            "component_type", "model", "manufacturer", "parameters", "is_active")}
        comp["device_id"] = device_id
        comp.setdefault("is_active", "Y")
        _insert_component(base, comp)

    # The board's broker credential (migration 007). Only the mosquitto hash
    # travels; the plaintext is on the board. The RPC is the one write path the
    # API role has to that table, and a failure here is a registration failure:
    # a board the broker refuses is not onboarded.
    if spec.get("mqtt_password_hash"):
        _request(base, "/rpc/register_mqtt_credential", "POST", {
            "p_username": spec["mqtt_username"],
            "p_password_hash": spec["mqtt_password_hash"],
            "p_device_id": device_id,
            "p_role": spec["device_type"],
            "p_topic_base": spec["topic_base"],
        })
    return device_id, action


def board(base, serial):
    """Where the board with this serial (MAC hex) is registered, or None."""
    rows = _request(base, "/device?select=device_id,dns_name,zone_id,device_type,is_active"
                          "&serial_number=eq." + _q(serial.lower()))
    if not rows:
        return None
    d = rows[0]
    unit = zone = ""
    if d.get("zone_id") is not None:
        z = _request(base, "/cea_zone?select=zone_code,unit_id&zone_id=eq.%d" % d["zone_id"])
        if z:
            zone = z[0]["zone_code"]
            u = _request(base, "/cea_unit?select=unit_code&unit_id=eq.%d" % z[0]["unit_id"])
            unit = u[0]["unit_code"] if u else ""
    return {"device_id": d["device_id"], "dns_name": d.get("dns_name") or "",
            "zone_id": d.get("zone_id"), "role": (d.get("device_type") or "").upper(),
            "is_active": d.get("is_active") or "Y", "unit_code": unit, "zone_code": zone}


def _q(v):
    """Encode a value for a PostgREST filter.

    Percent-encoding only. PostgREST 12 does NOT strip surrounding double
    quotes from a `col=eq."value"` filter — it looks for a row whose value
    literally begins with a quote, finds nothing, and returns an empty list.
    That reads exactly like "no such device", which is how re-onboarding a
    board tried to INSERT a second row for a slot that already had one.
    """
    return urllib.parse.quote(str(v), safe="")


def _insert_device(base, row):
    return _insert_retrying(base, "/device", row, "device_device_id_seq", "device_id")


def _insert_component(base, row):
    return _insert_retrying(base, "/component", row,
                            "component_component_id_seq", "component_id")


def _insert_retrying(base, path, row, seq, pk):
    """POST, stepping past a sequence that trails the table's max id.

    The tables were seeded by an import that supplied explicit ids, and that
    does not advance the sequence — so the first few nextval() values can
    already be taken. Each rejected attempt burns one, so retrying is both the
    diagnosis and the cure.

    Only for a PRIMARY KEY collision. Retrying any 23505 was wrong: a conflict
    on dns_name is a slot that already has a device, which no number of retries
    can fix, and the loop turned one clear "already exists" into thirty
    requests and a wrong diagnosis about the sequence.
    """
    last = None
    for _ in range(30):
        try:
            got = _request(base, path, "POST", row, prefer="return=representation")
            return got[0] if isinstance(got, list) else got
        except PlatformError as e:
            msg = str(e)
            if "23505" not in msg and "duplicate key" not in msg:
                raise
            if ("Key (%s)=" % pk) not in msg and ("%s_pkey" % pk) not in msg:
                raise      # a different unique constraint; retrying cannot help
            last = e
    raise PlatformError(
        "%s kept rejecting the insert on its primary key. The %s sequence is far "
        "behind the table. Fix it once:  SELECT setval('medcea.%s', (SELECT max(%s) "
        "FROM medcea.%s));  (last error: %s)"
        % (path, seq, seq, pk, path.lstrip("/"), last))


# --------------------------------------------------------------------- cli ----
def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd = argv[1]
    try:
        base = api_base()
        if cmd == "ping":
            _request(base, "/cea_unit?select=unit_id&limit=1")
            print(base)
            return 0
        if cmd == "slots":
            return print_slots(base)
        if cmd == "board":
            if len(argv) < 3:
                print("usage: board SERIAL", file=sys.stderr)
                return 2
            b = board(base, argv[2])
            if b:
                print("BOARD\t%s" % "\t".join(str(b[k] if b[k] is not None else "") for k in (
                    "device_id", "dns_name", "zone_id", "role", "is_active",
                    "unit_code", "zone_code")))
            return 0
        if cmd == "register":
            spec = json.load(sys.stdin)
            device_id, action = register(base, spec)
            print("%s\t%d" % (action, device_id))
            return 0
    except PlatformError as e:
        print(str(e), file=sys.stderr)
        return 1
    print("unknown command: %s" % cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
