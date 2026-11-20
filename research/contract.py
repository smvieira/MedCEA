"""The research sandbox's side of the coupling contract (plan, "Coupling contract").

The sandbox reads production's metadata from production's own files at a pinned commit
(research/harness/algorithms_loader.py); it never keeps a copy it runs on. What this
module holds is the *reviewed* form of those sources: the meaning the plant model
(research/twin_plant/) and the harness were written against. It is never used to drive a
simulation. tests/test_research_contract.py compares it with the sources, so a change to
either side fails that test until both are updated in the same commit (and the chamber
model reviewed for the new meaning).

Standard library only (plus a Loaded object from algorithms_loader, passed in).
"""
from __future__ import annotations

# Bumped whenever the reviewed form below changes; a campaign manifest can name it.
# 2 (research Phase 3): the sandbox reads the lake through lake-api (LAKE below).
CONTRACT_VERSION = 2

# The four interfaces (README.md states them; nothing else is shared).
INTERFACES = (
    ("identity", "one Keycloak realm, the platform roles and the access policy's route table"),
    ("data", "snapshots only, never a live connection: an exporter in namespace medcea reads the "
             "owner-run read functions medcea.research_*() (EXECUTE only, no view over the base "
             "tables, no person column) and writes append-only snapshots up to a high-water mark "
             "into the research database medcea_research, minus the held-out ranges; "
             "medcea.research_contract_version() is the contract version (Phase 2a); the sandbox "
             "reads snapshots only through lake-api's lake_api.*() functions, pinned by snapshot id "
             "and lineage (Phase 3)"),
    ("metadata", "recipe_types.yaml, recipe format 2, the controller contract, loop_resolver, "
                 "esp32-control.json, read at a pinned commit"),
    ("candidates", "one gateway running production's validators, writing only a draft (Phase 6)"),
)

# The operational sources of interface 3 that Phase 1 reads (repository-relative).
SOURCES = (
    "apps/database/recipe_types.yaml",
    "edge/templates/esp32-control.json",
    "schd/cea/loop_resolver.py",
    "schd/cea/algorithms/__init__.py",
    "schd/cea/algorithms/base.py",
    "schd/cea/algorithms/params.py",
    # recipe_line_setpoints_guard (migration 011): the setpoint rules the runner applies to
    # a scenario's recipe line, with the same texts (tests/test_research_contract.py).
    "apps/database/medcea_db_migrations.sql",
    # lake-api's read functions (Phase 3): what research/calib/lake.py asks for, and how
    # a snapshot's lineage is computed (LAKE below).
    "apps/research/db/lake_api.sql",
)

# The controller codes the harness accepts (= ALGORITHM_NAMES) and params.py's schema version.
ALGORITHM_CODES = ("FLC", "IF_THEN_ELSE", "MPC", "PID", "Q_LEARNING")
PARAMS_SCHEMA_VERSION = 1

# The loopable quantities, in catalogue order. The order matters: build_default_map makes
# one loop per quantity in this order, and the tick publishes in loop order, so it decides
# which command a shared relay (air_flow_fan) ends the tick with.
QUANTITIES = (
    ("air_temperature", {"tag": "air_temperature", "commands": ["DOWN", "OFF", "UP"], "phase": "always"}),
    ("air_humidity", {"tag": "air_humidity", "commands": ["DOWN", "OFF", "UP"], "phase": "always"}),
    ("co2", {"tag": "co2", "commands": ["OFF", "UP"], "phase": "always",
             "command_map": {"DOWN": "UP", "UP": "OFF", "OFF": "OFF"}}),
    ("substrate_temperature", {"tag": "ground_temperature", "commands": ["DOWN", "OFF", "UP"],
                               "phase": "always"}),
)

# The relay8 board's commands actuators: the relays each command sets
# (edge/templates/esp32-control.json). chamber.py's balances assume exactly these.
ACTUATORS = {
    "air_temperature": {"quantity": "air_temperature", "commands": {
        "UP": {"air_heater": 1, "air_cooler": 0, "air_flow_fan": 0},
        "DOWN": {"air_heater": 0, "air_cooler": 1, "air_flow_fan": 1},
        "OFF": {"air_heater": 0, "air_cooler": 0, "air_flow_fan": 0}}},
    "air_humidity": {"quantity": "air_humidity", "commands": {
        "UP": {"air_humidifier": 1, "air_flow_fan": 1},
        "DOWN": {"air_humidifier": 0, "air_flow_fan": 1},
        "OFF": {"air_humidifier": 0, "air_flow_fan": 0}}},
    "co2": {"quantity": "co2", "commands": {
        "UP": {"co2_fan": 1, "co2_steriliser": 1},
        "DOWN": {"co2_fan": 0, "co2_steriliser": 0},
        "OFF": {"co2_fan": 0, "co2_steriliser": 0}}},
    "substrate_temperature": {"quantity": "substrate_temperature", "commands": {
        "UP": {"substrate_heater": 1, "air_flow_fan": 0},
        "DOWN": {"substrate_heater": 0, "air_flow_fan": 1},
        "OFF": {"substrate_heater": 0, "air_flow_fan": 0}}},
}

# The light actuator: per light type, the relays ON and OFF set.
LIGHT_TYPES = {
    "DARK": {"ON": {"light_uv": 0, "light_red": 0, "light_blue": 0},
             "OFF": {"light_uv": 0, "light_red": 0, "light_blue": 0}},
    "RED": {"ON": {"light_uv": 0, "light_red": 1, "light_blue": 0}, "OFF": {"light_red": 0}},
    "BLUE": {"ON": {"light_uv": 0, "light_red": 0, "light_blue": 1}, "OFF": {"light_blue": 0}},
    "UV": {"ON": {"light_uv": 1, "light_red": 0, "light_blue": 0}, "OFF": {"light_uv": 0}},
}

# Interface 2 as the sandbox reads it (Phase 3): lake-api's functions (apps/research/db/
# lake_api.sql), their parameters and columns (with PostgreSQL's types: the digests are
# recomputed from their text forms), the largest page measurements() accepts and the
# lineage rule. A reviewed literal only: tests/test_research_contract.py parses
# lake_api.sql and compares it with LAKE and with research/calib/lake.py's own constants.
LAKE = {
    "functions": {
        "snapshots": {"params": [],
                      "columns": [["snapshot_id", "bigint"], ["cut_at", "timestamptz"],
                                  ["previous_cut_at", "timestamptz"], ["created_at", "timestamptz"],
                                  ["contract_version", "integer"], ["rows", "jsonb"], ["digests", "jsonb"],
                                  ["lineage", "text"]]},
        "measurements": {"params": ["p_snapshot", "p_unit", "p_zone", "p_tag", "p_from", "p_to", "p_sensor",
                                    "p_limit"],
                         "columns": [["snapshot_id", "bigint"], ["ingested_at", "timestamptz"],
                                     ["measured_at", "timestamptz"], ["unit_code", "text"], ["zone_code", "text"],
                                     ["tag", "text"], ["sensor", "text"], ["value", "numeric"], ["uom", "text"]]},
        "units": {"params": ["p_snapshot"],
                  "columns": [["snapshot_id", "bigint"], ["unit_code", "text"], ["recipe_type", "text"],
                              ["area", "numeric"], ["height", "numeric"], ["is_active", "text"]]},
        "zones": {"params": ["p_snapshot"],
                  "columns": [["snapshot_id", "bigint"], ["unit_code", "text"], ["zone_code", "text"],
                              ["is_active", "text"]]},
        "recipes": {"params": ["p_snapshot"],
                    "columns": [["snapshot_id", "bigint"], ["recipe_id", "integer"], ["recipe_type", "text"],
                                ["status", "text"]]},
        "recipe_lines": {"params": ["p_snapshot"],
                         "columns": [["snapshot_id", "bigint"], ["recipe_id", "integer"], ["seq", "integer"],
                                     ["cycle_number", "integer"], ["light_type", "text"],
                                     ["light_on_minutes", "integer"], ["light_off_minutes", "integer"],
                                     ["setpoints", "jsonb"]]},
        "catalogue": {"params": ["p_snapshot"],
                      "columns": [["snapshot_id", "bigint"], ["kind", "text"], ["code", "text"], ["doc", "jsonb"]]},
        "holds": {"params": [],
                  "columns": [["unit_code", "text"], ["zone_code", "text"], ["from_at", "timestamptz"],
                              ["to_at", "timestamptz"]]},
    },
    "max_limit": 50000,
    "lineage": "L_0 = '', L_N = hex(sha256(utf8(L_{N-1} || E'\\n' || digests->>'measurement'))), "
               "in snapshot_id order",
}

# Relays more than one actuator sets: the last message of a tick wins on the board.
SHARED_RELAYS = {"air_flow_fan": ("air_humidity", "air_temperature", "substrate_temperature")}


def reviewed():
    """The reviewed form, in the shape observed() returns."""
    return {
        "algorithm_codes": list(ALGORITHM_CODES),
        "params_schema_version": PARAMS_SCHEMA_VERSION,
        "quantities": [[c, dict(q)] for c, q in QUANTITIES],
        "actuators": {a: {"quantity": d["quantity"],
                          "commands": {c: dict(s) for c, s in d["commands"].items()}}
                      for a, d in ACTUATORS.items()},
        "light_types": {t: {c: dict(s) for c, s in b.items()} for t, b in LIGHT_TYPES.items()},
        "shared_relays": {r: list(a) for r, a in SHARED_RELAYS.items()},
    }


def observed(loaded):
    """The same structure read from the sources LOADED (algorithms_loader.load) read."""
    quantities = []
    for q in loaded.catalogue["quantities"]:
        if not q.get("loopable"):
            continue
        e = {"tag": q["default_tag"], "commands": list(q["commands"]), "phase": q["phase"]}
        if q.get("command_map"):
            e["command_map"] = dict(q["command_map"])
        quantities.append([q["code"], e])
    actuators, light, users = {}, {}, {}
    for name, d in loaded.actuators.items():
        if d.get("kind") == "commands":
            actuators[name] = {"quantity": d.get("quantity"),
                               "commands": {c: dict(b["set"]) for c, b in d["commands"].items()}}
            for b in d["commands"].values():
                for relay in b["set"]:
                    users.setdefault(relay, set()).add(name)
        elif name == loaded.lr.LIGHT_ACTUATOR:
            light = {t: {c: dict(b["set"]) for c, b in br.items()} for t, br in d["types"].items()}
    params = loaded.params
    return {
        "algorithm_codes": sorted(loaded.algorithms.ALGORITHM_NAMES),
        "params_schema_version": getattr(params, "SCHEMA_VERSION", None),
        "quantities": quantities,
        "actuators": actuators,
        "light_types": light,
        "shared_relays": {r: sorted(a) for r, a in sorted(users.items()) if len(a) > 1},
    }


def drift(loaded):
    """Sentences naming each part of the contract whose sources differ from the reviewed
    form ([] when they agree)."""
    want, got = reviewed(), observed(loaded)
    return ["%s: the sources say %r, the sandbox was reviewed for %r" % (k, got[k], want[k])
            for k in want if got.get(k) != want[k]]
