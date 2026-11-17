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
CONTRACT_VERSION = 1

# The four interfaces (README.md states them; nothing else is shared).
INTERFACES = (
    ("identity", "one Keycloak realm, the platform roles and the access policy's route table"),
    ("data", "snapshots only, never a live connection: an exporter in namespace medcea reads the "
             "read-only research views medcea.v_*_research and writes immutable, pseudonymised "
             "snapshots into the research database; each view has a contract version (Phase 3)"),
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
