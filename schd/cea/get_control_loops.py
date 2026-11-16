"""cea.get_control_loops — a unit's loop map, read once at run start (feedback
control Phase 2; Q11, Q19, Q20 decided per zone; recipe types, migration 011).

    get_control_loops(unit_code, conn) -> {"source": "table" | "default" | "mixed",
                                           "loops": [loop…], "warnings": [str…],
                                           "quantities": {code: {…}}}

Runs as the login /installer/.env gives the runner (svc_scheduler under
IAM_DB_SERVICE_ROLES; policy version 2a gives it SELECT on medcea.control_loop, the
recipe-types version on the catalogue). Every query is parameterised. The
transaction is always ended (rollback), as cea.runs does.

  * the quantities are the unit's recipe type's (medcea.control_quantity through
    recipe_type_quantity); before migration 011 (no catalogue) the built-in copy
    loop_resolver.QUANTITIES, with a warning.
  * medcea.control_loop missing (a database deployed before migration 010): every
    actuator zone gets the default map, with a warning.
  * a zone with active rows uses them: input from its SENSE onboarding, output from
    its CONTROL onboarding; a half-bound row (one onboarding has chosen, the other
    not yet) runs with the default map's other half (loop_resolver.complete_half),
    with a warning, as the zone ran before anyone chose. A zone of the unit with an
    active ACTUATOR and no rows gets the default map (loop_resolver), its actuators
    the ones declaring each quantity.
  * any invalid row (the database's _loop_check rules, but the zone inventory)
    raises RuntimeError: the run fails closed at start, nothing written.
  * a permission error (42501: the table is there, the grant is not) propagates;
    never a silent fallback while rows may exist.
"""
import json

from . import loop_resolver

SQL_HAS_TABLE = "SELECT pg_catalog.to_regclass('medcea.control_loop') IS NOT NULL"
SQL_HAS_CATALOGUE = "SELECT pg_catalog.to_regclass('medcea.recipe_type_quantity') IS NOT NULL"

SQL_QUANTITIES = """
    SELECT c.quantity_code, c.default_tag, c.sense_uoms, c.commands, c.command_map, c.phase, c.loopable
      FROM medcea.cea_unit u
      JOIN medcea.recipe_type t          ON t.recipe_type_code = u.unit_type
      JOIN medcea.recipe_type_quantity x ON x.recipe_type_id = t.recipe_type_id
      JOIN medcea.control_quantity c     ON c.quantity_id = x.quantity_id
     WHERE u.unit_code = %s
     ORDER BY c.ordinal, c.quantity_code
"""

SQL_ROWS = """
    SELECT z.zone_code, l.loop_id, l.loop_code, l.input, l.output
      FROM medcea.cea_unit u
      JOIN medcea.cea_zone z     ON z.unit_id = u.unit_id
      JOIN medcea.control_loop l ON l.zone_id = z.zone_id
     WHERE u.unit_code = %s AND u.is_active = 'Y' AND z.is_active = 'Y' AND l.is_active = 'Y'
     ORDER BY z.zone_code, l.loop_code, l.loop_id
"""

SQL_ACTUATORS = """
    SELECT z.zone_code, c.parameters
      FROM medcea.cea_unit u
      JOIN medcea.cea_zone z  ON z.unit_id = u.unit_id
      JOIN medcea.device d    ON d.zone_id = z.zone_id
      JOIN medcea.component c ON c.device_id = d.device_id
     WHERE u.unit_code = %s AND u.is_active = 'Y' AND z.is_active = 'Y'
       AND coalesce(d.is_active, 'Y') = 'Y'
       AND c.component_type = 'ACTUATOR' AND c.is_active = 'Y'
     ORDER BY z.zone_code, c.component_id
"""

ROW_COLUMNS = ("zone_code", "loop_id", "loop_code", "input", "output")


def _obj(v):
    if isinstance(v, (str, bytes)):
        try:
            return json.loads(v)
        except ValueError:
            return None
    return v


def quantities_from_rows(rows):
    """{code: {tag, sense_uoms, commands, command_map?, phase, loopable}} from the
    SQL_QUANTITIES rows (the shape of loop_resolver.QUANTITIES)."""
    out = {}
    for code, tag, uoms, commands, cmap, phase, loop_ok in rows:
        q = {"tag": tag, "sense_uoms": list(uoms or []), "commands": sorted(commands or []),
             "phase": phase, "loopable": bool(loop_ok)}
        cmap = _obj(cmap)
        if isinstance(cmap, dict):
            q["command_map"] = cmap
        out[code] = q
    return out


def get_control_loops(unit_code, conn):
    warnings = []
    cur = conn.cursor()
    try:
        cur.execute(SQL_HAS_CATALOGUE)
        if bool(cur.fetchone()[0]):
            cur.execute(SQL_QUANTITIES, (unit_code,))
            quantities = quantities_from_rows(cur.fetchall())
            if not quantities:
                raise RuntimeError(f"unit {unit_code}: its recipe type lists no quantity (apps/database/recipe_types.yaml)")
        else:
            quantities = dict(loop_resolver.QUANTITIES)
            warnings.append("the recipe-type catalogue is not deployed yet (./apps/database/deploy.sh, "
                            "migration 011): the built-in quantities are used")
        cur.execute(SQL_HAS_TABLE)
        has_table = bool(cur.fetchone()[0])
        rows = []
        if has_table:
            cur.execute(SQL_ROWS, (unit_code,))
            rows = [dict(zip(ROW_COLUMNS, r)) for r in cur.fetchall()]
        else:
            warnings.append("medcea.control_loop not deployed yet (./apps/database/deploy.sh): "
                            "every zone uses the default loop map")
        cur.execute(SQL_ACTUATORS, (unit_code,))
        actuators = {}
        for zone, params in cur.fetchall():
            p = _obj(params)
            defs = p.get("actuator_definitions") if isinstance(p, dict) else None
            actuators.setdefault(zone, {}).update(defs if isinstance(defs, dict) else {})
    finally:
        try:
            cur.close()
        finally:
            conn.rollback()

    table_loops = []
    for r in rows:
        r = dict(r, input=_obj(r["input"]), output=_obj(r["output"]))
        lp = loop_resolver.complete_half(loop_resolver.loop_from_row(r, quantities), quantities,
                                         actuators.get(r["zone_code"]))
        if lp is None:
            if r["input"] is not None:
                warnings.append(f"zone {r['zone_code']}: loop {r['loop_code']} has its sensor but no actuator: "
                                "the zone has no CONTROL board actuator for it yet: not run")
            continue
        if lp.get("completed"):
            who = "SENSE" if lp["completed"] == "input" else "CONTROL"
            what = ("every sensor of tag %s (one fresh one is used)" % lp["input"]["tag"]
                    if lp["completed"] == "input" else "actuator %s" % lp["output"]["actuator"])
            warnings.append(f"zone {r['zone_code']}: loop {r['loop_code']} is half-bound: its {lp['completed']} is "
                            f"the default map's ({what}) until a {who} onboarding chooses it")
        table_loops.append(lp)
    row_zones = sorted({r["zone_code"] for r in rows})
    default_zones = sorted(set(actuators) - set(row_zones))
    if not table_loops and not default_zones:
        raise RuntimeError(f"No active actuator found for unit code: {unit_code}")
    if not loop_resolver.topic_safe(unit_code):
        raise RuntimeError(f"unit code {unit_code!r} cannot be used in an MQTT topic ('+', '#' or '/')")

    loops = table_loops + (loop_resolver.build_default_map(default_zones, quantities, actuators)
                           if default_zones else [])
    errs, warns = loop_resolver.validate_loops(loops, quantities)
    if errs:
        raise RuntimeError(f"control loop(s) of unit {unit_code} invalid (fix medcea.control_loop, "
                           f"e.g. by re-onboarding the zone): " + "; ".join(errs))
    warnings += warns
    for z in row_zones:
        missing = [c for c in loop_resolver.loopable(quantities)
                   if not any(lp["zone_code"] == z and lp["loop_code"] == c for lp in table_loops)]
        if missing:
            warnings.append(f"zone {z}: loops from medcea.control_loop; not controlled: {', '.join(missing)}")
    if default_zones:
        warnings.append(f"DEFAULT_LOOP_MAP unit={unit_code} zones={','.join(default_zones)} (no control_loop rows: "
                        "a quantity's default tag with one fresh sensor uses it, several give no_data + ALARM "
                        "ambiguous_source; the actuator declaring each quantity, else the one named after it)")
    source = "table" if not default_zones else ("default" if not table_loops else "mixed")
    return {"source": source, "loops": loops, "warnings": warnings, "quantities": quantities}
