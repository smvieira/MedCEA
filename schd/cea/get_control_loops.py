"""cea.get_control_loops — a unit's loop map, read once at run start (feedback
control Phase 2; Q11, Q19, Q20 decided per zone).

    get_control_loops(unit_code, conn) -> {"source": "table" | "default" | "mixed",
                                           "loops": [loop…], "warnings": [str…]}

Runs as the login /installer/.env gives the runner (svc_scheduler under
IAM_DB_SERVICE_ROLES; policy version 2a gives it SELECT on medcea.control_loop).
Every query is parameterised; the recipe columns a row names are never put into SQL.
The transaction is always ended (rollback), as cea.runs does.

  * medcea.control_loop missing (a database deployed before migration 010): every
    actuator zone gets the default map, with a warning.
  * a zone with active rows uses them (zones and units active); a zone of the unit
    with an active ACTUATOR and no rows gets the default map (loop_resolver).
  * any invalid row (the database's _loop_problems rules, but the zone inventory)
    raises RuntimeError: the run fails closed at start, nothing written.
  * a permission error (42501: the table is there, the grant is not) propagates;
    never a silent fallback while rows may exist.
"""
from . import loop_resolver

SQL_HAS_TABLE = "SELECT pg_catalog.to_regclass('medcea.control_loop') IS NOT NULL"

SQL_ROWS = """
    SELECT z.zone_code, l.loop_id, l.loop_code, l.recipe_lower, l.recipe_upper, l.input, l.output
      FROM medcea.cea_unit u
      JOIN medcea.cea_zone z     ON z.unit_id = u.unit_id
      JOIN medcea.control_loop l ON l.zone_id = z.zone_id
     WHERE u.unit_code = %s AND u.is_active = 'Y' AND z.is_active = 'Y' AND l.is_active = 'Y'
     ORDER BY z.zone_code, l.loop_code, l.loop_id
"""

SQL_ACTUATOR_ZONES = """
    SELECT DISTINCT z.zone_code
      FROM medcea.cea_unit u
      JOIN medcea.cea_zone z  ON z.unit_id = u.unit_id
      JOIN medcea.device d    ON d.zone_id = z.zone_id
      JOIN medcea.component c ON c.device_id = d.device_id
     WHERE u.unit_code = %s AND u.is_active = 'Y' AND z.is_active = 'Y'
       AND coalesce(d.is_active, 'Y') = 'Y'
       AND c.component_type = 'ACTUATOR' AND c.is_active = 'Y'
     ORDER BY z.zone_code
"""

ROW_COLUMNS = ("zone_code", "loop_id", "loop_code", "recipe_lower", "recipe_upper", "input", "output")


def get_control_loops(unit_code, conn):
    warnings = []
    cur = conn.cursor()
    try:
        cur.execute(SQL_HAS_TABLE)
        has_table = bool(cur.fetchone()[0])
        rows = []
        if has_table:
            cur.execute(SQL_ROWS, (unit_code,))
            rows = [dict(zip(ROW_COLUMNS, r)) for r in cur.fetchall()]
        else:
            warnings.append("medcea.control_loop not deployed yet (./apps/database/deploy.sh): "
                            "every zone uses the default loop map")
        cur.execute(SQL_ACTUATOR_ZONES, (unit_code,))
        actuator_zones = [r[0] for r in cur.fetchall()]
    finally:
        try:
            cur.close()
        finally:
            conn.rollback()

    table_loops = [loop_resolver.loop_from_row(r) for r in rows]
    row_zones = sorted({lp["zone_code"] for lp in table_loops})
    default_zones = sorted(set(actuator_zones) - set(row_zones))
    if not table_loops and not default_zones:
        raise RuntimeError(f"No active actuator found for unit code: {unit_code}")
    if not loop_resolver.topic_safe(unit_code):
        raise RuntimeError(f"unit code {unit_code!r} cannot be used in an MQTT topic ('+', '#' or '/')")

    loops = table_loops + (loop_resolver.build_default_map(default_zones) if default_zones else [])
    errs, warns = loop_resolver.validate_loops(loops)
    if errs:
        raise RuntimeError(f"control loop(s) of unit {unit_code} invalid (fix medcea.control_loop, "
                           f"e.g. by re-onboarding the zone): " + "; ".join(errs))
    warnings += warns
    for z in row_zones:
        missing = [c for c in loop_resolver.QUANTITIES
                   if not any(lp["zone_code"] == z and lp["loop_code"] == c for lp in table_loops)]
        if missing:
            warnings.append(f"zone {z}: loops from medcea.control_loop; not controlled: {', '.join(missing)}")
    if default_zones:
        warnings.append(f"DEFAULT_LOOP_MAP unit={unit_code} zones={','.join(default_zones)} (no control_loop rows: "
                        "a tag with one fresh sensor uses it, several give no_data + ALARM ambiguous_source; "
                        "substrate reads ground_temperature, CO2 above limit -> fans UP)")
    source = "table" if not default_zones else ("default" if not table_loops else "mixed")
    return {"source": source, "loops": loops, "warnings": warnings}
