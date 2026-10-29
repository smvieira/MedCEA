import json


def load_algorithm_state(unit_id: int, algorithm: str, channel: str, conn) -> dict:
    """
    Load persisted algorithm state from medcea.algorithm_state.

    Returns the stored state dict, or {} if no row exists yet
    (first run / state was purged) or, once migration 008b is loaded, if the
    state was retired (medcea.retire_algorithm_state: the next run starts cold).

    Parameters
    ----------
    unit_id   : int   — production unit identifier
    algorithm : str   — algorithm code, e.g. 'Q_LEARNING'
    channel   : str   — sensor channel, e.g. 'air_temperature'
    conn      : psycopg2 connection (caller owns transaction / commit)
    """
    from .actor import has_008b
    retired = "AND  retired_at IS NULL" if has_008b(conn) else ""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT state
            FROM   medcea.algorithm_state
            WHERE  unit_id   = %s
              AND  algorithm = %s
              AND  channel   = %s
              """ + retired,
            (unit_id, algorithm, channel),
        )
        row = cur.fetchone()
    if row is None:
        return {}
    state = row[0]
    # psycopg2 may return a dict (JSONB auto-cast) or a string
    if isinstance(state, str):
        return json.loads(state)
    return state or {}
