import json


def save_algorithm_state(unit_id: int, algorithm: str, channel: str,
                          state: dict, conn, run_id=None) -> None:
    """
    Persist algorithm state to medcea.algorithm_state (upsert).

    Creates or replaces the row for (unit_id, algorithm, channel),
    updating updated_at to NOW(). Commits the transaction.

    Parameters
    ----------
    unit_id   : int   — production unit identifier
    algorithm : str   — algorithm code, e.g. 'Q_LEARNING'
    channel   : str   — sensor channel, e.g. 'air_temperature'
    state     : dict  — serialisable state from algo.get_state()
    conn      : psycopg2 connection
    run_id    : int   — the run that learnt it (a run started by the scheduler API):
                        the write then acts for that run (cea.actor.acting), so the
                        Q-table event records the run and its actor. A new state
                        clears a retirement (logged as 'unretired').
    """
    payload = json.dumps(state)
    sql = """
            INSERT INTO medcea.algorithm_state (unit_id, algorithm, channel, state, updated_at)
            VALUES (%s, %s, %s, %s::jsonb, NOW())
            ON CONFLICT (unit_id, algorithm, channel)
            DO UPDATE SET
                state      = EXCLUDED.state,
                updated_at = NOW()
            """
    if run_id is not None:
        from .actor import acting
        with acting(conn, run_id) as cur:
            cur.execute(sql, (unit_id, algorithm, channel, payload))
        return
    with conn.cursor() as cur:
        cur.execute(sql, (unit_id, algorithm, channel, payload))
    conn.commit()
