def update_recipe_run(recipe_run_id, status, conn):
    """
    Updates a recipe run's status and either recipe_run_start or recipe_run_end,
    using Python timestamps with timezone awareness.
    """
    import datetime
    import pytz
    import inspect
    import sys

    cursor = conn.cursor()
    now_utc = datetime.datetime.now(pytz.utc)

    if status == 'C':
        sql = "UPDATE medcea.recipe_run SET recipe_run_end = %s, recipe_run_status = %s, timestamp_upd = %s WHERE recipe_run_id = %s"
        params = (now_utc, status, now_utc, recipe_run_id)
    elif status in ('R', 'F'):
        sql = "UPDATE medcea.recipe_run SET recipe_run_status = %s, timestamp_upd = %s WHERE recipe_run_id = %s"
        params = (status, now_utc, recipe_run_id)
    else:
        raise ValueError("Invalid status. Must be 'C', 'R', or 'F'")  # Include 'F' in valid statuses

    try:
        cursor.execute(sql, params)
        conn.commit()
        print(f"Changed recipe run id: {recipe_run_id} status to '{status}'")
        return recipe_run_id
    except Exception as e:
        print(f"Error in {inspect.currentframe().f_code.co_name}: {e}")
        conn.rollback()  # Rollback changes in case of error
        raise  # Re-raise the exception to be handled upstream
    finally:
        cursor.close()