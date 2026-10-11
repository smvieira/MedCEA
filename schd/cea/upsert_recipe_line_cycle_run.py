def upsert_recipe_line_cycle_run(values, conn):
    """
    Inserts a new record into the medcea.RECIPE_LINE_CYCLE_RUN table
    or updates status upon completion, using Python timestamps with timezone awareness.

    Parameters:
    - conn: Database connection object
    - values: A dictionary containing the values to insert or update.
              Required keys for insert (status 'S'):
                - recipe_run_id: ID of the recipe run
                - recipe_id: ID of the recipe
                - recipe_item_seq_id: Sequence ID of the recipe item
                - recipe_item_seq_cycle_num: Cycle number of the recipe item sequence
                - status: Status of the recipe line cycle run ('S')
                - run_params: Dictionary of run parameters
              Required keys for update (status 'R', 'C', 'F'):
                - recipe_line_cycle_run_id: ID of the recipe line cycle run to update
                - status: Status to update to ('R', 'C', or 'F')
                - run_params (only for status 'R'): Dictionary of run parameters

    Returns:
    - recipe_line_cycle_run_id: ID of the newly inserted or updated recipe line cycle run
    """
    import datetime
    import pytz

    try:
        status = values.get("status")
        now_utc = datetime.datetime.now(pytz.utc)

        if status == 'S':
            recipe_run_id = values.get("recipe_run_id")
            recipe_id = values.get("recipe_id")
            recipe_item_seq_id = values.get("recipe_item_seq_id")
            recipe_item_seq_cycle_num = values.get("recipe_item_seq_cycle_num")
            run_params = values.get("run_params")
            print(f"Recipe run id: {recipe_run_id}, recipe_id: {recipe_id}, recipe_item_seq_id: {recipe_item_seq_id}, recipe_item_seq_cycle_num: {recipe_item_seq_cycle_num}, status: {status}")
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO medcea.RECIPE_LINE_CYCLE_RUN (
                    recipe_run_id, recipe_id, recipe_item_seq_id,
                    recipe_line_seq_cycle_run_start, recipe_item_seq_cycle_num, recipe_line_cycle_run_status, run_params,
                    timestamp_cre, timestamp_upd
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING recipe_line_cycle_run_id
                """,
                (recipe_run_id, recipe_id, recipe_item_seq_id, now_utc, recipe_item_seq_cycle_num, status, run_params, now_utc, now_utc)
            )
            recipe_line_cycle_run_id = cursor.fetchone()[0]
            conn.commit()

            print(f"        Inserted new recipe line cycle run with id: {recipe_line_cycle_run_id}")
            return recipe_line_cycle_run_id
        elif status == 'R':
            run_params = values.get("run_params")
            print(f"params are:{run_params}")
            recipe_line_cycle_run_id = values.get("recipe_line_cycle_run_id")
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE medcea.RECIPE_LINE_CYCLE_RUN
                SET recipe_line_cycle_run_status = 'R',
                    run_params = %s,
                    timestamp_upd = %s
                WHERE recipe_line_cycle_run_id = %s
                RETURNING recipe_line_cycle_run_id
                """,
                (run_params, now_utc, recipe_line_cycle_run_id,)
            )
            conn.commit()

            print(f"        Updated recipe line cycle run id id: {recipe_line_cycle_run_id} with status: {status}")
            return recipe_line_cycle_run_id
        elif status == 'C':
            recipe_line_cycle_run_id = values.get("recipe_line_cycle_run_id")
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE medcea.RECIPE_LINE_CYCLE_RUN
                SET recipe_line_seq_cycle_run_end = %s,
                    recipe_line_cycle_run_status = 'C',
                    timestamp_upd = %s
                WHERE recipe_line_cycle_run_id = %s
                RETURNING recipe_line_cycle_run_id
                """,
                (now_utc, now_utc, recipe_line_cycle_run_id,)
            )
            recipe_line_cycle_run_id = cursor.fetchone()[0]
            conn.commit()

            print(f"        Updated recipe line cycle run id id: {recipe_line_cycle_run_id} with status: {status}")
            return recipe_line_cycle_run_id
        elif status == 'F':
            recipe_line_cycle_run_id = values.get("recipe_line_cycle_run_id")
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE medcea.RECIPE_LINE_CYCLE_RUN
                SET recipe_line_cycle_run_status = 'F',
                    timestamp_upd = %s
                WHERE recipe_line_cycle_run_id = %s
                RETURNING recipe_line_cycle_run_id
                """,
                (now_utc, recipe_line_cycle_run_id,)
            )
            recipe_line_cycle_run_id = cursor.fetchone()[0]
            conn.commit()

            print(f"        Updated recipe line cycle run id id: {recipe_line_cycle_run_id} with status: {status}")
            return recipe_line_cycle_run_id
        else:
            raise ValueError(f"Status {status} not allowed for recipe line cycle run.")
    except Exception as e:
        conn.rollback()
        print(f"Error upserting recipe line cycle run: {e}")
        raise