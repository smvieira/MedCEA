# 
def get_recipe_run_status(recipe_run_id, conn):

    """
    Checks if the given recipe is already running on the unit,
    and if so, if it's in a state that allows restarting.
    """
    import pandas as pd

    cursor = conn.cursor()
    cursor.execute(
        "SELECT r.recipe_id, "
        "r.recipe_name, "
        "r.recipe_description, "
        "rl.recipe_item_seq_id, "
        "rl.recipe_item_seq_name, "
        "rl.cycle_number, "
        "rr.recipe_run_id, "
        "rr.unit_id, "
        "rr.recipe_run_start, "
        "rlcr.recipe_line_cycle_run_id, "
        "rlcr.recipe_item_seq_cycle_num, "
        "rlcr.recipe_line_seq_cycle_run_start, "
        "rlcr.recipe_line_seq_cycle_run_end, "
        "rlcr.recipe_line_cycle_run_status, "
        "rlcr.run_params "
        " FROM medcea.recipe r "
        "INNER JOIN medcea.recipe_line rl ON r.recipe_id = rl.recipe_id "
        "INNER JOIN medcea.recipe_run rr ON r.recipe_id = rr.recipe_id "
        "LEFT OUTER JOIN medcea.recipe_line_cycle_run rlcr ON rr.recipe_run_id = rlcr.recipe_run_id AND "
        "                                                  rl.recipe_id = rlcr.recipe_id AND "
        "                                                  rl.recipe_item_seq_id = rlcr.recipe_item_seq_id "
        " WHERE rr.recipe_run_id=%s "
        " ORDER BY rl.recipe_item_seq_id, rlcr.recipe_item_seq_cycle_num",
        (recipe_run_id,)
    )
    recipe_line_cycle_run_df = pd.DataFrame(cursor.fetchall(),
                                     columns=['recipe_id', 'recipe_name', 'recipe_description',
                                              'recipe_item_seq_id', 'recipe_item_seq_name', 'cycle_number',
                                              'recipe_run_id', 'unit_id', 'recipe_run_start',
                                              'recipe_line_cycle_run_id', 'recipe_item_seq_cycle_num',
                                              'recipe_line_seq_cycle_run_start', 'recipe_line_seq_cycle_run_end',
                                              'recipe_line_cycle_run_status', 'run_params'])
    return recipe_line_cycle_run_df
