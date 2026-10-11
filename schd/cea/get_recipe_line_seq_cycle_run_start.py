# Get the recipe_id for the recipe name
def get_recipe_line_seq_cycle_run_start(recipe_line_cycle_run_id, conn):
    """
    Retrieves the recipe_id from the recipe_name.
    """
    cursor = conn.cursor()
    cursor.execute(
        """SELECT recipe_line_seq_cycle_run_start FROM medcea.recipe_line_cycle_run
        where recipe_line_cycle_run_id = %s
        """,
        (recipe_line_cycle_run_id,)
    )
    result = cursor.fetchone()
    if result:
        print('Recipe_line_cycle_run_id '+ str(recipe_line_cycle_run_id) )
        return result[0]
    else:
        raise Exception(f"Recipe recipe_line_cycle_run_id '{str(recipe_line_cycle_run_id)}' not found in the database.")