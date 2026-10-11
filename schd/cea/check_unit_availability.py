# Check if the unit is available to run the recipe
# to do validate if there if is consistent i.e. should not have more than one recipe run with status R or S.
def check_unit_availability(recipe_name, unit_code , conn):
    """
    Checks if a unit is currently running a different recipe or has inconsistencies.
    Return result_df if the unit is available to resume a run. 

    Raises exceptions for:
    - Multiple active recipes for the unit.
    - A different active recipe than the one intended.
    - The intended recipe already running.
    """

    import pandas as pd

    from cea.get_unit_id_from_code import get_unit_id_from_code
    from cea.get_recipe_id_from_name import get_recipe_id_from_name

    unit_id = get_unit_id_from_code(unit_code, conn)
    recipe_id = get_recipe_id_from_name(recipe_name, conn)
    

    cursor = conn.cursor()
    cursor.execute(
        "SELECT recipe_id, recipe_run_id, recipe_run_status FROM medcea.recipe_run "
        "WHERE unit_id = %s AND IS_ACTIVE = 'Y' AND recipe_run_status IN ('R', 'S', 'F') "
        "ORDER BY recipe_run_start",
        (unit_id,),
    )
    result_df = pd.DataFrame(cursor.fetchall(), columns=['recipe_id','recipe_run_id', 'recipe_run_status'])

    if result_df.shape[0] > 1:
         raise Exception("Recipe table is inconsistent: Multiple active recipes found for the unit.")
    
    if not result_df.empty:
        current_recipe_id = int(result_df['recipe_id'].iloc[0])
        current_recipe_run_id = int(result_df['recipe_run_id'].iloc[0])
        current_recipe_status = result_df['recipe_run_status'].iloc[0]
        print(f"Current recipe id: {current_recipe_id}, recipe run id:{current_recipe_run_id}, status: {current_recipe_status}")
        
        if current_recipe_id != recipe_id:
            cursor.execute("SELECT recipe_name FROM medcea.recipe WHERE recipe_id = %s", (current_recipe_id,))
            current_recipe_name = cursor.fetchone()[0]
            raise Exception(f"Attempt to run: {recipe_name} recipe. Unit currently running another recipe: {current_recipe_name}")

        if current_recipe_status in ('R','F'):
            raise Exception(f"Currently, unit {unit_code} has {recipe_name} recipe with {current_recipe_status} status, "
            "consider to change it to 'S' if you intend to resume run.")

    print('Unit is available to run "{}" recipe in production unit "{}".'.format(recipe_name, unit_code))
    return result_df  # Unit is available or is already running the intended recipe
