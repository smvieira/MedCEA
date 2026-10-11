# Get the recipe_id for the recipe name
def get_recipe_id_from_name(recipe_name, conn):
    """
    Retrieves the recipe_id from the recipe_name.
    """
    import inspect
    import sys

    cursor = conn.cursor()
    cursor.execute(
        "SELECT recipe_id FROM medcea.recipe WHERE recipe_name = %s",
        (recipe_name,)
    )
    result = cursor.fetchone()
    if result:
        print('Recipe "'+ recipe_name+ '" identifier is ' + str( result[0]))
        return result[0]
    else:
        frame = inspect.currentframe()
        func_name = inspect.getframeinfo(frame).function
        print(f"ERROR: An exception occurred in function '{func_name}'", file=sys.stderr)
        raise Exception("Recipe not found for the given name.")
