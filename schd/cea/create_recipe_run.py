def create_recipe_run(recipe_name, unit_code, conn):
    """
    Creates a new recipe run in the database.
    """
    import cea
    unit_id = cea.get_unit_id_from_code(unit_code, conn)
    recipe_id = cea.get_recipe_id_from_name(recipe_name, conn)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO medcea.recipe_run (recipe_id, unit_id, recipe_run_start, recipe_run_status, is_active) "
        "VALUES (%s, %s, now(), 'S', 'Y') RETURNING recipe_run_id",
        (recipe_id, unit_id)
    )
    recipe_run_id = cursor.fetchone()[0]
    conn.commit()
    print(f"Created new recipe run with id: {recipe_run_id}")
    return recipe_run_id