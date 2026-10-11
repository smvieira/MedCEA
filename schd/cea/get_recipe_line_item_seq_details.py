
# not needed, covered bu get_recipe_run_status
def get_recipe_line_item_seq_details(recipe_id, recipe_item_seq_id, conn):
    """Fetches the recipe steps from the database and returns them as a JSON object.
    
    
    Parameters:
    - conn: Database connection object
    - recipe_id: ID of the recipe
    - recipe_item_seq_id: Sequence ID of the recipe item

    Returns:
    - recipe_line_details: Json with recipe details of a given recipe item sequence
    """
    import json
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT recipe_id, recipe_item_seq_id,
               air_temperature_lower_limit,
               air_temperature_upper_limit,
               light_type,
               light_on_minutes,
               light_off_minutes,
               co2_lower_limit,
               co2_upper_limit,
               hr_lower_limit,
               hr_upper_limit,
               substrate_temperature_lower_limit,
               substrate_temperature_upper_limit 
        FROM medcea.recipe_line 
        WHERE recipe_id = %s 
        AND recipe_item_seq_id = %s 
        """,
        (recipe_id, recipe_item_seq_id,)
    )
    recipe_line_details = cursor.fetchall()
    columns = ['recipe_id', 'recipe_item_seq_id',
               'air_temperature_lower_limit', 'air_temperature_upper_limit',
               'light_type', 'light_on_minutes', 'light_off_minutes',
               'co2_lower_limit', 'co2_upper_limit',
               'hr_lower_limit', 'hr_upper_limit',
               'substrate_temperature_lower_limit', 'substrate_temperature_upper_limit']
    # Convert the fetched data into a list of dictionaries
    recipe_line_details_json = [dict(zip(columns, row)) for row in recipe_line_details]
    return json.dumps(recipe_line_details_json, indent=4)
