def get_recipe_line_item_seq_details(recipe_id, recipe_item_seq_id, conn):
    """One recipe line as JSON text: a list of one dict {recipe_id, recipe_item_seq_id,
    light_type, light_on_minutes, light_off_minutes, setpoints} (migration 011:
    setpoints {"<quantity>": {"lower": n, "upper": n}} replaces the eight *_limit
    columns; loop_resolver.limits() reads it). The runner stores it as the cycle's
    run_params."""
    import json
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT recipe_id, recipe_item_seq_id, light_type, light_on_minutes, light_off_minutes, setpoints
          FROM medcea.recipe_line
         WHERE recipe_id = %s AND recipe_item_seq_id = %s
        """,
        (recipe_id, recipe_item_seq_id,)
    )
    rows = cursor.fetchall()
    columns = ['recipe_id', 'recipe_item_seq_id', 'light_type', 'light_on_minutes', 'light_off_minutes',
               'setpoints']
    out = []
    for row in rows:
        d = dict(zip(columns, row))
        sp = d['setpoints']
        if isinstance(sp, (str, bytes)):
            sp = json.loads(sp)
        d['setpoints'] = sp if isinstance(sp, dict) else {}
        out.append(d)
    return json.dumps(out, indent=4)
