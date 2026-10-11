# Get the unit_id for the unit code
def get_unit_id_from_code(unit_code,conn):
    """
    Retrieves the unit_id from the unit_code.
    """
    cursor = conn.cursor()
    cursor.execute(
        "SELECT unit_id FROM medcea.cea_unit WHERE unit_code = %s",
        (unit_code,)
    )
    result = cursor.fetchone()
    if result:
        return result[0]
    else:
        raise Exception(f"Unit code {unit_code} not found in database.")
