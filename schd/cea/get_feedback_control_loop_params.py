def get_feedback_control_loop_params(unit_code, conn):
    """Retrieves MQTT topics and parameters from the database.

    Returns:
        str: A JSON string representing a list of dictionaries, where each dictionary
             represents a row from the database.  Returns an empty JSON list if no 
             results are found.  Each dictionary contains 'unit_code', 'zone_code', 
             and 'parameters' keys.
    """
    import json
    import psycopg2
    try:
        cursor = conn.cursor()
        sql = """
            SELECT
                u.unit_code,
                z.zone_code,
                c.parameters
            FROM
                medcea.cea_unit u,
                medcea.device d,
                medcea.component c,
                medcea.cea_zone z
            WHERE
                u.unit_code = %s
                AND u.unit_id = z.unit_id
                AND z.zone_id = d.zone_id
                AND d.device_id = c.device_id
                AND c.component_type = 'ACTUATOR'
                AND u.is_active = 'Y'
                AND z.is_active = 'Y'
                AND c.is_active = 'Y'
            """
        cursor.execute(sql, (unit_code,))
        results = cursor.fetchall()  # Fetch all results as a list of tuples
        if not results:
            raise Exception(f"No active actuator found for unit code: {unit_code}")

        # Convert the list of tuples to a list of dictionaries
        columns = ['unit_code', 'zone_code', 'parameters']
        result_list = [dict(zip(columns, row)) for row in results]
        
        return json.dumps(result_list)  # Return the JSON string
    except psycopg2.Error as e:
        print(f"Database error: {e}")
        return json.dumps([])  # Return an empty JSON list in case of error
    finally:
        if cursor:
            cursor.close()
