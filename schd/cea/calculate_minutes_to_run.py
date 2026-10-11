
def calculate_minutes_to_run(run_params, recipe_line_seq_cycle_run_start):
    """
    Calculates the difference between the end time of a cycle and the current time, in minutes.

    Args:
        run_params (list): A list of dictionaries, where each dictionary contains recipe parameters,
                           including 'light_on_minutes' and 'light_off_minutes'.  It is assumed that the relevant
                           parameters are in the first element of the list.
        recipe_line_seq_cycle_run_start (datetime.datetime): A datetime object representing the start
                                               date and time of the recipe line cycle.

    Returns:
        float: The difference in minutes (can be 0 if the result is negative), rounded to 2 decimal places.
               Returns 0 if there is an error.
    """
    import json
    import datetime
    from dateutil.relativedelta import relativedelta

    # Parse the JSON string into a Python object
    run_params_list = json.loads(run_params)
    param_dict = run_params_list[0]
    light_on_minutes = param_dict.get("light_on_minutes", 0)
    light_off_minutes = param_dict.get("light_off_minutes", 0)
    minutes_to_run = light_on_minutes + light_off_minutes


    end_time = recipe_line_seq_cycle_run_start + relativedelta(minutes=minutes_to_run)
    current_time = datetime.datetime.now(recipe_line_seq_cycle_run_start.tzinfo)

    time_difference = end_time - current_time
    minutes_remaining = time_difference.total_seconds() / 60
    return max(0.0, round(minutes_remaining, 2))
