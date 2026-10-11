import sys
import time
import os
import json
from dotenv import load_dotenv
import paho.mqtt.client as mqtt
import cea  # Assuming this is a local module
#import psycopg2 # Removed this, cea.py likely uses it, so we don't need to import it directly.
print("Starting run_recipe.py...")
def run_recipe(unit_code, recipe_name):
    """
    Executes a specified growth recipe in a given CEA production unit.

    This script is designed to be called by a wrapper shell script that provides
    the unit code and recipe name as command-line arguments.  It connects to the
    CEA database, starts the recipe run, interacts with the CEA agent,
    and updates the database with the run status.  It also clears MQTT retained
    messages for the unit.

    Args:
        unit_code (str): The unique identifier for the CEA production unit (e.g., 'UNIT01').
        recipe_name (str): The name of the growth recipe to execute (e.g., 'Basilico').

    Returns:
        None.  The function interacts with the daMQTT broker.
        It prints status messages to standard output.  Errors are printed to
        standard error, and the program exits with a non-zero exit code on failure.
    """
    # Load environment variables.  This should be in a .env file.
    ENV = '../installer/.env'  # Relative path to the .env file
    load_dotenv(ENV, override=True)

    # Database connection details from environment variables.
    db_config = {
        "host": os.getenv('DB_HOST'),  
        "database": os.getenv('DB_NAME'),
        "user": os.getenv('DB_USER'),    
        "password": os.getenv('DB_PASS') 
    }

    # MQTT broker details from environment variables
    mqtt_url = os.getenv('MQTT_URL')
    mqtt_port = int(os.getenv('MQTT_PORT', 1883))  # Provide a default port if not set
    mqtt_rootname = os.getenv('PROJECT_NAME', "medcea") #Provide a default
    print(f"Connecting to MQTT broker at {mqtt_url}:{mqtt_port}...")

    conn = None  # Initialize conn
    try:
        # Connect to the database
        conn = cea.connect_to_db(db_config)
        if not conn:
            print("Failed to connect to database.", file=sys.stderr)
            sys.exit(1)

        print("Connected to database.")

        # Check unit availability and create/retrieve recipe run ID.
        recipe_run_df = cea.check_unit_availability(recipe_name=recipe_name, unit_code=unit_code, conn=conn)
        if recipe_run_df.empty:
            recipe_run_id = cea.create_recipe_run(recipe_name=recipe_name, unit_code=unit_code, conn=conn)
        else:
            recipe_run_id = int(recipe_run_df['recipe_run_id'].iloc[0])

        # Get initial recipe run status
        recipe_run_status_df = cea.get_recipe_run_status(recipe_run_id, conn=conn)

        # Update recipe run status to 'Running'
        cea.update_recipe_run(recipe_run_id, status='R', conn=conn)

        # Clear retained MQTT messages
        mqtt_topic_prefix_to_clear = f"{mqtt_rootname}/{unit_code}/#"
        client_id = f"{mqtt_rootname}-orchestrator-clean-retained-msg-{unit_code}"
        client = mqtt.Client(client_id=client_id)
        
        # Maybe not needed to clear retained messages
        # mqtt_topic_prefix_cleared = cea.clear_retained_messages(
        #    client=client, mqtt_url=mqtt_url, mqtt_port=mqtt_port, topic_prefix=mqtt_topic_prefix_to_clear, timeout=10
        #)
        #print(f"Cleared retained messages for topic: {mqtt_topic_prefix_cleared}")

        # Run the recipe
        print("Starting recipe run...")
        print(f"Recipe run ID: {recipe_run_id}")
        print(f"Unit code: {unit_code}")
        print(f"Recipe name: {recipe_name}")

        # Iterate through recipe steps, handling duplicates and status checks
        for index, row in recipe_run_status_df.drop_duplicates(
                subset=['recipe_id', 'recipe_item_seq_id', 'recipe_run_id']
        ).iterrows():  # Corrected subset
            recipe_id = row['recipe_id']
            recipe_item_seq_id = row['recipe_item_seq_id']
            cycle_number = row['cycle_number']

            run_params = cea.get_recipe_line_item_seq_details(recipe_id, recipe_item_seq_id, conn=conn)

            # Inject the resolved control algorithm + params into run_params for audit trail.
            # CONTROL_ALGORITHM and CONTROL_ALGORITHM_PARAMS are set by scheduler-api.py
            # when it launches this subprocess; they default to IF_THEN_ELSE / {} if not set.
            _algo   = (os.getenv('CONTROL_ALGORITHM', 'IF_THEN_ELSE') or 'IF_THEN_ELSE').upper()
            _params = json.loads(os.getenv('CONTROL_ALGORITHM_PARAMS', '{}') or '{}')
            _rp = json.loads(run_params) if isinstance(run_params, str) else run_params
            if _rp and isinstance(_rp, list):
                _rp[0]['control_algorithm']        = _algo
                _rp[0]['control_algorithm_params'] = _params
                run_params = json.dumps(_rp)

            print(f"Processing recipe: {recipe_name}, item seq ID {recipe_item_seq_id} with {cycle_number} cycles (algo={_algo})")

            for cycle_num in range(1, cycle_number + 1):
                # Check for existing record for this cycle
                record_exists = not recipe_run_status_df[
                    (recipe_run_status_df['recipe_id'] == recipe_id) &
                    (recipe_run_status_df['recipe_item_seq_id'] == recipe_item_seq_id) &
                    (recipe_run_status_df['recipe_run_id'] == recipe_run_id) & # Added recipe_run_id
                    (recipe_run_status_df['recipe_item_seq_cycle_num'] == cycle_num)].empty

                if not record_exists:
                    # Create a new record for this cycle
                    recipe_line_cycle_run_values = {
                        "recipe_run_id": recipe_run_id,
                        "recipe_id": recipe_id,
                        "recipe_item_seq_id": recipe_item_seq_id,
                        "recipe_item_seq_cycle_num": cycle_num,
                        "status": 'S',  # 'S' for Started
                        "run_params": run_params
                    }
                    print(f"     recipe_line_cycle_run_values 1 {recipe_line_cycle_run_values}")
                    recipe_line_cycle_run_id = cea.upsert_recipe_line_cycle_run(recipe_line_cycle_run_values, conn)
                elif record_exists:
                    #check the status
                    existing_record = recipe_run_status_df[
                        (recipe_run_status_df['recipe_id'] == recipe_id) &
                        (recipe_run_status_df['recipe_item_seq_id'] == recipe_item_seq_id) &
                        (recipe_run_status_df['recipe_run_id'] == recipe_run_id) &
                        (recipe_run_status_df['recipe_item_seq_cycle_num'] == cycle_num)]
                    current_recipe_line_cycle_run_status = existing_record.iloc[0]['recipe_line_cycle_run_status']
                    recipe_line_cycle_run_id = int(existing_record.iloc[0]['recipe_line_cycle_run_id'])

                    print(f"    Checking if cycle {cycle_num} is already completed.")
                    print(f"     status: {current_recipe_line_cycle_run_status}")
                    if current_recipe_line_cycle_run_status == 'C':
                        print(f"    Skipping recipe_line_cycle_run_id: {recipe_line_cycle_run_id} cycle number: {cycle_num}. Already processed!!!")
                        continue  # Skip to the next cycle

                print(f"    Running: {recipe_line_cycle_run_id}")
                recipe_line_cycle_run_values = {
                    "recipe_line_cycle_run_id": recipe_line_cycle_run_id,
                    "status": 'R',  # 'R' for Running
                    "run_params": run_params
                }

                print(f"     recipe_line_cycle_run_values 2 {recipe_line_cycle_run_values}")
                cea.upsert_recipe_line_cycle_run(recipe_line_cycle_run_values, conn)

                recipe_line_seq_cycle_run_start = cea.get_recipe_line_seq_cycle_run_start(recipe_line_cycle_run_id, conn)

                # RUN AGENT 
                cea.run_agent(unit_code, run_params, recipe_line_seq_cycle_run_start, conn)
                print(f"    Ran agent in unit: {unit_code} with: {run_params} with start date {recipe_run_status_df['recipe_run_start'].iloc[0]}")

                print(f"    Completed: {recipe_line_cycle_run_id}")
                recipe_line_cycle_run_values = {
                    "recipe_line_cycle_run_id": recipe_line_cycle_run_id,
                    "status": 'C'  # 'C' for Completed
                }
                
                print(f"     recipe_line_cycle_run_values 3 {recipe_line_cycle_run_values}")
                cea.upsert_recipe_line_cycle_run(recipe_line_cycle_run_values, conn)

        # Update overall recipe run status to 'Completed'
        print("Recipe run completed.")
        cea.update_recipe_run(recipe_run_id, status='C', conn=conn)
        print(f"Recipe {recipe_name} in unit {unit_code} completed! Recipe Run Id {recipe_run_id} updated to Completed (C)")

    except Exception as e:
        # Handle errors, print to standard error, and set recipe run status to 'Failed'
        print(f"Error: {e}", file=sys.stderr)
        if conn: #check if connection is still valid
           try:
               cea.update_recipe_run(recipe_run_id, status='F', conn=conn)
           except:
               print(f"Error updating recipe run status to Failed", file=sys.stderr)
        sys.exit(1)  # Use a non-zero exit code to indicate failure

    finally:
        # Ensure database connection is closed
        if conn:
            conn.close()
            print("Connection closed.")

if __name__ == "__main__":
    # Check if the required arguments are provided by the shell script
    if len(sys.argv) != 3:
        print("Usage: python run_recipe.py <unit_code> <recipe_name>", file=sys.stderr)
        sys.exit(1)

    # Read parameters from command-line arguments
    unit_code = sys.argv[1]
    recipe_name = sys.argv[2]

    # Run the recipe with the provided parameters
    run_recipe(unit_code, recipe_name)
