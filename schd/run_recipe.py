import sys
import time
import os
import json
from datetime import datetime, timezone
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

        # The legacy path writes recipe_run and its cycles directly: refused once the
        # database enforces (IAM_DB_ROLES=true), where only the run functions may.
        if cea.has_008b(conn) and cea.enforcing(conn):
            print("Refused: IAM_DB_ROLES=true — a run is started through the scheduler "
                  "(medcea.start_run), which hands it to this script as RECIPE_RUN_ID.", file=sys.stderr)
            sys.exit(1)
        conn.rollback()

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
        if os.getenv('MQTT_USER'):      # the broker admits nobody anonymously
            client.username_pw_set(os.getenv('MQTT_USER'), os.getenv('MQTT_PASS', ''))
        
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

def run_recipe_by_id(run_id, unit_code, recipe_name):
    """
    Executes run `run_id`, which the scheduler API has already started
    (medcea.start_run: S -> R, executed_by recorded) — IAM plan 2.4.

    Every write goes through migration 008b's functions, each in its own
    transaction acting as system:scheduler for the run's creator (cea.actor):
    per cycle record_cycle(R) -> agent -> record_cycle(C, end), then
    finish_run(C). Cycles already completed (a re-executed run) are skipped,
    and a completed cycle is never reopened.

    The algorithm: IAM_DB_ROLES=true — the run's parameter set (params_id);
    false — CONTROL_ALGORITHM / CONTROL_ALGORITHM_PARAMS from the scheduler
    (its execute body or the schedule's inline settings, as before).

    A stop (SIGTERM from the stop route, which has already marked the run F)
    exits 0 and writes nothing. Any other failure marks the current cycle and
    the run F while the run is still R, and exits 1.
    """
    load_dotenv('../installer/.env', override=True)
    db_config = {
        "host": os.getenv('DB_HOST'),
        "database": os.getenv('DB_NAME'),
        "user": os.getenv('DB_USER'),
        "password": os.getenv('DB_PASS')
    }
    conn = cea.connect_to_db(db_config)
    if not conn:
        print("Failed to connect to database.", file=sys.stderr)
        sys.exit(1)
    print(f"Connected to database. Recipe run ID: {run_id}")

    # Preconditions: nothing is written when they fail (the scheduler ends a run it
    # spawned and that is still R once this process exits).
    try:
        if not cea.has_008b(conn):
            raise RuntimeError("RECIPE_RUN_ID needs migration 008b (./apps/database/deploy.sh)")
        ctx = cea.run_context(conn, run_id)
        if ctx is None:
            raise RuntimeError(f"no run {run_id}")
        if ctx['recipe_run_status'] != 'R':
            raise RuntimeError(f"run {run_id} is {ctx['recipe_run_status']}, not R (medcea.start_run first)")
        if ctx['unit_code'] != unit_code or ctx['recipe_name'] != recipe_name:
            raise RuntimeError(f"run {run_id} is {ctx['recipe_name']!r} on {ctx['unit_code']!r}, "
                               f"not {recipe_name!r} on {unit_code!r}")
        enforce = cea.enforcing(conn)
        conn.rollback()
        if enforce:
            if ctx['params_id'] is None or not ctx['set_algorithm']:
                raise RuntimeError(f"run {run_id} has no parameter set (IAM_DB_ROLES=true)")
            algo = ctx['set_algorithm'].upper()
            params = ctx['set_params'] or {}
            if isinstance(params, str):
                params = json.loads(params)
            if os.getenv('CONTROL_ALGORITHM'):
                print("CONTROL_ALGORITHM ignored: the run uses its parameter set.")
        else:
            algo = (os.getenv('CONTROL_ALGORITHM', 'IF_THEN_ELSE') or 'IF_THEN_ELSE').upper()
            params = json.loads(os.getenv('CONTROL_ALGORITHM_PARAMS', '{}') or '{}')
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        conn.close()
        sys.exit(1)

    print(f"Unit code: {unit_code}")
    print(f"Recipe name: {recipe_name}")
    print(f"Algorithm: {algo} (params_id {ctx['params_id']})")

    current = None          # (recipe_id, seq_id, cycle) of the cycle in progress
    stopped = False
    rc = 0
    try:
        status_df = cea.get_recipe_run_status(run_id, conn=conn)
        conn.rollback()
        for _, row in status_df.drop_duplicates(subset=['recipe_id', 'recipe_item_seq_id', 'recipe_run_id']).iterrows():
            recipe_id = int(row['recipe_id'])
            seq_id = int(row['recipe_item_seq_id'])
            cycles = int(row['cycle_number'])
            run_params = json.loads(cea.get_recipe_line_item_seq_details(recipe_id, seq_id, conn=conn))
            conn.rollback()
            # the algorithm and its parameters go into the cycle's run_params (audit trail)
            if run_params and isinstance(run_params, list):
                run_params[0]['control_algorithm'] = algo
                run_params[0]['control_algorithm_params'] = params
            print(f"Processing recipe: {recipe_name}, item seq ID {seq_id} with {cycles} cycles (algo={algo})")
            for cycle_num in range(1, cycles + 1):
                done = status_df[(status_df['recipe_id'] == recipe_id) &
                                 (status_df['recipe_item_seq_id'] == seq_id) &
                                 (status_df['recipe_item_seq_cycle_num'] == cycle_num) &
                                 (status_df['recipe_line_cycle_run_status'] == 'C')]
                if not done.empty:
                    print(f"    Skipping cycle {cycle_num} of item seq {seq_id}. Already completed.")
                    continue
                current = (recipe_id, seq_id, cycle_num)
                cycle_id = cea.record_cycle(conn, run_id, recipe_id, seq_id, cycle_num, 'R', run_params=run_params)
                print(f"    Running: {cycle_id}")
                cycle_start = cea.get_recipe_line_seq_cycle_run_start(cycle_id, conn)
                conn.rollback()
                cea.run_agent(unit_code, json.dumps(run_params), cycle_start, conn,
                              run_id=run_id, algorithm=(algo, params))
                cea.record_cycle(conn, run_id, recipe_id, seq_id, cycle_num, 'C',
                                 end=datetime.now(timezone.utc).isoformat())
                print(f"    Completed: {cycle_id}")
                current = None
        if cea.finish(conn, run_id, 'C'):
            print(f"Recipe {recipe_name} in unit {unit_code} completed! Recipe Run Id {run_id} updated to Completed (C)")
        else:
            print(f"Recipe run {run_id} is no longer R (stopped meanwhile); not completed.")
    except cea.RunStopped:
        stopped = True
    except BaseException as e:      # SystemExit and KeyboardInterrupt included: the run must not stay R
        print(f"Error: {e!r}", file=sys.stderr)
        rc = 1
        try:
            if cea.run_status(conn, run_id) == 'R':
                if current is not None:
                    cea.record_cycle(conn, run_id, *current, 'F')
                cea.finish(conn, run_id, 'F')
                print(f"Recipe run {run_id} marked Failed (F).", file=sys.stderr)
        except BaseException as e2:
            print(f"Error marking run {run_id} Failed: {e2!r}", file=sys.stderr)
    finally:
        conn.close()
        print("Connection closed.")
    if stopped:
        print(f"Recipe run {run_id} stopped (already marked F by the scheduler).")
        sys.exit(0)
    sys.exit(rc)


if __name__ == "__main__":
    # Check if the required arguments are provided by the shell script
    if len(sys.argv) != 3:
        print("Usage: python run_recipe.py <unit_code> <recipe_name>", file=sys.stderr)
        sys.exit(1)

    # Read parameters from command-line arguments
    unit_code = sys.argv[1]
    recipe_name = sys.argv[2]

    # RECIPE_RUN_ID: a run the scheduler API created and started (IAM plan 2.4).
    # Without it, the legacy command-line path (finds or creates the unit's run).
    if os.getenv('RECIPE_RUN_ID'):
        run_recipe_by_id(int(os.environ['RECIPE_RUN_ID']), unit_code, recipe_name)
    else:
        run_recipe(unit_code, recipe_name)
