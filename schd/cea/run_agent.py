def run_agent(unit_code, run_params, recipe_line_seq_cycle_run_start, conn, run_id=None, algorithm=None):
    """
    run_agent(unit_code, run_params, recipe_line_seq_cycle_run_start, conn, run_id=None, algorithm=None)
    =============================================================================
    Runs the MQTT agent with separate threads for subscription and control logic.
    This function initializes and manages the MQTT agent for a specific unit, 
    subscribing to topics and executing control logic in separate threads. It 
    handles graceful shutdowns and ensures proper cleanup of resources.
    Parameters
    ----------
    unit_code : str
        The unique identifier for the unit to be controlled.
    run_params : dict
        A dictionary containing runtime parameters for the agent.
    recipe_line_seq_cycle_run_start : datetime
        The start time of the recipe line sequence cycle.
    conn : object
        Database connection object used to fetch feedback control loop parameters.
    run_id : int, optional
        A run started by the scheduler API (RECIPE_RUN_ID, IAM plan 2.4). Then: the
        algorithm comes from `algorithm` when given; the transaction is ended before
        the cycle's wait (no idle transaction for hours); the Q-table state is saved
        acting for the run; and SIGTERM/SIGINT stops the threads, sends STOP and
        raises cea.RunStopped (the stop route has already marked the run F).
        Without run_id the behaviour is exactly the legacy one.
    algorithm : (str, dict), optional
        (algorithm code, parameters) for a run_id run, overriding run_params.
    Raises
    ------
    SystemExit
        Raised when a keyboard interrupt (Ctrl+C) or termination signal is detected.
    Exception
        Raised for any unexpected errors during the execution of the agent.
    Notes
    -----
    - The function retrieves feedback control loop parameters for the specified unit 
      and subscribes to MQTT topics based on these parameters.
    - It uses threading to run MQTT subscription and control logic concurrently.
    - The agent runs for a specified duration, calculated based on the provided 
      runtime parameters and recipe start time.
    - Graceful shutdown is implemented to stop threads and disconnect the MQTT client.
    Examples
    --------
    # run_agent("unit_123", {"param1": "value1"}, datetime.now(), db_connection)
    """
    import threading
    import time
    import paho.mqtt.client as mqtt
    import os
    import signal
    import sys
    from datetime import datetime
    from dateutil.relativedelta import relativedelta
    import json
    import cea  # Assuming cea is a module that provides the required functions
    import random

    mqtt_rootname = os.getenv('PROJECT_NAME')
    

    def signal_handler(sig, frame):
        """Handles keyboard interrupt (Ctrl+C)."""
        print("Keyboard interrupt detected. Stopping agent...")
        # stop_event.set()  # Make sure stop_event is defined and accessible here
        sys.exit(0)

    _stop_holder = {}

    def stop_handler(sig, frame):
        """A run_id run: SIGTERM from the scheduler's stop route (or Ctrl+C)."""
        print("Stop signal received. Stopping agent...")
        if _stop_holder.get('event') is not None:
            _stop_holder['event'].set()
        raise cea.RunStopped()

    # Assuming get_feedback_control_loop_params returns a list of dictionaries
    feedback_control_loop_params = cea.get_feedback_control_loop_params(unit_code, conn)  # get list of topics

    # Resolve algorithm + params from run_params (baked in by run_recipe.py at trigger time)
    _rp = json.loads(run_params) if isinstance(run_params, str) else run_params
    _rp_dict         = (_rp[0] if _rp and isinstance(_rp, list) else {}) or {}
    _control_algo    = (_rp_dict.get('control_algorithm',        'IF_THEN_ELSE') or 'IF_THEN_ELSE').upper()
    _algo_params     = _rp_dict.get('control_algorithm_params', {}) or {}
    if run_id is not None and algorithm is not None:
        _control_algo = (algorithm[0] or 'IF_THEN_ELSE').upper()
        _algo_params  = algorithm[1] or {}
    _unit_id         = cea.get_unit_id_from_code(unit_code, conn)

    # Pre-load persisted algorithm state so stateful algorithms warm-start
    _STATEFUL_ALGORITHMS = ('Q_LEARNING', 'PID')
    _preloaded_states: dict = {}
    _result_states:    dict = {}   # control_logic_thread writes final states here on exit
    if _control_algo in _STATEFUL_ALGORITHMS and _unit_id:
        for _ch in ('air_temperature', 'substrate_temperature', 'air_humidity', 'co2'):
            _preloaded_states[_ch] = cea.load_algorithm_state(_unit_id, _control_algo, _ch, conn)

    run_for_n_min=cea.calculate_minutes_to_run(run_params, recipe_line_seq_cycle_run_start)


    if feedback_control_loop_params:  # Check if the list is not empty
        # Access the 'zone_code' from the first element of the list.
        zone_code = json.loads(feedback_control_loop_params)[0]['zone_code']  # Access the first element of the list
        mqtt_topics = mqtt_rootname + '/' + unit_code + '/' + zone_code + '/sense/#' #for zone_code in zone_codes]  <to correct> Create a list of topics. one unit can have multiple zones.
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Feedback control loop parameters: {feedback_control_loop_params}")  # print feedback control loop params

        print(mqtt_topics)  # print mqtt topic

        mqtt_rootname=os.getenv('PROJECT_NAME')
        client_id = mqtt_rootname+f'-orchestrator-feedback-control-loop-{random.randint(0, 100)}'

        client = mqtt.Client(client_id=client_id)
        if os.getenv('MQTT_USER'):      # the broker admits nobody anonymously
            client.username_pw_set(os.getenv('MQTT_USER'), os.getenv('MQTT_PASS', ''))
        # Clear retained messages for the topic prefix
        stop_event = threading.Event()  # create event here.
        instance_shared_data ={}  # Initialize shared data dictionary
        data_lock = threading.Lock()  # Initialize a lock for thread-safe access to shared data

        # Set up MQTT client callbacks
        mqtt_thread = threading.Thread(target=cea.mqtt_subscribe_thread, args=(client, [mqtt_topics],instance_shared_data, data_lock, stop_event)) #pass mqtt_topics as a list
#        control_thread = threading.Thread(target=cea.control_logic_thread, args=(client, run_params, recipe_line_seq_cycle_run_start,instance_shared_data, stop_event))
        control_thread = threading.Thread(
            target=cea.control_logic_thread,
            args=(client, run_params, recipe_line_seq_cycle_run_start,
                  instance_shared_data, data_lock, stop_event),
            kwargs={
                'control_algorithm':        _control_algo,
                'control_algorithm_params': _algo_params,
                'preloaded_states':         _preloaded_states,
                'result_states':            _result_states,
            }
        )

        # Register signal handler for graceful shutdown
        if run_id is None:
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
        else:
            _stop_holder['event'] = stop_event
            signal.signal(signal.SIGINT, stop_handler)
            signal.signal(signal.SIGTERM, stop_handler)

        # Start threads
        all_threads = [mqtt_thread, control_thread]  #  List of threads
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting MQTT subscription and control logic threads...")
        for thread in all_threads:
            thread.start()

        run_for_n_min = cea.calculate_minutes_to_run(run_params, recipe_line_seq_cycle_run_start)
        if run_id is None:
            time.sleep(run_for_n_min * 60)  # Run for specified minutes
        else:
            conn.rollback()  # end the read transaction: nothing waits on it for the cycle's length
            try:
                time.sleep(run_for_n_min * 60)
            except cea.RunStopped:
                stop_event.set()
                for thread in all_threads:
                    thread.join(timeout=30)
                try:
                    cea.mqtt_publish_control_message(client, topic=mqtt_topics, payload={"command": "STOP", "value": 0}, publish_type="finished")
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Published shutdown message to {mqtt_topics}")
                    client.disconnect()
                except Exception as e:  # noqa: BLE001 — stopping must not fail on the broker
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Could not publish STOP: {e}", file=sys.stderr)
                raise
        stop_event.set()  # signal stop to both threads

        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Stopping threads...")
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Shared data content before clear: {instance_shared_data} for threads to finish...")
        instance_shared_data.clear()  # Clear shared data to signal threads to finish


        
        # Shutdown all controllers
        print("Shutting down all controllers...")
        # Publish a message to all controllers to stop
        print("Agent stopped.")
        # Handle SystemExit or KeyboardInterrupt to stop all threads gracefully
        try:
            # Wait for threads to finish
            for thread in all_threads:
                thread.join()
                if thread.is_alive():
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] WARNING: Thread '{thread.name}' did not stop within the timeout.", file=sys.stderr)
                else:
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Thread '{thread.name}' stopped successfully.")

            # Persist stateful algorithm state for next run
            if _control_algo in _STATEFUL_ALGORITHMS and _unit_id and _result_states:
                for _ch, _state in _result_states.items():
                    if run_id is None:
                        cea.save_algorithm_state(_unit_id, _control_algo, _ch, _state, conn)
                    else:
                        cea.save_algorithm_state(_unit_id, _control_algo, _ch, _state, conn, run_id=run_id)
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {_control_algo} state saved for {len(_result_states)} channel(s).")

            for topic in [mqtt_topics]: # <to correct> attention to correct when support multiple zones.
                # Publish a message to the control topic to stop all controllers
                cea.mqtt_publish_control_message(client, topic=topic, payload={"command": "STOP", "value": 0}, publish_type="finished")
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Published shutdown message to {topic}")
            # Disconnect MQTT client
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Disconnecting MQTT client...")   
            client.disconnect()  # disconnect client.

        except (SystemExit, KeyboardInterrupt):
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] SystemExit or KeyboardInterrupt detected. Stopping all threads...")
            stop_event.set()  # Signal threads to stop
            for thread in all_threads:
                thread.join()
            print("All threads stopped.")
            for topic in mqtt_topics:
            # Publish a message to the control topic to stop all controllers
                cea.mqtt_publish_control_message(client, topic=topic, payload={"command": "STOP", "value": 0}, publish_type="finished")
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Published shutdown message to {topic}")
            # Disconnect MQTT client
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Disconnecting MQTT client...")   
            client.disconnect()  # disconnect client.
        
        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] An error occurred: {e}", file=sys.stderr)
            # Ensure all threads are stopped
            stop_event.set()

    else:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] No feedback control loop parameters found for unit code: {unit_code}.  Agent not started.")
