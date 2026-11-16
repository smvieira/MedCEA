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
        Database connection object (algorithm state; the loop map only when run_params lacks it).
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
    - The loop map comes from run_params[0]['control_loops'] (run_recipe.py reads it
      once per run with cea.get_control_loops); the agent subscribes to sense/# of
      every zone of the map and publishes to control/<actuator> (cea.loop_resolver).
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
    import uuid

    mqtt_rootname = os.getenv('PROJECT_NAME') or 'medcea'
    

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

    # Resolve algorithm + params from run_params (baked in by run_recipe.py at trigger time)
    _rp = json.loads(run_params) if isinstance(run_params, str) else run_params
    _rp_dict         = (_rp[0] if _rp and isinstance(_rp, list) else {}) or {}
    _control_algo    = (_rp_dict.get('control_algorithm',        'IF_THEN_ELSE') or 'IF_THEN_ELSE').upper()
    _algo_params     = _rp_dict.get('control_algorithm_params', {}) or {}
    if run_id is not None and algorithm is not None:
        _control_algo = (algorithm[0] or 'IF_THEN_ELSE').upper()
        _algo_params  = algorithm[1] or {}

    # The loop map: read once at run start into run_params (run_recipe.py); read here
    # only for a caller that did not (defensive). No loops is an error, never a
    # silent "agent not started".
    loops = _rp_dict.get('control_loops')
    if loops is None:
        loopset = cea.get_control_loops(unit_code, conn)
        for w in loopset['warnings']:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] WARNING: {w}", file=sys.stderr)
        loops = loopset['loops']
    if not loops:
        raise RuntimeError(f"no control loops for unit {unit_code}")
    lr = cea.loop_resolver
    zones = lr.zones_of(loops)
    multi_zone = len(zones) > 1
    mqtt_topics = lr.subscribe_topics(mqtt_rootname, unit_code, zones)
    if not mqtt_topics:
        raise RuntimeError(f"no MQTT topic can be built for unit {unit_code!r} zones {zones}")
    stop_list = lr.stop_topics(mqtt_rootname, unit_code, zones)
    _unit_id         = cea.get_unit_id_from_code(unit_code, conn)

    # Pre-load persisted algorithm state so stateful algorithms warm-start
    _STATEFUL_ALGORITHMS = ('Q_LEARNING', 'PID')
    _preloaded_states: dict = {}
    _result_states:    dict = {}   # control_logic_thread writes final states here on exit
    if _control_algo in _STATEFUL_ALGORITHMS and _unit_id:
        for _key in sorted({lr.state_key(l, multi_zone) for l in loops}):
            _preloaded_states[_key] = cea.load_algorithm_state(_unit_id, _control_algo, _key, conn)

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Control loops ({_rp_dict.get('control_loops_source', 'read now')}): "
          + "; ".join(f"{l['zone_code']}/{l['loop_code']} <- {l['input'].get('tag')} -> control/{l['output'].get('actuator')}"
                      for l in loops))
    print(mqtt_topics)

    client_id = f"{mqtt_rootname}-orchestrator-feedback-control-loop-{uuid.uuid4().hex[:8]}"
    client = mqtt.Client(client_id=client_id)
    if os.getenv('MQTT_USER'):      # the broker admits nobody anonymously
        client.username_pw_set(os.getenv('MQTT_USER'), os.getenv('MQTT_PASS', ''))
    stop_event = threading.Event()
    instance_shared_data = {}       # (zone, tag, sensor) -> (value, receive time)
    data_lock = threading.Lock()

    def publish_stop():
        """STOP (all_controllers_off) to every zone of the map, each on its own."""
        for topic in stop_list:
            try:
                cea.mqtt_publish_control_message(client, topic=topic, payload={"command": "STOP", "value": 0}, publish_type="finished")
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Published shutdown message to {topic}")
            except Exception as e:  # noqa: BLE001 — stopping must not fail on the broker
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Could not publish STOP to {topic}: {e}", file=sys.stderr)

    mqtt_thread = threading.Thread(target=cea.mqtt_subscribe_thread,
                                   args=(client, mqtt_topics, instance_shared_data, data_lock, stop_event),
                                   kwargs={'root': mqtt_rootname, 'unit_code': unit_code})
    control_thread = threading.Thread(
        target=cea.control_logic_thread,
        args=(client, run_params, recipe_line_seq_cycle_run_start,
              instance_shared_data, data_lock, stop_event),
        kwargs={
            'control_algorithm':        _control_algo,
            'control_algorithm_params': _algo_params,
            'preloaded_states':         _preloaded_states,
            'result_states':            _result_states,
            'loops':                    loops,
            'unit_code':                unit_code,
            'root':                     mqtt_rootname,
            'multi_zone':               multi_zone,
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
    all_threads = [mqtt_thread, control_thread]
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
            publish_stop()
            try:
                client.disconnect()
            except Exception as e:  # noqa: BLE001
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Could not disconnect: {e}", file=sys.stderr)
            raise
    stop_event.set()  # signal stop to both threads

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Stopping threads...")
    print("Shutting down all controllers...")
    try:
        # Wait for threads to finish
        for thread in all_threads:
            thread.join()
            if thread.is_alive():
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] WARNING: Thread '{thread.name}' did not stop within the timeout.", file=sys.stderr)
            else:
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Thread '{thread.name}' stopped successfully.")
        instance_shared_data.clear()

        # Persist stateful algorithm state for next run
        if _control_algo in _STATEFUL_ALGORITHMS and _unit_id and _result_states:
            for _key, _state in _result_states.items():
                if run_id is None:
                    cea.save_algorithm_state(_unit_id, _control_algo, _key, _state, conn)
                else:
                    cea.save_algorithm_state(_unit_id, _control_algo, _key, _state, conn, run_id=run_id)
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {_control_algo} state saved for {len(_result_states)} loop(s).")

        publish_stop()
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Disconnecting MQTT client...")
        client.disconnect()
        print("Agent stopped.")

    except (SystemExit, KeyboardInterrupt):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] SystemExit or KeyboardInterrupt detected. Stopping all threads...")
        stop_event.set()  # Signal threads to stop
        for thread in all_threads:
            thread.join()
        print("All threads stopped.")
        publish_stop()
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Disconnecting MQTT client...")
        client.disconnect()

    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] An error occurred: {e}", file=sys.stderr)
        # Ensure all threads are stopped
        stop_event.set()
