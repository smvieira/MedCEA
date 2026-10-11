def control_logic_thread(client, run_params, recipe_line_seq_cycle_run_start,
                          instance_shared_data, data_lock, stop_event,
                          control_algorithm='IF_THEN_ELSE',
                          control_algorithm_params=None,
                          preloaded_states=None,
                          result_states=None):
    import inspect
    from cea import mqtt_publish_control_message
    from cea.algorithms import get_algorithm
    import json
    import datetime
    import time
    import sys
    from dateutil.relativedelta import relativedelta

    """Thread for control logic."""

    shared_data = instance_shared_data
    func_name   = inspect.currentframe().f_code.co_name

    try:
        run_params_list = json.loads(run_params)
        if not run_params_list or not isinstance(run_params_list[0], dict):
            print(f"ERROR in {func_name}: Invalid run_params format.", file=sys.stderr)
            return
        param_dict = run_params_list[0]

        air_temperature_lower_limit      = param_dict.get('air_temperature_lower_limit')
        air_temperature_upper_limit      = param_dict.get('air_temperature_upper_limit')
        substrate_temperature_lower_limit = param_dict.get('substrate_temperature_lower_limit')
        substrate_temperature_upper_limit = param_dict.get('substrate_temperature_upper_limit')
        hr_lower_limit  = param_dict.get('hr_lower_limit')
        hr_upper_limit  = param_dict.get('hr_upper_limit')
        co2_lower_limit = param_dict.get('co2_lower_limit')
        co2_upper_limit = param_dict.get('co2_upper_limit')
        light_type       = param_dict.get('light_type', 'unknown_light')
        light_on_minutes = param_dict.get('light_on_minutes', 0)

        # Algorithm resolved at trigger time and baked into run_params (audit trail).
        # Fall back to the values passed as kwargs if not in run_params.
        _algo_code   = param_dict.get('control_algorithm', control_algorithm) or 'IF_THEN_ELSE'
        _algo_params = param_dict.get('control_algorithm_params', control_algorithm_params) or {}

        if any(v is None for v in [air_temperature_lower_limit,
                                    air_temperature_upper_limit,
                                    recipe_line_seq_cycle_run_start]):
            print(f"ERROR in {func_name}: Missing essential parameters.", file=sys.stderr)
            return

        if not isinstance(recipe_line_seq_cycle_run_start, datetime.datetime):
            print(f"ERROR in {func_name}: recipe_line_seq_cycle_run_start is not a datetime object.", file=sys.stderr)
            return

        print(f"{func_name}: recipe_line_seq_cycle_run_start: {recipe_line_seq_cycle_run_start}")

        day_end_time = recipe_line_seq_cycle_run_start + relativedelta(minutes=light_on_minutes)
        tz           = recipe_line_seq_cycle_run_start.tzinfo
        if tz is None:
            print(f"WARNING in {func_name}: recipe_line_seq_cycle_run_start is offset-naive.", file=sys.stderr)

        # ── Build one algorithm instance per sensor channel ───────────────────
        _channel_limits = {
            'air_temperature':      (air_temperature_lower_limit,       air_temperature_upper_limit),
            'substrate_temperature': (substrate_temperature_lower_limit, substrate_temperature_upper_limit),
            'air_humidity':          (hr_lower_limit,                    hr_upper_limit),
            'co2':                   (co2_lower_limit,                   co2_upper_limit),
        }

        _algorithms: dict = {}
        for ch, (lo, hi) in _channel_limits.items():
            if lo is not None and hi is not None:
                algo = get_algorithm(_algo_code, float(lo), float(hi), **_algo_params)
                if preloaded_states and ch in preloaded_states:
                    algo.load_state(preloaded_states[ch])
                _algorithms[ch] = algo

        print(f"{func_name}: Using algorithm '{_algo_code}' for channels: {list(_algorithms.keys())}")

        # ── Control loop ──────────────────────────────────────────────────────
        while not stop_event.is_set():
            now_aware    = datetime.datetime.now(tz)
            current_time = time.strftime('%Y-%m-%d %H:%M:%S')

            with data_lock:
                data_snapshot = shared_data.copy()

            if not data_snapshot:
                time.sleep(1)
                continue

            _light_published = False   # publish light once per cycle, not once per topic

            for topic, payload in data_snapshot.items():
                try:
                    if not isinstance(payload, dict) or 'value' not in payload:
                        continue

                    sensor_value = float(payload['value'])
                    tag          = topic.split('/')[-1]

                    try:
                        # Find which channel this topic belongs to
                        matched_channel = next(
                            (ch for ch in _algorithms if ch in topic), None
                        )

                        if matched_channel:
                            command = _algorithms[matched_channel].compute(sensor_value)
                            mqtt_publish_control_message(
                                client, topic=topic,
                                payload={"timestamp": str(now_aware),
                                         "tag": tag, "command": command}
                            )
                            print(f"[{current_time}] {matched_channel.upper()}: "
                                  f"{sensor_value} → {command} (algo={_algo_code})")

                            # Light control — time-based, published once per loop cycle.
                            # Derive the control topic from the first matched sense topic:
                            #   medcea/UNIT/ZONE/sense/air_temperature
                            #   →  medcea/UNIT/ZONE/control/light
                            if not _light_published:
                                parts = topic.split('/')
                                # Replace 'sense' segment with 'control', drop channel segment
                                try:
                                    sense_idx = parts.index('sense')
                                    light_control_topic = '/'.join(parts[:sense_idx]) + '/control/light'
                                except ValueError:
                                    # Fallback: replace last two segments
                                    light_control_topic = '/'.join(parts[:-2]) + '/control/light'

                                light_command = "ON" if now_aware < day_end_time else "OFF"
                                print(f"[{current_time}] LIGHT: {light_command} "
                                      f"({light_type}) → {light_control_topic}")
                                mqtt_publish_control_message(
                                    client, topic=light_control_topic,
                                    payload={"timestamp": str(now_aware), "tag": "light",
                                             "value": light_type, "command": light_command}
                                )
                                _light_published = True

                    except Exception as pub_e:
                        print(f"[{current_time}] ERROR in {func_name}: publish failed: {pub_e}",
                              file=sys.stderr)

                except (ValueError, TypeError) as val_e:
                    print(f"[{current_time}] ERROR in {func_name}: "
                          f"invalid payload for '{topic}': {val_e}", file=sys.stderr)
                except Exception as loop_e:
                    print(f"[{current_time}] ERROR in {func_name}: "
                          f"exception on '{topic}': {loop_e}", file=sys.stderr)

            time.sleep(10)

    except Exception as main_e:
        print(f"FATAL ERROR in '{func_name}' during setup: {main_e}", file=sys.stderr)
        stop_event.set()

    finally:
        # Collect final algorithm states for Q-table persistence
        if result_states is not None:
            for ch, algo in _algorithms.items() if '_algorithms' in dir() else []:
                state = algo.get_state()
                if state:
                    result_states[ch] = state

        print(f"Control logic thread '{func_name}' stopped.")
