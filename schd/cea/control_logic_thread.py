def control_logic_thread(client, run_params, recipe_line_seq_cycle_run_start,
                          instance_shared_data, data_lock, stop_event,
                          control_algorithm='IF_THEN_ELSE',
                          control_algorithm_params=None,
                          preloaded_states=None,
                          result_states=None,
                          loops=None, unit_code=None, root=None, multi_zone=False):
    """Thread for control logic (feedback control Phase 2): a thin wrapper around
    cea.loop_resolver.

    Every 10 s, per active loop of the map (run_params[0]['control_loops']): resolve
    the process value from the readings the subscriber stored ((zone, tag, sensor) ->
    (value, receive time)), decide, and publish the command to
    <root>/<unit>/<zone>/control/<output.actuator> (the board dispatches on "tag" =
    the actuator). Limits come from the recipe line's columns the loop names
    (recipe_lower/recipe_upper); a NULL limit makes that loop inactive for the line,
    with one warning. Q8: a fallback sensor keeps controlling, with an ALARM line; on
    no_data the last command is held (re-sent, state "hold") and ALARM lines repeat;
    nothing is sent before a first command, so no_data never switches fans OFF.
    The light is time-based: once per iteration per zone of the map, readings or not.
    Stateful algorithms are keyed by loop_resolver.state_key (the old channel name on
    a unit of one zone).
    """
    import inspect
    from cea import mqtt_publish_control_message
    from cea import loop_resolver as lr
    from cea.algorithms import get_algorithm
    import json
    import datetime
    import time
    import sys
    from dateutil.relativedelta import relativedelta

    shared_data = instance_shared_data
    func_name = inspect.currentframe().f_code.co_name
    algorithms = {}           # state_key -> algorithm, built before the loop (no dir() hack)

    def log(msg, err=False):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", file=sys.stderr if err else sys.stdout, flush=True)

    try:
        run_params_list = json.loads(run_params) if isinstance(run_params, str) else run_params
        if not run_params_list or not isinstance(run_params_list[0], dict):
            print(f"ERROR in {func_name}: Invalid run_params format.", file=sys.stderr)
            return
        param_dict = run_params_list[0]
        light_type = param_dict.get('light_type', 'unknown_light')
        light_on_minutes = param_dict.get('light_on_minutes', 0) or 0

        # Algorithm resolved at trigger time and baked into run_params (audit trail).
        _algo_code = param_dict.get('control_algorithm', control_algorithm) or 'IF_THEN_ELSE'
        _algo_params = param_dict.get('control_algorithm_params', control_algorithm_params) or {}

        if loops is None:
            loops = param_dict.get('control_loops') or []
        if recipe_line_seq_cycle_run_start is None:
            print(f"ERROR in {func_name}: Missing essential parameters.", file=sys.stderr)
            return
        if not isinstance(recipe_line_seq_cycle_run_start, datetime.datetime):
            print(f"ERROR in {func_name}: recipe_line_seq_cycle_run_start is not a datetime object.", file=sys.stderr)
            return
        print(f"{func_name}: recipe_line_seq_cycle_run_start: {recipe_line_seq_cycle_run_start}")

        day_end_time = recipe_line_seq_cycle_run_start + relativedelta(minutes=light_on_minutes)
        tz = recipe_line_seq_cycle_run_start.tzinfo
        if tz is None:
            print(f"WARNING in {func_name}: recipe_line_seq_cycle_run_start is offset-naive.", file=sys.stderr)

        # ── one algorithm per active loop ─────────────────────────────────────
        active = []
        for loop in loops:
            lo, hi, why = lr.limits(loop, param_dict)
            if why:
                log(f"WARNING zone {loop['zone_code']} loop {loop['loop_code']}: {why}", err=True)
                continue
            key = lr.state_key(loop, multi_zone)
            algo = get_algorithm(_algo_code, lo, hi, **_algo_params)
            if preloaded_states and preloaded_states.get(key):
                algo.load_state(preloaded_states[key])
            algorithms[key] = algo
            active.append((loop, key))
        zones = lr.zones_of(loops) if loops else []
        print(f"{func_name}: algorithm '{_algo_code}' for loops: "
              f"{[k for _, k in active]}; light for zones {zones}")

        alarms = lr.AlarmTracker(unit_code)
        last_cmd = {}
        started_at = time.monotonic()

        # ── control loop ──────────────────────────────────────────────────────
        while not stop_event.is_set():
            now_aware = datetime.datetime.now(tz)
            now = time.monotonic()
            with data_lock:
                snap = dict(shared_data)

            for loop, key in active:
                try:
                    r = lr.resolve(loop, snap, now, started_at)
                    for line in alarms.update((loop['zone_code'], loop['loop_code']), r['alarm'], now,
                                              lr.alarm_detail(r, last_cmd.get(key))):
                        log(line, err=True)
                    cmd, hold = lr.decide(loop, r, algorithms[key], last_cmd.get(key))
                    if not cmd:
                        continue
                    topic = lr.command_topic(root, unit_code, loop['zone_code'], loop['output']['actuator'])
                    mqtt_publish_control_message(
                        client, topic=topic,
                        payload=lr.command_payload(loop, r, cmd, hold, str(now_aware)))
                    last_cmd[key] = cmd
                    log(f"{loop['zone_code']} {loop['loop_code'].upper()}: {r['value']} [{r['state']}"
                        f"{' hold' if hold else ''} {','.join(r['used'])}] -> {cmd} (algo={_algo_code})")
                except Exception as loop_e:     # one loop's failure never stops the others
                    log(f"ERROR in {func_name}: loop {key}: {loop_e!r}", err=True)

            light_command = "ON" if now_aware < day_end_time else "OFF"
            for zone in zones:
                try:
                    mqtt_publish_control_message(
                        client, topic=lr.light_topic(root, unit_code, zone),
                        payload={"timestamp": str(now_aware), "tag": "light",
                                 "value": light_type, "command": light_command})
                except Exception as pub_e:
                    log(f"ERROR in {func_name}: light publish failed for zone {zone}: {pub_e!r}", err=True)

            stop_event.wait(10)

    except Exception as main_e:
        print(f"FATAL ERROR in '{func_name}' during setup: {main_e}", file=sys.stderr)
        stop_event.set()

    finally:
        # Collect final algorithm states for persistence (Q_LEARNING, PID)
        if result_states is not None:
            for key, algo in algorithms.items():
                state = algo.get_state()
                if state:
                    result_states[key] = state

        print(f"Control logic thread '{func_name}' stopped.")
