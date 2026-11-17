"""
cea.algorithms.params: the parameter schema of every controller in ALGORITHM_NAMES.

Part of the research sandbox's coupling contract (plan "Coupling contract", item 3):
the scheduler and the research gateway read this one table to check a parameter set
before it is used or registered. Standard library only; it imports no algorithm, so
reading it needs neither gekko nor scikit-fuzzy.

Names, types and defaults are each class's __init__ keyword arguments
(tests/test_controllers_parity.py compares them with inspect.signature). The min/max
bounds are sanity limits for validation, not tuning advice; where a bound comes from
the code it says so, otherwise it is an assumption to revisit with the plant model
(research sandbox Phase 3 calibration).

    from cea.algorithms.params import validate_params
    problems = validate_params("FLC", {"deadband_fraction": 0.08})   # [] when valid

A parameter entry: {"type": "float"|"int", "default", "min", "max",
"min_exclusive" (bool, optional), "unit", "meaning"}. An int parameter accepts only
an int; a float parameter accepts an int or a float (never a bool or a string).
"""

SCHEMA_VERSION = 1

PARAMS = {
    # bang_bang.py: no tuning parameter.
    "IF_THEN_ELSE": {},
    # pid.py. The error is in the quantity's own unit (degC, %RH, ppm), so a useful gain
    # differs per quantity; the bounds below only refuse nonsense (assumption).
    "PID": {
        "kp": {"type": "float", "default": 0.2, "min": 0.0, "max": 100.0,
               "unit": "1 / quantity unit", "meaning": "proportional gain"},
        "ki": {"type": "float", "default": 0.05, "min": 0.0, "max": 100.0,
               "unit": "1 / (quantity unit x s)", "meaning": "integral gain"},
        "kd": {"type": "float", "default": 0.01, "min": 0.0, "max": 100.0,
               "unit": "s / quantity unit", "meaning": "derivative gain"},
        # min 1 s: below the runner's 10-s tick the PWM window is meaningless anyway;
        # max one hour (assumption). The default 10 s equals the tick, so the duty
        # cycle aliases with it (plan, Phase 1: a property of production PID).
        "cycle_time": {"type": "float", "default": 10.0, "min": 1.0, "max": 3600.0,
                       "unit": "s", "meaning": "PWM (time-proportioning) window length"},
    },
    # flc.py. The output sets are trapmf(-1, -1, -0.4, -db) and trapmf(db, 0.4, 1, 1), so
    # db must stay below 0.4 for the membership functions to keep their order (code);
    # 0 would make the zero set a point (min exclusive).
    "FLC": {
        "deadband_fraction": {"type": "float", "default": 0.1, "min": 0.0, "min_exclusive": True,
                              "max": 0.4, "unit": "fraction of the setpoint span",
                              "meaning": "width of the zero-error band"},
    },
    # mpc.py. horizon is clamped to >= 1 by the code; max 60 steps = 10 min ahead at the
    # 10-s tick (assumption: solve time grows with it).
    "MPC": {
        "horizon": {"type": "int", "default": 6, "min": 1, "max": 60,
                    "unit": "steps of ~10 s", "meaning": "prediction and control horizon"},
        "switching_cost": {"type": "float", "default": 0.1, "min": 0.0, "max": 10.0,
                           "unit": "dimensionless", "meaning": "penalty on changes of the control action (DCOST)"},
    },
    # q_learning.py. Learning rate and decay must be in (0, 1], discount and exploration
    # in [0, 1] (the definitions of the terms).
    "Q_LEARNING": {
        "alpha": {"type": "float", "default": 0.1, "min": 0.0, "min_exclusive": True, "max": 1.0,
                  "unit": "dimensionless", "meaning": "learning rate"},
        "gamma": {"type": "float", "default": 0.95, "min": 0.0, "max": 1.0,
                  "unit": "dimensionless", "meaning": "discount factor"},
        "epsilon": {"type": "float", "default": 0.2, "min": 0.0, "max": 1.0,
                    "unit": "probability", "meaning": "initial exploration rate"},
        "epsilon_decay": {"type": "float", "default": 0.995, "min": 0.0, "min_exclusive": True, "max": 1.0,
                          "unit": "factor per step", "meaning": "multiplicative decay of epsilon per call"},
    },
}


def defaults(code):
    """The default parameter set of CODE (a new dict), or None for an unknown code."""
    spec = PARAMS.get(code)
    if spec is None:
        return None
    return {k: v["default"] for k, v in spec.items()}


def _type_ok(kind, value):
    if isinstance(value, bool):
        return False
    if kind == "int":
        return isinstance(value, int)
    return isinstance(value, (int, float))


def validate_params(code, params):
    """Problems with PARAMS for algorithm CODE, as a list of sentences ([] when valid).

    Kinds: an unknown code (get_algorithm would silently run bang-bang), a parameter set
    that is not an object, an unknown key (the classes swallow it through **kwargs), a
    wrong type, a value out of range. None or {} means the defaults.
    """
    if not isinstance(code, str) or code not in PARAMS:
        return ["unknown algorithm code %r (known: %s)" % (code, ", ".join(sorted(PARAMS)))]
    if params is None:
        return []
    if not isinstance(params, dict):
        return ["%s: the parameters must be an object, not %s" % (code, type(params).__name__)]
    spec = PARAMS[code]
    problems = []
    for key in sorted(params, key=str):
        value = params[key]
        if key not in spec:
            known = ", ".join(sorted(spec)) or "none"
            problems.append("%s: unknown parameter %r (known: %s)" % (code, key, known))
            continue
        p = spec[key]
        if not _type_ok(p["type"], value):
            problems.append("%s: %s must be %s, not %r" % (
                code, key, "an integer" if p["type"] == "int" else "a number", value))
            continue
        if value != value or value in (float("inf"), float("-inf")):
            problems.append("%s: %s must be a finite number" % (code, key))
            continue
        low_bad = value <= p["min"] if p.get("min_exclusive") else value < p["min"]
        if low_bad or value > p["max"]:
            problems.append("%s: %s = %r is outside %s%s, %s]" % (
                code, key, value, "(" if p.get("min_exclusive") else "[", p["min"], p["max"]))
    return problems
