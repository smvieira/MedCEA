import sys as _sys
from .base import ControlAlgorithm

# Fallback reporting (research sandbox Phase 1, owner decision of 17 Nov 2026): FLC used
# to fall back to bang-bang silently (scikit-fuzzy 0.5.0 also needs `packaging`, which it
# does not declare). FALLBACK_TOTAL counts every fallback in this process; each instance
# keeps fallback_count and last_fallback (the reason). One stderr line the first time an
# instance falls back, then one every REPORT_EVERY fallbacks (one an hour at the 10-s tick).
FALLBACK_TOTAL = 0
REPORT_EVERY = 360


def _one_line(text, limit=200):
    return " ".join(str(text).split())[:limit]


def _note_fallback(algo, reason):
    global FALLBACK_TOTAL
    FALLBACK_TOTAL += 1
    algo.fallback_count += 1
    algo.last_fallback = reason
    if (algo.fallback_count - 1) % REPORT_EVERY == 0:
        print("WARNING flc fallback: %s; bang-bang used (fallback %d of this controller,"
              " reported every %d)" % (reason, algo.fallback_count, REPORT_EVERY),
              file=_sys.stderr, flush=True)


class FLCAlgorithm(ControlAlgorithm):
    """
    Fuzzy Logic Control.

    IEEE-validated for Pleurotus ostreatus cultivation: +37% yield vs bang-bang.
    Maps naturally to discrete UP/DOWN/OFF commands with no plant model needed.
    Library: scikit-fuzzy (pip install scikit-fuzzy).

    Tuning parameters:
        deadband_fraction (float, default 0.1) - fraction of setpoint span used
                                                  as the zero-error deadband width.

    Two input variables:
        error      : (sensor - setpoint) normalised by span → [-1, 1]
        error_rate : change in error since last call, normalised by span

    Output membership: DOWN (positive error), OFF (near zero), UP (negative error).
    Defuzzification → centroid → thresholded to discrete command.

    Falls back to BANG_BANG behaviour if scikit-fuzzy is not installed or compute fails,
    and reports it (fallback_count, last_fallback, a rate-limited stderr WARNING).
    """

    def __init__(self, lower_limit: float, upper_limit: float,
                 deadband_fraction: float = 0.1, **kwargs):
        super().__init__(lower_limit, upper_limit)
        self.deadband_fraction = float(deadband_fraction)
        self._span       = max(upper_limit - lower_limit, 1e-9)
        self._prev_error = 0.0
        self._ctrl       = None  # lazy-initialised fuzzy controller
        self._import_error  = None  # why scikit-fuzzy could not be imported
        self.fallback_count = 0     # compute() calls answered by the bang-bang fallback
        self.last_fallback  = None  # the reason of the latest fallback
        self._build_controller()

    def _build_controller(self):
        try:
            import numpy as np
            import skfuzzy as fuzz
            from skfuzzy import control as ctrl

            error_range = np.linspace(-1.0, 1.0, 101)
            rate_range  = np.linspace(-1.0, 1.0, 101)
            out_range   = np.linspace(-1.0, 1.0, 101)

            error_var = ctrl.Antecedent(error_range, 'error')
            rate_var  = ctrl.Antecedent(rate_range,  'rate')
            out_var   = ctrl.Consequent(out_range,   'output', defuzzify_method='centroid')

            db = self.deadband_fraction

            # Error membership functions: NL, NS, ZE, PS, PL
            error_var['NL'] = fuzz.trapmf(error_range, [-1.0, -1.0, -0.6, -db])
            error_var['NS'] = fuzz.trimf(error_range,  [-0.6,  -db,    0.0])
            error_var['ZE'] = fuzz.trimf(error_range,  [ -db,   0.0,    db])
            error_var['PS'] = fuzz.trimf(error_range,  [  0.0,   db,   0.6])
            error_var['PL'] = fuzz.trapmf(error_range, [   db,  0.6,  1.0, 1.0])

            # Rate membership functions
            rate_var['N']  = fuzz.trapmf(rate_range, [-1.0, -1.0, -db, 0.0])
            rate_var['ZE'] = fuzz.trimf(rate_range,  [ -db,  0.0,   db])
            rate_var['P']  = fuzz.trapmf(rate_range, [ 0.0,   db,  1.0, 1.0])

            # Output membership functions
            out_var['UP']   = fuzz.trapmf(out_range, [-1.0, -1.0, -0.4, -db])
            out_var['OFF']  = fuzz.trimf(out_range,  [ -db,  0.0,   db])
            out_var['DOWN'] = fuzz.trapmf(out_range, [   db,  0.4,  1.0, 1.0])

            # Rules
            rules = [
                ctrl.Rule(error_var['NL'],                          out_var['UP']),
                ctrl.Rule(error_var['NS'],                          out_var['UP']),
                ctrl.Rule(error_var['ZE'] & rate_var['ZE'],         out_var['OFF']),
                ctrl.Rule(error_var['ZE'] & rate_var['P'],          out_var['DOWN']),
                ctrl.Rule(error_var['ZE'] & rate_var['N'],          out_var['UP']),
                ctrl.Rule(error_var['PS'],                          out_var['DOWN']),
                ctrl.Rule(error_var['PL'],                          out_var['DOWN']),
            ]

            system      = ctrl.ControlSystem(rules)
            self._ctrl  = ctrl.ControlSystemSimulation(system)

        except ImportError as e:
            # scikit-fuzzy (or numpy, or packaging) not installed: compute() falls back
            # to bang-bang and reports it
            self._ctrl = None
            self._import_error = "scikit-fuzzy is not usable (%s)" % _one_line(e)

    def compute(self, sensor_value: float) -> str:
        error = (sensor_value - self.setpoint) / self._span
        rate  = (error - self._prev_error)      / self._span
        self._prev_error = error

        if self._ctrl is not None:
            try:
                self._ctrl.input['error'] = max(-1.0, min(1.0, error))
                self._ctrl.input['rate']  = max(-1.0, min(1.0, rate))
                self._ctrl.compute()
                output = self._ctrl.output['output']
                db = self.deadband_fraction
                if abs(output) <= db:
                    return "OFF"
                return "DOWN" if output > 0 else "UP"
            except Exception as e:
                # fall through to bang-bang, reported
                _note_fallback(self, "compute failed (%s: %s)" % (type(e).__name__, _one_line(e)))
        else:
            _note_fallback(self, self._import_error or "the fuzzy controller is not built")

        # Fallback: bang-bang
        if sensor_value > self.upper_limit:
            return "DOWN"
        if sensor_value < self.lower_limit:
            return "UP"
        return "OFF"

    def reset(self):
        self._prev_error = 0.0
