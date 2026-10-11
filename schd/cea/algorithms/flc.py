from .base import ControlAlgorithm


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

    Falls back to BANG_BANG behaviour if scikit-fuzzy is not installed.
    """

    def __init__(self, lower_limit: float, upper_limit: float,
                 deadband_fraction: float = 0.1, **kwargs):
        super().__init__(lower_limit, upper_limit)
        self.deadband_fraction = float(deadband_fraction)
        self._span       = max(upper_limit - lower_limit, 1e-9)
        self._prev_error = 0.0
        self._ctrl       = None  # lazy-initialised fuzzy controller
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

        except ImportError:
            # scikit-fuzzy not installed — fall back silently
            self._ctrl = None

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
            except Exception:
                pass  # fall through to bang-bang

        # Fallback: bang-bang
        if sensor_value > self.upper_limit:
            return "DOWN"
        if sensor_value < self.lower_limit:
            return "UP"
        return "OFF"

    def reset(self):
        self._prev_error = 0.0
