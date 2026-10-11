import time as _time
from .base import ControlAlgorithm


class MPCAlgorithm(ControlAlgorithm):
    """
    Model Predictive Control (receding-horizon).

    Uses GEKKO (pip install gekko) with remote=False (bundles IPOPT solver locally).
    Assumes a first-order discrete linear model per channel:
        x[k+1] = a*x[k] + b*u[k]
    where x is the normalised state (sensor/setpoint) and u ∈ {-1, 0, +1}.

    Tuning parameters:
        horizon       (int,   default 6)   - prediction/control horizon in steps.
                                             Each step is ~10 s, so horizon=6 → 60 s ahead.
        switching_cost (float, default 0.1) - penalty weight on actuator switching to
                                             discourage rapid UP/DOWN oscillation.

    Falls back to BANG_BANG behaviour if GEKKO is not installed or the solver fails.
    """

    def __init__(self, lower_limit: float, upper_limit: float,
                 horizon: int = 6, switching_cost: float = 0.1, **kwargs):
        super().__init__(lower_limit, upper_limit)
        self.horizon        = max(1, int(horizon))
        self.switching_cost = float(switching_cost)
        self._span          = max(upper_limit - lower_limit, 1e-9)
        self._prev_u        = 0.0   # last control action (-1/0/+1) for switching cost
        self._gekko         = None
        self._build_model()

    # ------------------------------------------------------------------
    def _build_model(self):
        try:
            from gekko import GEKKO
            m = GEKKO(remote=False)
            m.options.IMODE   = 6   # MPC mode
            m.options.NODES   = 2
            m.options.SOLVER  = 1   # APOPT
            m.options.CV_TYPE = 2   # l2 objective

            N = self.horizon

            # First-order model: x[k+1] = a*x[k] + b*u[k]
            # Conservative guesses — will be reasonable for slow thermal/humidity systems.
            a = m.Const(0.95)
            b = m.Const(0.05)

            x = m.CV(value=0.0, lb=-2.0, ub=2.0)   # normalised state
            u = m.MV(value=0.0,  lb=-1.0, ub=1.0)   # continuous relaxation of {-1,0,+1}
            u.STATUS = 1
            u.DCOST  = self.switching_cost           # penalise changes in u

            x.STATUS = 1
            x.SP     = 0.0   # track normalised setpoint (= 0 means error = 0)
            x.SPHI   = 0.05
            x.SPLO   = -0.05

            m.Equation(x.dt() == (a * x - x + b * u) / 1.0)

            m.time = list(range(N + 1))

            self._m = m
            self._x = x
            self._u = u
            self._gekko = True

        except ImportError:
            self._gekko = None

    # ------------------------------------------------------------------
    def compute(self, sensor_value: float) -> str:
        error_norm = (sensor_value - self.setpoint) / self._span

        if self._gekko:
            try:
                self._x.value = error_norm
                self._m.solve(disp=False)
                u_opt = float(self._u.NEWVAL)

                db = 0.05
                if abs(u_opt) <= db:
                    command = "OFF"
                elif u_opt < -db:
                    command = "UP"
                else:
                    command = "DOWN"

                self._prev_u = u_opt
                return command

            except Exception:
                pass   # fall through to bang-bang

        # Fallback: bang-bang
        if sensor_value > self.upper_limit:
            return "DOWN"
        if sensor_value < self.lower_limit:
            return "UP"
        return "OFF"

    def reset(self):
        self._prev_u = 0.0
        self._build_model()
