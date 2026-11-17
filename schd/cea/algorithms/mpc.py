import sys as _sys
import time as _time
from .base import ControlAlgorithm

# Fallback reporting (research sandbox Phase 1, owner decision of 17 Nov 2026): MPC used
# to fall back to bang-bang silently, so a run could not tell which controller it ran.
# FALLBACK_TOTAL counts every fallback of every instance in this process; each instance
# also keeps fallback_count and last_fallback (the reason) for the harness to read.
# One stderr line the first time an instance falls back, then one every REPORT_EVERY
# fallbacks (360 x the 10-s tick = one line an hour), never one per tick.
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
        print("WARNING mpc fallback: %s; bang-bang used (fallback %d of this controller,"
              " reported every %d)" % (reason, algo.fallback_count, REPORT_EVERY),
              file=_sys.stderr, flush=True)


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

    Falls back to BANG_BANG behaviour if GEKKO is not installed or the solver fails,
    and reports it (fallback_count, last_fallback, a rate-limited stderr WARNING).
    """

    def __init__(self, lower_limit: float, upper_limit: float,
                 horizon: int = 6, switching_cost: float = 0.1, **kwargs):
        super().__init__(lower_limit, upper_limit)
        self.horizon        = max(1, int(horizon))
        self.switching_cost = float(switching_cost)
        self._span          = max(upper_limit - lower_limit, 1e-9)
        self._prev_u        = 0.0   # last control action (-1/0/+1) for switching cost
        self._gekko         = None
        self._m             = None  # the GEKKO model; it owns a temp directory (close())
        self._import_error  = None  # why GEKKO could not be imported, for the fallback line
        self.fallback_count = 0     # compute() calls answered by the bang-bang fallback
        self.last_fallback  = None  # the reason of the latest fallback
        self._build_model()

    # ------------------------------------------------------------------
    def _build_model(self):
        self._cleanup_model()
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

        except ImportError as e:
            self._gekko = None
            self._import_error = "gekko is not installed (%s)" % _one_line(e)

    # ------------------------------------------------------------------
    def compute(self, sensor_value: float) -> str:
        error_norm = (sensor_value - self.setpoint) / self._span

        if self._gekko:
            try:
                self._x.value = error_norm
                self._m.solve(disp=False)
                u_opt = float(self._u.NEWVAL)

                # The model is x' = (a-1)*x + b*u with b > 0 and
                # x = (sensor - setpoint) / span, so u > 0 raises the reading: UP.
                # (Until 17 Nov 2026 this mapping was inverted: below the band MPC
                # answered DOWN and above it UP. Production never ran it, because
                # the scheduler pod lacked gekko and fell back to bang-bang.)
                db = 0.05
                if abs(u_opt) <= db:
                    command = "OFF"
                elif u_opt > db:
                    command = "UP"
                else:
                    command = "DOWN"

                self._prev_u = u_opt
                return command

            except Exception as e:
                # fall through to bang-bang, reported
                _note_fallback(self, "solver failed (%s: %s)" % (type(e).__name__, _one_line(e)))
        else:
            _note_fallback(self, self._import_error or "the GEKKO model is not built")

        # Fallback: bang-bang
        if sensor_value > self.upper_limit:
            return "DOWN"
        if sensor_value < self.lower_limit:
            return "UP"
        return "OFF"

    def reset(self):
        self._prev_u = 0.0
        self._build_model()

    # ------------------------------------------------------------------
    # GEKKO(remote=False) creates a directory with tempfile.mkdtemp for every model and
    # gekko removes it only in m.cleanup(); it has no __del__. Without these calls each
    # instance (one per loop per recipe cycle) left a directory in /tmp for the life of
    # the process.
    def _cleanup_model(self):
        m, self._m = getattr(self, "_m", None), None
        self._gekko = None
        if m is None:
            return
        try:
            m.cleanup()
        except Exception:
            pass   # a directory already gone is no reason to fail a control cycle

    def close(self):
        """Remove the GEKKO model's temp directory. Idempotent; compute() then answers
        through the bang-bang fallback."""
        self._cleanup_model()

    def __del__(self):
        try:
            self._cleanup_model()
        except Exception:
            pass
