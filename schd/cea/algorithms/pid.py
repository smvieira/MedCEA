import time as _time
from .base import ControlAlgorithm


class PIDAlgorithm(ControlAlgorithm):
    """
    Proportional-integral-derivative controller with time-proportioning (PWM) output.

    The PID output is normalised to a [-1, 1] duty cycle and mapped onto a
    repeating cycle_time window.  Within each window the actuator is commanded
    UP or DOWN for (|output| × cycle_time) seconds, then OFF for the remainder,
    giving true power throttling rather than simple bang-bang switching.

    Tuning parameters (set via control_algorithm_params):
        kp          (float, default 0.2)  - proportional gain
        ki          (float, default 0.05) - integral gain
        kd          (float, default 0.01) - derivative gain
        cycle_time  (float, default 10.0) - PWM window length in seconds

    Sign convention: error = sensor - setpoint.
    Positive error (above setpoint) → positive output → DOWN.
    Negative error (below setpoint) → negative output → UP.
    A 2% deadband around the setpoint span returns OFF and lets the I-term settle.
    Integral is anti-windup clamped to ±100.
    """

    def __init__(self, lower_limit: float, upper_limit: float,
                 kp: float = 0.2, ki: float = 0.05, kd: float = 0.01,
                 cycle_time: float = 10.0, **kwargs):
        super().__init__(lower_limit, upper_limit)
        self.kp         = float(kp)
        self.ki         = float(ki)
        self.kd         = float(kd)
        self.cycle_time = float(cycle_time)
        self._integral   = 0.0
        self._prev_error = None   # None = first call; avoids derivative kick
        self._prev_time  = None

    def compute(self, sensor_value: float) -> str:
        now   = _time.monotonic()
        error = sensor_value - self.setpoint

        # First call: seed state and return OFF to avoid a derivative spike.
        if self._prev_time is None:
            self._prev_error = error
            self._prev_time  = now
            return "OFF"

        dt = max(now - self._prev_time, 0.001)

        self._integral  = max(-100.0, min(100.0, self._integral + error * dt))
        derivative      = (error - self._prev_error) / dt
        output          = self.kp * error + self.ki * self._integral + self.kd * derivative
        output          = max(-1.0, min(1.0, output))   # normalise to duty-cycle range

        self._prev_error = error
        self._prev_time  = now

        deadband = (self.upper_limit - self.lower_limit) * 0.02
        if abs(error) <= deadband:
            return "OFF"

        # Time-proportioning (PWM): fire for duty_cycle_sec out of every cycle_time.
        elapsed_in_cycle = now % self.cycle_time
        duty_cycle_sec   = abs(output) * self.cycle_time
        if elapsed_in_cycle < duty_cycle_sec:
            return "DOWN" if output > 0 else "UP"
        return "OFF"

    def reset(self):
        self._integral   = 0.0
        self._prev_error = None
        self._prev_time  = None

    # ------------------------------------------------------------------
    def get_state(self) -> dict:
        """Serialise integral for DB persistence across cycle runs."""
        return {"integral": self._integral}

    def load_state(self, state: dict):
        """Restore integral from a previously saved dict.

        _prev_error and _prev_time are intentionally left as None so the
        first compute() call after restore still skips the derivative term
        rather than computing a spurious spike from stale timestamps.
        """
        if state:
            self._integral = float(state.get("integral", 0.0))
