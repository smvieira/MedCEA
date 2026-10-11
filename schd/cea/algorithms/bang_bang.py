from .base import ControlAlgorithm


class BangBangAlgorithm(ControlAlgorithm):
    """
    Bang-bang (on/off hysteresis) control.

    Exact replication of the original if/elif logic.
    No tuning parameters. No state.
    """

    def compute(self, sensor_value: float) -> str:
        if sensor_value > self.upper_limit:
            return "DOWN"
        if sensor_value < self.lower_limit:
            return "UP"
        return "OFF"
