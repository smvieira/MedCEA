from abc import ABC, abstractmethod


class ControlAlgorithm(ABC):
    """
    Abstract base class for all feedback control algorithms.

    One instance is created per sensor channel per recipe cycle run.
    State (PID integral, Q-table) lives in instance attributes and is
    discarded when the cycle ends, unless persisted externally.

    The command vocabulary is: "UP", "DOWN", "OFF", "ON".
    - UP:   increase the controlled variable (heat, humidify, generate CO2)
    - DOWN: decrease the controlled variable (cool, dehumidify, scrub CO2)
    - OFF:  within acceptable range, turn actuator off
    - ON:   used by time-based channels such as light
    """

    def __init__(self, lower_limit: float, upper_limit: float, **kwargs):
        self.lower_limit = float(lower_limit)
        self.upper_limit = float(upper_limit)
        self.setpoint    = (self.lower_limit + self.upper_limit) / 2.0

    @abstractmethod
    def compute(self, sensor_value: float) -> str:
        """
        Given the current sensor reading, return a control command.

        Parameters
        ----------
        sensor_value : float
            Current sensor measurement.

        Returns
        -------
        str
            One of "UP", "DOWN", "OFF".
        """
        ...

    def reset(self):
        """Reset internal state. Override in stateful algorithms."""
        pass

    def get_state(self) -> dict:
        """Return serialisable state dict for persistence. Override in stateful algorithms."""
        return {}

    def load_state(self, state: dict):
        """Restore state from a previously saved dict. Override in stateful algorithms."""
        pass
