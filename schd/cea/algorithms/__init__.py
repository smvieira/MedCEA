"""
cea.algorithms — pluggable feedback control strategy package.

Usage
-----
    from cea.algorithms import get_algorithm

    algo = get_algorithm('FLC', lower_limit=18.0, upper_limit=22.0,
                         deadband_fraction=0.08)
    command = algo.compute(sensor_value)   # → "UP" / "DOWN" / "OFF"
"""

from .base       import ControlAlgorithm
from .bang_bang  import BangBangAlgorithm
from .pid        import PIDAlgorithm
from .flc        import FLCAlgorithm
from .mpc        import MPCAlgorithm
from .q_learning import QLearningAlgorithm

__all__ = [
    "ControlAlgorithm",
    "BangBangAlgorithm",
    "PIDAlgorithm",
    "FLCAlgorithm",
    "MPCAlgorithm",
    "QLearningAlgorithm",
    "get_algorithm",
    "ALGORITHM_NAMES",
]

ALGORITHM_NAMES: dict[str, type] = {
    "IF_THEN_ELSE": BangBangAlgorithm,
    "PID":        PIDAlgorithm,
    "FLC":        FLCAlgorithm,
    "MPC":        MPCAlgorithm,
    "Q_LEARNING": QLearningAlgorithm,
}


def get_algorithm(code: str, lower_limit: float, upper_limit: float,
                  **params) -> ControlAlgorithm:
    """
    Factory: return an instantiated ControlAlgorithm for *code*.

    Unknown codes fall back silently to BangBangAlgorithm so existing
    deployments without a configured algorithm keep working.

    Parameters
    ----------
    code        : str   — algorithm code, e.g. 'FLC'
    lower_limit : float — sensor lower bound
    upper_limit : float — sensor upper bound
    **params    : algorithm-specific tuning parameters
    """
    cls = ALGORITHM_NAMES.get((code or "").upper(), BangBangAlgorithm)
    return cls(lower_limit=lower_limit, upper_limit=upper_limit, **params)
