import random as _random
import json as _json
from .base import ControlAlgorithm


class QLearningAlgorithm(ControlAlgorithm):
    """
    ε-greedy Q-learning reinforcement control.

    Learns the grow-chamber's thermal/humidity dynamics from experience.
    No plant model is required — the agent discovers the optimal policy by
    observing which actions reduce the tracking error over time.

    The Q-table is persisted between cycle runs (via get_state / load_state)
    so the agent continues learning across grow cycles rather than cold-starting.

    State discretisation: 7 buckets spanning [-3·span, +3·span] around setpoint.
    Actions: UP (-1), OFF (0), DOWN (+1) → mapped to command strings.

    Tuning parameters:
        alpha         (float, default 0.1)   - learning rate.
        gamma         (float, default 0.95)  - discount factor.
        epsilon       (float, default 0.2)   - initial exploration rate.
        epsilon_decay (float, default 0.995) - multiplicative decay per step.
    """

    _ACTIONS     = [-1, 0, 1]           # UP, OFF, DOWN
    _CMD         = {-1: "UP", 0: "OFF", 1: "DOWN"}
    _N_BUCKETS   = 7
    _EPSILON_MIN = 0.01

    def __init__(self, lower_limit: float, upper_limit: float,
                 alpha: float = 0.1, gamma: float = 0.95,
                 epsilon: float = 0.2, epsilon_decay: float = 0.995, **kwargs):
        super().__init__(lower_limit, upper_limit)
        self.alpha         = float(alpha)
        self.gamma         = float(gamma)
        self.epsilon       = float(epsilon)
        self.epsilon_decay = float(epsilon_decay)
        self._span         = max(upper_limit - lower_limit, 1e-9)

        # Q-table: {state_bucket: {action: q_value}}
        self._q: dict[int, dict[int, float]] = {
            s: {a: 0.0 for a in self._ACTIONS}
            for s in range(self._N_BUCKETS)
        }
        self._prev_state  = None
        self._prev_action = None

    # ------------------------------------------------------------------
    def _discretise(self, sensor_value: float) -> int:
        """Map sensor reading to a state bucket index [0, N_BUCKETS-1]."""
        half_span = self._span * 1.5                    # ±1.5 spans = 3-span window
        error     = sensor_value - self.setpoint
        frac      = (error + half_span) / (2 * half_span)   # [0, 1]
        bucket    = int(frac * self._N_BUCKETS)
        return max(0, min(self._N_BUCKETS - 1, bucket))

    def _reward(self, sensor_value: float) -> float:
        """Sparse reward: +1 within dead-band, −|error_norm| outside."""
        error_norm = abs(sensor_value - self.setpoint) / self._span
        deadband   = 0.1
        if error_norm <= deadband:
            return 1.0
        return -error_norm

    def compute(self, sensor_value: float) -> str:
        state = self._discretise(sensor_value)

        # --- Update Q-table from the previous transition ---
        if self._prev_state is not None:
            reward    = self._reward(sensor_value)
            best_next = max(self._q[state].values())
            old_q     = self._q[self._prev_state][self._prev_action]
            self._q[self._prev_state][self._prev_action] = (
                old_q + self.alpha * (reward + self.gamma * best_next - old_q)
            )

        # --- ε-greedy action selection ---
        if _random.random() < self.epsilon:
            action = _random.choice(self._ACTIONS)
        else:
            action = max(self._q[state], key=self._q[state].__getitem__)

        self.epsilon = max(self._EPSILON_MIN, self.epsilon * self.epsilon_decay)

        self._prev_state  = state
        self._prev_action = action
        return self._CMD[action]

    def reset(self):
        self._prev_state  = None
        self._prev_action = None

    # ------------------------------------------------------------------
    def get_state(self) -> dict:
        """Serialise Q-table + current epsilon for DB persistence."""
        return {
            "q_table": {
                str(s): {str(a): v for a, v in actions.items()}
                for s, actions in self._q.items()
            },
            "epsilon": self.epsilon,
        }

    def load_state(self, state: dict):
        """Restore Q-table + epsilon from a previously saved dict."""
        if not state:
            return
        raw_q = state.get("q_table", {})
        for s_str, actions in raw_q.items():
            s = int(s_str)
            if s in self._q:
                for a_str, v in actions.items():
                    a = int(a_str)
                    if a in self._q[s]:
                        self._q[s][a] = float(v)
        if "epsilon" in state:
            self.epsilon = float(state["epsilon"])
