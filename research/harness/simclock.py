"""Simulated time for production's controllers.

pid.py reads the module-level `_time.monotonic()` for its dt and for its PWM phase
(`now % cycle_time`); q_learning.py draws from the module-level `_random`. A scenario
swaps both for the duration of the run and puts the originals back afterwards
(SimClock.uninstall, called from a finally in runner.run_scenario).

monotonic() = start_offset_s + t, where t is the scenario's simulated time in seconds.
start_offset_s is the arbitrary origin of the host's monotonic clock in production: with
the default PID cycle_time of 10 s and a 10-s tick, `now % cycle_time` is the same at
every tick, so whether PID's duty cycle ever fires depends on this offset (the aliasing
the campaigns sweep).

jitter_s: production's tick is `stop_event.wait(10)` plus the time one pass takes, so
the interval is 10 s plus a little. next_interval() returns base + U(0, jitter_s), drawn
from a Random seeded by the scenario seed (jitter 0 gives an exact 10-s tick).
"""
from __future__ import annotations

import random


class SimClock:
    def __init__(self, start_offset_s=0.0, jitter_s=0.0, seed=0):
        if jitter_s < 0:
            raise ValueError("jitter_s must be >= 0")
        self.start_offset_s = float(start_offset_s)
        self.jitter_s = float(jitter_s)
        self.seed = seed
        self.t = 0.0
        self._jitter_rng = random.Random("simclock:jitter:%s" % seed)
        # The Random q_learning draws from: its own stream, so the tick jitter never
        # shifts the exploration sequence.
        self.random = random.Random("simclock:q_learning:%s" % seed)
        self._saved = []          # (module, attribute, original)

    # time
    def monotonic(self):
        return self.start_offset_s + self.t

    def advance(self, dt):
        if dt < 0:
            raise ValueError("time cannot go backwards")
        self.t += dt

    def next_interval(self, base=10.0):
        if self.jitter_s == 0:
            return float(base)
        return float(base) + self._jitter_rng.uniform(0.0, self.jitter_s)

    # swapping the modules' clocks and random sources
    def _swap(self, module, attr, value):
        self._saved.append((module, attr, getattr(module, attr)))
        setattr(module, attr, value)

    def install(self, pid_module=None, q_module=None):
        """pid_module._time -> this clock; q_module._random -> self.random."""
        if pid_module is not None:
            self._swap(pid_module, "_time", self)
        if q_module is not None:
            self._swap(q_module, "_random", self.random)
        return self

    def uninstall(self):
        """Put every swapped attribute back, last swapped first."""
        while self._saved:
            module, attr, original = self._saved.pop()
            setattr(module, attr, original)
