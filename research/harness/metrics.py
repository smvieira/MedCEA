"""Metrics of one simulated run (METRICS_VERSION 1). A change to any formula bumps the version,
because campaigns compare results only within one version.

The runner samples the chamber's true state (never a sensor reading) once per control
tick, before the tick's decision; every metric below is computed from those samples,
from the ticks at or after `metrics_from_s` (a scenario's settling time, default 0).
Every sample has the same weight; with the 10-s tick (plus jitter) that is close to a
time average.

Per loop (a quantity with a setpoint on the recipe line), with lower L, upper U, band
width W = U - L, midpoint M = (L + U) / 2 and true values x_i, i = 1..N:

- rmsd_mid = sqrt( (1/N) * sum_i (x_i - M)^2 ), in the quantity's unit.
- out_of_band = (1/N) * #{ i : x_i < L or x_i > U }, a fraction of the samples.
- boundary_hugging = #{ i : L <= x_i <= U and min(x_i - L, U - x_i) <= 0.1 W } / #{ i : L <= x_i <= U },
  the share of the in-band samples that lie within 10 % of the band width from an edge
  (None when no sample is in band). A controller that parks the value just inside one edge
  scores high, one that holds it near the middle scores low.
- command_changes = the number of ticks whose published command for the loop differs
  from the loop's previous published command (holds and repeats are not changes).
- mean_abs_error = (1/N) * sum_i max(L - x_i, 0, x_i - U), how far outside the band, on average.

Per relay (the board's channels, after every command of a tick was applied in
publishing order, so the shared air_flow_fan counts once per tick):

- switches = the number of ticks at which the relay's state differs from its state at
  the previous tick (end-of-tick states; an on-off-on inside one tick is not seen).
- energy_wh = the chamber's own count: electrical power x on-time, over the whole run
  (not only after metrics_from_s, because energy is spent while settling too), from
  twin_plant.chamber.Chamber.energy_wh(). total_wh is their sum.
"""
from __future__ import annotations

import math

METRICS_VERSION = 1
HUG_FRACTION = 0.1


class LoopSeries:
    """The samples of one loop."""

    def __init__(self):
        self.n = 0
        self.sq = 0.0
        self.out = 0
        self.in_band = 0
        self.hug = 0
        self.abs_out = 0.0
        self.changes = 0
        self._last = None

    def sample(self, x, lower, upper):
        mid = (lower + upper) / 2.0
        width = upper - lower
        self.n += 1
        self.sq += (x - mid) ** 2
        if x < lower or x > upper:
            self.out += 1
            self.abs_out += max(lower - x, x - upper)
        else:
            self.in_band += 1
            if min(x - lower, upper - x) <= HUG_FRACTION * width:
                self.hug += 1

    def command(self, cmd):
        """A published command (the loop's own message, after command_map)."""
        if cmd is None:
            return
        if self._last is not None and cmd != self._last:
            self.changes += 1
        self._last = cmd

    def result(self):
        if self.n == 0:
            return {"samples": 0, "rmsd_mid": None, "out_of_band": None, "boundary_hugging": None,
                    "mean_abs_error": None, "command_changes": self.changes}
        return {
            "samples": self.n,
            "rmsd_mid": math.sqrt(self.sq / self.n),
            "out_of_band": self.out / self.n,
            "boundary_hugging": (self.hug / self.in_band) if self.in_band else None,
            "mean_abs_error": self.abs_out / self.n,
            "command_changes": self.changes,
        }


class RelaySeries:
    def __init__(self, relays):
        self.switches = {r: 0 for r in relays}
        self._last = None

    def sample(self, state):
        if self._last is not None:
            for r in self.switches:
                if state.get(r, 0) != self._last.get(r, 0):
                    self.switches[r] += 1
        self._last = dict(state)


def energy(energy_wh):
    per = {r: energy_wh[r] for r in sorted(energy_wh)}
    return {"per_relay_wh": per, "total_wh": sum(per.values())}
