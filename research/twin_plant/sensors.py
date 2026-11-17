"""Sensor models for the chamber: what a SENSE board would publish, standard library only.

A SensorSpec says which tags one sensor publishes, how noisy and how finely quantised each
value is, how often it publishes, how late the message arrives and how often one is lost.
A SensorBank turns the chamber's truth into those messages, reproducibly from a seed.

Noise: a datasheet "accuracy" of +-a is taken as 2 standard deviations (sd = a / 2) of
independent Gaussian noise per message. That is an assumption: real sensors also carry a
slow bias, which `bias` (a constant offset per tag) can add; default none.

Quantisation: the board rounds every published value to 2 decimals
(edge/src/app/cea_sense.py, round(v, 2)); a sensor's own resolution can be coarser
(DS18B20, 12-bit: 0.0625 C). The coarser of the two is applied, then the 2-decimal rounding.

Timing: sensor k publishes at start_offset_s + j * publish_interval_s (j = 0, 1, ...); the
default 30 s is the SENSE board's DEFAULT message interval. Each message (one per tag, as
the firmware publishes one MQTT message per tag) arrives latency_s later, or is dropped with
probability dropout_p.
"""
from __future__ import annotations

import hashlib
import math
import random
from dataclasses import dataclass, field

KINDS = ("sht45", "scd30", "sen0562", "ds18b20")

BOARD_DECIMALS = 2       # cea_sense.py publishes round(v, 2)

# What each tag may physically read; a noisy value outside is clipped as the sensor would.
_CLIP = {
    "air_humidity": (0.0, 100.0),
    "co2": (0.0, None),
    "light_intensity": (0.0, None),
}


@dataclass
class SensorSpec:
    sensor_id: str                       # the wiring id the board publishes as <topic>/<tag>/<sensor_id>
    kind: str                            # sht45 | scd30 | sen0562 | ds18b20
    tags: tuple                          # tags it publishes, e.g. ("air_temperature", "air_humidity")
    noise_sd: dict = field(default_factory=dict)       # tag -> absolute sd, in the tag's unit
    noise_rel_sd: dict = field(default_factory=dict)   # tag -> sd as a fraction of the true value
    quantisation: dict = field(default_factory=dict)   # tag -> resolution step, in the tag's unit (0 = none)
    bias: dict = field(default_factory=dict)           # tag -> constant offset, in the tag's unit
    publish_interval_s: float = 30.0     # s, SENSE board DEFAULT message interval
    latency_s: float = 0.0               # s, publish -> arrival at the runner
    dropout_p: float = 0.0               # probability a message is lost
    start_offset_s: float = 0.0          # s, time of the first publish

    def validate(self) -> None:
        if not self.sensor_id or not isinstance(self.sensor_id, str):
            raise ValueError("sensor_id must be a non-empty string")
        if self.sensor_id == "default":
            raise ValueError("sensor_id 'default' is reserved (an old board's sensor)")
        if self.kind not in KINDS:
            raise ValueError("sensor %s: unknown kind %r" % (self.sensor_id, self.kind))
        if not self.tags:
            raise ValueError("sensor %s publishes no tag" % self.sensor_id)
        for name in ("noise_sd", "noise_rel_sd", "quantisation", "bias"):
            extra = sorted(set(getattr(self, name)) - set(self.tags))
            if extra:
                raise ValueError("sensor %s: %s names tags it does not publish: %s"
                                 % (self.sensor_id, name, ", ".join(extra)))
            for tag, v in getattr(self, name).items():
                if name != "bias" and v < 0:
                    raise ValueError("sensor %s: %s[%s] must be >= 0" % (self.sensor_id, name, tag))
        if self.publish_interval_s <= 0:
            raise ValueError("sensor %s: publish_interval_s must be > 0" % self.sensor_id)
        if self.latency_s < 0 or self.start_offset_s < 0:
            raise ValueError("sensor %s: latency_s and start_offset_s must be >= 0" % self.sensor_id)
        if not 0.0 <= self.dropout_p <= 1.0:
            raise ValueError("sensor %s: dropout_p must be within 0..1" % self.sensor_id)


def default_specs() -> list:
    """The sensors of one SENSE board as the bench template wires them (SHT45, SCD30) plus a
    DS18B20 for the substrate. Start offsets are staggered (assumption: boards do not align)."""
    return [
        SensorSpec(
            sensor_id="sht45", kind="sht45",
            tags=("air_temperature", "air_humidity"),
            noise_sd={"air_temperature": 0.05,      # SHT45 datasheet: +-0.1 C typical, as 2 sd
                      "air_humidity": 0.5},          # SHT45 datasheet: +-1 %RH typical, as 2 sd
            quantisation={"air_temperature": 0.01, "air_humidity": 0.01},
            start_offset_s=0.0,
        ),
        SensorSpec(
            sensor_id="scd30", kind="scd30",
            tags=("co2", "air_temperature", "air_humidity"),
            noise_sd={"co2": 15.0,                   # SCD30 datasheet: +-(30 ppm + 3 %), as 2 sd
                      "air_temperature": 0.2,        # SCD30 datasheet: +-(0.4 C + 0.023 x (T - 25 C)), constant part as 2 sd
                      "air_humidity": 1.5},          # SCD30 datasheet: +-3 %RH, as 2 sd
            noise_rel_sd={"co2": 0.015},             # the 3 % part of the SCD30's CO2 accuracy, as 2 sd
            quantisation={"co2": 0.01, "air_temperature": 0.01, "air_humidity": 0.01},
            start_offset_s=3.0,
        ),
        SensorSpec(
            sensor_id="ds18b20", kind="ds18b20",
            tags=("ground_temperature",),
            noise_sd={"ground_temperature": 0.25},  # DS18B20 datasheet: +-0.5 C (-10..85 C), as 2 sd
            quantisation={"ground_temperature": 0.0625},  # DS18B20 12-bit resolution
            start_offset_s=7.0,
        ),
    ]


def _quantise(value: float, step: float) -> float:
    if step and step > 0:
        value = round(value / step) * step
    return round(value, BOARD_DECIMALS)


def _clip(tag: str, value: float) -> float:
    lo, hi = _CLIP.get(tag, (None, None))
    if lo is not None and value < lo:
        value = lo
    if hi is not None and value > hi:
        value = hi
    return value


class SensorBank:
    """Every sensor of a chamber. Each sensor draws from its own random.Random, seeded from
    (seed, sensor_id), so adding or removing a sensor never changes another's readings."""

    def __init__(self, specs: list, seed: int = 0):
        ids = set()
        for s in specs:
            s.validate()
            if s.sensor_id in ids:
                raise ValueError("sensor_id %s listed twice" % s.sensor_id)
            ids.add(s.sensor_id)
        self.specs = list(specs)
        self.seed = seed
        self._rng = {}
        self._next_k = {}
        for s in self.specs:
            digest = hashlib.sha256(("sensorbank:%d:%s" % (seed, s.sensor_id)).encode()).hexdigest()
            self._rng[s.sensor_id] = random.Random(int(digest[:16], 16))
            self._next_k[s.sensor_id] = 0
        self.last_t = None

    def readings_due(self, t: float, truth: dict) -> list:
        """Messages published in (last_t, t] (the first call: [0, t]), each as
        (tag, sensor_id, value, arrival_t), sorted by arrival_t then sensor and tag.

        Every message in the window samples `truth` as given: call at least once per
        publish interval (the harness calls every 10-s tick). A tag absent from truth is
        not published. A dropped message is not returned, but its random draws are made,
        so the noise of later messages does not depend on dropout_p.
        """
        if not isinstance(t, (int, float)) or isinstance(t, bool) or not math.isfinite(t):
            raise ValueError("t must be a finite number")
        if self.last_t is not None and t < self.last_t:
            raise ValueError("readings_due: time went backwards (%s < %s)" % (t, self.last_t))
        out = []
        for s in self.specs:
            rng = self._rng[s.sensor_id]
            while True:
                k = self._next_k[s.sensor_id]
                pub_t = s.start_offset_s + k * s.publish_interval_s
                if pub_t > t:
                    break
                self._next_k[s.sensor_id] = k + 1
                for tag in s.tags:
                    lost = rng.random() < s.dropout_p
                    z = rng.gauss(0.0, 1.0)
                    if tag not in truth:
                        continue
                    true_v = float(truth[tag])
                    sd = s.noise_sd.get(tag, 0.0) + s.noise_rel_sd.get(tag, 0.0) * abs(true_v)
                    v = true_v + s.bias.get(tag, 0.0) + sd * z
                    v = _quantise(_clip(tag, v), s.quantisation.get(tag, 0.0))
                    if lost:
                        continue
                    out.append((tag, s.sensor_id, v, pub_t + s.latency_s))
        self.last_t = t
        out.sort(key=lambda m: (m[3], m[1], m[0]))
        return out
