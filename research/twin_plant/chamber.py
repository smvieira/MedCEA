"""A lumped model of one MedCEA growth chamber (60 x 60 x 60 cm), standard library only.

State (the "truth" the sensors sample):
- air temperature T_a (C): one node holding the air, the walls and the fittings;
- substrate temperature T_s (C): the growing substrate, reported as ground_temperature;
- water vapour density rho_v (g/m3), from which relative humidity follows;
- CO2 concentration c (ppm by volume).

Balances (all explicit Euler, sub-stepped, see Chamber.step):

    C_a dT_a/dt = UA (T_amb - T_a)                       walls
                + G_vent (T_amb - T_a)                   air exchanged with the room
                + G_as (T_s - T_a)                       substrate <-> air
                + P_heater + P_fan + P_lamps + P_fungi + P_extra
                - COP * P_cooler                         heat pumped out by the cooler
                - L * m_evap                             latent heat of the humidifier's mist

    C_s dT_s/dt = G_as (T_a - T_s) + G_sa (T_amb - T_s) + P_substrate_heater

    d rho_v/dt  = (m_hum + m_fungi) / V + n (rho_amb - rho_v)        then 0 <= rho_v <= rho_sat(T_a)

    dc/dt       = q_co2 / V * 1e6 + n (c_amb - c)                     then c >= 0

where n is the total air exchange rate (1/s): the leak, plus the air_flow_fan's and the
co2_fan's exchange while they run, plus a door opening. G_vent = rho_air cp V n.

The air node's time constant with every fan off and the door shut is tau_air_s by
construction: UA = C_a / tau_air_s - G_vent(leak) - G_as(still). The substrate couples
weakly, so a heater step on the air still looks first-order (tests/test_research_plant.py).

What the air_flow_fan does (the relay is shared by three actuators on the board):
- it exchanges some room air through the chamber's vents (fan_air_exchange_per_h);
- it multiplies the air <-> substrate conductance by fan_mixing_factor (forced convection
  over the substrate surface);
- its electrical power ends up as heat in the air.

Every default below is an assumption to calibrate in Phase 3 against the chamber's
recorded data, unless its comment names a source.
"""
from __future__ import annotations

import dataclasses
import math
import random
from dataclasses import dataclass

# The board's relays this model knows (edge/templates/esp32-control.json, driver relay8;
# the three lamp colours of the light actuator). Any other name is refused.
RELAYS = (
    "air_heater", "air_cooler", "air_humidifier", "air_flow_fan",
    "co2_fan", "co2_steriliser", "substrate_heater",
    "light_red", "light_blue", "light_uv",
)

TRUTH_KEYS = ("air_temperature", "air_humidity", "co2", "ground_temperature")

AMBIENT_KEYS = ("temperature", "humidity", "co2")
DISTURBANCE_KEYS = ("door_open", "extra_heat_w")

RHO_AIR = 1.2            # kg/m3, dry air near 20 C (textbook value)
CP_AIR = 1005.0          # J/(kg K), dry air (textbook value)
LATENT_HEAT = 2450.0     # J/g, latent heat of vaporisation of water near 20 C (textbook value)
R_VAPOUR = 461.5         # J/(kg K), specific gas constant of water vapour (textbook value)

MAX_INTERNAL_DT = 1.0    # s, the Euler sub-step's upper bound (the interface promises <= 1 s)


def saturation_pressure_pa(t_c: float) -> float:
    """Saturation vapour pressure over water (Magnus form, Sonntag 1990 coefficients)."""
    return 611.2 * math.exp(17.62 * t_c / (243.12 + t_c))


def saturation_density(t_c: float) -> float:
    """Saturation water vapour density in g/m3 at t_c (ideal gas)."""
    return saturation_pressure_pa(t_c) / (R_VAPOUR * (t_c + 273.15)) * 1000.0


def vapour_density(t_c: float, rh: float) -> float:
    """Water vapour density in g/m3 for a temperature and a relative humidity in %."""
    return saturation_density(t_c) * max(0.0, min(100.0, rh)) / 100.0


def _check_number(what: str, v) -> None:
    """ValueError unless v is a finite int or float (a bool is refused): a NaN state would
    propagate silently through every balance."""
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        raise ValueError("%s must be a finite number, not %r" % (what, v))


@dataclass
class ChamberParams:
    """Every physical parameter of the chamber. Units in each comment.

    Defaults are assumptions to calibrate in Phase 3 unless the comment names a source.
    """
    # Geometry
    volume_m3: float = 0.216                 # m3, 60 x 60 x 60 cm chamber (hardware spec)

    # Room around the chamber (assumed lab conditions)
    ambient_temperature: float = 20.0        # C
    ambient_humidity: float = 50.0           # RH %
    ambient_co2: float = 420.0               # ppm, outdoor background (assumed for the room)

    # Air node
    tau_air_s: float = 146 * 60.0            # s, air temperature time constant, fans off, door shut (~146 min estimated from chamber data; to calibrate)
    air_heat_capacity_j_per_k: float = 60000.0  # J/K, air + walls + fittings lumped (assumption; sets the heater's steady rise with tau_air_s)

    # Actuator electrical powers (W). Assumptions: nameplates not yet recorded.
    heater_w: float = 100.0                  # air_heater
    cooler_w: float = 60.0                   # air_cooler, electrical input
    cooler_cop: float = 0.5                  # heat removed / electrical input (assumed Peltier-class cooler)
    humidifier_w: float = 15.0               # air_humidifier (ultrasonic mister; its own dissipation is not counted as heat, only the mist's latent cooling)
    humidifier_g_per_h: float = 10.0         # g/h water delivered as mist, all evaporated in the air (assumption)
    substrate_heater_w: float = 30.0         # substrate_heater (heating mat)
    air_flow_fan_w: float = 3.0              # air_flow_fan (small DC fan)
    co2_fan_w: float = 5.0                   # co2_fan (exhaust fan)
    co2_steriliser_w: float = 8.0            # co2_steriliser (UV lamp on the intake; no effect on the balances here)
    light_red_w: float = 10.0                # light_red
    light_blue_w: float = 10.0               # light_blue
    light_uv_w: float = 5.0                  # light_uv
    lamp_heat_fraction: float = 1.0          # share of lamp power ending up as heat in the air (assumption: all of it, the box is closed)

    # Air exchange with the room (1/h, air changes per hour)
    leak_ach_per_h: float = 0.5              # closed chamber, door shut (assumption)
    fan_air_exchange_per_h: float = 2.0      # added while air_flow_fan runs (assumption: vents let some room air through)
    co2_fan_ach_per_h: float = 30.0          # added while co2_fan runs (assumption: ~1.8 m3/h exhaust fan on 0.216 m3)
    door_open_ach_per_h: float = 60.0        # added while a door is open (assumption)

    # Substrate node
    substrate_heat_capacity_j_per_k: float = 6000.0  # J/K, ~2 kg of wet substrate at ~3000 J/(kg K) (assumption)
    substrate_air_w_per_k: float = 0.3      # W/K, substrate <-> air with still air (assumption; kept small so the air stays first-order)
    fan_mixing_factor: float = 4.0           # x, air_flow_fan multiplies substrate <-> air conductance (forced convection; assumption)
    substrate_ambient_w_per_k: float = 0.2   # W/K, substrate <-> room through the floor (assumption)

    # Fungal respiration (oyster / lion's mane on ~2 kg substrate)
    co2_production_ml_per_h: float = 110.0   # mL CO2/h at fungi_ref_temperature (assumption: ~100 mg CO2/(kg h) on 2 kg, from respiration figures for Pleurotus; to calibrate)
    fungi_water_g_per_h: float = 1.0         # g/h water given off at the reference temperature (assumption)
    fungi_heat_w: float = 0.5                # W metabolic heat at the reference temperature (assumption)
    fungi_ref_temperature: float = 20.0      # C, temperature at which the three rates above hold
    fungi_q10: float = 2.0                   # x per 10 C: rate(T) = rate_ref * q10 ** ((T - T_ref) / 10), T = substrate temperature (common Q10 for respiration; assumption)

    # Disturbances
    door_open_extra_heat_w: float = 0.0      # W added while the door is open (a person nearby; default none)

    @classmethod
    def from_dict(cls, d: dict | None) -> "ChamberParams":
        """Defaults overridden by d. Unknown keys and non-numeric values are refused."""
        d = dict(d or {})
        names = {f.name for f in dataclasses.fields(cls)}
        unknown = sorted(k for k in d if k not in names)
        if unknown:
            raise ValueError("unknown chamber parameter(s): " + ", ".join(unknown))
        out = {}
        for k, v in d.items():
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise ValueError("chamber parameter %s must be a number, not %r" % (k, v))
            if not math.isfinite(v):
                raise ValueError("chamber parameter %s must be finite" % k)
            out[k] = float(v)
        p = cls(**out)
        p.validate()
        return p

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    def validate(self) -> None:
        positive = ("volume_m3", "tau_air_s", "air_heat_capacity_j_per_k",
                    "substrate_heat_capacity_j_per_k", "fungi_q10")
        for k in positive:
            if getattr(self, k) <= 0:
                raise ValueError("chamber parameter %s must be > 0" % k)
        for f in dataclasses.fields(self):
            if f.name in ("ambient_temperature", "fungi_ref_temperature"):
                continue
            if getattr(self, f.name) < 0:
                raise ValueError("chamber parameter %s must be >= 0" % f.name)
        if not 0.0 <= self.ambient_humidity <= 100.0:
            raise ValueError("ambient_humidity must be within 0..100")
        if not 0.0 <= self.lamp_heat_fraction <= 1.0:
            raise ValueError("lamp_heat_fraction must be within 0..1")
        if self.wall_conductance_w_per_k() < 0:
            raise ValueError("tau_air_s is too long for the leak and the substrate coupling: "
                             "the walls would need a negative conductance")

    # Derived quantities
    def vent_conductance_w_per_k(self, ach_per_h: float) -> float:
        """Heat carried by exchanged air, W/K, for an exchange rate in air changes per hour."""
        return RHO_AIR * CP_AIR * self.volume_m3 * ach_per_h / 3600.0

    def wall_conductance_w_per_k(self) -> float:
        """UA of the walls so that the air's closed-chamber time constant is tau_air_s."""
        return (self.air_heat_capacity_j_per_k / self.tau_air_s
                - self.vent_conductance_w_per_k(self.leak_ach_per_h)
                - self.substrate_air_w_per_k)

    def relay_power_w(self) -> dict:
        return {
            "air_heater": self.heater_w,
            "air_cooler": self.cooler_w,
            "air_humidifier": self.humidifier_w,
            "air_flow_fan": self.air_flow_fan_w,
            "co2_fan": self.co2_fan_w,
            "co2_steriliser": self.co2_steriliser_w,
            "substrate_heater": self.substrate_heater_w,
            "light_red": self.light_red_w,
            "light_blue": self.light_blue_w,
            "light_uv": self.light_uv_w,
        }


class Chamber:
    """The chamber's truth, advanced by step().

    initial: optional {air_temperature, air_humidity, co2, ground_temperature}; missing keys
    start at the ambient values (ground_temperature at the room's temperature, not at the
    initial air temperature). seed: kept for reproducible extensions (process noise);
    the balances themselves are deterministic, and the module never uses the global random.
    """

    def __init__(self, params: ChamberParams, initial: dict | None = None, seed: int = 0):
        if not isinstance(params, ChamberParams):
            raise TypeError("params must be a ChamberParams")
        params.validate()
        self.params = params
        self.seed = seed
        self.rng = random.Random("chamber:%d" % seed)
        initial = dict(initial or {})
        unknown = sorted(k for k in initial if k not in TRUTH_KEYS)
        if unknown:
            raise ValueError("unknown initial state key(s): " + ", ".join(unknown))
        for k, v in initial.items():
            _check_number("initial %s" % k, v)
        p = params
        self.t_air = float(initial.get("air_temperature", p.ambient_temperature))
        self.t_sub = float(initial.get("ground_temperature", p.ambient_temperature))
        rh = float(initial.get("air_humidity", p.ambient_humidity))
        self.rho_v = vapour_density(self.t_air, rh)
        self.co2 = max(0.0, float(initial.get("co2", p.ambient_co2)))
        self.time_s = 0.0
        self.light_on = False
        self._energy_j = {r: 0.0 for r in RELAYS}
        self._power = p.relay_power_w()

    # Public interface
    def truth(self) -> dict:
        rh = 100.0 * self.rho_v / saturation_density(self.t_air)
        return {
            "air_temperature": self.t_air,
            "air_humidity": max(0.0, min(100.0, rh)),
            "co2": max(0.0, self.co2),
            "ground_temperature": self.t_sub,
        }

    def energy_wh(self) -> dict:
        """Electrical energy each relay has drawn since the start, Wh (power x on-time)."""
        return {r: j / 3600.0 for r, j in self._energy_j.items()}

    def step(self, dt_s: float, relays: dict, light_on: bool,
             ambient: dict | None = None, disturbances: dict | None = None) -> None:
        """Advance the truth by dt_s seconds with the relays held as given.

        relays: {relay: 0|1}; a relay not named is off. light_on: the photoperiod state the
        runner decided; recorded (self.light_on) but the lamps' heat and energy follow the
        light_* relays, which are what the board switches. ambient: optional overrides
        {temperature, humidity, co2} for this step. disturbances: optional
        {door_open: bool, extra_heat_w: W}.
        """
        if isinstance(dt_s, bool) or not isinstance(dt_s, (int, float)) or not math.isfinite(dt_s):
            raise ValueError("dt_s must be a finite number")
        if dt_s < 0:
            raise ValueError("dt_s must be >= 0")
        on = self._relay_state(relays)
        amb = self._ambient(ambient)
        dist = self._disturbances(disturbances)
        self.light_on = bool(light_on)
        if dt_s == 0:
            return

        p = self.params
        # Rates constant over the step
        ach = p.leak_ach_per_h
        if on["air_flow_fan"]:
            ach += p.fan_air_exchange_per_h
        if on["co2_fan"]:
            ach += p.co2_fan_ach_per_h
        if dist["door_open"]:
            ach += p.door_open_ach_per_h
        n = ach / 3600.0                                   # 1/s
        g_vent = p.vent_conductance_w_per_k(ach)
        ua = p.wall_conductance_w_per_k()
        g_as = p.substrate_air_w_per_k * (p.fan_mixing_factor if on["air_flow_fan"] else 1.0)
        g_sa = p.substrate_ambient_w_per_k
        ca = p.air_heat_capacity_j_per_k
        cs = p.substrate_heat_capacity_j_per_k

        lamps = sum(self._power[r] for r in ("light_red", "light_blue", "light_uv") if on[r])
        q_fixed = (self._power["air_heater"] * on["air_heater"]
                   + self._power["air_flow_fan"] * on["air_flow_fan"]
                   + p.lamp_heat_fraction * lamps
                   - p.cooler_cop * self._power["air_cooler"] * on["air_cooler"]
                   + dist["extra_heat_w"]
                   + (p.door_open_extra_heat_w if dist["door_open"] else 0.0))
        m_hum = p.humidifier_g_per_h / 3600.0 * on["air_humidifier"]   # g/s
        q_sub = self._power["substrate_heater"] * on["substrate_heater"]
        rho_amb = vapour_density(amb["temperature"], amb["humidity"])

        # Sub-step: never above 1 s, and small enough that every linear rate stays stable
        fastest = max(n, (ua + g_vent + g_as) / ca, (g_as + g_sa) / cs, 1e-12)
        h_max = min(MAX_INTERNAL_DT, 0.5 / fastest)
        steps = max(1, int(math.ceil(dt_s / h_max - 1e-9)))
        h = dt_s / steps
        co2_per_ml = 1.0 / p.volume_m3                    # ppm per mL of CO2: 1e-6 m3 / V m3 x 1e6

        for _ in range(steps):
            f = p.fungi_q10 ** ((self.t_sub - p.fungi_ref_temperature) / 10.0)
            q_air = (q_fixed
                     + ua * (amb["temperature"] - self.t_air)
                     + g_vent * (amb["temperature"] - self.t_air)
                     + g_as * (self.t_sub - self.t_air)
                     + p.fungi_heat_w * f
                     - LATENT_HEAT * m_hum)
            q_s = q_sub + g_as * (self.t_air - self.t_sub) + g_sa * (amb["temperature"] - self.t_sub)
            m_fungi = p.fungi_water_g_per_h / 3600.0 * f
            co2_src = p.co2_production_ml_per_h / 3600.0 * f * co2_per_ml   # ppm/s

            d_ta = q_air / ca
            d_ts = q_s / cs
            d_rho = (m_hum + m_fungi) / p.volume_m3 + n * (rho_amb - self.rho_v)
            d_c = co2_src + n * (amb["co2"] - self.co2)

            self.t_air += h * d_ta
            self.t_sub += h * d_ts
            # Vapour above saturation condenses on the walls and leaves the balance.
            self.rho_v = min(max(0.0, self.rho_v + h * d_rho), saturation_density(self.t_air))
            self.co2 = max(0.0, self.co2 + h * d_c)

        for r in RELAYS:
            if on[r]:
                self._energy_j[r] += self._power[r] * dt_s
        self.time_s += dt_s

    # Input checks
    @staticmethod
    def _relay_state(relays: dict | None) -> dict:
        relays = dict(relays or {})
        unknown = sorted(k for k in relays if k not in RELAYS)
        if unknown:
            raise ValueError("unknown relay(s): " + ", ".join(unknown))
        out = {}
        for r in RELAYS:
            v = relays.get(r, 0)
            if not isinstance(v, int) or v not in (0, 1):   # bool is an int: True/False pass
                raise ValueError("relay %s must be 0 or 1, not %r" % (r, v))
            out[r] = int(v)
        return out

    def _ambient(self, ambient: dict | None) -> dict:
        p = self.params
        out = {"temperature": p.ambient_temperature, "humidity": p.ambient_humidity,
               "co2": p.ambient_co2}
        ambient = dict(ambient or {})
        unknown = sorted(k for k in ambient if k not in AMBIENT_KEYS)
        if unknown:
            raise ValueError("unknown ambient key(s): " + ", ".join(unknown))
        for k, v in ambient.items():
            _check_number("ambient %s" % k, v)
            out[k] = float(v)
        out["humidity"] = max(0.0, min(100.0, out["humidity"]))
        out["co2"] = max(0.0, out["co2"])
        return out

    @staticmethod
    def _disturbances(dist: dict | None) -> dict:
        dist = dict(dist or {})
        unknown = sorted(k for k in dist if k not in DISTURBANCE_KEYS)
        if unknown:
            raise ValueError("unknown disturbance(s): " + ", ".join(unknown))
        door = dist.get("door_open", False)
        if not isinstance(door, bool):
            raise ValueError("disturbance door_open must be true or false, not %r" % (door,))
        heat = dist.get("extra_heat_w", 0.0)
        _check_number("disturbance extra_heat_w", heat)
        return {"door_open": door, "extra_heat_w": float(heat)}
