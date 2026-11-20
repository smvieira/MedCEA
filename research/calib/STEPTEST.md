# Step-test protocol for the chamber model's plant constants

Status: designed, not run (research Phase 3, 20 Nov 2026). The platform
manual's section `research-steptest` is the same protocol for the people who
run it.

Every plant constant of `research/twin_plant/chamber.py` but the volume is an
assumption. `python3 -m research.calib fit-plant` refuses them (exit 3) because
no snapshot so far shows an actuator switching: lake contract 1 exports AP
readings only (no SP report, no command), the chamber has never had a CONTROL
board, and the room is not measured. The codes it prints are
`NO_ACTUATOR_DATA`, `NO_EXCITATION`, `NO_AMBIENT`, plus `NOT_OBSERVED` (the
substrate: no DS18B20), `CONDITIONAL_REFUSED` and `LITERATURE`.

This protocol produces the data that lifts those refusals once a CONTROL board
is fitted to the chamber.

## Preconditions

- The unit is idle: no run in R or S.
- The unit is in test mode (commissioning), proposed by an engineer and
  approved by qa through the Configuration UI (the existing flow).
- The door is closed for the whole series.
- A dummy substrate, or none, for the first series.
- A room sensor: a second SENSE board outside the chamber, in its own unit/zone
  slot. The slot's name is an owner decision.
- NTP checked on both boards (the fitted latency includes the board clock's
  offset; see the calibration file's `latency_s`, source `fitted_confounded`).
- A step log: the UTC time of every switch, written by hand, until the export
  carries the actuator events (below).

## Series

Each series is repeated twice, with at least 2 τ of rest between steps
(τ ≈ 2.4 h, so plan two days).

1. **Baseline**: 2 h, everything off.
2. **Heater**: on for 5 h (about 2 τ), then off for 5 h of relaxation. Gives τ,
   the gain K, `C_a = P·τ/K` (the heater's power measured with a plug meter)
   and UA. A 2-h step is not enough: with process variation of the magnitude
   measured in snapshot 1 (about 2·10⁻⁵ °C² per 3-s cycle on the SHT45), a 2-h
   step gives τ only to about 10 %, and the fit refuses about a third of such
   steps as too uncertain (`WIDE_CI`); the 5-h step gives τ to about 1–2 % and
   C_a to about 3 %
   (`tests/test_research_calib_plant.py`).
3. **air_flow_fan**: on for 2 h. Gives `fan_air_exchange_per_h` from the change
   in τ and the CO2 decay, and `fan_mixing_factor` once the substrate is
   measured.
4. **Humidifier**: on for 30 min. Gives `humidifier_g_per_h` from the rise in
   vapour density.
5. **co2_fan**: on for 1 h after CO2 has built up. Gives `co2_fan_ach_per_h`.
6. **Closed-chamber relaxation** of CO2 and humidity with the room measured.
   Gives `leak_ach_per_h`, and `co2_production_ml_per_h` once substrate is
   present (with a DS18B20 added).
7. **Cooler, lamps and substrate heater** in the same way, when fitted.

## The contract change it needs (a later phase, not Phase 3)

- Migration 014: `medcea.research_actuator_states(p_after, p_upto)` from SP
  reports (`control_setpoint`) and `medcea.research_commands(p_after, p_upto)`
  from CT rows (the runner's and test mode's commands). Columns: measured_at,
  ingested_at, unit_code, zone_code, actuator, state or command, origin
  (`loop` | `test`). No person column.
- `medcea.research_contract_version()` → 2. The research database gets
  `lake.actuator_event` and its stage table, `known_contracts {1, 2}`, a digest
  set `actuator_events`, and `lake_api.actuator_events(p_snapshot, …)`.
- A new member of the access policy's group `research_export`: a skeleton
  version approved by qa.

`fit-plant` and `plant_fit.fit_step` already take the shape (a step time, the
actuator, its power, an ambient series). Until the export carries actuator
events, a fit from the step log is not applied: Phase 3 refuses every `fitted`
plant entry in a calibration file ("plant fits are applied from a later
phase").
