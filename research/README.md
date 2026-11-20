# MedCEA Research Sandbox

The research sandbox is where control models and recipes are tried against a
simulated chamber before anyone proposes them to the platform. It is its own
application, loosely coupled to the rest of MedCEA: it runs production's own
controllers and loop rules on a plant model, and never writes to the
operational services. The plan is `codeplan/research-sandbox-plan.md`
(gitignored); the platform manual's research chapter is for the people who use it.

## Layout (Phases 1 and 3)

- `research/twin_plant/` — the plant model: a lumped 60×60×60 cm chamber (air
  temperature, substrate temperature, humidity, CO2, actuator power) and the
  sensors (SHT45, SCD30, DS18B20) with seeded noise, quantisation, latency and
  dropouts. The SEN0562 (light, lux) is not modelled: `light_intensity` is not
  a loopable quantity and the chamber has no lux balance; it comes with the lux
  loop (feedback control plan, Phase 5).
- `research/harness/` — the simulation harness: loads `schd/cea/algorithms/`
  and `schd/cea/loop_resolver.py` by path (never `import cea`, which pulls in
  psycopg2 and paho), runs the 10-s control tick against the plant, computes
  the metrics and runs campaigns (`results.jsonl` + `manifest.json`).
  `scenarios/` holds the scenarios, `campaigns/` the campaign specs.
- `research/calib/` (Phase 3) — calibration from the lake's snapshots
  (standard library + PyYAML): `lake.py` reads `lake-api` (GETs only, pinned by
  lineage, pages of 5,000 readings), `pgtext.py` recomputes the lake's digests,
  `dataset.py` and `extract.py` write the frozen dataset and the snapshot
  extract, `segments.py`, `stats.py` and `sensor_fit.py` fit the sensor model,
  `plant_fit.py` says which plant constants a dataset identifies (none so far),
  `calibfile.py` writes and checks the calibration file. `calibrations/` and
  `extracts/` hold the committed files; `STEPTEST.md` is the step-test protocol
  for when a CONTROL board is fitted.
- `research/harness/pins.py` (Phase 3) — resolves a scenario's `calibration`
  and `recipe_line_from` pins inside `campaign.resolve_spec`.
- `research/contract.py` — the reviewed form of the coupling contract
  (`CONTRACT_VERSION` 2 since Phase 3: it also names the lake reader's
  functions, `LAKE`); `tests/test_research_contract.py` compares it with
  production's sources and with `apps/research/db/lake_api.sql`.
- `research/requirements.txt` — numpy, scipy, scikit-fuzzy, gekko, PyYAML and
  their dependencies, pinned by version and sha256, so FLC and MPC run their
  real code paths instead of falling back to bang-bang.
- `research/lib-venv.sh` — `ensure_research_venv`, which builds
  `research/.venv` (gitignored).

Everything here runs on the host. The harness core is standard library + PyYAML;
FLC and MPC need the virtualenv, which has both.

## Build the virtualenv and run a campaign

From the repository root:

```bash
source research/lib-venv.sh && ensure_research_venv
research/.venv/bin/python -m research.harness.campaign research/harness/campaigns/smoke.yaml
```

`smoke.yaml` runs the five controller codes with a small parameter grid each on
the one-hour smoke scenario, two seeds and two clock offsets (36 runs, a few
CPU-minutes). `fruiting_compare.yaml` compares the five codes at their defaults on
the 48-hour Pleurotus fruiting scenario, three seeds and three offsets (45 runs);
its estimate is about 11 CPU-hours, mostly MPC, over the default cap of 4, so it
needs the cap raised:

```bash
research/.venv/bin/python -m research.harness.campaign \
  research/harness/campaigns/fruiting_compare.yaml --max-cpu-hours 12
```

Results go to `research/runs/<spec name>/` (gitignored) unless `--out DIR`.
A campaign refuses to run while the contract sources (`schd/cea/`, the
catalogue, the CONTROL template) or `research/` itself differ from the
committed version, because the manifest could not name the code that produced
the numbers. Add `--allow-dirty` only when testing uncommitted changes; the
changed files are then listed in `manifest.json`.

`ensure_research_venv` needs `python3 -m venv` (package `python3-venv`) and
PyPI. It installs with `--require-hashes --only-binary=:all:`: a wheel whose
hash is not in `requirements.txt` is refused. A re-run installs nothing new.
It returns non-zero on failure; the caller decides what to do.

## Calibrating from a snapshot (Phase 3)

Owner decision of 20 Nov 2026, "build now, fit what's there": the sensor model is
calibrated now; every plant constant stays an assumption, which the fit refuses
until step-test data exists (`research/calib/STEPTEST.md`).

```bash
apps/research/calibrate.sh snapshots                    # needs RESEARCH_ENABLED and a Running lake-api
apps/research/calibrate.sh fetch --snapshot 1 --expect-lineage <64 hex> \
    --unit UNIT01 --zone ZONE01 --out ~/calib/s1         # dataset.jsonl, extract.yaml, fetch-log.json
python3 -m research.calib fit-sensors ~/calib/s1/dataset.jsonl \
    --map sht45=sht45_1,scd30=scd30_1 --name unit01-zone01-s1 --out ~/calib/s1.yaml --report ~/calib/report.txt
python3 -m research.calib fit-plant ~/calib/s1/dataset.jsonl   # exit 3 while nothing is identifiable
python3 -m research.calib verify ~/calib/s1.yaml                 # also a dataset or an extract
```

`calibrate.sh` logs (`logs/research-calibrate-<ts>.log`), takes no lock and finds
lake-api's address for `snapshots` and `fetch`; every other subcommand passes
straight to `python3 -m research.calib`. Exit codes: 0, 2 (refused or usage),
3 (`fit-plant`: nothing identifiable; nothing written). A fetch never overwrites
a file, and `fit-sensors` refuses a `research/` that differs from HEAD unless
`--allow-dirty`, which the file records. The dataset (about 8 MB) is not
committed: a fetch with the same lineage gives the same bytes.

Committed: the extract `calib/extracts/snapshot-1-096015bc225c.yaml` and the
calibration `calib/calibrations/unit01-zone01-s1.yaml` (snapshot 1, lineage
`096015bc…`, UNIT01/ZONE01). A scenario uses them through pins, paths relative
to the scenario file and checked by sha256:

```yaml
calibration: {path: ../../calib/calibrations/unit01-zone01-s1.yaml, sha256: <hex>,
              extrapolate: {air_humidity: <why>}}     # the fit saw 51.35-55.33 %RH only
recipe_line_from: {extract: ../../calib/extracts/snapshot-1-096015bc225c.yaml, sha256: <hex>,
                   snapshot_id: 1, lineage: <hex>, recipe_id: 2, seq: 3,
                   light: {light_on_minutes: 720, light_off_minutes: 720, why: <why>}}
```

Calibrated specs: `campaigns/e39_compare_calibrated.yaml` (30 runs) and
`campaigns/fruiting_compare_calibrated.yaml` (45 runs, `--max-cpu-hours 14`),
the same grids as `e39_compare.yaml` and `fruiting_compare.yaml`. Their manifests
carry `provenance` (calibration, snapshot, lineage, the values applied and not
applied, the extrapolation reason, the recipe line) and `spec.json` sits beside
`manifest.json`. Calibration changes only what the controllers see; plant
behaviour is the model's assumption, so a difference is a sensor effect, never
evidence about the real chamber.

## Coupling contract

1. Identity: shared — the one Keycloak realm, the platform roles and the access policy's route table.
2. Data: by snapshot only, never a live connection (owner decision of 17 Nov 2026). Built in Phase 2a (owner decisions P, F and S of 18 Nov 2026): the nightly exporter (CronJob `research-export` in namespace `medcea`, `apps/research-export/`) reads production only through eleven owner-run read functions `medcea.research_*()` (migration 013; EXECUTE only, never views over the base tables, so no `medcea.v_*_research` view exists), and writes an append-only snapshot up to a high-water mark (the cut) into the research database `medcea_research` (`apps/research/`), minus every range qa has held out. No person column reaches the sandbox, not even a pseudonym. `medcea.research_contract_version()` is the contract version (1); the research database refuses a snapshot of a version it does not know. The sandbox never connects to the operational database. From Phase 2b notebooks, and from Phase 3 the calibration (`research/calib/`), read the snapshots through `lake-api` (GETs to read functions in schema `lake_api`, pinned by lineage); runs, cycles, control loops and parameter sets stay unexposed (decision O3, kept at Phase 3).
3. Metadata: read from production's own sources at a pinned commit, never copied — `recipe_types.yaml`, recipe format 2 and its setpoint rules (`recipe_line_setpoints_guard`), the `ControlAlgorithm` interface and `ALGORITHM_NAMES`, `loop_resolver`, `esp32-control.json`.
4. Candidates out: one gateway, which runs production's validators and writes only a draft (Phase 6).
5. Nothing else is shared: no import of operational services, no shared tables, no other write path.
