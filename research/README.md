# MedCEA Research Sandbox

The research sandbox is where control models and recipes are tried against a
simulated chamber before anyone proposes them to the platform. It is its own
application, loosely coupled to the rest of MedCEA: it runs production's own
controllers and loop rules on a plant model, and never writes to the
operational services. The plan is `codeplan/research-sandbox-plan.md`
(gitignored); the platform manual's research chapter is for the people who use it.

## Phase 1 layout

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
- `research/contract.py` — the reviewed form of the coupling contract;
  `tests/test_research_contract.py` compares it with production's sources.
- `research/requirements.txt` — numpy, scipy, scikit-fuzzy, gekko, PyYAML and
  their dependencies, pinned by version and sha256, so FLC and MPC run their
  real code paths instead of falling back to bang-bang.
- `research/lib-venv.sh` — `ensure_research_venv`, which builds
  `research/.venv` (gitignored).

Phase 1 runs on the host. The harness core is standard library + PyYAML;
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

## Coupling contract

1. Identity: shared — the one Keycloak realm, the platform roles and the access policy's route table.
2. Data: by snapshot only, never a live connection (owner decision of 17 Nov 2026). Built in Phase 2a (owner decisions P, F and S of 18 Nov 2026): the nightly exporter (CronJob `research-export` in namespace `medcea`, `apps/research-export/`) reads production only through eleven owner-run read functions `medcea.research_*()` (migration 013; EXECUTE only, never views over the base tables, so no `medcea.v_*_research` view exists), and writes an append-only snapshot up to a high-water mark (the cut) into the research database `medcea_research` (`apps/research/`), minus every range qa has held out. No person column reaches the sandbox, not even a pseudonym. `medcea.research_contract_version()` is the contract version (1); the research database refuses a snapshot of a version it does not know. The sandbox never connects to the operational database.
3. Metadata: read from production's own sources at a pinned commit, never copied — `recipe_types.yaml`, recipe format 2 and its setpoint rules (`recipe_line_setpoints_guard`), the `ControlAlgorithm` interface and `ALGORITHM_NAMES`, `loop_resolver`, `esp32-control.json`.
4. Candidates out: one gateway, which runs production's validators and writes only a draft (Phase 6).
5. Nothing else is shared: no import of operational services, no shared tables, no other write path.
