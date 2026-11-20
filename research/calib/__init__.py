"""Calibrating the sandbox's models from the research lake's snapshots (research Phase 3).

Standard library + PyYAML only. The lake is read through lake-api (HTTP GETs of the
lake_api.*() functions, pinned by snapshot id and lineage), never through a database
connection; nothing here writes the lake. codeplan/rs3-design.md is the design.

Commit B (lake access): lake.py (LakeClient), pgtext.py (PostgreSQL's text forms, so the
lake's digests recompute here), dataset.py (the frozen measurement dataset), extract.py
(the snapshot extract), cli.py (snapshots, fetch, verify).

Commit C (fits and wiring): segments.py (board cycles, cadence, outages), stats.py (the
deterministic statistics), sensor_fit.py (the sensor estimators), plant_fit.py (the plant
constants' identifiability and the step fit), calibfile.py (the calibration file), and the
cli's fit-sensors and fit-plant. A scenario pins a calibration file or a snapshot's recipe
line through research/harness/pins.py, resolved by campaign.resolve_spec.
"""

# The estimators' version (bumped when a fit's arithmetic changes).
CALIB_VERSION = 1
# The calibration file's schema (research/calib/calibrations/*.yaml).
CALIB_SCHEMA = 1
# The measurement dataset's schema (dataset.jsonl, line 1 "medcea_dataset").
DATASET_SCHEMA = 1
# The snapshot extract's schema (extract.yaml, "medcea_extract").
EXTRACT_SCHEMA = 1
