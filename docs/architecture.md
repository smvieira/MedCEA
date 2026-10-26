# MedCEA Architecture — Baseline Mapping

MedCEA is a four-layer operational stack plus a decoupled, read-only **Compliance Plane**. The stack
aligns with ISA-95 levels 0–4, the RAMI 4.0 hierarchy axis and IIRA edge/platform/enterprise. This
repository was forked from `pfplatform` (commit `2032725`), which already implements most of Layers 1–3.
This page records what exists and what is still to be built.

```
 Layer 4  Enterprise / Regulatory Interface   ──►┐
 Layer 3  Platform / Intelligence             ──►│   COMPLIANCE PLANE
 Layer 2  Edge / Control                      ──►│   (receives events, cannot be
 Layer 1  Physical / Cultivation                 │    modified by the operational layers)
                                                 ┘
```

## Layer 1 — Physical / Cultivation

Medicinal-species chambers, with sensors (air/substrate temperature, RH, CO2, light, airflow,
substrate moisture/pH) and actuators (heating, cooling, humidification, ventilation, LED).

| Exists | Where |
|---|---|
| Chamber model: location → unit → zone | `medcea.cea_location`, `medcea.cea_unit`, `medcea.cea_zone` (`apps/database/medcea_db_ddl.sql`) |
| Sensor drivers (SCD30, SCD4x, …) | `edge/src/app/cea_sense.py`, `edge/src/app/cea_sensors.py` |
| Actuator channel maps | `edge/templates/esp32-control.json`, `edge/src/host/bindings.py` |

**TODO:** light spectrum, airflow and pH sensors. A room-level ambient reference sensor (Exp 1/2). The four-chamber build (Task 5).

## Layer 2 — Edge / Control

| Exists | Where |
|---|---|
| MicroPython SENSE / CONTROL application (same image on every board) | `edge/src/app/` |
| Device onboarding (flash, slot from DB, channel map) | `edge/flash-device.sh`, `edge/wizard-daemon.sh` |
| MQTT transport (`medcea/<UNIT>/<ZONE>/...`) | Mosquitto, deployed by `deploy-infra.sh`; per-board and per-service credentials with topic ACLs (`medcea.mqtt_credential`, sidecar `k8s/mosquitto/mqtt-auth-sync.py`) |

**TODO:** edge-side validation and outlier detection. Lightweight on-device disturbance-rejection inference.

## Layer 3 — Platform / Intelligence

| Exists | Where |
|---|---|
| Recipe engine: recipes → lines → cycle runs | `schd/run_recipe.py`, `schd/cea/`, tables `recipe*`, `schedule` |
| Pluggable controllers: bang-bang, PID, fuzzy, MPC, Q-learning | `schd/cea/algorithms/` (`base.py` interface, `algorithm_state` persistence) |
| Scheduler UI/API, live run monitor | `apps/scheduler/`, `apps/monitor/` |
| Telemetry store | `medcea.measurement` (PostgreSQL), PostgREST config API |
| Flows, dashboards, notebooks | Node-RED (`apps/node-red/`), Grafana (`apps/report/`), JupyterHub (`infra/deploy-workbench.sh`) |
| Identity / SSO | Keycloak realm `medcea` |

**TODO:** recipe phases with explicit transition conditions and setpoint ramps. Controller rotation
scheduling for Exp 1 (time-sliced AI vs rule-based per chamber/phase). RMSD and boundary-hugging metrics.
A per-chamber digital twin and simulation harness for pre-deployment evaluation. MES batch/lot entities with
genotype and substrate registration. Linking post-harvest analytical results (HPLC-MS, β-glucan,
ICP-MS) to batches.

## Layer 4 — Enterprise / Regulatory Interface

**Nothing yet.** **TODO:** GACP compliance reports, a Novel Food evidence-package export (Exp 4), and
partner/regulator APIs.

## Compliance Plane (all TODO)

The plane must be architecturally separate from the operational data flows. The operational services
publish events into it. They hold no credentials that let them update or delete what it stores.

| Component | Intended placement |
|---|---|
| **GS1 EPCIS 2.0 event publisher** | A service that consumes operational events (MQTT/DB changes) and emits EPCIS JSON-LD ObjectEvents and TransformationEvents with CBV business steps. SGTIN for units, LGTIN for lots. Consider OpenEPCIS as the repository. |
| **Immutable audit trail** | Its own schema and DB role. Append-only (no UPDATE/DELETE grants). Each record carries `prev_hash` and `hash = H(prev_hash ‖ payload)`. Periodic anchoring of the chain head. |
| **Electronic Batch Record generator** | Compiles telemetry, the recipe execution log, controller segments, genotype identity and analytical results per lot into a reviewable, signed record. |
| **RBAC** | Keycloak realm roles `operator`, `qa`, `admin`, `auditor`, enforced at the API and DB-role level. Data creation and data review are separated (Annex 11). **Partly done:** the roles exist and the portal admits only them; people obtain one through a self-service access request reviewed by an admin in the User Manager (`apps/access`), with every request and decision in the append-only `iam.access_request_history`. **Still TODO:** per-role permissions inside each service (Grafana, Node-RED, config API, scheduler) and DB roles per realm role. |
| **Read-only regulator interface** | A query API and UI for auditors and Layer 4, with no write paths. It is the basis of the Exp 3 inspection simulation. |

## Runtime identifiers

`PROJECT_NAME="medcea"` in `config.env` is the single project identifier. It is the MQTT topic root
(`medcea/<UNIT>/<ZONE>/{sense,control,control_setpoint}/…`), the Kubernetes namespace and the
Keycloak realm. The database is `medcea_db`, schema `medcea`. pfplatform's `cea`/`ceaplatform`
names and its legacy `plantinc/#` root are gone. `cea_*` table names and the `schd/cea` package
keep "CEA" as the domain term.
