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
| MQTT transport (`medcea/<UNIT>/<ZONE>/...`) | Mosquitto, deployed by `deploy-infra.sh`; per-board and per-service credentials with topic ACLs (`medcea.mqtt_credential`, sidecar `k8s/mosquitto/mqtt-auth-sync.py`); per-person MQTT Explorer credentials from iam-api on the WebSocket listener only (`medcea.mqtt_service_credential`, IAM 3.5, `IAM_MQTT_PERSON`) |

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

## Compliance Plane (partly built)

The plane must be architecturally separate from the operational data flows. The operational services
publish events into it. They hold no credentials that let them update or delete what it stores.

| Component | Intended placement |
|---|---|
| **GS1 EPCIS 2.0 event publisher** | A service that consumes operational events (MQTT/DB changes) and emits EPCIS JSON-LD ObjectEvents and TransformationEvents with CBV business steps. SGTIN for units, LGTIN for lots. Consider OpenEPCIS as the repository. |
| **Immutable audit trail** | Its own schema and DB role. Append-only (no UPDATE/DELETE grants). Each record carries `prev_hash` and `hash = H(prev_hash ‖ payload)`. Periodic anchoring of the chain head. **Partly built:** the access policy's history `iam_policy.history` is hash-chained this way (migration 008a), written only through owner functions, and verified by the health check `iamchain` and `iam_policy.verify_chain()`; the nightly backup records the chain head. **Still TODO:** an anchor that reads the recorded head back, and the same trail for operational events. |
| **Electronic Batch Record generator** | Compiles telemetry, the recipe execution log, controller segments, genotype identity and analytical results per lot into a reviewable, signed record. |
| **RBAC** | The eleven Keycloak realm roles of `apps/iam/policy/defaults.yaml`, enforced from that one source by its compiler (`apps/iam/compiler/`) at the sign-in gates, the API and the DB-role level. Data creation and data review are separated (Annex 11). Status per phase of `codeplan/MedCEA_IAM_Implementation_Plan.md`: **Phase 0, done:** the roles, the policy source and compiler, every web host's sign-in gate compiled from it (`IAM_GATES`); people obtain a role through a self-service request reviewed in the User Manager (`apps/access`), recorded in the append-only `iam.access_request_history`. **Phase 1, done:** verified tokens in every Python service, the compiled route table, one NetworkPolicy per application pod (`IAM_NETPOL`). **Phase 2, built, switched by the operator:** PostgREST verifying the person's token (`IAM_POSTGREST_JWT`, 2b), services on their own DB roles (`IAM_DB_SERVICE_ROLES`, 2.5, on by default), per-realm-role DB roles with RLS and approval functions (`IAM_DB_ROLES`, 2a), runs written through 008b's functions with a person or `system:scheduler` actor (2.4), the services enforcing the route table (`IAM_ENFORCE`, 2.6; Database Management and the access Admin port always enforce), account decisions confirmed by qa (2.7), unit assignment (2.8); `./medcea.sh` → Bring IAM to full enforcement turns the off ones on. **Phase 3, done:** role settings compiled for Grafana, the AI Workbench, Node-RED's editor, the onboarding wizard, pgAdmin and Superset; personal MQTT Explorer credentials (`IAM_MQTT_PERSON`). **Phase 4, done (4.0 to 4.5):** the policy changes only as a version drafted, approved by a second person and applied with `apps/iam/apply.sh`, through the Policy UI; a widening git skeleton is refused by every deploy. **Phase 5, in progress:** health checks that prove the applied version is in force (`iamloaded`, `jwks`, `kcscopes`, `iamnetpol` added on 9 Nov 2026) and the documentation. |
| **Read-only regulator interface** | A query API and UI for auditors and Layer 4, with no write paths. It is the basis of the Exp 3 inspection simulation. |

## User journeys

### Quality Assurance (`qa`) — mostly TODO

The roles split a lot's quality work three ways (`apps/iam/policy/defaults.yaml`):
- **QC (`qc`)** tests product and records the analytical results (HPLC-MS, ICP-MS, β-glucan).
- **QA (`qa`)** reviews and approves what someone else recorded or changed. It never enters results itself, because data creation and data review stay separate (Annex 11).
- **QP (`qp`)** releases the lot.

| # | What QA does | Status |
|---|---|---|
| 1 | Signs in and reads everything an auditor reads: portal, Config UI, Scheduler, Monitor, Database Management | **Done** (IAM Phase 0 gates) |
| 2 | Approves recipes, controllers and their parameter sets, settings, master data and device changes made by someone else | **Built in the database, off by default** (IAM Phase 2a: `medcea.approval`, `approve_*()`, status columns; `IAM_DB_ROLES=true` makes it binding). While false a saved change is live, and editing an approved definition demotes it to draft with a warning. The approval screens are not built yet. |
| 3 | Confirms every account grant, role change and unit assignment an administrator makes | **Planned**, IAM Phase 2.7 (QA confirm screen in the User Manager). Unit assignments made with `apps/iam/units.sh` (IAM 2.8) wait as `pending_qa` and take effect only when qa confirms them; a refusal applies nothing (`--bootstrap`, allowed only while no other qa account exists, applies one at once and a refusal removes it). |
| 4 | Approves every access-policy change | **Planned**, IAM Phase 4 (Policy UI) |
| 5 | Reviews the analytical results QC recorded for a lot against its specification; accepts them or raises a deviation | **TODO, not yet planned.** Needs the Layer 3/4 entities, none of which exists in `medcea_db`: lot/batch (genotype, substrate, linked cycle runs), sample, analytical result (method, analyte, value, unit, LoQ, lab, CoA document), specification, deviation. A QC entry or import path (lab CSV, CoA PDF) is needed too. |
| 6 | Reviews the lot's Electronic Batch Record (telemetry, recipe execution log, controller segments, genotype, analytical results, deviations) and passes it to QP | **TODO, not implemented.** The EBR generator (Compliance Plane) depends on step 5, the hash-chained audit trail, and run attribution (`created_by_*`, IAM Phase 2). |
| 7 | Signs off the quarterly access review, reviews audit trails, exports evidence | **Planned**, IAM Phases 2.7 and 5 |

**Order of work for steps 5–6:**
1. The lot/batch entity linked to cycle runs.
2. Analytical results, specifications and deviations, with QC entry.
3. The EBR generator.
4. Electronic signatures for QA approval and QP release. These are out of scope in the IAM plan (§7); until they exist, an approval is an attributable record, not a signature.

The new tables join the access policy as new resource groups (IAM plan §7, "the L4 entities").

## Runtime identifiers

`PROJECT_NAME="medcea"` in `config.env` is the single project identifier. It is the MQTT topic root
(`medcea/<UNIT>/<ZONE>/{sense,control,control_setpoint}/…`), the Kubernetes namespace and the
Keycloak realm. The database is `medcea_db`, schema `medcea`. pfplatform's `cea`/`ceaplatform`
names and its legacy `plantinc/#` root are gone. `cea_*` table names and the `schd/cea` package
keep "CEA" as the domain term.
