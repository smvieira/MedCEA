# The MedCEA Concept

**Medicinal Controlled Environment Agriculture (MedCEA)** is a specialised subclass of CEA. Its primary
production objective is the optimised, reproducible and regulatory-compliant biosynthesis of target
bioactive compounds in medicinal fungal and plant species, not biomass yield.

This repository holds the open-source (MIT) IIoT platform that instantiates the concept. It is the
artefact of a Design Science Research PhD project (ISCTE-IUL / Instituto de Telecomunicações, with
ESACB, 2025–2028). The primary model organism is *Hericium erinaceus* (lion's mane).

## Research question

> How can an open, modular, and regulatory-compliant IIoT platform, integrating AI-driven adaptive
> control, end-to-end traceability and auditability, and authenticated genotype provenance, be
> designed, implemented, and evaluated to enable reproducible production of target bioactive
> compounds in medicinal mushrooms and medicinal plants?

## The four pillars

| Pillar | What the platform must do |
|---|---|
| **I — Bioactive-compound-centric control** | Execute recipes as structured programmes (phases, phase-specific setpoints, transition conditions) over the full environmental state vector: temperature, humidity, CO2, light spectrum/intensity, photoperiod, airflow and elicitors. AI control does recipe execution and disturbance rejection in real time. The environment→metabolite relationship is learned offline. |
| **II — Outcome reproducibility** | Validated recipe execution plus authenticated genotype identity per lot, so that batch-to-batch CV% of key compounds can be attributed to the environment. |
| **III — Regulatory compliance by design** | GACP Rev.1 (2025), EU GMP Annex 11, Novel Food (EC 2015/2283) and THMPD are built into the data model, access control and event logging, not added afterwards as reports. |
| **IV — End-to-end traceability & auditability** | Every lifecycle event (genotype, substrate, cultivation, harvest, post-harvest, analytics) is recorded as GS1 EPCIS 2.0, in a hash-chained ALCOA+ audit trail with Operator / QA / Admin / Auditor RBAC. |

## Hypotheses and experiments

| | Hypothesis | Experiment | Primary metrics |
|---|---|---|---|
| H1 | AI control holds setpoints better than rule-based control | **Exp 1:** time-sliced algorithm rotation over 4 chambers, ~30 days | Segment-level RMSD to setpoints, boundary-hugging event rate |
| H2 | Environmental parameters significantly determine bioactive profiles in *H. erinaceus* | **Exp 2:** two-recipe crossed design (literature optimum vs cool-stress fruiting) | Hericenones C/D (HPLC-MS), total β-glucan (Megazyme), within-recipe CV%, plus heavy metals (HPLC/ICP-MS) |
| H3 | The platform generates ALCOA+ EBRs and the evidence an EFSA Novel Food dossier needs | **Exp 3:** blind traceability inspection simulation. **Exp 4:** Novel Food gap analysis | ALCOA+ pass/partial/fail; gaps classified as structural vs analytical |
| Pillar III | — | Clause-by-clause EU GMP Annex 11 mapping | Fully / partially / not satisfied |

Exps 1–2 run May–Oct 2027. Exps 3–4 run Nov 2027–Apr 2028.

## Objectives

- **O1:** concept + four-layer reference architecture with a decoupled Compliance Plane, and the Annex 11 mapping.
- **O2:** AI vs rule-based control, and the recipe → bioactive-profile effect.
- **O3:** a MIAPPE-compatible metadata schema for fungal IIoT phenotyping, and a FAIR dataset.
- **O4:** ALCOA+ Electronic Batch Records and a draft Novel Food evidence package.
- **O5:** an integrated multi-chamber prototype, with all custom components released under MIT.

See [architecture.md](architecture.md) for how the existing code maps to the architecture.
