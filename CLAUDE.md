# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MedCEA is a shell-script-based IoT platform deployer targeting a single Ubuntu PC running MicroK8s. It installs and wires together: Kubeflow, Keycloak (SSO), PostgreSQL, Grafana, Node-RED, and OAuth2 Proxy.

**There is no build step, no test suite, and no package manager.** The codebase is bash scripts plus a config file, split into infrastructure (`deploy-infra.sh`) and application content (`deploy-apps.sh` / `apps/`).

## MedCEA Direction

This repo was forked from `pfplatform` (@2032725) as the baseline for the MedCEA PhD prototype. Read [docs/medcea-concept.md](docs/medcea-concept.md) (four pillars, H1–H3, experiments) and [docs/architecture.md](docs/architecture.md) (layer → component mapping, Compliance Plane TODOs) before adding features. Two rules follow from the concept:
- **The Compliance Plane is read-only from the operational layers.** Operational services may append events to it, but never get UPDATE/DELETE on audit, EPCIS or EBR storage.
- **`PROJECT_NAME` (`medcea`) is the one project identifier.** It is the MQTT topic root, and `config.env` derives `NAMESPACE` and `KEYCLOAK_REALM` from it; `deploy-infra.sh` refuses a value that is not `^[a-z][a-z0-9-]{1,30}$`. The database is `medcea_db` with schema `medcea` — a literal, because the schema name is written into the SQL, not templated. `cea` survives only as the domain term "controlled environment agriculture": the table names `cea_unit`/`cea_zone`/`cea_location`, the Python package `schd/cea/` (so `cea.run_agent(...)` is a module call, not a schema), `CEA_*` env vars, `cea-tls`/`cea-ca`, and the `cea-un-<mac6>`/`cea-<mac6>` board hostnames.

## Full Deployment Workflow

All scripts must be run from the repository root; they call each other via relative paths and source `config.env` from the current directory.

```bash
# 1. Deploy infrastructure (safe to re-run — bootstrap is skipped if already done).
#    The first run creates config.env from config.env.example by Q&A (infra/configure.sh);
#    later runs ask only for empty required values. Review all: ./deploy-infra.sh --configure
./deploy-infra.sh

# Help text (does not require config.env to be present)
./deploy-infra.sh --help

# 2. Deploy application content (interactive component selector):
./deploy-apps.sh
./deploy-apps.sh --all   # non-interactive

# Recovery only: if Juju charm update resets dex-auth config, re-run:
./patch-dex-keycloak.sh
```

## Script Roles

- **`bootstrap-infra.sh`** — Called by `deploy-infra.sh`. Handles: K3s cleanup, MicroK8s snap install/wipe (interactive prompt, also removes Juju on wipe), MicroK8s addon enablement (dns:8.8.8.8, hostpath-storage, rbac, ingress, helm3, metallb), inotify limit tuning, kubeconfig export, Juju 3.6/stable install, Charmed Kubeflow 1.9 deployment via `juju deploy kubeflow --trust`, dex-auth/oidc-gatekeeper initial configuration, and pod-count readiness wait.
- **`infra/configure.sh`** — Fills `config.env` by Q&A. It is called by `deploy-infra.sh` before logging starts, so answers and generated passwords stay out of `logs/`. `config.env.example` is always the base: on each run the file is rebuilt from the template with existing values carried over line for line, and keys only the old file had are kept at the end. It checks Tailscale on every run, before the early exit for a complete file. `USE_TAILSCALE` records whether `DOMAIN` depends on it: `true` makes a down Tailscale fatal, because the `DOMAIN` expression would quietly fall back to the LAN IP; `false` means LAN-only on purpose and is not raised again. Pressing Enter leaves a line untouched, so expressions like `DOMAIN="$(tailscale ip ...)"` stay expressions. Passwords are limited to `[A-Za-z0-9._~-]` because they are spliced unencoded into YAML, a `postgres://` URL, `helm --set` and a curl form body.
- **`deploy-infra.sh`** — Top-level infrastructure orchestrator. Also deploys the AI workbench (`infra/deploy-workbench.sh`, JupyterHub) unless `WORKBENCH_ENABLED=false` — it is a platform service, and infra already owns its Keycloak client, portal card and URL. Validates config (including METALLB_RANGE and KUBEFLOW_IP), prompts for Docker Hub credentials, calls `bootstrap-infra.sh`, then deploys Postgres → Keycloak → Mosquitto → (Node-RED + Grafana + OAuth2 Proxy) via Helm.
- **`deploy-apps.sh`** — Interactive app content installer. Discovers components under `apps/<component>/deploy.sh` and presents a checkbox menu. Use `--all` to skip the prompt.
- **`infra/deploy-workbench.sh`** — JupyterHub, authenticated against Keycloak with `GenericOAuthenticator`. Replaced Charmed Kubeflow, which `bootstrap-infra.sh` used to deploy. Runnable standalone to redeploy just the workbench.
- **`patch-dex-keycloak.sh`** — Recovery script. Re-applies the Keycloak OIDC connector to the `dex-auth` Juju charm via `juju config dex-auth connectors=<yaml>`. Not needed for initial deployment (deploy-infra.sh handles this). Run it when a Juju charm update resets the dex-auth config. There is no ConfigMap to patch — Juju owns the dex-auth config entirely.
- **`edge/flash-device.sh`** — Device onboarding. Flashes MicroPython over USB, asks for a role and a unit/zone slot from the platform database, asks which sensors or relay channels are wired to which GPIO, ships the application, and writes the `medcea.device` row. `--unregistered` keeps the old bench behaviour (no slot, no application, no database).
- **`edge/wizard-daemon.sh`** — The always-on browser front end for the above, behind Keycloak. Linked from the Devices tab.
- **`edge/templates/<family>-{sense,control}.json`** — **The wizard's questions are data, not code.** Adding a supported sensor is an entry here plus a branch in `edge/src/app/cea_sense.py`; `flash-device.sh` does not change. The file name carries the device family (`esp32-control.json`); `CEA_DEVICE_FAMILY` selects one, default `esp32`.
- **`edge/templates/esp32-gpio.json`** — The GPIO reference for the whole ESP32 family: which pins each of the seven variants has, and what already wants them (SPI flash, PSRAM, strapping, USB-JTAG, UART0, input-only). Sourced from Espressif's per-target ESP-IDF GPIO pages. It drives the form's board selector, its pin reference panel, and validation — one table, so the reference cannot say a pin is free while the validator calls it taken.
- **`edge/src/host/bindings.py`** — How a command reaches equipment: what identifies one channel, what counts as a legal address, and what the field is called in the file the device reads. Driven by the template's `binding` block, so a device family that is not addressed by GPIO is a new template rather than new Python. Also holds `validate_config()`, the structural checks both the renderer and the browser editor apply.
- **`edge/src/host/ui/channelmap.{js,css}`** — The channel-map editor. Inlined into the wizard page by `wizard_server.py` and into the standalone tool by `edge/tools/build-editor.sh` — one implementation, two hosts. It renders whatever `device_template.py channelmap` prints and contains no mention of a GPIO.
- **`edge/tools/build-editor.sh`** — Rebuilds `edge/tools/actuator-config-editor.html`, a serverless copy of the editor for inspecting or hand-correcting a map away from the platform. Re-run it after changing `channelmap.js`, `channelmap.css`, or the CONTROL template.
- **`edge/src/host/platform_db.py`** — Units, zones, free slots and device registration over PostgREST. Reaches `config-api` by ClusterIP (kube-proxy runs on the host, so ClusterIPs are routable); `CEA_CONFIG_API` overrides.
- **`edge/src/host/device_template.py`** — Turns a template into prompts, then prompts into the board's `device_cfg.py` / `actuator_config.json` and the database component rows.
- **`edge/src/app/`** — The MicroPython application, **identical on every board**. Per-device values live only in the generated `device_cfg.py`; `config.py` derives topics and client id from it, `main.py` dispatches on `ROLE`.
- **`apps/<component>/deploy.sh`** — Per-component idempotent deploy script. Each sources `config.env` from the repo root and uses `sudo microk8s kubectl` directly. New components are auto-discovered by `deploy-apps.sh`.
- **`config.env`** — Sourced by all scripts. Not committed (in `.gitignore`). See `config.env.example` for the full variable list.

## Key Architecture Decisions

**Single-pass deployment:** `deploy-infra.sh` deploys everything in one run. After Keycloak is ready, it uses the Admin REST API to create realm `medcea` and confidential clients (`node-red`, `grafana`, `kubeflow`), then writes the generated secrets into `config.env` and re-sources it before deploying the services that need them.

**Charmed Kubeflow 1.9 via Juju:** Kubeflow is deployed as `juju deploy kubeflow --trust --channel=$KF_CHANNEL` into MicroK8s. Juju manages the entire Kubeflow operator lifecycle. This replaces the old approach of manually cloning manifests and running 5 sequential `kubectl apply -k` passes with cert-manager readiness gating.

**MetalLB for Kubeflow ingress:** MicroK8s's MetalLB addon assigns a real LAN IP from `METALLB_RANGE` to Kubeflow's `istio-ingressgateway` LoadBalancer service. `KUBEFLOW_IP` is the first IP from that range and is used for all Dex and oidc-gatekeeper configuration. Kubeflow is accessed at `http://$KUBEFLOW_IP` (not via subdomain).

**Bootstrap fast-exit:** `bootstrap-infra.sh` exits immediately (without prompts) if both MicroK8s and a Juju controller named `k8s-controller` already exist. On wipe, it removes Juju (snap + `~/.local/share/juju`) before removing MicroK8s.

**Device identity comes from the database, not from typing:** a board is `<UNIT>_<ROLE>_<ZONE>` (e.g. `UNIT01_SENSE_ZONE01`), and a unit/zone holds one and only one SENSE and one and only one CONTROL. Free slots are read from `medcea.device` on every run — a slot is free when no *active* device of that role points at the zone — so replacing a board is marking the old one inactive, and re-onboarding a slot updates its row in place rather than creating a second one. Everything derivable from the slot (MQTT host and port, topics, client id) is inferred and never asked.

**Two names, one slot:** `UNIT01_SENSE_ZONE01` is the platform identifier (`dns_name`, MQTT payloads, the record). It is not a legal hostname — underscores, and 19 chars lowercased-hyphenated, over MicroPython's cap. The DHCP name is a compressed form of the same slot: `u01-s-z01`, with the alphabetic part shortened only as far as it stays unambiguous against every other unit code. A slot that cannot compress falls back to `cea-<mac6>` with a warning.

**A device family is a template, not a fork:** everything the platform does with a CONTROL device — ask which equipment is fitted, derive the command table, prune branches the chamber cannot perform, validate, render, write the component rows — runs through the template's `binding` block. `binding` names the address field (`pin`), its label (`GPIO`), the map key in the emitted file (`pin_descriptions`), whether an address is an integer or a string, which values are legal, and which carry a warning. `edge/templates/examples/modbus-control.json` is the worked proof: a CONTROL device addressed `3:0001` over Modbus renders and validates correctly through the same `device_template.py` and the same browser editor — labelled "Coil", checked against its own regex — with no Python anywhere for it. What a binding does **not** abstract is provisioning: `flash-device.sh` writes MicroPython over USB, and a device that is not flashed that way needs its own path into the fleet.

**The board is a variant of the binding, not a fork of it:** every ESP32 is addressed by GPIO number, but an S3 has 0-21/26-48 while a C3 stops at 21 and puts its flash on 12-17. Selecting a variant swaps the legal ranges and the per-pin rules and changes nothing else. The form defaults to `esp32s3` and lets the operator change it, because **the wiring question is asked before the board is ever probed** — a slot and a pin map are chosen while the ESP32 is still on the bench. Step 3 is where the two meet: once esptool reports the real chip, `flash-device.sh` re-validates the map against it and refuses if it cannot drive that silicon. Without that check an S3 map on a C3 flashes cleanly and then quietly fails to switch a relay.

**One editor, two hosts, one validator:** the channel map is edited in `edge/src/host/ui/channelmap.js`, which the wizard inlines and `build-editor.sh` bakes into a standalone page. Its structural rules are deliberately mirrored in `bindings.validate_config()` — the browser needs a verdict on every keystroke, and the renderer needs one it can refuse on. **Python is authoritative:** `render()` re-checks and raises rather than writing a table with errors in it, so a hand-crafted POST or a stale page cannot put a broken map on a board that has just been erased. Device-specific rules are not duplicated at all; both sides read them from the template.

**MQTT topic root is `$PROJECT_NAME` (= `medcea`):** SENSE publishes `medcea/<UNIT>/<ZONE>/sense/<tag>`, CONTROL subscribes `medcea/<UNIT>/<ZONE>/control/#` and reports to `.../control_setpoint/...`. Every consumer gets the root at deploy time, never from a literal: Node-RED has `__TOPIC_ROOT__/#` substituted by `apps/node-red/deploy.sh`; the scheduler pod gets `PROJECT_NAME` as env and hands it to `run_recipe.py`/`run_agent.py` through `/installer/.env`; `flash-device.sh` bakes it into each board's `device_cfg.py`. Mosquitto is anonymous with no ACLs, so it needs nothing. There is no legacy `plantinc/#` subscriber in MedCEA — it is a fresh fleet. Changing `PROJECT_NAME` after boards are flashed means reflashing them.

**Helm OCI authentication:** The Bitnami chart registry (`registry-1.docker.io/bitnamicharts/`) requires Docker Hub credentials for Helm chart pulls only. Runtime container images (Keycloak on Quay, Node-RED on GHCR, etc.) are all auth-free. `deploy-infra.sh` injects credentials via MicroK8s's `certs.d/docker.io/hosts.toml` and `helm3 registry login`.

**`grep -c` + `set -e` pitfall:** `grep -c` exits 1 when the match count is 0. Combined with `|| echo 0`, this appends a second `0` to stdout (producing `"0\n0"`), causing `[ "$VAR" -eq 0 ]` to fail with "integer expression expected". All wait-loop counters use `grep -c ... || true` to let grep's own `0` output pass cleanly.

## Helm Chart Versions (Pinned)

| Service      | Chart / Image                      | Version |
|--------------|------------------------------------|---------|
| PostgreSQL   | bitnami/postgresql (OCI)           | 18.4.0  |
| Keycloak     | quay.io/keycloak/keycloak (kubectl)| 26.0    |
| Grafana      | grafana/grafana                    | 7.3.12  |
| Node-RED     | node-red/node-red (schwarzit)      | 0.40.0  |
| OAuth2 Proxy | bitnami/oauth2-proxy (OCI)         | 8.0.2   |

## Common Pitfalls

- **Never add `set -e` before `source config.env`** in a script that has a `--help` flag — the help branch must run before `set -e` and before sourcing so it works without a config file.
- **`microk8s status --wait-ready` exits immediately** on a fresh install before the daemon socket exists. The readiness check uses a retry loop with a deadline, not a one-shot call.
- **Juju controller existence is the skip guard** (not kubeflow namespace or pod count). Re-running bootstrap when `k8s-controller` exists skips the entire Kubeflow install block.
- **bitnami/keycloak image is behind a paywall** since August 28, 2025. Use the official `quay.io/keycloak/keycloak:26.0` image via plain kubectl manifests instead of the Bitnami Helm chart. `bitnami/postgresql` is still free. Health probes use port 9000 (management interface); the main app runs on 8080.
- **Keycloak 26.0 tag exists on quay.io** — use `26.0`, not `26` (which doesn't exist) or `26.x.y` patch tags.
- **schwarzit/node-red chart splits image into registry+repository+tag** — set `image.registry=docker.io`, `image.repository=nodered/node-red`, `image.tag=3.1.9`. Setting `image.repository=ghcr.io/node-red/node-red` causes the chart to prepend `docker.io`, producing the invalid URL `docker.io/ghcr.io/...`.
- **`microk8s enable` chaining** — MicroK8s 1.33+ warns that space-separated addon lists will be deprecated. Enable each addon with a separate `microk8s enable` call.
- **Dex-auth has NO ConfigMap** in Charmed Kubeflow 1.9. It is a Juju-managed StatefulSet. Config is applied via `juju config dex-auth connectors=<yaml>`. The `connectors` value is a YAML string containing a list of Dex connector definitions.
- **dex-auth connector redirectURI** must be `http://${KUBEFLOW_DOMAIN}/dex/callback` — this is Dex's own callback endpoint where Keycloak redirects after authentication. Do NOT use the oidc-gatekeeper callback (`/authservice/oidc/callback`) here. Use KUBEFLOW_DOMAIN (nip.io), NOT KUBEFLOW_IP (LAN IP).
- **dex-auth issuer-url must use KUBEFLOW_DOMAIN** — set via `juju config dex-auth "issuer-url=http://${KUBEFLOW_DOMAIN}/dex"`. This controls `OIDC_PROVIDER` in the oidc-authservice. The authservice constructs its callback URL (`redirect_uri`) using the OIDC_PROVIDER host. If OIDC_PROVIDER uses `192.168.1.200` (MetalLB IP) but users access Kubeflow via the nip.io domain, the CSRF cookie is set for nip.io but the callback goes to `192.168.1.200` — CSRF check fails. Using KUBEFLOW_DOMAIN for issuer-url ensures the full OIDC flow (auth URL, callback) stays on the same nip.io domain.
- **dex-auth connector requires `insecureSkipVerify: true`** — the nginx ingress has a self-signed cert valid for `ingress.local`, not the actual Keycloak hostname. Without this, Dex fails to fetch the OIDC discovery endpoint and exits with code 2.
- **juju status wait loop** — check unit-level juju-status (`grep -A1 "juju-status:" | grep "current:"`), not the first `current:` in the output (which is the workload status and always shows `available`).
- **Keycloak realm "HTTPS required" blocks HTTP callbacks** — production mode defaults to `ssl_required: external`. OAuth2 Proxy and Dex use HTTP callback URIs (no TLS on ingress), so the realm must have `ssl_required: none`. Set via Admin API: `PUT /admin/realms/{realm}` with `{"sslRequired":"none"}` (use kubectl port-forward to reach Keycloak internally).
- **OAuth2 Proxy defaults to `google` provider** — must set `provider = "oidc"` in `configuration.content` values file. Without it, the login button says "Sign in with Google" even with `oidcIssuerUrl` set.
- **PostgREST does not strip quotes from a filter value** — `?dns_name=eq."UNIT01_SENSE_ZONE01"` matches nothing (it looks for a value that literally starts with a quote) and returns `[]`, which reads exactly like "no such row". Percent-encode the value instead; do not wrap it in double quotes.
- **A retry on any `23505` is wrong.** The `device`/`component` sequences trail the table because the seed import supplied explicit ids, so a *primary key* collision is worth retrying (each attempt burns one nextval). A collision on `dns_name` is a slot that already has a board, and retrying turns one clear error into thirty requests and a wrong diagnosis. Check which key is named in the error.
- **`while read ...; done < <(cmd)` gives its stdin to the loop BODY too** — so any prompt inside the loop reads from `cmd`'s output instead of the terminal, silently answering the question with the next line of data. Use `for x in "${arr[@]}"` with `IFS=$'\t' read -r ... <<<"$x"`, which redirects only that one `read`.
- **`ask()` must die on EOF, not return empty** — a re-asking prompt loop (`menu_ask`) spins forever when stdin is closed (`< /dev/null`, cron, a detached `timeout`).
- **`ujson.dumps()` will not serialise `bytes`** — `ubinascii.hexlify(machine.unique_id())` returns bytes, and putting it straight into a payload raises rather than publishing. `.decode()` it once, in `config.py`. A `str` there also matches `medcea.device.serial_number` exactly.
- **ESP32-P4 flash pins are package pins, not GPIOs** — the P4 datasheet's flash table (FLASH_CK = 32, FLASH_CS = 27 …) lists *package pin* numbers. Mapping those onto GPIO numbers would wrongly blacklist GPIO27-33. The P4's flash is on dedicated pins and its PSRAM is in-package, so unlike every other ESP32 it loses no GPIO to memory at all.
- **Changing the board in the form does not rewrite the map** — it re-checks the same table against different silicon, and the errors that appear are the point. Silently dropping the pins the new chip lacks would hide exactly what the operator needs to see.
- **The browser prompt loop re-renders on every poll** — `renderPrompt()` returns early when `p.id === curId`, and that guard is what keeps the channel-map editor from being re-mounted (and the operator's half-finished edits thrown away) once a second. Any new rich prompt kind must keep it.
- **An edited channel map is authoritative, not a hint** — when the wizard returns a table, `render()` uses it verbatim (`spec["actuator_config"]`) instead of re-deriving from `functions`. Re-deriving would silently discard the edit the operator was just shown and approved.
- **`ALTER ROLE postgres SET search_path TO medcea, public` breaks Keycloak** — Keycloak connects as `postgres` and has its own tables (e.g. `COMPONENT`) in the `public` schema. If `medcea` is first in the search_path, PostgreSQL finds `medcea.component` (our IoT table) instead, causing `column realm_id does not exist` crash-loops. Set `search_path` on the `authenticator` role (PostgREST) only, never on `postgres`.
