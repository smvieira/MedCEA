# MedCEA

**Medicinal Controlled Environment Agriculture** is an open IIoT platform for the reproducible,
regulatory-compliant production of bioactive compounds in medicinal mushrooms and plants. It is the
prototype artefact of the MedCEA PhD project (ISCTE-IUL). The concept is in
[docs/medcea-concept.md](docs/medcea-concept.md). [docs/architecture.md](docs/architecture.md) maps the
four-layer stack and the Compliance Plane to this code and lists what is still to be built. The
baseline was forked from `pfplatform`. Licensed under [MIT](LICENSE).

An IoT platform deployer for Ubuntu. Two commands install and wire together a complete stack on a single machine running MicroK8s, then deploy application content on top of it:

| Service | Purpose | Access |
|---|---|---|
| **Keycloak** | SSO / Identity Provider (realm: `medcea`) | `https://keycloak.<domain>` |
| **Portal** | Service catalog landing page (SSO) | `https://portal.<domain>` |
| **User Manager** | Access requests, users, roles, e-mail (admins) | `https://access.<domain>` |
| **Grafana** | Dashboards — reads from Postgres | `https://grafana.<domain>` |
| **Node-RED** | Flow-based IoT logic (behind SSO) | `https://node-red.<domain>` |
| **Mosquitto** | MQTT broker (every client authenticates) | `mqtt://<LAN-IP>:31883` |
| **MQTT Explorer** | Browser-based MQTT topic browser | `https://mqtt-explorer.<domain>` |
| **AI Workbench** | JupyterHub — notebooks and VS Code, per-user (SSO) | `https://ai-workbench.<domain>` |
| **Recipe Schedule Manager** | Schedule grow recipes, manage unit permissions, run/stop cycles | `https://scheduler.<domain>` |
| **Run Monitor** | Live view of active recipe runs, cycle progress, and sensor readings vs limits | `https://monitor.<domain>` |
| **System Configuration** | Manage locations, units, devices, recipes | `https://config.<domain>` |
| **Database Management** | Browse/export the PostgreSQL `medcea` schema | `https://dbmgmt.<domain>` |
| **pgAdmin** | PostgreSQL web UI | `https://pgadmin.<domain>` |
| **PostgreSQL** | Shared database | internal only |

**Sign-in.** Every web UI signs in through Keycloak, on one platform sign-in page
(in the platform's own theme): see [Users and access](#users-and-access). Any
platform role opens the services; the User Manager and **pgAdmin** need the
`admin` role. The **MQTT broker** admits nobody anonymously either: each board
has its own credential from onboarding, and each platform service its own
account — see [Connecting IoT devices to MQTT](#connecting-iot-devices-to-mqtt).

Re-running either deploy script is safe — work already done is detected and skipped.

---

## Requirements

- Ubuntu 22.04 or 24.04 (bare metal or VM)
- 16 GB RAM minimum (24 GB comfortable with the AI workbench in use)
- 100 GB disk
- Internet access
- Nothing else needs to be installed beforehand. Both `./deploy-infra.sh` and `./deploy-apps.sh` first check for the host packages a clean Ubuntu may lack: `curl` (missing on 24.04 desktop), `ca-certificates`, `openssl`, `python3`, `python3-venv` (needed by `edge/flash-device.sh`), `iproute2` and `snapd`. They list what is missing and why, and offer to `apt-get install` it.
- A free [Docker Hub](https://hub.docker.com) account — needed to pull the Bitnami Helm charts and avoid Docker Hub rate limits. You don't need to prepare anything: the installer links to sign-up and token creation, says which permission to pick, and checks the token.
- (Optional, recommended) [Tailscale](https://tailscale.com) — a fixed address reachable from any of your devices, at home or away, with no DNS or router setup. The installer checks for it on every run, prints the steps if it is missing, stopped or not logged in, and can run them for you. You can also continue LAN-only.

---

## Installation

### 1. Clone

```bash
git clone <repo-url> MedCEA
cd MedCEA
```

### 2. Install

```bash
./install.sh
```

One command installs everything: the infrastructure, then the applications, then a health check. `./install.sh --help` lists every option:

| Command | Does |
|---|---|
| `./install.sh` | install or update everything (safe to re-run) |
| `./install.sh --configure` | review every setting first, then install |
| `./install.sh --infra-only` / `--apps-only` | one half only |
| `./install.sh --uninstall-apps [component ...]` | remove application components; data kept (`--purge-data` drops the database) |
| `./install.sh --uninstall-infra` | remove every service and all data; keep MicroK8s |
| `./install.sh --uninstall-all` | total uninstall, MicroK8s included |

If a stage fails, the installer names it and its log; fix the cause and run `./install.sh` again.

**It starts by asking for its settings.** There is no file to edit by hand: on the first run it creates `config.env` from [config.env.example](config.env.example) and asks for each setting, with the default in `[brackets]` (press Enter to accept):

| Asked | Default |
|---|---|
| Tailscale | checked on every run. If it is missing, stopped or not logged in, the installer prints the steps (with links), then lets you re-check, run them for you, or continue LAN-only |
| Project name | `medcea` |
| Domain | with Tailscale: the name `medcea` (`https://ai-workbench.medcea`); otherwise your LAN IP + `.nip.io` |
| Admin username / password | `admin` / generated if you press Enter (shown once — note it down) |
| PostgreSQL password, volume size | generated / `10Gi` |
| Docker Hub username + access token | none: the installer links to sign-up and token creation and checks the pair |
| Timezone, AI workbench on/off | system timezone / on |

Passwords may use only letters, digits and `. _ ~ -`, because they are written unescaped into URLs and YAML. Service secrets (OAuth clients, cookies) are generated later in the run, with no questions.

On later runs only required values that are still empty are asked, so a complete `config.env` deploys straight through. To review or change settings:

```bash
./deploy-infra.sh --configure   # all questions, current values as defaults, then deploy
./infra/configure.sh            # all questions only, no deploy
```

Each run rebuilds `config.env` from the template and keeps your values, so variables added to the template later show up automatically. The previous file is saved as `config.env.bak`. If `DOMAIN` uses the Tailscale IP and Tailscale is down, the deploy stops rather than quietly switching to the LAN IP.

> **Domain:** with the name option, services are `https://<service>.medcea`; see [Name-based access](#name-based-access-servicemedcea) for the one Tailscale setting it needs. The nip.io option resolves every `<service>.<IP>.nip.io` to that IP with no setup at all. Changing `DOMAIN` after deployment means re-running `./install.sh` (certificates and SSO redirects use it).

#### Name-based access (`<service>.medcea`)

Choosing the name option in the installer sets `DOMAIN="medcea"` and `LOCAL_DNS="true"`. The install then:

- runs a small DNS server (`name-dns`, CoreDNS) on this machine's Tailscale IP, port 53, answering every `*.medcea` name with that IP;
- maps the names in this machine's `/etc/hosts`, so the server itself resolves them straight away;
- issues the certificate with every service name listed explicitly, because browsers reject a wildcard like `*.medcea` directly on a one-word name;
- turns the old `<service>.<IP>.nip.io` addresses into permanent redirects to the new names (`ALIAS_DOMAIN`), so bookmarks keep working.

**One manual step, once per tailnet:** tell Tailscale to send lookups for `medcea` to this server. The installer checks whether this is in place and prints these steps if not:

1. Open <https://login.tailscale.com/admin/dns>.
2. Nameservers → **Add nameserver** → **Custom…**
3. Nameserver: this machine's Tailscale IP (`tailscale ip -4`). Turn on **Restrict to domain** (Split DNS), domain `medcea`, then **Save**.
4. Devices need **Use Tailscale DNS settings** turned on, which is the default. On Linux: `sudo tailscale set --accept-dns=true`.

After **rebuilding the server** it gets a new Tailscale IP, but the entry above
keeps pointing at the old one: edit it to the new IP. The deploy warns when the
two differ and prints the exact change.

Test from any device with `nslookup portal.medcea`, then open `https://portal.medcea`. Type the `https://` the first time: browsers treat a one-word ending as a search until they have visited it.

> **TLS:** every service is served over HTTPS with a certificate the platform issues itself. See [Trust the platform certificate](#4-trust-the-platform-certificate) — without it browsers show "Not secure".

After the settings, the infrastructure stage (`deploy-infra.sh`) does:


1. **Bootstraps MicroK8s** — installs the snap, enables addons (dns, ingress, helm3, hostpath-storage, rbac), exports kubeconfig
2. **Issues the platform CA** and a certificate listing every service name, and publishes it as the `cea-tls` secret
3. **Deploys PostgreSQL** (Bitnami Helm chart)
4. **Deploys Keycloak** (official `quay.io/keycloak/keycloak:26.0` image, HTTPS ingress) with the `medcea` login theme
5. **Creates Keycloak realm `medcea`**: confidential OAuth2 clients for `node-red`, `grafana`, `workbench`, `portal`, `config`, `access` and `edge-wizard` (secrets written to `config.env`), the platform roles `operator` / `qa` / `auditor` / `admin`, the `groups` scope the portal checks, and the `organisation` profile field
6. **Deploys Mosquitto** (MQTT broker — TCP port 31883 for the boards; password + ACL authentication kept in sync from the database by a sidecar)
7. **Deploys Node-RED** behind OAuth2 Proxy (Keycloak SSO)
8. **Deploys Grafana** with Keycloak SSO and PostgreSQL datasource pre-wired
9. **Deploys pgAdmin** with PostgreSQL connection pre-configured and Keycloak sign-in (admins only)
10. **Deploys the Service Portal** (service catalog, Keycloak SSO)
11. **Deploys the AI Workbench** (JupyterHub, authenticated directly against Keycloak) unless `WORKBENCH_ENABLED=false`

Then the applications stage (`deploy-apps.sh --all`, next section) and `health-check.sh` run. Progress is logged to `logs/deploy-infra-<timestamp>.log` and `logs/deploy-apps-<timestamp>.log`.

**At the very end it shows your credentials.** Every password a person needs (platform admin, Keycloak, Grafana users, pgAdmin, PostgreSQL) is written to `credentials-<timestamp>.txt` in the repository root, readable only by you. Its content is shown on the terminal, never in the log. **Save it in a password manager, then delete the file**; the installer prints the exact `rm` command and lists any files left over from earlier runs. `config.env` keeps its own copy, because re-deploys need it.

> **Note:** Charmed Kubeflow was retired — it cost 37 Juju charm units and nothing in the codebase used it. JupyterHub replaced it and authenticates against Keycloak directly, which also removed Dex, oidc-gatekeeper, Istio, MetalLB and the static LAN IP.

### 3. Application components

`./install.sh` installs all of them. To pick components by hand, run `./deploy-apps.sh`: an interactive menu lets you choose which application components to install:

```
  [ ] 1. Database
  [ ] 2. Node Red

  a  Select all    n  Select none
  ↵  Install selected components
  q  Quit
```

Toggle items by number, confirm with Enter. Use `./deploy-apps.sh --all` to skip the menu and install everything.

Each component has an `uninstall.sh` next to its `deploy.sh`, which removes exactly what that deploy created. Use `./install.sh --uninstall-apps monitor scheduler` (or `./deploy-apps.sh --uninstall …`); reinstall with `./install.sh --apps-only`. Uninstalling greys out the component's portal card, and reinstalling restores it.

Currently available components:

| Component | What it installs |
|---|---|
| **access** | Access requests, the **User Manager**, the user menu and Profile — see [Users and access](#users-and-access) |
| **database** | `medcea` schema, measurement table, and DB migrations (control algorithms, permissions, algorithm state) |
| **edge-wizard** | The device onboarding wizard as a host service (`https://onboard-device.<domain>`), for flashing boards over USB |
| **frontend** | System Configuration UI and Database Management portal |
| **node-red** | `node-red-contrib-postgresql` package + MQTT→PostgreSQL flow |
| **monitor** | Run Monitor dashboard (live recipe runs) |
| **mqtt-explorer** | Browser MQTT tool, behind sign-in; talks to the broker as its own service account |
| **report** | Grafana dashboard definitions |
| **scheduler** | Recipe Schedule Manager Flask API and browser UI |

---

### 4. Trust the platform certificate

Every service is served over HTTPS using a certificate the platform issues
itself. Until you trust its CA, browsers show **"Not secure"** and `curl` refuses
to connect.

**Why not a real certificate?** Because it is impossible for these hostnames.
`DOMAIN` resolves to a Tailscale (CGNAT) or LAN address, so Let's Encrypt cannot
reach the host for an HTTP-01 challenge, and nip.io's DNS is not ours for
DNS-01. A private CA is the only option that gives TLS here — the alternative is
plain HTTP, which makes JupyterHub disable its XSRF checks and sends every
session cookie in clear.

`deploy-infra.sh` creates the CA once, on first run, at `.ca/ca.crt`. It is
**reused on every later deploy** — including `--reset` — so a client you trust
today keeps working. Only deleting `.ca/` invalidates it, and then every client
must be redone. `.ca/` is gitignored: the private key must never be committed.

#### Get the certificate and check what you are trusting

On the platform host:

```bash
openssl x509 -in .ca/ca.crt -noout -subject -dates -fingerprint -sha256
```

Note that SHA-256 fingerprint — it is unique to your installation — and confirm
it matches after importing. Then copy the file to the machine you browse from:

```bash
scp <user>@<platform-host>:<repo-path>/.ca/ca.crt ./cea-ca.crt
```

In case `scp` stops with `REMOTE HOST IDENTIFICATION HAS CHANGED`: the name or
IP you used belonged to an earlier server (a rebuild, or a Tailscale machine
renamed to take over the name). Your SSH client remembers the old server's key
in `~/.ssh/known_hosts` and refuses the new one. Forget it and retry:

```bash
ssh-keygen -R <platform-host>      # the same name or IP you gave scp
```

It removes only that one entry (a backup is kept as `known_hosts.old`). On the
retry, accept the new key only if its fingerprint matches the server's, which
you can read on the platform host with
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. The install summary prints it
next to the `scp` command.

The file is the public half of the CA. It is safe to copy around; the private
key stays in `.ca/ca.key` on the server.

#### Windows — Chrome and Edge

Both use the Windows certificate store.

Just for your Windows user (no admin needed, any PowerShell). Windows asks to confirm: check the fingerprint, then click **Yes**:

```powershell
certutil -user -addstore Root .\cea-ca.crt
certutil -user -store Root | Select-String "CEA Platform CA"
```

For every user on the PC, in **PowerShell as Administrator** (Win+X → Terminal (Admin)). In a normal window this fails with `0x80070005 ERROR_ACCESS_DENIED`:

```powershell
certutil -addstore -f "Root" .\cea-ca.crt
certutil -store Root | Select-String "CEA Platform CA"
```

Then quit Chrome completely — every window, since it caches certificate state —
and reopen.

Double-clicking the file works too, but you must choose **Local Machine** and
then *Place all certificates in the following store* → **Trusted Root
Certification Authorities**. Accepting the default of "Personal" is the usual
reason the warning does not go away.

#### Firefox — any OS

Firefox ignores the system store and keeps its own:

**Settings → Privacy & Security → Certificates → View Certificates →
Authorities → Import** → select `cea-ca.crt` → tick **"Trust this CA to identify
websites"**.

#### Linux

System store, used by `curl` and most command-line tools:

```bash
sudo cp cea-ca.crt /usr/local/share/ca-certificates/cea-platform.crt
sudo update-ca-certificates
```

Chrome and Chromium ignore that store on Linux and keep their own (NSS):

```bash
sudo apt install -y libnss3-tools
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "MedCEA Platform CA" -i cea-ca.crt
# snap Chromium: certutil -d sql:$HOME/snap/chromium/current/.pki/nssdb ...
```

Then quit Chrome completely and reopen it.

`./install.sh` prints all of these at the end, with this installation's host, path and fingerprint filled in.

#### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain cea-ca.crt
```

#### Confirm

```bash
curl -sI https://config.<domain>/
```

No certificate complaint means it is trusted, and the browser shows a padlock
instead of "Not secure".

> Every person and every browser that uses the platform needs this once. That is
> the standing cost of a private CA. The way to remove it is a domain you own:
> point it at the host and use a DNS-01 ACME challenge, which keeps the current
> subdomain layout and gives publicly trusted certificates.

---

## Service URLs

After deployment the summary section of the log shows all URLs. The pattern is:

```
Portal:        https://portal.<domain>          (start here — Keycloak SSO)
User Manager:  https://access.<domain>          (access requests — realm role admin)
Request access: https://access.<domain>/register (opens the Request access tab of the sign-in page)
Profile:       https://<any signed-in host>/_account/  (also from the name in the top-right)
Keycloak:      https://keycloak.<domain>       (admin / <ADMIN_PASS>)
Grafana:       https://grafana.<domain>         (login via Keycloak)
Node-RED:      https://node-red.<domain>        (login via Keycloak)
AI Workbench:  https://ai-workbench.<domain>   (JupyterHub — login via Keycloak)
Run Monitor:   https://monitor.<domain>         (live run progress + sensor readings)
Config UI:     https://config.<domain>          (locations, units, devices, recipes)
DB Mgmt:       https://dbmgmt.<domain>          (browse/export medcea schema)
Scheduler:     https://scheduler.<domain>       (recipe schedules)
Onboarding:    https://onboard-device.<domain>  (device wizard, runs on the host — login via Keycloak)
pgAdmin:       https://pgadmin.<domain>         (Keycloak sign-in, role admin)
MQTT Explorer: https://mqtt-explorer.<domain>   (browser MQTT tool; its broker socket is wss://…/mqtt)
Mosquitto:     mqtt://<LAN-IP>:31883           (boards on the LAN, per-device credentials)
Postgres:      rdbms-postgresql.medcea.svc.cluster.local:5432  (internal)
```

With the default nip.io setup and a Tailscale IP of `100.94.119.12`, for example:

```
Portal:        https://portal.100.94.119.12.nip.io
Keycloak:      https://keycloak.100.94.119.12.nip.io
Grafana:       https://grafana.100.94.119.12.nip.io
Node-RED:      https://node-red.100.94.119.12.nip.io
MQTT Explorer: https://mqtt-explorer.100.94.119.12.nip.io
```

---

## Users and access

### Signing in

Every signed-in service sends you to **one sign-in page** — Keycloak, wearing the
platform's look (the `medcea` theme in [k8s/keycloak/theme/](k8s/keycloak/theme/)).
It has two tabs: **Sign in** and **Request access**. *Forgot password?* appears
once e-mail is set up (below).

On the portal, the System Configuration UI and the User Manager, your **name**
sits in the top-right corner. It opens:

- **Profile** — change your first name, last name and organisation (username
  and e-mail are fixed; an admin changes those), and **Change password**, which
  uses Keycloak's own page in the same look, so no password passes through the
  platform's code.
- **Sign out** — ends the session everywhere, not only on that page.

Node-RED, Grafana and JupyterHub keep their own built-in user menus.

### Roles

Each account holds **one** platform role. The access policy
([apps/iam/policy/defaults.yaml](apps/iam/policy/defaults.yaml)) defines eleven;
the request form and the User Manager offer these five for now, the rest once
the services enforce the policy themselves:

| Role | Meant for |
|---|---|
| `operator` | running recipes and day-to-day cultivation in your zones |
| `engineer` | devices, recipes, controllers, flows and dashboards (drafts that qa approves) |
| `qa` | approving others' work, confirming account grants and policy changes |
| `auditor` | read-only access to records and audit trails |
| `admin` | managing the platform and its users — without access to production data |

Which role reaches which service is **compiled from the policy** into the sign-in
gates of the portal, Config UI, scheduler, Monitor, Database Management, MQTT
Explorer and Node-RED. `python3 apps/iam/compiler/cli.py hosts` lists every host
with the roles it admits and whether that gate is enforced yet; Grafana, the AI
Workbench, onboarding and the User Manager (admin only) follow in later phases.
Finer permissions inside each service are the next steps of the IAM plan.

**Existing accounts after this change** keep their role and its meaning, but
some lose services the policy does not give them:

| Account | Role | Loses | Still reaches |
|---|---|---|---|
| `admin` (platform) | admin | Monitor, Database Management, MQTT Explorer, Node-RED | portal, Config UI, scheduler, User Manager, pgAdmin, Grafana, Workbench |
| `developer` | operator | Database Management, MQTT Explorer, Node-RED | portal, Config UI, scheduler, Monitor |
| `viewer` | auditor | MQTT Explorer, Node-RED | portal, Config UI, scheduler, Monitor, Database Management |
| `QA_USER` (new) | qa | — | as auditor, plus approvals |
| `ENGINEER_USER` (new) | engineer | — | Node-RED, MQTT Explorer and everything an engineer drafts |

The install creates two people from `config.env`, each with a temporary password
(and no name yet — Keycloak asks for both at first sign-in): the first **qa
person** (`QA_USER`), because every account grant and every policy change is
confirmed by someone holding qa who is not the administrator; and the first
**engineer** (`ENGINEER_USER`), because only engineers reach Node-RED and the
MQTT Explorer. If you are the administrator and also the one editing flows, the
engineer is your second account, with its own username and e-mail (Gmail:
`name+engineer@gmail.com`). **Keycloak's own console** (`https://keycloak.<domain>/admin`) has a
separate break-glass account, `kc-breakglass`, listed in the credentials file; it
is for recovery only, and every use of it is recorded.

### Getting access

1. The person opens **Request access** on the sign-in page and gives name, e-mail,
   organisation, username, password, the **role they need** and a **business
   justification**. Their account is created **disabled**: they cannot sign in yet.
2. Every admin (every enabled user with role `admin`, plus the extra addresses in
   E-mail settings) gets an e-mail linking to the User Manager.
3. In **User Manager → Requests** the admin approves with the requested role,
   approves with a **different** role, or rejects. Notes are optional for an
   approval and required for a rejection.
4. The applicant's e-mail is pre-filled from the matching template, follows the
   decision as it changes, and can be edited before sending (or not sent).
   Approval enables the account with the granted role; rejection deletes the
   disabled account, so the person can apply again.

### Managing users

**User Manager → Users** lists every account with its role and status (Active,
Inactive, Awaiting approval), with search. For a selected person:

- **Deactivate account** — needs a reason; signs them out everywhere at once and
  blocks sign-in. Role and data are kept. **Activate account** reverses it.
- **Change role** — one role replaces the other; needs a reason; takes effect
  within about four minutes, without signing out.

You cannot deactivate or change the role of your own account, nor leave the
platform without an active admin. An account still awaiting approval is decided
under **Requests**.

### E-mail

E-mail is configured in the **User Manager**, not in `config.env`:

- **E-mail settings** — the Gmail address and its **app password**
  (<https://myaccount.google.com/apppasswords>; needs 2-Step Verification), the
  sender name and extra people to notify about new requests. *Save and verify*
  logs in to Gmail before storing anything; *Send test e-mail to me* proves
  delivery. The same account becomes Keycloak's mail server, which is what turns
  on *Forgot password?*. Until it is set, decisions still work and the messages
  go to the service log (`microk8s kubectl logs -n medcea deploy/access`).
- **Templates** — the four messages (new request, approved, approved with role
  reassigned, rejected), with click-to-insert placeholders such as `$first_name`,
  `$granted_role_label` and `$notes_block`. *Reset to default* returns to the
  files in [apps/access/templates/](apps/access/templates/).

### What is recorded

Every action above leaves a record that the platform can add to but never edit
or delete (the Compliance Plane rule):

| Record | Holds |
|---|---|
| `iam.access_request_history` | each request and decision: who, when, requested vs granted role, notes |
| `iam.access_request` | the request itself, plus the exact e-mail sent with the decision |
| `iam.user_status_history` | deactivations, activations and role changes: who, whose account, from/to, why |
| `iam.config_history` | changes to e-mail settings and templates (never the password) — **Change log** tab |

---

## Connecting IoT devices to MQTT

**Every MQTT client authenticates.** The broker has no anonymous access:

| Client | Username | Password | May |
|---|---|---|---|
| A board | its name, e.g. `unit01-s-zone01` | minted at onboarding, written to the board and to `edge/provisioned/<name>.json` | SENSE: publish `<root>/<UNIT>/<ZONE>/sense/#`; CONTROL: receive `…/control/#`, publish `…/control_setpoint/#` |
| Node-RED | `node-red` | `MQTT_NODE_RED_PASS` (config.env) | read `<root>/#` |
| Scheduler | `scheduler` | `MQTT_SCHEDULER_PASS` | read `…/sense/#`, publish `…/control/#` |
| MQTT Explorer | `mqtt-explorer` | `MQTT_EXPLORER_PASS` | read and publish `<root>/#` |

The root is `PROJECT_NAME` (`medcea`). Board credentials come only from the
onboarding wizard, which registers the password's hash in the database;
re-onboarding a board gives it a new password. **Marking a device inactive in
the Config UI locks it out of the broker within about 15 seconds.** Boards
flashed before broker authentication have no credential: re-onboard them.

| Transport | Address | Port | Use |
|---|---|---|---|
| MQTT (TCP) | `<server-LAN-IP>` | `31883` | boards on the LAN |
| MQTT (TCP) | `mosquitto.medcea.svc.cluster.local` | `1883` | services in the cluster |
| WebSocket | `wss://mqtt-explorer.<domain>/mqtt` | 443 | only through the MQTT Explorer's sign-in |

### Finding the server address

**LAN IP** (for IoT devices on the same network):
```bash
ip route get 8.8.8.8 | awk '/src/{print $7}'  # run on the server
```

> **Stability tip:** The LAN IP can change if your router reassigns it via DHCP. To avoid breakage, set a **DHCP reservation** in your router for the server's MAC address. Alternatively, IoT devices on the LAN can resolve the server by hostname: `<hostname>.local:31883` (requires Avahi/mDNS, which is installed by default on Ubuntu Desktop).

### Connection examples

The platform's own boards are configured by the onboarding wizard; these are for
other clients. Use a credential with the topics it is allowed (table above).

**MicroPython (umqtt.simple)**

```python
from umqtt.simple import MQTTClient

client = MQTTClient("unit01-s-zone01-test", "192.168.1.102", port=31883,
                    user="unit01-s-zone01", password="<from edge/provisioned/unit01-s-zone01.json>")
client.connect()
client.publish(b"medcea/UNIT01/ZONE01/sense/humidity", b"65")
client.disconnect()
```

**Python (paho-mqtt)** — e.g. from the AI Workbench, read-only as Node-RED's account:

```python
import paho.mqtt.client as mqtt

client = mqtt.Client(client_id="notebook-reader")
client.username_pw_set("node-red", "<MQTT_NODE_RED_PASS from config.env>")
client.connect("mosquitto.medcea.svc.cluster.local", 1883)

def on_message(client, userdata, msg):
    print(f"{msg.topic}: {msg.payload.decode()}")

client.subscribe("medcea/#")
client.on_message = on_message
client.loop_forever()
```

**Command line**

```bash
mosquitto_sub -h <server-LAN-IP> -p 31883 -u mqtt-explorer -P "$MQTT_EXPLORER_PASS" -t 'medcea/#' -v
```

**Node-RED** — the platform flow's broker node is configured by
`apps/node-red/deploy.sh` (server `mosquitto.medcea.svc.cluster.local:1883`,
user `node-red`). A new flow can reuse that broker node.

### Browser-based MQTT Explorer

Open **https://mqtt-explorer.\<domain\>** (sign-in required). It connects to the
broker over `wss://mqtt-explorer.<domain>/mqtt` as the `mqtt-explorer` account
and shows everything under the topic root. Click any topic to see its message
history; use the Publish panel at the bottom to send messages.

### Recommended topic structure

There is no enforced topic schema — use whatever works for your project. A common convention for IoT platforms:

```
sensors/<device-id>/<metric>       # e.g.  sensors/esp32-01/temperature
actuators/<device-id>/<command>    # e.g.  actuators/relay-01/state
status/<device-id>/online          # e.g.  status/esp32-01/online
```

---

## Application content (`apps/`)

Application content (flows, schemas, etc.) lives in `apps/` and follows a **separate lifecycle** from infrastructure — you can update flows or add new applications without re-running `deploy-infra.sh`.

### Structure

```
apps/
├── database/
│   ├── medcea_db_ddl.sql          # Schema DDL (plain SQL, schema `medcea`)
│   ├── medcea_db_migrations.sql   # Idempotent migrations (algorithms, permissions, state)
│   └── deploy.sh                  # Apply schema + migrations to PostgreSQL via kubectl exec
├── frontend/
│   ├── deploy.sh           # Deploy System Configuration UI + Database Management portal
│   ├── html/               # SPA source (index.html, dbmgmt.html)
│   ├── recipes/            # Platform recipe library (JSON files, served by nginx)
│   ├── devices/            # Platform device library (JSON files)
│   ├── units/              # Platform unit library (JSON files)
│   └── locations/          # Platform location library (JSON files)
├── node-red/
│   ├── flows/
│   │   └── message-processing.json   # Flow template (MQTT → PostgreSQL pipeline)
│   ├── packages.txt        # Required Node-RED contrib packages
│   └── deploy.sh           # Deploy packages + flows to Node-RED
├── monitor/
│   ├── deploy.sh           # Deploy Run Monitor to Kubernetes
│   ├── monitor-api.py      # Flask read-only API (active runs, steps, measurements)
│   └── html/
│       └── monitor.html    # Live run dashboard SPA
├── report/
│   ├── dashboards/         # Grafana dashboard JSON definitions
│   └── deploy.sh           # Import dashboards into Grafana
└── scheduler/
    ├── deploy.sh           # Deploy scheduler API + UI to Kubernetes
    ├── scheduler-api.py    # Flask REST API (run management, live log streaming)
    └── html/
        └── scheduler.html  # Recipe Schedule Manager browser UI
```

### Flow connection placeholders

Flow templates use placeholders substituted at deploy time with in-cluster K8s DNS names:

| Placeholder | Resolved value |
|---|---|
| `__MQTT_HOST__` | `mosquitto.<namespace>.svc.cluster.local` |
| `__PG_HOST__` | `rdbms-postgresql.<namespace>.svc.cluster.local` |
| `__PG_PORT__` | `5432` |
| `__PG_DB__` | `POSTGRES_DB` from config.env (default: `postgres`) |
| `__PG_USER__` | `POSTGRES_USER` from config.env (default: `postgres`) |
| `__PG_PASS__` | `POSTGRES_PASS` from config.env |

Using K8s service names instead of IPs ensures flows keep working even if pods are restarted or IPs change.

### Adding a new flow

1. Export the flow from the Node-RED UI (Menu → Export → selected flow → JSON)
2. Replace hardcoded IPs / credentials with the `__PLACEHOLDER__` values above
3. Save as `apps/node-red/flows/<name>.json`
4. Re-run `./deploy-apps.sh`

### Adding a new application component

Create a new subfolder — `deploy-apps.sh` discovers it automatically:

```
apps/<app-name>/
├── deploy.sh       # Idempotent deploy script (sources config.env)
└── ...             # App-specific assets
```

---

## Recipe Schedule Manager

The **Recipe Schedule Manager** (`https://scheduler.<domain>`) provides a browser UI and Flask REST API for running growth recipes against CEA production units.

Key capabilities:

- **Recipe ↔ Unit Permissions matrix** — grant or revoke which recipes may run on which units; set a default control algorithm and parameter overrides per permission
- **Schedule triggers** — start a recipe run on demand or via a cron-style schedule
- **Live log streaming** — tail the run log in the browser while a cycle is executing
- **Run history** — view past runs with status (Running / Completed / Failed / Stopped)

**Algorithm selection chain** — when a run starts, the algorithm is resolved as:

1. Schedule-level override (set at trigger time in the UI)
2. Permission-level default (set in the Permission Settings gear icon of the matrix)
3. System default: `IF_THEN_ELSE`

See [Control Algorithms](#control-algorithms) for the full list of available algorithms.

The scheduler mounts `schd/` from the host filesystem into the pod, so Python changes under `schd/` take effect on the next run without redeploying.

---

## Monitoring active recipe runs

### Checking for running processes

Each recipe run spawns a `run_recipe.py` subprocess on the host. To check what is currently running:

```bash
# List all active run_recipe processes (empty = nothing running)
ps aux | grep run_recipe.py | grep -v grep

# Count only — 0 means nothing running
pgrep -c -f run_recipe.py || echo 0

# Show unit and recipe name for each process
pgrep -af run_recipe.py
```

Via the scheduler API (shows DB status and PID together):

```bash
curl -s http://scheduler.<domain>/api/runs/active | python3 -m json.tool
```

The response includes a `pid` field per run: `null` means the scheduler API has no tracked PID for that run (e.g. after a pod restart), a number means a live process is registered.

### PID file persistence

The scheduler writes a PID file to `schd/run_<run_id>.pid` whenever a `run_recipe.py` process starts. On pod restart the API scans for these files:

- **Process still alive** → re-registered in the in-memory PID registry so stop/signal works correctly
- **Process dead** → PID file deleted, run marked **Failed** in the database automatically

This prevents orphaned processes (runs whose DB status still shows Running after the scheduler pod was killed) from accumulating silently.

### Killing orphaned processes manually

If processes are running that the scheduler is no longer tracking (e.g. after a hard pod kill before the PID persistence fix was deployed), kill them by PID:

```bash
sudo pkill -f run_recipe.py          # kill all run_recipe processes
# or target a specific PID:
sudo kill <pid>
```

After killing, the database run status should already be **Failed** (set during startup recovery on the next pod start). If it isn't, reset it manually:

```bash
microk8s kubectl exec -n medcea rdbms-postgresql-0 -- \
  env PGPASSWORD=<POSTGRES_PASS> psql -U postgres -d medcea_db -c \
  "UPDATE medcea.recipe_run SET recipe_run_status='F', recipe_run_end=NOW()
   WHERE recipe_run_id=<run_id> AND recipe_run_status IN ('R','S');"
```

### Preventing duplicate runs

The scheduler API rejects an execute request with **HTTP 409** if a live `run_recipe.py` process is already running for the same unit. This guard uses the in-memory PID registry (rebuilt from PID files on restart) rather than relying solely on DB status, so it catches cases where the DB was temporarily unavailable when a previous run was started.

---

## Control Algorithms

All CEA grow-chamber control loops use a pluggable algorithm that maps a sensor reading to one of three actuator commands: `UP`, `DOWN`, or `OFF`. The algorithm is selected per permission (or per run) and receives `lower_limit` / `upper_limit` bounds from the recipe line item.

### Available algorithms

| Code | Name | Description | Default params |
|---|---|---|---|
| `IF_THEN_ELSE` | Bang-Bang *(system default)* | Simple on/off switching with a deadband. No external dependencies. | `deadband_fraction=0.1` |
| `PID` | PID Controller | Proportional-Integral-Derivative control. Anti-windup integral clamped to ±100; 5% deadband around the setpoint. | `kp=1.0, ki=0.1, kd=0.05` |
| `FLC` | Fuzzy Logic Control | Two-input fuzzy system (error + error_rate). Requires `scikit-fuzzy`; falls back to `IF_THEN_ELSE` if not installed. | `deadband_fraction=0.1` |
| `MPC` | Model Predictive Control | Receding-horizon optimisation using GEKKO/IPOPT. First-order linear model per channel. Requires `gekko`; falls back to `IF_THEN_ELSE` if not installed. | `horizon=6, switching_cost=0.1` |
| `Q_LEARNING` | Q-Learning | ε-greedy reinforcement learner. Q-table is persisted between cycle runs in `medcea.algorithm_state` so the agent warm-starts across grow cycles rather than resetting. | `alpha=0.1, gamma=0.95, epsilon=0.2, epsilon_decay=0.995` |

Algorithm params are stored per-permission in `medcea.recipe_unit_permission.algorithm_params` (JSON) and can be overridden per-run in the scheduler UI.

### Adding a new algorithm

**1. Create the implementation** — `schd/cea/algorithms/<name>.py`

Inherit from `ControlAlgorithm` ([`schd/cea/algorithms/base.py`](schd/cea/algorithms/base.py)) and implement `compute()` and `reset()`:

```python
from .base import ControlAlgorithm

class MyAlgorithm(ControlAlgorithm):
    def __init__(self, lower_limit: float, upper_limit: float,
                 my_param: float = 1.0, **kwargs):
        super().__init__(lower_limit, upper_limit)
        self.my_param = float(my_param)

    def compute(self, sensor_value: float) -> str:
        # return "UP", "DOWN", or "OFF"
        ...

    def reset(self):
        # reset any accumulated internal state
        ...
```

If the algorithm has persistent state that should survive across runs (like Q_LEARNING's Q-table), also implement `get_state() -> dict` and `load_state(state: dict)`.

**2. Register in the factory** — [`schd/cea/algorithms/__init__.py`](schd/cea/algorithms/__init__.py)

```python
from .my_algorithm import MyAlgorithm

ALGORITHM_NAMES: dict[str, type] = {
    ...
    "MY_ALGO": MyAlgorithm,
}
```

**3. Add a DB seed row** — [`apps/database/medcea_db_migrations.sql`](apps/database/medcea_db_migrations.sql)

```sql
INSERT INTO medcea.control_algorithm (algorithm_id, algorithm_name, description, is_active)
VALUES ('MY_ALGO', 'My Algorithm', 'Short description', 'Y')
ON CONFLICT (algorithm_id) DO NOTHING;
```

**4. Apply the migration**

```bash
./deploy-apps.sh   # select "database", or use --all
```

The new algorithm will then appear in the Permission Settings modal in the scheduler UI.

---

## Accessing the platform from other devices

All services are published on `<name>.$DOMAIN`, which resolves to the Tailscale
address. Any device on the tailnet reaches them directly — no route advertising
is needed. Devices on the LAN but not the tailnet can use the LAN address form
instead.

Two things do not go through the ingress and use raw ports:

| Service | Address | Note |
|---|---|---|
| Mosquitto (IoT devices) | `mqtt://<lan-ip>:31883` | LAN NodePort — set a DHCP reservation |
| Onboarding wizard | `https://onboard-device.<domain>` | Runs on the host (port 8088 behind the ingress); needs the USB port |

Remember that each browsing device also needs the platform CA installed — see
[Trust the platform certificate](#4-trust-the-platform-certificate).

---

## Uninstall

```bash
./deploy-infra.sh --uninstall
```

Removes MicroK8s and all cluster data. Prompts for confirmation. This is destructive and permanent — all PersistentVolumes (database data, Node-RED flows) will be deleted.

---

## Script layout

```
install.sh               # One entry point: install, update, uninstall (--help)
deploy-infra.sh          # Infrastructure stage (run from repo root)
deploy-apps.sh           # Application stage (interactive, --all, --uninstall)
k8s/                     # Kubernetes manifests and Helm values as templates
├── keycloak/  mosquitto/  pgadmin/  portal/
│   └── keycloak/theme/  # the platform sign-in page (Keycloak login theme "medcea")
├── name-dns/            # DNS server for a name-based domain (+ Corefile)
├── alias/               # redirects from the old IP domain
├── grafana/  workbench/ # Helm values (+ Grafana datasource Secret)
└── oauth2-proxy/        # values-common.yaml + per-release values
infra/
├── bootstrap-infra.sh     # Called by deploy-infra.sh — MicroK8s bootstrap
├── configure.sh           # config.env questions (template: config.env.example)
├── deploy-workbench.sh    # JupyterHub (AI workbench), called by deploy-infra.sh
├── lib-render.sh          # render FILE VAR... — fills the k8s/ templates
├── lib-mk8s.sh lib-mk8s-remove.sh lib-prereqs.sh lib-dns.sh lib-portal.sh
├── lib-credentials.sh lib-wait.sh lib-sudo.sh
└── patch-dex-keycloak.sh  # Legacy (Kubeflow/Dex, retired) — not used by the install
apps/
├── access/              # Access requests, User Manager, user menu + Profile (schema iam)
├── database/            # PostgreSQL schema and migrations
├── edge-wizard/         # Device onboarding wizard as a host service
├── frontend/            # System Configuration UI + Database Management portal
├── monitor/             # Run Monitor dashboard
├── node-red/            # Node-RED packages and flows
├── report/              # Grafana dashboards
└── scheduler/           # Recipe Schedule Manager API + UI
                         # each app: deploy.sh, uninstall.sh, k8s/ (its manifests)
schd/
├── run_recipe.py            # Recipe execution entry point (spawned per recipe run)
└── cea/
    ├── algorithms/          # Pluggable control algorithm package
    │   ├── base.py          # Abstract ControlAlgorithm interface
    │   ├── bang_bang.py     # IF_THEN_ELSE implementation
    │   ├── pid.py           # PID implementation
    │   ├── flc.py           # Fuzzy Logic Control implementation
    │   ├── mpc.py           # Model Predictive Control implementation
    │   ├── q_learning.py    # Q-Learning implementation
    │   └── __init__.py      # Registry + get_algorithm() factory
    ├── control_logic_thread.py  # Per-run sensor→actuator control loop
    ├── mqtt_subscribe_thread.py # Inbound sensor data thread
    ├── run_agent.py             # Algorithm wiring + state persistence
    ├── load_algorithm_state.py  # Load Q-table state from DB
    └── save_algorithm_state.py  # Save Q-table state to DB
logs/                    # Timestamped deploy logs (auto-created)
config.env               # Your settings (not committed)
config.env.example       # Template with all variables documented
```

---

## Re-deploy / recovery

Both scripts are idempotent:

- If MicroK8s is already running, bootstrap is **skipped entirely** — the guard is the cluster responding, not a Juju controller.
- Helm releases use `upgrade --install` — they are updated if they already exist
- Keycloak realm and OAuth clients return 409 if they exist and are silently skipped
- The Keycloak TLS secret and all kubectl manifests use `--dry-run=client | kubectl apply` (idempotent)
- App components skip packages already installed and replace only the flow nodes being deployed

To **reinstall from scratch** (wipes all data):

```bash
./install.sh --uninstall-infra   # or --uninstall-all to remove MicroK8s too
./install.sh
```

---

## Configuration reference

All settings are in `config.env` (not committed — listed in `.gitignore`), written by the installer's questions. Change them with `./deploy-infra.sh --configure`, or edit the file directly; the next run keeps your edits. See [config.env.example](config.env.example) for the full variable list with comments.

Key variables:

| Variable | Default | Description |
|---|---|---|
| `PROJECT_NAME` | `medcea` | Project identifier: MQTT topic root (`medcea/<UNIT>/<ZONE>/…`), and the source of `NAMESPACE` and `KEYCLOAK_REALM` |
| `NAMESPACE` | `$PROJECT_NAME` (`medcea`) | Kubernetes namespace for all services |
| `DOMAIN` | `${PLATFORM_IP}.nip.io`; the installer offers `medcea` | Base domain for ingress hostnames |
| `PLATFORM_IP` | Tailscale IP, else LAN IP | The address every service name points to; also the onboarding wizard address |
| `LOCAL_DNS` | `false` | `true`: the platform serves DNS for `DOMAIN` (`name-dns`) and maps the names in `/etc/hosts` |
| `ALIAS_DOMAIN` | `${PLATFORM_IP}.nip.io` | The old IP domain, kept as redirects to `DOMAIN`; inactive when equal to it |
| `USE_TAILSCALE` | set by the installer | `true`: `DOMAIN` uses the Tailscale IP, and a deploy stops if Tailscale is down. `false`: LAN only, never asked again. Empty: not decided yet |
| `ADMIN_USER` | `admin` | Admin username for Keycloak and Grafana |
| `KEYCLOAK_REALM` | `$PROJECT_NAME` (`medcea`) | Keycloak realm name |
| `K8S_CHANNEL` | `1.29/stable` | MicroK8s snap channel |
| `WORKBENCH_ENABLED` | `true` | Deploy the JupyterHub workbench with the infrastructure |
| `NODE_RED_TZ` | system timezone | Timezone for Node-RED |
| `WORKBENCH_DOMAIN` | `ai-workbench.$DOMAIN` | Hostname for the AI workbench |
| `ACCESS_DOMAIN` | `access.$DOMAIN` | Hostname for the User Manager and the registration redirect |

E-mail (Gmail account, app password, templates) is **not** in `config.env`: it is set in the User Manager.

---

## Architecture notes

- **No public certificates are possible** for `*.nip.io` on a CGNAT or LAN address: Let's Encrypt cannot reach the host for HTTP-01 and the DNS is not ours for DNS-01. Hence the platform CA.
- **Keycloak uses HTTPS** — production mode sets `SameSite=None; Secure` on cookies. Its ingress uses the platform certificate (signed by the platform CA). Services talk to Keycloak inside the cluster over plain HTTP, by its service name.
- **Keycloak image** — uses `quay.io/keycloak/keycloak:26.0` (official, free). The Bitnami Keycloak chart has been behind a paywall since August 2025.
- **The AI workbench** is JupyterHub, deployed by `infra/deploy-workbench.sh` from `deploy-infra.sh`. It authenticates against Keycloak with `GenericOAuthenticator` — no Dex, no service mesh. Per-user notebook pods are culled when idle.
- **Docker Hub credentials** are required only for Helm OCI chart pulls (`bitnamicharts`) and to avoid the anonymous image pull rate limit. Runtime images for Keycloak (Quay), Node-RED (GHCR), OAuth2 Proxy (Quay), and Mosquitto (Docker Hub Official) do not require auth.
- **App content lifecycle** — `apps/` is intentionally decoupled from `deploy-infra.sh`. Infrastructure and application content can be versioned and deployed independently.

## Reinstalling

Three levels, from cheapest to most drastic. Pick the smallest one that covers
what you actually need to rebuild.

| Level | Command | Removes | Keeps | Time |
|---|---|---|---|---|
| **Apps** | `./install.sh --uninstall-apps` then `./install.sh --apps-only` | app components (Deployments, ConfigMaps, dashboards, flows); `--purge-data` also drops `medcea_db` | infrastructure, database contents | ~1 min |
| **Platform** | `./install.sh --uninstall-infra` then `./install.sh` | the `$NAMESPACE` namespace and every Helm release in it, including all PVCs and therefore **all data** | MicroK8s, every cached image, `config.env`, the CA | ~1–2 min + install |
| **Everything** | `./install.sh --uninstall-all` then `./install.sh` | MicroK8s itself, `/var/snap/microk8s`, `~/.kube`, the onboarding wizard service, `edge/.venv`, `logs/`, credentials files; optionally `config.env` and `.ca/` | `edge/provisioned/` (audit trail), `edge/firmware/`, the repo | ~15 min + image pulls |

Under the hood these are `deploy-apps.sh --uninstall`, `deploy-infra.sh --reset` and `deploy-infra.sh --uninstall`, which still work on their own.

`--uninstall-infra` is the one you almost always want. `--uninstall-all` re-downloads every
container image, which on this platform is roughly 10 GB.

### What survives a reset, and whether that is correct

| Survives | Correct? |
|---|---|
| `config.env` — user values *and* generated secrets | Mostly. The generated client secrets self-heal: Keycloak is rebuilt, `_create_client` returns the new secret, and the file is rewritten. Pass `--reset --secrets` to blank them first, so anything that fails to regenerate fails loudly instead of quietly reusing a dead value. |
| `edge/provisioned/*.json` | **Yes, deliberately.** These are the provisioning records — which board got which firmware, flashed by whom. They are the audit trail and must outlive the cluster. |
| `edge/firmware/*.bin`, `edge/.venv` | Yes — a download cache and a toolchain. Rebuilt on demand if deleted. |
| `logs/` | Yes. Delete by hand when it grows. |

### After a rebuild

```bash
./health-check.sh          # every service, with expected status codes
```

Then confirm the two things a fresh Keycloak realm affects: sign in at
`portal.$DOMAIN`, and sign in at `ai-workbench.$DOMAIN` — both go through
clients that `deploy-infra.sh` recreates from scratch.

### One ordering rule

`deploy-infra.sh` must run before `deploy-apps.sh`. The app deploys refuse to
start without the Keycloak client secrets that infra creates —
`apps/frontend` needs `CONFIG_OAUTH2_PROXY_SECRET` — and they say so rather
than deploying something broken. The workbench is not affected: it is deployed
by `deploy-infra.sh` itself.
