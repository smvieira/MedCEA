# Edge onboarding

Getting one ESP32-S3 from the box to a board that is in the fleet: on the
network, running the application for its role, publishing under an identity the
platform database gave it, and present in the Devices tab as the device in its
slot.

```
unit01-s-zone01     lower(unit) - s|c - lower(zone): the board's one name
```

The unit and the zone are **chosen, not typed**. They come from `medcea.cea_unit`
and `medcea.cea_zone`, and a unit/zone holds **one and only one SENSE and one and
only one CONTROL**, so a slot that already has a board is never offered. Nothing
in the wizard asks for an MQTT host, a topic or a client id: those follow from
the slot and from `config.env`, and an operator retyping them is only an
opportunity to get them wrong.

`--unregistered` still does the old thing — bring the board up on WiFi with no
platform identity at all, for a bench with no platform deployed. That board is
visibly unregistered by its name (`cea-un-<mac6>`) and has no MQTT credential, so it can talk to
nothing. Onboarding it again later gives it a slot; nothing has to be undone.

```bash
./edge/flash-device.sh            # terminal
./edge/flash-device.sh --ui       # terminal + a browser page behind a Keycloak login
```

**Onboarding happens over USB, on the platform host, by a signed-in operator.** A device is only
ever provisioned while physically plugged into the machine the platform runs on. That is a design
decision, and it is what removes the claim codes, setup access point, captive portal and
LAN-facing enrolment endpoint that an earlier design needed. The cable is the proof of possession;
the Keycloak session says who is holding it.

---

## The browser UI

`--ui` serves the same wizard as a web page, behind a Keycloak login, and prints
its URL. It exists for the normal case: the bench machine is reached over SSH, so
the person flashing a board has a terminal but wants the WiFi picker and the
final credentials somewhere they can read and copy properly.

### Always-on: the onboarding service

`--ui` serves one run and exits with it, which is fine at a bench but useless as
a link. For the config UI to offer onboarding, the wizard has to be there before
anyone asks — so it also runs as a daemon:

```bash
./apps/edge-wizard/deploy.sh               # what ./install.sh runs: the service
./edge/wizard-daemon.sh                    # foreground, for a one-off
```

**The install sets it up as a service.** The Devices tab in the config UI links
to this daemon, so if it is not running the "Onboard Device" button gives
`ERR_CONNECTION_REFUSED`. `apps/edge-wizard/deploy.sh` (run by `./install.sh` and
`./deploy-apps.sh --all`) builds `edge/.venv`, writes the `cea-edge-wizard`
user unit from `wizard-daemon.sh --install-unit`, restarts it, publishes it at
`https://onboard-device.<domain>` through the cluster ingress (the daemon itself stays on
`http://<ip>:8088`) and enables linger — without linger the service stops the moment you log out and does not
come back after a reboot. `./health-check.sh` and `apps/frontend/deploy.sh` both
check that it answers.

Same server, same Keycloak login, same prompts. The difference is a lifecycle:
it stays up, shows a catalogue of device types, and spawns that type's script
with `--ui-spool <dir>` when an operator picks one. The script is still the
engine — the daemon adds a front door, not a second copy of the flow. One run at
a time; a second start while one is in progress is refused with a 409.

### The catalogue

The landing page is a store front, not a single button, because the fleet will
not stay ESP32-only. Device types live in [catalog.json](catalog.json) and the
grid is rendered from it, so **adding a supported device is adding an entry** —
no server or page changes:

```json
{
  "id": "esp32-micropython",
  "name": "ESP32 / ESP32-S3",
  "subtitle": "MicroPython sense or control board",
  "icon": "⚡",
  "status": "available",
  "connection": "USB",
  "roles": ["SENSE", "CONTROL"],
  "script": "edge/flash-device.sh"
}
```

`status: "available"` renders a working tile; anything else renders disabled with
the status as its label. Two `planned` placeholders ship as examples — delete
them, nothing depends on them.

Two things the server does with this, both deliberate:

- **The command comes from the catalogue, never from the request.** A start
  request names an `id`; the script path is looked up. Posting a path does
  nothing.
- **Entries are validated at load.** A script that is missing, not executable, or
  resolves outside the repo is downgraded to `unavailable` at startup rather than
  failing when someone presses it. A tile is a promise that pressing it works.

It runs on the host, not in the cluster, because onboarding is over USB and
`/dev/ttyACM0` belongs to the host. That is also why it needs to run as a user
in the `dialout` group.

The **Devices** tab at `config.$DOMAIN` links to it — that is the intended entry
point, and the reason the daemon exists.

### Signing in

Provisioning mints credentials and puts hardware into the fleet, so it requires a
Keycloak session. `deploy-infra.sh` creates a confidential client `edge-wizard`
in realm `medcea` — alongside the existing node-red, grafana and portal clients —
and writes `EDGE_WIZARD_SECRET` into `config.env`. Without that the wizard
refuses to start:

```
 !! the browser UI needs Keycloak: EDGE_WIZARD_SECRET is not set in config.env.
       Run ./deploy-infra.sh to create the 'edge-wizard' client, or pass
       --ui-insecure to fall back to a URL token on a bench you trust.
```

| Setting | Meaning |
|---|---|
| `EDGE_WIZARD_SECRET` | Client secret, filled in by `deploy-infra.sh` |
| `EDGE_WIZARD_PORT` | Must match the registered redirect URIs (default 8088) |
| `EDGE_WIZARD_ROLE` | Realm role required to provision. Empty = any realm user |

`deploy-infra.sh` also creates a `config` client and puts `config.$DOMAIN` behind
its own oauth2-proxy. That page previously had **no authentication at all** —
the whole device inventory and every recipe were readable by anyone who could
reach the host — which had to change before putting a "mint a credential" button
on it.

The redirect URI is registered **per address and port**, so `--ui-port 0` is
refused with Keycloak, and the client is registered for loopback, the LAN address
and the Tailscale address. The wizard also checks the `Host` header against that
same list before building a redirect, so an unregistered address is refused a step
before Keycloak would refuse it.

`--ui-insecure` falls back to the URL token for a bench with no platform
deployed. It warns, and it is never the default.

```
==> Browser UI
    Open this and sign in with Keycloak:
      http://192.168.1.102:8088/
      http://100.94.119.12:8088/
      http://127.0.0.1:8088/
    realm medcea at keycloak.100.94.119.12.nip.io
```

Only addresses the chosen bind actually answers on are listed. With
`--ui-bind 127.0.0.1` you get the loopback URL and the `ssh -L` line to forward
it. `--ui-port 0` picks a free port if 8088 is taken.

The page shows the live log, the current step, whichever question the script is
waiting on, and a summary card at the end. That card now carries the slot as
well as the credentials: the hostname, unit/zone, role, the broker, the topics
the board will use, and whether the `medcea.device` row was actually written. The
link in the header goes to `$CONFIG_DOMAIN/#devices`, where the board it just
onboarded now appears.

Every new question — role, slot, sensor, GPIO — is a prompt the shell writes and
the page renders, so all of it works identically in the terminal. Nothing about
the browser path is a second implementation.

**The shell stays the engine.** The UI does not reimplement any of the flow: the
script writes prompts and log lines into a spool directory, the server renders
them and posts answers back. There is no second copy of the logic to drift out
of sync, and `--ui` changes nothing about what gets flashed.

```
shell  --write--> <spool>/prompt.json --serve--> browser
shell  <--read--- <spool>/answer      <--POST--- browser
shell  --append-> <spool>/log         --poll---> browser
```

### What it is not

- **Still plain HTTP.** Keycloak authenticates the operator, but the wizard is
  served over HTTP and the page accepts the WiFi PSK and shows the WebREPL
  password. The session cookie is `HttpOnly` and `SameSite=Lax`, which does not
  help against someone reading the wire. On a network you do not control, bind to
  loopback and tunnel. The server is single-run — it dies with the script.
- **Not a way to escape the terminal entirely.** If you answer "yes" to the
  `sudo` fallback, `sudo` asks for the password on the **terminal**, not in the
  browser. Fix the `dialout` membership and the question never comes up.
- **Not multi-board.** One run, one board, one page.

---

## Before the first run

### 1. Serial port access — do this first

On this machine the port exists but you cannot write to it:

```
$ ls -l /dev/ttyACM0
crw-rw---- 1 root dialout 166, 0 /dev/ttyACM0
$ id -nG
svieira adm cdrom sudo dip plugdev users lpadmin docker microk8s
```

No `dialout`. Every `esptool` call fails with a permission error until that
changes.

**`deploy-infra.sh` now does this for you** — it adds the group and restarts the
user service manager. If you need to do it by hand:

```bash
sudo usermod -aG dialout "$USER"
sudo systemctl restart "user@$(id -u)"
```

The second command is the one people miss. `usermod` only updates the database;
every running process keeps the group set it started with. The onboarding wizard
is a `systemd --user` service, and `systemctl --user restart cea-edge-wizard` is
**not** enough — it respawns from `user@.service`, which is itself still holding
the old set. Restarting that manager, or logging out and back in, is what
actually refreshes it.

Group membership is read at login, so **log out and back in** — or start a
subshell with `newgrp dialout` for the current terminal. Confirm with `id -nG`
before flashing. The script will offer to fall back to `sudo` for a single run,
but that is a workaround, not the fix: files it copies to the board are fine
either way, and the permanent change costs nothing.

### 2. Check what is actually connected

```bash
lsusb | grep -Ei 'espressif|qinheng|silicon|ftdi'
ls /dev/ttyUSB* /dev/ttyACM*
```

On this bench:

```
Bus 002 Device 004: ID 1a86:55d3 QinHeng Electronics USB Single Serial   -> /dev/ttyACM0
```

`1a86:55d3` is a **CH343** USB-to-UART bridge. That matters twice:

- It is a *bridge chip*, not the ESP32's own USB peripheral, so the port does not
  disappear when the board resets. If instead you see `303a:1001`, you are on the
  S3's native USB-CDC port, which re-enumerates on every reset — the script waits
  for the node to come back either way.
- Most ESP32-S3 devkits expose **two** USB-C sockets, one per path. If auto-reset
  into download mode misbehaves on one, try the other.

The kernel binds the CH343 with `cdc_acm`, so no vendor driver is needed. This
host is a VMware guest, so also confirm the device is passed through to the guest
rather than claimed by the host — if `lsusb` inside the VM does not show it, no
amount of debugging on the Linux side will help.

### 3. Firmware — nothing to do in advance

`edge/firmware/` may start empty. The script reads the chip family off the
silicon, lists whatever is already there for that board, asks micropython.org
what it publishes, and downloads on request. See
[firmware/README.md](firmware/README.md) for the variant table and for why there
is no upstream API to call.

If you would rather stage it by hand, or the bench has no network:

```bash
python3 edge/src/host/list_firmware.py --board ESP32_GENERIC_S3 --limit 5
curl -fL --output-dir edge/firmware -O <url from that list>
./edge/flash-device.sh --offline
```

---

## Download mode

Most S3 devkits reset themselves into the bootloader when `esptool` toggles
DTR/RTS, and the script simply works. When it does not — a CH343 bridge and a VM
serial layer between you and the board is exactly where this gets unreliable —
do it by hand:

1. **Hold BOOT** (labelled `BOOT` or `IO0`).
2. **Tap RESET** (labelled `RST` or `EN`), keeping BOOT held.
3. **Release BOOT.**

The board is now in download mode and stays there until it is reset. `esptool`
will connect on the next try. You will need this again after `erase_flash` on
some boards.

---

## What the script does

| # | Step | Notes |
|---|---|---|
| 0.5 | **Ask the role, then the slot** | SENSE or CONTROL, then a unit/zone from the database. Only **free** slots are offered; a unit/zone already holding that role is listed but not selectable |
| 0.6 | **Ask what is wired up** | Which sensors, or which GPIO drives which piece of equipment. The questions come from `edge/templates/<role>.json`; defaults are the reference build's wiring |
| 1 | Build `edge/.venv` from `requirements.txt` | `esptool` and `mpremote`, versions recorded in the provisioning record |
| 2 | Pick the serial port | Autodetects; prompts when several are present; detects the `dialout` problem and says so |
| 3 | `flash_id` — read chip family and MAC | Runs *before* firmware selection: the family determines the offset (`0x0` for S3/C3/C6, `0x1000` for classic ESP32 and S2) **and** which upstream board page is relevant |
| 4 | Pick the firmware, local or upstream | Local images for this board, newest first and default; plus whatever micropython.org publishes. Downloads on request and hashes into `SHA256SUMS` |
| 5 | Derive the identity | `unit01-s-zone01` from the slot — one name for DHCP, `dns_name` and the payloads. With `--unregistered`: `cea-un-<mac6>` |
| 6 | `erase_flash` then `write_flash` | 460800 baud, falls back to 115200 |
| 7 | Wait for the REPL | Handles both the bridge and native-USB re-enumeration cases |
| 8 | **Scan WiFi from the board's own radio** | Menu sorted by signal, with manual entry for hidden SSIDs |
| 9 | Generate the WebREPL password | 9 characters, this board only |
| 10 | Render and copy the board's files | `device_cfg.py` (generated), `actuator_config.json` for a CONTROL board, the application tree from `edge/src/app/`, and `webrepl_cfg.py` |
| 11 | Hard reset and verify | Asks the board for its IP after a real boot — not a simulation of one |
| 12 | **Register with the platform** | One `medcea.device` row plus one `medcea.component` per sensor (or one for the relay board). Skipped if the board never got an IP: a slot must not be filled by something that is not there |
| 13 | Write `edge/provisioned/<DEVICE_DNS>.json` | `chmod 600`, gitignored |

The identity questions are asked **first**, before the toolchain and the flash,
and deliberately so: they are the ones only the person standing at the chamber
can answer, and the twenty minutes of erase, write and verify that follow need
nobody. Asking them at the end is how a board gets flashed and then abandoned
half-onboarded because the operator walked away.

### The role, and what a slot is

A **unit** is a physical chamber; a **zone** is one area within it. Both are
rows in the database, created in the Units tab before any board is onboarded —
the wizard reads them and never creates them, because a chamber that exists only
because someone typed its name into a flashing tool is a chamber nothing else on
the platform knows about.

Each unit/zone holds exactly two boards:

```
UNIT01 / ZONE01  ->  unit01-s-zone01      reads the chamber
                     unit01-c-zone01      drives the chamber
```

That rule is read from the live `medcea.device` table on every run, not remembered:
a slot is free when no **active** device of that role points at the zone. Marking
the old device inactive in the Devices tab is therefore how a board is replaced,
and re-onboarding the same slot **updates the existing row in place** rather than
creating a second one.

### The template: what is asked, and what is inferred

The wizard asks for what only the operator can know, and derives the rest:

| | |
|---|---|
| **Asked** | role; unit/zone slot; which sensors are wired up and to which GPIO (or, for CONTROL, which relay channel drives which piece of equipment); WiFi network and passphrase |
| **Inferred** | MQTT host and port from `config.env`; topic root from `PROJECT_NAME`; topics, client id and the hostname from the slot; pin defaults from the reference build |

The questions themselves are data, in `edge/templates/esp32-sense.json` and
`edge/templates/esp32-control.json` — **adding a supported sensor is adding an
entry there** plus a branch in `edge/src/app/cea_sense.py`. Nothing in
`flash-device.sh` changes.

```
SENSE    medcea/UNIT01/ZONE01/sense/<tag>            one topic per tag published
CONTROL  medcea/UNIT01/ZONE01/control/#              subscribed
         medcea/UNIT01/ZONE01/control_setpoint/...   what it actually did
```

A SENSE board may carry several probes — the reference `UNIT01_SENSE01` carries
a water-level probe and a substrate thermometer — so the sensor question loops
until you say it is done. Pressing Enter through the whole thing gives you the
board the fleet already runs.

For a CONTROL board the only question is which channel drives what, offered
first as a single yes to the reference wiring. Equipment the chamber does not
have is left blank, and then **every command that needed it is dropped from the
board's table entirely** rather than shipped as a no-op. That matters: without
it, "turn the UV lamp on" in a chamber with no UV lamp survives as the leftover
half of the same command — turn the red and blue lamps off — and the board
reports that it did what it was asked. The scheduler has to be able to tell
*cannot* from *did, and nothing happened*.

Answer no to that and, in the browser, you get the map itself rather than ten
questions: a table of channels, every command the scheduler can send, and the
`actuator_config.json` being built underneath it as you type. It refuses to
submit a map with errors in it, and `render()` refuses one again on the way to
the board — a check worth having twice, because the alternative is finding out
after the flash has already erased the device. In a terminal the same step falls
back to asking for one address at a time; a table with a live verdict on it is
not a thing a terminal does well.

The same editor is available on its own, away from the platform, for inspecting
or hand-correcting a map:

```bash
./edge/tools/build-editor.sh          # -> edge/tools/actuator-config-editor.html
```

It is built from `edge/src/host/ui/channelmap.js` — the file the wizard inlines
— so there is one editor, not two that drift.

### Which board, and which pins it actually has

The form opens with a **board selector**. It defaults to `esp32s3` — what this
fleet runs — and every ESP32 variant is offered: ESP32, S2, S3, C3, C6, H2 and
P4. Changing it re-checks the map you already have against that silicon rather
than rewriting it, because the errors that appear are the whole point.

**Pin reference** opens the table for the selected board: every GPIO it has,
what else already wants it, and why that matters. The data is in
`edge/templates/esp32-gpio.json`, taken from Espressif's own per-target ESP-IDF
GPIO pages, and it feeds the reference panel *and* validation from one place —
so the table cannot claim a pin is free while the validator calls it taken.

Each channel row shows its pin's type as you type the number, which is the
pre-validation that matters: you find out GPIO12 is SPI flash on a C3 while
entering it, not after the board is flashed.

What the table knows, and what it refuses:

| Type | Verdict | Why |
|---|---|---|
| Input only | **unusable** | ESP32 GPIO34-39 and S2 GPIO46 have no output driver at all |
| SPI flash | **unusable** | driving it crashes the board |
| PSRAM / octal | caution | taken on modules that have it, free on those that don't |
| Strapping | caution | a relay holding it at reset can stop the board booting |
| USB-JTAG | caution | costs you the USB serial console this wizard flashes over |
| UART0 TX/RX | caution | the console and the flashing line |
| Not bonded out | caution | absent on SiP package variants of the C6 and H2 |

The ESP32-P4 is the odd one: its flash sits on dedicated package pins and its
PSRAM is in-package, so it is the only chip here that loses no GPIO to memory.

Because the wiring question is asked **before** the board is probed, the
selector is the operator's claim, not a measurement. Step 3 is where it is
tested: once esptool reports the chip, the map is re-validated against the real
silicon and refused if it cannot drive it.

```
 !  the channel map was checked against esp32s3, but this board is esp32c3.
    !! GPIO 46 - GPIO 46 is not addressable on this device (valid: 0-21)
    !! GPIO 12 - GPIO12 is used by the SPI flash. Driving it crashes the board.
 !! the map cannot drive this chip. Re-run and pick esp32c3 as the board.
```

The same table is available from the terminal:

```bash
python3 edge/src/host/device_template.py pins CONTROL esp32c3
```

### Devices that have no pins

Nothing above says GPIO by accident. What identifies one channel, what counts as
a legal address, and what the field is called in the file the device reads all
come from the template's `binding` block:

```json
"binding": {
  "kind": "gpio", "field": "pin", "label": "GPIO",
  "descriptions_key": "pin_descriptions", "address_kind": "int",
  "valid_ranges": [[0, 21], [26, 48]],
  "rules": [{"addresses": [26, 27, 28, 29, 30, 31, 32], "level": "error",
             "message": "GPIO {addr} is wired to the SPI flash."}]
}
```

Those `rules` are read by the renderer *and* shipped to the browser, so the
operator gets the same warnings the renderer would give, from one table rather
than two.

A device family is therefore a template, not a fork.
`edge/templates/examples/modbus-control.json` is the worked proof: a CONTROL
device addressed `3:0001` over Modbus renders, prunes and validates through the
same `device_template.py` and the same editor — labelled "Coil", checked against
its own regex, rejecting slave 0 as a broadcast — and there is no Modbus code in
this repo at all. Select a family with `CEA_DEVICE_FAMILY`; the default is
`esp32`.

What a binding does **not** abstract is provisioning. `flash-device.sh` writes
MicroPython over USB, and a Modbus relay or an HTTP smart plug is not flashed at
all — that device needs its own path into the fleet, and the binding only means
it will not also need its own command table, its own validator and its own
editor.

### One program, per-board data

Every board gets the same application tree from `edge/src/app/`. What differs is
`device_cfg.py`, which is generated and holds nothing but literals:

```
device_cfg.py    GENERATED  role, slot, credentials, the pins you chose
config.py        SHIPPED    derives topics, client id, intervals from them
main.py          SHIPPED    dispatches on device_cfg.ROLE
cea_sense.py     SHIPPED    reads cfg.SENSORS — the sensor list is data
cea_control.py   SHIPPED    reads actuator_config.json — the pin map is data
```

Re-onboarding rewrites `device_cfg.py` and leaves the rest alone. The fleet
previously carried one hand-edited copy of `config.py` and `main.py` per device,
and they drifted: nine copies of `webrepl_cfg.py` with the same password in git,
and a `read_scd30_sensor()` that raised `NameError` on its first call because it
read two constants nobody had defined. Both are fixed here, once.

### Where the platform database comes from

`platform_db.py` reaches PostgREST (the `config-api` Service) by its ClusterIP,
looked up with `kubectl` at call time. MicroK8s runs kube-proxy on the host, so
ClusterIPs are routable from here — no ingress, no oauth2-proxy, no port-forward.
`CEA_CONFIG_API` overrides it for a bench or a test.

If the database does not answer, the wizard says so and offers to continue
unregistered rather than inventing a unit code.

### Choosing a firmware image

The newest **local** image is always the default. A bench run must not depend on
the network, and must not quietly change what it flashes because upstream
published something overnight.

```
      Local images
      [ 1] ESP32_GENERIC_S3-20260406-v1.28.0.bin                   (default)
      [ 2] ESP32_GENERIC_S3-20250911-v1.26.1.bin

      Available from micropython.org
      [ 3] ESP32_GENERIC_S3-20260824-v1.29.0.bin       download · v1.29.0  newer than your local image
      [ 4] ESP32_GENERIC_S3-FLASH_4M-20250415-v1.25.0.bin  download · v1.25.0 · FLASH_4M
      [ 5] ESP32_GENERIC_S3-SPIRAM_OCT-20260824-v1.29.0.bin  download · v1.29.0 · SPIRAM_OCT

    select [1-5, Enter = 1]:
```

Only images matching the detected board are offered — a directory holding both
an S3 and a WROOM-32 build is the normal case once there are two board types in
the fleet, and offering the wrong one is how a board gets bricked quietly. With
no local image the menu has no default and you must choose something to
download. `--offline` skips the upstream check entirely; `--preview` adds the
nightly builds, which are excluded by default because they sort *newer by date*
than the latest stable release.

### Why the scan runs on the board

The obvious implementation is `nmcli dev wifi list` on the provisioning host.
That cannot work here — this host has no wireless interface at all, only `ens33`,
`tailscale0` and the container bridges. It would also be answering the wrong
question: what matters is the RF environment at the board, in the grow unit where
it will live, not at the server. `edge/src/bootstrap/scan_networks.py` runs on the
ESP32 over the serial link and reports what the device can actually hear, keeping
the strongest reading when an SSID appears on several APs or bands.

If a network you expect is missing, the usual cause is that it is **5 GHz only**.
The ESP32 and ESP32-S3 have 2.4 GHz radios and cannot see a 5 GHz SSID at all.

### One name, and the address you should actually use

```
hostname     unit01-s-zone01         DHCP name, dns_name, payload device_dns
ip address   192.168.1.122           <- always works
```

A board has **one name**: `lower(unit_code)-<s|c>-lower(zone_code)`, built from
the codes in the database at onboarding. It is what DHCP registers,
`medcea.device.dns_name`, the `device_dns` field in every MQTT payload, what the
config UI's Online check pings, and the provisioning record's file name.
Lowercasing is the only transformation — the unit and zone codes are already
human-chosen, so the name stays readable and is the same every time the slot is
onboarded.

**The codes must make a legal hostname.** RFC 1123 permits letters, digits and
hyphens only (no leading or trailing hyphen), and DHCP servers quietly drop or
mangle anything else. **It must also fit MicroPython's hostname buffer**, 32
characters (`MICROPY_PY_NETWORK_HOSTNAME_MAX_LEN`). The first version of this
script asked for a 35-character name; the board refused it, silently kept
MicroPython's default `mpy-esp32s3`, and registered *that* with DHCP. A slot whose
codes break either rule is listed as **not offered, with the reason** — rename
the code in the Units tab. There is no fallback name. The script also reads the
hostname back off the board after boot and says so loudly if what stuck is not
what was asked for.

**Unique by construction.** Unit codes are unique ignoring case, and zone codes
are unique within their unit ignoring case (database indexes, migration 005);
the role letter separates the two boards of a zone.

An **unregistered** board is `cea-un-<mac6>`: unique by MAC, and `un` says at a
glance that it has no slot.

This replaced two earlier names: `UNIT01_SENSE_ZONE01` (the old `dns_name`, not a
legal hostname, so it never resolved) and `u01-s-z01` (a compressed form that
changed whenever another unit was added). A board flashed before the change keeps
its old names until it is onboarded again; onboarding the slot updates the same
`medcea.device` row.

### `.local` does not work — the board runs no mDNS responder

Verified on the wire with a raw mDNS query: seven other devices on this LAN
answer, and the ESP32 answers nothing at all — not even a reverse PTR for its
own address. Setting a hostname is **not** the same as running an mDNS
responder; it sets the DHCP hostname (option 12) and the lwIP netif name, and
nothing more.

What does work here is DHCP → router DNS. Once the board registers a hostname,
the router resolves it:

```bash
nslookup cea-un-de739c 192.168.1.1        # -> 192.168.1.122
```

Note the `192.168.1.1` — querying the router **directly**. `ping cea-un-de739c`
will still fail, because systemd-resolved does not send single-label names to
upstream DNS (it reserves those for LLMNR/mDNS, both disabled here). Options, in
order of how much you'll thank yourself later:

1. **Use the IP.** It is in the provisioning record and printed in the summary.
2. **DHCP reservation** on the router, so the IP never moves. Already
   recommended for the Mosquitto NodePort for the same reason.
3. Add a search domain, or an `/etc/hosts` entry, if you want the bare name to
   work from this host.

The script no longer prints a name it hasn't tested. It resolves the hostname
after boot and reports what actually answers — or says plainly that nothing
does.

### The WebREPL password

MicroPython's WebREPL protocol carries the password in a fixed ten-byte field,
and `webrepl_setup` refuses anything outside 4–9 characters. Nine random
characters from an unambiguous alphabet is the most entropy the protocol will
hold — around 45 bits. It is a bring-up credential with a short life. What it
must not be is the same on every board.

To connect, use a **local checkout** of the client:

```bash
git clone https://github.com/micropython/webrepl ~/webrepl
xdg-open ~/webrepl/webrepl.html
```

The hosted page at `micropython.org/webrepl/` is served over HTTPS, and browsers
block a `ws://` connection from an HTTPS origin. It fails silently — the page
sits there saying nothing useful — and it is the single most common reason
WebREPL "doesn't work".

Serial console instead, whenever the network path is the thing you are debugging:

```bash
edge/.venv/bin/mpremote connect /dev/ttyACM0 repl     # Ctrl-] exits, Ctrl-D soft reboots
```

---

## Where this sits, and what it is not

A board that finishes this procedure is in the fleet: it has a slot, an
application, a topic and a row. What it does **not** have is a security model,
and two of its properties are findings in the fleet assessment:

- **WebREPL is a full Python REPL plus filesystem access**, to anyone who reaches
  port 8266 with the password. The existing fleet ships nine copies of
  `webrepl_cfg.py` with `PASS = 'teste'` in git. Generating a distinct password
  per board and keeping it out of git closes that specific hole; it does not make
  WebREPL safe to leave running, and a registered board leaves it running.
- **The WiFi PSK lands in plaintext on the device filesystem**, readable with
  `esptool read_flash` by anyone holding the board, until flash encryption is on.
- **MQTT is unauthenticated.** Mosquitto is deployed with `allow_anonymous true`,
  so the board's "credential" is its client id and nothing more. A per-device
  MQTT credential, and an image with no WebREPL and no PSK compiled into it, are
  what would close these — none of that exists yet.

What onboarding *does* bound is blast radius by identity: a board publishes only
under its own slot's topic, and the one-SENSE-one-CONTROL rule means a second
board cannot quietly start driving a chamber that already has a controller.

## Layout

```
edge/
  flash-device.sh              the onboarding procedure
  catalog.json                 device types the wizard offers
  requirements.txt             esptool + mpremote, version-bounded
  templates/                   WHAT THE WIZARD ASKS - data, not code
    esp32-sense.json           sensor drivers, their params, their tags
    esp32-control.json         relay functions, the commands they enable, and
                               the `binding` block that says these are GPIOs
    esp32-gpio.json            which GPIOs each ESP32 variant has, and what
                               already wants them - from Espressif's own docs
    examples/
      modbus-control.json      a CONTROL device with no pins, not loaded -
                               proof the binding abstraction carries its weight
  tools/
    build-editor.sh            bakes the wizard's editor into a standalone page
    editor-shell.html          the page it bakes it into
    actuator-config-editor.html   the built result (open it in a browser)
  firmware/                    MicroPython images + SHA256SUMS (bins gitignored)
  src/
    host/                      runs on THIS machine
      list_firmware.py         scrapes micropython.org's build list
      wizard_server.py         the --ui web front-end (stdlib only)
      platform_db.py           units, zones, free slots, device registration
      device_template.py       template -> questions -> the board's files
      bindings.py              how a command reaches equipment; the validator
      ui/
        channelmap.js          the channel-map editor, inlined by the wizard
        channelmap.css         its styles, themed from the wizard's tokens
    bootstrap/                 driven from the host, over the serial link
      scan_networks.py         prints the board's own WiFi scan
    app/                       RUNS ON THE BOARD - identical on every device
      boot.py                  hostname, WiFi, NTP, WebREPL
      main.py                  dispatches on device_cfg.ROLE
      config.py                derives topics/client id from device_cfg
      cea_sense.py             the SENSE loop, driven by cfg.SENSORS
      cea_control.py           the CONTROL loop, driven by actuator_config.json
      cea_sensors.py           sensor drivers (vendored from the fleet)
      cea_edge_functions.py    WiFi, NTP, MQTT connect (vendored)
      scd30.py scd4x.py        Sensirion drivers (vendored)
      sensor_pack_2/ umqtt/    third-party deps, vendored so a board needs
                               no network install at flash time
  provisioned/                 per-device records, chmod 600, gitignored
  .venv/                       toolchain, gitignored
```

`device_cfg.py` is not in that tree because it does not exist until a board is
onboarded: it is generated per device and written straight to the board.
