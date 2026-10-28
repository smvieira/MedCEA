#!/usr/bin/env bash
#
# edge/flash-device.sh — Stage 0 bench bring-up for one ESP32 / ESP32-S3.
#
# Takes a board that has just come out of the box and leaves it: running a pinned
# MicroPython build, joined to a WiFi network it chose from its own radio scan,
# carrying its role's application, publishing to the platform under an identity
# the platform database gave it, and registered as the device in that slot.
#
#     unit01-s-zone01     lower(unit) - s|c - lower(zone): the board's one name —
#                         DHCP hostname, medcea.device.dns_name, MQTT device_dns
#
# The unit and the zone are CHOSEN, not typed: they come from medcea.cea_unit and
# medcea.cea_zone, and a unit/zone holds one and only one SENSE and one and only
# one CONTROL, so a filled slot is never offered. Everything that follows from
# the slot - MQTT host, topics, client id - is inferred and never asked.
#
# --unregistered still does the old thing: bring the board up on WiFi with no
# platform identity at all, for a bench with no platform deployed.
#
# Run from the repository root:   ./edge/flash-device.sh
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FW_DIR="$SCRIPT_DIR/firmware"
SRC_DIR="$SCRIPT_DIR/src/bootstrap"
SRC_HOST="$SCRIPT_DIR/src/host"
OUT_DIR="$SCRIPT_DIR/provisioned"
VENV_DIR="$SCRIPT_DIR/.venv"

# ---------------------------------------------------------------- help --------
# Must run before `set -e` and before config.env is sourced, so that --help works
# on a checkout that has neither.
usage() {
  cat <<'EOF'
Usage: ./edge/flash-device.sh [options]

Flashes MicroPython onto one ESP32/ESP32-S3 over USB, gives it a slot from the
platform database, ships its role's application, and registers it as the device
in that slot. The board has one name, built from the slot's codes lowercased:

  unit01-s-zone01       lower(unit) - s|c - lower(zone): the DHCP hostname, the
                        medcea.device dns_name and device_dns in MQTT payloads

  (--unregistered instead gives cea-un-<mac6>)

Options:
      --role ROLE       SENSE or CONTROL, instead of being asked
      --unit CODE       Restrict the slot menu to this unit (e.g. UNIT01)
      --zone CODE       Restrict the slot menu to this zone (e.g. ZONE01)
      --advanced        Also ask the parameters the template marks advanced
                        (I2C frequency, UART pins) instead of taking defaults
      --unregistered    Skip the slot, the application and the database. Brings
                        the board up on WiFi with no platform identity, for a
                        bench with no platform deployed.
      --no-register     Flash and configure for the slot, but do not write the
                        device row. The slot stays free.
      --mqtt-host ADDR  Broker address to put on the board
                        (default: the LAN address from config.env)
      --mqtt-port PORT  Broker port (default 31883, the Mosquitto NodePort)
      --topic-root ROOT Topic root (default: PROJECT_NAME from config.env)
  -p, --port PATH       Serial port (default: autodetect, prompt if ambiguous)
  -f, --firmware PATH   Use this .bin and skip the selection menu entirely
  -b, --baud RATE       Flash baud rate (default: 460800; falls back to 115200)
      --offline         Don't ask micropython.org what builds exist; use only
                        what is already in edge/firmware/
      --preview         Also offer -preview nightly builds. These are newer than
                        the latest stable by date and are not release-tested.
  -s, --ssid SSID       Skip the network menu and use this SSID
      --psk PSK         WiFi passphrase (else prompted, not echoed)
      --no-erase        Skip erase_flash. Faster, but leaves old filesystem and
                        NVS contents in place — only for repeat runs on a board
                        you have already erased once.
  -y, --yes             Do not ask for confirmation before erasing
  -h, --help            Show this message

Browser UI:
      --ui              Also serve the wizard as a web page and print its URL.
                        Useful over SSH: the terminal still shows everything,
                        but the WiFi picker and the final credentials are
                        somewhere you can read and copy properly. Prompts are
                        answered in the browser while --ui is on.
      --ui-port PORT    Port to listen on (default 8088; 0 picks a free one)
      --ui-bind ADDR    Address to bind (default 0.0.0.0, so a laptop on the
                        LAN can reach it; use 127.0.0.1 with an SSH tunnel)
      --ui-insecure     Serve the UI behind a URL token instead of Keycloak.
                        Only for a bench with no platform deployed — normally
                        the wizard requires a Keycloak login.
      --ui-spool DIR    Join a spool directory owned by an already-running
                        wizard daemon instead of starting a server. Set by
                        edge/wizard-daemon; not usually typed by hand.
      --token-fd N      With --ui-spool only: the descriptor on which the
                        daemon hands out the operator's access tokens. Set by
                        the daemon, never typed.

Signing in:
  Registering a board reads and writes the platform database as the person
  running it. The browser modes (--ui, the wizard daemon) use the wizard's
  Keycloak sign-in. A terminal run shows a code to enter at
  https://keycloak.<domain>/realms/<realm>/device from any device with a
  browser. --unregistered needs no sign-in. Until IAM Phase 2 a run without a
  sign-in still works and says what would be refused — a code nobody entered
  included, and --yes without a terminal does not wait for one; only a sign-in
  denied in the browser, or an account without EDGE_WIZARD_ROLE, stops the
  run. From Phase 2 registering needs one. With --ui, open the address the
  terminal prints (it carries the run's token): a sign-in from the bare address
  gets a browser session but does not act for the run.

Firmware selection:
  The chip family is read off the silicon first, then edge/firmware/ is scanned
  for images matching that board and micropython.org is asked what it publishes.
  The newest LOCAL image is always the default, so a bench run never changes
  what it flashes just because upstream moved. Anything downloaded is hashed
  into edge/firmware/SHA256SUMS (upstream publishes no .sha256 sidecar).

Prerequisites:
  1. Write access to the serial port — see "dialout" in edge/README.md
  2. The board in download mode if it does not reset itself — hold BOOT,
     tap RESET, release BOOT.
  A firmware image is downloaded on demand, so edge/firmware/ may start empty.

What gets asked, and what does not:
  Asked      role, unit/zone slot, which sensors or relay channels are wired
             up and to which GPIO, WiFi network and passphrase.
  Inferred   MQTT host and port from config.env; topics, client id and
             the hostname from the slot; pin defaults from the reference build.
  The questions live in edge/templates/<role>.json. Adding a supported sensor
  is adding an entry there, not editing this script.

Outputs:
  On the board   device_cfg.py (generated), the application tree, and for a
                 CONTROL board actuator_config.json built from the pins chosen.
  In the platform  a medcea.device row plus one medcea.component row per sensor, or
                 one for the relay board.
  edge/provisioned/<hostname>.json     chmod 600 — MAC, firmware hash, WiFi
                                       SSID, WebREPL password, tool versions.
EOF
}

PORT=""; FIRMWARE=""; BAUD="460800"; SSID=""; PSK=""; DO_ERASE=1; ASSUME_YES=0
OFFLINE=0; WANT_PREVIEW=0
ROLE=""; UNIT_WANTED=""; ZONE_WANTED=""; UNREGISTERED=0; DO_REGISTER=1
ASK_ADVANCED=0; MQTT_HOST=""; MQTT_PORT=""; TOPIC_ROOT=""
CONTROL_PINS_TSV=""; CONTROL_ACTUATOR_JSON=""; CONTROL_VARIANT=""
UI=0; UI_PORT=8088; UI_BIND="0.0.0.0"; UI_DIR=""; UI_PID=""; UI_TOKEN=""; STAGE=""
UI_INSECURE=0; UI_MANAGED=0; TOKEN_FD=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)     usage; exit 0 ;;
    --ui)          UI=1;             shift ;;
    --ui-insecure) UI=1; UI_INSECURE=1; shift ;;
    --ui-spool)    UI=1; UI_MANAGED=1; UI_DIR="${2:-}"; shift 2 ;;
    --token-fd)    TOKEN_FD="${2:-}"; shift 2 ;;
    --ui-port)     UI_PORT="${2:-}"; shift 2 ;;
    --ui-bind)     UI_BIND="${2:-}"; shift 2 ;;
    --offline)     OFFLINE=1;         shift ;;
    --preview)     WANT_PREVIEW=1;    shift ;;
    -p|--port)     PORT="${2:-}";     shift 2 ;;
    -f|--firmware) FIRMWARE="${2:-}"; shift 2 ;;
    -b|--baud)     BAUD="${2:-}";     shift 2 ;;
    -s|--ssid)     SSID="${2:-}";     shift 2 ;;
    --psk)         PSK="${2:-}";      shift 2 ;;
    --role)        ROLE="$(tr '[:lower:]' '[:upper:]' <<<"${2:-}")"; shift 2 ;;
    --unit)        UNIT_WANTED="${2:-}";  shift 2 ;;
    --zone)        ZONE_WANTED="${2:-}";  shift 2 ;;
    --unregistered) UNREGISTERED=1;       shift ;;
    --no-register) DO_REGISTER=0;         shift ;;
    --advanced)    ASK_ADVANCED=1;        shift ;;
    --mqtt-host)   MQTT_HOST="${2:-}";    shift 2 ;;
    --mqtt-port)   MQTT_PORT="${2:-}";    shift 2 ;;
    --topic-root)  TOPIC_ROOT="${2:-}";   shift 2 ;;
    --no-erase)    DO_ERASE=0;        shift ;;
    -y|--yes)      ASSUME_YES=1;      shift ;;
    *) echo "Unknown option: $1" >&2; echo >&2; usage >&2; exit 2 ;;
  esac
done
if [ -n "$TOKEN_FD" ]; then
  [[ "$TOKEN_FD" =~ ^[0-9]+$ ]] || { echo "--token-fd: not a descriptor number: $TOKEN_FD" >&2; exit 2; }
  [ "$UI_MANAGED" = 1 ] || { echo "--token-fd is only for --ui-spool (set by the wizard daemon)" >&2; exit 2; }
  { : >&"$TOKEN_FD"; } 2>/dev/null || { echo "--token-fd $TOKEN_FD is not open" >&2; exit 2; }
fi

set -e

# config.env is optional only for --unregistered. Everywhere else it carries the
# facts a board needs and nobody should have to retype: the address of the
# broker it publishes to and the topic root the rest of the platform listens on.
# shellcheck source=/dev/null
[ -f "$REPO_ROOT/config.env" ] && source "$REPO_ROOT/config.env"
PROJECT_NAME="${PROJECT_NAME:-medcea}"

# Inferred, in this order: what was passed on the command line, what config.env
# computed, what this host can work out for itself.
#
# The LAN address, not the Tailscale one: IoT devices sit on the LAN, and a
# board that cannot route to the broker is a board that boots and publishes
# nothing. Give the host a DHCP reservation — this address ends up baked into
# every board flashed today.
TOPIC_ROOT="${TOPIC_ROOT:-$PROJECT_NAME}"
MQTT_PORT="${MQTT_PORT:-31883}"        # the Mosquitto NodePort, deploy-infra.sh
if [ -z "$MQTT_HOST" ]; then
  MQTT_HOST="${_LAN_IP:-}"
  [ -n "$MQTT_HOST" ] || MQTT_HOST="$(ip route get 8.8.8.8 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
fi

APP_DIR="$SCRIPT_DIR/src/app"
export SRC_HOST

# ------------------------------------------------------------- helpers --------
if [ -t 1 ]; then
  B=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; N=$'\033[0m'
else
  B=""; DIM=""; RED=""; YEL=""; GRN=""; N=""
fi
# --- browser mirror ----------------------------------------------------------
# The terminal stays the primary surface; the UI is a mirror of it plus a place
# to answer prompts. Colour codes are stripped on the way into the log so the
# page shows text, not escape sequences.
ui_on()     { [ "$UI" = 1 ] && [ -n "$UI_DIR" ]; }
ui_append() {
  ui_on || return 0
  printf '%s\n' "$*" | sed -r 's/\x1b\[[0-9;]*[mK]//g' >> "$UI_DIR/log" 2>/dev/null || true
}
ui_phase()  { ui_on || return 0; printf '%s' "$*" > "$UI_DIR/phase" 2>/dev/null || true; }
# Pass a command's output through to the terminal unchanged while copying a
# cleaned version into the log. esptool draws progress with \r, which would
# otherwise arrive as one enormous line.
ui_tee() {
  if ui_on; then tee >(tr '\r' '\n' | sed -r 's/\x1b\[[0-9;]*[mK]//g' >> "$UI_DIR/log" 2>/dev/null)
  else cat; fi
}

step()  { printf '\n%s==> %s%s\n' "$B" "$*" "$N"; ui_append ""; ui_append "==> $*"; ui_phase "$*"; }
info()  { printf '    %s\n' "$*"; ui_append "    $*"; }
warn()  { printf '%s !  %s%s\n' "$YEL" "$*" "$N" >&2; ui_append " !  $*"; }
die()   { printf '%s !! %s%s\n' "$RED" "$*" "$N" >&2; ui_append " !! $*"; exit 1; }
# EOF is not an answer. Without this, running the script with stdin closed —
# `< /dev/null`, a cron entry, a `timeout` that detached the terminal — makes
# any re-asking prompt spin forever on an empty reply nobody typed.
ask()   {
  local p="$1" d="${2:-}" r
  if ! read -r -p "    $p" r; then
    printf '\n' >&2
    die "no more input (stdin closed) — this step needs an answer"
  fi
  echo "${r:-$d}"
}

# --- prompts -----------------------------------------------------------------
# One question, answered in whichever surface is active. In UI mode the shell
# blocks on a file the server writes, so the script remains the single engine —
# there is no second copy of the flow to drift out of sync.
CHOICES=(); ANSWER=""
# These set $ANSWER rather than echoing it, and that is load-bearing: a
# $(command substitution) runs in a subshell, and bash defers a signal trap
# until the current foreground command finishes. Blocking for a browser answer
# inside one made the script unkillable by Ctrl-C — the trap could never run, so
# the spool directory (which holds the WebREPL password) leaked on every abort.
ui_wait_answer() {
  local json="$1" f="$UI_DIR/answer"
  rm -f "$f"
  printf '%s' "$json" > "$UI_DIR/prompt.json.tmp"
  mv "$UI_DIR/prompt.json.tmp" "$UI_DIR/prompt.json"
  while [ ! -f "$f" ]; do
    if [ -n "$UI_PID" ] && ! kill -0 "$UI_PID" 2>/dev/null; then
      rm -f "$UI_DIR/prompt.json"
      die "the browser UI stopped; re-run without --ui to answer in the terminal"
    fi
    sleep 0.3          # short, so a queued trap runs promptly
  done
  ANSWER="$(cat "$f")"; rm -f "$f"
}
# Build the prompt JSON with python so a label or an SSID containing quotes,
# backslashes or non-ASCII cannot break the payload.
ui_prompt_json() {
  local kind="$1" label="$2" default="$3" hint="$4"
  KIND="$kind" LABEL="$label" DEF="$default" HINT="$hint" ID="$RANDOM$$$(date +%s%N)" \
  python3 -c '
import json, os, sys
e = os.environ
print(json.dumps({"id": e["ID"], "kind": e["KIND"], "label": e["LABEL"],
                  "default": e["DEF"], "hint": e["HINT"],
                  "submit_on_click": e["KIND"] == "choice",
                  "options": [l.rstrip("\n") for l in sys.stdin.read().split("\x00") if l]}))' \
  < <(printf '%s\0' "${CHOICES[@]:-}")
}
prompt_text()    { # label default [hint]   -> $ANSWER
  if ui_on; then CHOICES=(); ui_wait_answer "$(ui_prompt_json text "$1" "${2:-}" "${3:-}")"
  else ANSWER="$(ask "$1" "${2:-}")"; fi
}
prompt_secret()  { # label [hint]          -> $ANSWER
  if ui_on; then CHOICES=(); ui_wait_answer "$(ui_prompt_json secret "$1" "" "${2:-}")"
  else read -r -s -p "    $1" ANSWER; echo; fi
}
prompt_confirm() { # label [hint]          -> $ANSWER = y|n
  if ui_on; then CHOICES=(); ui_wait_answer "$(ui_prompt_json confirm "$1" n "${2:-}")"
  else ANSWER="$(ask "$1 [y/N]: " n)"; fi
}
prompt_choice()  { # label default [hint]  -> $ANSWER, options in CHOICES
  if ui_on; then ui_wait_answer "$(ui_prompt_json choice "$1" "${2:-}" "${3:-}")"
  else ANSWER="$(ask "$1" "${2:-}")"; fi
}
# The channel map is the one question a terminal cannot ask well: it is a table
# with a live verdict on it, not a value. In the browser it is one prompt whose
# payload is the whole editable map; in a terminal the caller falls back to
# asking for one address at a time, which is why this returns empty rather than
# dying when there is no UI.
prompt_channelmap() { # label spec-file [hint]  -> $ANSWER = the edited config JSON
  ui_on || { ANSWER=""; return 0; }
  CHOICES=()
  ui_wait_answer "$(
    KIND=channelmap LABEL="$1" SPECF="$2" HINT="${3:-}" \
    ID="$RANDOM$$$(date +%s%N)" python3 -c '
import json, os
e = os.environ
with open(e["SPECF"], encoding="utf-8") as f:
    spec = json.load(f)
print(json.dumps({"id": e["ID"], "kind": e["KIND"], "label": e["LABEL"],
                  "default": "", "hint": e["HINT"], "submit_on_click": False,
                  "options": [], "spec": spec}))')"
}
ui_waiting() { ui_on && info "${DIM}→ answer in the browser${N}" || true; }

# --- who this run acts as (IAM 1.5) -------------------------------------------
# A holder — wizard_server (daemon or --ui) or the edge_auth.py agent (terminal)
# — keeps the refresh token and the client secret. This shell only ever asks it
# for an access token, right before each platform_db call, so every call has a
# token with time left however long the wiring questions took. TOK_R/TOK_W are
# the channel: the daemon's socketpair fd (both the same), or a coproc's saved
# fds (bash unsets the coproc array when it exits, and children never inherit
# them). None of these is exported.
TOK_R=""; TOK_W=""; AUTH_PID=""; EDGE_TOKEN=""; EDGE_USER=""; EDGE_NAME=""; EDGE_ROLE=""
EDGE_AUTH_CODE=""; EDGE_AUTH_MSG=""
# Phase 2 of the IAM plan: config-api verifies the token, so a missing one is a
# refusal rather than a note. deploy-infra.sh sets it with config-api's JWT key.
phase2() { [ "${IAM_POSTGREST_JWT:-false}" = true ]; }

# The device-code box. Terminal only: the code is a credential for the next few
# minutes, and the browser log is readable by whoever watches the wizard page.
token_show_device() { # uri code expires_in
  local mins=$(( (${3:-600} + 59) / 60 ))
  printf '\n    %sThis run reads and writes the platform database as you.%s\n' "$B" "$N"
  printf '    On any device with a browser open:  %s%s%s\n' "$B" "$1" "$N"
  printf '    and enter the code   %s%s%s\n' "$B" "$2" "$N"
  printf '    Waiting — the code expires in %s min. Ctrl-C stops; nothing has been written.\n\n' "$mins"
  ui_append "    sign in: open $1 and enter the code shown in the terminal"
}

# token_get MIN_TTL WHY -> EDGE_TOKEN, EDGE_USER, EDGE_NAME, EDGE_ROLE, or
# EDGE_AUTH_CODE/EDGE_AUTH_MSG and status 1. Sets globals like the prompts do,
# and for the same reason is never called inside $(…): a wait for a sign-in can
# be long, and a trap cannot run while a command substitution blocks.
# One reply is one write of at most 4096 bytes, but `read -t` returns whatever
# had arrived when it timed out, so a partial read is kept and continued.
token_get() {
  local _buf="" _part="" _rc=0 _line kind f1 f2 f3 f4 f5
  EDGE_TOKEN=""; EDGE_AUTH_CODE=""; EDGE_AUTH_MSG=""
  if [ -z "$TOK_R" ] || [ -z "$TOK_W" ]; then
    EDGE_AUTH_CODE=no_session; EDGE_AUTH_MSG="not signed in"; return 1
  fi
  # SIGPIPE is ignored for this one write: a holder whose end has closed (the
  # daemon's serve thread ended, a coproc not yet reaped) would otherwise kill
  # this shell on the spot — exit 141, no EXIT trap, so no cleanup, no record,
  # no `finished` — instead of failing the write into the branch below. Only
  # around the write, because children inherit an ignored SIGPIPE.
  trap '' PIPE
  { printf 'token\t%s\t%s\n' "$1" "${2//$'\t'/ }" >&"$TOK_W"; } 2>/dev/null
  _rc=$?
  trap - PIPE
  if [ "$_rc" -ne 0 ]; then
    token_close
    EDGE_AUTH_CODE=no_session; EDGE_AUTH_MSG="the sign-in helper stopped"; return 1
  fi
  while :; do
    _part=""
    if IFS= read -r -t 1 _part <&"$TOK_R"; then
      _line="$_buf$_part"; _buf=""
      IFS=$'\t' read -r kind f1 f2 f3 f4 f5 <<<"$_line"
      case "$kind" in
        WAIT)
          case "$f1" in
            device) token_show_device "$f2" "$f3" "$f4" ;;
            retry)  warn "$f2" ;;
            *)      info "$f2" ;;
          esac ;;
        OK)
          EDGE_TOKEN="$f5"; EDGE_USER="$f2"; EDGE_NAME="$f3"; EDGE_ROLE="$f4"
          [ "$EDGE_NAME" = - ] && EDGE_NAME="$EDGE_USER"
          return 0 ;;
        ERR)
          EDGE_AUTH_CODE="$f1"; EDGE_AUTH_MSG="$f2"; return 1 ;;
        *)
          EDGE_AUTH_CODE=no_session; EDGE_AUTH_MSG="the sign-in helper sent something unexpected"
          return 1 ;;
      esac
    else
      _rc=$?
      if [ "$_rc" -gt 128 ]; then
        _buf="$_buf$_part"
        # A holder that died mid-request would otherwise leave this waiting for
        # ever. The daemon has no pid here; its end of the socket closes instead.
        if { [ -n "$AUTH_PID" ] && ! kill -0 "$AUTH_PID" 2>/dev/null; } \
           || { [ "$UI_MANAGED" != 1 ] && [ -n "$UI_PID" ] && ! kill -0 "$UI_PID" 2>/dev/null; }; then
          token_close
          EDGE_AUTH_CODE=no_session; EDGE_AUTH_MSG="the sign-in helper stopped"; return 1
        fi
        continue
      fi
      # EOF: the holder is gone for good. Closing the channel makes every later
      # call return at once instead of writing into a dead socket.
      token_close
      EDGE_AUTH_CODE=no_session; EDGE_AUTH_MSG="the sign-in helper stopped"; return 1
    fi
  done
}

# Every platform_db call goes through this, with the token on fd 3.
#  - printf is a builtin, so the token is never in any process's argv;
#  - <(…) is always a pipe; never "simplify" it to 3<<<, which bash may back
#    with a temporary file on disk;
#  - 3< shadows any fd 3 this shell inherited, for this one command.
# PLATFORM_DB_TOKEN_FD is empty without a token, so platform_db reads nothing.
platdb() {
  PLATFORM_DB_TOKEN_FD=${EDGE_TOKEN:+3} IAM_POSTGREST_JWT="${IAM_POSTGREST_JWT:-false}" \
    python3 "$PLATDB" "$@" 3< <(printf '%s' "$EDGE_TOKEN")
}

# After this nothing in the run can obtain a token: the channel is closed, the
# agent (which wipes its tokens on EOF or SIGTERM) is stopped. The --ui server
# only drops the run's tokens on EOF and keeps serving the summary.
token_close() {
  EDGE_TOKEN=""
  # No 2>/dev/null on these: on a bare `exec` it would redirect the whole
  # script's stderr for good, and closing an fd with >&- cannot fail anyway.
  if [ -n "$TOK_W" ]; then exec {TOK_W}>&-; fi
  if [ -n "$TOK_R" ] && [ "$TOK_R" != "$TOK_W" ]; then exec {TOK_R}<&-; fi
  TOK_R=""; TOK_W=""
  if [ -n "$AUTH_PID" ]; then kill "$AUTH_PID" 2>/dev/null || true; AUTH_PID=""; fi
}

# The terminal holder: edge_auth.py agent, signing in with the device grant.
# Lazy — it does nothing until the first token request. The secret reaches it
# in its environment only (argv is world-readable), and it pops it.
auth_start_agent() {
  local _iss="https://${KEYCLOAK_DOMAIN}/realms/${KEYCLOAK_REALM:-medcea}"
  coproc EDGEAUTH { EDGE_WIZARD_SECRET="$EDGE_WIZARD_SECRET" exec python3 "$SRC_HOST/edge_auth.py" agent \
      --issuer "$_iss" --client-id "${EDGE_WIZARD_CLIENT:-edge-wizard}" --oidc-insecure \
      ${EDGE_WIZARD_ROLE:+--required-role "$EDGE_WIZARD_ROLE"}; }
  AUTH_PID=$EDGEAUTH_PID; TOK_R=${EDGEAUTH[0]}; TOK_W=${EDGEAUTH[1]}
}

# What a failed token_get means for STEP (signin, board, erase, register).
# Returns 0 to carry on without a token, 1 to skip the step (register), or dies.
# Phase 1 is report-only: only an explicit decision — a sign-in denied in the
# browser, a missing role — stops the run. A device code nobody entered (an
# unattended run, no browser at hand, a pending account) is reported like any
# other missing sign-in. The role is the wizard's own gate, enforced in every
# phase; lost mid-run it stops the run before the erase and skips register.
auth_report() {
  local _msg="${EDGE_AUTH_MSG:-no valid sign-in}"
  EDGE_TOKEN=""
  if [ "$EDGE_AUTH_CODE" = role ]; then
    token_close
    case "$1" in
      signin|board|erase) die "$_msg" ;;
      register) warn "$_msg"; return 1 ;;
    esac
  fi
  case "$1" in
    signin)
      [ "$EDGE_AUTH_CODE" = denied ] && die "$_msg"
      if ! phase2; then
        warn "$_msg — platform calls are anonymous, refused from IAM Phase 2"
        return 0
      fi
      warn "$_msg"
      ui_waiting
      prompt_confirm 'Continue without a platform identity?' \
        "The board will come up as cea-un-<mac6> with no MQTT credential, no unit and no zone — the same as --unregistered. Onboard it again once you can sign in."
      [ "$ANSWER" = "y" ] || die "aborted: no sign-in, and you chose not to continue unregistered"
      UNREGISTERED=1; token_close
      return 0 ;;
    board|erase)
      if phase2; then
        die "$_msg. Nothing was erased."
      fi
      warn "no valid sign-in ($_msg) — this step would be refused from IAM Phase 2"
      return 0 ;;
    register)
      warn "no valid sign-in ($_msg) — this step would be refused from IAM Phase 2"
      phase2 && return 1
      return 0 ;;
  esac
}

# --- menus -------------------------------------------------------------------
# A numbered list, printed the same way in both surfaces. The browser gets the
# entries as CHOICES and returns an index; the terminal prints them and reads
# one. Keeping the numbering in one place is what stops "[3]" meaning different
# things on the two screens — which is not a cosmetic bug when [3] is a zone.
MENU=()
menu_reset() { MENU=(); }
menu_add()   { MENU+=("$1|${2:-}"); }         # label [tag]
menu_head()  { MENU+=("## $1"); }
menu_count() { local n=0 e; for e in "${MENU[@]:-}"; do [[ "$e" == "## "* ]] || n=$((n+1)); done; echo "$n"; }
# label hint [default-index]  ->  $ANSWER = 1-based index into the non-header
# entries, guaranteed in range.
menu_ask() {
  local label="$1" hint="${2:-}" def="${3:-}" n i e lbl tag
  n="$(menu_count)"
  [ "$n" -gt 0 ] || die "internal: menu_ask with no options"
  while :; do
    echo
    i=0
    for e in "${MENU[@]}"; do
      if [[ "$e" == "## "* ]]; then
        printf '      %s%s%s\n' "$DIM" "${e:3}" "$N"
      else
        i=$((i+1)); lbl="${e%%|*}"; tag="${e#*|}"
        printf '      [%2d] %-44s %s%s%s\n' "$i" "$lbl" "$DIM" "$tag" "$N"
      fi
    done
    echo
    CHOICES=("${MENU[@]}")
    ui_waiting
    if [ -n "$def" ]; then
      prompt_choice "$label [1-$n, Enter = $def]: " "$def" "$hint"
    else
      prompt_choice "$label [1-$n]: " "" "$hint"
    fi
    if [[ "$ANSWER" =~ ^[0-9]+$ ]] && [ "$ANSWER" -ge 1 ] && [ "$ANSWER" -le "$n" ]; then
      return 0
    fi
    warn "pick a number between 1 and $n"
  done
}

# --- template answers --------------------------------------------------------
# SENSORS_TSV accumulates "<driver>\t<param>\t<value>" lines, one per answer,
# with a "<driver>\t\t" marker line so a driver that has no parameters is still
# recorded as present.
SENSORS_TSV=""
# Filled by the caller before ask_param() is used for a `choice` parameter; an
# unset array is fatal under `set -u`, and this is read on paths where no
# driver params have been loaded yet.
PARAMS=()
driver_chosen() { [ -n "$SENSORS_TSV" ] && grep -q "^$1"$'\t' <<<"$SENSORS_TSV"; }
chosen_count()  {
  [ -n "$SENSORS_TSV" ] || { echo 0; return; }
  awk -F'\t' 'NF && !seen[$1]++ {n++} END{print n+0}' <<<"$SENSORS_TSV"
}

# Ask one template parameter.  name kind default label hint  ->  $ANSWER
# Never returns empty: an unanswered question keeps the template's default,
# because a blank GPIO number reaching the board is a driver failing at 3am
# rather than a question failing here.
ask_param() {
  local name="$1" kind="$2" def="$3" label="$4" hint="$5"
  case "$kind" in
    bool)
      # A two-option menu rather than prompt_confirm, which is hardwired to
      # "[y/N]" and so cannot show a template default of true without
      # contradicting itself on screen.
      menu_reset
      menu_add "Yes" ""
      menu_add "No"  ""
      ui_waiting
      if [ "$def" = "true" ]; then
        menu_ask "$label?" "$hint" 1
      else
        menu_ask "$label?" "$hint" 2
      fi
      [ "$ANSWER" = "1" ] && ANSWER="true" || ANSWER="false"
      ;;
    choice)
      menu_reset
      local n=0 sel=1 ovalue olabel
      while IFS=$'\t' read -r _k _p ovalue olabel; do
        n=$((n+1)); menu_add "$olabel" "$ovalue"
        [ "$ovalue" = "$def" ] && sel="$n"
      done < <(printf '%s\n' "${PARAMS[@]}" | awk -F'\t' -v p="$name" '$1=="OPTION" && $2==p')
      if [ "$n" -eq 0 ]; then ANSWER="$def"; return 0; fi
      ui_waiting
      menu_ask "$label" "$hint" "$sel"
      ANSWER="$(printf '%s\n' "${PARAMS[@]}" \
                | awk -F'\t' -v p="$name" -v i="$ANSWER" \
                      '$1=="OPTION" && $2==p { n++; if (n==i) { print $3; exit } }')"
      [ -n "$ANSWER" ] || ANSWER="$def"
      ;;
    *)
      ui_waiting
      prompt_text "$label [$def]: " "$def" "$hint"
      [ -n "$ANSWER" ] || ANSWER="$def"
      ;;
  esac
}

# Every capture from the board goes through this. mpremote relays the board's
# serial output with CRLF line endings, and a lone \r survives both awk's field
# splitting (it is not whitespace to awk) and command substitution (which strips
# trailing newlines, not carriage returns). It then rides inside the captured
# value, and on the next printf it resets the cursor to column 0 and overwrites
# the start of the line — and lands in the provisioning record as "192.168.1.1\r".
mpy() { $SUDO "$MPREMOTE" connect "$PORT" "$@" | tr -d '\r'; }

# ------------------------------------------------------------- cleanup --------
# One trap for everything: the staging dir, the spool dir and the server. Set
# before anything is created so an early die() still tidies up.
cleanup() {
  local rc=$?
  if [ -n "$UI_DIR" ] && [ -d "$UI_DIR" ]; then
    printf '%s' "$rc" > "$UI_DIR/finished" 2>/dev/null || true
    # Give a watching browser a moment to fetch the final state before the
    # server goes away, otherwise the page just says "disconnected".
    if [ "$UI_MANAGED" != 1 ]; then
      [ "$rc" -eq 0 ] && [ -f "$UI_DIR/done.json" ] && sleep 3
      : > "$UI_DIR/stop" 2>/dev/null || true
    fi
  fi
  token_close 2>/dev/null || true
  [ -n "$UI_PID" ] && kill "$UI_PID" 2>/dev/null || true
  [ -n "$STAGE" ]  && rm -rf "$STAGE" 2>/dev/null || true
  # Only remove the spool if this run created it. Under --ui-spool the daemon
  # owns it and is still serving the summary from it.
  if [ "$UI_MANAGED" != 1 ] && [ -n "$UI_DIR" ]; then rm -rf "$UI_DIR" 2>/dev/null || true; fi
  return 0
}
# EXIT alone is not enough: bash does not run an EXIT trap when it dies on an
# unhandled signal, so a Ctrl-C or a `timeout` would leave the spool directory
# behind — and that directory can hold the WebREPL password in done.json and a
# just-submitted WiFi PSK in the answer file. Catch the signals, clean up, then
# die with the conventional 128+signal status.
trap cleanup EXIT
for _sig in INT TERM HUP; do
  # shellcheck disable=SC2064  # $_sig must expand now, not at trap time
  trap "cleanup; trap - $_sig EXIT; kill -s $_sig \$\$" "$_sig"
done

# ---------------------------------------------------- 0. browser UI -----------
if [ "$UI" = 1 ] && [ "$UI_MANAGED" = 1 ]; then
  # A wizard daemon already owns the spool, the server and the Keycloak session.
  # This run just writes into it.
  [ -d "$UI_DIR" ] || { echo "--ui-spool: no such directory: $UI_DIR" >&2; exit 2; }
  step "Browser UI"
  info "attached to the wizard daemon's session"
  if [ -n "$TOKEN_FD" ]; then
    TOK_R=$TOKEN_FD; TOK_W=$TOKEN_FD
  elif [ "$UNREGISTERED" != 1 ]; then
    phase2 && die "started without a sign-in channel: restart cea-edge-wizard (apps/edge-wizard/deploy.sh)"
    warn "the wizard daemon predates IAM 1.5 (no sign-in channel): platform calls are anonymous — restart cea-edge-wizard"
  fi
elif [ "$UI" = 1 ]; then
  UI_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cea-wizard.XXXXXX")"
  chmod 700 "$UI_DIR"
  : > "$UI_DIR/log"
  ONBOARD_URL="https://${CONFIG_DOMAIN:-config.example.invalid}/#devices"

  # Provisioning is an authenticated operation: it mints credentials and it is
  # how hardware gets into the fleet. Keycloak is the platform's identity
  # provider, so the wizard uses it rather than inventing a second one.
  UI_AUTH="token"
  if [ -n "${EDGE_WIZARD_SECRET:-}" ] && [ -n "${KEYCLOAK_DOMAIN:-}" ]; then
    UI_AUTH="keycloak"
  elif [ "$UI_INSECURE" = 1 ]; then
    warn "running the wizard with a URL token instead of Keycloak (--ui-insecure)"
  else
    die "the browser UI needs Keycloak: EDGE_WIZARD_SECRET is not set in config.env.
       Run ./deploy-infra.sh to create the 'edge-wizard' client, or pass
       --ui-insecure to fall back to a URL token on a bench you trust."
  fi

  _kc_args=()
  if [ "$UI_AUTH" = keycloak ]; then
    # The redirect URI is registered in Keycloak per address and port, so the
    # port cannot be ephemeral here.
    if [ "$UI_PORT" = 0 ]; then
      die "--ui-port 0 cannot be used with Keycloak: the redirect URI is registered
       against a fixed port. Use --ui-port ${EDGE_WIZARD_PORT:-8088}."
    fi
    _iss="https://${KEYCLOAK_DOMAIN}/realms/${KEYCLOAK_REALM:-medcea}"
    # No secret here: it goes in the server's environment (argv is world-readable).
    _kc_args=(--auth keycloak --issuer "$_iss"
              --client-id "${EDGE_WIZARD_CLIENT:-edge-wizard}" --oidc-insecure
              --token-channel stdio)
    [ -n "${EDGE_WIZARD_ROLE:-}" ] && _kc_args+=(--required-role "$EDGE_WIZARD_ROLE")
  fi

  # Addresses the browser may legitimately reach this on. Each is also a
  # registered redirect URI; anything else is refused before Keycloak sees it.
  # Rebuilt after the server reports its port, because --ui-port 0 means the
  # real port is not known until then.
  _lan="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  _ts="$(tailscale ip -4 2>/dev/null | head -1 || true)"
  build_hosts() {
    _hosts=()
    case "$UI_BIND" in
      0.0.0.0|"::"|"")
        [ -n "$_lan" ] && _hosts+=("$_lan:$UI_PORT")
        [ -n "$_ts" ]  && _hosts+=("$_ts:$UI_PORT")
        _hosts+=("127.0.0.1:$UI_PORT" "localhost:$UI_PORT") ;;
      127.0.0.1|localhost)
        _hosts+=("127.0.0.1:$UI_PORT" "localhost:$UI_PORT") ;;
      *)
        _hosts+=("$UI_BIND:$UI_PORT") ;;
    esac
  }
  build_hosts
  _host_args=(); for h in "${_hosts[@]}"; do _host_args+=(--allowed-host "$h"); done

  UI_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
  if [ "$UI_AUTH" = keycloak ]; then
    # A coproc, so the server is also this run's token holder: the first
    # Keycloak sign-in through the link printed below (it carries $UI_TOKEN)
    # binds the run (--token-channel stdio).
    coproc WIZ { EDGE_WIZARD_SECRET="$EDGE_WIZARD_SECRET" exec python3 "$SRC_HOST/wizard_server.py" \
        --dir "$UI_DIR" --token "$UI_TOKEN" \
        --port "$UI_PORT" --bind "$UI_BIND" --onboard-url "$ONBOARD_URL" \
        --parent-pid $$ "${_kc_args[@]}" "${_host_args[@]}"; }
    UI_PID=$WIZ_PID; TOK_R=${WIZ[0]}; TOK_W=${WIZ[1]}
  else
    python3 "$SRC_HOST/wizard_server.py" --dir "$UI_DIR" --token "$UI_TOKEN" \
        --port "$UI_PORT" --bind "$UI_BIND" --onboard-url "$ONBOARD_URL" \
        --parent-pid $$ "${_host_args[@]}" &
    UI_PID=$!
  fi

  for _ in $(seq 1 60); do [ -s "$UI_DIR/server.port" ] && break; sleep 0.1; done
  if ! kill -0 "$UI_PID" 2>/dev/null || [ ! -s "$UI_DIR/server.port" ]; then
    die "the browser UI failed to start — port $UI_PORT may be in use, or Keycloak
       at ${KEYCLOAK_DOMAIN:-?} may be unreachable."
  fi
  UI_PORT="$(cat "$UI_DIR/server.port")"
  build_hosts        # now with the port the server actually bound

  step "Browser UI"
  # Under Keycloak the token no longer admits anyone; it marks the sign-in that
  # binds the run (wizard_server _auth), so it goes to the terminal only. The
  # browser log is readable by every signed-in session, and a link copied from
  # it would let anyone bind the run.
  _q="/?t=$UI_TOKEN"
  _urls=(); _logurls=(); for h in "${_hosts[@]}"; do
    case "$h" in localhost:*) continue ;; esac      # 127.0.0.1 already covers it
    _urls+=("http://$h$_q")
    if [ "$UI_AUTH" = keycloak ]; then _logurls+=("http://$h/"); else _logurls+=("http://$h$_q"); fi
  done
  if [ "$UI_AUTH" = keycloak ]; then
    info "Open this exact link and sign in with Keycloak — the run acts as whoever does:"
  else
    info "Open this — the token is required:"
  fi
  for u in "${_urls[@]}"; do printf '      %s%s%s\n' "$B" "$u" "$N"; done
  for u in "${_logurls[@]}"; do ui_append "      $u"; done
  if [ "$UI_AUTH" = keycloak ]; then
    info "${DIM}realm ${KEYCLOAK_REALM:-medcea} at ${KEYCLOAK_DOMAIN}${N}"
    [ -n "${EDGE_WIZARD_ROLE:-}" ] && info "${DIM}requires the '${EDGE_WIZARD_ROLE}' realm role${N}"
  fi
  case "$UI_BIND" in
    127.0.0.1|localhost)
      info "${DIM}loopback only — from your laptop:${N}"
      info "${DIM}  ssh -L $UI_PORT:127.0.0.1:$UI_PORT $(id -un)@$(hostname -f 2>/dev/null || hostname)${N}" ;;
  esac
  info "Prompts are answered in the browser from here on."
fi

# ------------------------------------------ 0.5 role, slot and template -------
# Asked FIRST, before the toolchain and the flash, and deliberately so. These
# are the questions only the operator standing at the chamber can answer; the
# twenty minutes of erase, write and verify that follow need nobody. Asking
# them at the end is how a board gets flashed and then abandoned half-onboarded
# because the person walked away.
#
# A device's identity is not typed, it is CHOSEN from the platform database:
#
#   unit01-s-zone01     lower(unit) - s|c - lower(zone): the board's one name
#
# and a unit/zone has one and only one SENSE and one and only one CONTROL, so a
# slot that is already filled is not offered. Nothing here asks for an MQTT
# host, a topic or a client id: those follow from the slot and from config.env,
# and an operator retyping them is only an opportunity to get them wrong.
PLATDB="$SRC_HOST/platform_db.py"
TEMPLATE_TOOL="$SRC_HOST/device_template.py"
UNIT_CODE=""; ZONE_CODE=""; ZONE_ID=""; SLOT_DNS=""
SENSORS_TSV=""; CONTROL_PINS_TSV=""; CONTROL_DRIVER="relay8"
MESSAGE_INTERVAL=""; POLL_MS=""

# --- sign in -------------------------------------------------------------------
# Before the first database call: the slots are read, and later written, as the
# person onboarding the board. The browser modes already have a holder; a
# terminal run starts the device-grant agent here.
if [ "$UNREGISTERED" != 1 ]; then
  step "Sign in"
  if [ -z "$TOK_W" ] && [ "$UI_MANAGED" != 1 ]; then
    if [ "$ASSUME_YES" = 1 ] && [ ! -t 0 ] && ! phase2; then
      # A scripted run: nobody is there to enter a device code, and waiting the
      # code's ten minutes out would only delay the same anonymous run.
      warn "not signed in: --yes without a terminal — platform calls are anonymous (refused from IAM Phase 2)"
    elif [ -n "${EDGE_WIZARD_SECRET:-}" ] && [ -n "${KEYCLOAK_DOMAIN:-}" ]; then
      auth_start_agent
    elif phase2; then
      die "registered onboarding needs a Keycloak sign-in: run ./deploy-infra.sh, or use --unregistered"
    else
      warn "not signed in: EDGE_WIZARD_SECRET is not in config.env — platform calls are anonymous (refused from IAM Phase 2)"
    fi
  fi
  if [ -n "$TOK_W" ]; then
    if token_get 120 "read the free slots"; then
      info "signed in as ${B}$EDGE_NAME${N} ($EDGE_USER, $EDGE_ROLE) — this run acts as this person"
    else
      auth_report signin
    fi
  fi
fi

if [ "$UNREGISTERED" != 1 ]; then
  step "Platform slot"
  SLOTS=""
  if ! SLOTS="$(platdb slots 2>&1)" || ! grep -q '^SLOT' <<<"$SLOTS"; then
    warn "the platform database did not answer:"
    printf '%s\n' "$SLOTS" | sed 's/^/       /' >&2
    echo "    Units and zones live in the database, so without it this board"
    echo "    cannot be given a slot. It can still be brought up unregistered."
    ui_waiting
    prompt_confirm 'Continue without a platform identity?' \
      "The board will come up as cea-un-<mac6> with no MQTT credential, no unit and no zone — the same as --unregistered. Onboard it again once the platform is reachable."
    [ "$ANSWER" = "y" ] || die "aborted: no platform database, and you chose not to continue unregistered"
    UNREGISTERED=1
    token_close
  fi
fi

if [ "$UNREGISTERED" != 1 ]; then
  # --- role ---
  if [ -z "$ROLE" ]; then
    menu_reset
    menu_add "SENSE"   "reads the chamber and publishes"
    menu_add "CONTROL" "drives the chamber's relays"
    ui_waiting
    menu_ask "What is this board for?" \
      "SENSE boards publish readings; CONTROL boards subscribe to the scheduler and switch equipment. A unit/zone has exactly one of each."
    case "$ANSWER" in 1) ROLE=SENSE ;; 2) ROLE=CONTROL ;; esac
  fi
  info "role: ${B}$ROLE${N}"

  # --- slot ---
  # Free slots are offered; taken ones are listed separately rather than shown
  # greyed out in the same numbering, because a menu you can typo into a
  # rejected entry is worse than one that only holds valid answers.
  mapfile -t FREE < <(awk -F'\t' -v r="$ROLE" '$1=="SLOT" && $5==r && $6=="free"' <<<"$SLOTS")
  mapfile -t BUSY < <(awk -F'\t' -v r="$ROLE" '$1=="SLOT" && $5==r && $6=="taken"' <<<"$SLOTS")
  mapfile -t UNNAMED < <(awk -F'\t' -v r="$ROLE" '$1=="SLOT" && $5==r && $6=="unnamed"' <<<"$SLOTS")

  if [ "${#BUSY[@]}" -gt 0 ]; then
    info "${DIM}already has a $ROLE:${N}"
    for b in "${BUSY[@]}"; do
      IFS=$'\t' read -r _ bu bz _ _ _ _ _ bocc _ <<<"$b"
      info "  ${DIM}$bu / $bz  ->  ${bocc}${N}"
    done
  fi

  # Slots whose codes cannot form a hostname are not offered: the name is the
  # codes lowercased and nothing else, so the fix is renaming the code.
  if [ "${#UNNAMED[@]}" -gt 0 ] && [ -n "${UNNAMED[0]:-}" ]; then
    for b in "${UNNAMED[@]}"; do
      IFS=$'\t' read -r _ _ _ _ _ _ _ _ breason _ <<<"$b"
      warn "not offered: $breason"
    done
  fi

  if [ -n "$UNIT_WANTED" ] || [ -n "$ZONE_WANTED" ]; then
    # Non-interactive selection still goes through the free list, so --unit/--zone
    # cannot quietly overwrite a slot that already has a board in it.
    mapfile -t FREE < <(printf '%s\n' "${FREE[@]:-}" | awk -F'\t' \
      -v u="$UNIT_WANTED" -v z="$ZONE_WANTED" \
      '(u=="" || $2==u) && (z=="" || $3==z)')
  fi

  if [ "${#FREE[@]}" -eq 0 ] || [ -z "${FREE[0]:-}" ]; then
    warn "every $ROLE slot is taken${UNIT_WANTED:+ for unit $UNIT_WANTED}${ZONE_WANTED:+ zone $ZONE_WANTED}."
    echo "    A unit/zone holds one and only one $ROLE. Free one by marking the"
    echo "    existing device inactive in the Devices tab, or add a zone in Units."
    die "no free $ROLE slot"
  fi

  if [ "${#FREE[@]}" -eq 1 ]; then
    SLOT_LINE="${FREE[0]}"
    IFS=$'\t' read -r _ UNIT_CODE ZONE_CODE ZONE_ID _ _ SLOT_DNS _ _ _ _ <<<"$SLOT_LINE"
    info "only one free $ROLE slot: ${B}$UNIT_CODE / $ZONE_CODE${N}"
  else
    menu_reset
    for f in "${FREE[@]}"; do
      IFS=$'\t' read -r _ fu fz _ _ _ fdns _ _ ftype fdesc <<<"$f"
      menu_add "$fu / $fz" "$fdns${ftype:+ · $ftype}${fdesc:+ · $fdesc}"
    done
    ui_waiting
    menu_ask "Which unit and zone is this board going into?" \
      "Only free $ROLE slots are listed. Each is one physical zone of one chamber."
    SLOT_LINE="${FREE[$((ANSWER-1))]}"
    IFS=$'\t' read -r _ UNIT_CODE ZONE_CODE ZONE_ID _ _ SLOT_DNS _ _ _ _ <<<"$SLOT_LINE"
  fi

  [ -n "$SLOT_DNS" ] || die "internal: the platform returned a free slot with no hostname"
  # One name: the DHCP hostname, which is also dns_name and the payload's device_dns.
  info "hostname   : ${B}$SLOT_DNS${N}   ${DIM}(DHCP name, dns_name and MQTT device_dns)${N}"
fi

# ------------------------------------------------- 0.6 what is wired up -------
# The questions come from edge/templates/<role>.json, not from here — adding a
# supported sensor is adding an entry there plus a branch in cea_sense.py. Only
# the fields the template marks as asked are asked; everything derivable is
# derived. Defaults are the reference build's wiring, so pressing Enter through
# the whole thing produces the board the fleet already runs.
if [ "$UNREGISTERED" != 1 ]; then
  step "What is wired to this board"

  mapfile -t TPL < <(python3 "$TEMPLATE_TOOL" drivers "$ROLE") \
    || die "cannot read the $ROLE template"
  printf '%s\n' "${TPL[@]}" | grep -q '^DRIVER' \
    || die "the $ROLE template offers no drivers"

  # Say what will be filled in without asking. Printing it is the difference
  # between "inferred" and "silently assumed".
  info "${DIM}inferred, not asked:${N}"
  while IFS=$'\t' read -r kind name src note; do
    [ "$kind" = "INFERRED" ] || continue
    info "  ${DIM}$(printf '%-12s' "$name") ${note:-$src}${N}"
  done < <(printf '%s\n' "${TPL[@]}")

  if [ "$ROLE" = "SENSE" ]; then
    # A SENSE board can carry several probes — the reference UNIT01_SENSE01
    # carries a water-level probe and a substrate thermometer — so this loops
    # until the operator says it is done rather than asking for one sensor.
    SENSORS_TSV=""
    while :; do
      menu_reset
      _avail=0
      while IFS=$'\t' read -r kind did dname dsub dtags; do
        [ "$kind" = "DRIVER" ] || continue
        driver_chosen "$did" && continue
        _avail=$((_avail+1)); menu_add "$dname" "$dtags"
      done < <(printf '%s\n' "${TPL[@]}")
      _added="$(chosen_count)"
      if [ "$_avail" -eq 0 ]; then
        info "every sensor this template knows about is already on the board"
        break
      fi
      if [ "$_added" -gt 0 ]; then
        menu_head "or"
        menu_add "Done - $_added sensor(s) on this board" ""
      fi
      ui_waiting
      menu_ask "Which sensor is wired to this board?" \
        "Pick one at a time. A SENSE board may carry several; each publishes its own tags."
      _pick="$ANSWER"
      # The Done entry, when present, is always the last one.
      if [ "$_added" -gt 0 ] && [ "$_pick" -gt "$_avail" ]; then break; fi

      _n=0; DRIVER_ID=""; DRIVER_NAME=""
      while IFS=$'\t' read -r kind did dname dsub dtags; do
        [ "$kind" = "DRIVER" ] || continue
        driver_chosen "$did" && continue
        _n=$((_n+1))
        if [ "$_n" -eq "$_pick" ]; then DRIVER_ID="$did"; DRIVER_NAME="$dname"; break; fi
      done < <(printf '%s\n' "${TPL[@]}")
      [ -n "$DRIVER_ID" ] || die "internal: no driver at menu position $_pick"

      info "configuring ${B}$DRIVER_NAME${N}"
      # A driver with no parameters at all still has to be recorded as present.
      SENSORS_TSV+="$DRIVER_ID"$'\t'$'\t'$'\n'
      mapfile -t PARAMS < <(python3 "$TEMPLATE_TOOL" params "$ROLE" "$DRIVER_ID")
      # `for` over the array, NOT `while read ... done < <(...)`. A redirected
      # loop hands its stdin to the loop BODY too, so the `read` inside every
      # prompt swallows the next template line and answers the question with
      # it — silently, and with a plausible-looking number.
      for _line in "${PARAMS[@]}"; do
        IFS=$'\t' read -r kind pname pkind pdef plabel phint padv <<<"$_line"
        [ "$kind" = "PARAM" ] || continue
        if [ "$padv" = "1" ] && [ "$ASK_ADVANCED" != 1 ]; then
          info "  ${DIM}$pname = $pdef   (advanced; --advanced to be asked)${N}"
          SENSORS_TSV+="$DRIVER_ID"$'\t'"$pname"$'\t'"$pdef"$'\n'
          continue
        fi
        ask_param "$pname" "$pkind" "$pdef" "$plabel" "$phint"
        SENSORS_TSV+="$DRIVER_ID"$'\t'"$pname"$'\t'"$ANSWER"$'\n'
      done
    done
    [ -n "$SENSORS_TSV" ] || die "a SENSE board with no sensor would publish nothing"

  else
    # CONTROL: one relay board, and the only question is which GPIO drives what.
    # Offering the reference wiring as a single yes is not laziness — it is the
    # layout every chamber built to the reference design actually has, and ten
    # prompts answered by reflex are ten chances to mistype a pin.
    mapfile -t FUNCS < <(python3 "$TEMPLATE_TOOL" functions "$ROLE" "$CONTROL_DRIVER") \
      || die "cannot read the $CONTROL_DRIVER wiring template"
    echo
    printf '      %-24s %s\n' "EQUIPMENT" "GPIO"
    while IFS=$'\t' read -r kind fid flabel fpin; do
      [ "$kind" = "FUNC" ] || continue
      printf '      %-24s %s\n' "$flabel" "${fpin:--}"
      ui_append "      $(printf '%-24s' "$flabel") ${fpin:--}"
    done < <(printf '%s\n' "${FUNCS[@]}")
    echo
    ui_waiting
    prompt_confirm 'Use this reference wiring?' \
      "The relay layout of the reference build. Answer no to set each GPIO yourself, or to mark equipment this chamber does not have."
    CONTROL_PINS_TSV=""; CONTROL_ACTUATOR_JSON=""; CONTROL_VARIANT=""
    if [ "$ANSWER" = "y" ]; then
      while IFS=$'\t' read -r kind fid flabel fpin; do
        [ "$kind" = "FUNC" ] || continue
        [ -n "$fpin" ] && CONTROL_PINS_TSV+="$fid"$'\t'"$fpin"$'\n'
      done < <(printf '%s\n' "${FUNCS[@]}")
    elif ui_on; then
      # In the browser the whole map is one prompt: the operator edits the
      # command table itself and sees the file being built as they go, rather
      # than answering ten questions and finding out at the end what they add
      # up to. What comes back is authoritative — render() does not re-derive it.
      _CMSPEC="$(mktemp "${TMPDIR:-/tmp}/cea-channelmap.XXXXXX.json")"
      python3 "$TEMPLATE_TOOL" channelmap "$ROLE" "$CONTROL_DRIVER" > "$_CMSPEC" \
        || { rm -f "$_CMSPEC"; die "cannot build the $CONTROL_DRIVER channel map"; }
      ui_waiting
      prompt_channelmap "Which channel drives what?" "$_CMSPEC" \
        "Every command the scheduler can send, and what it does to the relay channels. Remove the equipment this chamber does not have; the commands that needed it disappear with it."
      rm -f "$_CMSPEC"
      [ -n "$ANSWER" ] || die "the browser returned an empty channel map"
      # {"config": {...}, "variant": "esp32s3"} — the map plus the silicon it
      # was checked against.
      CONTROL_VARIANT="$(ANSWER="$ANSWER" python3 -c '
import json, os
print(json.loads(os.environ["ANSWER"]).get("variant", ""))')" \
        || die "the browser returned a channel map that is not JSON"
      CONTROL_ACTUATOR_JSON="$(ANSWER="$ANSWER" python3 -c '
import json, os
print(json.dumps(json.loads(os.environ["ANSWER"])["config"]))')" \
        || die "the browser returned a channel map with no config in it"
      [ -n "$CONTROL_VARIANT" ] && info "checked against ${B}$CONTROL_VARIANT${N}"
      # The editor already refuses to submit a table with errors in it. Checking
      # again here is what keeps a hand-crafted POST, or a version skew between
      # page and script, from reaching a board that has just been erased.
      _CMV="$(printf '%s' "$CONTROL_ACTUATOR_JSON" \
              | python3 "$TEMPLATE_TOOL" validate "$ROLE" "$CONTROL_VARIANT")" || {
        printf '%s' "$_CMV" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for f in d["findings"]:
    if f["level"] == "error":
        print("    !! %s - %s" % (f["where"], f["message"]))'
        die "the channel map has errors and was not accepted"
      }
      info "$(printf '%s' "$_CMV" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("channel map accepted (%d warning(s))" % d["warnings"])')"
    else
      info "blank or '-' means this chamber does not have that equipment"
      # `for`, not a redirected `while read` — see the note in the SENSE branch.
      for _line in "${FUNCS[@]}"; do
        IFS=$'\t' read -r kind fid flabel fpin <<<"$_line"
        [ "$kind" = "FUNC" ] || continue
        ui_waiting
        prompt_text "$flabel GPIO [${fpin:--}]: " "${fpin:--}" \
          "Blank or '-' if the chamber has no $flabel. Every command that needs it is then left out of the board's table entirely, rather than shipped as a no-op that reports success."
        case "${ANSWER:--}" in
          -) info "  ${DIM}$flabel: not fitted${N}" ;;
          *) CONTROL_PINS_TSV+="$fid"$'\t'"$ANSWER"$'\n' ;;
        esac
      done
    fi
    if [ -n "$CONTROL_ACTUATOR_JSON" ]; then
      info "$(printf '%s' "$CONTROL_ACTUATOR_JSON" | python3 -c '
import json, sys
d = json.load(sys.stdin)
pins = next((v for k, v in d.items() if k.endswith("_descriptions")), {})
print("%d channel(s), %d actuator(s) from the editor"
      % (len(pins), len(d.get("actuator_definitions", {}))))') "
    else
      [ -n "$CONTROL_PINS_TSV" ] || die "a CONTROL board with no assigned channel would drive nothing"
      info "$(grep -c . <<<"$CONTROL_PINS_TSV" || true) relay channel(s) assigned"
    fi
  fi

  # --- device-wide parameters (publish interval, poll interval) --------------
  PARAMS=()   # no OPTION lines here; ask_param falls back to the default
  for _line in "${TPL[@]}"; do
    IFS=$'\t' read -r kind pname pkind pdef plabel phint padv <<<"$_line"
    [ "$kind" = "DEVPARAM" ] || continue
    if [ "$padv" = "1" ] && [ "$ASK_ADVANCED" != 1 ]; then
      ANSWER="$pdef"
      info "${DIM}$pname = $pdef   (advanced; --advanced to be asked)${N}"
    else
      ask_param "$pname" "$pkind" "$pdef" "$plabel" "$phint"
    fi
    case "$pname" in
      message_interval) MESSAGE_INTERVAL="$ANSWER" ;;
      poll_ms)          POLL_MS="$ANSWER" ;;
    esac
  done

  # --- what was inferred, said out loud -------------------------------------
  TOPIC_BASE="$TOPIC_ROOT/$UNIT_CODE/$ZONE_CODE"
  # The broker admits nobody anonymously: this board gets its own credential.
  # Username = its one name; a fresh password on every onboarding (re-flashing
  # rotates it). The board gets the plaintext, the platform only the mosquitto
  # hash (registered in step 10 through register_mqtt_credential).
  MQTT_USER="$SLOT_DNS"
  MQTT_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
  MQTT_PASS_HASH="$(printf '%s' "$MQTT_PASS" | python3 "$REPO_ROOT/infra/mqtt-passwd.py")"
  info "mqtt       : $MQTT_HOST:$MQTT_PORT as $MQTT_USER"
  if [ "$ROLE" = "SENSE" ]; then
    info "publishes  : $TOPIC_BASE/sense/<tag>"
  else
    info "subscribes : $TOPIC_BASE/control/#"
    info "reports    : $TOPIC_BASE/control_setpoint/<tag>/<pin>"
  fi
fi

# ---------------------------------------------------- 1. toolchain ------------
step "Toolchain"
source "$SCRIPT_DIR/lib-venv.sh"
[ -x "$VENV_DIR/bin/python" ] || info "creating $VENV_DIR"
ensure_edge_venv || die "could not build the toolchain in $VENV_DIR (see above)"

# esptool 5.x installs as `esptool`; 4.x as `esptool.py`. Accept either.
if   [ -x "$VENV_DIR/bin/esptool.py" ]; then ESPTOOL="$VENV_DIR/bin/esptool.py"
elif [ -x "$VENV_DIR/bin/esptool"    ]; then ESPTOOL="$VENV_DIR/bin/esptool"
else die "esptool not found in $VENV_DIR/bin"; fi
MPREMOTE="$VENV_DIR/bin/mpremote"
[ -x "$MPREMOTE" ] || die "mpremote not found in $VENV_DIR/bin"

ESPTOOL_VER="$("$ESPTOOL" version 2>/dev/null | head -1 || echo unknown)"
MPREMOTE_VER="$("$MPREMOTE" version 2>/dev/null | head -1 || echo unknown)"
info "esptool  $ESPTOOL_VER"
info "mpremote $MPREMOTE_VER"

# ---------------------------------------------------- 2. serial port ----------
step "Serial port"
if [ -z "$PORT" ]; then
  mapfile -t PORTS < <(ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null || true)
  case "${#PORTS[@]}" in
    0) die "No /dev/ttyUSB* or /dev/ttyACM* found. Is the board plugged in?
       In a VM, check the USB device is attached to the guest, not the host." ;;
    1) PORT="${PORTS[0]}" ;;
    *) info "More than one serial device is present:"
       for i in "${!PORTS[@]}"; do
         d="$(udevadm info -q property -n "${PORTS[$i]}" 2>/dev/null \
              | sed -n 's/^ID_VENDOR_FROM_DATABASE=//p' | head -1)"
         printf '      [%d] %s  %s%s%s\n' "$((i+1))" "${PORTS[$i]}" "$DIM" "${d:-}" "$N"
       done
       CHOICES=(); for i in "${!PORTS[@]}"; do
         d="$(udevadm info -q property -n "${PORTS[$i]}" 2>/dev/null \
              | sed -n 's/^ID_VENDOR_FROM_DATABASE=//p' | head -1)"
         CHOICES+=("${PORTS[$i]}|${d:-}")
       done
       ui_waiting
       prompt_choice "Which serial port is the board on?" 1; sel="$ANSWER"
       [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le "${#PORTS[@]}" ] \
         || die "invalid selection"
       PORT="${PORTS[$((sel-1))]}" ;;
  esac
fi
[ -e "$PORT" ] || die "$PORT does not exist"
info "port: $PORT"

# The provisioning host in this deployment is not in the dialout group, so the
# port is unreadable without help. Say so precisely rather than letting esptool
# fail with a bare permission error.
SUDO=""
if [ ! -r "$PORT" ] || [ ! -w "$PORT" ]; then
  warn "$PORT is not writable by $(id -un) (owner: $(stat -c '%U:%G %a' "$PORT"))."
  echo "    The durable fix, once, then log out and back in:"
  echo "        sudo usermod -aG dialout $(id -un)"
  echo "    Or for this session only:  newgrp dialout"
  # Under the wizard daemon there is no terminal, so sudo has nowhere to ask for
  # a password — offering it would just fail confusingly. Say what actually fixes
  # it instead, including the part people miss: a systemd --user service keeps
  # the group set it started with, so adding the group is not enough on its own.
  if [ "$UI_MANAGED" = 1 ]; then
    die "no access to $PORT, and sudo cannot prompt from the onboarding service.
       Fix it once, on the platform host:
           sudo usermod -aG dialout $(id -un)
           sudo systemctl restart user@\$(id -u)     # reloads the service's groups
       Then start onboarding again. Without the second command the wizard keeps
       the old group set and this message comes back."
  fi
  ui_waiting
  prompt_confirm 'Use sudo for this run instead?' "The durable fix is: sudo usermod -aG dialout $(id -un), then log out and back in."
  if [ "$ANSWER" = "y" ]; then
    SUDO="sudo"
    sudo -v || die "sudo declined"
  else
    die "no access to $PORT"
  fi
fi

# ---------------------------------------------------- 3. identify chip --------
# This runs BEFORE choosing an image, because the silicon decides which board
# page upstream is even relevant — and because the offset must come from the
# chip, never from a file name.
step "Identifying the board"
probe() { $SUDO "$ESPTOOL" --port "$PORT" --baud 115200 flash_id 2>&1; }
PROBE="$(probe || true)"
if ! grep -q '^Chip is' <<<"$PROBE"; then
  warn "esptool could not talk to the board."
  echo "    Put it in download mode by hand and try again:"
  echo "        hold BOOT (sometimes IO0)  ->  tap RESET (EN)  ->  release BOOT"
  echo
  sed 's/^/      | /' <<<"$PROBE" | tail -12
  die "no response on $PORT"
fi

CHIP_LINE="$(grep -m1 '^Chip is' <<<"$PROBE")"
CHIP_DESC="${CHIP_LINE#Chip is }"
MAC="$(grep -m1 '^MAC:' <<<"$PROBE" | awk '{print $2}')"
FLASH_SIZE="$(grep -m1 'flash size' <<<"$PROBE" | sed 's/.*: //' || true)"
[ -n "$MAC" ] || die "could not read MAC from the board"

# Family drives the flash offset, and getting it wrong produces a board that
# flashes cleanly and then never boots. It also names the upstream board page.
case "$CHIP_DESC" in
  ESP32-S3*) CHIP=esp32s3; OFFSET=0x0;    BOARD=ESP32_GENERIC_S3 ;;
  ESP32-C3*) CHIP=esp32c3; OFFSET=0x0;    BOARD=ESP32_GENERIC_C3 ;;
  ESP32-C6*) CHIP=esp32c6; OFFSET=0x0;    BOARD=ESP32_GENERIC_C6 ;;
  ESP32-S2*) CHIP=esp32s2; OFFSET=0x1000; BOARD=ESP32_GENERIC_S2 ;;
  ESP32-*)   CHIP=esp32;   OFFSET=0x1000; BOARD=ESP32_GENERIC    ;;
  ESP32*)    CHIP=esp32;   OFFSET=0x1000; BOARD=ESP32_GENERIC    ;;
  *) die "unrecognised chip: $CHIP_DESC" ;;
esac

info "chip:   $CHIP_DESC"
info "mac:    $MAC"

# Is this board already registered somewhere else? serial_number (the MAC) is
# unique, so a board moved to another slot cannot get a second row; registering
# would be refused at the very end, after the erase and the flash. Ask now,
# before anything is written: the slot was chosen before the board was probed,
# and this is the first moment both are known. Yes moves the board's own row to
# the new slot (platform_db.register, move_device_id) and frees the old one.
MOVE_FROM_ID=""
if [ "$UNREGISTERED" != 1 ] && [ "$DO_REGISTER" = 1 ]; then
  _serial="$(tr -d ':' <<<"$MAC" | tr '[:upper:]' '[:lower:]')"
  token_get 120 "check this board" || auth_report board
  if _b="$(platdb board "$_serial" 2>&1)"; then
    if [ -n "$_b" ]; then
      IFS=$'\t' read -r _ b_id b_dns b_zone b_role b_active b_unit b_zonecode <<<"$_b"
      if [ "$b_zone" = "$ZONE_ID" ] && [ "$b_role" = "$ROLE" ]; then
        info "already registered in this slot as $b_dns — its row is updated in place"
      else
        _where="${b_unit:-?} / ${b_zonecode:-?} ($b_role)"
        [ "$b_active" = "Y" ] || _where="$_where, inactive"
        warn "this board is already registered as $b_dns — $_where."
        if [ "$ASSUME_YES" = 1 ]; then
          die "not moving a registered board without asking: onboard it interactively, or delete $b_dns in the Devices tab first"
        fi
        ui_waiting
        prompt_confirm "Move this board from $b_dns to $UNIT_CODE / $ZONE_CODE?" \
          "Its database row moves to the new slot: the name becomes $SLOT_DNS, the components are replaced, and $_where becomes free. No: nothing is erased or written, and onboarding stops."
        [ "$ANSWER" = "y" ] || die "stopped before flashing: $b_dns keeps this board. Nothing was written."
        MOVE_FROM_ID="$b_id"
        info "will move device $b_id ($b_dns) to $SLOT_DNS"
      fi
    fi
  else
    warn "could not check whether this board is registered elsewhere:"
    printf '%s\n' "$_b" | while IFS= read -r l; do warn "  $l"; done
  fi
fi

# The wiring question is asked before the board is ever probed — an operator
# picks a slot and a pin map while the ESP32 is still just a thing on a bench.
# This is where the two meet: the map was validated against a board the operator
# NAMED, and the silicon has now said what it actually is. A C3 has no GPIO26,
# an original ESP32 cannot drive GPIO34 at all, and either mistake produces a
# board that flashes cleanly and then quietly fails to switch a relay.
if [ -n "$CONTROL_ACTUATOR_JSON" ] && [ -n "$CONTROL_VARIANT" ] \
   && [ "$CONTROL_VARIANT" != "$CHIP" ]; then
  warn "the channel map was checked against $CONTROL_VARIANT, but this board is $CHIP."
  if ! _RECHECK="$(printf '%s' "$CONTROL_ACTUATOR_JSON" \
                   | python3 "$TEMPLATE_TOOL" validate "$ROLE" "$CHIP" 2>&1)"; then
    # Not necessarily JSON: an unknown variant fails before validation runs, and
    # printing nothing at all is how a clear error becomes a mystery.
    printf '%s' "$_RECHECK" | python3 -c '
import json, sys
raw = sys.stdin.read()
try:
    findings = json.loads(raw)["findings"]
except (ValueError, KeyError, TypeError):
    print("    !! " + raw.strip().replace("\n", "\n    !! "))
    sys.exit(0)
for f in findings:
    if f["level"] == "error":
        print("    !! %s - %s" % (f["where"], f["message"]))' || true
    die "the map cannot drive this chip. Re-run and pick $CHIP as the board."
  fi
  info "re-checked against $CHIP: still valid"
  CONTROL_VARIANT="$CHIP"
fi
[ -n "$FLASH_SIZE" ] && info "flash:  $FLASH_SIZE"
info "offset: $OFFSET  (correct for $CHIP)"
info "board:  $BOARD"

# ---------------------------------------------------- 4. firmware -------------
# Local images first, upstream second. The default is always the newest image
# already on disk — a bench run must not depend on the network, and must not
# quietly change what it flashes because upstream published something.
step "Firmware image"

# Sort key for a MicroPython file name: the YYYYMMDD field is monotonic with
# release order, so plain string sort on it is enough and no version parsing is
# needed. Files that don't carry a date sort last, under key 0.
fw_datekey() { local n; n="$(basename "$1")"; [[ "$n" =~ -([0-9]{8})-v ]] && echo "${BASH_REMATCH[1]}" || echo 0; }

declare -a LOCAL_FILES=() MENU_LABEL=() MENU_KIND=() MENU_VALUE=()

if [ -n "$FIRMWARE" ]; then
  [ -f "$FIRMWARE" ] || die "firmware not found: $FIRMWARE"
else
  # Only images for THIS chip family are candidates. A directory holding both an
  # S3 and a WROOM-32 build is the normal case once there are two board types in
  # the fleet, and offering the wrong one is how a board gets bricked quietly.
  while IFS= read -r f; do
    [ -n "$f" ] && LOCAL_FILES+=("$f")
  done < <(ls "$FW_DIR"/*.bin 2>/dev/null | grep -F "$BOARD-" || true)

  # Newest first.
  if [ "${#LOCAL_FILES[@]}" -gt 1 ]; then
    while IFS= read -r line; do SORTED+=("${line#* }"); done \
      < <(for f in "${LOCAL_FILES[@]}"; do echo "$(fw_datekey "$f") $f"; done | sort -rk1,1)
    LOCAL_FILES=("${SORTED[@]}"); unset SORTED
  fi

  for f in "${LOCAL_FILES[@]}"; do
    MENU_LABEL+=("$(basename "$f")"); MENU_KIND+=(local); MENU_VALUE+=("$f")
  done

  # Ask upstream what exists. Never fatal: no network, a redesigned page or a
  # 404 all degrade to "local only".
  UPSTREAM=""
  if [ "$OFFLINE" = 1 ]; then
    info "skipping the upstream check (--offline)"
  else
    info "checking micropython.org for $BOARD builds…"
    PREVIEW_FLAG=(); [ "$WANT_PREVIEW" = 1 ] && PREVIEW_FLAG=(--include-preview)
    UPSTREAM="$(python3 "$SRC_HOST/list_firmware.py" --board "$BOARD" \
                  --newest-per-variant "${PREVIEW_FLAG[@]}" 2>/dev/null || true)"
    [ -n "$UPSTREAM" ] || warn "could not read the upstream build list — continuing with local images only"
  fi

  NEWEST_LOCAL_KEY=0
  [ "${#LOCAL_FILES[@]}" -gt 0 ] && NEWEST_LOCAL_KEY="$(fw_datekey "${LOCAL_FILES[0]}")"

  while IFS=$'\t' read -r variant date version fname furl; do
    [ -n "${fname:-}" ] || continue
    [ -f "$FW_DIR/$fname" ] && continue          # already on disk, listed above
    tag="v$version"
    [ "$variant" != "-" ] && tag="$tag · $variant"
    if [ "$date" \> "$NEWEST_LOCAL_KEY" ] && [ "$variant" = "-" ] && [ "$NEWEST_LOCAL_KEY" != 0 ]; then
      tag="$tag  ${GRN}newer than your local image${N}"
    fi
    MENU_LABEL+=("$fname|$tag"); MENU_KIND+=(download); MENU_VALUE+=("$furl")
  done <<<"$UPSTREAM"

  if [ "${#MENU_LABEL[@]}" -eq 0 ]; then
    if [ "$OFFLINE" = 1 ]; then
      die "No image for $BOARD in $FW_DIR, and --offline forbids fetching one.
       Re-run without --offline, or drop a build in by hand — see $FW_DIR/README.md."
    fi
    die "No image for $BOARD in $FW_DIR, and micropython.org could not be reached.
       Download one by hand and drop it there — see $FW_DIR/README.md."
  fi

  # One local image and nothing newer upstream: nothing to decide.
  if [ "${#LOCAL_FILES[@]}" -eq 1 ] && [ "${#MENU_LABEL[@]}" -eq 1 ]; then
    FIRMWARE="${LOCAL_FILES[0]}"
  else
    echo
    shown_dl=0
    # "## " prefixes a group heading in CHOICES; the browser renders it as a
    # non-selectable label, which keeps the numbering identical in both surfaces.
    CHOICES=()
    for i in "${!MENU_LABEL[@]}"; do
      if [ "${MENU_KIND[$i]}" = local ]; then
        [ "$i" -eq 0 ] && printf '      %sLocal images%s\n' "$DIM" "$N"
        [ "$i" -eq 0 ] && CHOICES+=("## Local images")
        mark=""; [ "$i" -eq 0 ] && mark=" ${B}(default)${N}"
        printf '      [%2d] %-54s %b\n' "$((i+1))" "${MENU_LABEL[$i]}" "$mark"
        CHOICES+=("${MENU_LABEL[$i]}|$([ "$i" -eq 0 ] && echo 'default' || echo 'on disk')")
      else
        if [ "$shown_dl" -eq 0 ]; then
          shown_dl=1
          [ "${#LOCAL_FILES[@]}" -gt 0 ] && printf '\n'
          printf '      %sAvailable from micropython.org%s\n' "$DIM" "$N"
          CHOICES+=("## Available from micropython.org")
        fi
        name="${MENU_LABEL[$i]%%|*}"; tag="${MENU_LABEL[$i]#*|}"
        printf '      [%2d] %-54s %b\n' "$((i+1))" "$name" "download · $tag"
        CHOICES+=("$name|download · $(sed -r 's/\x1b\[[0-9;]*m//g' <<<"$tag")")
      fi
    done
    echo
    if [ "${#LOCAL_FILES[@]}" -gt 0 ]; then
      ui_waiting
      prompt_choice "Which image should be flashed?" 1 \
             "The newest local image is the default. Downloads are hashed into SHA256SUMS."
      sel="$ANSWER"
    else
      warn "no local image for $BOARD — one must be downloaded"
      ui_waiting
      prompt_choice "No local image for $BOARD — which should be downloaded?" "" \
             "Nothing in edge/firmware/ matches this board."
      sel="$ANSWER"
    fi
    [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le "${#MENU_LABEL[@]}" ] \
      || die "invalid selection"
    idx=$((sel-1))

    if [ "${MENU_KIND[$idx]}" = local ]; then
      FIRMWARE="${MENU_VALUE[$idx]}"
    else
      url="${MENU_VALUE[$idx]}"; fname="$(basename "$url")"
      info "downloading $fname"
      tmp="$FW_DIR/.$fname.part"
      curl -fL --progress-bar -o "$tmp" "$url" || { rm -f "$tmp"; die "download failed: $url"; }
      mv "$tmp" "$FW_DIR/$fname"
      FIRMWARE="$FW_DIR/$fname"
      # micropython.org publishes no .sha256 sidecar, so the hash we record is
      # the one computed here, from the bytes actually written to the board.
      sha256sum "$FIRMWARE" | sed "s#$FW_DIR/##" >> "$FW_DIR/SHA256SUMS"
      info "recorded in $FW_DIR/SHA256SUMS"
    fi
  fi
fi

FW_NAME="$(basename "$FIRMWARE")"
FW_SHA="$(sha256sum "$FIRMWARE" | cut -d' ' -f1)"
info "image:  $FW_NAME"
info "sha256: $FW_SHA"

# Cross-check a hand-supplied image against the silicon. Auto-selected images are
# already filtered by board name; this is for --firmware. Not authoritative — a
# renamed file slips past — but it catches flashing the S3 build onto a WROOM-32
# out of the same box of boards.
FW_LOWER="$(tr '[:upper:]' '[:lower:]' <<<"$FW_NAME" | tr -d '_-')"
case "$CHIP" in
  esp32s3) grep -q 's3'  <<<"$FW_LOWER" || warn "image name does not mention S3 — is $FW_NAME really an ESP32-S3 build?" ;;
  esp32c3) grep -q 'c3'  <<<"$FW_LOWER" || warn "image name does not mention C3 — is $FW_NAME really an ESP32-C3 build?" ;;
  esp32)   grep -qE 's3|c3|c6|s2' <<<"$FW_LOWER" && warn "image name suggests a different chip family than $CHIP_DESC" ;;
esac

# ---------------------------------------------------- 5. identity -------------
# One name per board, and it is the DHCP hostname. A board with a slot is
# lower(unit)-<s|c>-lower(zone) (platform_db.slot_hostname): its network name,
# its dns_name and the device_dns in every payload. An unregistered board is
# cea-un-<mac6> — unique by MAC, and 'un' says at a glance it has no slot.
# Both are legal RFC 1123 hostnames, and no longer than MicroPython accepts;
# the name is read back off the board after boot (below), because a name the
# board refuses is silently replaced by its default ('mpy-esp32s3') — which is
# exactly what DHCP would then register.
step "Identity"
TS="$(date -u +%Y%m%d%H%M%S)"
MAC6="$(tr -d ':' <<<"$MAC" | tr '[:upper:]' '[:lower:]' | tail -c 7)"
if [ "$UNREGISTERED" != 1 ]; then
  HOSTNAME="$SLOT_DNS"
else
  HOSTNAME="cea-un-${MAC6}"
fi
DEVICE_DNS="$HOSTNAME"
info "hostname   : $HOSTNAME   ${DIM}(${#HOSTNAME} chars — DHCP name and device identity)${N}"

# ---------------------------------------------------- 6. flash ----------------
step "Flash"
echo "    About to write $FW_NAME to $CHIP_DESC at $MAC."
[ "$DO_ERASE" = 1 ] && echo "    ${YEL}erase_flash wipes the entire chip — filesystem, NVS, any stored credential.${N}"
# A forced refresh (330 s > the realm's 300 s lifespan) while the board is still
# intact: a sign-in that ended during the wiring questions is found now, not at
# register, after the erase.
if [ "$UNREGISTERED" != 1 ] && [ "$DO_REGISTER" = 1 ]; then
  token_get 330 "erase the board" || auth_report erase
fi
if [ "$ASSUME_YES" != 1 ]; then
  ui_waiting
  _hint="Writes $FW_NAME to $CHIP_DESC at $MAC."
  [ "$DO_ERASE" = 1 ] && _hint="$_hint erase_flash wipes the entire chip first — filesystem, NVS, any stored credential."
  prompt_confirm 'Erase and flash this board?' "$_hint"
  [ "$ANSWER" = "y" ] || die "aborted"
fi

flash_at() {
  local baud="$1"
  # ui_tee passes output through to the terminal unchanged and copies a cleaned
  # copy into the browser log; PIPESTATUS keeps esptool's status, not tee's.
  if [ "$DO_ERASE" = 1 ]; then
    $SUDO "$ESPTOOL" --chip "$CHIP" --port "$PORT" --baud "$baud" erase_flash 2>&1 | ui_tee
    [ "${PIPESTATUS[0]}" -eq 0 ] || return 1
  fi
  $SUDO "$ESPTOOL" --chip "$CHIP" --port "$PORT" --baud "$baud" \
        write_flash -z "$OFFSET" "$FIRMWARE" 2>&1 | ui_tee
  [ "${PIPESTATUS[0]}" -eq 0 ] || return 1
}
if ! flash_at "$BAUD"; then
  warn "flash at ${BAUD} baud failed — retrying at 115200"
  flash_at 115200 || die "flash failed at 115200 too. Re-enter download mode and retry."
fi
info "${GRN}written${N}"

# Give the board time to reset into fresh MicroPython. A board on its native USB
# port re-enumerates here and the device node briefly disappears; one behind a
# CH343/CP210x bridge (as on this bench) does not. Wait for either case.
step "Waiting for MicroPython"
for _ in $(seq 1 30); do [ -e "$PORT" ] && break; sleep 1; done
[ -e "$PORT" ] || die "$PORT did not come back after reset"
sleep 3
for attempt in 1 2 3 4 5; do
  if mpy eval "1+1" >/dev/null 2>&1; then break; fi
  [ "$attempt" = 5 ] && die "no MicroPython REPL on $PORT after flashing"
  sleep 2
done
MPY_VER="$(mpy eval "__import__('sys').version" 2>/dev/null | tr -d "'" || echo unknown)"
info "${GRN}REPL up${N} — MicroPython $MPY_VER"

# ---------------------------------------------------- 7. choose network -------
step "WiFi"
if [ -z "$SSID" ]; then
  while :; do
    info "scanning from the board's own radio…"
    SCAN="$(mpy run "$SRC_DIR/scan_networks.py" 2>/dev/null || true)"
    mapfile -t FOUND < <(grep $'^NET\t' <<<"$SCAN" || true)
    if [ "${#FOUND[@]}" -eq 0 ]; then
      warn "the board saw no networks (it may be out of range, or all nearby SSIDs are hidden)"
    else
      echo
      printf '      %-5s%-34s %-8s %s\n' "" "SSID" "SIGNAL" "SECURITY"
      for i in "${!FOUND[@]}"; do
        IFS=$'\t' read -r _ s rssi auth <<<"${FOUND[$i]}"
        case "$auth" in
          0) sec="open ${YEL}(!)${N}" ;; 1) sec="WEP ${YEL}(!)${N}" ;;
          2) sec="WPA-PSK" ;; 3) sec="WPA2-PSK" ;; 4) sec="WPA/WPA2-PSK" ;;
          5) sec="WPA2-Enterprise" ;; 6) sec="WPA3-PSK" ;; 7) sec="WPA2/WPA3-PSK" ;;
          *) sec="auth $auth" ;;
        esac
        printf '      [%2d] %-34s %-8s %b\n' "$((i+1))" "$s" "${rssi} dBm" "$sec"
      done
      echo
    fi
    echo "      [m]  type an SSID by hand (also the only way to join a hidden network)"
    echo "      [r]  rescan"
    # The browser gets the same list plus the two actions as trailing entries,
    # so 'm' and 'r' are buttons there and letters here.
    _n=${#FOUND[@]}
    if ui_on; then
      CHOICES=()
      for i in "${!FOUND[@]}"; do
        IFS=$'\t' read -r _ s rssi auth <<<"${FOUND[$i]}"
        case "$auth" in
          0) sec="open (!)" ;; 1) sec="WEP (!)" ;; 2) sec="WPA-PSK" ;; 3) sec="WPA2-PSK" ;;
          4) sec="WPA/WPA2-PSK" ;; 5) sec="WPA2-Enterprise" ;; 6) sec="WPA3-PSK" ;;
          7) sec="WPA2/WPA3-PSK" ;; *) sec="auth $auth" ;;
        esac
        CHOICES+=("$s|${rssi} dBm · $sec")
      done
      CHOICES+=("Type an SSID by hand|hidden networks")
      CHOICES+=("Rescan|")
    fi
    ui_waiting
    prompt_choice "Which network should the board join?" "" \
           "Scanned by the board's own radio. 2.4 GHz only — a 5 GHz SSID will not appear."
    sel="$ANSWER"
    if ui_on; then
      case "$sel" in
        "$((_n+1))") sel=m ;;
        "$((_n+2))") sel=r ;;
      esac
    fi
    case "$sel" in
      m|M) prompt_text 'SSID' '' 'Exactly as configured on the access point.'; SSID="$ANSWER"
           [ -n "$SSID" ] && break ;;
      r|R) continue ;;
      *) if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le "$_n" ]; then
           IFS=$'\t' read -r _ SSID _ _ <<<"${FOUND[$((sel-1))]}"; break
         fi
         warn "invalid selection" ;;
    esac
  done
fi
info "ssid: $SSID"

if [ -z "$PSK" ]; then
  ui_waiting
  prompt_secret "passphrase for '$SSID' (not echoed): " "Stored on the board in plaintext until flash encryption is on."
  PSK="$ANSWER"
fi
[ -n "$PSK" ] || warn "empty passphrase — only valid for an open network"

# ---------------------------------------------------- 8. WebREPL password -----
step "WebREPL credential"
# MicroPython's WebREPL protocol carries the password in a fixed 10-byte field,
# and webrepl_setup refuses anything outside 4-9 characters. Nine random chars
# from an unambiguous alphabet is the most entropy the protocol will hold —
# roughly 45 bits. It is a bring-up credential with a short life, not a secret
# to build on, which is exactly why it must not be the same on every board.
WEBREPL_PASS="$("$VENV_DIR/bin/python" - <<'PY'
import secrets
alpha = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
print("".join(secrets.choice(alpha) for _ in range(9)))
PY
)"
info "generated a 9-character password for this board only"

# ---------------------------------------------------- 9. write config ---------
step "Writing the board's files"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/cea-flash.XXXXXX")"
# cleanup() already removes $STAGE — see the trap set near the top.

DB_COMPONENTS="[]"
if [ "$UNREGISTERED" = 1 ]; then
  # No slot, so nothing to render from a template: the board gets an identity
  # that says it has none, and no application at all. main.py still ships, and
  # parks at "UNREGISTERED" rather than looping on a broker it cannot reach.
  HOSTNAME="$HOSTNAME" SSID="$SSID" PSK="$PSK" \
  FW_NAME="$FW_NAME" FW_SHA="$FW_SHA" MAC="$MAC" TS="$TS" STAGE="$STAGE" \
  TOPIC_ROOT="$TOPIC_ROOT" \
  "$VENV_DIR/bin/python" - <<'PY'
import json, os
e = os.environ
q = lambda k: json.dumps(e[k])
with open(os.path.join(e["STAGE"], "device_cfg.py"), "w") as f:
    f.write(f'''# GENERATED by edge/flash-device.sh - do not edit by hand.
# Bench bootstrap. This board has NO platform identity: no MQTT credential, no
# unit, no zone, no role. Onboarding it again overwrites this file.

STATE            = "UNREGISTERED"
ROLE             = "UNREGISTERED"
HOSTNAME         = {q("HOSTNAME")}
UNIT_CODE        = ""
ZONE_CODE        = ""
ZONE_ID          = None
WIFI_SSID        = {q("SSID")}
WIFI_PSK         = {q("PSK")}
MQTT_HOST        = ""
MQTT_PORT        = 0
MQTT_USER        = ""
MQTT_PASS        = ""
TOPIC_ROOT       = {q("TOPIC_ROOT")}
MAC              = {q("MAC")}
FIRMWARE         = {q("FW_NAME")}
FIRMWARE_SHA256  = {q("FW_SHA")}
FLASHED_AT       = {q("TS")}   # UTC, YYYYMMDDHHMMSS
''')
PY
else
  # The answers collected in step 0.6 become the board's files. Rendering runs
  # in one place so device_cfg.py, actuator_config.json and the database rows
  # cannot disagree about which pin drives what.
  RENDER_OUT="$(
    STAGE="$STAGE" ROLE="$ROLE" UNIT_CODE="$UNIT_CODE" ZONE_CODE="$ZONE_CODE" \
    ZONE_ID="$ZONE_ID" HOSTNAME="$HOSTNAME" \
    SSID="$SSID" PSK="$PSK" MQTT_HOST="$MQTT_HOST" MQTT_PORT="$MQTT_PORT" \
    MQTT_USER="$MQTT_USER" MQTT_PASS="$MQTT_PASS" \
    TOPIC_ROOT="$TOPIC_ROOT" MESSAGE_INTERVAL="${MESSAGE_INTERVAL:-30}" \
    POLL_MS="${POLL_MS:-100}" CONTROL_DRIVER="$CONTROL_DRIVER" \
    MAC="$MAC" FW_NAME="$FW_NAME" FW_SHA="$FW_SHA" TS="$TS" \
    SENSORS_TSV="$SENSORS_TSV" CONTROL_PINS_TSV="$CONTROL_PINS_TSV" \
    CONTROL_ACTUATOR_JSON="$CONTROL_ACTUATOR_JSON" \
    CONTROL_VARIANT="$CONTROL_VARIANT" \
    python3 -c '
import json, os, sys
e = os.environ
spec = {
    "out_dir": e["STAGE"], "role": e["ROLE"],
    "unit_code": e["UNIT_CODE"], "zone_code": e["ZONE_CODE"],
    "zone_id": int(e["ZONE_ID"]) if e["ZONE_ID"] else None,
    "hostname": e["HOSTNAME"],
    "wifi_ssid": e["SSID"], "wifi_psk": e["PSK"],
    "mqtt_host": e["MQTT_HOST"], "mqtt_port": int(e["MQTT_PORT"]),
    "mqtt_user": e["MQTT_USER"], "mqtt_pass": e["MQTT_PASS"],
    "topic_root": e["TOPIC_ROOT"],
    "message_interval": int(e["MESSAGE_INTERVAL"]),
    "poll_ms": int(e["POLL_MS"]), "driver": e["CONTROL_DRIVER"],
    "mac": e["MAC"], "firmware": e["FW_NAME"],
    "firmware_sha256": e["FW_SHA"], "flashed_at": e["TS"],
}
if e["ROLE"] == "SENSE":
    # "<driver>\t<param>\t<value>" lines, in the order they were answered; the
    # marker line with an empty param name is what records a driver that has no
    # parameters at all.
    comps, order = {}, []
    for line in e["SENSORS_TSV"].splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        drv = parts[0]
        if drv not in comps:
            comps[drv] = {"driver": drv, "params": {}}
            order.append(drv)
        if len(parts) >= 3 and parts[1]:
            comps[drv]["params"][parts[1]] = parts[2]
    spec["components"] = [comps[d] for d in order]
elif e.get("CONTROL_ACTUATOR_JSON"):
    # The operator edited the table itself. Passing it through rather than the
    # per-function addresses is the whole point: re-deriving would discard the
    # edit they were just shown and approved.
    spec["actuator_config"] = json.loads(e["CONTROL_ACTUATOR_JSON"])
    if e.get("CONTROL_VARIANT"):
        spec["variant"] = e["CONTROL_VARIANT"]
else:
    pins = {}
    for line in e["CONTROL_PINS_TSV"].splitlines():
        if not line.strip():
            continue
        fid, _, pin = line.partition("\t")
        pins[fid] = pin
    spec["functions"] = pins

sys.path.insert(0, os.path.join(os.environ["SRC_HOST"]))
import device_template
json.dump(device_template.render(spec), sys.stdout)
'
  )" || die "could not render the board configuration"
  DB_COMPONENTS="$(ANSWER="$RENDER_OUT" python3 -c '
import json, os
print(json.dumps(json.loads(os.environ["ANSWER"])["components"]))')"
  for f in $(ANSWER="$RENDER_OUT" python3 -c '
import json, os
print(" ".join(json.loads(os.environ["ANSWER"])["written"]))'); do
    info "rendered $f"
  done
fi

printf 'PASS = %s\n' "'$WEBREPL_PASS'" > "$STAGE/webrepl_cfg.py"

# The application tree. Identical on every board — role, slot and pins are all
# in device_cfg.py — so a fix here reaches the whole fleet on the next onboard
# instead of needing nine hand edits.
for f in "$STAGE"/*.py "$STAGE"/*.json; do
  [ -e "$f" ] || continue
  mpy fs cp "$f" ":$(basename "$f")" >/dev/null || die "failed to copy $(basename "$f") to the board"
  info "copied $(basename "$f")"
done
for f in "$APP_DIR"/*.py; do
  mpy fs cp "$f" ":$(basename "$f")" >/dev/null || die "failed to copy $(basename "$f") to the board"
done
info "copied $(ls -1 "$APP_DIR"/*.py | wc -l) application module(s)"
for pkg in umqtt sensor_pack_2; do
  [ -d "$APP_DIR/$pkg" ] || continue
  mpy fs mkdir ":$pkg" >/dev/null 2>&1 || true   # already there on a re-flash
  for f in "$APP_DIR/$pkg"/*.py; do
    mpy fs cp "$f" ":$pkg/$(basename "$f")" >/dev/null \
      || die "failed to copy $pkg/$(basename "$f") to the board"
  done
  info "copied $pkg/"
done

# ---------------------------------------------------- 10. verify --------------
# The acceptance test is the real boot path, not a simulation of it: hard-reset
# the board, let boot.py run, then ask the board what happened.
step "Verifying"
mpy reset >/dev/null 2>&1 || true
sleep 2
for _ in $(seq 1 20); do [ -e "$PORT" ] && break; sleep 1; done
sleep 8

IP=""
for attempt in 1 2 3 4 5 6; do
  OUT="$(mpy exec \
        "import network; w=network.WLAN(network.STA_IF); print('HN', network.hostname()); print('IFC', w.isconnected(), w.ifconfig()[0])" \
        2>/dev/null || true)"
  if grep -q 'IFC True' <<<"$OUT"; then
    CAND="$(awk '/^IFC/{print $3}' <<<"$OUT")"
    # Two things this rejects. A value that is not a bare dotted quad means the
    # capture is malformed, not that the board is online — accepting it silently
    # writes garbage into the provisioning record. And 0.0.0.0 is the real
    # window where the board has associated but DHCP has not answered yet;
    # isconnected() is already True there, so it has to be caught by value.
    if [[ "$CAND" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] && [ "$CAND" != "0.0.0.0" ]; then
      IP="$CAND"
      break
    fi
  fi
  sleep 3
done

# What the board actually calls itself, which is not necessarily what we asked
# for: MicroPython silently keeps its default if the name was refused, and then
# registers THAT with DHCP.
HOSTNAME_ACTUAL="$(awk '/^HN/{print $2}' <<<"${OUT:-}")"
HOSTNAME_OK=""
if [ -n "$HOSTNAME_ACTUAL" ] && [ "$HOSTNAME_ACTUAL" = "$HOSTNAME" ]; then
  HOSTNAME_OK="$HOSTNAME"
  info "hostname confirmed on the board: ${GRN}$HOSTNAME_ACTUAL${N}"
elif [ -n "$HOSTNAME_ACTUAL" ]; then
  warn "the board reports hostname '$HOSTNAME_ACTUAL', not '$HOSTNAME' — the name was refused."
  warn "It will register '$HOSTNAME_ACTUAL' with DHCP. Use the IP address below."
fi

# Only claim a name works if it actually resolves from here, right now. The
# previous version of this script printed a <name>.local line unconditionally;
# it never resolved, because this MicroPython build runs no mDNS responder.
RESOLVES=""
if [ -n "$HOSTNAME_OK" ] && [ -n "$IP" ]; then
  for cand in "$HOSTNAME_OK" "$HOSTNAME_OK.local"; do
    got="$(getent hosts "$cand" 2>/dev/null | awk '{print $1}' | head -1 || true)"
    if [ "$got" = "$IP" ]; then RESOLVES="$cand"; break; fi
  done
  if [ -z "$RESOLVES" ]; then
    # The system resolver refuses single-label names; the router may still know
    # it. Worth reporting, because it tells you the DHCP registration worked.
    gw="$(ip route | awk '/^default/{print $3; exit}')"
    if [ -n "$gw" ] && command -v nslookup >/dev/null 2>&1; then
      got="$(timeout 4 nslookup "$HOSTNAME_OK" "$gw" 2>/dev/null | awk '/^Address: /{print $2}' | tail -1 || true)"
      [ "$got" = "$IP" ] && RESOLVES="$HOSTNAME_OK (via $gw only)"
    fi
  fi
  [ -n "$RESOLVES" ] && info "resolves as: ${GRN}$RESOLVES${N}"
fi

if [ -z "$IP" ]; then
  warn "the board did not report an IP address."
  warn "Wrong passphrase, out of range, or a 5 GHz-only SSID — the ESP32 is 2.4 GHz only."
  echo "    Watch it boot and see for yourself:"
  echo "        $MPREMOTE connect $PORT repl      (Ctrl-] to exit, Ctrl-D to soft reboot)"
else
  info "${GRN}online at $IP${N}"
fi


# --------------------------------------------- 10.5 register in the platform --
# The board is online and running its own program; now the platform is told it
# exists. Until this row is written the device publishes into a topic nobody
# has a device record for, and the Devices tab does not know the slot is taken —
# which is what the one-SENSE-one-CONTROL rule is read from on the next run.
#
# Deliberately after the verify: registering a board that never joined the
# network would fill a slot with something that is not there.
REGISTERED_ID=""; REGISTERED_BY=""
if [ "$UNREGISTERED" != 1 ] && [ "$DO_REGISTER" = 1 ]; then
  step "Registering with the platform"
  if [ -z "$IP" ]; then
    warn "the board never reported an IP, so it is NOT being registered."
    warn "Fix the network problem and onboard it again; the slot stays free."
  else
    REG_JSON="$(
      SLOT_DNS="$SLOT_DNS" ROLE="$ROLE" ZONE_ID="$ZONE_ID" MAC="$MAC" \
      CHIP_DESC="$CHIP_DESC" DB_COMPONENTS="$DB_COMPONENTS" \
      MOVE_FROM_ID="$MOVE_FROM_ID" \
      MQTT_USER="$MQTT_USER" MQTT_PASS_HASH="$MQTT_PASS_HASH" TOPIC_BASE="$TOPIC_BASE" \
      python3 -c '
import json, os, re
e = os.environ
# serial_number is the MAC without separators, lowercased — the same form the
# existing device rows use, and the only field that joins a row to a board on
# the network.
serial = re.sub(r"[^0-9a-fA-F]", "", e["MAC"]).lower()
print(json.dumps({
    # The slot hostname (unit02-c-zone02): the one name of the device, what the
    # config UI pings. register() finds the row by slot, so a renamed unit or
    # zone code renames the row here instead of creating a second one.
    "dns_name": e["SLOT_DNS"],
    "device_type": e["ROLE"],
    "zone_id": int(e["ZONE_ID"]),
    "serial_number": serial,
    "model": e["CHIP_DESC"].split(" (")[0].strip() or "ESP32",
    "manufacturer": "Espressif",
    "connection_type": "WiFi",
    "is_active": "Y",
    "components": json.loads(e["DB_COMPONENTS"]),
    # Set when the operator agreed to move this board from another slot.
    "move_device_id": int(e["MOVE_FROM_ID"]) if e["MOVE_FROM_ID"] else None,
    # The broker credential: only the hash leaves this host.
    "mqtt_username": e["MQTT_USER"],
    "mqtt_password_hash": e["MQTT_PASS_HASH"],
    "topic_base": e["TOPIC_BASE"],
}))')"

    if [ "$ASSUME_YES" != 1 ]; then
      info "$SLOT_DNS  ->  $UNIT_CODE / $ZONE_CODE  (zone_id $ZONE_ID)"
      info "$ROLE  $CHIP_DESC  $(tr -d ':' <<<"$MAC" | tr '[:upper:]' '[:lower:]')"
      _n="$(ANSWER="$DB_COMPONENTS" python3 -c '
import json, os; print(len(json.loads(os.environ["ANSWER"])))')"
      info "$_n component row(s)"
    fi

    _reg_go=1
    token_get 330 "record the board" || auth_report register || _reg_go=0
    if [ "$_reg_go" != 1 ]; then
      warn "the board is up, but it was not registered: no valid sign-in."
      warn "Until it is registered the broker refuses this board's credential, so it"
      warn "cannot publish. Onboard it again once signed in (the slot's row is updated in place)."
    elif REG_OUT="$(printf '%s' "$REG_JSON" | platdb register 2>&1)"; then
      IFS=$'\t' read -r REG_ACTION REGISTERED_ID <<<"$REG_OUT"
      info "${GRN}$REG_ACTION device $REGISTERED_ID${N} — the slot is now taken"
      [ -n "$EDGE_TOKEN" ] && REGISTERED_BY="$EDGE_USER"
    else
      # Not fatal. The board is flashed, online and running; what failed is the
      # bookkeeping, and re-running the wizard for the same slot updates the row
      # in place rather than creating a second one.
      warn "the board is up, but the platform database refused the registration:"
      # Through warn, not a bare printf to stderr: the wizard's log is fed by
      # ui_append, and the reason used to arrive there as an empty line.
      while IFS= read -r l; do warn "  $l"; done <<<"$REG_OUT"
      warn "Until it is registered the broker refuses this board's credential, so it"
      warn "cannot publish. Onboard it again once fixed (the slot's row is updated in place)."
    fi
  fi
fi
# The run needs no further token: end the channel (and the agent's refresh token).
token_close

# ---------------------------------------------------- 11. record --------------
mkdir -p "$OUT_DIR"; chmod 700 "$OUT_DIR"
RECORD="$OUT_DIR/${DEVICE_DNS}.json"
DEVICE_DNS="$DEVICE_DNS" HOSTNAME="$HOSTNAME" MAC="$MAC" CHIP_DESC="$CHIP_DESC" \
FW_NAME="$FW_NAME" FW_SHA="$FW_SHA" MPY_VER="$MPY_VER" SSID="$SSID" PSK="$PSK" \
WEBREPL_PASS="$WEBREPL_PASS" IP="$IP" PORT="$PORT" PROJECT_NAME="$PROJECT_NAME" \
HOSTNAME_OK="$HOSTNAME_OK" RESOLVES="$RESOLVES" \
ESPTOOL_VER="$ESPTOOL_VER" MPREMOTE_VER="$MPREMOTE_VER" RECORD="$RECORD" \
UNREGISTERED="$UNREGISTERED" ROLE="$ROLE" UNIT_CODE="$UNIT_CODE" \
ZONE_CODE="$ZONE_CODE" ZONE_ID="$ZONE_ID" REGISTERED_ID="$REGISTERED_ID" \
MQTT_HOST="$MQTT_HOST" MQTT_PORT="$MQTT_PORT" TOPIC_ROOT="$TOPIC_ROOT" \
MQTT_USER="${MQTT_USER:-}" MQTT_PASS="${MQTT_PASS:-}" \
DB_COMPONENTS="$DB_COMPONENTS" REGISTERED_BY="$REGISTERED_BY" \
"$VENV_DIR/bin/python" - <<'PY'
import datetime, getpass, json, os, socket
e = os.environ
unreg = e["UNREGISTERED"] == "1"
rec = {
    "state": "UNREGISTERED" if unreg else "REGISTERED",
    "role": e["ROLE"] or None,
    "unit_code": e["UNIT_CODE"] or None,
    "zone_code": e["ZONE_CODE"] or None,
    "zone_id": int(e["ZONE_ID"]) if e["ZONE_ID"] else None,
    # The medcea.device row this board owns, or None if it was not registered —
    # the difference between "the platform knows about this board" and "a board
    # exists that nothing has a record of".
    "platform_device_id": int(e["REGISTERED_ID"]) if e["REGISTERED_ID"] else None,
    # The Keycloak account the registration was made as (IAM 1.5), or None when
    # it was made anonymously or not at all. flashed_by below is the host login.
    "registered_by": e["REGISTERED_BY"] or None,
    # The board's broker credential sits here in plaintext like its Wi-Fi PSK
    # (this file is mode 600 in a 700 directory); the platform keeps only a hash.
    "mqtt": None if unreg else {"host": e["MQTT_HOST"], "port": int(e["MQTT_PORT"]),
                                "topic_root": e["TOPIC_ROOT"],
                                "username": e["MQTT_USER"], "password": e["MQTT_PASS"]},
    "components": json.loads(e["DB_COMPONENTS"] or "[]"),
    "hostname": e["HOSTNAME"],
    "hostname_verified": e["HOSTNAME_OK"] or None,
    "resolves_as": e["RESOLVES"] or None,
    "mac": e["MAC"],
    "chip": e["CHIP_DESC"],
    "firmware": e["FW_NAME"],
    "firmware_sha256": e["FW_SHA"],
    "micropython": e["MPY_VER"],
    "wifi_ssid": e["SSID"],
    "wifi_psk": e["PSK"],
    "webrepl_password": e["WEBREPL_PASS"],
    "ip_at_provision": e["IP"] or None,
    "project": e["PROJECT_NAME"],
    "flashed_by": getpass.getuser(),
    "flashed_on": socket.gethostname(),
    "flashed_port": e["PORT"],
    "flashed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "tools": {"esptool": e["ESPTOOL_VER"], "mpremote": e["MPREMOTE_VER"]},
}
path = e["RECORD"]
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(rec, f, indent=2)
    f.write("\n")
PY
chmod 600 "$RECORD"

# ---------------------------------------------------- 12. summary -------------
# The browser gets the same facts as a structured card, so the password and the
# WebREPL address can be copied rather than retyped off a terminal.
if ui_on; then
  DEVICE_DNS="$DEVICE_DNS" HOSTNAME_ACTUAL="${HOSTNAME_ACTUAL:-}" HOSTNAME="$HOSTNAME" \
  RESOLVES="${RESOLVES:-}" IP="${IP:-}" MAC="$MAC" CHIP_DESC="$CHIP_DESC" \
  FW_NAME="$FW_NAME" FW_SHA="$FW_SHA" SSID="$SSID" WEBREPL_PASS="$WEBREPL_PASS" \
  RECORD="$RECORD" ONBOARD_URL="${ONBOARD_URL:-}" UI_DIR="$UI_DIR" \
  UNREGISTERED="$UNREGISTERED" ROLE="$ROLE" UNIT_CODE="$UNIT_CODE" \
  ZONE_CODE="$ZONE_CODE" REGISTERED_ID="$REGISTERED_ID" \
  REGISTERED_BY_NAME="${REGISTERED_BY:+$EDGE_NAME ($REGISTERED_BY)}" \
  TOPIC_BASE="${TOPIC_BASE:-}" MQTT_HOST="$MQTT_HOST" MQTT_PORT="$MQTT_PORT" \
  python3 -c '
import json, os
e = os.environ
unreg = e["UNREGISTERED"] == "1"
ip = e["IP"] or "not connected"
f = [["ip address", ip, True]]
if not unreg:
    f += [["hostname", e["HOSTNAME"], True],
          ["unit / zone", "%s / %s" % (e["UNIT_CODE"], e["ZONE_CODE"]), False],
          ["role", e["ROLE"], False],
          ["broker", "%s:%s" % (e["MQTT_HOST"], e["MQTT_PORT"]), False]]
    if e["ROLE"] == "CONTROL":
        f += [["subscribes", e["TOPIC_BASE"] + "/control/#", False],
              ["reports", e["TOPIC_BASE"] + "/control_setpoint", False]]
    else:
        f += [["publishes", e["TOPIC_BASE"] + "/sense/<tag>", False]]
    f += [["registered as", ("medcea.device %s" % e["REGISTERED_ID"]) if e["REGISTERED_ID"]
                            else "NOT REGISTERED - see the log", False]]
    if e["REGISTERED_BY_NAME"]:
        f += [["recorded by", e["REGISTERED_BY_NAME"], False]]
else:
    f += [["hostname", e["HOSTNAME"], False]]
f += [["webrepl", "ws://%s:8266/" % ip, True],
      ["webrepl password", e["WEBREPL_PASS"], True],
      ["board reports", e["HOSTNAME_ACTUAL"] or "unknown", False],
      ["resolves as", e["RESOLVES"] or "nothing - this build runs no mDNS responder", False],
      ["mac", e["MAC"], False],
      ["chip", e["CHIP_DESC"], False],
      ["firmware", e["FW_NAME"], False],
      ["sha256", e["FW_SHA"], False],
      ["wifi", e["SSID"], False],
      ["record", e["RECORD"], False]]

if unreg:
    title = "Board is up - UNREGISTERED"
    note = ("This board is UNREGISTERED: no MQTT credential, no unit, no zone, no role. "
            "WebREPL is an open door - anyone reaching port 8266 with that password has a "
            "full Python REPL and the filesystem. Onboard it again with the platform "
            "reachable to give it a slot.")
elif not e["REGISTERED_ID"]:
    title = "Board is up - NOT REGISTERED"
    note = ("The board is flashed and running, but the medcea.device row was not written, "
            "so the platform does not know it exists and the slot still reads as free. "
            "See the log above; onboarding the same slot again updates in place rather "
            "than creating a second row.")
else:
    title = "Board is up - %s" % e["DEVICE_DNS"]
    note = ("WebREPL is on and is an open door: anyone reaching port 8266 with that "
            "password has a full Python REPL and the filesystem. The password is in the "
            "record below and nowhere else.")
if e["HOSTNAME_ACTUAL"] and e["HOSTNAME_ACTUAL"] != e["HOSTNAME"]:
    note = ("The board refused the hostname %r and kept %r. Use the IP. "
            % (e["HOSTNAME"], e["HOSTNAME_ACTUAL"])) + note
out = {"title": title, "fields": f, "note": note, "onboard_url": e["ONBOARD_URL"]}
with open(os.path.join(e["UI_DIR"], "done.json.tmp"), "w") as fh:
    json.dump(out, fh)
os.replace(os.path.join(e["UI_DIR"], "done.json.tmp"),
           os.path.join(e["UI_DIR"], "done.json"))'
  info "summary posted to the browser"
fi

# Say what is true. A name is only printed as usable if it resolved above.
HOSTNAME_NOTE=""
if [ -n "$HOSTNAME_ACTUAL" ] && [ "$HOSTNAME_ACTUAL" != "$HOSTNAME" ]; then
  HOSTNAME_NOTE="   ${YEL}(asked for '$HOSTNAME' — REFUSED by the board)${N}"
fi

if [ "$UNREGISTERED" = 1 ]; then
  TITLE="Board is up — UNREGISTERED"
elif [ -n "$REGISTERED_ID" ]; then
  TITLE="Board is up — $DEVICE_DNS"
else
  TITLE="Board is up — NOT REGISTERED"
fi

cat <<EOF

${B}────────────────────────────────────────────────────────────────${N}
${B} $TITLE${N}
${B}────────────────────────────────────────────────────────────────${N}

  ip address   ${B}${IP:-<not connected>}${N}   ${DIM}<- use this${N}
  hostname     ${B}$HOSTNAME${N}
  reports      ${HOSTNAME_ACTUAL:-<unknown>}${HOSTNAME_NOTE}
  resolves as  ${RESOLVES:-nothing — this MicroPython build runs no mDNS responder}
  mac          $MAC
  chip         $CHIP_DESC
  firmware     $FW_NAME
               sha256 $FW_SHA
  wifi         $SSID
EOF

if [ "$UNREGISTERED" != 1 ]; then
  cat <<EOF

${B} Platform${N}
  unit / zone  ${B}$UNIT_CODE / $ZONE_CODE${N}   ${DIM}(zone_id $ZONE_ID)${N}
  role         $ROLE
  broker       $MQTT_HOST:$MQTT_PORT  (as $MQTT_USER)
EOF
  if [ "$ROLE" = "CONTROL" ]; then
    echo "  subscribes   $TOPIC_BASE/control/#"
    echo "  reports      $TOPIC_BASE/control_setpoint/<tag>/<pin>"
    echo "  relays       $(grep -c . <<<"$CONTROL_PINS_TSV") channel(s) assigned"
  else
    echo "  publishes    $TOPIC_BASE/sense/<tag>"
    echo "  sensors      $(awk -F'\t' 'NF && !s[$1]++{printf "%s%s", sep, $1; sep=", "}' <<<"$SENSORS_TSV")"
    echo "  every        ${MESSAGE_INTERVAL:-30}s"
  fi
  if [ -n "$REGISTERED_ID" ]; then
    echo "  registered   ${GRN}medcea.device $REGISTERED_ID${N} — the slot is taken"
  elif [ "$DO_REGISTER" != 1 ]; then
    echo "  registered   ${YEL}skipped (--no-register) — the slot still reads as free${N}"
  else
    echo "  registered   ${RED}NO — the platform does not know this board exists${N}"
  fi
fi

cat <<EOF

${B} WebREPL${N}
  password     ${B}$WEBREPL_PASS${N}
  address      ws://${IP:-<ip>}:8266/

  Open the client from a local checkout, not the hosted page — the page at
  micropython.org is served over HTTPS and browsers block a ws:// connection
  from an HTTPS origin, which shows up as a silent failure to connect:

      git clone https://github.com/micropython/webrepl ~/webrepl
      xdg-open ~/webrepl/webrepl.html

  Serial console instead:
      $MPREMOTE connect $PORT repl

${B} Record${N}
  $RECORD  (chmod 600, gitignored)
EOF

if [ "$UNREGISTERED" = 1 ]; then
  cat <<EOF

${B} Next${N}
  This board has no MQTT credential and no place in the fleet, and its
  name says so: cea-un-$MAC6 ('un' for unregistered, then the MAC suffix).

  Onboard it again with the platform reachable to give it a unit, a zone
  and a role. That run rewrites device_cfg.py, ships the application for
  its role, and writes the medcea.device row — nothing here has to be undone.

  Until then, treat WebREPL as the open door it is: anyone who reaches
  port 8266 with this password has a full Python REPL and the filesystem.

EOF
else
  cat <<EOF

${B} Next${N}
  The board is running its own program. Watch it work:

      $MPREMOTE connect $PORT repl          ${DIM}(Ctrl-] exits, Ctrl-D reboots)${N}
      mosquitto_sub -h $MQTT_HOST -p $MQTT_PORT -u mqtt-explorer -P "\$MQTT_EXPLORER_PASS" -t '$TOPIC_BASE/#' -v
                                    ${DIM}(MQTT_EXPLORER_PASS is in config.env; or open https://mqtt-explorer.<domain>)${N}

  It appears in the Devices tab under $UNIT_CODE / $ZONE_CODE. Re-running
  this wizard for the same slot updates that row in place; it never
  creates a second one.

  WebREPL is still on, and is still an open door — anyone who reaches port
  8266 with this password has a full Python REPL and the filesystem.

EOF
fi
