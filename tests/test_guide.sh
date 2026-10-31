#!/usr/bin/env bash
# tests/test_guide.sh — ./guide.sh walks its question tree and builds the right commands.
# Offline, and never against the real scripts: every case runs a copy of guide.sh in a
# scratch tree whose scripts are stubs that only print their name and arguments (every
# path guide.sh names, and apps/<c>/{deploy,uninstall}.sh for each real component), plus
# the real infra/lib-lock.sh. A broken dry-run guard therefore runs stubs, never a deploy.
# Dry runs read a scratch config.env (MEDCEA_GUIDE_CONFIG).
#   1  units assign: an invalid unit code is re-asked; --by is remembered for the session
#   2  uninstall apps: an unknown component is re-asked; anything but "yes" cancels;
#      --purge-data is offered with database and lands after the component
#   3  an invalid menu choice is re-asked
#   4  end of input dies with exit 1
#   5  IAM_POSTGREST_JWT rollback with IAM_DB_ROLES=true: the recipe rolls IAM_DB_ROLES back
#      first; the config.env changes are printed, the file is untouched, no backup is made
#   6  IAM_DB_ROLES enable is refused while IAM_POSTGREST_JWT is false
#   7  a switch set on two active lines is refused
#   8  a precondition answered no stops before any step
#   9  --help works from a copy with no config.env; bad arguments exit 2
#  10  the repository's own config.env is byte for byte the same afterwards
#  11  a real (not dry) switch in the scratch tree: the one line is replaced, a mode-600
#      backup is made and the diff shown, the steps run under the guide's deploy lock
#      (MEDCEA_LOCK_HELD) which is free again afterwards, the backup is kept or deleted as
#      answered; a failing stub stops the recipe and says how to restore config.env
#  12  a switch is refused, with config.env untouched, while another process holds the lock
#  13  Ctrl-C during a step: the guide reports that config.env changed and exits 130
#  14  a username or unit code starting with - is re-asked (no --bootstrap smuggled in)
#  15  a recipe whose order depends on a duplicated or expression-valued switch is refused
#  16  uninstall.sh --purge-data directly: yes, then the project name
#  17  the fixture kept for the write probes: up && load && apply, each only after the last
#      succeeded (dry and real against stubs)
#  18  the IAM 2.7 rollback prints the psql command that reads the password in the pod
#  19  IAM_ENFORCE enable (routes-diff --strict first) and rollback (one infra deploy, no
#      app deploys), dry
#  20  IAM_MQTT_PERSON enable and rollback: set, (enable: the iam deploy, which refuses
#      without iam-api before the broker changes), the infra deploy, then the Explorer's
#      deploy, in that order, dry
#  21  IAM_DB_ROLES enable (the database deploy, then the workbench deploy that opens the
#      notebooks' hop) and rollback (the workbench deploy before the database deploy);
#      with WORKBENCH_ENABLED=false no workbench step, dry
#
#   tests/test_guide.sh      exit 1 on any FAIL

set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
FAILS=0
pass() { printf "  ${GREEN}PASS${NC}  %s\n" "$1"; }
fail() { printf "  ${RED}FAIL${NC}  %s\n" "$1"; FAILS=$((FAILS + 1)); }

T="$(mktemp -d)"
LOCKER=""
trap '[[ -n "$LOCKER" ]] && kill "$LOCKER" 2>/dev/null; rm -rf "$T"' EXIT

sum_real() { [[ -f "$REPO/config.env" ]] && sha256sum "$REPO/config.env" | cut -d' ' -f1; }
REAL_BEFORE="$(sum_real)"

# ── The scratch tree ─────────────────────────────────────────────────────────
S="$T/tree"; mkdir -p "$S/infra"
cp "$REPO/guide.sh" "$REPO/config.env.example" "$S/"
cp "$REPO/infra/lib-lock.sh" "$S/infra/"
mkstub() {   # mkstub RELPATH: prints "STUB RELPATH args", the lock it inherited, exits $STUB_RC
    local p="$1" f="$S/$1"
    mkdir -p "$(dirname "$f")"
    if [[ "$p" == *.py ]]; then
        printf '%s\n' 'import os, sys' \
            "print('STUB $p', *sys.argv[1:])" \
            'sys.exit(int(os.environ.get("STUB_RC", "0")))' >"$f"
    else
        printf '%s\n' '#!/bin/sh' \
            "echo \"STUB $p \$*\"" \
            'echo "LOCK_HELD=${MEDCEA_LOCK_HELD:-}"' \
            '[ -n "${STUB_INT:-}" ] && kill -INT 0' \
            'exit "${STUB_RC:-0}"' >"$f"
    fi
    chmod +x "$f"
}
while IFS= read -r p; do
    case "$p" in guide.sh|infra/lib-lock.sh) continue ;; esac
    mkstub "$p"
done < <(grep -oE '(\./)?(apps|infra|edge|tests)/[A-Za-z0-9_./-]+\.(sh|py)|\./[a-z-]+\.sh' "$REPO/guide.sh" | sed 's#^\./##' | sort -u)
for f in "$REPO"/apps/*/deploy.sh "$REPO"/apps/*/uninstall.sh; do mkstub "${f#"$REPO"/}"; done
# Nothing in the tree is a real script but guide.sh and lib-lock.sh.
REAL_IN_TREE="$(cd "$S" && find . -type f \( -name '*.sh' -o -name '*.py' \) ! -name guide.sh ! -name lib-lock.sh \
    -exec grep -L '^.*STUB ' {} + 2>/dev/null)"
[[ -z "$REAL_IN_TREE" ]] && echo "  (scratch tree: $(find "$S" -name '*.sh' -o -name '*.py' | wc -l) scripts, all stubs but guide.sh and lib-lock.sh)" \
    || { echo "scratch tree has non-stub scripts: $REAL_IN_TREE"; exit 1; }

# A scratch config.env from the template; IAM_DB_ROLES and IAM_POSTGREST_JWT as given.
mkcfg() {   # mkcfg DBROLES JWT
    sed -e "s/^IAM_DB_ROLES=.*/IAM_DB_ROLES=\"$1\"/" -e "s/^IAM_POSTGREST_JWT=.*/IAM_POSTGREST_JWT=\"$2\"/" \
        "$REPO/config.env.example" >"$T/config.env"
}

OUT=""; RC=0
guide() {   # guide INPUT → OUT, RC: a dry run of the scratch copy
    OUT="$(printf '%s' "$1" | NO_COLOR=1 MEDCEA_GUIDE_CONFIG="$T/config.env" "$S/guide.sh" --dry-run 2>&1)"
    RC=$?
}
real() {    # real INPUT → OUT, RC: a real run of the scratch copy (stubs, $S/config.env)
    OUT="$(printf '%s' "$1" | NO_COLOR=1 "$S/guide.sh" 2>&1)"
    RC=$?
}
has()  { grep -qF -- "$2" <<<"$OUT" && pass "$1" || { fail "$1 — missing: $2"; }; }
hasnt(){ grep -qF -- "$2" <<<"$OUT" && fail "$1 — unexpected: $2" || pass "$1"; }
rc_is(){ [[ "$RC" == "$2" ]] && pass "$1" || fail "$1 — exit $RC, wanted $2"; }
no_stub() { hasnt "a dry run ran nothing" "STUB "; }
lock_free() { flock -n "$S/.medcea.lock" true; }
menu_index() {   # menu_index KIND NAME → the component's number in the guide's menu
    local i=0 f
    for f in "$S"/apps/*/"$1".sh; do i=$((i + 1)); [[ "$f" == "$S/apps/$2/$1.sh" ]] && { echo "$i"; return; }; done
}

echo "1  units assign, --by remembered"
mkcfg false false
guide $'4\n2\ndeveloper\nUNIT;03 X\nUNIT03 unit04\nsvieira\n\nn\ny\nb\n2\ndev2\nU1\n\nbecause\nn\ny\nq\n'
rc_is "quits with 0" 0
has   "an invalid unit code is re-asked" "'UNIT;03': a unit code is letters"
has   "first command" "[dry run] not executed: ./apps/iam/units.sh assign developer UNIT03 unit04 --by svieira"
has   "--by offered as the default" "Your Keycloak username (--by) [svieira]:"
has   "second command reuses --by" "[dry run] not executed: ./apps/iam/units.sh assign dev2 U1 --by svieira --reason because"
has   "says it takes the lock" "Deploy lock: takes it"
no_stub

echo "2  uninstall apps needs the word yes"
guide $'1\n4\nmonitor bogus\nmonitor scheduler\ny\nb\n4\ndatabase\ny\nyes\nq\n'
rc_is "quits with 0" 0
has   "an unknown component is re-asked" "unknown component 'bogus'"
has   "the command is shown" "./install.sh --uninstall-apps monitor scheduler"
has   "y is not yes" "Cancelled; nothing was run."
hasnt "never ran the cancelled one" "not executed: ./install.sh --uninstall-apps monitor"
has   "yes runs (dry)" "[dry run] not executed: ./install.sh --uninstall-apps database --purge-data"
no_stub

echo "3  invalid menu input"
guide $'9\nx\nq\n'
rc_is "quits with 0" 0
has   "9 is re-asked" "not a choice: '9'"
has   "x is re-asked" "not a choice: 'x'"

echo "4  end of input"
guide $'1\n'
rc_is "dies with 1" 1
has   "says why" "input ended (EOF)"

echo "5  IAM_POSTGREST_JWT rollback while IAM_DB_ROLES=true"
mkcfg true true
SUM_BEFORE="$(sha256sum "$T/config.env" | cut -d' ' -f1)"
guide $'5\n4\n2\ny\nq\n'
rc_is "quits with 0" 0
has   "shows the current value" 'Now: IAM_POSTGREST_JWT="true"'
has   "step 1 rolls IAM_DB_ROLES back" '1. config.env: IAM_DB_ROLES="false"'
has   "step 2 closes the notebooks' hop" '2. ./infra/deploy-workbench.sh'
has   "step 3 is the database deploy" '3. ./apps/database/deploy.sh'
has   "step 4 sets the switch" '4. config.env: IAM_POSTGREST_JWT="false"'
has   "step 5 is the frontend deploy" '5. ./apps/frontend/deploy.sh'
has   "prints the config.env change" 'would set'
has   "with the old and new value" 'IAM_DB_ROLES="true" → IAM_DB_ROLES="false"'
has   "prints the deploy it would run" '[dry run] would run: ./apps/frontend/deploy.sh'
no_stub
[[ "$(sha256sum "$T/config.env" | cut -d' ' -f1)" == "$SUM_BEFORE" ]] && pass "config.env untouched" || fail "config.env changed"
compgen -G "$T/config.env.guide*" >/dev/null && fail "a backup or temp file was made" || pass "no backup made"

echo "6  IAM_DB_ROLES enable refused without IAM_POSTGREST_JWT"
mkcfg false false
guide $'5\n6\n1\nq\n'
has   "refused with the reason" "IAM_POSTGREST_JWT is 'false': enable it first"
has   "nothing changed" "Nothing was changed."
hasnt "no step ran" "[dry run] would"

echo "7  a switch on two active lines"
mkcfg false false
echo 'IAM_NETPOL="false"' >>"$T/config.env"
guide $'5\n2\nq\n'
has   "refused" "IAM_NETPOL is set on 2 active lines"
hasnt "no recipe offered" "Recipe:"

echo "8  a precondition answered no"
mkcfg false false
guide $'5\n2\n1\nn\nq\n'
has   "checklist shown" "[ ] Every caller of an application pod"
has   "stops" "Do those first. Nothing was changed."
hasnt "no step ran" "[dry run] would"

echo "9  --help and arguments"
mkdir -p "$T/copy"; cp "$REPO/guide.sh" "$T/copy/guide.sh"
OUT="$(cd "$T/copy" && ./guide.sh --help 2>&1)"; RC=$?
rc_is "--help exits 0 with no config.env" 0
has   "--help prints the usage" "./guide.sh [--dry-run] [--help]"
OUT="$("$S/guide.sh" --bogus </dev/null 2>&1)"; RC=$?
rc_is "an unknown argument exits 2" 2
OUT="$(MEDCEA_GUIDE_CONFIG="$T/config.env" "$S/guide.sh" </dev/null 2>&1)"; RC=$?
rc_is "MEDCEA_GUIDE_CONFIG without --dry-run exits 2" 2

echo "11 a real switch against stubs (scratch tree only)"
sed 's/^IAM_NETPOL=.*/IAM_NETPOL="true"/' "$REPO/config.env.example" >"$S/config.env"; chmod 600 "$S/config.env"
real $'5\n2\n2\ny\nn\nq\n'
rc_is "quits with 0" 0
has   "the stub ran" "STUB deploy-infra.sh"
grep -qE '^LOCK_HELD=[0-9]+$' <<<"$OUT" && pass "the step ran under the guide's lock (MEDCEA_LOCK_HELD)" \
    || fail "the step did not inherit MEDCEA_LOCK_HELD"
lock_free && pass "the lock is free after the recipe" || fail "the lock is still held"
has   "the diff is shown" '+IAM_NETPOL="false"'
has   "done" 'All 2 steps done: IAM_NETPOL="false".'
has   "offers to delete the backup" "Delete that backup now?"
[[ "$(grep -c '^IAM_NETPOL=' "$S/config.env")" == 1 ]] && grep -q '^IAM_NETPOL="false"$' "$S/config.env" \
    && pass "exactly that line changed" || fail "IAM_NETPOL line not replaced"
[[ "$(diff "$S/config.env.example" "$S/config.env" | grep -c '^[<>]')" == 2 ]] \
    && pass "nothing else changed" || fail "other lines changed"
B="$(compgen -G "$S/config.env.guide-*.bak" | head -1)"
[[ -n "$B" && "$(stat -c %a "$B")" == 600 ]] && grep -q '^IAM_NETPOL="true"$' "$B" \
    && pass "backup kept as answered, the old value, mode 600" || fail "no proper backup"
compgen -G "$S/config.env.guide.*" >/dev/null && fail "a temp file was left" || pass "no temp file left"
rm -f "$S"/config.env.guide-*.bak
real $'5\n2\n1\ny\ny\n\nq\n'
rc_is "enable again: quits with 0" 0
grep -q '^IAM_NETPOL="true"$' "$S/config.env" && pass "enable again: set" || fail "enable again: not set"
compgen -G "$S/config.env.guide-*.bak" >/dev/null && fail "Enter did not delete the backup" || pass "Enter deletes the backup"
OUT="$(printf '5\n2\n2\ny\nq\n' | NO_COLOR=1 STUB_RC=3 "$S/guide.sh" 2>&1)"; RC=$?
has   "the failing step is named" "Step 2 failed (exit code 3): ./deploy-infra.sh"
has   "says config.env changed" "config.env has already been changed."
has   "says how to restore" "cp -p config.env.guide-"
hasnt "no backup deletion offered after a failure" "Delete that backup now?"
grep -q '^IAM_NETPOL="false"$' "$S/config.env" && pass "the set step before it stays done" || fail "set step lost"
lock_free && pass "the lock is free after a failed recipe" || fail "the lock is still held"
rm -f "$S"/config.env.guide-*.bak

echo "12 the lock held by another deploy"
sed -i 's/^IAM_NETPOL=.*/IAM_NETPOL="true"/' "$S/config.env"
SUM_BEFORE="$(sha256sum "$S/config.env" | cut -d' ' -f1)"
( exec 8>>"$S/.medcea.lock"; flock 8 && exec sleep 60 ) &
LOCKER=$!
for _ in $(seq 50); do lock_free || break; sleep 0.1; done
if lock_free; then
    fail "could not take the lock for the test"
else
    real $'5\n2\n2\ny\nq\n'
    rc_is "quits with 0" 0
    has   "refused" "another MedCEA deploy is running"
    has   "nothing changed" "Nothing was changed."
    hasnt "no step ran" "STUB "
    [[ "$(sha256sum "$S/config.env" | cut -d' ' -f1)" == "$SUM_BEFORE" ]] && pass "config.env untouched" || fail "config.env changed"
fi
kill "$LOCKER" 2>/dev/null; wait "$LOCKER" 2>/dev/null; LOCKER=""

echo "13 Ctrl-C during a step"
if command -v setsid >/dev/null; then
    sed -i 's/^IAM_NETPOL=.*/IAM_NETPOL="true"/' "$S/config.env"
    # Its own process group, so the stub's kill -INT 0 is a Ctrl-C to the guide and the
    # step only, never to this script.
    OUT="$(setsid -w bash -c 'printf "5\n2\n2\ny\nq\n" | NO_COLOR=1 STUB_INT=1 "$1"' _ "$S/guide.sh" 2>&1)"; RC=$?
    rc_is "exits 130" 130
    has   "says it was interrupted" "Stopped by Ctrl-C (SIGINT) during step 2"
    has   "says config.env changed" "config.env has already been changed."
    has   "says how to restore" "cp -p config.env.guide-"
    hasnt "does not claim success" "steps done"
    lock_free && pass "the lock is free afterwards" || fail "the lock is still held"
    rm -f "$S"/config.env.guide-*.bak
else
    echo "  (setsid not installed: skipped)"
fi

echo "14 a leading - is never taken as a value"
mkcfg false false
guide $'4\n2\n--bootstrap\ndeveloper\nUNIT03 --bootstrap\n-x\nUNIT03\nsvieira\n\nn\ny\nb\n1\n-x\n\nn\nq\n'
has   "a username starting with - is re-asked" "'--bootstrap': letters, digits"
has   "a unit code starting with - is re-asked" "'--bootstrap': a unit code is"
has   "-x as a unit code too" "'-x': a unit code is"
has   "the command has no smuggled option" "[dry run] not executed: ./apps/iam/units.sh assign developer UNIT03 --by svieira"
hasnt "--bootstrap never reached the command" "UNIT03 --bootstrap --by"
has   "list: -x is re-asked" "'-x': letters, digits"
no_stub

echo "15 a dependency switch that cannot be read"
mkcfg true true
echo 'IAM_DB_ROLES="false"' >>"$T/config.env"
guide $'5\n5\n2\nq\n'
has   "duplicated: refused" "this recipe's order depends on IAM_DB_ROLES"
has   "nothing changed" "Nothing was changed."
hasnt "no step" "[dry run] would"
mkcfg true true
sed -i 's/^IAM_DB_ROLES=.*/IAM_DB_ROLES="${MEDCEA_X:-true}"/' "$T/config.env"
guide $'5\n4\n2\nq\n'
has   "an expression: refused" 'write it as "true" or "false"'
hasnt "no step" "[dry run] would"

echo "16 uninstall.sh --purge-data asks for the project name"
mkcfg false false
I="$(menu_index uninstall database)"
guide "3"$'\n'"5"$'\n'"$I"$'\n'"y"$'\n'"yes"$'\n'"medcea"$'\n'"b"$'\n'"5"$'\n'"$I"$'\n'"y"$'\n'"yes"$'\n'"nope"$'\n'"q"$'\n'
rc_is "quits with 0" 0
has   "asks for the project name" "Type the project name ('medcea')"
has   "the name runs it (dry)" "[dry run] not executed: ./apps/database/uninstall.sh --purge-data"
[[ "$(grep -c 'not executed: ./apps/database/uninstall.sh' <<<"$OUT")" == 1 ]] \
    && pass "a wrong name cancels" || fail "a wrong name did not cancel"
no_stub

echo "17 the fixture kept for the write probes"
mkcfg false false
guide $'6\n13\n\ny\nq\n'
has   "the chain is shown" "[dry run] not executed: tests/iam-db-fixture.sh up && tests/iam-db-fixture.sh load && tests/iam-db-fixture.sh apply false"
no_stub
guide $'6\n8\n\n\nn\nq\n'
has   "the probes note points at the keep entry" "'Build the throwaway database and keep it'"
real $'6\n13\n\ny\nq\n'
has   "real: up ran" "STUB tests/iam-db-fixture.sh up"
has   "real: then load" "STUB tests/iam-db-fixture.sh load"
has   "real: then apply" "STUB tests/iam-db-fixture.sh apply false"
OUT="$(printf '6\n13\n\ny\nq\n' | NO_COLOR=1 STUB_RC=1 "$S/guide.sh" 2>&1)"
has   "a failure stops the chain" "STUB tests/iam-db-fixture.sh up"
hasnt "load did not run" "STUB tests/iam-db-fixture.sh load"

echo "18 the IAM 2.7 rollback's psql command"
mkcfg false false
guide $'5\n7\nq\n'
has   "namespace from config.env" "microk8s kubectl exec -i -n medcea rdbms-postgresql-0 -- \\"
has   "reads the password in the pod" "sh -c 'PGPASSWORD=\"\$(cat \"\$POSTGRES_PASSWORD_FILE\")\" psql -X -1 -v ON_ERROR_STOP=1 -U postgres -d medcea_db -f -'"

echo "19 IAM_ENFORCE enable and rollback"
mkcfg true true
SUM_BEFORE="$(sha256sum "$T/config.env" | cut -d' ' -f1)"
guide $'5\n3\n1\ny\ny\nq\n'
rc_is "quits with 0" 0
has   "shows the current value" 'Now: IAM_ENFORCE="false"'
has   "the soak is on the checklist" "[ ] A report-only soak is over"
has   "step 1 is the strict route diff" '1. python3 tests/iam-routes-diff.py --strict'
has   "step 2 sets the switch" '2. config.env: IAM_ENFORCE="true"'
has   "step 3 is the infra deploy" '3. ./deploy-infra.sh'
hasnt "no step 4" '4. '
hasnt "no app deploy" 'would run: ./deploy-apps.sh'
has   "prints the deploy it would run" '[dry run] would run: ./deploy-infra.sh'
no_stub
[[ "$(sha256sum "$T/config.env" | cut -d' ' -f1)" == "$SUM_BEFORE" ]] && pass "config.env untouched" || fail "config.env changed"
sed -i 's/^IAM_ENFORCE=.*/IAM_ENFORCE="true"/' "$T/config.env"
guide $'5\n3\n2\ny\nq\n'
rc_is "quits with 0" 0
has   "step 1 sets the switch back" '1. config.env: IAM_ENFORCE="false"'
has   "step 2 is the infra deploy" '2. ./deploy-infra.sh'
hasnt "no step 3" '3. '
hasnt "no app deploy" 'would run: ./deploy-apps.sh'
no_stub

echo "20 IAM_MQTT_PERSON enable and rollback"
mkcfg true true
SUM_BEFORE="$(sha256sum "$T/config.env" | cut -d' ' -f1)"
guide $'5\n8\n1\ny\ny\nq\n'
rc_is "quits with 0" 0
has   "shows the current value" 'Now: IAM_MQTT_PERSON="false"'
has   "iam_svc is on the checklist" "[ ] IAM_DB_SERVICE_ROLES is true and ./apps/database/deploy.sh has let iam_svc log in"
has   "the shared password's users are warned" "Nobody uses MQTT_EXPLORER_PASS outside the Explorer page"
has   "step 1 sets the switch" '1. config.env: IAM_MQTT_PERSON="true"'
has   "step 2 deploys iam-api, before the broker changes" '2. ./apps/iam/deploy.sh'
has   "step 3 is the infra deploy" '3. ./deploy-infra.sh'
has   "step 4 is the Explorer's deploy" '4. ./apps/mqtt-explorer/deploy.sh'
hasnt "no step 5" '5. '
has   "the lock is held for the recipe" "Every step takes the deploy lock"
no_stub
[[ "$(sha256sum "$T/config.env" | cut -d' ' -f1)" == "$SUM_BEFORE" ]] && pass "config.env untouched" || fail "config.env changed"
sed -i 's/^IAM_MQTT_PERSON=.*/IAM_MQTT_PERSON="true"/' "$T/config.env"
guide $'5\n8\n2\ny\nq\n'
rc_is "quits with 0" 0
has   "step 1 sets the switch back" '1. config.env: IAM_MQTT_PERSON="false"'
has   "step 2 is the infra deploy" '2. ./deploy-infra.sh'
has   "step 3 is the Explorer's deploy" '3. ./apps/mqtt-explorer/deploy.sh'
has   "the shared account comes back" "The shared mqtt-explorer account (MQTT_EXPLORER_PASS) is back"
no_stub

echo "21 IAM_DB_ROLES and the notebooks' hop"
mkcfg false true
sed -i 's/^IAM_DB_SERVICE_ROLES=.*/IAM_DB_SERVICE_ROLES="true"/' "$T/config.env"
guide $'5\n6\n1\ny\ny\nq\n'
rc_is "quits with 0" 0
has   "step 1 sets the switch" '1. config.env: IAM_DB_ROLES="true"'
has   "step 2 is the database deploy" '2. ./apps/database/deploy.sh'
has   "step 3 opens the notebooks' hop" '3. ./infra/deploy-workbench.sh'
no_stub
mkcfg true true
guide $'5\n6\n2\ny\nq\n'
rc_is "quits with 0" 0
has   "step 1 sets the switch back" '1. config.env: IAM_DB_ROLES="false"'
has   "step 2 closes the notebooks' hop first" '2. ./infra/deploy-workbench.sh'
has   "step 3 is the database deploy" '3. ./apps/database/deploy.sh'
no_stub
sed -i 's/^WORKBENCH_ENABLED=.*/WORKBENCH_ENABLED="false"/' "$T/config.env"
guide $'5\n6\n2\ny\nq\n'
has   "no workbench: step 2 is the database deploy" '2. ./apps/database/deploy.sh'
hasnt "no workbench deploy" 'deploy-workbench.sh'
no_stub

echo "10 the real config.env"
[[ "$(sum_real)" == "$REAL_BEFORE" ]] && pass "unchanged" || fail "the repository's config.env changed"

echo
if (( FAILS )); then echo -e "${RED}$FAILS failure(s)${NC}"; exit 1; fi
echo -e "${GREEN}All passed${NC}"
