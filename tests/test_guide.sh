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
#  22  Bring IAM to full enforcement: every switch true → nothing to do; a switch written
#      as an expression → refused, nothing changed
#  23  a mix: the plan lists only the false switches, in the documented order
#  24  a dry run of the whole chain: every recipe planned as if the ones before it were
#      done (IAM_DB_ROLES is not refused), every command printed, nothing run, config.env
#      untouched, and no lock taken (it runs while another process holds the lock)
#  25  a real chain against stubs: each switch set, each recipe's steps in order, all under
#      one lock taken once (every step finds it held by someone else's open, and the lock
#      file's mtime, rewritten at each take, is the same for every step), the backups
#      offered for deletion
#  26  a checklist answered no (IAM_DB_ROLES) stops the chain with what is done, how to
#      resume, later switches still false; running again resumes from IAM_DB_ROLES
#  27  a failing step stops the chain: the step, config.env changed and how to restore it
#  28  the operators' units are read before IAM_DB_ROLES: an operator without a unit asks
#      whether to go on, and no stops cleanly; an unreadable list says so and asks too
#  29  Ctrl-C during the chain exits 130 with the resume text
#  30  Ctrl-C while the chain waits at a question (IAM_DB_ROLES's checklist, the units
#      question), then y typed: exit 130 at once, IAM_DB_ROLES still false, no new backup
#  31  Backups: now (changes, the lock), list, verify with a folder (a bad name re-asked) and
#      restore-help for the newest, dry; the restore entry runs restore-help, nothing else
#  32  Deploy IAM 4.1: access, database, infra in that order, the 503 window explained
#      before the [y/N]; dry: nothing run, no lock; real against stubs: all three under the
#      guide's one lock (each finds it held), a failure stops the chain, the lock is free
#      afterwards; refused, nothing run, while another process holds the lock
#  33  Deploy IAM 4.2a: database, infra, iam in that order; --by asked (a leading - re-asked)
#      and passed to the iam deploy as MEDCEA_POLICY_BOOTSTRAP_BY; one lock for all three; the
#      notes (order, no 503 window, the bootstrap, the two new checks) before the [y/N]
#  34  Bootstrap version 1 by hand: the typed word yes (y cancels), --by remembered, a --by
#      starting with - re-asked; apply.sh gets MEDCEA_CONFIRMED=1 and takes its own lock
#  35  Policy versions: status and Print the applied policy are read-only ([Y/n], no lock);
#      Would version 1 bootstrap? passes --check-only; Finish an interrupted apply is [y/N]
#  36  How to use policy break-glass is shown, never run: no command, no confirmation, and it
#      says break-glass does not bypass the skeleton gate
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
            "echo \"LOCK_STAMP=\$(stat -c %y $(printf %q "$S/.medcea.lock") 2>/dev/null)\"" \
            "flock -n $(printf %q "$S/.medcea.lock") true 9>&- && echo LOCK_PROBE=free || echo LOCK_PROBE=held" \
            'echo "ENV_BY=${MEDCEA_POLICY_BOOTSTRAP_BY:-} ENV_CONFIRMED=${MEDCEA_CONFIRMED:-}"' \
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
guide $'10\nx\nq\n'
rc_is "quits with 0" 0
has   "10 is re-asked" "not a choice: '10'"
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
hasnt "no shared password on the checklist" "MQTT_EXPLORER_PASS"
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
has   "the Explorer is left without a credential" "The MQTT Explorer then has no broker credential"
hasnt "the shared account does not come back" "MQTT_EXPLORER_PASS"
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

# ── Bring IAM to full enforcement (area 5, item 9) ──
SW_ALL=(IAM_GATES IAM_NETPOL IAM_POSTGREST_JWT IAM_DB_SERVICE_ROLES IAM_DB_ROLES IAM_ENFORCE IAM_MQTT_PERSON)
swcfg() {   # swcfg FILE KEY=VAL…: the template with those switches set
    local f="$1" kv; shift
    cp "$REPO/config.env.example" "$f"; chmod 600 "$f"
    for kv in "$@"; do sed -i "s/^${kv%%=*}=.*/${kv%%=*}=\"${kv#*=}\"/" "$f"; done
}
sw_is() {   # sw_is FILE KEY VAL
    grep -q "^$2=\"$3\"\$" "$1" && pass "$2 is $3" || fail "$2 is not $3: $(grep "^$2=" "$1")"
}
# units.sh list, as the chain reads it: the table on stdout (UNITS_MODE ok|none|fail)
printf '%s\n' '#!/bin/sh' \
    'echo "STUB apps/iam/units.sh $*" >&2' \
    'echo "LOCK_HELD=${MEDCEA_LOCK_HELD:-}" >&2' \
    '[ -n "${MEDCEA_NO_LOG:-}" ] || echo "Log: logs/app-iam-units-stub.log"' \
    '[ "${UNITS_MODE:-ok}" = logline ] && echo "Log: logs/app-iam-units-stub.log"' \
    'case "${UNITS_MODE:-ok}" in' \
    '  ok|logline) printf "USERNAME\tROLE\tENABLED\tUNITS\tWAITING_QA\nop1\toperator\ttrue\tUNIT01\t-\nqa1\tqa\ttrue\t-\t-\n" ;;' \
    '  none) printf "USERNAME\tROLE\tENABLED\tUNITS\tWAITING_QA\nop1\toperator\ttrue\tUNIT01\t-\nop2\toperator\ttrue\t-\tUNIT02\n" ;;' \
    '  fail) exit 2 ;;' \
    'esac' >"$S/apps/iam/units.sh"
chain() {   # chain INPUT [ENV=VAL…] → OUT, RC: a real run of the scratch copy
    local in="$1"; shift
    OUT="$(printf '%s' "$in" | env NO_COLOR=1 "$@" "$S/guide.sh" 2>&1)"; RC=$?
}

echo "22 full enforcement: nothing to do, or refused"
swcfg "$T/config.env" "${SW_ALL[@]/%/=true}"
guide $'5\n9\n\nq\n'
rc_is "quits with 0" 0
has   "says so" "Every IAM switch is already true: nothing to do."
hasnt "no plan" "Plan:"
no_stub
swcfg "$T/config.env"
sed -i 's/^IAM_ENFORCE=.*/IAM_ENFORCE="${X:-false}"/' "$T/config.env"
guide $'5\n9\n\nq\n'
has   "an expression is refused" 'IAM_ENFORCE is '\''${X:-false}'\'' on line'
has   "nothing changed" "Nothing was changed."
hasnt "no plan" "Plan:"

echo "23 full enforcement: the plan lists only the false switches, in order"
swcfg "$T/config.env" IAM_GATES=false IAM_NETPOL=true IAM_POSTGREST_JWT=true IAM_DB_SERVICE_ROLES=false IAM_DB_ROLES=false IAM_ENFORCE=false IAM_MQTT_PERSON=true
guide $'5\n9\nn\n\nq\n'
rc_is "quits with 0" 0
has   "plan heading" "Plan: 4 switch(es) → true, in this order"
has   "1. IAM_GATES" "1. IAM_GATES → true"
has   "2. IAM_DB_SERVICE_ROLES" "2. IAM_DB_SERVICE_ROLES → true"
has   "3. IAM_DB_ROLES" "3. IAM_DB_ROLES → true"
has   "4. IAM_ENFORCE" "4. IAM_ENFORCE → true"
hasnt "IAM_NETPOL (true) skipped" "IAM_NETPOL → true"
hasnt "IAM_POSTGREST_JWT (true) skipped" "IAM_POSTGREST_JWT → true"
hasnt "IAM_MQTT_PERSON (true) skipped" "IAM_MQTT_PERSON → true"
has   "the recipe steps as the switch recipe shows them" '1. config.env: IAM_DB_SERVICE_ROLES="true"'
has   "the purpose is shown" "Each database client logs in as its own role instead of postgres"
has   "one confirmation, [y/N]" "Run these 4 recipes (12 steps)? [y/N]"
has   "no is cancel" "Cancelled. Nothing was changed."
no_stub

echo "24 full enforcement: a dry run changes nothing and takes no lock"
swcfg "$T/config.env"
SUM_BEFORE="$(sha256sum "$T/config.env" | cut -d' ' -f1)"
( exec 8>>"$S/.medcea.lock"; flock 8 && exec sleep 60 ) &
LOCKER=$!
for _ in $(seq 50); do lock_free || break; sleep 0.1; done
lock_free && fail "could not take the lock for the test"
guide $'5\n9\ny\ny\ny\ny\ny\n\nq\n'
kill "$LOCKER" 2>/dev/null; wait "$LOCKER" 2>/dev/null; LOCKER=""
rc_is "quits with 0" 0
has   "fresh install: 5 switches" "Plan: 5 switch(es) → true, in this order"
hasnt "IAM_GATES (true) skipped" "IAM_GATES → true"
has   "IAM_DB_ROLES planned, not refused" "3. IAM_DB_ROLES → true"
hasnt "no refusal" "enable it first"
has   "every set printed" '[dry run] would set '"$T"'/config.env line'
has   "the JWT set" 'IAM_POSTGREST_JWT="false" → IAM_POSTGREST_JWT="true"'
has   "the units list printed" "[dry run] would run: ./apps/iam/units.sh list"
has   "the database deploy printed" "[dry run] would run: ./apps/database/deploy.sh"
has   "the Explorer deploy printed" "[dry run] would run: ./apps/mqtt-explorer/deploy.sh"
has   "done, without the lock" "[dry run] the whole chain shown; nothing was run or changed, and no lock was taken."
hasnt "never refused for the lock" "another MedCEA deploy is running"
no_stub
[[ "$(sha256sum "$T/config.env" | cut -d' ' -f1)" == "$SUM_BEFORE" ]] && pass "config.env untouched" || fail "config.env changed"
compgen -G "$T/config.env.guide*" >/dev/null && fail "a backup or temp file was made" || pass "no backup made"

echo "25 full enforcement: a real chain against stubs"
swcfg "$S/config.env"
rm -f "$S"/config.env.guide-*.bak
# run; JWT checklist; IAM_DB_ROLES checklist; IAM_ENFORCE's; IAM_MQTT_PERSON's; redeploy the apps; delete backups (Enter)
chain $'5\n9\ny\ny\ny\ny\ny\ny\n\n\nq\n'
rc_is "quits with 0" 0
for k in "${SW_ALL[@]}"; do sw_is "$S/config.env" "$k" true; done
WANT='STUB deploy-infra.sh
STUB apps/frontend/deploy.sh
STUB deploy-apps.sh --all
STUB deploy-infra.sh
STUB apps/iam/units.sh list
STUB apps/database/deploy.sh
STUB infra/deploy-workbench.sh
STUB tests/iam-routes-diff.py --strict
STUB deploy-infra.sh
STUB apps/iam/deploy.sh
STUB deploy-infra.sh
STUB apps/mqtt-explorer/deploy.sh
STUB deploy-apps.sh --all'
GOT="$(grep '^STUB ' <<<"$OUT" | sed 's/ *$//')"
[[ "$GOT" == "$WANT" ]] && pass "every recipe's steps ran, in order" || fail "steps out of order:"$'\n'"$GOT"
LH="$(grep '^LOCK_HELD=' <<<"$OUT" | sort -u)"
[[ "$(wc -l <<<"$LH")" == 1 && "$LH" =~ ^LOCK_HELD=[0-9]+$ ]] && pass "every step got MEDCEA_LOCK_HELD ($LH)" || fail "not one MEDCEA_LOCK_HELD: $LH"
LP="$(grep '^LOCK_PROBE=' <<<"$OUT" | sort -u)"
[[ "$LP" == LOCK_PROBE=held ]] && pass "the lock was held during every step" || fail "the lock was free during a step: $LP"
# The guide rewrites the lock file each time it takes the lock: one mtime = one take,
# so the lock was not released and taken again between switches.
LS="$(grep '^LOCK_STAMP=' <<<"$OUT" | sort -u)"
[[ "$(grep -c '^LOCK_STAMP=' <<<"$OUT")" -ge 10 && "$(wc -l <<<"$LS")" == 1 && "$LS" != "LOCK_STAMP=" ]] \
    && pass "the lock was taken once for the whole chain" || fail "the lock was taken more than once: $LS"
has   "the units check found every operator placed" "Every enabled operator has a unit in effect."
has   "the plan names the last redeploy" "Last: ./deploy-apps.sh --all"
has   "the redeploy is asked, [y/N]" "No run is active: redeploy the apps now? [y/N]"
has   "done" "IAM is at full enforcement: IAM_POSTGREST_JWT IAM_DB_SERVICE_ROLES IAM_DB_ROLES IAM_ENFORCE IAM_MQTT_PERSON turned on"
has   "the backups are offered for deletion" "Delete these 5 backups now?"
compgen -G "$S/config.env.guide-*.bak" >/dev/null && fail "Enter did not delete the backups" || pass "Enter deletes the backups"
lock_free && pass "the lock is free afterwards" || fail "the lock is still held"
[[ "$(diff "$S/config.env.example" "$S/config.env" | grep -c '^[<>]')" == 10 ]] \
    && pass "only the five switch lines changed" || fail "other lines changed"

echo "26 full enforcement: a refused checklist stops the chain; running again resumes"
swcfg "$S/config.env" IAM_POSTGREST_JWT=false
rm -f "$S"/config.env.guide-*.bak
# run; JWT checklist y; IAM_DB_ROLES checklist n
chain $'5\n9\ny\ny\nn\n\nq\n'
rc_is "the guide goes on (quits with 0)" 0
has   "stopped at IAM_DB_ROLES" "Bring IAM to full enforcement stopped at IAM_DB_ROLES: its checklist was answered no"
has   "what is done" "Already done, now true in config.env and deployed: IAM_POSTGREST_JWT IAM_DB_SERVICE_ROLES."
has   "what is not started" "Not started: IAM_ENFORCE IAM_MQTT_PERSON."
has   "config.env not changed for it" "config.env was not changed for IAM_DB_ROLES."
has   "the backups are listed" "Backups of config.env, one before each switch this run changed"
has   "how to resume" "switches already true are skipped, so it resumes from IAM_DB_ROLES."
hasnt "no database deploy" "STUB apps/database/deploy.sh"
sw_is "$S/config.env" IAM_DB_SERVICE_ROLES true
sw_is "$S/config.env" IAM_DB_ROLES false
sw_is "$S/config.env" IAM_ENFORCE false
sw_is "$S/config.env" IAM_MQTT_PERSON false
lock_free && pass "the lock is free afterwards" || fail "the lock is still held"
chain $'5\n9\ny\ny\ny\ny\ny\nn\n\nq\n'
rc_is "again: quits with 0" 0
has   "again: the plan starts at IAM_DB_ROLES" "1. IAM_DB_ROLES → true"
hasnt "again: JWT skipped" "IAM_POSTGREST_JWT → true"
hasnt "again: no infra deploy before the database" "STUB apps/frontend/deploy.sh"
has   "again: done" "IAM is at full enforcement: IAM_DB_ROLES IAM_ENFORCE IAM_MQTT_PERSON turned on"
has   "again: a backup kept as answered" "Kept. ./install.sh --uninstall-all deletes them"
for k in "${SW_ALL[@]}"; do sw_is "$S/config.env" "$k" true; done
rm -f "$S"/config.env.guide-*.bak

echo "27 full enforcement: a failing step stops the chain"
swcfg "$S/config.env" IAM_POSTGREST_JWT=true
chain $'5\n9\ny\n\nq\n' STUB_RC=3
has   "the failing step is named" "Step 2 failed (exit code 3): ./deploy-apps.sh --all"
has   "says config.env changed" "config.env has already been changed."
has   "says how to restore" "cp -p config.env.guide-"
has   "the chain says where" "stopped at IAM_DB_SERVICE_ROLES: step 2 failed"
has   "its switch is already set" 'IAM_DB_SERVICE_ROLES is already "true" in config.env, but its recipe did not finish'
has   "a plain re-run would skip it" "would skip it"
has   "how to resume" "it resumes from IAM_DB_SERVICE_ROLES;"
# put that switch's backup back as told: the next run resumes from it
B="$(compgen -G "$S/config.env.guide-*.bak" | head -1)"
[[ -n "$B" ]] && cp -p "$B" "$S/config.env"
sw_is "$S/config.env" IAM_DB_SERVICE_ROLES false
sw_is "$S/config.env" IAM_POSTGREST_JWT true
chain $'5\n9\nn\n\nq\n'
has   "after restoring: the plan starts at it" "1. IAM_DB_SERVICE_ROLES → true"
hasnt "nothing after it ran" "STUB apps/database/deploy.sh"
hasnt "no success" "IAM is at full enforcement"
sw_is "$S/config.env" IAM_DB_ROLES false
lock_free && pass "the lock is free afterwards" || fail "the lock is still held"
rm -f "$S"/config.env.guide-*.bak

echo "28 full enforcement: operators without a unit, before IAM_DB_ROLES"
swcfg "$S/config.env" IAM_POSTGREST_JWT=true IAM_DB_SERVICE_ROLES=true
chain $'5\n9\ny\nn\n\nq\n' UNITS_MODE=none
rc_is "quits with 0" 0
has   "the list ran under the chain's lock" "STUB apps/iam/units.sh list"
grep -qE '^LOCK_HELD=[0-9]+$' <<<"$OUT" && pass "units.sh inherited the lock" || fail "units.sh ran without the lock"
has   "names the operator" "enabled operator(s) with no unit in effect: op2"
has   "says the consequence" "they see no telemetry or runs (an empty Monitor) and start none"
has   "says how to assign" "./apps/iam/units.sh assign <operator> <UNIT>… --by <your username>"
has   "mentions qa" "a qa person other than you confirms it"
has   "asks" "Go on with IAM_DB_ROLES anyway? [y/N]"
hasnt "asked before the checklist" "Is every item in 'Before you start' true for IAM_DB_ROLES"
has   "no stops cleanly" "stopped at IAM_DB_ROLES: you chose not to go on while operators have no unit in effect"
hasnt "no database deploy" "STUB apps/database/deploy.sh"
sw_is "$S/config.env" IAM_DB_ROLES false
compgen -G "$S/config.env.guide-*.bak" >/dev/null && fail "a backup was made" || pass "config.env not touched"
lock_free && pass "the lock is free afterwards" || fail "the lock is still held"
chain $'5\n9\ny\nn\n\nq\n' UNITS_MODE=fail
has   "an unreadable list is said" "could not read the operators' units (./apps/iam/units.sh list exited 2)"
has   "and asked about" "Go on with IAM_DB_ROLES anyway? [y/N]"
# yes goes on to the checklist and the recipe
# ... and the redeploy answered no: the switches are true, the end says what is left
chain $'5\n9\ny\ny\ny\ny\ny\nn\n\n\nq\n' UNITS_MODE=none
has   "yes goes on" "STUB apps/database/deploy.sh"
sw_is "$S/config.env" IAM_MQTT_PERSON true
hasnt "no redeploy when answered no" "STUB deploy-apps.sh --all"
hasnt "no claim of full enforcement" "IAM is at full enforcement"
has   "says the apps are left" "Still to do, with no run active: ./deploy-apps.sh --all"
rm -f "$S"/config.env.guide-*.bak
# a "Log: …" line before the table (units.sh logging) still reads as a list
swcfg "$S/config.env" IAM_POSTGREST_JWT=true IAM_DB_SERVICE_ROLES=true
chain $'5\n9\ny\nn\n\nq\n' UNITS_MODE=logline
has   "a log line before the header is skipped" "Every enabled operator has a unit in effect."
hasnt "not called unreadable" "could not read the operators' units"
grep -q '^Log: logs/app-iam-units-stub.log' <<<"$OUT" && pass "the stub printed its log line" || fail "the stub printed no log line"
rm -f "$S"/config.env.guide-*.bak

echo "29 full enforcement: Ctrl-C"
if command -v setsid >/dev/null; then
    swcfg "$S/config.env" IAM_POSTGREST_JWT=true
    OUT="$(setsid -w bash -c 'printf "5\n9\ny\n" | NO_COLOR=1 STUB_INT=1 "$1"' _ "$S/guide.sh" 2>&1)"; RC=$?
    rc_is "exits 130" 130
    has   "says it was interrupted" "Stopped by Ctrl-C (SIGINT) during step 2"
    has   "the chain says where" "stopped at IAM_DB_SERVICE_ROLES: step 2 was interrupted"
    has   "how to resume" "it resumes from IAM_DB_SERVICE_ROLES;"
    has   "the backup to put back" "cp -p config.env.guide-"
    lock_free && pass "the lock is free afterwards" || fail "the lock is still held"
    rm -f "$S"/config.env.guide-*.bak
else
    echo "  (setsid not installed: skipped)"
fi

echo "30 full enforcement: Ctrl-C at a question stops before the switch's steps"
# The guide is started with SIGINT at its default (a background job of a script would
# ignore it), the answers fed until the question shows, then SIGINT, then "y".
sigprompt() {   # sigprompt INPUT PROMPT [ENV=VAL…] → OUT, RC
    local in="$1" prompt="$2"; shift 2
    OUT="$(env NO_COLOR=1 "$@" python3 -c '
import os, signal, subprocess, sys, time
guide, answers, prompt = sys.argv[1:4]
p = subprocess.Popen([guide], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                     preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL))
os.set_blocking(p.stdout.fileno(), False)
p.stdin.write(answers.encode()); p.stdin.flush()
out, deadline = b"", time.time() + 20
while prompt.encode() not in out and time.time() < deadline and p.poll() is None:
    out += p.stdout.read() or b""; time.sleep(0.05)
time.sleep(0.3)                       # the guide is now blocked in read
p.send_signal(signal.SIGINT)
time.sleep(0.5)
try:
    p.stdin.write(b"y\ny\ny\ny\n\nq\n"); p.stdin.flush(); p.stdin.close()
except (BrokenPipeError, OSError):
    pass
rc = p.wait(timeout=30)
os.set_blocking(p.stdout.fileno(), True)
out += p.stdout.read() or b""
sys.stdout.write(out.decode(errors="replace")); sys.exit(rc)
' "$S/guide.sh" "$in" "$prompt" 2>&1)"; RC=$?
}
swcfg "$S/config.env" IAM_POSTGREST_JWT=true
rm -f "$S"/config.env.guide-*.bak
sigprompt $'5\n9\ny\n' "Is every item in 'Before you start' true for IAM_DB_ROLES?"
rc_is "exits 130" 130
has   "says where" "Stopped by Ctrl-C (SIGINT) at a question for IAM_DB_ROLES; none of its steps ran."
has   "the chain says where" "stopped at IAM_DB_ROLES: stopped by Ctrl-C (SIGINT) before its steps"
has   "what is done" "Already done, now true in config.env and deployed: IAM_DB_SERVICE_ROLES."
has   "how to resume" "switches already true are skipped, so it resumes from IAM_DB_ROLES."
hasnt "no step of IAM_DB_ROLES" "STUB apps/database/deploy.sh"
sw_is "$S/config.env" IAM_DB_SERVICE_ROLES true
sw_is "$S/config.env" IAM_DB_ROLES false
[[ "$(compgen -G "$S/config.env.guide-*.bak" | wc -l)" == 1 ]] && pass "no new backup (only IAM_DB_SERVICE_ROLES's)" || fail "backups: $(compgen -G "$S/config.env.guide-*.bak")"
lock_free && pass "the lock is free afterwards" || fail "the lock is still held"
rm -f "$S"/config.env.guide-*.bak
swcfg "$S/config.env" IAM_POSTGREST_JWT=true IAM_DB_SERVICE_ROLES=true
sigprompt $'5\n9\ny\n' "Go on with IAM_DB_ROLES anyway?" UNITS_MODE=none
rc_is "at the units question: exits 130" 130
has   "at the units question: says where" "Stopped by Ctrl-C (SIGINT) at a question for IAM_DB_ROLES; none of its steps ran."
has   "at the units question: no switch finished" "No switch was finished by this run."
hasnt "at the units question: no step" "STUB apps/database/deploy.sh"
sw_is "$S/config.env" IAM_DB_ROLES false
compgen -G "$S/config.env.guide-*.bak" >/dev/null && fail "a backup was made" || pass "config.env not touched"
lock_free && pass "the lock is free afterwards" || fail "the lock is still held"

echo "31 backups"
mkcfg false false
guide $'9\n1\ny\nb\n2\n\nb\n3\n../etc\n20261102-023000Z\n\nb\n4\n\n\nq\n'
rc_is "quits with 0" 0
has   "now (dry)" "[dry run] not executed: ./apps/backup/backups.sh now"
has   "now takes the lock" "Deploy lock: takes it"
has   "list (dry)" "[dry run] not executed: ./apps/backup/backups.sh list"
has   "a bad folder name is re-asked" "a folder name like 20261102-023000Z"
has   "verify with the folder (dry)" "[dry run] not executed: ./apps/backup/backups.sh verify 20261102-023000Z"
has   "restore-help for the newest (dry)" "[dry run] not executed: ./apps/backup/backups.sh restore-help"
has   "the restore is shown, not run" "Shown, not run"
hasnt "no folder smuggled in" "backups.sh verify ../etc"
no_stub

echo "32 deploy IAM 4.1 (policy versions schema)"
mkcfg false false
guide $'8\n8\ny\nq\n'
rc_is "quits with 0" 0
has   "the chain, in order" "[dry run] not executed: ./apps/access/deploy.sh && ./apps/database/deploy.sh && ./deploy-infra.sh"
has   "the 503 window is explained" "the User Manager answers 503"
has   "one lock for all three" "held by the guide for all three"
has   "a change ([y/N])" "Kind:        changes the platform"
no_stub
lock_free && pass "a dry run takes no lock" || fail "a dry run left the lock held"
real $'8\n8\ny\nq\n'
rc_is "real: quits with 0" 0
has   "real: access first" "STUB apps/access/deploy.sh"
has   "real: then the database" "STUB apps/database/deploy.sh"
has   "real: then deploy-infra" "STUB deploy-infra.sh"
python3 - "$OUT" <<'PY' && pass "real: access, database, infra in that order" || fail "real: wrong order"
import sys
o = sys.argv[1]
i = [o.index(x) for x in ("STUB apps/access/deploy.sh", "STUB apps/database/deploy.sh", "STUB deploy-infra.sh")]
sys.exit(0 if i == sorted(i) else 1)
PY
[[ "$(grep -c '^LOCK_PROBE=held$' <<<"$OUT")" == 3 && "$(grep -cE '^LOCK_HELD=[0-9]+$' <<<"$OUT")" == 3 ]] \
    && pass "real: each step runs under the guide's lock" || fail "real: a step ran without the guide's lock"
lock_free && pass "real: the lock is free afterwards" || fail "real: the lock is still held"
OUT="$(printf '8\n8\ny\nq\n' | NO_COLOR=1 STUB_RC=1 "$S/guide.sh" 2>&1)"
has   "a failure stops the chain" "STUB apps/access/deploy.sh"
hasnt "the database deploy did not run" "STUB apps/database/deploy.sh"
lock_free && pass "the lock is free after a failure" || fail "the lock is still held after a failure"
( exec 8>>"$S/.medcea.lock"; flock 8 && exec sleep 60 ) &
LOCKER=$!
for _ in $(seq 50); do lock_free || break; sleep 0.1; done
if lock_free; then
    fail "could not take the lock for the test"
else
    real $'8\n8\ny\nq\n'
    has   "refused while another deploy holds the lock" "another MedCEA deploy is running"
    hasnt "nothing ran" "STUB "
fi
kill "$LOCKER" 2>/dev/null; wait "$LOCKER" 2>/dev/null; LOCKER=""

echo "33 deploy IAM 4.2a (version 1 and the skeleton gate)"
mkcfg true true
guide $'8\n9\n-x\nsvieira\ny\nq\n'
rc_is "quits with 0" 0
has   "a --by starting with - is re-asked" "'-x': letters, digits and . _ @ -"
has   "the chain, in order, --by to the iam deploy" "[dry run] not executed: ./apps/database/deploy.sh && ./deploy-infra.sh && env MEDCEA_POLICY_BOOTSTRAP_BY=svieira ./apps/iam/deploy.sh"
has   "one lock for all three" "held by the guide for all three"
has   "a change ([y/N])" "Kind:        changes the platform"
has   "the order is explained" "Order: the database deploy first"
has   "no 503 window" "No 503 window"
has   "the bootstrap is explained" "bootstraps version 1 from apps/iam/policy/defaults.yaml, claimed by svieira"
has   "the two new checks" "Access policy version and Policy artefacts (54 checks)"
has   "the clean tree" "git status -- apps/iam must be clean"
no_stub
lock_free && pass "a dry run takes no lock" || fail "a dry run left the lock held"
real $'8\n9\nsvieira\ny\nq\n'
rc_is "real: quits with 0" 0
python3 - "$OUT" <<'PY2' && pass "real: database, infra, iam in that order" || fail "real: wrong order"
import sys
o = sys.argv[1]
i = [o.index(x) for x in ("STUB apps/database/deploy.sh", "STUB deploy-infra.sh", "STUB apps/iam/deploy.sh")]
sys.exit(0 if i == sorted(i) else 1)
PY2
grep -q '^ENV_BY=svieira ENV_CONFIRMED=$' <<<"$OUT" && pass "real: the iam deploy gets MEDCEA_POLICY_BOOTSTRAP_BY" \
    || fail "real: MEDCEA_POLICY_BOOTSTRAP_BY not passed"
[[ "$(grep -c '^LOCK_PROBE=held$' <<<"$OUT")" == 3 && "$(grep -cE '^LOCK_HELD=[0-9]+$' <<<"$OUT")" == 3 ]] \
    && pass "real: each step runs under the guide's lock" || fail "real: a step ran without the guide's lock"
lock_free && pass "real: the lock is free afterwards" || fail "real: the lock is still held"
OUT="$(printf '8\n9\nsvieira\ny\nq\n' | NO_COLOR=1 STUB_RC=1 "$S/guide.sh" 2>&1)"
has   "a failure stops the chain" "STUB apps/database/deploy.sh"
hasnt "deploy-infra did not run" "STUB deploy-infra.sh"
hasnt "the iam deploy did not run" "STUB apps/iam/deploy.sh"

echo "34 bootstrap version 1 by hand needs the typed yes"
mkcfg true true
guide $'8\n12\n--bootstrap\nsvieira\ny\nb\n12\n\nyes\nq\n'
rc_is "quits with 0" 0
has   "--bootstrap as --by is re-asked" "'--bootstrap': letters, digits and . _ @ -"
has   "destructive" "This is destructive."
has   "y is not yes" "Cancelled; nothing was run."
has   "--by remembered" "Your Keycloak username (--by) [svieira]:"
has   "yes runs (dry), confirmed for apply.sh" "[dry run] not executed: env MEDCEA_CONFIRMED=1 ./apps/iam/apply.sh --bootstrap --by svieira"
has   "a permanent record" "a PERMANENT record claimed by svieira"
[[ "$(grep -c 'not executed: env MEDCEA_CONFIRMED=1 ./apps/iam/apply.sh --bootstrap' <<<"$OUT")" == 1 ]] \
    && pass "the cancelled one never ran" || fail "the cancelled one ran"
no_stub
real $'8\n12\nsvieira\nyes\nq\n'
has   "real: apply.sh ran" "STUB apps/iam/apply.sh --bootstrap --by svieira"
grep -q '^ENV_BY= ENV_CONFIRMED=1$' <<<"$OUT" && pass "real: MEDCEA_CONFIRMED=1 reaches apply.sh" || fail "real: MEDCEA_CONFIRMED not passed"
grep -q '^LOCK_HELD=$' <<<"$OUT" && pass "real: apply.sh takes its own lock (none inherited)" || fail "real: the guide held the lock"

echo "35 status and export are read-only; check-only and resume"
mkcfg true true
guide $'8\n10\n\nb\n14\n\nb\n11\nsvieira\n\nb\n13\n\ny\nq\n'
rc_is "quits with 0" 0
has   "status (dry)" "[dry run] not executed: ./apps/iam/apply.sh --status"
has   "export (dry)" "[dry run] not executed: python3 apps/iam/compiler/cli.py export-applied"
has   "check-only (dry)" "[dry run] not executed: ./apps/iam/apply.sh --bootstrap --check-only --by svieira"
has   "resume (dry)" "[dry run] not executed: env MEDCEA_CONFIRMED=1 ./apps/iam/apply.sh --resume --by svieira"
[[ "$(grep -c 'Kind:        read-only' <<<"$OUT")" == 3 ]] && pass "status, export, check-only: read-only" || fail "not read-only"
[[ "$(grep -c 'Run it? \[Y/n\]' <<<"$OUT")" == 3 ]] && pass "three [Y/n]" || fail "not [Y/n]"
has   "resume asks [y/N]" "Run it? [y/N]"
has   "export never writes" "the guide never writes the file"
no_stub
real $'8\n10\n\nq\n'
has   "real: status ran" "STUB apps/iam/apply.sh --status"
grep -q '^LOCK_HELD=$' <<<"$OUT" && grep -q '^LOCK_PROBE=free$' <<<"$OUT" \
    && pass "real: status runs without the lock" || fail "real: status ran under a lock"

echo "36 policy break-glass is shown, never run"
mkcfg true true
guide $'8\n15\nq\n'
rc_is "quits with 0" 0
has   "the variables" "MEDCEA_POLICY_FILE=<file.yaml> MEDCEA_POLICY_BREAK_GLASS="
has   "typed at the terminal" "type the word break-glass at the terminal"
has   "never bypasses the gate" "It does NOT bypass the skeleton gate"
has   "only the matrix and the waivers" "It changes only the matrix and the waivers"
has   "how it ends" "./deploy-infra.sh and ./deploy-apps.sh --all end it everywhere"
hasnt "no command to run" "Run it?"
hasnt "nothing planned" "not executed"
no_stub
real $'8\n15\nq\n'
hasnt "real: nothing ran" "STUB "

echo "10 the real config.env"
[[ "$(sum_real)" == "$REAL_BEFORE" ]] && pass "unchanged" || fail "the repository's config.env changed"

echo
if (( FAILS )); then echo -e "${RED}$FAILS failure(s)${NC}"; exit 1; fi
echo -e "${GREEN}All passed${NC}"
