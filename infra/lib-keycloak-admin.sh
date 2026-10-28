#!/usr/bin/env bash
# infra/lib-keycloak-admin.sh — who the deploy scripts are when they call
# Keycloak's admin API, and the master-realm identities behind that.
#
#   kc_admin_select       pick the identity once Keycloak answers; returns 1 if none works
#   kc_admin_token        a master-realm admin token for that identity (reused ~45 s)
#   kc_ensure_master_identities
#                         create the break-glass account and the deployer client,
#                         turn on master-realm events, disable the legacy admin once
#   kc_enable_events REALM
#   kc_password_status REALM USER   ok | changed | temporary | missing — from the
#                         admin API, without signing in as the person
#
# Three master-realm identities, tried in this order:
#   1. client medcea-deployer (client credentials, KC_DEPLOYER_SECRET) — what the
#      scripts normally are, so automated changes show in Keycloak's admin events
#      as the deploy script, never as a person;
#   2. KC_BREAKGLASS_USER / KC_BREAKGLASS_PASS — the console account, for
#      recovery and for creating the deployer client the first time;
#   3. ADMIN_USER / ADMIN_PASS — the bootstrap admin of installs made before the
#      split, used to migrate and then disabled (once; never deleted).
# Nothing here signs in as a person or as the break-glass account except when
# no other identity works or the migration needs to prove it can: a login event
# for kc-breakglass should mean someone used break-glass.
# The platform's own `admin` in realm $KEYCLOAK_REALM is a different account and
# is never touched here.
#
# Needs KC_URL (default http://localhost:18080, the deploy's port-forward) and
# the variables above from config.env. Nothing here prints a secret.

KC_URL="${KC_URL:-http://localhost:18080}"
KC_DEPLOYER_CLIENT="medcea-deployer"
KC_ADMIN_MODE=""
# One token per ~45 s instead of one per call: each token is a login event in
# the master realm, and a deploy makes a few hundred admin calls. The cache is a
# private file (removed by kc_admin_done) because callers use $(_kc_token).
KC_TOKEN_CACHE=""

_kc_master_token() {   # grant-args... → token or empty
    curl -sf -X POST "$KC_URL/realms/master/protocol/openid-connect/token" "$@" \
      | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null || true
}

_kc_token_as() {
    case "$1" in
        deployer)   _kc_master_token -d grant_type=client_credentials \
                        --data-urlencode "client_id=$KC_DEPLOYER_CLIENT" --data-urlencode "client_secret=${KC_DEPLOYER_SECRET:-}" ;;
        breakglass) _kc_master_token -d grant_type=password -d client_id=admin-cli \
                        --data-urlencode "username=${KC_BREAKGLASS_USER:-}" --data-urlencode "password=${KC_BREAKGLASS_PASS:-}" ;;
        legacy)     _kc_master_token -d grant_type=password -d client_id=admin-cli \
                        --data-urlencode "username=${ADMIN_USER:-}" --data-urlencode "password=${ADMIN_PASS:-}" ;;
    esac
}

# Does this token carry master-realm admin authority (not merely sign-in)?
_kc_is_admin() {
    [[ -n "$1" ]] && curl -sf -o /dev/null "$KC_URL/admin/realms/master/users?max=1" -H "Authorization: Bearer $1"
}

kc_admin_select() {
    local m t
    for m in deployer breakglass legacy; do
        [[ "$m" == deployer && -z "${KC_DEPLOYER_SECRET:-}" ]] && continue
        [[ "$m" == breakglass && -z "${KC_BREAKGLASS_PASS:-}" ]] && continue
        t="$(_kc_token_as "$m")"
        if _kc_is_admin "$t"; then
            KC_ADMIN_MODE="$m"
            KC_TOKEN_CACHE="$(mktemp)"; chmod 600 "$KC_TOKEN_CACHE"
            printf '%s' "$t" > "$KC_TOKEN_CACHE"
            return 0
        fi
    done
    return 1
}

kc_admin_token() {
    if [[ -n "$KC_TOKEN_CACHE" && -s "$KC_TOKEN_CACHE" ]] \
       && (( $(date +%s) - $(stat -c %Y "$KC_TOKEN_CACHE") < 45 )); then
        cat "$KC_TOKEN_CACHE"
        return 0
    fi
    local t; t="$(_kc_token_as "${KC_ADMIN_MODE:-legacy}")"
    [[ -n "$KC_TOKEN_CACHE" && -n "$t" ]] && printf '%s' "$t" > "$KC_TOKEN_CACHE"
    printf '%s' "$t"
}

# Switch identity (after the deployer exists) and drop the cached token.
_kc_use() { KC_ADMIN_MODE="$1"; [[ -n "$KC_TOKEN_CACHE" ]] && : > "$KC_TOKEN_CACHE"; }

kc_admin_done() { [[ -n "$KC_TOKEN_CACHE" ]] && rm -f "$KC_TOKEN_CACHE"; KC_TOKEN_CACHE=""; }

# GET/send helpers. _kc_get takes a full admin path (realms/<r>/...).
_kc_get() { curl -sf "$KC_URL/admin/$1" -H "Authorization: Bearer $(kc_admin_token)"; }
_kc_send() {   # METHOD PATH [JSON] → HTTP code
    curl -s -o /dev/null -w '%{http_code}' -X "$1" "$KC_URL/admin/$2" \
      -H "Authorization: Bearer $(kc_admin_token)" -H "Content-Type: application/json" ${3:+-d "$3"}
}
_kc_user_id() {   # REALM USER
    _kc_get "realms/$1/users?username=$2&exact=true" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else '')" 2>/dev/null || true
}
_kc_grant_master_admin() {   # USER_ID → 0 only if the mapping is in place
    local role code
    role="$(_kc_get "realms/master/roles/admin")" || return 1
    code="$(_kc_send POST "realms/master/users/$1/role-mappings/realm" "[$role]")"
    [[ "$code" == 204 ]] || return 1
}

# Save a value to config.env at once (upsert), so a later failure in the run
# cannot lose a credential Keycloak already holds.
_kc_save() {   # KEY VALUE
    [[ -f config.env ]] || return 0
    if grep -q "^$1=" config.env; then
        sed -i "s|^$1=.*|$1=\"$2\"|" config.env
    else
        printf '%s="%s"\n' "$1" "$2" >> config.env
    fi
}

kc_ensure_master_identities() {
    local id body code uuid sa secret created=0 legacy_id

    # 1. Break-glass console account. Its password lives only in config.env and
    #    the credentials file; an existing account's password is never reset here.
    id="$(_kc_user_id master "$KC_BREAKGLASS_USER")"
    if [[ -z "$id" ]]; then
        body="$(U="$KC_BREAKGLASS_USER" P="$KC_BREAKGLASS_PASS" E="${KC_BREAKGLASS_USER}@${PROJECT_NAME:-medcea}.invalid" python3 -c '
import json, os
print(json.dumps({"username": os.environ["U"], "enabled": True, "emailVerified": True,
    "email": os.environ["E"], "firstName": "Break-glass", "lastName": "Keycloak",
    "credentials": [{"type": "password", "value": os.environ["P"], "temporary": False}]}))')"
        code="$(_kc_send POST realms/master/users "$body")"
        [[ "$code" == 201 ]] || { echo "  ERROR: could not create break-glass account '$KC_BREAKGLASS_USER' (HTTP $code)" >&2; return 1; }
        id="$(_kc_user_id master "$KC_BREAKGLASS_USER")"
        created=1
        echo "  Created break-glass console account '$KC_BREAKGLASS_USER'."
    fi
    _kc_grant_master_admin "$id" || { echo "  ERROR: could not grant master admin to '$KC_BREAKGLASS_USER'" >&2; return 1; }
    # A fresh install bootstraps this account from KC_BOOTSTRAP_ADMIN_*, which
    # Keycloak 26 marks as a temporary admin (and the console then urges its
    # deletion). It is the permanent break-glass identity: drop the mark.
    body="$(_kc_get "realms/master/users/$id" | python3 -c '
import json, sys
u = json.load(sys.stdin)
a = u.get("attributes") or {}
if "is_temporary_admin" not in a:
    sys.exit(0)
a.pop("is_temporary_admin"); u["attributes"] = a
print(json.dumps(u))' 2>/dev/null || true)"
    [[ -n "$body" ]] && _kc_send PUT "realms/master/users/$id" "$body" >/dev/null

    # 2. Deployer client: client credentials only, no browser login, no password.
    _kc_send POST realms/master/clients "{\"clientId\":\"$KC_DEPLOYER_CLIENT\",\"enabled\":true,\"publicClient\":false,
        \"standardFlowEnabled\":false,\"directAccessGrantsEnabled\":false,\"implicitFlowEnabled\":false,
        \"serviceAccountsEnabled\":true,\"description\":\"The MedCEA deploy scripts (infra/lib-keycloak-admin.sh)\"}" >/dev/null
    uuid="$(_kc_get "realms/master/clients?clientId=$KC_DEPLOYER_CLIENT" | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null || true)"
    [[ -n "$uuid" ]] || { echo "  ERROR: could not create client '$KC_DEPLOYER_CLIENT'" >&2; return 1; }
    sa="$(_kc_get "realms/master/clients/$uuid/service-account-user" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || true)"
    { [[ -n "$sa" ]] && _kc_grant_master_admin "$sa"; } || { echo "  ERROR: could not grant master admin to '$KC_DEPLOYER_CLIENT'" >&2; return 1; }
    secret="$(_kc_get "realms/master/clients/$uuid/client-secret" | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])" 2>/dev/null || true)"
    [[ -n "$secret" ]] || { echo "  ERROR: no secret for '$KC_DEPLOYER_CLIENT'" >&2; return 1; }
    KC_DEPLOYER_SECRET="$secret"
    _kc_is_admin "$(_kc_token_as deployer)" || { echo "  ERROR: '$KC_DEPLOYER_CLIENT' has no admin authority" >&2; return 1; }
    _kc_save KC_DEPLOYER_SECRET "$secret"
    _kc_use deployer

    # 3. Master-realm events: every console or API change is recorded.
    kc_enable_events master

    # 4. The legacy bootstrap admin (same name as the platform admin) is disabled
    #    once, never deleted, so its past events still resolve to an account.
    #    Only after both new identities are proven to hold admin authority, so
    #    nobody is ever locked out; break-glass is signed in as only here, while
    #    the migration is still pending. A deliberate re-enable later (recovery)
    #    is left alone: the deployer client carries the "done" mark.
    [[ "${ADMIN_USER:-}" == "$KC_BREAKGLASS_USER" ]] && return 0
    if _kc_get "realms/master/clients/$uuid" | python3 -c '
import json, sys
sys.exit(0 if (json.load(sys.stdin).get("attributes") or {}).get("medcea.legacy-admin-disabled") == "true" else 1)' 2>/dev/null; then
        legacy_id="$(_kc_user_id master "$ADMIN_USER")"
        if [[ -n "$legacy_id" ]] && _kc_get "realms/master/users/$legacy_id" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("enabled") else 1)' 2>/dev/null; then
            echo "  NOTE: the legacy master-realm account '$ADMIN_USER' is enabled again (recovery?). Left as is." >&2
        fi
        return 0
    fi
    if ! _kc_is_admin "$(_kc_token_as breakglass)"; then
        echo "  WARNING: '$KC_BREAKGLASS_USER' cannot act as admin with KC_BREAKGLASS_PASS;" >&2
        echo "           the legacy admin is left enabled. Fix the account in the console, then re-run." >&2
        return 1
    fi
    legacy_id="$(_kc_user_id master "$ADMIN_USER")"
    if [[ -n "$legacy_id" ]]; then
        body="$(_kc_get "realms/master/users/$legacy_id" | python3 -c '
import json, sys
u = json.load(sys.stdin)
if not u.get("enabled"):
    sys.exit(0)
u["enabled"] = False
print(json.dumps(u))' 2>/dev/null || true)"
        if [[ -n "$body" ]]; then
            code="$(_kc_send PUT "realms/master/users/$legacy_id" "$body")"
            if [[ "$code" != 204 ]]; then
                echo "  WARNING: could not disable the legacy master-realm account '$ADMIN_USER' (HTTP $code)." >&2
                return 1
            fi
            echo "  Disabled the legacy master-realm account '$ADMIN_USER' (the console now uses '$KC_BREAKGLASS_USER')."
        fi
    fi
    body="$(_kc_get "realms/master/clients/$uuid" | python3 -c '
import json, sys
c = json.load(sys.stdin)
c.setdefault("attributes", {})["medcea.legacy-admin-disabled"] = "true"
print(json.dumps(c))' 2>/dev/null || true)"
    [[ -n "$body" ]] && _kc_send PUT "realms/master/clients/$uuid" "$body" >/dev/null
    return 0
}

# kc_enable_events REALM — login and admin events on, read-modify-write. Never
# fails the deploy: events matter, but not more than finishing the run.
kc_enable_events() {
    local cfg code
    cfg="$(_kc_get "realms/$1/events/config" | python3 -c '
import json, sys
c = json.load(sys.stdin)
c.update(eventsEnabled=True, adminEventsEnabled=True, adminEventsDetailsEnabled=True)
c["eventsListeners"] = sorted(set(c.get("eventsListeners") or []) | {"jboss-logging"})
print(json.dumps(c))' 2>/dev/null || true)"
    if [[ -z "$cfg" ]]; then
        echo "  WARNING: could not read the event settings of realm '$1'; events unchanged." >&2
        return 0
    fi
    code="$(_kc_send PUT "realms/$1/events/config" "$cfg")"
    [[ "$code" == 204 ]] || echo "  WARNING: could not turn on events in realm '$1' (HTTP $code)." >&2
    return 0
}

# kc_password_status REALM USER — whether the password config.env holds for an
# account is still the one it was created with, read from the admin API (the
# password credential's date against the account's), so nobody's record gets
# a login they did not make. ok | changed | temporary | missing
kc_password_status() {
    local id
    id="$(_kc_user_id "$1" "$2")"
    [[ -n "$id" ]] || { echo missing; return 0; }
    U="$(_kc_get "realms/$1/users/$id")" C="$(_kc_get "realms/$1/users/$id/credentials")" python3 -c '
import json, os
u = json.loads(os.environ["U"] or "{}")
creds = [c for c in json.loads(os.environ["C"] or "[]") if c.get("type") == "password"]
if not creds:
    print("missing")
elif "UPDATE_PASSWORD" in (u.get("requiredActions") or []):
    print("temporary")
elif creds[0].get("createdDate", 0) - u.get("createdTimestamp", 0) > 60000:
    print("changed")   # set more than a minute after the account was made
else:
    print("ok")' 2>/dev/null || echo missing
}
