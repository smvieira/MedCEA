# tests/lib-hub-cleanup.sh — remove the live tests' throwaway users from the AI workbench's
# hub (sourced by tests/iam-workbench.sh and tests/iam-signin.sh, both under the deploy lock).
#
# A hub administrator cannot delete its own hub user (JupyterHub: "Cannot delete
# yourself!"), and any second administrator that removes it becomes the next leftover, so
# a test's throwaway admin stayed in the hub and health "Workbench accounts" WARNed after
# every run. Owner decision of 20 Nov 2026: the test removes it through the hub's own
# database and restarts the hub.
#
#   hub_sweep_test_users WB_NS REALM
#
# A hub user is removed only when all of these hold:
#   - its name is a live test's throwaway name, ^test-[a-z][a-z_-]*-[0-9a-f]{6}$ (iam-workbench.sh,
#     iam-signin.sh); any other hub user is never touched;
#   - Keycloak answers, for that exact username in REALM, that no account exists (an error
#     or any account keeps it: the caller deletes its accounts first);
#   - it has no server (a spawner with a server is a running workspace).
# Earlier runs' leftovers that fit are removed too. The read is sqlite opened mode=ro (as
# health wbaccounts); the delete is what the hub's DELETE /hub/api/users/<name> does
# (jupyterhub.orm: the user row, its spawners, tokens and group and role links by the ORM's
# cascades; the home volume is never touched: KubeSpawner's delete_pvc is false and no
# spawner is called), in the hub container, one transaction, each user checked again.
# Then, only when a user was removed, `rollout restart deployment/hub` (strategy Recreate)
# and its rollout status: the running hub caches users, the new one reads the database.
# The hub pauses for about a minute; running workspaces keep running.
# Never fails its caller (a cleanup step): it prints what it did or could not do.
# Needs $KUBECTL and _kc_get (infra/lib-keycloak-admin.sh, a selected admin mode).

HUB_TEST_USER_RE='^test-[a-z][a-z_-]*-[0-9a-f]{6}$'

# The candidates, one "name|running" line each (running 1 or 0), then "end|".
HUB_LIST_PY='
import re, sqlite3
db = sqlite3.connect("file:/srv/jupyterhub/jupyterhub.sqlite?mode=ro", uri=True)
pat = re.compile(r"^test-[a-z][a-z_-]*-[0-9a-f]{6}$")
for name, running in db.execute(
        "SELECT u.name, EXISTS (SELECT 1 FROM spawners s WHERE s.user_id = u.id"
        " AND s.server_id IS NOT NULL) FROM users u ORDER BY u.name"):
    if name and pat.match(name):
        print("%s|%d" % (name, running))
print("end|")'

# Deletes the names in argv as the hub does; prints "deleted|N", "running|N", "absent|N".
HUB_DELETE_PY='
import re, sys
from jupyterhub import orm
pat = re.compile(r"^test-[a-z][a-z_-]*-[0-9a-f]{6}$")
db = orm.new_session_factory("sqlite:////srv/jupyterhub/jupyterhub.sqlite")()
out = []
for name in sys.argv[1:]:
    if not pat.match(name):
        continue
    u = orm.User.find(db, name)
    if u is None:
        out.append("absent|" + name)
    elif any(sp.server is not None for sp in u._orm_spawners):
        out.append("running|" + name)
    else:
        db.delete(u)
        out.append("deleted|" + name)
db.commit()
print("\n".join(out))
print("end|")'

hub_sweep_test_users() {
    local ns="$1" realm="$2" pod out rc=0 line name running kc gone=() kept=() deleted=()
    pod="$($KUBECTL get pods -n "$ns" -l app=jupyterhub,component=hub --field-selector=status.phase=Running \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    if [[ -z "$pod" ]]; then
        echo "Hub cleanup: no running hub in $ns, nothing to remove."
        return 0
    fi
    out="$($KUBECTL exec -n "$ns" "$pod" -c hub -- python3 -c "$HUB_LIST_PY" 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]] || ! grep -q '^end|$' <<<"$out"; then
        echo -e "${RED:-}  Hub cleanup: cannot read the hub's users in $ns/$pod: $(grep -v '|' <<<"$out" | tail -n1 | cut -c1-120)${NC:-}" >&2
        return 0
    fi
    while IFS='|' read -r name running; do
        [[ "$name" =~ $HUB_TEST_USER_RE ]] || continue
        if [[ "$running" == 1 ]]; then
            kept+=("$name (a workspace is running)"); continue
        fi
        if ! kc="$(_kc_get "realms/$realm/users?username=$name&exact=true")"; then
            kept+=("$name (Keycloak did not answer)"); continue
        fi
        if [[ "$(tr -d '[:space:]' <<<"$kc")" == "[]" ]]; then
            gone+=("$name")
        else
            kept+=("$name (still an account in realm $realm)")
        fi
    done < <(grep -v '^end|$' <<<"$out")
    if [[ ${#kept[@]} -gt 0 ]]; then
        printf '  Hub cleanup: kept %s\n' "${kept[@]}"
    fi
    if [[ ${#gone[@]} -eq 0 ]]; then
        echo "Hub cleanup: no throwaway test user left in the hub."
        return 0
    fi
    rc=0
    out="$($KUBECTL exec -n "$ns" "$pod" -c hub -- python3 -c "$HUB_DELETE_PY" "${gone[@]}" 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]] || ! grep -q '^end|$' <<<"$out"; then
        echo -e "${RED:-}  Hub cleanup: could not remove ${gone[*]} from the hub: $(grep -v '|' <<<"$out" | tail -n1 | cut -c1-160) — remove them on the hub's admin page${NC:-}" >&2
        return 0
    fi
    mapfile -t deleted < <(sed -n 's/^deleted|//p' <<<"$out")
    while IFS= read -r line; do
        echo "  Hub cleanup: kept ${line#running|} (a workspace started meanwhile)"
    done < <(grep '^running|' <<<"$out")
    if [[ ${#deleted[@]} -eq 0 ]]; then
        echo "Hub cleanup: nothing removed."
        return 0
    fi
    echo "Hub cleanup: removed ${deleted[*]} from the hub's database; restarting the hub (running workspaces keep running)..."
    if $KUBECTL rollout restart deployment/hub -n "$ns" >/dev/null \
            && $KUBECTL rollout status deployment/hub -n "$ns" --timeout=5m >/dev/null; then
        echo "Hub cleanup: the hub is back."
    else
        echo -e "${RED:-}  Hub cleanup: the hub did not come back by itself: microk8s kubectl -n $ns rollout status deployment/hub${NC:-}" >&2
    fi
    return 0
}
