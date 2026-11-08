#!/usr/bin/env bash
# apps/superset/lib-superset.sh — what apps/superset/deploy.sh, health-check.sh
# (supersetroles) and deploy-infra.sh (the wheel cache's folder) share, so the deploy and
# the check compute the same things the same way (Superset stage C). Sourced; defines functions only, takes no lock. Needs $KUBECTL
# (a caller may prefix it, e.g. KUBECTL="timeout 10 $KUBECTL").
#
#   superset_config_checksum NS
#       sha256 of what Superset's pods read at start only: the data of Secret
#       superset-secrets and of ConfigMap superset-config, as they are in the cluster
#       now. deploy.sh writes it into the pod template (medcea/config-checksum) right
#       after it applied both; health compares a running pod's annotation with it, so a
#       Secret or ConfigMap changed behind the pod's back (a role mapping it does not
#       run yet: the mapping is a secretKeyRef env, read at start only) is a FAIL. Both
#       objects reach python on stdin; it prints the digest only, never a value.
#       Returns 1 and prints nothing when either is missing or unreadable.
#   superset_web_pods NS
#       one line "<pod> <medcea/config-checksum or ->" per running Superset web pod
#       (phase Running, not being deleted); nothing when none runs. Returns 1 when the
#       pods cannot be read. Health and deploy.sh --gate-only compare it with
#       superset_config_checksum: the pods are current only when every one matches.
#   superset_wheel_dir
#       SUPERSET_WHEEL_DIR (config.env; default /var/lib/$PROJECT_NAME/superset-wheels),
#       validated as BACKUP_DIR is; returns 1 with a message on stderr otherwise.
#   superset_wheel_dir_ok
#       superset_wheel_dir, never inside or around the volumes' directory (StorageClass
#       microk8s-hostpath's pvDir, read through $KUBECTL; the nightly backup copies that,
#       and a PVC is no place for host state). Sets SUPERSET_WHEEL_DIR; returns 1 with
#       WHEELS_WHY set otherwise. deploy.sh checks the cache with it, and deploy-infra.sh
#       before it creates the folder, so deploy-infra never makes one the deploy refuses.
#   superset_wheel_owner_ok
#       SUPERSET_WHEEL_UID/SUPERSET_WHEEL_GID: the owner of SUPERSET_WHEEL_DIR, the uid/gid
#       the init containers read it as; returns 1 with WHEELS_WHY set when it cannot be
#       read or is root (they never run as root).
#   superset_wheels_missing DIR REQUIREMENTS
#       prints, one per line, each requirement whose pinned sha256 no *.whl in DIR has
#       (nothing when the cache is complete); returns 1 when DIR cannot be read.
#
# The wheel cache (owner decision N10, 7 Nov 2026): the init containers install the
# three hash-pinned wheels of requirements.txt from DIR (a hostPath, read-only, never
# PyPI), so a pod start — a restart by apply.sh's rollout, a node reboot, an eviction —
# needs no internet. Only the full deploy fills it (Job superset-wheels, pip download
# --require-hashes from PyPI); --gate-only refuses while it is incomplete.

superset_config_checksum() {
    local ns="$1"
    { $KUBECTL get secret superset-secrets -n "$ns" -o json 2>/dev/null || echo null
      echo
      $KUBECTL get configmap superset-config -n "$ns" -o json 2>/dev/null || echo null; } \
        | python3 -c '
import base64, hashlib, json, sys
text, dec, objs, i = sys.stdin.read(), json.JSONDecoder(), [], 0
try:
    while len(objs) < 2:
        while i < len(text) and text[i].isspace():
            i += 1
        o, i = dec.raw_decode(text, i)
        objs.append(o)
    sec, cm = objs
    if not sec or not cm or sec.get("kind") != "Secret" or cm.get("kind") != "ConfigMap":
        sys.exit(1)
    doc = {
        "secret": {k: base64.b64decode(v).decode() for k, v in (sec.get("data") or {}).items()},
        "configmap": dict(cm.get("data") or {},
                          **{k: base64.b64decode(v).decode("latin-1") for k, v in (cm.get("binaryData") or {}).items()}),
    }
except Exception:
    sys.exit(1)
blob = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
print(hashlib.sha256(blob).hexdigest())'
}

superset_web_pods() {
    local ns="$1" json
    json="$($KUBECTL get pod -n "$ns" -l app=superset,component=web -o json 2>/dev/null)" || return 1
    printf '%s' "$json" | python3 -c '
import json, sys
try:
    items = json.load(sys.stdin)["items"]
except Exception:
    sys.exit(1)
for p in items:
    if p.get("status", {}).get("phase") == "Running" and not p["metadata"].get("deletionTimestamp"):
        print(p["metadata"]["name"], (p["metadata"].get("annotations") or {}).get("medcea/config-checksum") or "-")
'
}

superset_wheel_dir() {
    local d="${SUPERSET_WHEEL_DIR:-}"
    [[ -n "$d" ]] || d="/var/lib/${PROJECT_NAME:-medcea}/superset-wheels"
    if [[ ! "$d" =~ ^/[A-Za-z0-9._/-]+$ || "$d" == */../* || "$d" == */.. || "$d" == */./* ]]; then
        echo "SUPERSET_WHEEL_DIR='$d' must be an absolute path of letters, digits and . _ - / (config.env)." >&2
        return 1
    fi
    d="${d%/}"
    [[ -n "$d" ]] || { echo "SUPERSET_WHEEL_DIR must not be /." >&2; return 1; }
    echo "$d"
}

superset_wheel_dir_ok() {
    local storage d
    if ! d="$(superset_wheel_dir 2>/dev/null)"; then
        WHEELS_WHY="$(superset_wheel_dir 2>&1 >/dev/null)"; return 1
    fi
    SUPERSET_WHEEL_DIR="$d"
    storage="$($KUBECTL get storageclass microk8s-hostpath -o jsonpath='{.parameters.pvDir}' 2>/dev/null || true)"
    storage="${storage:-/var/snap/microk8s/common/default-storage}"
    case "$SUPERSET_WHEEL_DIR/" in
        "$storage"/*) WHEELS_WHY="SUPERSET_WHEEL_DIR=$SUPERSET_WHEEL_DIR is inside the volumes' directory $storage: choose another folder (config.env)."; return 1 ;;
    esac
    case "$storage/" in
        "$SUPERSET_WHEEL_DIR"/*) WHEELS_WHY="SUPERSET_WHEEL_DIR=$SUPERSET_WHEEL_DIR contains the volumes' directory $storage: choose another folder (config.env)."; return 1 ;;
    esac
}

superset_wheel_owner_ok() {
    if ! { SUPERSET_WHEEL_UID="$(stat -L -c %u "$SUPERSET_WHEEL_DIR" 2>/dev/null)" \
           && SUPERSET_WHEEL_GID="$(stat -L -c %g "$SUPERSET_WHEEL_DIR" 2>/dev/null)"; }; then
        WHEELS_WHY="cannot read the owner of $SUPERSET_WHEEL_DIR"; return 1
    fi
    if [[ "$SUPERSET_WHEEL_UID" == 0 ]]; then
        WHEELS_WHY="$SUPERSET_WHEEL_DIR belongs to root: the init containers run as its owner, never root. Make it the deploying account's (sudo chown \$(id -un): $SUPERSET_WHEEL_DIR), then re-run."
        return 1
    fi
}

superset_wheels_missing() {
    local dir="$1" req="$2"
    [[ -d "$dir" && -r "$dir" && -x "$dir" ]] || return 1
    python3 - "$dir" "$req" <<'PY'
import hashlib, os, re, sys
d, req = sys.argv[1], sys.argv[2]
have = set()
for n in os.listdir(d):
    p = os.path.join(d, n)
    if n.endswith(".whl") and os.path.isfile(p):
        with open(p, "rb") as f:
            have.add(hashlib.sha256(f.read()).hexdigest())
for line in open(req):
    line = line.split("#", 1)[0].strip()
    m = re.match(r"([A-Za-z0-9_.-]+==[^ ]+).*--hash=sha256:([0-9a-f]{64})", line)
    if m and m.group(2) not in have:
        print(m.group(1))
PY
}
