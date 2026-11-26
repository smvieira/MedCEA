#!/usr/bin/env bash
# infra/lib-workbench.sh — where the AI workbench's Helm release lives, and what moving it
# between the platform namespace and the research zone needs (research sandbox Phase 2b).
# Functions only: sourcing it runs nothing. Sourced by infra/deploy-workbench.sh.
#
#   workbench_release_ns     the namespace holding Helm release `workbench` (one line), nothing
#                            when there is none; return 3 (printing both, space-separated) when
#                            two namespaces hold one; 1 when helm cannot be asked
#   workbench_tls_issue NS   issue $CA_DIR/workbench.{key,crt} from the platform CA (SAN
#                            WORKBENCH_DOMAIN only, prime256v1, 825 days, as deploy-infra issues
#                            mosquitto-tls) and apply Secret workbench-tls (type tls) in NS; the
#                            key mode 600. Never a copy of cea-tls, whose SANs name every host.
#   workbench_zone_ready RNS 0 when namespace RNS exists, the zone's NetworkPolicies are the
#                            compiled ones (_pa_rsnetpol_equal) and the compile holds rs-hub,
#                            rs-workbench-proxy and rs-notebooks; else 1 and the reason on stderr
#   workbench_pv_dir         microk8s-hostpath's PV directory (StorageClass parameters.pvDir, else
#                            the snap's default-storage)
#   workbench_home_plan …    the move's plan for the homes (one line per claim; below)
#   workbench_home_manifests …  the PV and PVC of one copied home, as JSON (below)
#   workbench_rebind_manifest DST CLAIM PV PVS
#                            the PVC that binds CLAIM in DST to the kept PV, as JSON (below)
#   workbench_unmoved_homes SRC DST ADMIN
#                            the homes of SRC a move to DST has not taken (a fresh install
#                            into DST refuses while there are any)
#   workbench_rebind_released NS
#                            a fresh install into NS: the one Released PV labelled
#                            medcea/workbench-home whose claimRef names NS (per claim, its
#                            directory still there) loses its claimRef uid, so the person's
#                            next claim-<name> binds to it again
#
# Needs KUBECTL (and HELM or MK8S for workbench_release_ns), REPO_ROOT, NAMESPACE.
# Nothing here prints a secret; nothing here deletes a directory on disk (sudo is used only
# for `test -d`).

workbench_release_ns() {
    local out rc=0
    out="$(${HELM:-${MK8S:-microk8s} helm3} list -A -f '^workbench$' -o json 2>/dev/null </dev/null)" || return 1
    out="$(python3 -c '
import json, sys
text = sys.stdin.read().strip()
try:
    rows = json.loads(text) if text else []
except ValueError:
    sys.exit(1)
ns = sorted({r.get("namespace", "") for r in rows or [] if isinstance(r, dict) and r.get("name") == "workbench"} - {""})
print(" ".join(ns))
sys.exit(3 if len(ns) > 1 else 0)' <<<"$out")" || rc=$?
    case "$rc" in
        0) [[ -n "$out" ]] && echo "$out"; return 0 ;;
        3) echo "$out"; return 3 ;;
        *) return 1 ;;
    esac
}

workbench_tls_issue() {
    local ns="$1" ca="${CA_DIR:-$REPO_ROOT/.ca}"
    : "${WORKBENCH_DOMAIN:?}"
    [[ -f "$ca/ca.key" && -f "$ca/ca.crt" ]] \
        || { echo "workbench_tls_issue: no platform CA in $ca (./deploy-infra.sh creates it)" >&2; return 1; }
    ( umask 077 && openssl ecparam -name prime256v1 -genkey -noout -out "$ca/workbench.key" ) || return 1
    openssl req -new -key "$ca/workbench.key" -subj "/CN=${WORKBENCH_DOMAIN}" -out "$ca/workbench.csr" || return 1
    openssl x509 -req -in "$ca/workbench.csr" -CA "$ca/ca.crt" -CAkey "$ca/ca.key" \
      -CAcreateserial -days 825 -sha256 -out "$ca/workbench.crt" \
      -extfile <(printf "subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n" "$WORKBENCH_DOMAIN") \
      2>/dev/null || return 1
    chmod 600 "$ca/workbench.key"
    rm -f "$ca/workbench.csr"
    $KUBECTL create secret tls workbench-tls -n "$ns" \
      --cert="$ca/workbench.crt" --key="$ca/workbench.key" \
      --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null
}

workbench_zone_ready() {
    local rns="$1" want missing
    if [[ "$($KUBECTL get namespace "$rns" -o name 2>/dev/null </dev/null || true)" != "namespace/$rns" ]]; then
        echo "namespace $rns does not exist (./deploy-infra.sh creates it while RESEARCH_ENABLED is true)" >&2
        return 1
    fi
    if ! ( SCRIPT_DIR="$REPO_ROOT"; RESEARCH_NAMESPACE="$rns"; MK8S="${MK8S:-microk8s}"
           source "$REPO_ROOT/infra/lib-policy-artefacts.sh" && _pa_rsnetpol_equal ); then
        echo "the research zone's network policies in $rns are not the compiled ones (./infra/deploy-research-namespace.sh, or ./deploy-infra.sh)" >&2
        return 1
    fi
    # the names only: a placeholder node address compiles them (the specs were compared above)
    local _wo=()
    mapfile -t _wo < <(SCRIPT_DIR="$REPO_ROOT" RESEARCH_NAMESPACE="$rns" bash -c 'source "$SCRIPT_DIR/infra/lib-policy-tools.sh"; zone_other_args research' 2>/dev/null)
    want="$(python3 "$REPO_ROOT/apps/iam/compiler/cli.py" compile netpol --zone research \
              --namespace "$rns" --platform-namespace "$NAMESPACE" "${_wo[@]}" --node-ip 192.0.2.1)" \
        || { echo "the research zone's network policies do not compile (python3 apps/iam/compiler/cli.py check)" >&2; return 1; }
    missing="$(python3 -c '
import json, sys
names = {i["metadata"]["name"] for i in json.load(sys.stdin).get("items") or []}
print(" ".join(n for n in ("rs-hub", "rs-workbench-proxy", "rs-notebooks") if n not in names))' <<<"$want")" \
        || { echo "cannot read the compiled research zone's network policies" >&2; return 1; }
    if [[ -n "$missing" ]]; then
        echo "the access policy's research zone has no $missing: the workbench cannot run there" >&2
        return 1
    fi
}

workbench_pv_dir() {
    local d
    d="$($KUBECTL get storageclass microk8s-hostpath -o jsonpath='{.parameters.pvDir}' 2>/dev/null </dev/null || true)"
    echo "${d:-/var/snap/microk8s/common/default-storage}"
}

# workbench_home_plan SRC DST ADMIN_CLAIM SRC_PVCS DST_PVCS PVS — the files hold
# `get pvc -n SRC -o json`, `get pvc -n DST -o json`, `get pv -o json`. One tab-separated line
# per claim-* claim of SRC, in name order:
#   skip     CLAIM  why       nothing to do (ADMIN_CLAIM; DST's claim is the copy an earlier
#                             run made, labelled medcea/moved-from=SRC; no bound PV)
#   conflict CLAIM  why       DST holds a claim of that name that no move from SRC made (e.g. a
#                             fresh install's empty home), or several kept volumes could hold
#                             it: neither side is touched, an administrator decides
#   rebind   CLAIM  PV  DIR   the source claim is labelled medcea/moved-to=DST (what DST holds
#                             is newer) and exactly one Released/Available Retain PV labelled
#                             medcea/workbench-home=CLAIM names DST/CLAIM: bind a new claim to
#                             it, no copy (DIR: its directory, checked before the bind)
#   replace  CLAIM  SRC_DIR  DST_PV   DST holds the stale copy left by the move to SRC
#                             (medcea/moved-to=SRC): retire its volume (DST_PV), delete that
#                             claim, then copy
#   copy     CLAIM  SRC_DIR   copy the source directory into a new volume
# A volume labelled medcea/superseded (a replaced stale copy) is never a candidate, and a source
# claim labelled moved-from=DST (moved back since: newer than anything DST kept) is copied.
# Exit 1 when a file cannot be read.
workbench_home_plan() {
    python3 - "$@" <<'PY'
import json, re, sys
src, dst, admin_claim, f_src, f_dst, f_pv = sys.argv[1:7]
try:
    spvc = json.load(open(f_src)).get("items") or []
    dpvc = {i["metadata"]["name"]: i for i in json.load(open(f_dst)).get("items") or []}
    pvs = json.load(open(f_pv)).get("items") or []
except (OSError, ValueError, KeyError, TypeError):
    sys.exit(1)
by_name = {p["metadata"]["name"]: p for p in pvs}
plain = lambda path: bool(re.fullmatch(r"/[A-Za-z0-9._/-]+", path)) and "/../" not in path + "/"
hostpath = lambda p: (((p or {}).get("spec") or {}).get("hostPath") or {}).get("path") or ""
labels_of = lambda o: (o.get("metadata") or {}).get("labels") or {}
for c in sorted(spvc, key=lambda i: i["metadata"]["name"]):
    name = c["metadata"]["name"]
    if not name.startswith("claim-"):
        continue
    if name == admin_claim:
        print("skip\t%s\tthe hub administrator's own home (not moved; O7)" % name)
        continue
    d = dpvc.get(name)
    dst_pv = ""
    if d is not None:
        dl = labels_of(d)
        if dl.get("medcea/moved-from") == src:
            print("skip\t%s\talready in %s" % (name, dst))
            continue
        if dl.get("medcea/moved-to") != src:
            print("conflict\t%s\t%s holds its own %s, not a copy from %s: neither is changed; compare the two "
                  "homes and keep one by hand" % (name, dst, name, src))
            continue
        dst_pv = (d.get("spec") or {}).get("volumeName") or "-"   # the stale copy: replaced below
    elif labels_of(c).get("medcea/moved-to") == dst:
        hits = [p for p in pvs
                if labels_of(p).get("medcea/workbench-home") == name and "medcea/superseded" not in labels_of(p)
                and ((p.get("spec") or {}).get("claimRef") or {}).get("namespace") == dst
                and ((p.get("spec") or {}).get("claimRef") or {}).get("name") == name
                and ((p.get("status") or {}).get("phase")) in ("Released", "Available")
                and (p.get("spec") or {}).get("persistentVolumeReclaimPolicy") == "Retain"]
        if len(hits) > 1:
            print("conflict\t%s\tseveral kept volumes could hold it in %s (%s): none is bound; keep one by hand"
                  % (name, dst, " ".join(sorted(p["metadata"]["name"] for p in hits))))
            continue
        if hits and plain(hostpath(hits[0])):
            print("rebind\t%s\t%s\t%s" % (name, hits[0]["metadata"]["name"], hostpath(hits[0])))
            continue
    pv = by_name.get((c.get("spec") or {}).get("volumeName") or "")
    path = hostpath(pv)
    if not pv or not plain(path):
        print("skip\t%s\tno bound volume with a plain host path (left as it is)" % name)
        continue
    if d is not None:
        print("replace\t%s\t%s\t%s" % (name, path, dst_pv))
    else:
        print("copy\t%s\t%s" % (name, path))
PY
}

# workbench_unmoved_homes SRC DST ADMIN_CLAIM — the claim-* homes of SRC a move to DST has not
# taken yet (every plan line but skip), one "CLAIM" per line; for a fresh install into DST,
# which must not start next to homes it would shadow. Exit 1 when the cluster cannot be read.
workbench_unmoved_homes() {
    local src="$1" dst="$2" admin="$3" d rc=0
    d="$(mktemp -d)" || return 1
    if $KUBECTL get pvc -n "$src" -o json > "$d/src.json" 2>/dev/null </dev/null \
       && $KUBECTL get pvc -n "$dst" -o json > "$d/dst.json" 2>/dev/null </dev/null \
       && $KUBECTL get pv -o json > "$d/pv.json" 2>/dev/null </dev/null; then
        workbench_home_plan "$src" "$dst" "$admin" "$d/src.json" "$d/dst.json" "$d/pv.json" > "$d/plan" || rc=1
        [[ "$rc" == 0 ]] && awk -F'\t' '$1 != "skip" { print $2 }' "$d/plan"
    else
        rc=1
    fi
    rm -f "$d/src.json" "$d/dst.json" "$d/pv.json" "$d/plan"; rmdir "$d" 2>/dev/null || true
    return "$rc"
}

# workbench_home_manifests SRC DST CLAIM UUID DST_DIR SRC_PVC PVS → a v1 List: PV pvc-UUID
# (hostPath DST_DIR with the source PV's hostPath type, microk8s-hostpath, Retain, the source
# PV's capacity, access modes and nodeAffinity, claimRef DST/CLAIM, labels
# medcea/workbench-home=CLAIM and medcea/moved-from=SRC) and PVC CLAIM in DST bound to it
# (volumeName; the source claim's class, access modes and request; label medcea/moved-from).
# SRC_PVC holds `get pvc CLAIM -n SRC -o json`, PVS `get pv -o json`.
workbench_home_manifests() {
    python3 - "$@" <<'PY'
import json, sys
src, dst, claim, uid, dst_dir, f_pvc, f_pv = sys.argv[1:8]
pvc = json.load(open(f_pvc))
pv = next(p for p in json.load(open(f_pv)).get("items") or []
          if p["metadata"]["name"] == (pvc.get("spec") or {}).get("volumeName"))
ps, cs = pv.get("spec") or {}, pvc.get("spec") or {}
host = {"path": dst_dir}
if (ps.get("hostPath") or {}).get("type"):
    host["type"] = ps["hostPath"]["type"]
new_pv = {"apiVersion": "v1", "kind": "PersistentVolume",
          "metadata": {"name": "pvc-" + uid,
                       "labels": {"medcea/workbench-home": claim, "medcea/moved-from": src}},
          "spec": {"capacity": dict(ps.get("capacity") or {}),
                   "accessModes": list(ps.get("accessModes") or cs.get("accessModes") or ["ReadWriteOnce"]),
                   "persistentVolumeReclaimPolicy": "Retain",
                   "storageClassName": "microk8s-hostpath",
                   "hostPath": host,
                   "claimRef": {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "namespace": dst, "name": claim}}}
if ps.get("nodeAffinity"):
    new_pv["spec"]["nodeAffinity"] = ps["nodeAffinity"]
req = ((cs.get("resources") or {}).get("requests") or {}).get("storage") or (ps.get("capacity") or {}).get("storage")
new_pvc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
           "metadata": {"name": claim, "namespace": dst, "labels": {"medcea/moved-from": src}},
           "spec": {"accessModes": list(cs.get("accessModes") or ["ReadWriteOnce"]),
                    "storageClassName": cs.get("storageClassName") or "microk8s-hostpath",
                    "volumeName": "pvc-" + uid,
                    "resources": {"requests": {"storage": req}}}}
print(json.dumps({"apiVersion": "v1", "kind": "List", "items": [new_pv, new_pvc]}, sort_keys=True))
PY
}

# workbench_rebind_released NS — for a fresh install into NS (the release in no namespace):
# a Released PV labelled medcea/workbench-home (never one labelled medcea/superseded) whose
# claimRef names NS gets its claimRef's uid and resourceVersion cleared, so it is Available for
# exactly that claim again (a move whose install failed, a --reset of the research namespace).
# Only when it is the one such volume for its claim, NS holds no claim of that name and its
# directory is still on this host (sudo test -d: the PV directory is root's); otherwise a
# WARNING on stderr names it and nothing is freed. Prints the PVs it freed.
workbench_rebind_released() {
    local ns="$1" pvs pvcs pv claim dir why
    pvs="$($KUBECTL get pv -l medcea/workbench-home -o json 2>/dev/null </dev/null)" || return 0
    pvcs="$($KUBECTL get pvc -n "$ns" -o json 2>/dev/null </dev/null)" || pvcs='{"items": []}'
    while IFS=$'\t' read -r why pv claim dir; do
        [[ -n "$why" ]] || continue
        if [[ "$why" != one ]]; then
            echo "WARNING: $claim in $ns: $why; nothing bound again (an administrator keeps one by hand)" >&2
            continue
        fi
        if ! sudo -p "[sudo] password for %u (to check the kept home $claim still has its directory): " test -d "$dir"; then
            echo "WARNING: volume $pv ($claim) names $dir, which is not on this host: not bound again" >&2
            continue
        fi
        $KUBECTL patch pv "$pv" --type merge -p '{"spec":{"claimRef":{"uid":null,"resourceVersion":null}}}' >/dev/null \
            && echo "$pv"
    done < <(PVCS="$pvcs" python3 -c '
import json, os, re, sys
try:
    items = json.load(sys.stdin).get("items") or []
    have = {c["metadata"]["name"] for c in json.loads(os.environ["PVCS"]).get("items") or []}
except (ValueError, KeyError, TypeError):
    sys.exit(0)
by = {}
for p in items:
    ref = (p.get("spec") or {}).get("claimRef") or {}
    lab = p["metadata"].get("labels") or {}
    if (p.get("status") or {}).get("phase") == "Released" and ref.get("namespace") == sys.argv[1] and ref.get("uid") \
       and "medcea/superseded" not in lab and ref.get("name") == lab.get("medcea/workbench-home"):
        by.setdefault(ref["name"], []).append(p)
for claim, ps in sorted(by.items()):
    if claim in have:
        continue
    if len(ps) > 1:
        print("several kept volumes could hold it (%s)\t-\t%s\t-" % (" ".join(sorted(p["metadata"]["name"] for p in ps)), claim))
        continue
    d = ((ps[0].get("spec") or {}).get("hostPath") or {}).get("path") or ""
    if not re.fullmatch(r"/[A-Za-z0-9._/-]+", d) or "/../" in d + "/":
        print("its volume %s has no plain host path\t-\t%s\t-" % (ps[0]["metadata"]["name"], claim))
        continue
    print("one\t%s\t%s\t%s" % (ps[0]["metadata"]["name"], claim, d))' "$ns" <<<"$pvs")
}

# workbench_rebind_manifest DST CLAIM PV PVS → the PVC CLAIM in DST bound (volumeName) to PV,
# a Released Retain home volume an earlier move made (its class, access modes and capacity;
# label medcea/moved-from as the PV says). PVS holds `get pv -o json`.
workbench_rebind_manifest() {
    python3 - "$@" <<'PY'
import json, sys
dst, claim, name, f_pv = sys.argv[1:5]
pv = next(p for p in json.load(open(f_pv)).get("items") or [] if p["metadata"]["name"] == name)
ps = pv.get("spec") or {}
labels = {}
if (pv["metadata"].get("labels") or {}).get("medcea/moved-from"):
    labels["medcea/moved-from"] = pv["metadata"]["labels"]["medcea/moved-from"]
print(json.dumps({"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                  "metadata": {"name": claim, "namespace": dst, "labels": labels},
                  "spec": {"accessModes": list(ps.get("accessModes") or ["ReadWriteOnce"]),
                           "storageClassName": ps.get("storageClassName") or "microk8s-hostpath",
                           "volumeName": name,
                           "resources": {"requests": {"storage": (ps.get("capacity") or {}).get("storage")}}}},
                 sort_keys=True))
PY
}
