#!/usr/bin/env bash
# infra/lib-manual.sh — the platform manual in the portal: https://<PORTAL_DOMAIN>/manual/.
#
#   manual_build OUT              docs/manual/build.py --out OUT --standalone: the page built
#                                 from the chapters now, never the committed index.html (which
#                                 may lag), as a complete document (doctype, charset); 1 with
#                                 build.py's message when it refuses
#   manual_cm_json NS HTML        the ConfigMap portal-manual for that page on stdout: the
#                                 page gzipped (binaryData index.html.gz, deterministic:
#                                 mtime 0) and annotation medcea/manual-sha256 = sha256 of
#                                 the page; 3 with a message when it would not fit
#   manual_publish NS [--no-roll] build → ConfigMap (server-side apply) → restart the
#                                 portal and wait; --no-roll for deploy-infra.sh, which
#                                 restarts the portal itself after applying its manifest.
#                                 No restart when the portal Deployment does not mount
#                                 ConfigMap portal-manual yet (a portal older than the
#                                 manual: ./deploy-infra.sh must run once). Sets
#                                 MANUAL_SERVED=yes only after the restart, no otherwise.
#
# Callers: deploy-infra.sh section 9 (every infra deploy publishes it), infra/publish-manual.sh
# (./medcea.sh → Infrastructure → Publish the manual to the portal: a docs change needs no
# full deploy), and health-check.sh's `manual` check (manual_build only: read-only).
#
# Needs KUBECTL for manual_publish. The portal's nginx (k8s/portal/nginx.conf) serves the
# file with gzip_static always and gunzip on, so the ConfigMap holds ~160 KiB for a
# ~570 KiB page. A ConfigMap holds at most 1 MiB; MANUAL_MAX_BYTES (default 1000000,
# leaving room for the key and metadata) is the refusal's limit. Server-side apply, not
# client-side: a client-side apply would copy the whole page into the last-applied
# annotation, and annotations hold at most 256 KiB. Nothing here writes to the working
# tree: the page and its gzip live in a mktemp -d directory removed on return.

_MANUAL_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANUAL_CM=portal-manual
MANUAL_ANNOTATION=medcea/manual-sha256

manual_build() {
    local out="$1" msg
    if ! msg="$(python3 "$_MANUAL_REPO/docs/manual/build.py" --out "$out" --standalone 2>&1)"; then
        echo "ERROR: docs/manual/build.py refuses to build the manual, so it is not published:" >&2
        printf '%s\n' "$msg" | sed 's/^/  /' >&2
        echo "  Fix the chapter it names (docs/manual/chapters/), then publish again." >&2
        return 1
    fi
    [[ -s "$out" ]] || { echo "ERROR: docs/manual/build.py wrote nothing to $out" >&2; return 1; }
}

# The commit the page was built from, for the annotation and the messages: <short sha>,
# with -dirty when docs/manual differs from it; "unknown" without git.
_manual_commit() {
    local c
    c="$(git -C "$_MANUAL_REPO" rev-parse --short HEAD 2>/dev/null)" || { echo unknown; return; }
    [[ -n "$(git -C "$_MANUAL_REPO" status --porcelain -- docs/manual 2>/dev/null)" ]] && c+="-dirty"
    echo "$c"
}

manual_cm_json() {
    local ns="$1" html="$2"
    MANUAL_COMMIT="$(_manual_commit)" python3 - "$ns" "$html" "${MANUAL_MAX_BYTES:-1000000}" \
        "$MANUAL_CM" "$MANUAL_ANNOTATION" <<'PY'
import base64, gzip, hashlib, json, os, sys
ns, path, limit, name, ann = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
page = open(path, "rb").read()
gz = gzip.compress(page, 9, mtime=0)
if len(gz) > limit:
    print(f"ERROR: the manual is {len(page) // 1024} KiB, {len(gz)} bytes gzipped: over the "
          f"{limit} bytes a ConfigMap may hold here (Kubernetes' limit is 1 MiB). It is not "
          "published, and the portal keeps serving the last one. Shorten the manual or split "
          "it into more than one ConfigMap (infra/lib-manual.sh).", file=sys.stderr)
    sys.exit(3)
print(json.dumps({
    "apiVersion": "v1", "kind": "ConfigMap",
    "metadata": {"name": name, "namespace": ns, "labels": {"app": "portal"},
                 "annotations": {ann: hashlib.sha256(page).hexdigest(),
                                 "medcea/manual-commit": os.environ.get("MANUAL_COMMIT", "unknown"),
                                 "medcea/manual-bytes": str(len(page))}},
    "binaryData": {"index.html.gz": base64.b64encode(gz).decode()},
}))
PY
}

manual_publish() {
    local ns="$1" roll=true tmp rc=0 sha gz
    MANUAL_SERVED=no
    [[ "${2:-}" == --no-roll ]] && roll=false
    tmp="$(mktemp -d)"
    if ! manual_build "$tmp/index.html"; then rm -rf "$tmp"; return 1; fi
    manual_cm_json "$ns" "$tmp/index.html" >"$tmp/cm.json" || rc=$?
    if (( rc )); then rm -rf "$tmp"; return "$rc"; fi
    sha="$(sha256sum "$tmp/index.html" | cut -c1-12)"
    gz="$(python3 -c 'import base64, json, sys
print(len(base64.b64decode(json.load(open(sys.argv[1]))["binaryData"]["index.html.gz"])) // 1024)' "$tmp/cm.json")"
    echo "  manual: $(( $(stat -c %s "$tmp/index.html") / 1024 )) KiB, ${gz} KiB gzipped in ConfigMap $MANUAL_CM (sha256 $sha…, commit $(_manual_commit))"
    if ! $KUBECTL apply --server-side --force-conflicts --field-manager=medcea-manual -f "$tmp/cm.json" >/dev/null; then
        echo "ERROR: could not apply ConfigMap $MANUAL_CM in $ns; the portal keeps serving the last manual." >&2
        rm -rf "$tmp"; return 1
    fi
    rm -rf "$tmp"
    $roll || return 0
    local dep
    if ! dep="$($KUBECTL get deployment portal -n "$ns" -o json 2>/dev/null)"; then
        echo "  manual: published; no portal deployment in $ns yet (./deploy-infra.sh serves it)."
        return 0
    fi
    # An install whose portal predates the manual (no volume from ConfigMap portal-manual,
    # and an nginx config without /manual/) does not serve it until ./deploy-infra.sh's
    # section 9 runs once: a restart would change nothing, so none, and no claim it is served.
    if ! python3 -c '
import json, sys
d = json.loads(sys.stdin.read() or "{}")
vols = ((d.get("spec") or {}).get("template") or {}).get("spec", {}).get("volumes") or []
sys.exit(0 if any((v.get("configMap") or {}).get("name") == sys.argv[1] for v in vols) else 1)
' "$MANUAL_CM" <<<"$dep"; then
        echo "  manual: stored in ConfigMap $MANUAL_CM, but the portal in $ns is not set up to serve it yet"
        echo "  (its Deployment does not mount $MANUAL_CM). Run ./deploy-infra.sh once: its section 9"
        echo "  adds the mount, the portal's /manual/ route and the Platform manual card. Not restarted."
        return 0
    fi
    # The ConfigMap is a directory mount, which kubelet refreshes within about a minute
    # anyway; the restart makes it immediate and proves the portal starts with it.
    $KUBECTL rollout restart deployment/portal -n "$ns" >/dev/null || return 1
    $KUBECTL rollout status deployment/portal -n "$ns" --timeout=3m || return 1
    echo "  manual: the portal serves it at /manual/ (sha256 $sha…)."
    MANUAL_SERVED=yes
}
