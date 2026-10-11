#!/usr/bin/env bash
# infra/lib-portal.sh — turn a service card on the portal page on or off.
# Sourced by apps/<component>/deploy.sh (enable) and uninstall.sh (disable).
#
#   portal_card enable  URL     <div class="card card-dis" data-href=URL> → <a class="card" href=URL>
#   portal_card disable URL     the reverse; the card stays, greyed out and unclickable
#
# Needs KUBECTL and NAMESPACE. A card is found by its URL, so it is the same
# operation whichever app owns it, and enable/disable are exact inverses: an
# uninstalled app's card comes back when the app is deployed again. A no-op
# when the portal or the card is absent (e.g. infra not deployed).

portal_card() {
    local action="$1" url="$2" current updated
    current="$($KUBECTL get cm portal-html -n "$NAMESPACE" -o jsonpath='{.data.index\.html}' 2>/dev/null)" || return 0
    [[ -n "$current" ]] || return 0
    updated="$(printf '%s' "$current" | PORTAL_ACTION="$action" PORTAL_URL="$url" python3 -c '
import os, re, sys
html, url, action = sys.stdin.read(), os.environ["PORTAL_URL"], os.environ["PORTAL_ACTION"]
u = re.escape(url)
if action == "disable":
    # Cards are <a> elements with no nested <a>, so the lazy match ends at this card.
    pat = re.compile(r"<a class=\"card\" href=\"" + u + r"\"[^>]*>(.*?)</a>", re.S)
    html = pat.sub(lambda m: "<div class=\"card card-dis\" data-href=\"" + url + "\">" + m.group(1) + "</div><!--/card-->", html, count=1)
else:
    pat = re.compile(r"<div class=\"card card-dis\" data-href=\"" + u + r"\">(.*?)</div><!--/card-->", re.S)
    html = pat.sub(lambda m: "<a class=\"card\" href=\"" + url + "\" target=\"_blank\" rel=\"noopener\">" + m.group(1) + "</a>", html, count=1)
sys.stdout.write(html)
')" || return 0
    [[ "$updated" == "$current" ]] && return 0
    printf '%s\n' "$updated" \
        | $KUBECTL create configmap portal-html -n "$NAMESPACE" \
            --from-file=index.html=/dev/stdin --dry-run=client -o yaml \
        | $KUBECTL apply -f - >/dev/null
    # nginx serves the file from a ConfigMap volume; a restart picks it up at once.
    $KUBECTL rollout restart deployment/portal -n "$NAMESPACE" >/dev/null 2>&1 || true
}
