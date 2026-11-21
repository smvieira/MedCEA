# infra/lib-research-zone-namespace.sh — the body of infra/deploy-research-gw-namespace.sh and
# infra/deploy-research-agents-namespace.sh (research Phase 4a, design rs4 R2): the two scripts differ
# only in the zone. Sourced after config.env, lib-render.sh, lib-policy-source.sh and
# lib-policy-artefacts.sh, with SCRIPT_DIR, REPO_ROOT, NAMESPACE, KUBECTL, MK8S and _MODE set.
#
#   rzn_run ZONE   ZONE research-gw | research-agents. Skips (exit 0, one line) while RESEARCH_ENABLED is
#                  not true or the applied access policy has no such zone; otherwise applies
#                  k8s/<zone>/{namespace,quota,limitrange}.yaml and pa_zonenetpol ZONE full. --policy-only
#                  (_MODE=scoped) prints gwnetpol / ranetpol: unchanged|re-rendered|not deployed.

rzn_run() {
    local _z="$1" _comp _var _key _ns
    case "$_z" in
        research-gw)     _var=RESEARCH_GW_NAMESPACE;     _key=gwnetpol ;;
        research-agents) _var=RESEARCH_AGENTS_NAMESPACE; _key=ranetpol ;;
        *) echo "rzn_run: unknown zone '$_z'" >&2; return 2 ;;
    esac
    _comp="deploy-$_z-namespace"
    _ns="$(zone_namespace "$_z")"
    local _other
    printf -v "$_var" %s "$_ns"; export "${_var?}"   # the manifests' ${RESEARCH_*_NAMESPACE}
    _valid() {
        [[ "$_ns" =~ ^[a-z][a-z0-9-]{1,52}$ && "$_ns" != "$NAMESPACE" ]] || return 1
        for _other in research research-gw research-agents; do
            [[ "$_other" == "$_z" ]] || [[ "$(zone_namespace "$_other")" != "$_ns" ]] || return 1
        done
    }
    _present() { [[ "$($KUBECTL get namespace "$_ns" -o name 2>/dev/null || true)" == "namespace/$_ns" ]]; }

    if [[ "${RESEARCH_ENABLED:-false}" != "true" ]]; then
        if [[ "$_MODE" == scoped ]]; then
            _pa_line "$_key" "not deployed"
        else
            log "skipped: RESEARCH_ENABLED is not true (config.env), so the $_z namespace is not deployed"
        fi
        if _valid && _present; then
            warn "RESEARCH_ENABLED is not true, but namespace $_ns is still there and is left as it is (./apps/research/uninstall.sh first, if it is deployed). To remove it: $KUBECTL delete namespace $_ns"
        fi
        return 0
    fi
    _valid || die "$_var='$_ns' must match ^[a-z][a-z0-9-]{1,52}\$ and differ from NAMESPACE='$NAMESPACE' and from the other research namespaces (config.env)."

    policy_source_init "$NAMESPACE" || exit $?

    if ! _pa_zone_has "$_z"; then
        if [[ "$_MODE" == scoped ]]; then
            _pa_line "$_key" "not deployed"
        else
            log "skipped: the applied access policy has no $_z zone yet; it comes with an approved skeleton version (./apps/iam/apply.sh --status)"
        fi
        _present && warn "namespace $_ns exists, but the applied access policy has no $_z zone: its network policies are left as they are."
        policy_source_finish "$NAMESPACE" "$_comp"
        return 0
    fi

    if [[ "$_MODE" == scoped ]]; then
        pa_zonenetpol "$_z" scoped
    else
        log "namespace $_ns (zone $_z), quota and limits"
        local _f
        for _f in namespace quota limitrange; do
            render "$REPO_ROOT/k8s/$_z/$_f.yaml" "$_var" | $KUBECTL apply -f -
        done
        pa_zonenetpol "$_z" full
    fi
    policy_source_finish "$NAMESPACE" "$_comp"
}
