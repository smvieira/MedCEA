#!/usr/bin/env bash
# infra/lib-render.sh — fill a manifest template from the environment.
#
#   render FILE VAR...    print FILE with ${VAR} / $VAR replaced, for exactly the
#                         named variables, and nothing else
#
# Manifests live as files (k8s/<component>/, apps/<c>/k8s/) instead of bash
# heredocs, so they can be read, diffed and — later — handed to a GitOps tool.
# The variable list is explicit on purpose: these files also contain dollar
# signs that must reach the cluster untouched — nginx $host/$uri/$1, JupyterHub
# $HOME, the alias redirect's $request_uri, JavaScript ${...} in HTML. A bare
# envsubst would blank all of them.
#
# Output goes to stdout, straight into `kubectl apply -f -` or a mktemp values
# file: rendered manifests carry passwords and are never written under k8s/.
# The subshell keeps the exports from leaking into later commands.

render() {
    local file="$1"; shift
    [[ -f "$file" ]] || { echo "render: no such template: $file" >&2; return 1; }
    (
        local list="" v
        for v in "$@"; do
            list+="\${$v} "
            export "$v"
        done
        envsubst "$list" < "$file"
    )
}
