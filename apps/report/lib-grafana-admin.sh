#!/usr/bin/env bash
# apps/report/lib-grafana-admin.sh — the Grafana local admin (break-glass, IAM 3.1)
# as a curl config, so its password never reaches argv:
#
#   curl -K <(grafana_admin_cfg) ...
#
# The login is ADMIN_USER with GRAFANA_BREAKGLASS_PASS (Secret grafana-admin,
# written by deploy-infra.sh). printf is a builtin, so nothing here is a process
# with the password on its command line; `"` and `\` are escaped for curl's
# config syntax.
grafana_admin_cfg() {
    local u="${ADMIN_USER//\\/\\\\}" p="${GRAFANA_BREAKGLASS_PASS//\\/\\\\}"
    u="${u//\"/\\\"}"; p="${p//\"/\\\"}"
    printf 'user = "%s:%s"\n' "$u" "$p"
}
