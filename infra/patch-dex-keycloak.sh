#!/usr/bin/env bash
#
# [RETIRED] This script re-applied the Keycloak OIDC connector to Charmed
# Kubeflow's dex-auth charm after a charm update reset it.
#
# Kubeflow has been replaced by JupyterHub (infra/deploy-workbench.sh), which authenticates
# against Keycloak directly. There is no dex-auth charm to patch, and running
# this will fail at the first `juju config`.
#
# Kept alongside the commented-out Kubeflow blocks in infra/bootstrap-infra.sh
# and deploy-infra.sh so the old path can be restored as a set.
#
echo "patch-dex-keycloak.sh is retired: Kubeflow was replaced by infra/deploy-workbench.sh (JupyterHub)." >&2
echo "Nothing to do. See deploy-infra.sh [RETIRED] section to restore the old stack." >&2
exit 0

# # =============================================================================
# # patch-dex-keycloak.sh
# #
# # Run this AFTER:
# #   1. Kubeflow is live (Pass 1 complete + Juju settled)
# #   2. You have created a confidential client called 'kubeflow' in the
# #      $KEYCLOAK_REALM realm and copied its secret into config.env
# #
# # Charmed Kubeflow 1.9: dex-auth is a Juju charm (StatefulSet).
# # Configuration is applied via: juju config dex-auth connectors=...
# # There is no ConfigMap to patch — Juju owns the config entirely.
# # =============================================================================
# REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# mkdir -p "$REPO_ROOT/logs"
# LOG_FILE="$REPO_ROOT/logs/patch-dex-keycloak-$(date +%Y%m%d-%H%M%S).log"
# exec > >(tee "$LOG_FILE") 2>&1
# echo "patch-dex-keycloak started: $(date)"

# set -e
# source "$REPO_ROOT/config.env"

# YELLOW='\033[0;33m'
# GREEN='\033[0;32m'
# RED='\033[0;31m'
# NC='\033[0m'

# # --- Validate required secrets ---
# if [[ -z "$KUBEFLOW_CLIENT_SECRET" ]]; then
#     echo -e "${RED}ERROR: KUBEFLOW_CLIENT_SECRET is not set in config.env.${NC}"
#     echo "Steps:"
#     echo "  1. Open https://$KEYCLOAK_DOMAIN — log in as $ADMIN_USER"
#     echo "  2. Create realm '$KEYCLOAK_REALM', then a confidential client: kubeflow"
#     echo "  3. Copy the client secret into config.env as KUBEFLOW_CLIENT_SECRET"
#     exit 1
# fi

# # --- Configure dex-auth to federate with Keycloak ---
# # dex-auth is managed by Juju — use 'juju config' to set OIDC connectors.
# # The redirectURI must point to Dex's own callback (Dex handles the Keycloak
# # response, then issues a token back to oidc-gatekeeper).
# echo -e "${YELLOW}Configuring dex-auth OIDC connector for Keycloak...${NC}"

# _CONNECTORS="- type: oidc
#   id: keycloak
#   name: Keycloak (${KEYCLOAK_REALM})
#   config:
#     issuer: http://${KEYCLOAK_DOMAIN}/realms/${KEYCLOAK_REALM}
#     clientID: kubeflow
#     clientSecret: ${KUBEFLOW_CLIENT_SECRET}
#     redirectURI: http://${KUBEFLOW_DOMAIN}/dex/callback
#     insecureSkipEmailVerified: true
#     insecureSkipVerify: true
#     scopes:
#       - openid
#       - profile
#       - email
#     userNameKey: email"

# juju config dex-auth "connectors=${_CONNECTORS}"
# # Set issuer-url so Dex and oidc-authservice use the nip.io domain for OIDC_PROVIDER.
# # This ensures the CSRF cookie domain matches the authservice callback URL.
# juju config dex-auth "issuer-url=http://${KUBEFLOW_DOMAIN}/dex"

# # --- Wait for dex-auth charm to settle ---
# # Check the unit-level juju-status (idle = charm hook finished successfully),
# # not the application-level workload status (which is always "available").
# echo -e "${YELLOW}Waiting for dex-auth to apply config (up to 5 min)...${NC}"
# _DEADLINE=$(($(date +%s) + 300))
# while true; do
#     _STATUS=$(juju status dex-auth --format=yaml 2>/dev/null \
#         | grep -A1 "juju-status:" | grep "current:" | head -1 | awk '{print $2}' || echo "unknown")
#     if [[ "$_STATUS" == "idle" ]]; then
#         echo -e "${GREEN}dex-auth is idle — config applied successfully.${NC}"
#         break
#     fi
#     if [[ "$(date +%s)" -ge "$_DEADLINE" ]]; then
#         echo -e "${YELLOW}Warning: dex-auth status is '$_STATUS' after 5 min — continuing anyway.${NC}"
#         break
#     fi
#     echo -e "${YELLOW}dex-auth juju-status: $_STATUS — waiting 15s...${NC}"
#     sleep 15
# done

# echo -e "\n${GREEN}Done! Kubeflow will now redirect logins to Keycloak.${NC}"
# echo -e "Open http://${KUBEFLOW_DOMAIN} and you should see 'Log in with Keycloak (${KEYCLOAK_REALM})'."
# echo ""
# echo -e "${YELLOW}Note:${NC} To verify: juju config dex-auth connectors"
# echo "If SSO stops working after a charm update, re-run this script."
