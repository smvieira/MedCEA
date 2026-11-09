#!/bin/bash
# infra/lib-keycloak-clients.sh — the Keycloak clients that carry the platform's client
# scopes "groups" and "medcea-identity" (Phase 5, G2): one list for deploy-infra.sh's
# scope loop, which attaches both scopes to each client, and health-check.sh's kcscopes,
# which checks them in Keycloak's database. Data only: sourcing it runs nothing.
#
# KC_SCOPE_CLIENTS  every client of the access policy's hosts plus the token clients, in
#                   the order deploy-infra.sh has always attached them (it must not move:
#                   tests/test_keycloak_clients.py pins it). workbench-notebook has no host:
#                   it is network.clients.notebooks' token_client.
# KC_API_CLIENTS    the clients whose access tokens reach a platform API (HOST_CLIENTS of
#                   apps/access/deploy.sh, the token clients of the policy, and the edge
#                   wizard, which calls config-api with the person's token): a missing scope
#                   or mapper there breaks token verification or the gate, so kcscopes FAILs.
#                   The others (grafana, pgadmin, superset, node-red, workbench) sign people
#                   in to a tool only: kcscopes WARNs for them.
# shellcheck disable=SC2034  # read by the scripts that source it
KC_SCOPE_CLIENTS=(portal access policy config monitor scheduler dbmgmt mqtt-explorer pgadmin edge-wizard node-red workbench grafana superset workbench-notebook)
# shellcheck disable=SC2034
KC_API_CLIENTS=(portal access policy config monitor scheduler dbmgmt mqtt-explorer edge-wizard workbench-notebook)
