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
# KC_POLICY_TOKEN_CLIENTS  the clients that exist only while the applied access policy
#                   names them as some network.clients entry's token_client (research
#                   Phase 2b, D2): deploy-infra.sh creates (or brings back) each one while
#                   `cli.py has-token-client NAME` says 0, and otherwise disables an existing
#                   one (read-modify-write, enabled false; never created, never deleted);
#                   infra/deploy-workbench.sh --move disables it too (kc_client_disable).
#                   Every one is a public device-sign-in client (_create_public_device_client).
#                   The two lists above keep them (their order is pinned): a disabled client
#                   found by the scope loop still gets its scopes, which is harmless.
# shellcheck disable=SC2034  # read by the scripts that source it
KC_SCOPE_CLIENTS=(portal access policy config monitor scheduler dbmgmt mqtt-explorer pgadmin edge-wizard node-red workbench grafana superset workbench-notebook)
# shellcheck disable=SC2034
KC_API_CLIENTS=(portal access policy config monitor scheduler dbmgmt mqtt-explorer edge-wizard workbench-notebook)
# shellcheck disable=SC2034
KC_POLICY_TOKEN_CLIENTS=(workbench-notebook)
# KC_RESEARCH_CLIENTS  the clients of the agent campaigns (research Phase 4a): research-agent
#                   is a public device-grant client whose tokens carry `groups` and the
#                   scope medcea-research (audience medcea-research, never medcea-api) and
#                   not medcea-identity. deploy-infra.sh creates it only while
#                   `cli.py has-token-client NAME` says 0 (a pod's token_clients entry in
#                   the applied policy), else disables an existing one. Outside the three
#                   lists above on purpose: the scope loop would give it medcea-identity.
# shellcheck disable=SC2034
KC_RESEARCH_CLIENTS=(research-agent)
