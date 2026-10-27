#!/usr/bin/env bash
# =====================================================================
# run.sh – IdP group mapper end-to-end test: real Keycloak brokering itself, logins played with curl
#
#   ci/idp-mapper-e2e/run.sh [keycloak-version] [provider-jar]
#
# Starts the official Keycloak distribution with the provider jar and runs idp_mapper_e2e.py
# against it (see ci/lib/run-keycloak-e2e.sh for the details and defaults). The mapper's own
# logger runs on DEBUG so that the test can check the summary line of every sync, including
# the ones that changed nothing.
#
# Output in $WORK_DIR (default .idp-mapper-e2e/): keycloak.log, e2e.out
# =====================================================================
E2E_NAME="idp-mapper-e2e"
E2E_SCRIPT="$(cd "$(dirname "$0")" && pwd)/idp_mapper_e2e.py"
KC_PORT="${KC_PORT:-18280}"
KC_MGMT_PORT="${KC_MGMT_PORT:-19200}"
KC_LOG_LEVEL="${KC_LOG_LEVEL:-info,nrw.sit.keycloak.mapper:debug}"
source "$(dirname "$0")/../lib/run-keycloak-e2e.sh"
