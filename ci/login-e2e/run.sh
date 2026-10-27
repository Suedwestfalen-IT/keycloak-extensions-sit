#!/usr/bin/env bash
# =====================================================================
# run.sh – login end-to-end test: real Keycloak, login played with curl
#
#   ci/login-e2e/run.sh [keycloak-version] [provider-jar]
#
# Starts the official Keycloak distribution with the provider jar and runs login_e2e.py
# against it (see ci/lib/run-keycloak-e2e.sh for the details and defaults).
#
# Output in $WORK_DIR (default .login-e2e/): keycloak.log, e2e.out
# =====================================================================
E2E_NAME="login-e2e"
E2E_SCRIPT="$(cd "$(dirname "$0")" && pwd)/login_e2e.py"
KC_PORT="${KC_PORT:-18180}"
KC_MGMT_PORT="${KC_MGMT_PORT:-19100}"
KC_LOG_LEVEL="${KC_LOG_LEVEL:-info,org.keycloak.authentication:debug}"
source "$(dirname "$0")/../lib/run-keycloak-e2e.sh"
