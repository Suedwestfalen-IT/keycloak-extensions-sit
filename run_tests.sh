#!/usr/bin/env bash
set -euo pipefail
# =====================================================================
# run_tests.sh – keycloak-extensions-sit
#
# Führt die Unit-Tests lokal via Docker (Maven) aus. Gleiche Steuerung
# wie build_jar.sh über .env oder Umgebungsvariablen:
#   KC_VERSION     Keycloak-Zielversion (default: 26.7.4)
#   MAVEN_IMAGE    Maven-Docker-Image   (default: maven:3.9-eclipse-temurin-17)
#
# Zusätzliche Argumente gehen an Maven durch, z.B.:
#   ./run_tests.sh -Dtest=IdpGroupMapperTest
#
# Alternativ ohne Docker: mvn test -Dkeycloak.version=26.7.4
# =====================================================================

[ ! -f .env ] || export $(grep -v '^#' .env | xargs)

KC_VERSION="${KC_VERSION:-26.7.4}"
MAVEN_IMAGE="${MAVEN_IMAGE:-maven:3.9-eclipse-temurin-17}"

SETTINGS_MOUNT=""
if [ -f "settings.xml" ]; then
  SETTINGS_MOUNT="-v $(pwd)/settings.xml:/root/.m2/settings.xml:ro"
  echo "[INFO] Using local settings.xml (proxy config)"
fi

echo "[INFO] Running tests against Keycloak ${KC_VERSION}..."

docker run --rm \
  -v "$(pwd):/src:ro" \
  ${SETTINGS_MOUNT} \
  -e KC_VERSION="${KC_VERSION}" \
  "${MAVEN_IMAGE}" \
  bash -c '
    cp -r /src /build && cd /build
    mvn -q -Dkeycloak.version="${KC_VERSION}" test "$@"
    status=$?
    echo
    cat target/surefire-reports/*.txt 2>/dev/null | grep -E "^Tests run|^Test set" || true
    exit $status
  ' -- "$@"
