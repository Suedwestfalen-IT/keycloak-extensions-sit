#!/usr/bin/env bash
set -euo pipefail
# =====================================================================
# build_jar.sh – keycloak-extensions-sit
#
# Baut das Provider-Jar lokal via Docker (Maven).
# Kein Registry-Login erforderlich.
#
# Ergebnis: dist/keycloak-extensions-sit-v<VERSION>-kc<KC_VERSION>.jar
#
# Steuerung via .env oder Umgebungsvariablen:
#   KC_VERSION     Keycloak-Zielversion (default: 26.6.2)
#   VERSION        Provider-Version     (default: aus pom.xml)
#   MAVEN_IMAGE    Maven-Docker-Image   (default: maven:3.9-eclipse-temurin-17)
#   OUTPUT_DIR     Ausgabeverzeichnis   (default: ./dist)
#
# Alternativ: mvn clean package -Dkeycloak.version=26.6.2
# =====================================================================

[ ! -f .env ] || export $(grep -v '^#' .env | xargs)

KC_VERSION="${KC_VERSION:-26.6.2}"
MAVEN_IMAGE="${MAVEN_IMAGE:-maven:3.9-eclipse-temurin-17}"
OUTPUT_DIR="${OUTPUT_DIR:-./dist}"

# Version aus pom.xml lesen, falls nicht gesetzt
if [ -z "${VERSION:-}" ]; then
  VERSION=$(grep -m1 '<version>' pom.xml | sed 's/.*<version>\(.*\)<\/version>.*/\1/' | tr -d '[:space:]')
fi

JAR_NAME="keycloak-extensions-sit-v${VERSION}-kc${KC_VERSION}.jar"
mkdir -p "${OUTPUT_DIR}"

echo "[INFO] Building keycloak-extensions-sit ${VERSION} for Keycloak ${KC_VERSION}..."

SETTINGS_MOUNT=""
if [ -f "settings.xml" ]; then
  SETTINGS_MOUNT="-v $(pwd)/settings.xml:/root/.m2/settings.xml:ro"
  echo "[INFO] Using local settings.xml (proxy config)"
fi

docker run --rm \
  -v "$(pwd):/src:ro" \
  ${SETTINGS_MOUNT} \
  -v "$(realpath "${OUTPUT_DIR}"):/output" \
  -e KC_VERSION="${KC_VERSION}" \
  -e VERSION="${VERSION}" \
  -e JAR_NAME="${JAR_NAME}" \
  "${MAVEN_IMAGE}" \
  bash -c '
    set -e
    cp -r /src /build && cd /build
    mvn -q versions:set -DnewVersion="${VERSION}" -DgenerateBackupPoms=false
    mvn -q versions:set-property \
      -Dproperty=keycloak.version \
      -DnewVersion="${KC_VERSION}" \
      -DgenerateBackupPoms=false
    mvn -q dependency:go-offline || true
    mvn -q clean package -DskipTests
    JAR=$(find target -name "*.jar" ! -name "*-sources.jar" ! -name "*-javadoc.jar" | head -1)
    cp "$JAR" "/output/${JAR_NAME}"
    echo "[INFO] Written: /output/${JAR_NAME}"
  '

echo "[SUCCESS] ${OUTPUT_DIR}/${JAR_NAME}"
