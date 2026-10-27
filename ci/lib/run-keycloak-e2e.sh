#!/usr/bin/env bash
# =====================================================================
# run-keycloak-e2e.sh – shared runner for the end-to-end tests that need nothing but a Keycloak
# (ci/login-e2e, ci/idp-mapper-e2e). The test's own run.sh sets the variables below and sources
# this file; ci/kerberos-e2e needs a KDC and root and keeps its own runner.
#
#   E2E_NAME        test name, used for the default work dir (.<name>/) and messages
#   E2E_SCRIPT      python test, started as: <script> http://localhost:$KC_PORT
#   KC_PORT         Keycloak HTTP port          (default 18080)
#   KC_MGMT_PORT    Keycloak management port    (default 19000)
#   KC_LOG_LEVEL    --log-level for Keycloak    (default info)
#   $1 / $2         Keycloak version (default: keycloak.version from pom.xml), provider jar
#                   (default: target/, built with mvn package -DskipTests if missing)
#
# Starts the official Keycloak distribution (Maven Central, or KC_DIST=<unpacked dir>) with the
# provider jar, runs the python test against it and exports KC_LOG, the Keycloak log file, to it.
# No root, no Docker. Needs Java 17+, Python 3, curl.
#
# Output in $WORK_DIR (default .<E2E_NAME>/): keycloak.log, e2e.out
# =====================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${E2E_NAME:?E2E_NAME not set}"
: "${E2E_SCRIPT:?E2E_SCRIPT not set}"
KC_VERSION="${1:-$(sed -n 's:.*<keycloak.version>\(.*\)</keycloak.version>.*:\1:p' "$ROOT/pom.xml" | head -n 1)}"
JAR="${2:-}"
WORK_DIR="${WORK_DIR:-$ROOT/.$E2E_NAME}"
KC_PORT="${KC_PORT:-18080}"
KC_MGMT_PORT="${KC_MGMT_PORT:-19000}"
KC_LOG_LEVEL="${KC_LOG_LEVEL:-info}"
START_TIMEOUT="${START_TIMEOUT:-300}"
MVN="${MVN:-mvn -B -q}"

mkdir -p "$WORK_DIR"
LOG="$WORK_DIR/keycloak.log"
OUT="$WORK_DIR/e2e.out"

if [ -z "$JAR" ]; then
  JAR=$(ls "$ROOT"/target/keycloak-extensions-sit-*.jar 2>/dev/null | grep -v -- '-sources\|-javadoc' | head -n 1 || true)
  if [ -z "$JAR" ]; then
    echo "[e2e] building provider jar"
    (cd "$ROOT" && $MVN -Dkeycloak.version="$KC_VERSION" clean package -DskipTests) || { echo "[e2e] build failed"; exit 1; }
    JAR=$(ls "$ROOT"/target/keycloak-extensions-sit-*.jar | grep -v -- '-sources\|-javadoc' | head -n 1)
  fi
fi
echo "[e2e] jar: $JAR"

if [ -n "${KC_DIST:-}" ]; then
  DIST_DIR="$KC_DIST"
else
  DIST_DIR="$WORK_DIR/dist/keycloak-$KC_VERSION"
  if [ ! -x "$DIST_DIR/bin/kc.sh" ]; then
    mkdir -p "$WORK_DIR/dist"
    $MVN dependency:copy -Dartifact="org.keycloak:keycloak-quarkus-dist:$KC_VERSION:tar.gz" \
      -DoutputDirectory="$WORK_DIR/dist" || { echo "[e2e] Keycloak distribution $KC_VERSION not available"; exit 1; }
    tar -xzf "$WORK_DIR/dist/keycloak-quarkus-dist-$KC_VERSION.tar.gz" -C "$WORK_DIR/dist"
    rm -f "$WORK_DIR/dist/keycloak-quarkus-dist-$KC_VERSION.tar.gz"
  fi
fi

RUN_DIR="$WORK_DIR/run"
rm -rf "$RUN_DIR"
cp -r "$DIST_DIR" "$RUN_DIR"
cp "$JAR" "$RUN_DIR/providers/"

echo "[e2e] starting Keycloak $KC_VERSION"
KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  "$RUN_DIR/bin/kc.sh" start-dev \
    --http-port="$KC_PORT" \
    --http-management-port="$KC_MGMT_PORT" \
    --health-enabled=true \
    --log-level="$KC_LOG_LEVEL" \
    > "$LOG" 2>&1 &
KC_PID=$!

stop_kc() {
  if kill -0 "$KC_PID" 2>/dev/null; then
    kill "$KC_PID" 2>/dev/null
    for _ in $(seq 1 30); do kill -0 "$KC_PID" 2>/dev/null || break; sleep 1; done
    kill -9 "$KC_PID" 2>/dev/null || true
  fi
}
trap stop_kc EXIT

ready=false
for _ in $(seq 1 "$START_TIMEOUT"); do
  kill -0 "$KC_PID" 2>/dev/null || break
  if curl -sf --noproxy '*' "http://localhost:$KC_MGMT_PORT/health/ready" > /dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
if ! $ready; then
  echo "[e2e] Keycloak did not start:"; tail -n 40 "$LOG"; exit 1
fi
echo "[e2e] Keycloak ready"

KC_LOG="$LOG" python3 "$E2E_SCRIPT" "http://localhost:$KC_PORT" 2>&1 | tee "$OUT"
rc=${PIPESTATUS[0]}
stop_kc
trap - EXIT

errors=$(grep -E '^[0-9-]+ [0-9:,.]+ +ERROR ' "$LOG" || true)
if [ -n "$errors" ]; then
  echo "[e2e] ERROR lines in the Keycloak log:"; printf '%s\n' "$errors" | head -n 20
  rc=1
fi
[ "$rc" -eq 0 ] && echo "[e2e] PASS" || echo "[e2e] FAIL (see $OUT and $LOG)"
exit "$rc"
