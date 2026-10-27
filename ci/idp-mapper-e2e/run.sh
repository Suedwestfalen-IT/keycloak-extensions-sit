#!/usr/bin/env bash
# =====================================================================
# run.sh – IdP group mapper end-to-end test: real Keycloak brokering itself, logins played with curl
#
#   ci/idp-mapper-e2e/run.sh [keycloak-version] [provider-jar]
#
# Starts the official Keycloak distribution (Maven Central, or KC_DIST=<unpacked
# dir>) with the provider jar, then runs idp_mapper_e2e.py against it. No root, no
# Docker. Defaults: keycloak.version from pom.xml, jar from target/ (built with
# mvn package -DskipTests if missing). Needs Java 17+, Python 3, curl.
#
# Output in $WORK_DIR (default .idp-mapper-e2e/): keycloak.log, e2e.out
# =====================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT_DIR="$ROOT/ci/idp-mapper-e2e"
KC_VERSION="${1:-$(sed -n 's:.*<keycloak.version>\(.*\)</keycloak.version>.*:\1:p' "$ROOT/pom.xml" | head -n 1)}"
JAR="${2:-}"
WORK_DIR="${WORK_DIR:-$ROOT/.idp-mapper-e2e}"
KC_PORT="${KC_PORT:-18280}"
KC_MGMT_PORT="${KC_MGMT_PORT:-19200}"
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
    --log-level=info \
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

python3 "$SCRIPT_DIR/idp_mapper_e2e.py" "http://localhost:$KC_PORT" 2>&1 | tee "$OUT"
rc=${PIPESTATUS[0]}
stop_kc
trap - EXIT

echo "[e2e] log: $(grep -c 'IdpGroupMapper: user=' "$LOG") sync summary line(s)," \
  "$(grep -c 'does not explicitly support sync mode' "$LOG") 'does not explicitly support sync mode' warning(s)"

errors=$(grep -E '^[0-9-]+ [0-9:,.]+ +ERROR ' "$LOG" || true)
if [ -n "$errors" ]; then
  echo "[e2e] ERROR lines in the Keycloak log:"; printf '%s\n' "$errors" | head -n 20
  rc=1
fi
[ "$rc" -eq 0 ] && echo "[e2e] PASS" || echo "[e2e] FAIL (see $OUT and $LOG)"
exit "$rc"
