#!/usr/bin/env bash
# Drives the Swift kit against the real enrolment service over HTTP:
#
#   clients/ios/tools/interop/run.sh
#
# Compiles services/device-enrolment and the libraries it needs (offline, from the local Maven repository),
# starts Interop.java - the service's own classes, wired as its Main wires them with REGISTRY=memory and
# REQUIRE_COMPLIANT_DEVICE=false, beside an oracle standing in for Apple and PingOne - and runs the kit's
# InteropTests against it with swift test. A developer's tool on a Mac: it is not in the reactor and no
# workflow runs it (InteropTests skips itself when the variables below are unset, as it does in CI).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
M2="${MAVEN_REPO:-$HOME/.m2/repository}"
WORK="$(mktemp -d)"
HARNESS_PID=""
cleanup() {
  if [[ -n "$HARNESS_PID" ]]; then kill "$HARNESS_PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

bom_version() {
  sed -n "s:.*<$1>\(.*\)</$1>.*:\1:p" "$ROOT/bom/pom.xml" | head -1
}
newest_dir() {
  find "$1" -mindepth 1 -maxdepth 1 -type d -name "$2" | sort -V | tail -1
}
first_jar() {
  find "$1" -maxdepth 1 -type f -name "$2" | sort | head -1
}

JOSE4J="$(bom_version version.pf.jose4j)"
JACKSON="$(bom_version version.pf.jackson)"
COMMONS_LOGGING="$(bom_version version.pf.commons-logging)"
BOUNCYCASTLE="$(bom_version version.bouncycastle)"
ANNOTATIONS="$(newest_dir "$M2/com/fasterxml/jackson/core/jackson-annotations" "${JACKSON%.*}*")"
SLF4J="$(newest_dir "$M2/org/slf4j/slf4j-api" "*")"

(cd "$ROOT" && mvn -o -B -q -pl services/device-enrolment -am -DskipTests -Djacoco.skip=true compile)

CP="$ROOT/services/device-enrolment/target/classes"
for module in libs/oidf-jose libs/device-instance libs/app-attest libs/client-attestation; do
  CP="$CP:$ROOT/$module/target/classes"
done
CP="$CP:$M2/org/bitbucket/b_c/jose4j/$JOSE4J/jose4j-$JOSE4J.jar"
CP="$CP:$M2/com/fasterxml/jackson/core/jackson-databind/$JACKSON/jackson-databind-$JACKSON.jar"
CP="$CP:$M2/com/fasterxml/jackson/core/jackson-core/$JACKSON/jackson-core-$JACKSON.jar"
CP="$CP:$(first_jar "$ANNOTATIONS" 'jackson-annotations-*.jar')"
CP="$CP:$M2/com/fasterxml/jackson/dataformat/jackson-dataformat-cbor/$JACKSON/jackson-dataformat-cbor-$JACKSON.jar"
CP="$CP:$M2/commons-logging/commons-logging/$COMMONS_LOGGING/commons-logging-$COMMONS_LOGGING.jar"
CP="$CP:$(first_jar "$SLF4J" 'slf4j-api-*.jar')"
for bc in bcprov bcpkix bcutil; do
  CP="$CP:$M2/org/bouncycastle/$bc-jdk18on/$BOUNCYCASTLE/$bc-jdk18on-$BOUNCYCASTLE.jar"
done

javac -d "$WORK/classes" -cp "$CP" "$HERE/Interop.java"
java -cp "$CP:$WORK/classes" Interop >"$WORK/harness.out" 2>"$WORK/harness.err" &
HARNESS_PID=$!

for _ in $(seq 1 60); do
  grep -q '^audience=' "$WORK/harness.out" 2>/dev/null && break
  if ! kill -0 "$HARNESS_PID" 2>/dev/null; then
    cat "$WORK/harness.err" >&2
    echo "ERROR: the harness exited before it was ready" >&2
    exit 1
  fi
  sleep 0.5
done
grep -q '^audience=' "$WORK/harness.out" || { cat "$WORK/harness.err" >&2; echo "ERROR: the harness did not start" >&2; exit 1; }
cat "$WORK/harness.out"

AGENTIDENTITYKIT_INTEROP_SERVICE="$(sed -n 's/^service=//p' "$WORK/harness.out")" \
AGENTIDENTITYKIT_INTEROP_ORACLE="$(sed -n 's/^oracle=//p' "$WORK/harness.out")" \
AGENTIDENTITYKIT_INTEROP_AUDIENCE="$(sed -n 's/^audience=//p' "$WORK/harness.out")" \
  swift test --package-path "$ROOT/clients/ios/AgentIdentityKit" --filter InteropTests
