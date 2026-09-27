#!/usr/bin/env bash
# The enrolment protocol's vectors, printed by the server's own classes:
#
#   clients/ios/tools/vectors/run.sh
#
# Compiles services/device-enrolment and the libraries it needs (offline, from the local Maven repository) and
# runs Vectors.java against their target/classes, so a value here is what the running server computes. A
# developer's tool: it is not in the reactor and no workflow runs it. The library versions are read from
# bom/pom.xml, the jars from the local Maven repository (MAVEN_REPO overrides ~/.m2/repository).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
M2="${MAVEN_REPO:-$HOME/.m2/repository}"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

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
# jackson-annotations dropped the patch number from 2.20 on; take the newest of the BOM's minor line.
ANNOTATIONS="$(newest_dir "$M2/com/fasterxml/jackson/core/jackson-annotations" "${JACKSON%.*}*")"
# jose4j's own dependency; any cached version serves a program that never logs.
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

javac -d "$OUT" -cp "$CP" "$HERE/Vectors.java"
java -cp "$CP:$OUT" Vectors "$ROOT/libs/app-attest/src/test/resources/fixtures"
