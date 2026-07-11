#!/usr/bin/env bash
# Assemble pf-runtime.war = STOCK PingFederate runtime war + the OIDF module jar + jose4j, injected
# into WEB-INF/lib. No web.xml surgery: the module's servlets/filter map via their @WebServlet/@WebFilter
# annotations (pf-runtime.war scans WEB-INF/lib — that's why RegisteredClientsServlet et al. resolve).
#
# Inputs (all provided by the CI job — see .github/workflows/deploy-pingfederate.yml):
#   $1  STOCK_WAR   path to the stock pf-runtime.war extracted from the pingidentity/pingfederate image
#   $2  MODULE_JAR  path to the built module jar (pf-integration → target/oidf.jar)
#   $3  JOSE4J_JAR  path to jose4j-0.9.6.jar (public Maven: org.bitbucket.b_c:jose4j:0.9.6)
#   $4  OUT_WAR     path to write the assembled pf-runtime.war
#
# Result is byte-for-byte the same shape as today's hand-assembled war (module jar + jose4j in
# WEB-INF/lib), but reproducibly, in CI, from source + the licensed image — nothing binary in git.
set -euo pipefail
STOCK_WAR="$1"; MODULE_JAR="$2"; JOSE4J_JAR="$3"; OUT_WAR="$4"
MODULE_NAME="pf-oidf-modules-0.0.1-SNAPSHOT.jar"   # keep the WEB-INF/lib entry name stable

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
cp "$STOCK_WAR" "$OUT_WAR"
mkdir -p "$work/WEB-INF/lib"
cp "$MODULE_JAR" "$work/WEB-INF/lib/$MODULE_NAME"
cp "$JOSE4J_JAR" "$work/WEB-INF/lib/$(basename "$JOSE4J_JAR")"
( cd "$work" && zip -q "$OUT_WAR" WEB-INF/lib/"$MODULE_NAME" WEB-INF/lib/"$(basename "$JOSE4J_JAR")" )

echo "assembled $OUT_WAR:"
unzip -l "$OUT_WAR" | grep -E "pf-oidf-modules|jose4j" || { echo "ERROR: module jars not present in war"; exit 1; }
