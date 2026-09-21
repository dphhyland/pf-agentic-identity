#!/usr/bin/env bash
# Assemble pf-runtime.war = STOCK PingFederate runtime war + the OIDF module jars (+ optionally jose4j),
# injected into WEB-INF/lib, PLUS web.xml edits to register four filters over PF's own endpoints.
#
# Annotation-mapped module classes (@WebServlet servlets like RegisteredClientsServlet, the SSF servlets)
# auto-map once the jar is on WEB-INF/lib (pf-runtime.war scans it). Plain filters that must run over PF's
# OWN endpoints are NOT annotated (mapping them by annotation would only bind the module's context), so they
# are registered explicitly in this war's WEB-INF/web.xml:
#   - SsfLogoutSignal (LogoutEventFilter) over /idp/init_logout.openid → emits caep.session-revoked SETs.
#   - Fapi2Profile (Fapi2ProfileFilter) over every endpoint that takes a client assertion or a DPoP proof
#     → the two FAPI 2.0 rules PF 13.0 has no setting for, for the clients OIDF_FAPI2_CLIENTS lists. MUST be
#     mapped before the two below (see its block — the order is checked).
#   - OidfAutoRegistration (TokenEndpointAutoRegistrationFilter) over /as/token.oauth2 → §12.1 automatic
#     registration; MUST be mapped before ClientAttestationAuth (see below — the order is checked).
#   - ClientAttestationAuth (ClientAttestationAuthFilter) over /as/token.oauth2 → attest_jwt_client_auth.
# All four registrations are idempotent, and the script fails if any mapping is missing afterwards.
#
# Inputs (provided by the caller — build/pingfederate/Dockerfile here, or a consumer repo's CI job):
#   $1  STOCK_WAR   path to the stock pf-runtime.war extracted from the pingidentity/pingfederate image
#   $2  MODULES     the built module jar(s): either a single jar (the legacy monolith
#                   pf-oidf-modules.jar), or a DIRECTORY of jars (the monorepo's modular output —
#                   oidf.jar + attestation-issuer/ssf/oidf-jose/client-attestation/openid-federation);
#                   every *.jar in the directory is injected into WEB-INF/lib under its own name.
#   $3  JOSE4J_JAR  path to jose4j jar, or "-" to skip. SKIP for pf-runtime.war merging: PF already
#                   ships jose4j on its server classpath, and bundling a second copy in WEB-INF/lib
#                   causes a LinkageError (loader constraint violation) when PF-loaded jose4j types
#                   (JwksEndpointKeyAccessor results) cross into module code.
#   $4  OUT_WAR     path to write the assembled pf-runtime.war
set -euo pipefail
STOCK_WAR="$1"; MODULES="$2"; JOSE4J_JAR="$3"; OUT_WAR="$4"
MODULE_NAME="pf-oidf-modules-0.0.1-SNAPSHOT.jar"   # single-jar mode: keep the WEB-INF/lib entry name stable

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
cp "$STOCK_WAR" "$OUT_WAR"
# Resolve OUT_WAR to an absolute path — the `zip` calls below run from inside $work, so a relative
# OUT_WAR would land in the temp dir instead of the intended output.
OUT_WAR="$(cd "$(dirname "$OUT_WAR")" && pwd)/$(basename "$OUT_WAR")"
mkdir -p "$work/WEB-INF/lib"
if [[ -d "$MODULES" ]]; then
  # Refuse an incomplete or hand-populated stage. stage-modules.sh writes MANIFEST naming exactly what
  # it staged; if that is missing, or the directory does not match it, the war would assemble happily
  # and then NoClassDefFoundError at the first request touching the absent module — which is how both
  # the agent-registry and device-instance omissions reached a running staging PF.
  manifest="$MODULES/MANIFEST"
  if [[ ! -f "$manifest" ]]; then
    echo "ERROR: $MODULES has no MANIFEST — it was not produced by build/pingfederate/stage-modules.sh." >&2
    echo "       Run 'mvn -q -DskipTests package && build/pingfederate/stage-modules.sh'." >&2
    echo "       Hand-copying jars here is how modules have gone missing before." >&2
    exit 1
  fi
  missing=""
  while IFS= read -r want; do
    [[ -z "$want" ]] && continue
    [[ -f "$MODULES/$want" ]] || missing="$missing $want"
  done < "$manifest"
  if [[ -n "$missing" ]]; then
    echo "ERROR: staged modules/ is incomplete — MANIFEST names jars that are not present:$missing" >&2
    echo "       Re-run build/pingfederate/stage-modules.sh after 'mvn package'." >&2
    exit 1
  fi
  for present in "$MODULES"/*.jar; do
    base="$(basename "$present")"
    grep -qxF "$base" "$manifest" || {
      echo "ERROR: $base is in modules/ but not in MANIFEST — a stale or hand-added jar." >&2
      echo "       Re-run build/pingfederate/stage-modules.sh so the directory matches the build." >&2
      exit 1; }
  done
  echo "modules/: $(wc -l < "$manifest" | tr -d ' ') jars, matching MANIFEST"
  cp "$MODULES"/*.jar "$work/WEB-INF/lib/"
else
  cp "$MODULES" "$work/WEB-INF/lib/$MODULE_NAME"
fi
if [[ "$JOSE4J_JAR" != "-" ]]; then
  cp "$JOSE4J_JAR" "$work/WEB-INF/lib/$(basename "$JOSE4J_JAR")"
fi
( cd "$work" && zip -q "$OUT_WAR" WEB-INF/lib/*.jar )

# --- web.xml surgery: register the SSF logout filter (idempotent) ---
unzip -oq "$OUT_WAR" WEB-INF/web.xml -d "$work"
WEBXML="$work/WEB-INF/web.xml"
if [[ ! -f "$WEBXML" ]]; then
  echo "ERROR: stock pf-runtime.war has no WEB-INF/web.xml" >&2; exit 1
fi
if grep -q "SsfLogoutSignal" "$WEBXML"; then
  echo "web.xml: SsfLogoutSignal already registered — leaving as is"
else
  grep -q "</web-app>" "$WEBXML" || { echo "ERROR: web.xml has no </web-app> to insert before" >&2; exit 1; }
  awk '
    /<\/web-app>/ && !done {
      print "  <filter>"
      print "    <filter-name>SsfLogoutSignal</filter-name>"
      print "    <filter-class>com.pingidentity.ps.oidf.servlet.ssf.LogoutEventFilter</filter-class>"
      print "  </filter>"
      print "  <filter-mapping>"
      print "    <filter-name>SsfLogoutSignal</filter-name>"
      print "    <url-pattern>/idp/init_logout.openid</url-pattern>"
      print "  </filter-mapping>"
      done=1
    }
    { print }
  ' "$WEBXML" > "$WEBXML.new" && mv "$WEBXML.new" "$WEBXML"
  ( cd "$work" && zip -q "$OUT_WAR" WEB-INF/web.xml )
  echo "web.xml: registered SsfLogoutSignal over /idp/init_logout.openid"
fi

# Fapi2Profile (Fapi2ProfileFilter) — FAPI 2.0 Security Profile: a client assertion's aud must be this
# server's issuer, as a string (§5.3.2.1), and a DPoP proof must be signed with PS256, ES256 or EdDSA
# (§5.4.1). PF 13.0 accepts the token endpoint URL as an audience and RS256 on a proof, and has no
# setting for either. Registered always and OFF by default: it examines only the clients named in
# OIDF_FAPI2_CLIENTS ("*" for all) and passes everything else through, because OIDC Core tells clients
# to use the token endpoint URL, and a server with FAPI 2.0 clients usually has the other kind too.
#
# Mapped over every PF endpoint that authenticates a client by assertion or takes a DPoP proof. One the
# list misses is one where the rule is silently not applied, so it errs long: PAR, token, introspection,
# revocation, CIBA, and UserInfo (the one resource PF serves itself).
#
# MUST be mapped BEFORE OidfAutoRegistration and ClientAttestationAuth. An assertion this server is
# about to refuse should not first trigger an automatic registration; and ClientAttestationAuth replaces
# the client's assertion with a bridge assertion of its own, which is not the one the rule is about.
if grep -q "Fapi2Profile" "$WEBXML"; then
  echo "web.xml: Fapi2Profile already registered — leaving as is"
else
  awk '
    /<\/web-app>/ && !ins {
      print "  <filter>"
      print "    <filter-name>Fapi2Profile</filter-name>"
      print "    <filter-class>com.pingidentity.ps.oidf.servlet.fapi2.Fapi2ProfileFilter</filter-class>"
      print "  </filter>"
      print "  <filter-mapping>"
      print "    <filter-name>Fapi2Profile</filter-name>"
      print "    <url-pattern>/as/par.oauth2</url-pattern>"
      print "    <url-pattern>/as/token.oauth2</url-pattern>"
      print "    <url-pattern>/as/introspect.oauth2</url-pattern>"
      print "    <url-pattern>/as/revoke_token.oauth2</url-pattern>"
      print "    <url-pattern>/as/bc-auth.ciba</url-pattern>"
      print "    <url-pattern>/idp/userinfo.openid</url-pattern>"
      print "  </filter-mapping>"
      ins=1
    }
    { print }
  ' "$WEBXML" > "$WEBXML.new" && mv "$WEBXML.new" "$WEBXML"
  ( cd "$work" && zip -q "$OUT_WAR" WEB-INF/web.xml )
  echo "web.xml: registered Fapi2Profile over the client-assertion and DPoP endpoints (only for clients listed in OIDF_FAPI2_CLIENTS)"
fi

# OidfAutoRegistration (TokenEndpointAutoRegistrationFilter) over /as/token.oauth2 — OpenID
# Federation §12.1 automatic registration: an unknown federation client presenting its trust chain in
# its client_assertion is just-in-time materialised in PF's client store so the same request then
# authenticates normally. Fail-open; idempotent for known clients. Trust controller comes from
# OIDF_FEDERATION_TRUST_CONTROLLER_HOST at runtime (FederationRuntimeConfig).
#
# MUST be mapped BEFORE ClientAttestationAuth. Filters run in <filter-mapping> document order, and
# ClientAttestationAuth REPLACES client_assertion with a bridge assertion that carries no trust_chain
# header - so if it ran first, this filter would find nothing to register from and §12.1 could never
# fire for exactly the attestation clients it exists to serve. The reverse dependency does not hold:
# this filter re-validates the chain itself and reads no attestation state. The check after both
# blocks enforces the order.
if grep -q "OidfAutoRegistration" "$WEBXML"; then
  echo "web.xml: OidfAutoRegistration already registered — leaving as is"
else
  awk '
    /<\/web-app>/ && !ins {
      print "  <filter>"
      print "    <filter-name>OidfAutoRegistration</filter-name>"
      print "    <filter-class>com.pingidentity.ps.oidf.servlet.clientregistration.TokenEndpointAutoRegistrationFilter</filter-class>"
      print "  </filter>"
      print "  <filter-mapping>"
      print "    <filter-name>OidfAutoRegistration</filter-name>"
      print "    <url-pattern>/as/token.oauth2</url-pattern>"
      print "  </filter-mapping>"
      ins=1
    }
    { print }
  ' "$WEBXML" > "$WEBXML.new" && mv "$WEBXML.new" "$WEBXML"
  ( cd "$work" && zip -q "$OUT_WAR" WEB-INF/web.xml )
  echo "web.xml: registered OidfAutoRegistration over /as/token.oauth2"
fi
# ClientAttestationAuth (ClientAttestationAuthFilter) over /as/token.oauth2 — implements
# attest_jwt_client_auth (draft-ietf-oauth-attestation-based-client-auth): verifies the
# OAuth-Client-Attestation(+PoP) headers and forwards the request authenticated to PF via a bridge
# private_key_jwt signed with THAT CLIENT'S key (OIDF_BRIDGE_SIGNER_BACKING + OIDF_BRIDGE_SIGNING_KEYS;
# the superseded single-key OIDF_BRIDGE_PRIVATE_JWK is now refused at startup rather than ignored).
# With no bridge signing configured the filter refuses to start, unless
# OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY=false says the operator meant to run without it - in which case
# attestation headers pass through and PF enforces each client's own configured authentication.
# Mapped AFTER OidfAutoRegistration - see the ordering note there.
if grep -q "ClientAttestationAuth" "$WEBXML"; then
  echo "web.xml: ClientAttestationAuth already registered — leaving as is"
else
  awk '
    /<\/web-app>/ && !ins {
      print "  <filter>"
      print "    <filter-name>ClientAttestationAuth</filter-name>"
      print "    <filter-class>com.pingidentity.ps.oidf.servlet.clientregistration.ClientAttestationAuthFilter</filter-class>"
      print "  </filter>"
      print "  <filter-mapping>"
      print "    <filter-name>ClientAttestationAuth</filter-name>"
      print "    <url-pattern>/as/token.oauth2</url-pattern>"
      print "  </filter-mapping>"
      ins=1
    }
    { print }
  ' "$WEBXML" > "$WEBXML.new" && mv "$WEBXML.new" "$WEBXML"
  ( cd "$work" && zip -q "$OUT_WAR" WEB-INF/web.xml )
  echo "web.xml: registered ClientAttestationAuth over /as/token.oauth2"
fi


echo "assembled $OUT_WAR:"
if [[ -d "$MODULES" ]]; then
  for j in "$MODULES"/*.jar; do
    unzip -l "$OUT_WAR" | grep -qF "WEB-INF/lib/$(basename "$j")" \
      || { echo "ERROR: module jar $(basename "$j") not present in war"; exit 1; }
  done
  unzip -l "$OUT_WAR" | grep -E "WEB-INF/lib/.*\.jar" | tail -n +1
else
  unzip -l "$OUT_WAR" | grep -E "pf-oidf-modules" || { echo "ERROR: module jar not present in war"; exit 1; }
fi
unzip -p "$OUT_WAR" WEB-INF/web.xml | grep -q "SsfLogoutSignal" \
  || { echo "ERROR: SsfLogoutSignal filter mapping not present in assembled war" >&2; exit 1; }
unzip -p "$OUT_WAR" WEB-INF/web.xml | grep -q "ClientAttestationAuth" \
  || { echo "ERROR: ClientAttestationAuth filter mapping not present in assembled war" >&2; exit 1; }
unzip -p "$OUT_WAR" WEB-INF/web.xml | grep -q "OidfAutoRegistration" \
  || { echo "ERROR: OidfAutoRegistration filter mapping not present in assembled war" >&2; exit 1; }
unzip -p "$OUT_WAR" WEB-INF/web.xml | grep -q "Fapi2Profile" \
  || { echo "ERROR: Fapi2Profile filter mapping not present in assembled war" >&2; exit 1; }
# Order is load-bearing, not cosmetic (see the OidfAutoRegistration block): the LAST occurrence of each
# name is its <filter-mapping>, and auto-registration's must come first. This also catches a bad order
# baked into a stock web.xml, which the "already registered — leaving as is" branches would skip over.
_mapping_line() { unzip -p "$OUT_WAR" WEB-INF/web.xml | grep -n "<filter-name>$1</filter-name>" | tail -1 | cut -d: -f1; }
_autoreg_at="$(_mapping_line OidfAutoRegistration)"; _attest_at="$(_mapping_line ClientAttestationAuth)"
[ -n "$_autoreg_at" ] && [ -n "$_attest_at" ] && [ "$_autoreg_at" -lt "$_attest_at" ] || {
  echo "ERROR: filter order wrong in $OUT_WAR - OidfAutoRegistration (line ${_autoreg_at:-?}) must be" >&2
  echo "       mapped before ClientAttestationAuth (line ${_attest_at:-?}); the attestation filter" >&2
  echo "       rewrites client_assertion and would hide the trust_chain from auto-registration." >&2
  exit 1; }
_fapi2_at="$(_mapping_line Fapi2Profile)"
[ -n "$_fapi2_at" ] && [ "$_fapi2_at" -lt "$_autoreg_at" ] || {
  echo "ERROR: filter order wrong in $OUT_WAR - Fapi2Profile (line ${_fapi2_at:-?}) must be mapped" >&2
  echo "       before OidfAutoRegistration (line $_autoreg_at): a refused assertion must not trigger a" >&2
  echo "       registration, and must be judged before ClientAttestationAuth replaces it." >&2
  exit 1; }
echo "verified: SsfLogoutSignal + Fapi2Profile + OidfAutoRegistration + ClientAttestationAuth mapped in $OUT_WAR (order checked)"
