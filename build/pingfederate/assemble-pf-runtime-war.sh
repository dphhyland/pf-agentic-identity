#!/usr/bin/env bash
# Assemble pf-runtime.war = STOCK PingFederate runtime war + the OIDF module jars (+ optionally jose4j),
# injected into WEB-INF/lib, PLUS web.xml edits to register seven filters over PF's own endpoints.
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
#   - FapiResourceServer (FapiResourceServerFilter) over /idp/userinfo.openid → the two FAPI 1.0 Baseline
#     resource-server provisions UserInfo misses: the x-fapi-interaction-id header, no token in the query.
#   - OAuthErrorDescription (OAuthErrorDescriptionFilter) over the backchannel, token and PAR endpoints →
#     error_description kept inside RFC 6749's character set (PF puts a formatted date in it).
#   - OidfFrontChannelAutoRegistration (FrontChannelAutoRegistrationFilter) over the authorization and PAR
#     endpoints → §12.1.1 automatic registration of an RP from its signed request; MUST be mapped after
#     Fapi2Profile and OAuthErrorDescription (the order is checked).
# All seven registrations are idempotent, and the script fails if any mapping is missing afterwards.
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

# On any failure, take the output war with us. The first thing this script does is copy the STOCK war
# to OUT_WAR, so every check below - the MANIFEST checks, the namespace guard, the filter-mapping
# verification - fails with a plausible-looking pf-runtime.war already sitting at the output path: one
# with no modules and no filters in it. A caller that assembles and deploys in separate steps, or that
# misses the exit code, ships a PingFederate with none of this repo's code and no error to explain it.
# Deleting it makes a refusal absent rather than subtly wrong.
# `rc=$?` must come first - anything before it clobbers the status we are testing. Reading the exit
# status rather than setting a "we got there" flag at the bottom means a check added later is covered
# automatically, with nothing to remember.
work="$(mktemp -d)"; trap 'rc=$?; rm -rf "$work"; [[ $rc -eq 0 ]] || rm -f "$OUT_WAR"' EXIT
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

# --- namespace guard: the stock war decides which servlet namespace this PingFederate speaks ---
#
# PingFederate 13.1 moved its container to jakarta.servlet (Jetty ee9); 13.0.x is javax.servlet (ee8).
# Nothing above notices the difference. A module compiled against the wrong namespace assembles into a
# perfectly well-formed war and the build passes; it fails at BOOT instead, and how it fails depends on
# how the class is reached:
#   - a FILTER is named in web.xml below, so the whole merged war dies with "class ...Filter is not a
#     jakarta.servlet.Filter" and PF serves 503 - loud, but only after a deploy;
#   - an @WebServlet is found by annotation scanning, and ee9's scanner keys on
#     jakarta.servlet.annotation.WebServlet, so a javax-annotated servlet is never mapped at all. That
#     one is silent: the endpoint 404s and nothing in the log says why.
# The MANIFEST check above cannot catch this. It compares the directory against its own manifest, not
# against the PingFederate being assembled, so a stale but self-consistent modules/ passes it - which is
# exactly the shape of the accident this guards: a consumer pulls a new base image while a gitignored
# modules/ still holds jars built for the old one.
#
# The stock war's own web.xml is the authority (javaee 3.1 on 13.0.x, jakartaee 5.0 on 13.1.x), so this
# needs no flag and stays correct on both lines. Background: docs/pf-13_1-jakarta-migration-plan.md.
ns_descriptor="$(unzip -p "$STOCK_WAR" WEB-INF/web.xml)"
case "$ns_descriptor" in
  *jakarta.ee/xml/ns/jakartaee*) ns_want=jakarta; ns_other=javax ;;
  *)                             ns_want=javax;   ns_other=jakarta ;;
esac
ns_wrong=""
for staged in "$work"/WEB-INF/lib/*.jar; do
  # COUNT the matches; never write this as `grep -q`. This script runs under `set -o pipefail`, where
  # grep -q exits at the first match, unzip dies of SIGPIPE, the pipeline reports failure, and the
  # `|| true` then turns a MATCH into "no match" - a guard that passes everything. Not hypothetical:
  # that is how the first draft of this check behaved on all four module/image combinations.
  ns_hits="$(unzip -p "$staged" '*.class' 2>/dev/null | LC_ALL=C grep -ac "${ns_other}/servlet/" || true)"
  if [[ "${ns_hits:-0}" -gt 0 ]]; then ns_wrong="$ns_wrong $(basename "$staged")"; fi
done
if [[ -n "$ns_wrong" ]]; then
  echo "ERROR: $(basename "$STOCK_WAR") speaks ${ns_want}.servlet, but these staged jars are compiled" >&2
  echo "       against ${ns_other}.servlet:$ns_wrong" >&2
  echo "       A war built from them boots to a 503 (filters) or silently 404s (servlets). Rebuild the" >&2
  echo "       modules against the matching PingFederate line, or stage a set that was - see" >&2
  echo "       docs/pf-13_1-jakarta-migration-plan.md." >&2
  exit 1
fi
echo "namespace: ${ns_want}.servlet (per the stock war); no staged jar references ${ns_other}.servlet"

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

# FapiResourceServer (FapiResourceServerFilter) over /idp/userinfo.openid — FAPI 1.0 Baseline §6.2.1: a
# resource server echoes the client's x-fapi-interaction-id or mints a UUID (provision 11), and does not
# accept an access token in the query (provision 3). UserInfo is the one resource PF serves itself and it
# does neither; the FAPI-CIBA plan fails every positive module on the first and the happy path on the
# second. Order-independent: a header before the chain, or a 400 instead of it.
if grep -q "FapiResourceServer" "$WEBXML"; then
  echo "web.xml: FapiResourceServer already registered — leaving as is"
else
  awk '
    /<\/web-app>/ && !ins {
      print "  <filter>"
      print "    <filter-name>FapiResourceServer</filter-name>"
      print "    <filter-class>com.pingidentity.ps.oidf.servlet.fapi1.FapiResourceServerFilter</filter-class>"
      print "  </filter>"
      print "  <filter-mapping>"
      print "    <filter-name>FapiResourceServer</filter-name>"
      print "    <url-pattern>/idp/userinfo.openid</url-pattern>"
      print "  </filter-mapping>"
      ins=1
    }
    { print }
  ' "$WEBXML" > "$WEBXML.new" && mv "$WEBXML.new" "$WEBXML"
  ( cd "$work" && zip -q "$OUT_WAR" WEB-INF/web.xml )
  echo "web.xml: registered FapiResourceServer over /idp/userinfo.openid"
fi

# OAuthErrorDescription (OAuthErrorDescriptionFilter) over the backchannel, token and PAR endpoints —
# RFC 6749 §5.2 gives error_description a character set, and PF 13.0.3 puts jose4j's explanation of a
# refused request object in it, Java-formatted date and its U+202F included. The filter buffers a 4xx
# JSON body and brings the description inside the set. Order: it wraps the response, so it must be
# OUTERMOST for these endpoints - registered here, before the filters that run inside it; the container
# applies filter-mappings in web.xml order.
if grep -q "OAuthErrorDescription" "$WEBXML"; then
  echo "web.xml: OAuthErrorDescription already registered — leaving as is"
else
  awk '
    /<\/web-app>/ && !ins {
      print "  <filter>"
      print "    <filter-name>OAuthErrorDescription</filter-name>"
      print "    <filter-class>com.pingidentity.ps.oidf.servlet.oauth.OAuthErrorDescriptionFilter</filter-class>"
      print "  </filter>"
      print "  <filter-mapping>"
      print "    <filter-name>OAuthErrorDescription</filter-name>"
      print "    <url-pattern>/as/bc-auth.ciba</url-pattern>"
      print "    <url-pattern>/as/token.oauth2</url-pattern>"
      print "    <url-pattern>/as/par.oauth2</url-pattern>"
      print "  </filter-mapping>"
      ins=1
    }
    { print }
  ' "$WEBXML" > "$WEBXML.new" && mv "$WEBXML.new" "$WEBXML"
  ( cd "$work" && zip -q "$OUT_WAR" WEB-INF/web.xml )
  echo "web.xml: registered OAuthErrorDescription over the backchannel, token and PAR endpoints"
fi

# OidfFrontChannelAutoRegistration (FrontChannelAutoRegistrationFilter) over the authorization and PAR
# endpoints — OpenID Federation §12.1.1 automatic registration: an RP that has never registered here sends
# its request with its Entity Identifier as client_id and a signed request object (or, at PAR, a
# private_key_jwt assertion) as proof it holds its keys; the filter resolves its chain, verifies that proof
# against the keys it publishes for openid_relying_party, and registers it before PF sees the request.
# Refusals are JSON at PAR and a page - never a redirect - at the authorization endpoint (§12.1.3).
#
# MUST be mapped AFTER Fapi2Profile and OAuthErrorDescription: a PAR assertion FAPI 2.0 refuses must not
# first cause a registration, and a PAR refusal from here must pass through the description sanitiser,
# which wraps the response and so has to sit outside. The check below enforces both.
if grep -q "OidfFrontChannelAutoRegistration" "$WEBXML"; then
  echo "web.xml: OidfFrontChannelAutoRegistration already registered — leaving as is"
else
  awk '
    /<\/web-app>/ && !ins {
      print "  <filter>"
      print "    <filter-name>OidfFrontChannelAutoRegistration</filter-name>"
      print "    <filter-class>com.pingidentity.ps.oidf.servlet.clientregistration.FrontChannelAutoRegistrationFilter</filter-class>"
      print "  </filter>"
      print "  <filter-mapping>"
      print "    <filter-name>OidfFrontChannelAutoRegistration</filter-name>"
      print "    <url-pattern>/as/authorization.oauth2</url-pattern>"
      print "    <url-pattern>/as/par.oauth2</url-pattern>"
      print "  </filter-mapping>"
      ins=1
    }
    { print }
  ' "$WEBXML" > "$WEBXML.new" && mv "$WEBXML.new" "$WEBXML"
  ( cd "$work" && zip -q "$OUT_WAR" WEB-INF/web.xml )
  echo "web.xml: registered OidfFrontChannelAutoRegistration over the authorization and PAR endpoints"
fi

# OidfAutoRegistration (TokenEndpointAutoRegistrationFilter) over /as/token.oauth2 — OpenID
# Federation §12.1 automatic registration: an unknown federation client presenting its trust chain in
# its client_assertion is just-in-time materialised in PF's client store so the same request then
# authenticates normally, and a federation client's registration is renewed as it nears its end (§12.3).
# Fail-closed by default (OIDF_AUTO_REGISTRATION_FAIL_CLOSED); a current registration costs one store
# read. Trust controller comes from OIDF_FEDERATION_TRUST_CONTROLLER_HOST at runtime (FederationRuntimeConfig).
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
# Read the listing and the descriptor ONCE, then grep the strings. Never `unzip ... | grep -q`: under
# `set -o pipefail`, grep -q exits at its first match, unzip is still writing, dies of SIGPIPE, and the
# pipeline reports failure - so a mapping that IS present reads as absent. Whether it happens depends on
# how much of the descriptor sits after the match and how the pipe buffers, which is why the same
# context built clean on this machine and failed on Railway's builder (2026-09-23, "Fapi2Profile filter
# mapping not present in assembled war" with the mapping in the war). The namespace guard above found
# the same thing from the other side.
war_listing="$(unzip -l "$OUT_WAR")"
war_web_xml="$(unzip -p "$OUT_WAR" WEB-INF/web.xml)"
if [[ -d "$MODULES" ]]; then
  for j in "$MODULES"/*.jar; do
    grep -qF "WEB-INF/lib/$(basename "$j")" <<<"$war_listing" \
      || { echo "ERROR: module jar $(basename "$j") not present in war"; exit 1; }
  done
  grep -E "WEB-INF/lib/.*\.jar" <<<"$war_listing" || true
else
  grep -E "pf-oidf-modules" <<<"$war_listing" || { echo "ERROR: module jar not present in war"; exit 1; }
fi
for mapping in SsfLogoutSignal ClientAttestationAuth OidfAutoRegistration OidfFrontChannelAutoRegistration Fapi2Profile FapiResourceServer OAuthErrorDescription; do
  grep -q "$mapping" <<<"$war_web_xml" \
    || { echo "ERROR: $mapping filter mapping not present in assembled war" >&2; exit 1; }
done
# Order is load-bearing, not cosmetic (see the OidfAutoRegistration block): the LAST occurrence of each
# name is its <filter-mapping>, and auto-registration's must come first. This also catches a bad order
# baked into a stock web.xml, which the "already registered — leaving as is" branches would skip over.
_mapping_line() { grep -n "<filter-name>$1</filter-name>" <<<"$war_web_xml" | tail -1 | cut -d: -f1; }
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
_frontchannel_at="$(_mapping_line OidfFrontChannelAutoRegistration)"; _description_at="$(_mapping_line OAuthErrorDescription)"
[ -n "$_frontchannel_at" ] && [ "$_fapi2_at" -lt "$_frontchannel_at" ] && [ "$_description_at" -lt "$_frontchannel_at" ] || {
  echo "ERROR: filter order wrong in $OUT_WAR - OidfFrontChannelAutoRegistration (line ${_frontchannel_at:-?}) must be" >&2
  echo "       mapped after Fapi2Profile (line $_fapi2_at) and OAuthErrorDescription (line ${_description_at:-?}): a" >&2
  echo "       PAR assertion FAPI 2.0 refuses must not register a client, and its refusals need the sanitiser." >&2
  exit 1; }
echo "verified: SsfLogoutSignal + Fapi2Profile + OidfAutoRegistration + OidfFrontChannelAutoRegistration + ClientAttestationAuth + FapiResourceServer + OAuthErrorDescription mapped in $OUT_WAR (order checked)"
