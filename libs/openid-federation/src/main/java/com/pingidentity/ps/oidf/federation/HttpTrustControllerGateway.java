package com.pingidentity.ps.oidf.federation;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwt.JwtClaims;
import com.pingidentity.ps.oidf.jose.HttpGetClient;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.jose.Claims;
import com.pingidentity.ps.oidf.jose.VerificationPolicy;

/**
 * HTTP-backed {@link TrustControllerGateway}. Fetches entity configurations, member lists and
 * subordinate statements over HTTP (resolving each authority's {@code federation_fetch_endpoint}
 * on demand) and caches statements in a {@link SubordinateStatementCache}, honouring optional
 * max-age freshness bounds and staging writes into a supplied {@link SubordinateStatementCache.PendingWrites}.
 */
public final class HttpTrustControllerGateway
implements TrustControllerGateway {
    private static final Log LOGGER = LogFactory.getLog(HttpTrustControllerGateway.class);
    private static final String ENTITY_STATEMENT_ACCEPT = "application/entity-statement+jwt, application/json";
    private static final String JSON_ACCEPT = "application/json";
    private final HttpGetClient http;
    private final String trustControllerBaseUrl;
    private final String selfIssuer;
    private final SubordinateStatementCache subordinateStatementCache;
    /** The bound anchors, by {@link EntityId#comparable} identifier. */
    private final Map<String, Binding> anchors = new ConcurrentHashMap<>();

    /** An anchor and the algorithms its statements may use. */
    private record Binding(TrustAnchor anchor, Set<String> acceptedSigningAlgorithms) {
    }

    public HttpTrustControllerGateway(HttpGetClient http, String trustControllerBaseUrl) {
        this(http, trustControllerBaseUrl, null, new SubordinateStatementCache());
    }

    public HttpTrustControllerGateway(HttpGetClient http, String trustControllerBaseUrl, SubordinateStatementCache subordinateStatementCache) {
        this(http, trustControllerBaseUrl, null, subordinateStatementCache);
    }

    /**
     * @param selfIssuer the trust controller's own federation identity (a bare, possibly
     *     path-less issuer string, e.g. PF's self-computed OAuth issuer) — distinct from
     *     {@code trustControllerBaseUrl}, which is the HTTP base actually needed to reach it (may
     *     carry a context path such as {@code /oidf}). When an {@code issuer}/{@code authorityIssuer}
     *     parameter passed to a fetch method equals this value, the fetch is redirected to
     *     {@code trustControllerBaseUrl} instead of constructing a URL from the identity string
     *     directly — otherwise a self-referential fetch (the trust controller resolving a chain that
     *     bottoms out at itself) would try to reach its own {@code .well-known} at its bare identity
     *     path, which is frequently not where it's actually served. Pass {@code null} to disable this
     *     (matches the pre-existing behaviour, appropriate when this gateway never needs to fetch its
     *     own trust controller's statements).
     */
    public HttpTrustControllerGateway(HttpGetClient http, String trustControllerBaseUrl, String selfIssuer) {
        this(http, trustControllerBaseUrl, selfIssuer, new SubordinateStatementCache());
    }

    public HttpTrustControllerGateway(HttpGetClient http, String trustControllerBaseUrl, String selfIssuer, SubordinateStatementCache subordinateStatementCache) {
        this.http = Objects.requireNonNull(http, "http");
        this.trustControllerBaseUrl = normalizeBaseUrl(Objects.requireNonNull(trustControllerBaseUrl, "trustControllerBaseUrl"));
        this.selfIssuer = selfIssuer;
        this.subordinateStatementCache = Objects.requireNonNull(subordinateStatementCache, "subordinateStatementCache");
    }

    @Override
    public JwtClaims fetchEntityConfiguration() throws Exception {
        String url = this.trustControllerBaseUrl + "/.well-known/openid-federation";
        String jwt = this.http.get(url, ENTITY_STATEMENT_ACCEPT);
        EntityStatementType.require(jwt, "from " + url);
        return JwtCodec.parseUnverifiedClaims(jwt);
    }

    @Override
    public List<String> fetchMembers() throws Exception {
        String body = this.http.get(this.trustControllerBaseUrl + "/list", JSON_ACCEPT);
        ObjectMapper mapper = new ObjectMapper();
        List<String> items = mapper.readValue(body, new TypeReference<List<String>>(){});
        return toStringList(items);
    }

    @Override
    public String fetchEntityStatement(String issuer) throws Exception {
        return this.fetchEntityStatement(issuer, -1L, null);
    }

    @Override
    public String fetchEntityStatement(String issuer, long maxAgeFromIatSeconds) throws Exception {
        return this.fetchEntityStatement(issuer, maxAgeFromIatSeconds, null);
    }

    @Override
    public String fetchEntityStatement(String issuer, long maxAgeFromIatSeconds, SubordinateStatementCache.PendingWrites pendingWrites) throws Exception {
        Objects.requireNonNull(issuer, "issuer");
        String cached = this.subordinateStatementCache.get(issuer, issuer, 300L, maxAgeFromIatSeconds);
        if (cached != null) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(String.format("fetchEntityStatement-cache-found: issuer(%s)", issuer));
            }
            return cached;
        }
        String pending = pendingWrites != null ? pendingWrites.find(issuer, issuer) : null;
        if (pending != null) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(String.format("fetchEntityStatement-pending-found: issuer(%s)", issuer));
            }
            return pending;
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(String.format("fetchEntityStatement-cache-not-found: issuer(%s)", issuer));
        }
        String jwt = this.http.get(this.entityConfigurationUrl(issuer), ENTITY_STATEMENT_ACCEPT);
        this.recordCacheWrite(issuer, issuer, jwt, pendingWrites);
        return jwt;
    }

    /**
     * A self-referential fetch (issuer is the trust controller itself) uses the actual reachable base
     * URL rather than appending .well-known to the bare identity string — see selfIssuer javadoc.
     */
    private String entityConfigurationUrl(String issuer) {
        if (this.selfIssuer != null && EntityId.same(issuer, this.selfIssuer)) {
            return this.trustControllerBaseUrl + "/.well-known/openid-federation";
        }
        // §9: a trailing "/" is removed before /.well-known/openid-federation is appended.
        return EntityId.wellKnownUrl(issuer);
    }

    /**
     * Adds an anchor, or replaces the one bound under the same Entity Identifier. Several validators, or one
     * validator with several anchors, can share this gateway and its cache: an anchor's Entity Configuration
     * is only ever verified with the keys bound for the identifier it claims, so one anchor's keys never vouch
     * for another's configuration.
     */
    @Override
    public void bindTrustAnchor(TrustAnchor trustAnchor, Set<String> acceptedSigningAlgorithms) {
        Objects.requireNonNull(trustAnchor, "trustAnchor");
        this.anchors.put(EntityId.comparable(trustAnchor.entityId()), new Binding(trustAnchor,
                acceptedSigningAlgorithms == null ? Set.of() : Set.copyOf(acceptedSigningAlgorithms)));
    }

    /** The anchor's Entity Configuration, verified against its configured keys (see {@link #authorityConfiguration}). */
    @Override
    public String anchorConfiguration(TrustAnchor anchor, Set<String> acceptedSigningAlgorithms,
            SubordinateStatementCache.PendingWrites pendingWrites) throws Exception {
        return this.verifiedAnchorConfiguration(new Binding(anchor, acceptedSigningAlgorithms == null ? Set.of()
                : Set.copyOf(acceptedSigningAlgorithms)), pendingWrites);
    }

    /**
     * The Entity Configuration of an authority whose fetch endpoint is needed.
     *
     * <p>For the bound Trust Anchor, OpenID Federation 1.0 §10.2 requires ES[i] — the anchor's Entity
     * Configuration — to validate with a public key of the anchor, and §4 distributes those keys out of
     * band. It is therefore verified against the configured keys, never believed because HTTPS
     * delivered it: its {@code federation_fetch_endpoint} decides where every subordinate statement is
     * requested from. §11.3 treats a mismatch between the out-of-band keys and the Entity Configuration
     * as something to retrieve again before concluding, so a copy that does not verify (a stale cache
     * entry after a legitimate rollover, a transient bad response) is dropped and fetched once more;
     * failing again is a security or configuration problem and the chain is refused.
     *
     * <p>Verifying the signature rather than comparing key sets for equality is deliberate: during a
     * §11.2 rollover the anchor publishes its new keys alongside the old before operators have updated
     * the pinned set, and a configuration signed by a pinned key is the anchor speaking either way.
     *
     * <p>Any other authority's Entity Configuration is only a directory entry here. What it points at
     * is a Subordinate Statement that the chain verifies against the keys its own superior asserts.
     */
    private JwtClaims authorityConfiguration(String authorityIssuer, SubordinateStatementCache.PendingWrites pendingWrites) throws Exception {
        Binding binding = this.anchors.get(EntityId.comparable(authorityIssuer));
        if (binding == null) {
            return this.fetchEntityConfigurationOf(authorityIssuer, pendingWrites);
        }
        return JwtCodec.parseUnverifiedClaims(this.verifiedAnchorConfiguration(binding, pendingWrites));
    }

    /** The anchor's Entity Configuration as a JWT, verified against its configured keys, with the §11.3 retry. */
    private String verifiedAnchorConfiguration(Binding binding, SubordinateStatementCache.PendingWrites pendingWrites) throws Exception {
        TrustAnchor anchor = binding.anchor();
        String authorityIssuer = anchor.entityId();
        String jwt = this.fetchEntityStatement(authorityIssuer, -1L, pendingWrites);
        // §3 before §10.2: an untyped configuration is refused outright, not retried - a retry could
        // only return the same wrong type, and no key should be tried on it.
        EntityStatementType.require(jwt, "iss=sub=" + authorityIssuer);
        try {
            anchor.verify(jwt, binding.acceptedSigningAlgorithms(), VerificationPolicy.entityStatement());
            return jwt;
        }
        catch (Exception first) {
            LOGGER.warn("Trust anchor " + authorityIssuer + " entity configuration did not verify against the configured keys ("
                    + first.getMessage() + "); retrieving it again (OpenID Federation 1.0 §11.3)");
            this.subordinateStatementCache.evict(authorityIssuer, authorityIssuer);
            String again = this.http.get(this.entityConfigurationUrl(authorityIssuer), ENTITY_STATEMENT_ACCEPT);
            EntityStatementType.require(again, "iss=sub=" + authorityIssuer);
            try {
                anchor.verify(again, binding.acceptedSigningAlgorithms(), VerificationPolicy.entityStatement());
            }
            catch (Exception second) {
                throw new IllegalStateException("Trust anchor " + authorityIssuer + " entity configuration does not verify against the"
                        + " configured trust anchor keys, on two retrievals: a security or configuration problem (OpenID Federation 1.0"
                        + " §11.3). Check whether the anchor has rolled its keys and the pinned JWKS needs updating, or whether "
                        + authorityIssuer + " is being served by something other than the anchor", second);
            }
            // Staged writes are read newest-first and committed in order, so this verified copy
            // supersedes the one that failed, both for the rest of this walk and in the shared cache.
            this.recordCacheWrite(authorityIssuer, authorityIssuer, again, pendingWrites);
            return again;
        }
    }

    @Override
    public JwtClaims fetchEntityConfigurationOf(String issuer, SubordinateStatementCache.PendingWrites pendingWrites) throws Exception {
        // Its federation_fetch_endpoint decides where subordinate statements are requested from, so an
        // untyped configuration is refused here (OpenID Federation 1.0 §3), not only once it is in a chain.
        String jwt = this.fetchEntityStatement(issuer, -1L, pendingWrites);
        EntityStatementType.require(jwt, "iss=sub=" + issuer);
        return JwtCodec.parseUnverifiedClaims(jwt);
    }

    @Override
    public String fetchSubordinateStatement(String authorityIssuer, String subject) throws Exception {
        return this.fetchSubordinateStatement(authorityIssuer, subject, -1L, null);
    }

    @Override
    public String fetchSubordinateStatement(String authorityIssuer, String subject, long maxAgeFromIatSeconds) throws Exception {
        return this.fetchSubordinateStatement(authorityIssuer, subject, maxAgeFromIatSeconds, null);
    }

    @Override
    public String fetchSubordinateStatement(String authorityIssuer, String subject, long maxAgeFromIatSeconds, SubordinateStatementCache.PendingWrites pendingWrites) throws Exception {
        String endpoint;
        JwtClaims authorityConfig;
        Map<String, Object> federationEntity;
        Object endpointValue;
        Objects.requireNonNull(authorityIssuer, "authorityIssuer");
        Objects.requireNonNull(subject, "subject");
        String cached = this.subordinateStatementCache.get(authorityIssuer, subject, 300L, maxAgeFromIatSeconds);
        if (cached != null) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(String.format("fetchSubordinateStatement-cache-found: issuer(%s) subject(%s)", authorityIssuer, subject));
            }
            return cached;
        }
        String pending = pendingWrites != null ? pendingWrites.find(authorityIssuer, subject) : null;
        if (pending != null) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(String.format("fetchSubordinateStatement-pending-found: issuer(%s) subject(%s)", authorityIssuer, subject));
            }
            return pending;
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(String.format("fetchSubordinateStatement-cache-not-found: issuer(%s) subject(%s)", authorityIssuer, subject));
        }
        if (!((endpointValue = (federationEntity = Claims.optionalNestedMap(Claims.optionalMap(authorityConfig = this.authorityConfiguration(authorityIssuer, pendingWrites), "metadata"), "federation_entity")).get("federation_fetch_endpoint")) instanceof String) || ((String)endpointValue).isBlank()) {
            throw new IllegalStateException("Authority " + authorityIssuer + " does not publish a federation_fetch_endpoint and cannot resolve subordinate statements");
        }
        endpoint = (String)endpointValue;
        // §8.1.1 defines sub alone. iss is sent too, for fetch endpoints built to earlier drafts that required
        // it; §8 says a parameter an endpoint does not understand "MUST be ignored", so a Final one is unaffected.
        String url = endpoint + (endpoint.contains("?") ? "&" : "?")
                + "sub=" + URLEncoder.encode(subject, StandardCharsets.UTF_8)
                + "&iss=" + URLEncoder.encode(authorityIssuer, StandardCharsets.UTF_8);
        String jwt = this.http.get(url, "application/entity-statement+jwt");
        this.recordCacheWrite(authorityIssuer, subject, jwt, pendingWrites);
        return jwt;
    }

    @Override
    public SubordinateStatementCache.PendingWrites newPendingWrites() {
        return this.subordinateStatementCache.newPendingWrites();
    }

    @Override
    public void evictCachedStatement(String issuer, String subject) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(String.format("evictCachedStatement: issuer(%s) subject(%s)", issuer, subject));
        }
        this.subordinateStatementCache.evict(issuer, subject);
    }

    private void recordCacheWrite(String authorityIssuer, String subject, String jwt, SubordinateStatementCache.PendingWrites pendingWrites) {
        Long expSeconds = tryExtractExpEpochSeconds(jwt);
        if (expSeconds == null) {
            return;
        }
        Long iatSeconds = tryExtractIatEpochSeconds(jwt);
        long iatValue = iatSeconds != null ? iatSeconds : 0L;
        if (pendingWrites != null) {
            pendingWrites.stagePut(authorityIssuer, subject, jwt, expSeconds, iatValue);
        } else {
            this.subordinateStatementCache.put(authorityIssuer, subject, jwt, expSeconds, iatValue);
        }
    }

    private static Long tryExtractExpEpochSeconds(String jwt) {
        JwtClaims claims;
        block3: {
            try {
                claims = JwtCodec.parseUnverifiedClaims(jwt);
                if (claims.hasClaim("exp")) break block3;
                return null;
            }
            catch (Exception e) {
                LOGGER.debug("Failed to parse exp claim from subordinate statement; will not cache: " + e.getMessage());
                return null;
            }
        }
        try {
            return claims.getExpirationTime().getValue();
        }
        catch (org.jose4j.jwt.MalformedClaimException e) {
            return null;
        }
    }

    private static Long tryExtractIatEpochSeconds(String jwt) {
        JwtClaims claims;
        block3: {
            try {
                claims = JwtCodec.parseUnverifiedClaims(jwt);
                if (claims.hasClaim("iat")) break block3;
                return null;
            }
            catch (Exception e) {
                LOGGER.debug("Failed to parse iat claim from subordinate statement; will cache without age bound: " + e.getMessage());
                return null;
            }
        }
        try {
            return claims.getIssuedAt().getValue();
        }
        catch (org.jose4j.jwt.MalformedClaimException e) {
            return null;
        }
    }

    private static List<String> toStringList(List<?> list) {
        ArrayList<String> result = new ArrayList<String>();
        for (Object item : list) {
            result.add(String.valueOf(item));
        }
        return result;
    }

    private static String normalizeBaseUrl(String baseUrl) {
        return baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    }
}

