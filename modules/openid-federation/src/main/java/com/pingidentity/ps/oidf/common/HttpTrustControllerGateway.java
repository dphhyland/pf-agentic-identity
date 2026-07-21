package com.pingidentity.ps.oidf.common;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwt.JwtClaims;

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
    private final SubordinateStatementCache subordinateStatementCache;

    public HttpTrustControllerGateway(HttpGetClient http, String trustControllerBaseUrl) {
        this(http, trustControllerBaseUrl, new SubordinateStatementCache());
    }

    public HttpTrustControllerGateway(HttpGetClient http, String trustControllerBaseUrl, SubordinateStatementCache subordinateStatementCache) {
        this.http = Objects.requireNonNull(http, "http");
        this.trustControllerBaseUrl = normalizeBaseUrl(Objects.requireNonNull(trustControllerBaseUrl, "trustControllerBaseUrl"));
        this.subordinateStatementCache = Objects.requireNonNull(subordinateStatementCache, "subordinateStatementCache");
    }

    @Override
    public JwtClaims fetchEntityConfiguration() throws Exception {
        String url = this.trustControllerBaseUrl + "/.well-known/openid-federation";
        return JwtCodec.parseUnverifiedClaims(this.http.get(url, ENTITY_STATEMENT_ACCEPT));
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
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(String.format("fetchEntityStatement-cache-not-found: issuer(%s)", issuer));
        }
        String jwt = this.http.get(issuer + "/.well-known/openid-federation", ENTITY_STATEMENT_ACCEPT);
        this.recordCacheWrite(issuer, issuer, jwt, pendingWrites);
        return jwt;
    }

    @Override
    public JwtClaims fetchEntityConfigurationOf(String issuer, SubordinateStatementCache.PendingWrites pendingWrites) throws Exception {
        return JwtCodec.parseUnverifiedClaims(this.fetchEntityStatement(issuer, -1L, pendingWrites));
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
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(String.format("fetchSubordinateStatement-cache-not-found: issuer(%s) subject(%s)", authorityIssuer, subject));
        }
        if (!((endpointValue = (federationEntity = Claims.optionalNestedMap(Claims.optionalMap(authorityConfig = this.fetchEntityConfigurationOf(authorityIssuer, pendingWrites), "metadata"), "federation_entity")).get("federation_fetch_endpoint")) instanceof String) || ((String)endpointValue).isBlank()) {
            throw new IllegalStateException("Authority " + authorityIssuer + " does not publish a federation_fetch_endpoint and cannot resolve subordinate statements");
        }
        endpoint = (String)endpointValue;
        String url = endpoint + (endpoint.contains("?") ? "&" : "?") + "sub=" + URLEncoder.encode(subject, StandardCharsets.UTF_8);
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

