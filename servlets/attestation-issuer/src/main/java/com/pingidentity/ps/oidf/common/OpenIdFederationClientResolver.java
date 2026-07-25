/*
 * IssuanceClientResolver backed by an OpenID Federation entity configuration.
 */
package com.pingidentity.ps.oidf.common;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.jwt.JwtClaims;

/**
 * Resolves the attester's clients from an <strong>OpenID Federation</strong> entity. The attester fetches
 * a federation entity's configuration (a signed Entity Statement at
 * {@code <entity>/.well-known/openid-federation}), verifies it against the entity's own published JWKS,
 * and reads the SPIFFE-ID → OAuth-client bindings from a {@code spiffe_client_bindings} metadata claim.
 * This lets the mapping — and each client's entitlement ceiling (downscoping) — be governed by a
 * federation the attester trusts, rather than a flat file or the local PF store.
 *
 * <p>This is the federation-native counterpart of {@link CimdClientResolver}: same binding shape (each
 * entry carries {@code spiffe_id}, {@code client_id}, evidence trust config and an {@code entitlement}
 * ceiling), but delivered inside a signed, self-describing federation entity statement. Full trust-chain
 * validation to an anchor is the natural extension (the {@code openid-federation} library validates
 * chains); this resolver verifies the entity's self-signature and issuer, which is the minimum that makes
 * the document tamper-evident. The attester signing key stays deployment config, never in the statement.
 */
public final class OpenIdFederationClientResolver implements IssuanceClientResolver {

    public static final long DEFAULT_TTL_SECONDS = 300L;
    private static final String BINDINGS_CLAIM = "spiffe_client_bindings";

    private final String entityUrl;
    private final HttpGetClient http;
    private final long ttlSeconds;
    private final String defaultSigningJwk;

    private volatile List<AttesterClient> cached;
    private volatile long cachedAtEpochSeconds;

    public OpenIdFederationClientResolver(String entityUrl, String defaultSigningJwk) {
        this(entityUrl, new JdkHttpGetClient(false), DEFAULT_TTL_SECONDS, defaultSigningJwk);
    }

    public OpenIdFederationClientResolver(String entityUrl, HttpGetClient http, long ttlSeconds,
            String defaultSigningJwk) {
        this.entityUrl = entityUrl.endsWith("/") ? entityUrl.substring(0, entityUrl.length() - 1) : entityUrl;
        this.http = http;
        this.ttlSeconds = ttlSeconds;
        this.defaultSigningJwk = defaultSigningJwk;
    }

    @Override
    public String pluginId() {
        return ClientResolverPlugins.OPENID_FEDERATION;
    }

    @Override
    public AttestationIssuanceConfig resolve(String clientId) throws IssuanceException {
        for (AttesterClient c : attestationClients()) {
            if (c.clientId().equals(clientId)) {
                return c.config();
            }
        }
        throw IssuanceException.invalidClient("unknown client: " + clientId);
    }

    @Override
    public List<AttesterClient> attestationClients() throws IssuanceException {
        long now = System.currentTimeMillis() / 1000L;
        List<AttesterClient> local = this.cached;
        if (local != null && now - this.cachedAtEpochSeconds < this.ttlSeconds) {
            return local;
        }
        String entityConfig;
        try {
            entityConfig = this.http.get(this.entityUrl + "/.well-known/openid-federation", "application/entity-statement+jwt");
        } catch (Exception e) {
            if (local != null) {
                return local;
            }
            throw IssuanceException.serverError("federation entity configuration could not be fetched: " + this.entityUrl);
        }
        List<AttesterClient> parsed = parse(entityConfig);
        this.cached = parsed;
        this.cachedAtEpochSeconds = now;
        return parsed;
    }

    @SuppressWarnings("unchecked")
    private List<AttesterClient> parse(String entityStatementJwt) throws IssuanceException {
        JwtClaims claims;
        try {
            // The Entity Configuration is self-issued and self-signed: verify it against the JWKS it
            // publishes (iss == the entity, sub == the entity). This is the tamper-evidence floor.
            Map<String, Object> unverified = JwtCodec.parseUnverifiedClaims(entityStatementJwt).getClaimsMap();
            Object jwks = unverified.get("jwks");
            if (!(jwks instanceof Map)) {
                throw new IllegalArgumentException("entity statement has no jwks");
            }
            claims = JwtCodec.verifyAgainstInlineJwks(entityStatementJwt, (Map<String, Object>) jwks, this.entityUrl);
        } catch (IssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw IssuanceException.serverError("federation entity statement did not verify: " + e.getMessage());
        }

        Object bindings;
        try {
            bindings = claims.getClaimValue(BINDINGS_CLAIM);
        } catch (Exception e) {
            bindings = null;
        }
        if (!(bindings instanceof List)) {
            throw IssuanceException.serverError("federation entity carries no '" + BINDINGS_CLAIM + "' claim");
        }
        List<AttesterClient> out = new ArrayList<>();
        for (Object item : (List<Object>) bindings) {
            if (!(item instanceof Map)) {
                continue;
            }
            Map<String, Object> entry = (Map<String, Object>) item;
            String clientId = str(entry.get("client_id"));
            String spiffeId = str(entry.get("spiffe_id"));
            if (clientId == null || spiffeId == null) {
                continue;
            }
            out.add(new AttesterClient(clientId, CimdMapping.toConfig(entry, spiffeId, this.defaultSigningJwk)));
        }
        return out;
    }

    private static String str(Object o) {
        return o == null ? null : String.valueOf(o);
    }
}
