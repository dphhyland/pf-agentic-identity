/*
 * IssuanceClientResolver backed by an OpenID Federation entity configuration.
 */
package com.pingidentity.ps.oidf.issuer;

import com.pingidentity.ps.oidf.federation.FederationError;
import com.pingidentity.ps.oidf.federation.FederationException;
import com.pingidentity.ps.oidf.federation.TrustChainValidationResult;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.federation.ValidationRequest;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwt.JwtClaims;

/**
 * Resolves the attester's clients from an <strong>OpenID Federation</strong> entity. The entity's trust chain is
 * validated to one of the deployment's pinned trust anchors (OpenID Federation 1.0 §10), and the SPIFFE-ID →
 * OAuth-client bindings are read from the {@code spiffe_client_bindings} claim of its <em>verified</em> Entity
 * Configuration. So the mapping - and each client's entitlement ceiling (downscoping) - is governed by a
 * federation the attester trusts, rather than by a flat file, the local PF store, or whoever answers at the
 * entity's URL.
 *
 * <p>This is the federation-native counterpart of {@link CimdClientResolver}: same binding shape (each
 * entry carries {@code spiffe_id}, {@code client_id}, evidence trust config and an {@code entitlement}
 * ceiling). The attester signing key stays deployment config, never in the statement.
 *
 * <p>The answer is kept for {@code ttlSeconds}. When the federation cannot be reached, the last answer stands:
 * an outage is not evidence against anyone. When the chain no longer validates - the anchor, or a superior,
 * stopped vouching for the entity - the kept answer is dropped and its clients are refused, so revoking the
 * entity at the anchor stops issuance within one TTL.
 */
public final class OpenIdFederationClientResolver implements IssuanceClientResolver {
    private static final Log LOGGER = LogFactory.getLog(OpenIdFederationClientResolver.class);

    public static final long DEFAULT_TTL_SECONDS = 300L;
    private static final String BINDINGS_CLAIM = "spiffe_client_bindings";

    private final String entityUrl;
    private final TrustChainValidator validator;
    private final long ttlSeconds;
    private final String defaultSigningJwk;
    private final Clock clock;

    private volatile List<AttesterClient> cached;
    private volatile long cachedAtEpochSeconds;

    public OpenIdFederationClientResolver(String entityUrl, TrustChainValidator validator, String defaultSigningJwk) {
        this(entityUrl, validator, DEFAULT_TTL_SECONDS, defaultSigningJwk, Clock.systemUTC());
    }

    public OpenIdFederationClientResolver(String entityUrl, TrustChainValidator validator, long ttlSeconds, String defaultSigningJwk,
                                          Clock clock) {
        this.entityUrl = entityUrl.endsWith("/") ? entityUrl.substring(0, entityUrl.length() - 1) : entityUrl;
        this.validator = Objects.requireNonNull(validator, "validator");
        this.ttlSeconds = ttlSeconds;
        this.defaultSigningJwk = defaultSigningJwk;
        this.clock = Objects.requireNonNull(clock, "clock");
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
        long now = this.clock.instant().getEpochSecond();
        List<AttesterClient> local = this.cached;
        if (local != null && now - this.cachedAtEpochSeconds < this.ttlSeconds) {
            return local;
        }
        TrustChainValidationResult validated;
        try {
            // Statements older than the TTL are fetched afresh rather than taken from the validator's cache, so an
            // anchor that stops vouching for the entity is heard within one TTL, not when its last statement expires.
            validated = this.validator.validate(ValidationRequest.forSubject(this.entityUrl)
                    .maxLeafAgeSeconds(this.ttlSeconds)
                    .maxAnchorAgeSeconds(this.ttlSeconds)
                    .build());
        } catch (FederationException e) {
            if (e.error() == FederationError.TEMPORARILY_UNAVAILABLE) {
                if (local != null) {
                    LOGGER.warn("Federation entity " + this.entityUrl + " could not be reached; its clients stand as last validated");
                    return local;
                }
                throw IssuanceException.serverError("the federation entity " + this.entityUrl + " could not be reached");
            }
            this.cached = null;
            throw IssuanceException.invalidClient("the federation entity " + this.entityUrl
                    + " does not validate to a trusted anchor (" + e.error().code() + "), so none of its clients is");
        }
        List<AttesterClient> parsed = this.parse(validated.leafEntityStatement());
        this.cached = parsed;
        this.cachedAtEpochSeconds = now;
        return parsed;
    }

    @SuppressWarnings("unchecked")
    private List<AttesterClient> parse(JwtClaims verified) throws IssuanceException {
        Object bindings = verified.getClaimValue(BINDINGS_CLAIM);
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
