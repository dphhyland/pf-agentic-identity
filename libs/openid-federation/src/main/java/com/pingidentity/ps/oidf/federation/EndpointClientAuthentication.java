/*
 * A client authenticating at a federation endpoint.
 */
package com.pingidentity.ps.oidf.federation;

import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.jose.JwtVerificationException;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Semaphore;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.JwtClaims;

/**
 * OpenID Federation 1.0 §8.8: {@code private_key_jwt} at a federation endpoint. The client authentication JWT "MUST be
 * signed with a Federation Entity Key", its audience "MUST be the Entity Identifier of the Entity whose federation endpoint
 * is being authenticated to", and the endpoint "MUST NOT accept JWTs containing audience values other than its Entity
 * Identifier". The key is the client's own, as its Entity Configuration publishes it once its chain has validated to an
 * anchor this entity trusts: anyone can publish an Entity Configuration, only a member of the federation has one that
 * resolves. As OpenID Connect Core §9 has it: {@code iss} and {@code sub} the client, {@code exp}, and a {@code jti} used
 * once.
 */
public final class EndpointClientAuthentication {
    /** RFC 7523's assertion type, which {@code client_assertion_type} must be. */
    static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    static final long CLOCK_SKEW_SECONDS = 60L;
    /**
     * How far off an assertion's {@code exp} may be. Its {@code jti} is remembered until then, so one that lived longer
     * would outlast the record of its use.
     */
    static final long MAX_LIFETIME_SECONDS = 600L;
    /** Clients whose chains are resolved at once; the rest are told to come back (§18.1). */
    static final int MAX_CONCURRENT_RESOLUTIONS = 8;

    /** Where a spent {@code jti} is recorded: true the first time a client's {@code jti} is seen, false after. */
    @FunctionalInterface
    public interface JtiGuard {
        boolean firstSeen(String clientId, String jti, long ttlSeconds);
    }

    private final Set<String> algorithms;
    private final Clock clock;
    private final JtiGuard spent;
    private final Semaphore resolutions;

    EndpointClientAuthentication(Set<String> algorithms, Clock clock, JtiGuard spent) {
        this(algorithms, clock, spent, MAX_CONCURRENT_RESOLUTIONS);
    }

    EndpointClientAuthentication(Set<String> algorithms, Clock clock, JtiGuard spent, int maxConcurrentResolutions) {
        this.algorithms = Set.copyOf(algorithms);
        this.clock = Objects.requireNonNull(clock, "clock");
        this.spent = Objects.requireNonNull(spent, "spent");
        this.resolutions = new Semaphore(maxConcurrentResolutions);
    }

    /**
     * @param validator resolves the client's chain to an anchor this entity trusts
     * @param audience  this entity's Entity Identifier
     * @return the client's Entity Identifier
     * @throws FederationException {@code invalid_client} (401) when it does not authenticate; {@code temporarily_unavailable}
     *                             when its federation cannot be reached to find out
     */
    String authenticate(TrustChainValidator validator, String assertionType, String assertion, String audience) {
        if (!ASSERTION_TYPE.equals(assertionType)) {
            throw refused("client_assertion_type must be " + ASSERTION_TYPE);
        }
        Map<String, Object> header;
        JwtClaims claims;
        try {
            header = JwtCodec.getJwtHeaders(assertion);
            claims = JwtCodec.parseUnverifiedClaims(assertion);
        } catch (Exception e) {
            throw refused("the client assertion is not a signed JWT");
        }
        if (!(header.get("kid") instanceof String kid) || kid.isBlank()) {
            throw refused("the client assertion names no kid: it is checked with exactly the key it names");
        }
        String client = claims.getClaimValue("iss") instanceof String s ? s : null;
        if (client == null || !EntityId.isValid(client) || !client.equals(claims.getClaimValue("sub"))) {
            throw refused("the client assertion's iss and sub must both be the client's Entity Identifier");
        }
        if (!onlyAudience(claims.getClaimValue("aud"), audience)) {
            throw refused("the client assertion's aud must be " + audience + " and nothing else (OpenID Federation 1.0 §8.8)");
        }
        long now = this.clock.instant().getEpochSecond();
        if (!(claims.getClaimValue("exp") instanceof Number exp) || exp.longValue() <= now - CLOCK_SKEW_SECONDS) {
            throw refused("the client assertion has no exp, or has expired");
        }
        if (exp.longValue() > now + MAX_LIFETIME_SECONDS) {
            throw refused("the client assertion expires more than " + MAX_LIFETIME_SECONDS / 60 + " minutes from now");
        }
        Object iat = claims.getClaimValue("iat");
        if (iat != null && !(iat instanceof Number issued && issued.longValue() <= now + CLOCK_SKEW_SECONDS)) {
            throw refused("the client assertion's iat is not a time in the past");
        }
        if (!(claims.getClaimValue("jti") instanceof String jti) || jti.isBlank()) {
            throw refused("the client assertion has no jti");
        }
        // Anyone can send an assertion naming any client, and finding a client's keys can take a couple of dozen fetches:
        // only so many are looked up at once.
        if (!this.resolutions.tryAcquire()) {
            throw new FederationException(FederationError.TEMPORARILY_UNAVAILABLE, "too many clients are being checked at once;"
                    + " try again shortly");
        }
        List<JsonWebKey> keys;
        try {
            keys = federationKeys(validator, client);
        } finally {
            this.resolutions.release();
        }
        try {
            JwtCodec.verifySignature(assertion, keys, this.algorithms);
        } catch (JwtVerificationException e) {
            throw refused("the client assertion is not signed with one of the client's Federation Entity Keys (" + e.code() + ")");
        }
        // Until the assertion could no longer be used: exp, plus the skew allowed on it.
        long window = Math.max(CLOCK_SKEW_SECONDS, exp.longValue() - now + CLOCK_SKEW_SECONDS);
        if (!this.spent.firstSeen(client, jti, window)) {
            throw refused("the client assertion has been used before (its jti is spent)");
        }
        return client;
    }

    /** The client's Federation Entity Keys: the {@code jwks} of its Entity Configuration, once its chain has validated. */
    private static List<JsonWebKey> federationKeys(TrustChainValidator validator, String client) {
        TrustChainValidationResult chain;
        try {
            chain = validator.validate(ValidationRequest.forSubject(client).build());
        } catch (FederationException e) {
            if (e.error() == FederationError.TEMPORARILY_UNAVAILABLE) {
                throw e;
            }
            throw refused("the client's trust chain does not validate to an anchor this entity trusts: " + e.description());
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> jwks = (Map<String, Object>) chain.leafEntityStatement().getClaimValue("jwks");
        return Jwks.parseFederationKeySet(jwks);
    }

    private static boolean onlyAudience(Object aud, String audience) {
        if (aud instanceof String s) {
            return EntityId.same(s, audience);
        }
        return aud instanceof List<?> list && list.size() == 1 && list.get(0) instanceof String s && EntityId.same(s, audience);
    }

    private static FederationException refused(String description) {
        return new FederationException(FederationError.INVALID_CLIENT, description);
    }
}
