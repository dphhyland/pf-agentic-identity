package com.pingidentity.ps.oidf.servlet.trustanchor;

import com.pingidentity.ps.oidf.common.HttpGetClient;
import com.pingidentity.ps.oidf.common.JwtCodec;
import com.pingidentity.ps.oidf.common.SigningKeyProvider;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

/**
 * Builds and signs the trust-anchor federation's own artifacts: its entity configuration,
 * entity/subordinate statements, {@code .well-known} federation metadata, and resolved trust
 * chains. Statements are RSA-signed with the configured algorithm and an inline JWKS derived
 * from the {@link SigningKeyProvider}.
 *
 * <p>Subordinate statements about a <em>foreign</em> configured subordinate embed that entity's
 * own keys, learned by fetching its self-signed entity configuration from
 * {@code <subject>/.well-known/openid-federation} (cached briefly). This is what makes the anchor's
 * vouching meaningful: a validator verifies the subordinate's self-statement against the keys the
 * anchor asserts, so those keys must be the subordinate's, not the anchor's.
 *
 * <p>A subordinate that is instead <em>hosted</em> by this same authority (see
 * {@code com.pingidentity.ps.oidf.authority} — an ephemeral entity with no HTTPS endpoint of its own to
 * fetch) is resolved by {@code hostedEntityJwksLookup} first, ahead of and bypassing
 * {@link #subordinateConfigCache} entirely: a revoked hosted entity must stop resolving on the very next
 * call, not after a cache TTL. Deliberately a plain {@code subject -> jwks-or-null} function rather than
 * a direct dependency on the {@code authority} package's types, so this class and its existing tests
 * stay unaware of — and unaffected by — that package's own (static, process-wide) state.
 */
final class FederationService {
    private static final String ENTITY_STATEMENT_TYP = "entity-statement+jwt";
    private static final String ENTITY_STATEMENT_ACCEPT = "application/entity-statement+jwt, application/json";
    private static final long SUBORDINATE_CONFIG_CACHE_SECONDS = 300L;
    private final FederationConfiguration configuration;
    private final SigningKeyProvider signingKeyProvider;
    private final HttpGetClient subordinateFetcher;
    private final Function<String, Map<String, Object>> hostedEntityJwksLookup;
    private final ConcurrentHashMap<String, CachedSubordinateConfig> subordinateConfigCache = new ConcurrentHashMap<String, CachedSubordinateConfig>();

    FederationService(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider) {
        this(configuration, signingKeyProvider, null);
    }

    FederationService(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider, HttpGetClient subordinateFetcher) {
        this(configuration, signingKeyProvider, subordinateFetcher, null);
    }

    FederationService(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider,
                       HttpGetClient subordinateFetcher, Function<String, Map<String, Object>> hostedEntityJwksLookup) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.signingKeyProvider = Objects.requireNonNull(signingKeyProvider, "signingKeyProvider");
        this.subordinateFetcher = subordinateFetcher;
        this.hostedEntityJwksLookup = hostedEntityJwksLookup;
    }

    Map<String, Object> federationWellKnownMetadata(String oidcIssuer) {
        return Map.of("issuer", oidcIssuer, "federation_entity_endpoint", oidcIssuer + "/federation/entity", "federation_fetch_endpoint", oidcIssuer + "/federation/fetch", "federation_list_endpoint", oidcIssuer + "/federation/list", "federation_resolve_endpoint", oidcIssuer + "/federation/resolve", "authority_hints", this.configuration.authorityHints());
    }

    String createEntityConfigurationJwt(String oidcIssuer) throws JoseException {
        JwtClaims claims = baseClaims(oidcIssuer, oidcIssuer);
        claims.setClaim("jwks", this.buildInlineJwks());
        LinkedHashMap<String, Map<String, Object>> metadata = new LinkedHashMap<String, Map<String, Object>>();
        metadata.put("federation_entity", Map.of("federation_fetch_endpoint", oidcIssuer + "/federation/fetch", "federation_list_endpoint", oidcIssuer + "/federation/list", "federation_resolve_endpoint", oidcIssuer + "/federation/resolve"));
        AttestationMetadataConfig attestationMetadata = this.configuration.attestationMetadata();
        LinkedHashMap<String, Object> openidProvider = new LinkedHashMap<String, Object>();
        openidProvider.put("issuer", oidcIssuer);
        openidProvider.put("authorization_endpoint", oidcIssuer + "/as/authorization.oauth2");
        openidProvider.put("token_endpoint", oidcIssuer + "/as/token.oauth2");
        openidProvider.put("pushed_authorization_request_endpoint", oidcIssuer + "/as/par.oauth2");
        openidProvider.put("client_registration_types_supported", List.of("explicit"));
        openidProvider.put("federation_registration_endpoint", oidcIssuer + "/federation/register");
        openidProvider.put("token_endpoint_auth_methods_supported", attestationMetadata.tokenEndpointAuthMethodsSupported());
        openidProvider.put("client_attestation_signing_alg_values_supported", attestationMetadata.clientAttestationSigningAlgValuesSupported());
        openidProvider.put("client_attestation_pop_signing_alg_values_supported", attestationMetadata.clientAttestationPopSigningAlgValuesSupported());
        openidProvider.put("dpop_signing_alg_values_supported", attestationMetadata.dpopSigningAlgValuesSupported());
        List<String> popMethods = attestationMetadata.clientAttestationPopMethodsSupported();
        if (!popMethods.isEmpty()) {
            // draft-10 §8: the array MUST NOT be empty when the parameter is present
            openidProvider.put("client_attestation_pop_methods_supported", popMethods);
        }
        if (attestationMetadata.challengeEndpointEnabled()) {
            openidProvider.put("challenge_endpoint", oidcIssuer + "/federation/attestation-challenge");
        }
        metadata.put("openid_provider", openidProvider);
        metadata.put("oauth_authorization_server", Map.of("issuer", oidcIssuer, "authorization_endpoint", oidcIssuer + "/as/authorization.oauth2", "token_endpoint", oidcIssuer + "/as/token.oauth2", "pushed_authorization_request_endpoint", oidcIssuer + "/as/par.oauth2"));
        String attesterJwks = this.configuration.attesterJwks();
        if (attesterJwks != null) {
            // Publish the co-hosted Client Attester's signing keys so a remote AS can trust
            // attestations from this entity via the federation chain (FederationAttesterKeyResolver
            // prefers metadata.oauth_client_attester.jwks over the entity's federation jwks).
            metadata.put("oauth_client_attester", Map.of("jwks", JsonUtil.parseJson(attesterJwks)));
        }
        claims.setClaim("metadata", metadata);
        List<String> authorityHints = this.configuration.authorityHints();
        if (!authorityHints.isEmpty() && !this.configuration.isTrustAnchor(oidcIssuer)) {
            claims.setClaim("authority_hints", authorityHints);
        }
        return this.signClaims(claims);
    }

    String createEntityStatement(String subject, String requestedIssuer, String oidcIssuer) throws JoseException {
        String actualIssuer = requestedIssuer == null || requestedIssuer.isBlank() ? oidcIssuer : requestedIssuer;
        JwtClaims claims = baseClaims(actualIssuer, subject);
        if (!subject.equals(oidcIssuer)) {
            // Subordinate statement about a foreign entity: vouch for ITS keys, learned from its own
            // entity configuration. Metadata and authority_hints stay on the subordinate's leaf
            // statement — a subordinate statement only needs iss/sub/jwks for chain verification.
            claims.setClaim("jwks", this.fetchSubordinateJwks(subject));
            return this.signClaims(claims);
        }
        Map<String, Map<String, Object>> metadata = Map.of("openid_provider", Map.of("issuer", oidcIssuer, "jwks_uri", oidcIssuer + "/pf/JWKS", "authorization_endpoint", oidcIssuer + "/as/authorization.oauth2", "token_endpoint", oidcIssuer + "/as/token.oauth2", "pushed_authorization_request_endpoint", oidcIssuer + "/as/par.oauth2"));
        claims.setClaim("jwks", this.buildInlineJwks());
        claims.setClaim("metadata", metadata);
        claims.setClaim("authority_hints", this.configuration.authorityHints());
        return this.signClaims(claims);
    }

    private Map<String, Object> fetchSubordinateJwks(String subject) {
        if (this.hostedEntityJwksLookup != null) {
            Map<String, Object> hosted = this.hostedEntityJwksLookup.apply(subject);
            if (hosted != null) {
                return hosted;
            }
            // null means "not a hosted entity" (or no longer resolvable) — fall through to the
            // statically-configured-subordinate + fetch path below, unchanged.
        }
        if (!this.configuration.subordinates().contains(subject)) {
            // The subject itself doesn't exist here — not_found (404), not a malformed request.
            throw new FederationEntityNotFoundException("Unknown subordinate: " + subject);
        }
        CachedSubordinateConfig cached = this.subordinateConfigCache.get(subject);
        long now = Instant.now().getEpochSecond();
        if (cached != null && now - cached.fetchedAtEpochSeconds <= SUBORDINATE_CONFIG_CACHE_SECONDS) {
            return cached.jwks;
        }
        if (this.subordinateFetcher == null) {
            throw new IllegalStateException("No subordinate fetcher configured; cannot learn keys for " + subject);
        }
        try {
            String body = this.subordinateFetcher.get(subject + "/.well-known/openid-federation", ENTITY_STATEMENT_ACCEPT);
            JwtClaims selfConfig = JwtCodec.parseUnverifiedClaims(body);
            if (!subject.equals(selfConfig.getIssuer()) || !subject.equals(selfConfig.getSubject())) {
                throw new IllegalStateException("Entity configuration of " + subject + " is not self-signed (iss=" + selfConfig.getIssuer() + ", sub=" + selfConfig.getSubject() + ")");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> jwks = (Map<String, Object>) selfConfig.getClaimValue("jwks");
            if (jwks == null || jwks.isEmpty()) {
                throw new IllegalStateException("Entity configuration of " + subject + " contains no jwks");
            }
            this.subordinateConfigCache.put(subject, new CachedSubordinateConfig(jwks, now));
            return jwks;
        }
        catch (RuntimeException e) {
            throw e;
        }
        catch (Exception e) {
            if (cached != null) {
                // Stale-on-error: keep vouching from the last good fetch rather than failing the chain.
                return cached.jwks;
            }
            throw new IllegalStateException("Failed to fetch entity configuration of subordinate " + subject, e);
        }
    }

    private static final class CachedSubordinateConfig {
        private final Map<String, Object> jwks;
        private final long fetchedAtEpochSeconds;

        private CachedSubordinateConfig(Map<String, Object> jwks, long fetchedAtEpochSeconds) {
            this.jwks = jwks;
            this.fetchedAtEpochSeconds = fetchedAtEpochSeconds;
        }
    }

    String fetchEntityStatement(String issuer, String subject, String oidcIssuer) throws JoseException {
        boolean knownIssuer;
        boolean bl = knownIssuer = issuer.equals(oidcIssuer) || this.configuration.isTrustAnchor(issuer);
        if (!knownIssuer) {
            throw new IllegalArgumentException("Unknown issuer: " + issuer);
        }
        return this.createEntityStatement(subject, issuer, oidcIssuer);
    }

    List<String> listSubordinates(String entityType) {
        return this.configuration.subordinates();
    }

    Map<String, Object> resolveTrustChain(String subject, String trustAnchorIssuer, String oidcIssuer) throws JoseException {
        String anchorIssuer = this.configuration.findTrustAnchor(trustAnchorIssuer != null ? trustAnchorIssuer : this.configuration.defaultTrustAnchorIssuer());
        String trustAnchorStatement = this.createConfiguredTrustAnchorStatement(anchorIssuer, oidcIssuer);
        String leafStatement = this.createEntityStatement(subject, trustAnchorIssuer, oidcIssuer);
        return Map.of("subject", subject, "trust_anchor", anchorIssuer, "resolved_chain", List.of(trustAnchorStatement, leafStatement), "metadata", Map.of("openid_provider", Map.of("issuer", oidcIssuer, "jwks_uri", oidcIssuer + "/pf/JWKS")));
    }

    private String createConfiguredTrustAnchorStatement(String anchorIssuer, String subject) throws JoseException {
        JwtClaims claims = baseClaims(anchorIssuer, subject);
        claims.setClaim("metadata", Map.of("openid_provider", Map.of("issuer", anchorIssuer, "jwks_uri", anchorIssuer + "/pf/JWKS", "authorization_endpoint", anchorIssuer + "/as/authorization.oauth2", "token_endpoint", anchorIssuer + "/as/token.oauth2", "pushed_authorization_request_endpoint", anchorIssuer + "/as/par.oauth2")));
        return this.signClaims(claims);
    }

    private static JwtClaims baseClaims(String issuer, String subject) {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(issuer);
        claims.setSubject(subject);
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(60.0f);
        return claims;
    }

    private SigningKeyProvider resolveSigningKeyProvider() {
        return this.signingKeyProvider;
    }

    private String signClaims(JwtClaims claims) throws JoseException {
        String algorithm = this.configuration.signingAlgorithm();
        SigningKeyProvider signingKeys = this.resolveSigningKeyProvider();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(signingKeys.privateKey());
        jws.setAlgorithmHeaderValue(algorithm);
        jws.setHeader("typ", ENTITY_STATEMENT_TYP);
        jws.setKeyIdHeaderValue(signingKeys.keyId());
        return jws.getCompactSerialization();
    }

    private Map<String, Object> buildInlineJwks() throws JoseException {
        String algorithm = this.configuration.signingAlgorithm();
        SigningKeyProvider signingKeys = this.resolveSigningKeyProvider();
        RSAPublicKey pub = signingKeys.publicKey();
        Objects.requireNonNull(pub, "signingKeys.publicKey()");
        RsaJsonWebKey jwk = new RsaJsonWebKey(pub);
        jwk.setUse("sig");
        jwk.setAlgorithm(algorithm);
        jwk.setKeyId(signingKeys.keyId());
        String jwksJson = new JsonWebKeySet(new JsonWebKey[]{jwk}).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        return JsonUtil.parseJson(jwksJson);
    }
}

