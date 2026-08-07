package com.pingidentity.ps.oidf.servlet.trustanchor;

import com.pingidentity.ps.oidf.common.HttpGetClient;
import com.pingidentity.ps.oidf.common.JwtCodec;
import com.pingidentity.ps.oidf.common.SigningKeyProvider;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
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
 * fetch) is resolved by {@code hostedSubordinateLookup} first, ahead of and bypassing
 * {@link #subordinateConfigCache} entirely: a revoked hosted entity must stop resolving on the very next
 * call, not after a cache TTL. The lookup returns a claims fragment — {@code "jwks"} and, when this
 * authority declares one for the entity, {@code "metadata_policy"} — rather than a direct dependency on
 * the {@code authority} package's types, so this class and its existing tests stay unaware of, and
 * unaffected by, that package's own (static, process-wide) state.
 */
final class FederationService {
    private static final String ENTITY_STATEMENT_TYP = "entity-statement+jwt";
    private static final String ENTITY_STATEMENT_ACCEPT = "application/entity-statement+jwt, application/json";
    private static final long SUBORDINATE_CONFIG_CACHE_SECONDS = 300L;
    // Refresher period — kept under SUBORDINATE_CONFIG_CACHE_SECONDS so entries are re-fetched
    // while still fresh and request threads never see an empty cache after boot.
    private static final long REFRESH_INTERVAL_SECONDS = 240L;
    private final FederationConfiguration configuration;
    private final SigningKeyProvider signingKeyProvider;
    private final HttpGetClient subordinateFetcher;
    private final Function<String, Map<String, Object>> hostedSubordinateLookup;
    private final Function<String, List<String>> hostedSubordinateIds;
    private final String federationBasePath;
    private final ConcurrentHashMap<String, CachedSubordinateConfig> subordinateConfigCache = new ConcurrentHashMap<String, CachedSubordinateConfig>();

    FederationService(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider) {
        this(configuration, signingKeyProvider, null);
    }

    FederationService(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider, HttpGetClient subordinateFetcher) {
        // Delegates straight to the full constructor: with both a Function-taking and a String-taking
        // 4-arg overload below, a bare `this(…, null)` would be ambiguous.
        this(configuration, signingKeyProvider, subordinateFetcher, null, null, "");
    }

    /**
     * @param hostedSubordinateLookup subject -> a {@code Map} with a {@code "jwks"} entry and, optionally,
     *                                a {@code "metadata_policy"} entry, or {@code null} if the subject is
     *                                not (or no longer) hosted by this authority
     */
    FederationService(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider,
                       HttpGetClient subordinateFetcher, Function<String, Map<String, Object>> hostedSubordinateLookup) {
        this(configuration, signingKeyProvider, subordinateFetcher, hostedSubordinateLookup, null, "");
    }

    /**
     * @param federationBasePath the servlet context path this entity's own {@code /federation/*}
     *   endpoints are served under (e.g. {@code "/oidf"}), or {@code ""} when deployed at root.
     *   The entity's IDENTITY stays {@code oidcIssuer} (PF's OAuth issuer, always path-less), but
     *   the endpoints it ADVERTISES must include the context path or a peer following
     *   {@code federation_fetch_endpoint} gets a 404. PF-native endpoints ({@code /as/*},
     *   {@code /pf/JWKS}) are NOT prefixed — they really are at the root.
     */
    FederationService(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider, HttpGetClient subordinateFetcher, String federationBasePath) {
        this(configuration, signingKeyProvider, subordinateFetcher, null, null, federationBasePath);
    }

    /**
     * @param hostedSubordinateIds entity_type (possibly {@code null}) -> the hosted entity ids
     *                             {@code /federation/list} should include for that filter — already
     *                             restricted by the caller to listable, resolvable entities; see
     *                             {@code AuthoritySupport.hostedEntityIds}
     */
    FederationService(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider,
                       HttpGetClient subordinateFetcher, Function<String, Map<String, Object>> hostedSubordinateLookup,
                       Function<String, List<String>> hostedSubordinateIds) {
        this(configuration, signingKeyProvider, subordinateFetcher, hostedSubordinateLookup, hostedSubordinateIds, "");
    }

    /** The full constructor every overload above funnels into; see the overloads for parameter docs. */
    FederationService(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider,
                       HttpGetClient subordinateFetcher, Function<String, Map<String, Object>> hostedSubordinateLookup,
                       Function<String, List<String>> hostedSubordinateIds, String federationBasePath) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.signingKeyProvider = Objects.requireNonNull(signingKeyProvider, "signingKeyProvider");
        this.subordinateFetcher = subordinateFetcher;
        this.hostedSubordinateLookup = hostedSubordinateLookup;
        this.hostedSubordinateIds = hostedSubordinateIds;
        this.federationBasePath = federationBasePath == null || "/".equals(federationBasePath) ? "" : federationBasePath;
    }

    /** Base URL for this entity's own war-hosted {@code /federation/*} endpoints. */
    private String federationBase(String oidcIssuer) {
        return oidcIssuer + this.federationBasePath;
    }

    Map<String, Object> federationWellKnownMetadata(String oidcIssuer) {
        String fedBase = this.federationBase(oidcIssuer);
        return Map.of("issuer", oidcIssuer, "federation_entity_endpoint", fedBase + "/federation/entity", "federation_fetch_endpoint", fedBase + "/federation/fetch", "federation_list_endpoint", fedBase + "/federation/list", "federation_resolve_endpoint", fedBase + "/federation/resolve", "authority_hints", this.configuration.authorityHints());
    }

    String createEntityConfigurationJwt(String oidcIssuer) throws JoseException {
        JwtClaims claims = baseClaims(oidcIssuer, oidcIssuer);
        claims.setClaim("jwks", this.buildInlineJwks());
        claims.setClaim("metadata", this.selfMetadata(oidcIssuer));
        List<String> authorityHints = this.configuration.authorityHints();
        if (!authorityHints.isEmpty() && !this.configuration.isTrustAnchor(oidcIssuer)) {
            claims.setClaim("authority_hints", authorityHints);
        }
        return this.signClaims(claims);
    }

    /**
     * The metadata blocks this authority publishes about itself — {@code federation_entity},
     * {@code openid_provider}, {@code oauth_authorization_server} and (when an attester is co-hosted)
     * {@code oauth_client_attester}. Shared by {@link #createEntityConfigurationJwt} and the self-subject
     * branch of {@link #createEntityStatement} (Phase 1.8) so the two can no longer drift apart: before
     * this, the self-statement branch published only {@code openid_provider}, omitting
     * {@code federation_entity} — so a trust chain resolved down to an Intermediate via
     * {@code createEntityStatement} never learned that Intermediate's
     * {@code federation_fetch_endpoint}, and subordinate resolution had nowhere to go.
     *
     * <p>War-hosted {@code /federation/*} endpoints are prefixed with {@link #federationBase} (the
     * servlet context path); PF-native endpoints ({@code /as/*}, {@code /pf/JWKS}) really are at the
     * root and are not.
     */
    private LinkedHashMap<String, Object> selfMetadata(String oidcIssuer) throws JoseException {
        LinkedHashMap<String, Object> metadata = new LinkedHashMap<String, Object>();
        String fedBase = this.federationBase(oidcIssuer);
        metadata.put("federation_entity", Map.of("federation_fetch_endpoint", fedBase + "/federation/fetch", "federation_list_endpoint", fedBase + "/federation/list", "federation_resolve_endpoint", fedBase + "/federation/resolve"));
        AttestationMetadataConfig attestationMetadata = this.configuration.attestationMetadata();
        LinkedHashMap<String, Object> openidProvider = new LinkedHashMap<String, Object>();
        openidProvider.put("issuer", oidcIssuer);
        openidProvider.put("authorization_endpoint", oidcIssuer + "/as/authorization.oauth2");
        openidProvider.put("token_endpoint", oidcIssuer + "/as/token.oauth2");
        openidProvider.put("pushed_authorization_request_endpoint", oidcIssuer + "/as/par.oauth2");
        openidProvider.put("client_registration_types_supported", List.of("explicit"));
        openidProvider.put("federation_registration_endpoint", fedBase + "/federation/register");
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
            openidProvider.put("challenge_endpoint", fedBase + "/federation/attestation-challenge");
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
        return metadata;
    }

    String createEntityStatement(String subject, String requestedIssuer, String oidcIssuer) throws JoseException {
        String actualIssuer = requestedIssuer == null || requestedIssuer.isBlank() ? oidcIssuer : requestedIssuer;
        JwtClaims claims = baseClaims(actualIssuer, subject);
        if (!subject.equals(oidcIssuer)) {
            // A subordinate hosted by this same authority (see com.pingidentity.ps.oidf.authority) is
            // checked first, ahead of and bypassing subordinateConfigCache entirely: a revoked hosted
            // entity must stop resolving on the very next call, not after a 300s cache TTL. Its claims
            // may carry "jwks" and, when this authority declares one, "metadata_policy" — the only two
            // claims a subordinate statement ever needs (metadata and authority_hints stay on the
            // subordinate's own leaf statement).
            if (this.hostedSubordinateLookup != null) {
                Map<String, Object> hosted = this.hostedSubordinateLookup.apply(subject);
                if (hosted != null) {
                    claims.setClaim("jwks", hosted.get("jwks"));
                    Object metadataPolicy = hosted.get("metadata_policy");
                    if (metadataPolicy != null) {
                        claims.setClaim("metadata_policy", metadataPolicy);
                    }
                    return this.signClaims(claims);
                }
                // null means "not a hosted entity" (or no longer resolvable) — fall through below.
            }
            // Subordinate statement about a foreign entity: vouch for ITS keys, learned from its own
            // entity configuration. Metadata and authority_hints stay on the subordinate's leaf
            // statement — a subordinate statement only needs iss/sub/jwks for chain verification.
            claims.setClaim("jwks", this.fetchSubordinateJwks(subject));
            return this.signClaims(claims);
        }
        claims.setClaim("jwks", this.buildInlineJwks());
        claims.setClaim("metadata", this.selfMetadata(oidcIssuer));
        claims.setClaim("authority_hints", this.configuration.authorityHints());
        return this.signClaims(claims);
    }

    /**
     * Keep the subordinate entity-configuration cache perpetually fresh from a background
     * daemon, so a request NEVER blocks on a cross-network subordinate fetch. Called from
     * servlet init. Two failure modes drove this design, both observed live: (a) a freshly
     * booted trust anchor's first token exchange blocked on a cold fetch of each subordinate's
     * {@code .well-known/openid-federation}; (b) after the 300s cache expired, the NEXT request
     * ate a synchronous refresh — and the refresh path (Railway→Azure in the observed
     * deployment) intermittently stalls 15s+ even though the same URL answers in milliseconds
     * from elsewhere, which pushed the whole exchange past the calling agent platform's hard
     * 30s tool timeout. The refresher re-fetches every {@code REFRESH_INTERVAL_SECONDS}
     * (< the 300s freshness window) so {@link #fetchSubordinateJwks} always finds a usable
     * entry, and {@link #fetchSubordinateJwks}'s serve-stale behaviour covers any window where
     * refreshes keep failing.
     */
    void prewarmSubordinatesAsync() {
        List<String> subs = this.configuration.subordinates();
        if (this.subordinateFetcher == null || subs.isEmpty()) {
            return;
        }
        Thread warmer = new Thread(() -> {
            org.apache.commons.logging.Log log = org.apache.commons.logging.LogFactory.getLog(FederationService.class);
            while (true) {
                for (String subject : subs) {
                    try {
                        this.refreshSubordinateJwks(subject);
                        log.info("subordinate-refresh: cached entity configuration of " + subject);
                    } catch (Exception e) {
                        log.info("subordinate-refresh: " + subject + " not reachable (will retry; serving stale if cached): " + e.getMessage());
                    }
                }
                try {
                    Thread.sleep(REFRESH_INTERVAL_SECONDS * 1000L);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }, "oidf-subordinate-refresh");
        warmer.setDaemon(true);
        warmer.start();
    }

    private Map<String, Object> fetchSubordinateJwks(String subject) {
        if (!this.configuration.subordinates().contains(subject)) {
            // The subject itself doesn't exist here — not_found (404), not a malformed request.
            throw new FederationEntityNotFoundException("Unknown subordinate: " + subject);
        }
        CachedSubordinateConfig cached = this.subordinateConfigCache.get(subject);
        if (cached != null) {
            // Serve whatever we have, fresh OR stale, without ever fetching on the request
            // thread — the background refresher (prewarmSubordinatesAsync) owns freshness.
            // A synchronous refresh here after mere staleness is exactly the failure observed
            // in production: the cross-network fetch stalled 15s inside a token exchange that
            // the caller abandons at 30s. Subordinate federation keys rotate rarely; serving a
            // stale-but-signed key set until the refresher catches up is the right trade.
            return cached.jwks;
        }
        if (this.subordinateFetcher == null) {
            throw new IllegalStateException("No subordinate fetcher configured; cannot learn keys for " + subject);
        }
        // Cold cache (request raced ahead of the boot-time refresher): fetch synchronously once.
        return this.refreshSubordinateJwks(subject);
    }

    /** Live-fetch {@code subject}'s entity configuration and cache its jwks. */
    private Map<String, Object> refreshSubordinateJwks(String subject) {
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
            this.subordinateConfigCache.put(subject, new CachedSubordinateConfig(jwks, Instant.now().getEpochSecond()));
            return jwks;
        }
        catch (RuntimeException e) {
            throw e;
        }
        catch (Exception e) {
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
        List<String> subordinates = new ArrayList<String>();
        if (entityType == null || entityType.isBlank()) {
            // The statically configured subordinates carry no verified type — including them under a
            // typed filter would be a guess, not a fact, so they only ever appear on the untyped list.
            subordinates.addAll(this.configuration.subordinates());
        }
        if (this.hostedSubordinateIds != null) {
            subordinates.addAll(this.hostedSubordinateIds.apply(entityType));
        }
        return List.copyOf(subordinates);
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

