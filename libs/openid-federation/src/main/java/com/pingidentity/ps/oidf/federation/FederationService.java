package com.pingidentity.ps.oidf.federation;

import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.jose.HttpGetClient;
import com.pingidentity.ps.oidf.jose.HttpPostClient;
import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.jose.JwtVerificationException;
import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;

/**
 * This deployment as a federation entity: the statements it issues and the federation endpoints it
 * answers - its Entity Configuration, the fetch endpoint (OpenID Federation 1.0 §8.1), the list endpoint
 * (§8.2) and the resolve endpoint (§8.3). Statements are RSA-signed with the configured algorithm under a
 * Federation Entity Key from the {@link SigningKeyProvider}.
 *
 * <p>A Subordinate Statement about a <em>foreign</em> configured subordinate embeds that entity's own keys,
 * learned from its self-signed Entity Configuration and kept fresh by a background refresher: a verifier
 * checks the subordinate's own configuration against the keys this entity asserts, so those keys must be
 * the subordinate's. A subordinate <em>hosted</em> here (an agent with no HTTPS endpoint of its own, see
 * {@code com.pingidentity.ps.oidf.authority}) is looked up uncached, ahead of the foreign path: a revoked
 * hosted entity stops resolving on the very next call.
 *
 * <p>The entity configuration advertises what is actually enabled: the fetch and list endpoints only when
 * this entity has subordinates (§5.1.1: "Leaf Entities MUST NOT" publish them), the resolve endpoint only
 * when a resolver is configured, the Trust Mark endpoints only when it issues Trust Marks, and the client
 * registration types the deployment accepts (§5.1.3).
 *
 * <p>As a Trust Mark Issuer (§7, §8.4-§8.6) it signs marks with the same Federation Entity Key. A mark is minted
 * once and served again while more than half its life is left and the grant it was minted under still stands.
 */
public final class FederationService {
    private static final Log LOGGER = LogFactory.getLog(FederationService.class);
    static final String ENTITY_STATEMENT_TYP = "entity-statement+jwt";
    static final String RESOLVE_RESPONSE_TYP = "resolve-response+jwt";
    private static final String ENTITY_STATEMENT_ACCEPT = "application/entity-statement+jwt, application/json";
    private static final long STATEMENT_LIFETIME_SECONDS = 3600L;
    // Refresher period — under the lifetime a verifier would accept a stale key for, so entries are
    // re-fetched while still fresh and request threads never see an empty cache after boot.
    private static final long REFRESH_INTERVAL_SECONDS = 240L;
    private static final int MINTED_MEMORY = 4096;
    private final FederationConfiguration configuration;
    private final SigningKeyProvider signingKeyProvider;
    private final HttpGetClient subordinateFetcher;
    private final Function<String, Map<String, Object>> hostedSubordinateLookup;
    private final Function<String, List<String>> hostedSubordinateIds;
    private final Function<String, String> hostedConfiguration;
    private final BooleanSupplier hosting;
    private final String federationBasePath;
    private final TrustAnchorSet resolverAnchors;
    private final TrustControllerGateway resolverGateway;
    private final Set<String> resolverAlgorithms;
    private final ValidatorOptions resolverOptions;
    private final HttpPostClient trustMarkStatusClient;
    private final TrustMarkIssuing trustMarkIssuing;
    private final List<Map<String, Object>> ownTrustMarks;
    private final Map<String, List<String>> trustMarkIssuers;
    private final Map<String, Object> trustMarkOwners;
    /** Marks minted, by issuer, type and subject: served again until half their life is gone or their grant changes. */
    private final Map<String, Minted> minted = Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Minted> eldest) {
            return this.size() > MINTED_MEMORY;
        }
    });
    private final Clock clock;
    private final ConcurrentHashMap<String, CachedSubordinateConfig> subordinateConfigCache = new ConcurrentHashMap<String, CachedSubordinateConfig>();

    public FederationService(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider) {
        this(builder(configuration, signingKeyProvider));
    }

    public FederationService(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider, HttpGetClient subordinateFetcher) {
        this(builder(configuration, signingKeyProvider).subordinateFetcher(subordinateFetcher));
    }

    /**
     * @param hostedSubordinateLookup subject -> a {@code Map} with a {@code "jwks"} entry and, optionally,
     *                                a {@code "metadata_policy"} entry, or {@code null} if the subject is
     *                                not (or no longer) hosted by this authority
     */
    public FederationService(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider,
                       HttpGetClient subordinateFetcher, Function<String, Map<String, Object>> hostedSubordinateLookup) {
        this(builder(configuration, signingKeyProvider).subordinateFetcher(subordinateFetcher).hostedSubordinateLookup(hostedSubordinateLookup));
    }

    /** @param federationBasePath see {@link Builder#federationBasePath} */
    public FederationService(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider, HttpGetClient subordinateFetcher, String federationBasePath) {
        this(builder(configuration, signingKeyProvider).subordinateFetcher(subordinateFetcher).federationBasePath(federationBasePath));
    }

    /** @param hostedSubordinateIds see {@link Builder#hostedSubordinateIds} */
    public FederationService(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider,
                       HttpGetClient subordinateFetcher, Function<String, Map<String, Object>> hostedSubordinateLookup,
                       Function<String, List<String>> hostedSubordinateIds) {
        this(builder(configuration, signingKeyProvider).subordinateFetcher(subordinateFetcher)
                .hostedSubordinateLookup(hostedSubordinateLookup).hostedSubordinateIds(hostedSubordinateIds));
    }

    public FederationService(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider,
                       HttpGetClient subordinateFetcher, Function<String, Map<String, Object>> hostedSubordinateLookup,
                       Function<String, List<String>> hostedSubordinateIds, String federationBasePath) {
        this(builder(configuration, signingKeyProvider).subordinateFetcher(subordinateFetcher)
                .hostedSubordinateLookup(hostedSubordinateLookup).hostedSubordinateIds(hostedSubordinateIds)
                .federationBasePath(federationBasePath));
    }

    private FederationService(Builder b) {
        this.configuration = Objects.requireNonNull(b.configuration, "configuration");
        this.signingKeyProvider = Objects.requireNonNull(b.signingKeyProvider, "signingKeyProvider");
        this.subordinateFetcher = b.subordinateFetcher;
        this.hostedSubordinateLookup = b.hostedSubordinateLookup;
        this.hostedSubordinateIds = b.hostedSubordinateIds;
        this.hostedConfiguration = b.hostedConfiguration;
        this.hosting = b.hosting != null ? b.hosting : () -> false;
        this.federationBasePath = b.federationBasePath == null || "/".equals(b.federationBasePath) ? "" : b.federationBasePath;
        this.resolverAnchors = b.resolverAnchors;
        this.resolverGateway = b.resolverGateway;
        this.resolverAlgorithms = b.resolverAlgorithms == null ? Set.of() : Set.copyOf(b.resolverAlgorithms);
        this.resolverOptions = b.resolverOptions != null ? b.resolverOptions : ValidatorOptions.defaults();
        this.trustMarkStatusClient = b.trustMarkStatusClient;
        this.trustMarkIssuing = b.trustMarkIssuing;
        this.ownTrustMarks = List.copyOf(b.ownTrustMarks);
        this.trustMarkIssuers = Collections.unmodifiableMap(new LinkedHashMap<>(b.trustMarkIssuers));
        this.trustMarkOwners = Collections.unmodifiableMap(new LinkedHashMap<>(b.trustMarkOwners));
        this.clock = b.clock != null ? b.clock : Clock.systemUTC();
    }

    public static Builder builder(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider) {
        return new Builder(configuration, signingKeyProvider);
    }

    /** Base URL for this entity's own war-hosted {@code /federation/*} endpoints. */
    private String federationBase(String oidcIssuer) {
        return EntityId.comparable(oidcIssuer) + this.federationBasePath;
    }

    /** The fetch endpoint URL - also each Subordinate Statement's {@code source_endpoint} (§3.1.3). */
    public String fetchEndpoint(String oidcIssuer) {
        return this.federationBase(oidcIssuer) + "/federation/fetch";
    }

    /**
     * Whether this entity is a superior: it has configured subordinates, hosts entities, or is a configured
     * trust anchor. Only a superior publishes fetch and list endpoints (§5.1.1).
     */
    public boolean isSuperior(String oidcIssuer) {
        return !this.configuration.subordinates().isEmpty() || this.configuration.isTrustAnchor(oidcIssuer)
                || this.hosting.getAsBoolean();
    }

    /** Whether the resolve endpoint is enabled: a resolver has trust anchors to resolve against. */
    public boolean resolveEnabled() {
        return this.resolverAnchors != null && !this.resolverAnchors.isEmpty() && this.resolverGateway != null;
    }

    // ---- this entity's own configuration -----------------------------------------------------------------

    public String createEntityConfigurationJwt(String oidcIssuer) throws JoseException {
        JwtClaims claims = this.baseClaims(oidcIssuer, oidcIssuer);
        claims.setClaim("jwks", this.buildInlineJwks());
        claims.setClaim("metadata", this.selfMetadata(oidcIssuer));
        List<String> authorityHints = this.configuration.authorityHints();
        if (!authorityHints.isEmpty() && !this.configuration.isTrustAnchor(oidcIssuer)) {
            claims.setClaim("authority_hints", authorityHints);
        }
        this.addTrustMarkClaims(claims, oidcIssuer);
        return this.signClaims(claims, ENTITY_STATEMENT_TYP);
    }

    /**
     * §3.1.2: the Trust Marks this entity carries - those configured from other issuers, then those it issues
     * itself - and, when it is a trust anchor, whose marks the federation accepts and who owns which type.
     */
    private void addTrustMarkClaims(JwtClaims claims, String oidcIssuer) throws JoseException {
        List<Map<String, Object>> marks = new ArrayList<>(this.ownTrustMarks);
        marks.addAll(this.issuedTrustMarks(oidcIssuer, oidcIssuer));
        if (!marks.isEmpty()) {
            claims.setClaim("trust_marks", marks);
        }
        if (!this.configuration.isTrustAnchor(oidcIssuer)) {
            return;
        }
        Map<String, Object> issuers = this.anchorTrustMarkIssuers(oidcIssuer);
        if (!issuers.isEmpty()) {
            claims.setClaim("trust_mark_issuers", issuers);
        }
        if (!this.trustMarkOwners.isEmpty()) {
            claims.setClaim("trust_mark_owners", this.trustMarkOwners);
        }
    }

    /**
     * The configured {@code trust_mark_issuers}, with this entity named for every type it issues itself - an anchor
     * that forgot to list itself would otherwise have its own marks refused - unless anyone may issue the type.
     */
    private Map<String, Object> anchorTrustMarkIssuers(String oidcIssuer) {
        Map<String, Object> issuers = new LinkedHashMap<>(this.trustMarkIssuers);
        for (String type : this.issuedTypes()) {
            List<String> listed = this.trustMarkIssuers.get(type);
            if (listed == null) {
                issuers.put(type, List.of(oidcIssuer));
            } else if (!listed.isEmpty() && listed.stream().noneMatch(i -> EntityId.same(i, oidcIssuer))) {
                List<String> withSelf = new ArrayList<>(listed);
                withSelf.add(oidcIssuer);
                issuers.put(type, withSelf);
            }
        }
        return issuers;
    }

    /**
     * The metadata blocks this entity publishes about itself — {@code federation_entity},
     * {@code openid_provider}, {@code oauth_authorization_server} and (when an attester is co-hosted)
     * {@code oauth_client_attester}. Shared by {@link #createEntityConfigurationJwt} and the self-subject
     * branch of {@link #createEntityStatement} so the two cannot drift apart.
     *
     * <p>War-hosted {@code /federation/*} endpoints are prefixed with {@link #federationBase} (the servlet
     * context path); PF-native endpoints ({@code /as/*}, {@code /pf/JWKS}) really are at the root and are not.
     */
    private LinkedHashMap<String, Object> selfMetadata(String oidcIssuer) throws JoseException {
        LinkedHashMap<String, Object> metadata = new LinkedHashMap<String, Object>();
        String fedBase = this.federationBase(oidcIssuer);
        LinkedHashMap<String, Object> federationEntity = new LinkedHashMap<String, Object>();
        if (this.isSuperior(oidcIssuer)) {
            federationEntity.put("federation_fetch_endpoint", this.fetchEndpoint(oidcIssuer));
            federationEntity.put("federation_list_endpoint", fedBase + "/federation/list");
        }
        if (this.resolveEnabled()) {
            federationEntity.put("federation_resolve_endpoint", fedBase + "/federation/resolve");
        }
        if (this.issuesTrustMarks()) {
            federationEntity.put("federation_trust_mark_endpoint", fedBase + "/federation/trust_mark");
            federationEntity.put("federation_trust_mark_status_endpoint", fedBase + "/federation/trust_mark_status");
            federationEntity.put("federation_trust_mark_list_endpoint", fedBase + "/federation/trust_marked_list");
        }
        if (this.configuration.organizationName() != null) {
            federationEntity.put("organization_name", this.configuration.organizationName());
        }
        metadata.put("federation_entity", federationEntity);
        AttestationMetadataConfig attestationMetadata = this.configuration.attestationMetadata();
        LinkedHashMap<String, Object> openidProvider = new LinkedHashMap<String, Object>();
        openidProvider.put("issuer", oidcIssuer);
        openidProvider.put("authorization_endpoint", oidcIssuer + "/as/authorization.oauth2");
        openidProvider.put("token_endpoint", oidcIssuer + "/as/token.oauth2");
        openidProvider.put("pushed_authorization_request_endpoint", oidcIssuer + "/as/par.oauth2");
        List<String> registrationTypes = this.configuration.clientRegistrationTypes();
        if (!registrationTypes.isEmpty()) {
            openidProvider.put("client_registration_types_supported", registrationTypes);
        }
        if (registrationTypes.contains("explicit")) {
            // §5.1.3: REQUIRED when Explicit Registration is supported, and only then.
            openidProvider.put("federation_registration_endpoint", fedBase + "/federation/register");
        }
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

    // ---- fetch (§8.1) --------------------------------------------------------------------------------

    /**
     * The fetch endpoint (§8.1): the Subordinate Statement this entity issues about {@code sub}.
     *
     * @param iss        optional; §8.1.1 defines {@code sub} alone, and draft-era clients also send the
     *                   issuer - accepted when it names this entity
     * @param sub        the subject; required
     * @param oidcIssuer this entity's identifier
     * @throws FederationException {@code invalid_request} when {@code sub} is missing or names this entity
     *                             itself (§8.1.2), {@code invalid_issuer} when {@code iss} names another
     *                             entity, {@code not_found} for a subject this entity has no statement about,
     *                             {@code temporarily_unavailable} when a subordinate's keys cannot be had yet
     */
    public String fetchSubordinateStatement(String iss, String sub, String oidcIssuer) throws JoseException {
        if (sub == null || sub.isBlank()) {
            throw new FederationException(FederationError.INVALID_REQUEST, "sub is required");
        }
        if (iss != null && !iss.isBlank() && !EntityId.same(iss, oidcIssuer)) {
            throw new FederationException(FederationError.INVALID_ISSUER, "this endpoint issues statements only as " + oidcIssuer);
        }
        if (EntityId.same(sub, oidcIssuer)) {
            throw new FederationException(FederationError.INVALID_REQUEST,
                    "sub names this entity itself; its Entity Configuration is at /.well-known/openid-federation (§8.1.2)");
        }
        return this.subordinateStatement(sub, oidcIssuer);
    }

    /** @deprecated the pre-§8.1 signature, which required {@code iss}; see {@link #fetchSubordinateStatement}. */
    @Deprecated
    public String fetchEntityStatement(String issuer, String subject, String oidcIssuer) throws JoseException {
        return this.fetchSubordinateStatement(issuer, subject, oidcIssuer);
    }

    /**
     * The non-standard {@code /federation/entity} statement: this entity's self statement when
     * {@code subject} is itself, otherwise the same Subordinate Statement the fetch endpoint issues.
     * {@code requestedIssuer} is ignored - a statement signed with this entity's key names this entity as
     * issuer, whatever the caller asked for.
     */
    public String createEntityStatement(String subject, String requestedIssuer, String oidcIssuer) throws JoseException {
        if (!EntityId.same(subject, oidcIssuer)) {
            return this.subordinateStatement(subject, oidcIssuer);
        }
        JwtClaims claims = this.baseClaims(oidcIssuer, subject);
        claims.setClaim("jwks", this.buildInlineJwks());
        claims.setClaim("metadata", this.selfMetadata(oidcIssuer));
        claims.setClaim("authority_hints", this.configuration.authorityHints());
        this.addTrustMarkClaims(claims, oidcIssuer);
        return this.signClaims(claims, ENTITY_STATEMENT_TYP);
    }

    private String subordinateStatement(String subject, String oidcIssuer) throws JoseException {
        JwtClaims claims = this.baseClaims(oidcIssuer, subject);
        // A subordinate hosted by this same authority is checked first, ahead of and bypassing
        // subordinateConfigCache entirely: a revoked hosted entity must stop resolving on the very next
        // call, not after a cache TTL.
        Map<String, Object> hosted = this.hostedSubordinateLookup == null ? null : this.hostedSubordinateLookup.apply(subject);
        if (hosted != null) {
            claims.setClaim("jwks", hosted.get("jwks"));
            Object metadataPolicy = hosted.get("metadata_policy");
            if (metadataPolicy != null) {
                claims.setClaim("metadata_policy", metadataPolicy);
            }
        } else {
            // A foreign subordinate: vouch for ITS keys, learned from its own entity configuration.
            // Metadata and authority_hints stay on the subordinate's own configuration.
            claims.setClaim("jwks", this.fetchSubordinateJwks(subject));
        }
        claims.setClaim("source_endpoint", this.fetchEndpoint(oidcIssuer));
        return this.signClaims(claims, ENTITY_STATEMENT_TYP);
    }

    // ---- list (§8.2) ---------------------------------------------------------------------------------

    /** @deprecated a single {@code entity_type}; see {@link #listSubordinates(ListRequest)}. */
    @Deprecated
    public List<String> listSubordinates(String entityType) {
        return this.listSubordinates(new ListRequest(entityType == null || entityType.isBlank() ? List.of() : List.of(entityType),
                null, null, null));
    }

    /**
     * The list endpoint (§8.2): the Immediate Subordinates, filtered.
     *
     * <p>A filter lists only what this entity knows to match. A configured subordinate's Entity Types, and
     * whether it is an Intermediate (it publishes a fetch endpoint, which §8.1 requires of anything with
     * subordinates), are known once its configuration has been fetched; until then it appears only in an
     * unfiltered list. A hosted entity is never an Intermediate.
     *
     * <p>{@code trust_marked=true} and {@code trust_mark_type} keep the subordinates this entity has issued a Trust
     * Mark to that is still valid - of that type, for {@code trust_mark_type}, which leaves none for a type it does not
     * issue.
     *
     * @throws FederationException {@code unsupported_parameter} for {@code trust_marked=true} or
     *                             {@code trust_mark_type} when this entity issues no Trust Marks to filter by
     */
    public List<String> listSubordinates(ListRequest request) {
        boolean markFilter = Boolean.TRUE.equals(request.trustMarked()) || request.trustMarkType() != null;
        if (markFilter && !this.issuesTrustMarks()) {
            throw new FederationException(FederationError.UNSUPPORTED_PARAMETER,
                    "this entity issues no Trust Marks, so it cannot filter by them");
        }
        List<String> types = request.entityTypes();
        boolean intermediatesOnly = Boolean.TRUE.equals(request.intermediate());
        List<String> listed = new ArrayList<>();
        for (String subordinate : this.configuration.subordinates()) {
            if (types.isEmpty() && !intermediatesOnly) {
                listed.add(subordinate);
                continue;
            }
            CachedSubordinateConfig cached = this.subordinateConfigCache.get(subordinate);
            if (cached != null && cached.entityTypes.containsAll(types) && (!intermediatesOnly || cached.intermediate)) {
                listed.add(subordinate);
            }
        }
        if (this.hostedSubordinateIds != null && !intermediatesOnly) {
            if (types.isEmpty()) {
                listed.addAll(this.hostedSubordinateIds.apply(null));
            } else {
                List<String> hosted = new ArrayList<>(this.hostedSubordinateIds.apply(types.get(0)));
                for (String type : types.subList(1, types.size())) {
                    hosted.retainAll(this.hostedSubordinateIds.apply(type));
                }
                listed.addAll(hosted);
            }
        }
        List<String> distinct = List.copyOf(new LinkedHashSet<>(listed));
        return markFilter ? distinct.stream().filter(s -> this.trustMarkIssuing.isMarked(s, request.trustMarkType())).toList() : distinct;
    }

    // ---- Trust Marks (§7, §8.4-§8.6) -----------------------------------------------------------------

    /** Whether this entity issues Trust Marks. */
    public boolean issuesTrustMarks() {
        return !this.issuedTypes().isEmpty();
    }

    private Set<String> issuedTypes() {
        return this.trustMarkIssuing == null ? Set.of() : this.trustMarkIssuing.types();
    }

    private void requireIssuing() {
        if (!this.issuesTrustMarks()) {
            throw new FederationException(FederationError.NOT_FOUND, "this entity issues no Trust Marks");
        }
    }

    /**
     * The marks this entity issues to {@code subject} as {@code issuerId}, as a {@code trust_marks} claim (§3.1.2): one
     * for each type the subject holds now. For its own configuration, and the configurations of entities it hosts.
     */
    public List<Map<String, Object>> issuedTrustMarks(String subject, String issuerId) throws JoseException {
        List<Map<String, Object>> marks = new ArrayList<>();
        for (String type : this.issuedTypes()) {
            Optional<String> mark = this.mint(type, subject, issuerId);
            if (mark.isPresent()) {
                marks.add(Map.of("trust_mark_type", type, "trust_mark", mark.get()));
            }
        }
        return marks;
    }

    /** A mark of {@code type} for {@code subject}: the one minted earlier while it is still fresh, else a new one. */
    private Optional<String> mint(String type, String subject, String issuerId) throws JoseException {
        Optional<TrustMarkIssuing.Mintable> mintable = this.trustMarkIssuing.mintable(issuerId, type, subject);
        if (mintable.isEmpty()) {
            return Optional.empty();
        }
        String key = issuerId + "\n" + type + "\n" + subject;
        long now = this.clock.instant().getEpochSecond();
        Minted kept = this.minted.get(key);
        if (kept != null && kept.grantedAt().equals(mintable.get().grantedAt()) && now - kept.issuedAt() < (kept.expiresAt() - kept.issuedAt()) / 2) {
            return Optional.of(kept.jwt());
        }
        JwtClaims claims = mintable.get().claims();
        String jwt = this.signClaims(claims, TrustMarkValidator.TRUST_MARK_TYP);
        long iat = ((Number) claims.getClaimValue("iat")).longValue();
        long exp = ((Number) claims.getClaimValue("exp")).longValue();
        this.minted.put(key, new Minted(jwt, iat, exp, mintable.get().grantedAt()));
        FederationEvents.event(FederationEvents.TRUST_MARK_ISSUED).subject(subject).partner(issuerId).role("TMI").audit()
                .field("trust_mark_type", type).field("exp", exp).emit();
        return Optional.of(jwt);
    }

    private record Minted(String jwt, long issuedAt, long expiresAt, java.time.Instant grantedAt) {
    }

    /**
     * The Trust Mark endpoint (§8.6): the mark of {@code type} this entity issues to {@code subject}.
     *
     * @throws FederationException {@code invalid_request} without {@code trust_mark_type} or {@code sub};
     *                             {@code not_found} when the subject holds no such mark (§8.6.2) or this entity issues none
     */
    public String trustMark(String type, String subject, String oidcIssuer) throws JoseException {
        this.requireIssuing();
        if (type == null || type.isBlank()) {
            throw new FederationException(FederationError.INVALID_REQUEST, "trust_mark_type is required");
        }
        if (subject == null || subject.isBlank()) {
            throw new FederationException(FederationError.INVALID_REQUEST, "sub is required");
        }
        return this.mint(type, subject, oidcIssuer).orElseThrow(() ->
                new FederationException(FederationError.NOT_FOUND, "that entity holds no Trust Mark of that type from this issuer"));
    }

    /**
     * The Trust Mark Status endpoint (§8.4): a signed {@code trust-mark-status-response+jwt} saying whether a mark this
     * entity issued is {@code active}, {@code expired} or {@code revoked} - or {@code invalid}, when it names this entity
     * as issuer but is not typed as a Trust Mark or its signature does not verify with this entity's key.
     *
     * @throws FederationException {@code invalid_request} without {@code trust_mark} or when it is not a signed JWT;
     *                             {@code not_found} for a mark this entity did not issue or knows nothing of (§8.4.2)
     */
    public String trustMarkStatus(String trustMark, String oidcIssuer) throws JoseException {
        this.requireIssuing();
        if (trustMark == null || trustMark.isBlank()) {
            throw new FederationException(FederationError.INVALID_REQUEST, "trust_mark is required");
        }
        Map<String, Object> header;
        JwtClaims mark;
        try {
            header = JwtCodec.getJwtHeaders(trustMark);
            mark = JwtCodec.parseUnverifiedClaims(trustMark);
        } catch (Exception e) {
            throw new FederationException(FederationError.INVALID_REQUEST, "trust_mark is not a signed JWT");
        }
        if (!(mark.getClaimValue("iss") instanceof String iss) || !EntityId.same(iss, oidcIssuer)) {
            throw new FederationException(FederationError.NOT_FOUND, "this entity did not issue that Trust Mark");
        }
        String status = !TrustMarkValidator.TRUST_MARK_TYP.equals(header.get("typ")) || !this.signedWithOwnKey(trustMark) ? "invalid"
                : this.trustMarkIssuing.status(mark).orElseThrow(() ->
                        new FederationException(FederationError.NOT_FOUND, "this entity knows nothing of that Trust Mark"));
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(oidcIssuer);
        claims.setIssuedAt(NumericDate.fromSeconds(this.clock.instant().getEpochSecond()));
        claims.setClaim("trust_mark", trustMark);
        claims.setClaim("status", status);
        return this.signClaims(claims, TrustMarkValidator.STATUS_RESPONSE_TYP);
    }

    private boolean signedWithOwnKey(String jwt) throws JoseException {
        try {
            JwtCodec.verifySignature(jwt, Jwks.parseFederationKeySet(this.buildInlineJwks()), Set.of(this.configuration.signingAlgorithm()));
            return true;
        } catch (JwtVerificationException e) {
            return false;
        }
    }

    /**
     * The Trust Marked Entities Listing endpoint (§8.5): the entities holding a valid mark of {@code type} from this
     * entity, only {@code subject} when it is given.
     *
     * @throws FederationException {@code invalid_request} without {@code trust_mark_type}; {@code not_found} when this
     *                             entity issues no Trust Marks
     */
    public List<String> trustMarkedEntities(String type, String subject) {
        this.requireIssuing();
        if (type == null || type.isBlank()) {
            throw new FederationException(FederationError.INVALID_REQUEST, "trust_mark_type is required");
        }
        return this.trustMarkIssuing.marked(type, subject == null || subject.isBlank() ? null : subject);
    }

    // ---- resolve (§8.3) ------------------------------------------------------------------------------

    /**
     * The resolve endpoint (§8.3): validates a chain from {@code sub} to one of the requested anchors and
     * returns a signed {@code resolve-response+jwt} carrying the resolved metadata, the chain, which ends with the
     * anchor's Entity Configuration, and the subject's Trust Marks that verified against that anchor (§8.3.2: "Only
     * valid Trust Marks that have been issued by Trust Mark issuers trusted by the Trust Anchor").
     *
     * @throws FederationException {@code invalid_request} without {@code sub} or {@code trust_anchor};
     *                             {@code invalid_trust_anchor} when none of the requested anchors is trusted
     *                             here; {@code invalid_subject} for a subject outside what this resolver
     *                             resolves unauthenticated (§18.1); and every chain refusal with its own code
     */
    public String resolve(ResolveRequest request, String oidcIssuer) throws JoseException {
        String subject = request.subject();
        if (subject == null || subject.isBlank()) {
            throw new FederationException(FederationError.INVALID_REQUEST, "sub is required");
        }
        if (request.trustAnchors().isEmpty()) {
            throw new FederationException(FederationError.INVALID_REQUEST, "trust_anchor is required");
        }
        if (!this.resolveEnabled()) {
            throw new FederationException(FederationError.INVALID_TRUST_ANCHOR, "this entity resolves against no trust anchor");
        }
        if (this.configuration.resolveDiscovery() == FederationConfiguration.ResolveDiscovery.KNOWN && !this.isKnown(subject, oidcIssuer)) {
            throw new FederationException(FederationError.INVALID_SUBJECT, "this resolver resolves only this entity, its"
                    + " subordinates and the entities it hosts (OpenID Federation 1.0 §18.1)");
        }
        TrustChainValidator validator = new TrustChainValidator(
                new LocalFirstTrustControllerGateway(this.resolverGateway, this.localStatements(oidcIssuer)),
                this.resolverAnchors, this.resolverAlgorithms, this.resolverOptions);
        TrustChainValidationResult result = validator.validate(ValidationRequest.forSubject(subject)
                .requestedAnchors(request.trustAnchors())
                .includeAnchorConfiguration(true)
                .build());
        TrustMarkValidator.Result marks = new TrustMarkValidator(validator, this.resolverAlgorithms, this.clock, this.trustMarkStatusClient)
                .validate(result);
        Map<String, Object> metadata = new LinkedHashMap<>();
        for (Map.Entry<String, Object> type : result.resolvedMetadata().entrySet()) {
            if (request.entityTypes().isEmpty() || request.entityTypes().contains(type.getKey())) {
                metadata.put(type.getKey(), type.getValue());
            }
        }
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(oidcIssuer);
        claims.setSubject(subject);
        claims.setIssuedAt(NumericDate.fromSeconds(this.clock.instant().getEpochSecond()));
        // §8.3.2: "the minimum of the exp value of the Trust Chain ..., as well as any Trust Mark included in the response".
        long marksExpire = marks.earliestExpiry();
        claims.setExpirationTime(NumericDate.fromSeconds(marksExpire < 0 ? result.expEpochSeconds() : Math.min(result.expEpochSeconds(), marksExpire)));
        claims.setClaim("metadata", metadata);
        claims.setClaim("trust_chain", result.trustChain());
        if (!marks.verified().isEmpty()) {
            claims.setClaim("trust_marks", marks.asClaim());
        }
        LOGGER.info("Resolved " + subject + " to trust anchor " + result.trustAnchorIssuer() + " (" + result.trustChain().size()
                + " statements, " + result.fetchesUsed() + " fetches, " + marks.verified().size() + " of "
                + (marks.verified().size() + marks.rejected().size()) + " Trust Marks verified)");
        return this.signClaims(claims, RESOLVE_RESPONSE_TYP);
    }

    private boolean isKnown(String subject, String oidcIssuer) {
        return EntityId.same(subject, oidcIssuer) || this.configuration.isSubordinate(subject)
                || this.hostedSubordinateLookup != null && this.hostedSubordinateLookup.apply(subject) != null;
    }

    /**
     * The statements this entity issues, produced in-process for its own resolver: its Entity Configuration,
     * the configurations of the entities it hosts, and its Subordinate Statements.
     */
    LocalStatementSource localStatements(String oidcIssuer) {
        return new LocalStatements(oidcIssuer);
    }

    private final class LocalStatements implements LocalStatementSource {
        private final String self;

        LocalStatements(String self) {
            this.self = self;
        }

        @Override
        public String entityConfiguration(String entityId) throws Exception {
            if (EntityId.same(entityId, this.self)) {
                return FederationService.this.createEntityConfigurationJwt(this.self);
            }
            return FederationService.this.hostedConfiguration == null ? null : FederationService.this.hostedConfiguration.apply(entityId);
        }

        @Override
        public String subordinateStatement(String issuer, String subject) throws Exception {
            return EntityId.same(issuer, this.self) ? FederationService.this.fetchSubordinateStatement(null, subject, this.self) : null;
        }
    }

    // ---- foreign subordinates' keys ----------------------------------------------------------------------

    /**
     * Keep the subordinate entity-configuration cache perpetually fresh from a background daemon, so a
     * request NEVER blocks on a cross-network subordinate fetch. Called from servlet init. Two failure modes
     * drove this design, both observed live: (a) a freshly booted trust anchor's first token exchange
     * blocked on a cold fetch of each subordinate's {@code .well-known/openid-federation}; (b) after the
     * cache expired, the NEXT request ate a synchronous refresh - and the refresh path intermittently
     * stalled 15s+, which pushed the whole exchange past the calling agent platform's hard 30s tool timeout.
     * The refresher re-fetches every {@code REFRESH_INTERVAL_SECONDS} so {@link #fetchSubordinateJwks}
     * always finds a usable entry, and its serve-stale behaviour covers any window where refreshes fail.
     */
    public void prewarmSubordinatesAsync() {
        List<String> subs = this.configuration.subordinates();
        if (this.subordinateFetcher == null || subs.isEmpty()) {
            return;
        }
        Thread warmer = new Thread(() -> {
            while (true) {
                for (String subject : subs) {
                    try {
                        this.refreshSubordinateJwks(subject);
                        LOGGER.info("subordinate-refresh: cached entity configuration of " + subject);
                    } catch (Exception e) {
                        LOGGER.info("subordinate-refresh: " + subject + " not reachable (will retry; serving stale if cached): " + e.getMessage());
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
        if (!this.configuration.isSubordinate(subject)) {
            // The subject itself doesn't exist here — not_found (404), not a malformed request.
            throw new FederationEntityNotFoundException("Unknown subordinate: " + subject);
        }
        CachedSubordinateConfig cached = this.subordinateConfigCache.get(subject);
        if (cached != null) {
            // Serve whatever we have, fresh OR stale, without ever fetching on the request thread — the
            // background refresher (prewarmSubordinatesAsync) owns freshness. Subordinate federation keys
            // rotate rarely; serving a stale-but-signed key set until the refresher catches up is the right
            // trade.
            return cached.jwks;
        }
        if (this.subordinateFetcher == null) {
            throw new IllegalStateException("No subordinate fetcher configured; cannot learn keys for " + subject);
        }
        // Cold cache (request raced ahead of the boot-time refresher): fetch synchronously once.
        try {
            return this.refreshSubordinateJwks(subject);
        } catch (RuntimeException e) {
            throw new FederationException(FederationError.TEMPORARILY_UNAVAILABLE,
                    "the subordinate's entity configuration could not be fetched yet", e);
        }
    }

    /**
     * Live-fetch {@code subject}'s entity configuration and cache its jwks, Entity Types and role. Only called
     * with a fetcher configured (both callers check).
     */
    private Map<String, Object> refreshSubordinateJwks(String subject) {
        try {
            String body = this.subordinateFetcher.get(EntityId.wellKnownUrl(subject), ENTITY_STATEMENT_ACCEPT);
            JwtClaims selfConfig = JwtCodec.parseUnverifiedClaims(body);
            if (!EntityId.same(subject, selfConfig.getIssuer()) || !EntityId.same(subject, selfConfig.getSubject())) {
                throw new IllegalStateException("Entity configuration of " + subject + " is not self-signed (iss=" + selfConfig.getIssuer() + ", sub=" + selfConfig.getSubject() + ")");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> jwks = (Map<String, Object>) selfConfig.getClaimValue("jwks");
            if (jwks == null || jwks.isEmpty()) {
                throw new IllegalStateException("Entity configuration of " + subject + " contains no jwks");
            }
            Map<String, Object> metadata = com.pingidentity.ps.oidf.jose.Claims.optionalMap(selfConfig, "metadata");
            boolean intermediate = com.pingidentity.ps.oidf.jose.Claims.optionalNestedMap(metadata, "federation_entity")
                    .get("federation_fetch_endpoint") instanceof String;
            this.subordinateConfigCache.put(subject, new CachedSubordinateConfig(jwks, Set.copyOf(metadata.keySet()), intermediate));
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
        private final Set<String> entityTypes;
        private final boolean intermediate;

        private CachedSubordinateConfig(Map<String, Object> jwks, Set<String> entityTypes, boolean intermediate) {
            this.jwks = jwks;
            this.entityTypes = entityTypes;
            this.intermediate = intermediate;
        }
    }

    // ---- signing -------------------------------------------------------------------------------------

    private JwtClaims baseClaims(String issuer, String subject) {
        long now = this.clock.instant().getEpochSecond();
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(issuer);
        claims.setSubject(subject);
        claims.setIssuedAt(NumericDate.fromSeconds(now));
        claims.setExpirationTime(NumericDate.fromSeconds(now + STATEMENT_LIFETIME_SECONDS));
        return claims;
    }

    private String signClaims(JwtClaims claims, String typ) throws JoseException {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(this.signingKeyProvider.privateKey());
        jws.setAlgorithmHeaderValue(this.configuration.signingAlgorithm());
        jws.setHeader("typ", typ);
        jws.setKeyIdHeaderValue(this.signingKeyProvider.keyId());
        return jws.getCompactSerialization();
    }

    private Map<String, Object> buildInlineJwks() throws JoseException {
        RSAPublicKey pub = this.signingKeyProvider.publicKey();
        Objects.requireNonNull(pub, "signingKeys.publicKey()");
        RsaJsonWebKey jwk = new RsaJsonWebKey(pub);
        jwk.setUse("sig");
        jwk.setAlgorithm(this.configuration.signingAlgorithm());
        jwk.setKeyId(this.signingKeyProvider.keyId());
        String jwksJson = new JsonWebKeySet(new JsonWebKey[]{jwk}).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        return JsonUtil.parseJson(jwksJson);
    }

    /** Everything a {@link FederationService} can be given; only the configuration and signing keys are required. */
    public static final class Builder {
        private final FederationConfiguration configuration;
        private final SigningKeyProvider signingKeyProvider;
        private HttpGetClient subordinateFetcher;
        private Function<String, Map<String, Object>> hostedSubordinateLookup;
        private Function<String, List<String>> hostedSubordinateIds;
        private Function<String, String> hostedConfiguration;
        private BooleanSupplier hosting;
        private String federationBasePath = "";
        private TrustAnchorSet resolverAnchors;
        private TrustControllerGateway resolverGateway;
        private Set<String> resolverAlgorithms;
        private ValidatorOptions resolverOptions;
        private HttpPostClient trustMarkStatusClient;
        private TrustMarkIssuing trustMarkIssuing;
        private List<Map<String, Object>> ownTrustMarks = List.of();
        private Map<String, List<String>> trustMarkIssuers = Map.of();
        private Map<String, Object> trustMarkOwners = Map.of();
        private Clock clock;

        private Builder(FederationConfiguration configuration, SigningKeyProvider signingKeyProvider) {
            this.configuration = configuration;
            this.signingKeyProvider = signingKeyProvider;
        }

        /** Fetches each foreign subordinate's entity configuration, for its keys. */
        public Builder subordinateFetcher(HttpGetClient fetcher) {
            this.subordinateFetcher = fetcher;
            return this;
        }

        /** subject -> {@code {"jwks": ..., "metadata_policy"?: ...}} for a hosted entity, or null. */
        public Builder hostedSubordinateLookup(Function<String, Map<String, Object>> lookup) {
            this.hostedSubordinateLookup = lookup;
            return this;
        }

        /**
         * entity_type (possibly null) -> the hosted entity ids the list endpoint includes for that filter,
         * already restricted to listable, resolvable entities.
         */
        public Builder hostedSubordinateIds(Function<String, List<String>> ids) {
            this.hostedSubordinateIds = ids;
            return this;
        }

        /** entity id -> the hosted entity's signed Entity Configuration, or null; used by the resolver. */
        public Builder hostedConfiguration(Function<String, String> configuration) {
            this.hostedConfiguration = configuration;
            return this;
        }

        /** Whether this deployment hosts entities (asked per request: hosting may be configured after start). */
        public Builder hosting(BooleanSupplier hosting) {
            this.hosting = hosting;
            return this;
        }

        /**
         * The servlet context path this entity's {@code /federation/*} endpoints are served under (e.g.
         * {@code "/oidf"}), or {@code ""} at the root. The entity's identity stays the path-less OAuth issuer;
         * the endpoints it advertises must carry the context path or a peer following them gets a 404.
         */
        public Builder federationBasePath(String path) {
            this.federationBasePath = path;
            return this;
        }

        /** Enables the resolve endpoint: the anchors it resolves against and the gateway it fetches through. */
        public Builder resolver(TrustAnchorSet anchors, TrustControllerGateway gateway, Set<String> acceptedAlgorithms,
                                ValidatorOptions options) {
            this.resolverAnchors = anchors;
            this.resolverGateway = gateway;
            this.resolverAlgorithms = acceptedAlgorithms;
            this.resolverOptions = options;
            return this;
        }

        /** Issues Trust Marks (§7, §8.4-§8.6) under the grants {@code issuing} decides on. */
        public Builder trustMarkIssuing(TrustMarkIssuing issuing) {
            this.trustMarkIssuing = issuing;
            return this;
        }

        /** Trust Marks from other issuers this entity carries in its own configuration (§3.1.2). */
        public Builder ownTrustMarks(List<Map<String, Object>> marks) {
            this.ownTrustMarks = marks == null ? List.of() : marks;
            return this;
        }

        /**
         * As a trust anchor: whose Trust Marks of each type the federation accepts ({@code trust_mark_issuers}, §3.1.2).
         * This entity is added for the types it issues itself.
         */
        public Builder trustMarkIssuers(Map<String, List<String>> issuers) {
            this.trustMarkIssuers = issuers == null ? Map.of() : issuers;
            return this;
        }

        /** As a trust anchor: who owns which Trust Mark type ({@code trust_mark_owners}, §3.1.2). */
        public Builder trustMarkOwners(Map<String, Object> owners) {
            this.trustMarkOwners = owners == null ? Map.of() : owners;
            return this;
        }

        /** Asks each Trust Mark issuer's status endpoint (§8.4) about a mark before a resolve response carries it. */
        public Builder trustMarkStatus(HttpPostClient client) {
            this.trustMarkStatusClient = client;
            return this;
        }

        public Builder clock(Clock clock) {
            this.clock = clock;
            return this;
        }

        public FederationService build() {
            return new FederationService(this);
        }
    }
}
