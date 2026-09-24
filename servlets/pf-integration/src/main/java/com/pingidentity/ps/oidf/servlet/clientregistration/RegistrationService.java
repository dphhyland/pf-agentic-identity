package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.ExpiryEnforcement;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.federation.EntityId;
import com.pingidentity.ps.oidf.federation.FederationException;
import com.pingidentity.ps.oidf.federation.HttpTrustControllerGateway;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.jose.JdkHttpGetClient;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.pf.PfJwksSigningKeyProvider;
import com.pingidentity.ps.oidf.pf.PfMgmtClientStore;
import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import com.pingidentity.ps.oidf.federation.SubordinateStatementCache;
import com.pingidentity.ps.oidf.federation.TrustChainValidationResult;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.federation.ValidationRequest;
import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalLong;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ClientAuthenticationType;
import org.sourceid.oauth20.domain.ParamValues;

/**
 * OpenID Federation 1.0 §12 client registration on PingFederate: explicit registration (§12.2), automatic
 * registration at the token endpoint (§12.1), and the lifetime every registration has (§12.3).
 *
 * <p>Order matters and is the whole point: the trust chain is validated first; only then is the client
 * store consulted, and a client this module did not register (no {@code status} extended parameter - a
 * console or Terraform client) is never modified.
 *
 * <p>Every registration records when it ends: the earlier of its chain's expiry and the deployment's maximum
 * ({@link RegistrationLifetime}). An automatically registered client is renewed at the token endpoint as it
 * nears that time ({@link #admit}); an explicitly registered one is renewed by its RP registering again, as
 * §12.3 says. What an expired registration that cannot be renewed gets is the deployment's choice:
 * {@link ExpiryEnforcement}.
 */
final class RegistrationService {
    static final String STATUS_REGISTERED = "registered";
    static final String STATUS_AUTO = "auto_registered";
    private static final String RESPONSE_TYP = "explicit-registration-response+jwt";
    private static final String RELYING_PARTY = "openid_relying_party";
    private static final String OAUTH_CLIENT = "oauth_client";
    /** A registration renewed this recently is not renewed again for being due: its chain may simply be short-lived. */
    static final long RENEWAL_MIN_INTERVAL_SECONDS = 60L;
    /** A failed attempt is not repeated with the same hint for this long: the request that triggers it is unauthenticated. */
    static final long TRUST_FAILURE_BACKOFF_SECONDS = 60L;
    static final long TRANSPORT_FAILURE_BACKOFF_SECONDS = 15L;
    private static final int ATTEMPT_MEMORY = 4096;
    private final RegistrationConfiguration configuration;
    private final TrustChainValidator trustChainValidator;
    private final ClientStore clientStore;
    private final SigningKeyProvider signingKeyProvider;
    private final RegistrationLifetime lifetime;
    /**
     * Recent attempts: a failure under its client and hint, so a caller's bad chain never stands in for the client's
     * own or for discovery, and a success under its client alone.
     */
    private final Map<String, Attempt> recentAttempts = java.util.Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Attempt> eldest) {
            return this.size() > ATTEMPT_MEMORY;
        }
    });
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    static final Log LOGGER = LogFactory.getLog(RegistrationService.class);

    /** What the token endpoint may do with a request naming a client. */
    enum Admission {
        /** Not a client this module registered, and no chain to register one from: PingFederate decides. */
        NOT_FEDERATION,
        /** A federation client whose registration is current. */
        CURRENT,
        /** Registered now, from the chain the request presented. */
        REGISTERED,
        /** Renewed now: its chain validated again and the registration's life was extended. */
        RENEWED,
        /** Due for renewal, not yet expired, and renewal failed: the current registration stands for now. */
        DEFERRED,
        /** Expired and not renewed, and the deployment only logs that ({@link ExpiryEnforcement#LOG}). */
        EXPIRED_ALLOWED
    }

    /** One registration attempt: when, and why it failed - null when it did not. */
    private record Attempt(long at, RegistrationRejectedException failure) {
    }

    /**
     * The production wiring. The anchors' keys come from {@link FederationRuntimeConfig#trustAnchors()}
     * - the same deployment-wide source the configuration's host came from - so a deployment that has
     * not pinned them fails at init, here, rather than at the first chain. A chain registers through
     * whichever pinned anchor it reaches.
     */
    RegistrationService(RegistrationConfiguration configuration) {
        this(configuration, new TrustChainValidator(new HttpTrustControllerGateway(new JdkHttpGetClient(configuration.ignoreSslErrors(), OutboundUrlPolicy.fromEnvironment()
                        .trusting(configuration.trustControllerBaseUrl(), configuration.trustControllerHost())), configuration.trustControllerBaseUrl(), configuration.trustControllerHost(), new SubordinateStatementCache(configuration.subordinateStatementCacheMaxEntries())), FederationRuntimeConfig.get().trustAnchors(), configuration.acceptedSigningAlgorithms(), ValidatorOptions.defaults()), new PfMgmtClientStore(), null);
    }

    RegistrationService(RegistrationConfiguration configuration, TrustChainValidator trustChainValidator, ClientStore clientStore) {
        this(configuration, trustChainValidator, clientStore, null);
    }

    RegistrationService(RegistrationConfiguration configuration, TrustChainValidator trustChainValidator, ClientStore clientStore, SigningKeyProvider signingKeyProvider) {
        this(configuration, trustChainValidator, clientStore, signingKeyProvider,
                new RegistrationLifetime(FederationRuntimeConfig.get().registration(), Clock.systemUTC()));
    }

    RegistrationService(RegistrationConfiguration configuration, TrustChainValidator trustChainValidator, ClientStore clientStore,
                        SigningKeyProvider signingKeyProvider, RegistrationLifetime lifetime) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.trustChainValidator = Objects.requireNonNull(trustChainValidator, "trustChainValidator");
        this.clientStore = Objects.requireNonNull(clientStore, "clientStore");
        this.signingKeyProvider = signingKeyProvider;
        this.lifetime = Objects.requireNonNull(lifetime, "lifetime");
    }

    RegistrationLifetime lifetime() {
        return this.lifetime;
    }

    // ---- explicit registration (§12.2) -------------------------------------------------------------------

    /**
     * §12.2 explicit registration: the chain from the posted Entity Configuration validated first (its
     * metadata is what is registered, §12.2.2), then the client created or refreshed in place - which is how
     * "that registration MUST be invalidated" is met for a repeat request: the old one is replaced whole.
     *
     * @return the registration and the signed {@code explicit-registration-response+jwt} for it (§12.2.3)
     */
    RegisteredClient explicitRegister(ExplicitRegistrationRequest request, String opIssuer) throws Exception {
        Objects.requireNonNull(request, "request");
        TrustChainValidationResult validation = this.validate(ValidationRequest.forSubject(request.issuer())
                .presentedChain(request.presentedChain())
                .opIssuer(opIssuer)
                .peerTrustChain(request.peerTrustChain())
                .maxPresentedEntryAgeSeconds(this.configuration.trustChainEntryMaxAgeSeconds())
                .build());
        String clientId = request.sub();
        String trustAnchorIssuer = validation.trustAnchorIssuer();
        String rpSubject = validation.leafSubject();
        String entityType = clientEntityType(validation, RELYING_PARTY);
        Map<String, Object> leafMetadata = federationClientMetadata(validation, entityType, clientId);
        requireRegistrationType(leafMetadata, clientId, "explicit");

        Client existing = this.clientStore.get(clientId);
        if (existing != null && !isFederationRegistered(existing)) {
            throw new RegistrationRejectedException(409, "invalid_client_metadata",
                    "client_id " + clientId + " is administered outside OpenID Federation and cannot be registered through it");
        }
        // Deliberately after the 409: a client that is not ours to touch should be told so, rather than
        // told its chain lacks a policy - the first is the actionable answer and the more specific one.
        requireConstrainedByPolicy(validation, entityType, clientId);
        long expiresAt = this.lifetime.expiresAt(validation);

        Map<String, Object> rpJwks = jwksOf(validation);
        LinkedHashMap<String, Object> registered = new LinkedHashMap<String, Object>(leafMetadata);
        registered.put("client_id", clientId);
        registered.put("client_id_issued_at", this.lifetime.now());
        // §12.2.3 SHOULD: the parameters that have a default, as registered.
        registered.putIfAbsent("token_endpoint_auth_method", "private_key_jwt");
        String signedJwt = this.buildSignedRegistrationResponse(opIssuer, rpSubject, trustAnchorIssuer, immediateSuperior(validation),
                rpJwks, entityType, registered, expiresAt);
        Client client = buildClient(clientId, leafMetadata, rpJwks, validation.trustChain(), STATUS_REGISTERED, expiresAt, trustAnchorIssuer, entityType);
        this.store(client, existing);
        if (existing != null) {
            LOGGER.info((Object)("Refreshed federation client " + clientId + " via explicit registration (trust anchor " + trustAnchorIssuer + ")"));
        } else {
            LOGGER.info((Object)("Explicitly registered federation client " + clientId + " (trust anchor " + trustAnchorIssuer + ")"));
        }
        this.registrationEvent(existing == null ? FederationEvents.REGISTRATION_CREATED : FederationEvents.REGISTRATION_REFRESHED,
                clientId, trustAnchorIssuer, "explicit", entityType, expiresAt, existing, client);
        return new RegisteredClient(clientId, rpSubject, trustAnchorIssuer, validation.trustChain(), registered, STATUS_REGISTERED, signedJwt, expiresAt);
    }

    // ---- automatic registration (§12.1) and renewal (§12.3) -------------------------------------------------

    /**
     * §12.1 automatic registration: the chain validated - from {@code presented} when the request carried one,
     * by discovery when it did not - and the client provisioned just-in-time from its resolved metadata, or
     * refreshed in place when this module registered it automatically before.
     *
     * @throws RegistrationRejectedException when the chain does not validate, the entity does not advertise
     *                                       {@code automatic}, or its metadata cannot become a client here
     */
    private void registerAutomatically(List<String> presented, String clientId, String opIssuer, Client existing) throws Exception {
        TrustChainValidationResult validation = this.validate(ValidationRequest.forSubject(clientId)
                .presentedChain(presented)
                .opIssuer(opIssuer)
                .maxPresentedEntryAgeSeconds(this.configuration.trustChainEntryMaxAgeSeconds())
                .build());
        String entityType = clientEntityType(validation, OAUTH_CLIENT);
        Map<String, Object> leafMetadata = federationClientMetadata(validation, entityType, clientId);
        requireRegistrationType(leafMetadata, clientId, "automatic");
        requireConstrainedByPolicy(validation, entityType, clientId);
        long expiresAt = this.lifetime.expiresAt(validation);
        Client client = buildClient(clientId, leafMetadata, jwksOf(validation), validation.trustChain(), STATUS_AUTO, expiresAt,
                validation.trustAnchorIssuer(), entityType);
        this.store(client, existing);
        if (existing != null) {
            // An auto-registered client is wholly derived from its (just re-validated) trust chain, so a
            // chain presenting new keys/metadata refreshes the record — this is how §12.1 key rotation
            // works: the federation, not the stored copy, is the authority.
            LOGGER.info((Object)("Refreshed auto-registered federation client " + clientId + " (trust anchor " + validation.trustAnchorIssuer() + ")"));
        } else {
            // The demo's activity panel parses this line; keep its wording.
            LOGGER.info((Object)("Automatically registered federation client " + clientId + " (trust anchor " + validation.trustAnchorIssuer() + ")"));
        }
        this.registrationEvent(existing == null ? FederationEvents.REGISTRATION_CREATED : FederationEvents.REGISTRATION_REFRESHED,
                clientId, validation.trustAnchorIssuer(), "automatic", entityType, expiresAt, existing, client);
    }

    /**
     * What the token endpoint does with a request naming {@code clientId}, before PingFederate authenticates
     * it. The request is not authenticated yet, so nothing here trusts it: the chain it presents is only ever
     * a hint, validated like any other; a presented chain that fails never costs a client its current
     * registration, and never stands in for the client's own attempts.
     *
     * <ul>
     *   <li>No such client: registered automatically from the presented chain, or left to PingFederate when
     *       there is none.</li>
     *   <li>A client this module did not register: left to PingFederate.</li>
     *   <li>An explicit registration: current until it expires; after that only its RP can renew it, by
     *       registering again (§12.3), and the expiry is enforced.</li>
     *   <li>An automatic registration: renewed when it nears expiry, or when the request presents a newer Entity
     *       Configuration with different keys or metadata - the notice of a change §12.5 describes. A renewal
     *       that fails before expiry leaves the registration standing; after expiry the chain is tried again by
     *       discovery, and if that fails too the expiry is enforced.</li>
     * </ul>
     *
     * <p>A failed attempt is not repeated with the same hint within its backoff, a registration renewed in the
     * last {@value #RENEWAL_MIN_INTERVAL_SECONDS}s is not renewed again for being due, and a presented Entity
     * Configuration older than the registered one is never used - replaying it would roll the registration
     * back to keys the client has retired.
     *
     * @throws RegistrationRejectedException when the request must be refused
     */
    Admission admit(String clientId, List<String> hint, String opIssuer) throws Exception {
        List<String> presented = hint == null ? List.of() : hint;
        Client existing = this.clientStore.get(clientId);
        if (existing == null) {
            if (presented.isEmpty()) {
                return Admission.NOT_FEDERATION;
            }
            RegistrationRejectedException recent = this.recentFailure(clientId, presented);
            if (recent != null) {
                throw recent;
            }
            this.register(presented, clientId, opIssuer, null);
            return Admission.REGISTERED;
        }
        String status = extendedParamValue(existing, FederationClientParams.STATUS);
        if (!STATUS_AUTO.equals(status) && !STATUS_REGISTERED.equals(status)) {
            return Admission.NOT_FEDERATION;
        }
        OptionalLong expiresAt = RegistrationLifetime.storedExpiry(existing);
        boolean expired = this.lifetime.isExpired(expiresAt);
        if (STATUS_REGISTERED.equals(status)) {
            if (!expired) {
                return Admission.CURRENT;
            }
            return this.enforceExpiry(existing, clientId, new RegistrationRejectedException(401, "invalid_client",
                    "the client's explicit registration has expired; its RP renews it by registering again (OpenID Federation 1.0 §12.3)",
                    RegistrationRejectedException.Kind.TRUST, null));
        }
        boolean changed = presentsChange(presented, existing, clientId);
        if (!expired && !changed && (!this.lifetime.isDueForRenewal(expiresAt) || this.renewedRecently(clientId))) {
            return Admission.CURRENT;
        }
        List<String> renewFrom = predatesRegistration(presented, existing, clientId) ? List.of() : presented;
        RegistrationRejectedException reason = this.recentFailure(clientId, renewFrom);
        if (reason == null) {
            try {
                this.register(renewFrom, clientId, opIssuer, existing);
                return Admission.RENEWED;
            } catch (RegistrationRejectedException e) {
                reason = e;
                if (!expired) {
                    FederationEvents.event(FederationEvents.REGISTRATION_REFRESH_DEFERRED).failure(kindCode(e)).subject(clientId)
                            .role("OP").description(e.getMessage()).emit();
                }
            }
        }
        if (!expired) {
            return Admission.DEFERRED;
        }
        if (!renewFrom.isEmpty()) {
            // The presented chain is the caller's; the federation's own answer is what counts.
            RegistrationRejectedException byDiscovery = this.recentFailure(clientId, List.of());
            if (byDiscovery == null) {
                try {
                    this.register(List.of(), clientId, opIssuer, existing);
                    return Admission.RENEWED;
                } catch (RegistrationRejectedException e) {
                    byDiscovery = e;
                }
            }
            reason = byDiscovery;
        }
        return this.enforceExpiry(existing, clientId, reason);
    }

    /** Registers or renews {@code clientId} from {@code hint} (empty: by discovery), remembering how it went. */
    private void register(List<String> hint, String clientId, String opIssuer, Client existing) throws Exception {
        try {
            this.registerAutomatically(hint, clientId, opIssuer, existing);
        } catch (RegistrationRejectedException e) {
            this.recentAttempts.put(failureKey(clientId, hint), new Attempt(this.lifetime.now(), e));
            throw e;
        }
        this.recentAttempts.put(renewalKey(clientId), new Attempt(this.lifetime.now(), null));
    }

    private Admission enforceExpiry(Client existing, String clientId, RegistrationRejectedException reason) throws RegistrationRejectedException {
        ExpiryEnforcement enforcement = this.lifetime.settings().expiryEnforcement();
        FederationEvents.event(FederationEvents.REGISTRATION_EXPIRED).failure(kindCode(reason))
                .subject(clientId).role("OP").field("enforcement", enforcement.name().toLowerCase(java.util.Locale.ROOT))
                .audit().description(reason.getMessage()).emit();
        if (enforcement == ExpiryEnforcement.LOG) {
            LOGGER.warn((Object)("Federation client " + clientId + " is past its registration's expiry and could not be renewed ("
                    + reason.getMessage() + "); allowed because " + FederationRuntimeConfig.REGISTRATION_EXPIRY_ENFORCEMENT_ENV + "=log"));
            return Admission.EXPIRED_ALLOWED;
        }
        if (enforcement == ExpiryEnforcement.DISABLE && existing.isEnabled()) {
            disableExpired(this.clientStore, existing, this.lifetime.now());
            FederationEvents.event(FederationEvents.REGISTRATION_DISABLED).subject(clientId).role("OP").audit()
                    .description("expired and not renewed").emit();
        }
        boolean transport = reason.isTransport();
        throw new RegistrationRejectedException(transport ? 503 : 401, transport ? "temporarily_unavailable" : "invalid_client",
                transport ? "the client's federation registration has expired and its trust chain cannot be checked right now"
                        : "the client's federation registration has expired and could not be renewed: " + reason.getMessage(),
                reason.kind(), reason);
    }

    /**
     * Disables a client whose registration expired, marking it ({@link FederationClientParams#DISABLED_AT}) so that
     * a renewal knows the disable was this module's to undo.
     */
    static void disableExpired(ClientStore store, Client client, long now) {
        Map<String, ParamValues> params = client.getExtendedParams() == null ? new HashMap<>() : new HashMap<>(client.getExtendedParams());
        addParamValue(params, FederationClientParams.DISABLED_AT, Long.toString(now));
        client.setExtendedParams(params);
        store.disable(client);
    }

    private static String kindCode(RegistrationRejectedException e) {
        return e.kind().name().toLowerCase(java.util.Locale.ROOT);
    }

    private boolean renewedRecently(String clientId) {
        Attempt renewal = this.recentAttempts.get(renewalKey(clientId));
        return renewal != null && this.lifetime.now() - renewal.at() < RENEWAL_MIN_INTERVAL_SECONDS;
    }

    /** The failure of the same attempt - this client, this hint - within its backoff, or null. */
    private RegistrationRejectedException recentFailure(String clientId, List<String> hint) {
        String key = failureKey(clientId, hint);
        Attempt attempt = this.recentAttempts.get(key);
        if (attempt == null) {
            return null;
        }
        long backoff = attempt.failure().isTransport() ? TRANSPORT_FAILURE_BACKOFF_SECONDS : TRUST_FAILURE_BACKOFF_SECONDS;
        if (this.lifetime.now() - attempt.at() >= backoff) {
            this.recentAttempts.remove(key);
            return null;
        }
        return attempt.failure();
    }

    private static String renewalKey(String clientId) {
        return "renewed\n" + clientId;
    }

    /** A failure is keyed by the statement the attempt started from: another caller's chain is another attempt. */
    private static String failureKey(String clientId, List<String> hint) {
        return "failed\n" + clientId + "\n" + (hint.isEmpty() ? "" : sha256Hex(hint.get(0)));
    }

    private static String sha256Hex(String value) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    /**
     * Whether the presented chain gives notice of a change (§12.5): its first statement is {@code clientId}'s own
     * Entity Configuration, issued after the one the registration was built from, with other keys or metadata.
     * Nothing here is verified - a notice only earns a renewal attempt, which validates like any other.
     */
    static boolean presentsChange(List<String> presented, Client registered, String clientId) {
        JwtClaims offered = entityConfiguration(presented.isEmpty() ? null : presented.get(0), clientId);
        if (offered == null) {
            return false;
        }
        JwtClaims current = entityConfiguration(firstChainEntry(registered), clientId);
        if (current == null) {
            return true;
        }
        return issuedAt(offered) > issuedAt(current)
                && (!Objects.equals(offered.getClaimValue("jwks"), current.getClaimValue("jwks"))
                        || !Objects.equals(offered.getClaimValue("metadata"), current.getClaimValue("metadata")));
    }

    /** Whether the presented Entity Configuration is older than the one the registration was built from. */
    static boolean predatesRegistration(List<String> presented, Client registered, String clientId) {
        JwtClaims offered = entityConfiguration(presented.isEmpty() ? null : presented.get(0), clientId);
        JwtClaims current = offered == null ? null : entityConfiguration(firstChainEntry(registered), clientId);
        return current != null && issuedAt(offered) < issuedAt(current);
    }

    /** The unverified claims of {@code jwt} when it is {@code clientId}'s Entity Configuration, else null. */
    private static JwtClaims entityConfiguration(String jwt, String clientId) {
        if (jwt == null) {
            return null;
        }
        try {
            JwtClaims claims = JwtCodec.parseUnverifiedClaims(jwt);
            return EntityId.same(claims.getIssuer(), clientId) && EntityId.same(claims.getSubject(), clientId) ? claims : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static long issuedAt(JwtClaims claims) {
        Object iat = claims.getClaimValue("iat");
        return iat instanceof Number number ? number.longValue() : Long.MIN_VALUE;
    }

    // ---- shared ------------------------------------------------------------------------------------------

    private TrustChainValidationResult validate(ValidationRequest request) throws RegistrationRejectedException {
        try {
            return this.trustChainValidator.validate(request);
        } catch (FederationException e) {
            FederationEvents.event(FederationEvents.REGISTRATION_REFUSED).failure(e.error().code()).subject(request.subject())
                    .role("OP").audit().description(e.description()).emit();
            throw RegistrationRejectedException.from(e);
        }
    }

    /**
     * Writes a freshly derived client over the old one. A client this module disabled because its registration
     * expired comes back enabled; one disabled by anyone else - an operator - stays disabled.
     */
    private void store(Client client, Client existing) {
        if (existing == null) {
            this.clientStore.add(client);
            return;
        }
        if (!existing.isEnabled()) {
            boolean disabledHere = extendedParamValue(existing, FederationClientParams.DISABLED_AT) != null;
            client.setEnabled(disabledHere);
            if (!disabledHere) {
                LOGGER.info((Object)("Federation client " + client.getClientId() + " was renewed but stays disabled: it was"
                        + " disabled by an operator, not by its registration expiring"));
            }
        }
        this.clientStore.update(client);
    }

    /**
     * The audit record of a registration written. A refresh - §12.2.2's "that registration MUST be invalidated",
     * met by replacing it whole - also says when the old one would have ended and whether the keys changed.
     */
    private void registrationEvent(String code, String clientId, String anchor, String type, String entityType, long expiresAt,
                                   Client previous, Client written) {
        com.pingidentity.ps.oidf.federation.event.FederationEvent.Builder event = FederationEvents.event(code).subject(clientId).partner(anchor).role("OP")
                .field("type", type).field("entity_type", entityType).field("expires_at", expiresAt).audit();
        if (previous != null) {
            RegistrationLifetime.storedExpiry(previous).ifPresent(p -> event.field("previous_expires_at", p));
            event.field("keys_changed", !sameKeys(previous.getJwks(), written.getJwks()));
        }
        event.emit();
    }

    /** Whether two stored JWK Sets hold the same keys, however their JSON was laid out. */
    static boolean sameKeys(String a, String b) {
        if (a == null || b == null) {
            return a == null && b == null;
        }
        try {
            return OBJECT_MAPPER.readTree(a).equals(OBJECT_MAPPER.readTree(b));
        } catch (java.io.IOException e) {
            return false;
        }
    }

    /** The first statement of the chain stored on a client - its entity configuration when it was registered. */
    private static String firstChainEntry(Client client) {
        Map<String, ParamValues> params = client.getExtendedParams();
        ParamValues values = params == null ? null : params.get("trust_chain");
        List<String> elements = values == null ? null : values.getElements();
        return elements == null || elements.isEmpty() ? null : elements.get(0);
    }

    /** The subject's own key set: the {@code jwks} of its verified Entity Configuration. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> jwksOf(TrustChainValidationResult validation) {
        Object jwks = validation.leafEntityStatement().getClaimValue("jwks");
        return jwks instanceof Map ? (Map<String, Object>) jwks : Map.of();
    }

    /** §12.2.3: the RP's Immediate Superior in the selected chain - the issuer of the statement about it. */
    private static String immediateSuperior(TrustChainValidationResult validation) throws Exception {
        List<String> chain = validation.trustChain();
        return chain.size() < 2 ? validation.trustAnchorIssuer() : JwtCodec.parseUnverifiedClaims(chain.get(1)).getIssuer();
    }

    /**
     * The leaf's client metadata under {@code entityType}: {@code oauth_client} (agents) or
     * {@code openid_relying_party} (OIDC RPs).
     */
    private static Map<String, Object> federationClientMetadata(TrustChainValidationResult validation, String entityType, String clientId)
            throws RegistrationRejectedException {
        Map<String, Object> leafMetadata = validation.metadataFor(entityType);
        if (leafMetadata.isEmpty()) {
            throw new RegistrationRejectedException(400, "invalid_client_metadata",
                    "the resolved entity has no oauth_client or openid_relying_party metadata, so " + clientId + " cannot be registered");
        }
        return leafMetadata;
    }

    /**
     * Which entity type this registration consumes: {@code preferred} when the leaf carries it, otherwise the
     * other client type. Explicit registration prefers {@code openid_relying_party} - the type §12.2 is written
     * for - and the token endpoint {@code oauth_client}, the agents' type (§12(3) lets an OAuth profile use it
     * in place of the RP's). The policy check and the response use the type chosen here, so they agree.
     */
    private static String clientEntityType(TrustChainValidationResult validation, String preferred) {
        if (!validation.metadataFor(preferred).isEmpty()) {
            return preferred;
        }
        return OAUTH_CLIENT.equals(preferred) ? RELYING_PARTY : OAUTH_CLIENT;
    }

    /**
     * Refuses a client whose metadata no superior in the trust chain constrained.
     *
     * <p>{@link com.pingidentity.ps.oidf.federation.MetadataPolicy} applies a {@code metadata_policy}
     * faithfully — but a chain is under no obligation to declare one, and when none does, the leaf's
     * self-published metadata is resolved verbatim. Everything this method's caller then writes onto a
     * PF client — {@code scope}, {@code grant_types}, {@code response_types} — is whatever the entity
     * asked for. The trust chain still proves the entity is who it says and that the anchor vouches for
     * its existence; it does not, on its own, say what the entity may do.
     *
     * <p>So this fails closed by default: an anchor that has not published a policy for the entity type
     * being registered gets a rejection rather than a client with unbounded scope. The policy itself is
     * anchor configuration and lives with whoever deploys the federation; the DEFAULT belongs here,
     * because a permissive default is invisible in exactly the deployments least likely to notice.
     *
     * <p>Note the type checked is the one actually consumed ({@link #clientEntityType}): at the token endpoint
     * that is {@code oauth_client} when the leaf has it, so an anchor that publishes only an
     * {@code openid_relying_party} policy has constrained nothing for an agent, and is treated as such.
     */
    private static void requireConstrainedByPolicy(TrustChainValidationResult validation, String entityType, String clientId)
            throws RegistrationRejectedException {
        if (validation.isPoliced(entityType) || !FederationRuntimeConfig.get().requireMetadataPolicy()) {
            return;
        }
        throw new RegistrationRejectedException(400, "invalid_client_metadata",
                "no superior in the trust chain declares a metadata_policy for " + entityType + ", so "
                        + clientId + " would be registered with the scope, grant_types and response_types "
                        + "it published about itself. Publish a metadata_policy at the trust anchor (or an "
                        + "intermediate), or set " + FederationRuntimeConfig.REQUIRE_METADATA_POLICY_ENV
                        + "=false to accept unconstrained federation metadata.", RegistrationRejectedException.Kind.POLICY, null);
    }

    private static void requireRegistrationType(Map<String, Object> leafMetadata, String clientId, String type) throws RegistrationRejectedException {
        Object regTypes = leafMetadata.get("client_registration_types");
        if (!(regTypes instanceof List) || !((List<?>) regTypes).contains(type)) {
            throw new RegistrationRejectedException(400, "invalid_client_metadata",
                    "client " + clientId + " does not advertise client_registration_types=" + type + "; refusing " + type + " registration");
        }
    }

    /** True when this module registered the client (explicitly or automatically); false for console/Terraform clients. */
    private static boolean isFederationRegistered(Client client) {
        String status = extendedParamValue(client, FederationClientParams.STATUS);
        return STATUS_REGISTERED.equals(status) || STATUS_AUTO.equals(status);
    }

    /**
     * The §12.2.3 explicit registration response: signed with a Federation Entity Key, typed
     * {@code explicit-registration-response+jwt}, {@code aud} the RP alone, {@code exp} the registration's
     * expiry, {@code trust_anchor} the anchor its chain reached, {@code authority_hints} its Immediate
     * Superior, {@code jwks} a verbatim copy of the RP's own, and the registered metadata. An RP's is under
     * {@code openid_relying_party}; an agent registered from {@code oauth_client} metadata gets it under that
     * type instead - the OAuth reading of a response §12 writes for OpenID Connect.
     */
    private String buildSignedRegistrationResponse(String opIssuer, String rpIssuer, String trustAnchorIssuer, String authorityHint,
                                                   Map<String, Object> rpJwks, String entityType, Map<String, Object> rpMetadata,
                                                   long expiresAt) throws JoseException {
        SigningKeyProvider signingKeys = this.resolveSigningKeyProvider();
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(opIssuer);
        claims.setSubject(rpIssuer);
        claims.setAudience(rpIssuer);
        claims.setIssuedAt(NumericDate.fromSeconds(this.lifetime.now()));
        claims.setExpirationTime(NumericDate.fromSeconds(expiresAt));
        claims.setClaim("trust_anchor", trustAnchorIssuer);
        claims.setClaim("authority_hints", List.of(authorityHint));
        claims.setClaim("jwks", rpJwks);
        claims.setClaim("metadata", Map.of(entityType, rpMetadata));
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(signingKeys.privateKey());
        jws.setAlgorithmHeaderValue(this.configuration.signingAlgorithm());
        jws.setHeader("typ", RESPONSE_TYP);
        jws.setKeyIdHeaderValue(signingKeys.keyId());
        return jws.getCompactSerialization();
    }

    private SigningKeyProvider resolveSigningKeyProvider() {
        return this.signingKeyProvider != null ? this.signingKeyProvider : new PfJwksSigningKeyProvider(this.configuration.signingAlgorithm());
    }

    private static Client buildClient(String clientId, Map<String, Object> metadata, Map<String, Object> jwks, List<String> trustChain,
                                      String status, long expiresAt, String trustAnchor, String entityType) throws Exception {
        Client client = new Client();
        Map<String, Object> oidcRPMetadata = metadata;
        String tokenEndpointAuthMethod = metadataString(oidcRPMetadata, "token_endpoint_auth_method");
        boolean attestationAuth = "attest_jwt_client_auth".equals(tokenEndpointAuthMethod) || "attest_jwt_client_auth_dpop".equals(tokenEndpointAuthMethod);
        // PingFederate has no native attest_jwt_client_auth type. It used to be mapped to NONE - a
        // PUBLIC client - on the theory that ClientAttestationAuthFilter and the OGNL issuance
        // criterion would authenticate it instead. But the filter passes through when no bridge key is
        // configured, and no environment in this repo sets one, so that composition produced
        // JIT-registered clients PF would accept with no credential at all. Attestation clients are
        // now PRIVATE_KEY_JWT authenticated by their OWN registered keys: the filter mints an assertion
        // under the client's own key (BridgeSigners), so PF's native authenticator makes the decision,
        // and a client with no signing key configured simply cannot authenticate (fail closed) rather
        // than authenticating trivially.
        client.setClientAuthnType(ClientAuthenticationType.PRIVATE_KEY_JWT);
        // The client's own registered JWKS, unmodified. Nothing is injected here any more: the bridge
        // signs with the key this client is ALREADY registered with, so there is no deployment key whose
        // public half has to be merged in - and no ordering trap where a client registered before that
        // key existed never carried it.
        client.setJwks(OBJECT_MAPPER.writeValueAsString(jwks));
        // String.valueOf(null) is the string "null", not null. Every one of these used to write that
        // literal into PF whenever the leaf omitted the field - a client actually named "null", signing
        // algorithms of "null", and (worst) a client restricted to a scope called "null", which is a
        // scope no token will ever carry. metadataString is the null-safe reader; use it.
        client.setName(metadataString(oidcRPMetadata, "client_name"));
        // An oauth_client doing client_credentials legitimately has no redirect_uris / response_types,
        // but PF's XML client store iterates these lists unguarded at save time — never pass null.
        List redirectUris = (List)oidcRPMetadata.get("redirect_uris");
        client.setRedirectUris(redirectUris != null ? redirectUris : new ArrayList<>());
        List responseTypes = (List)oidcRPMetadata.get("response_types");
        client.setRestrictedResponseTypes(responseTypes != null ? responseTypes : new ArrayList<>());
        // The list alone restricts nothing: PingFederate consults restrictedResponseTypes only when
        // restrictResponseTypes is set. Until this flag was set a federation client could use any response
        // type the server allows, whatever its (policy-constrained) metadata said.
        client.setRestrictResponseTypes(true);
        List grantTypes = (List)oidcRPMetadata.get("grant_types");
        client.setGrantTypes(grantTypes != null ? new HashSet(grantTypes) : new HashSet());
        client.setTokenEndpointAuthSigningAlgorithm(metadataString(oidcRPMetadata, "token_endpoint_auth_signing_alg"));
        client.setIdTokenSigningAlgorithm(metadataString(oidcRPMetadata, "id_token_signed_response_alg"));
        client.setRequestObjectSigningAlgorithm(metadataString(oidcRPMetadata, "request_object_signing_alg"));
        String scope = metadataString(oidcRPMetadata, "scope");
        List<String> scopes = scope == null ? List.of()
                : Arrays.stream(scope.trim().split(" +")).filter(s -> !s.isBlank()).toList();
        client.setRestrictedScopes(scopes);
        // Likewise for scopes: without the flag PF ignores the list and the client may request any scope the
        // server defines - exactly what a superior's metadata_policy on `scope` exists to prevent. With it, a
        // leaf that declares no scope may request none.
        client.setRestrictScopes(true);
        client.setBypassApprovalPage(bypassApprovalPage(grantTypes));
        HashMap<String, ParamValues> extendedParams = new HashMap<String, ParamValues>();
        // Every name written here must be declared in extended-properties.tf or PF rejects/drops it -
        // see FederationClientParams, which both this and that file are checked against.
        addParamValue(extendedParams, FederationClientParams.STATUS, status);
        addParamValue(extendedParams, oidcRPMetadata, "application_type");
        addParamValue(extendedParams, oidcRPMetadata, "subject_type");
        addParamValue(extendedParams, oidcRPMetadata, "contacts");
        addParamValues(extendedParams, "trust_chain", trustChain);
        addParamValue(extendedParams, FederationClientParams.EXPIRES_AT, Long.toString(expiresAt));
        addParamValue(extendedParams, FederationClientParams.TRUST_ANCHOR, trustAnchor);
        addParamValue(extendedParams, FederationClientParams.ENTITY_TYPE, entityType);
        if (attestationAuth) {
            addParamValue(extendedParams, "token_endpoint_auth_method", tokenEndpointAuthMethod);
            addParamValue(extendedParams, "attestation_required", "true");
        }
        client.setExtendedParams(extendedParams);
        if (clientId != null) {
            client.setClientId(clientId);
        }
        return client;
    }

    /**
     * Whether to skip the approval page. Previously always true, which silently suppressed consent for
     * every federation-registered client - including one running authorization_code with a real user in
     * front of it.
     *
     * <p>The honest rule is whether there is anyone to ask. A client whose only grant is
     * {@code client_credentials} acts with no resource owner present, so an approval page has no one to
     * show and bypassing is correct. Any user-facing grant gets the page.
     *
     * <p>This is a behaviour change, in the safer direction: some clients that skipped consent will now
     * ask for it. A deployment that genuinely wants consent suppressed for a user-facing client should
     * configure that on the client in PF, where it is visible, rather than inherit it from a default
     * that applied to everything.
     */
    private static boolean bypassApprovalPage(List<?> grantTypes) {
        if (grantTypes == null || grantTypes.isEmpty()) {
            return false;
        }
        for (Object g : grantTypes) {
            if (!"client_credentials".equals(String.valueOf(g))) {
                return false;
            }
        }
        return true;
    }

    private static String metadataString(Map<String, Object> oidcRPMetadata, String key) {
        Object value = oidcRPMetadata.get(key);
        return value == null ? null : String.valueOf(value);
    }

    private static void addParamValue(Map<String, ParamValues> extendedParams, Map<String, Object> oidcRPMetadata, String paramName) {
        if (!oidcRPMetadata.containsKey(paramName)) {
            return;
        }
        Object rpMetadataValue = oidcRPMetadata.get(paramName);
        if (rpMetadataValue instanceof List) {
            addParamValues(extendedParams, paramName, (List)rpMetadataValue);
        } else {
            String paramValue = String.valueOf(rpMetadataValue);
            addParamValue(extendedParams, paramName, paramValue);
        }
    }

    private static void addParamValue(Map<String, ParamValues> extendedParams, String paramName, String paramValue) {
        ParamValues existing = extendedParams.get(paramName);
        if (existing != null) {
            existing.getElements().add(paramValue);
            return;
        }
        ParamValues paramValues = new ParamValues();
        ArrayList<String> elements = new ArrayList<String>();
        elements.add(paramValue);
        paramValues.setElements(elements);
        extendedParams.put(paramName, paramValues);
    }

    /** First value of a client's extended param, or null when absent — the read twin of addParamValue. */
    static String extendedParamValue(Client client, String paramName) {
        Map<String, ParamValues> params = client.getExtendedParams();
        ParamValues values = params != null ? params.get(paramName) : null;
        List<String> elements = values != null ? values.getElements() : null;
        return elements != null && !elements.isEmpty() ? elements.get(0) : null;
    }

    private static void addParamValues(Map<String, ParamValues> extendedParams, String paramName, List<String> paramValues1) {
        ParamValues existing = extendedParams.get(paramName);
        if (existing != null) {
            existing.getElements().addAll(paramValues1);
            return;
        }
        ParamValues paramValues = new ParamValues();
        ArrayList<String> elements = new ArrayList<String>();
        elements.addAll(paramValues1);
        paramValues.setElements(elements);
        extendedParams.put(paramName, paramValues);
    }
}
