package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.federation.EntityId;
import com.pingidentity.ps.oidf.federation.FederationException;
import com.pingidentity.ps.oidf.federation.HttpTrustControllerGateway;
import com.pingidentity.ps.oidf.federation.SubordinateStatementCache;
import com.pingidentity.ps.oidf.federation.TrustChainValidationResult;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.federation.TrustMarkValidator;
import com.pingidentity.ps.oidf.federation.ValidationRequest;
import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.event.LogSafe;
import com.pingidentity.ps.oidf.federation.policy.DecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.NarrowingObligations;
import com.pingidentity.ps.oidf.jose.HttpPostClient;
import com.pingidentity.ps.oidf.jose.JdkHttpClient;
import com.pingidentity.ps.oidf.jose.JdkHttpGetClient;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.AutoRegistrationSettings;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.ExpiryEnforcement;
import com.pingidentity.ps.oidf.pf.PfJwksSigningKeyProvider;
import com.pingidentity.ps.oidf.pf.PfMgmtClientStore;
import java.util.HashMap;
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
import org.sourceid.oauth20.domain.ParamValues;

/**
 * OpenID Federation 1.0 §12 client registration on PingFederate: explicit registration (§12.2), automatic
 * registration (§12.1) at the token endpoint and - for an RP - at the authorization and PAR endpoints, and the
 * lifetime every registration has (§12.3).
 *
 * <p>Order matters and is the whole point: the trust chain is validated first; only then is the client
 * store consulted, and a client this module did not register (no {@code status} extended parameter - a
 * console or Terraform client) is never modified.
 *
 * <p>Every registration records when it ends: the earlier of its chain's expiry and the deployment's maximum
 * ({@link RegistrationLifetime}). An automatically registered client is renewed as it nears that time
 * ({@link #admit}); an explicitly registered one is renewed by its RP registering again, as §12.3 says. What an
 * expired registration that cannot be renewed gets is the deployment's choice: {@link ExpiryEnforcement}.
 *
 * <p>Automatic registration starts from a request nobody has authenticated, so a chain it presents is only ever
 * validated on its own, fetching nothing: if it does not validate as it stands, the federation's own answer - by
 * discovery from the client's own Entity Configuration - is what counts, never statements a stranger chose.
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
    /** A chain that validated is used again for this long (or until it expires), so repeating a request repeats no fetch. */
    static final long RESOLUTION_REUSE_SECONDS = 60L;
    private static final int ATTEMPT_MEMORY = 4096;
    private static final int RESOLUTION_MEMORY = 1024;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    static final Log LOGGER = LogFactory.getLog(RegistrationService.class);

    private final RegistrationConfiguration configuration;
    private final TrustChainValidator trustChainValidator;
    private final ClientStore clientStore;
    private final SigningKeyProvider signingKeyProvider;
    private final RegistrationLifetime lifetime;
    private final RpKeyMaterial rpKeyMaterial;
    private final RegistrationCoordinator coordinator;
    /** Asks a Trust Mark issuer's status endpoint (§8.4), when the deployment checks status. */
    private final HttpPostClient trustMarkStatusClient;
    /** Whoever decides, beyond the federation's own checks, whether a registration goes ahead and what it may keep. */
    private final RegistrationPolicy policy;
    private final Channel tokenChannel = new TokenChannel();
    /**
     * Recent attempts: a failure under its client and hint, so a caller's bad chain never stands in for the client's
     * own or for discovery, and a success under its client alone.
     */
    private final Map<String, Attempt> recentAttempts = lru(ATTEMPT_MEMORY);
    /** Chains that validated, under the same keys, with the RP keys resolved from them. */
    private final Map<String, Resolution> resolutions = lru(RESOLUTION_MEMORY);

    /** What the endpoint may do with a request naming a client. */
    enum Admission {
        /** Not a client this module registered, and nothing to register one from: PingFederate decides. */
        NOT_FEDERATION,
        /** A federation client whose registration is current. */
        CURRENT,
        /** Registered now. */
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

    /** A chain that validated, and the keys resolved from it once they were needed. */
    private static final class Resolution {
        private final long at;
        private final TrustChainValidationResult validation;
        private volatile RpKeyMaterial.Keys keys;

        private Resolution(long at, TrustChainValidationResult validation) {
            this.at = at;
            this.validation = validation;
        }
    }

    /**
     * The production wiring. The anchors' keys come from {@link FederationRuntimeConfig#trustAnchors()}
     * - the same deployment-wide source the configuration's host came from - so a deployment that has
     * not pinned them fails at init, here, rather than at the first chain. A chain registers through
     * whichever pinned anchor it reaches. An RP's own key sets are fetched through the outbound URL policy.
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
                new RegistrationLifetime(FederationRuntimeConfig.get().registration(), java.time.Clock.systemUTC()));
    }

    RegistrationService(RegistrationConfiguration configuration, TrustChainValidator trustChainValidator, ClientStore clientStore,
                        SigningKeyProvider signingKeyProvider, RegistrationLifetime lifetime) {
        this(configuration, trustChainValidator, clientStore, signingKeyProvider, lifetime,
                // An RP's own key set is a federation fetch like its statements, under the same TLS setting.
                new RpKeyMaterial(new JdkHttpGetClient(configuration.ignoreSslErrors(), OutboundUrlPolicy.fromEnvironment()), lifetime.clock()),
                coordinatorFor(FederationRuntimeConfig.get().autoRegistration()));
    }

    RegistrationService(RegistrationConfiguration configuration, TrustChainValidator trustChainValidator, ClientStore clientStore,
                        SigningKeyProvider signingKeyProvider, RegistrationLifetime lifetime, RpKeyMaterial rpKeyMaterial,
                        RegistrationCoordinator coordinator) {
        this(configuration, trustChainValidator, clientStore, signingKeyProvider, lifetime, rpKeyMaterial, coordinator,
                // A Trust Mark issuer's status endpoint is a federation fetch too, under the same TLS setting.
                new JdkHttpClient(configuration.ignoreSslErrors(), OutboundUrlPolicy.fromEnvironment()));
    }

    RegistrationService(RegistrationConfiguration configuration, TrustChainValidator trustChainValidator, ClientStore clientStore,
                        SigningKeyProvider signingKeyProvider, RegistrationLifetime lifetime, RpKeyMaterial rpKeyMaterial,
                        RegistrationCoordinator coordinator, HttpPostClient trustMarkStatusClient) {
        this(configuration, trustChainValidator, clientStore, signingKeyProvider, lifetime, rpKeyMaterial, coordinator, trustMarkStatusClient,
                RegistrationPolicy.fromEnvironment());
    }

    RegistrationService(RegistrationConfiguration configuration, TrustChainValidator trustChainValidator, ClientStore clientStore,
                        SigningKeyProvider signingKeyProvider, RegistrationLifetime lifetime, RpKeyMaterial rpKeyMaterial,
                        RegistrationCoordinator coordinator, HttpPostClient trustMarkStatusClient, RegistrationPolicy policy) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.trustChainValidator = Objects.requireNonNull(trustChainValidator, "trustChainValidator");
        this.clientStore = Objects.requireNonNull(clientStore, "clientStore");
        this.signingKeyProvider = signingKeyProvider;
        this.lifetime = Objects.requireNonNull(lifetime, "lifetime");
        this.rpKeyMaterial = Objects.requireNonNull(rpKeyMaterial, "rpKeyMaterial");
        this.coordinator = Objects.requireNonNull(coordinator, "coordinator");
        this.trustMarkStatusClient = Objects.requireNonNull(trustMarkStatusClient, "trustMarkStatusClient");
        this.policy = Objects.requireNonNull(policy, "policy");
    }

    static RegistrationCoordinator coordinatorFor(AutoRegistrationSettings settings) {
        return new RegistrationCoordinator(settings.maxConcurrentResolutions(), settings.lockWaitMillis());
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
        PresentedMarks marks = new PresentedMarks(validation);
        this.requireTrustMarks(marks, FederationRuntimeConfig.get().requiredTrustMarks().requiredFor(entityType), entityType, clientId,
                "registering it as " + entityType);
        NarrowingObligations obligations = this.policy.decide(DecisionPoint.EXPLICIT_REGISTRATION, clientId, opIssuer, "registration",
                entityType, validation, leafMetadata, marks.verifiedTypes());
        this.requireTrustMarks(marks, List.copyOf(obligations.requiredTrustMarks()), entityType, clientId, "the policy decision");
        long expiresAt = this.lifetime.expiresAt(validation, obligations.maxTtlSeconds());

        Client client = FederationClientBuilder.agent(clientId, leafMetadata, this.keysFor(entityType, leafMetadata, validation, clientId),
                new FederationClientBuilder.Provenance(STATUS_REGISTERED, validation.trustChain(), expiresAt, trustAnchorIssuer, entityType));
        FederationClientBuilder.narrow(client, obligations, expiresAt, this.lifetime.now());
        LinkedHashMap<String, Object> registered = new LinkedHashMap<String, Object>(leafMetadata);
        registered.put("client_id", clientId);
        registered.put("client_id_issued_at", this.lifetime.now());
        // §12.2.3 SHOULD: the parameters that have a default, as registered.
        registered.putIfAbsent("token_endpoint_auth_method", "private_key_jwt");
        // What the policy decision took away is not registered, so the response does not claim it.
        FederationClientBuilder.narrowed(registered, client);
        String signedJwt = this.buildSignedRegistrationResponse(opIssuer, rpSubject, trustAnchorIssuer, immediateSuperior(validation),
                jwksOf(validation), entityType, registered, expiresAt);
        this.store(client, existing);
        if (existing != null) {
            LOGGER.info((Object)("Refreshed federation client " + clientId + " via explicit registration (trust anchor " + trustAnchorIssuer + ")"));
        } else {
            LOGGER.info((Object)("Explicitly registered federation client " + clientId + " (trust anchor " + trustAnchorIssuer + ")"));
        }
        this.registrationEvent(existing == null ? FederationEvents.REGISTRATION_CREATED : FederationEvents.REGISTRATION_REFRESHED,
                clientId, trustAnchorIssuer, "explicit", "registration", entityType, expiresAt, existing, client);
        return new RegisteredClient(clientId, rpSubject, trustAnchorIssuer, validation.trustChain(), registered, STATUS_REGISTERED, signedJwt, expiresAt);
    }

    // ---- automatic registration (§12.1) and renewal (§12.3) -------------------------------------------------

    /** {@link #admit(String, List, String, Channel)} at the token endpoint. */
    Admission admit(String clientId, List<String> hint, String opIssuer) throws Exception {
        return this.admit(clientId, hint, opIssuer, this.tokenChannel);
    }

    /**
     * What an endpoint does with a request naming {@code clientId}, before PingFederate authenticates it. The request
     * is not authenticated yet, so nothing here trusts it: the chain it presents is only ever a hint, validated on
     * its own; a presented chain that fails never costs a client its current registration, and never stands in for
     * the client's own attempts.
     *
     * <ul>
     *   <li>No such client: registered automatically - from the presented chain, else by discovery where the
     *       channel allows it (the front channel does; the token endpoint registers only a client that presents a
     *       chain). Otherwise left to PingFederate.</li>
     *   <li>A client this module did not register: left to PingFederate.</li>
     *   <li>An explicit registration: current until it expires; after that only its RP can renew it, by
     *       registering again (§12.3), and the expiry is enforced.</li>
     *   <li>An automatic registration: renewed when it nears expiry, or when the request presents a newer Entity
     *       Configuration with different keys or metadata - the notice of a change §12.5 describes. A notice renews
     *       only from the chain it came with; a renewal that is due falls back to discovery. One that fails before
     *       expiry leaves the registration standing; after expiry the expiry is enforced.</li>
     * </ul>
     *
     * <p>A failed attempt is not repeated with the same hint within its backoff, a registration renewed in the
     * last {@value #RENEWAL_MIN_INTERVAL_SECONDS}s is not renewed again for being due, and a presented Entity
     * Configuration older than the registered one is never used - replaying it would roll the registration
     * back to keys the client has retired.
     *
     * @throws RegistrationRejectedException when the request must be refused
     */
    Admission admit(String clientId, List<String> hint, String opIssuer, Channel channel) throws Exception {
        List<String> presented = hint == null ? List.of() : hint;
        Client existing = this.clientStore.get(clientId);
        if (existing == null) {
            if (presented.isEmpty() && !channel.discoversUnknownClients()) {
                return Admission.NOT_FEDERATION;
            }
            this.register(presented, clientId, opIssuer, null, channel, true);
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
        if (!channel.renews(existing)) {
            if (!expired) {
                return this.admitted(channel, existing, Admission.CURRENT);
            }
            return this.admitted(channel, existing, this.enforceExpiry(existing, clientId, new RegistrationRejectedException(401,
                    "invalid_client", "the client's registration has expired; an RP registered at the authorization or PAR endpoint renews it"
                    + " there, with its next request (OpenID Federation 1.0 §12.3)", RegistrationRejectedException.Kind.TRUST, null)));
        }
        boolean changed = presentsChange(presented, existing, clientId);
        boolean due = this.lifetime.isDueForRenewal(expiresAt);
        if (!expired && !changed && (!due || this.renewedRecently(clientId))) {
            return this.admitted(channel, existing, Admission.CURRENT);
        }
        List<String> renewFrom = predatesRegistration(presented, existing, clientId) ? List.of() : presented;
        boolean known = this.recentFailure(clientId, renewFrom) != null;
        try {
            this.register(renewFrom, clientId, opIssuer, existing, channel, due);
            return Admission.RENEWED;
        } catch (RegistrationRejectedException e) {
            if (e.kind() == RegistrationRejectedException.Kind.REQUEST || expired && e.kind() == RegistrationRejectedException.Kind.BUSY) {
                throw e;
            }
            if (!expired) {
                if (!known && e.concernsTheClient()) {
                    FederationEvents.event(FederationEvents.REGISTRATION_REFRESH_DEFERRED).failure(kindCode(e)).subject(clientId)
                            .role("OP").field("endpoint", channel.endpoint()).description(e.getMessage()).emit();
                }
                return this.admitted(channel, existing, Admission.DEFERRED);
            }
            return this.admitted(channel, existing, this.enforceExpiry(existing, clientId, e));
        }
    }

    /**
     * An automatic registration's request going ahead on the registration it has - nothing was registered for it now -
     * which the channel still holds to what every request owes ({@link Channel#admitted}).
     */
    private Admission admitted(Channel channel, Client existing, Admission admission) throws RegistrationRejectedException {
        channel.admitted(existing);
        return admission;
    }

    /**
     * Registers or renews {@code clientId}. A presented chain is validated on its own, fetching nothing; when that
     * fails and {@code discover} allows, by discovery from the client's own Entity Configuration. Runs alone among
     * registrations of the client, and first checks another request has not just done it.
     */
    private void register(List<String> hint, String clientId, String opIssuer, Client existing, Channel channel, boolean discover)
            throws Exception {
        channel.precheck();
        this.coordinator.register(clientId, () -> {
            if (!sameRecord(this.clientStore.get(clientId), existing)) {
                return;
            }
            if (!hint.isEmpty()) {
                RegistrationRejectedException presented = this.attempt(hint, 0, clientId, opIssuer, existing, channel);
                if (presented == null) {
                    return;
                }
                if (!discover) {
                    throw presented;
                }
            }
            RegistrationRejectedException discovered = this.attempt(List.of(), -1, clientId, opIssuer, existing, channel);
            if (discovered != null) {
                throw discovered;
            }
        });
    }

    /**
     * One attempt from {@code hint} (empty: discovery) with at most {@code maxFetches} fetches (-1: the validator's
     * limit). Null when it registered; its failure otherwise, remembered when it concerns the client. A failure of
     * the request itself - its proof - is thrown: no chain would change it.
     */
    private RegistrationRejectedException attempt(List<String> hint, int maxFetches, String clientId, String opIssuer, Client existing,
                                                  Channel channel) throws Exception {
        RegistrationRejectedException recent = this.recentFailure(clientId, hint);
        if (recent != null) {
            return recent;
        }
        try {
            this.registerFrom(hint, maxFetches, clientId, opIssuer, existing, channel);
        } catch (RegistrationRejectedException e) {
            if (!e.concernsTheClient()) {
                throw e;
            }
            this.recentAttempts.put(failureKey(clientId, hint), new Attempt(this.lifetime.now(), e));
            return e;
        }
        this.recentAttempts.put(renewalKey(clientId), new Attempt(this.lifetime.now(), null));
        return null;
    }

    private void registerFrom(List<String> hint, int maxFetches, String clientId, String opIssuer, Client existing, Channel channel)
            throws Exception {
        Resolution resolution = this.resolution(clientId, hint, maxFetches, opIssuer);
        TrustChainValidationResult validation = resolution.validation;
        String entityType = channel.entityType(validation);
        Map<String, Object> leafMetadata = federationClientMetadata(validation, entityType, clientId);
        requireRegistrationType(leafMetadata, clientId, "automatic");
        requireConstrainedByPolicy(validation, entityType, clientId);
        PresentedMarks marks = new PresentedMarks(validation);
        this.requireTrustMarks(marks, FederationRuntimeConfig.get().requiredTrustMarks().requiredFor(entityType), entityType, clientId,
                "registering it as " + entityType);
        NarrowingObligations obligations = this.policy.decide(DecisionPoint.AUTOMATIC_REGISTRATION, clientId, opIssuer, channel.endpoint(),
                entityType, validation, leafMetadata, marks.verifiedTypes());
        this.requireTrustMarks(marks, List.copyOf(obligations.requiredTrustMarks()), entityType, clientId, "the policy decision");
        long expiresAt = this.lifetime.expiresAt(validation, obligations.maxTtlSeconds());
        RpKeyMaterial.Keys keys = resolution.keys;
        if (keys == null) {
            keys = channel.keys(leafMetadata, validation, entityType, clientId);
            resolution.keys = keys;
        }
        Client client = channel.build(clientId, leafMetadata, keys,
                new FederationClientBuilder.Provenance(STATUS_AUTO, validation.trustChain(), expiresAt, validation.trustAnchorIssuer(), entityType));
        FederationClientBuilder.narrow(client, obligations, expiresAt, this.lifetime.now());
        channel.beforeStore(keys);
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
                clientId, validation.trustAnchorIssuer(), "automatic", channel.endpoint(), entityType, expiresAt, existing, client);
    }

    /** The chain for {@code clientId} from {@code hint}: one that validated moments ago, or validated now. */
    private Resolution resolution(String clientId, List<String> hint, int maxFetches, String opIssuer) throws RegistrationRejectedException {
        String key = failureKey(clientId, hint);
        long now = this.lifetime.now();
        Resolution kept = this.resolutions.get(key);
        // No expiry check needed here: a registration from it still has to outlive RegistrationLifetime's minimum.
        if (kept != null && now - kept.at < RESOLUTION_REUSE_SECONDS) {
            return kept;
        }
        TrustChainValidationResult validation = this.validate(ValidationRequest.forSubject(clientId)
                .presentedChain(hint)
                .opIssuer(opIssuer)
                .maxPresentedEntryAgeSeconds(this.configuration.trustChainEntryMaxAgeSeconds())
                .maxFetches(maxFetches)
                .build());
        Resolution fresh = new Resolution(now, validation);
        this.resolutions.put(key, fresh);
        return fresh;
    }

    /** Whether the client is as it was when the request found it - not registered, renewed or replaced meanwhile. */
    static boolean sameRecord(Client now, Client before) {
        if (now == null || before == null) {
            return now == before;
        }
        return RegistrationLifetime.storedExpiry(now).equals(RegistrationLifetime.storedExpiry(before))
                && Objects.equals(firstChainEntry(now), firstChainEntry(before));
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
        boolean retryable = reason.isRetryable();
        throw new RegistrationRejectedException(retryable ? 503 : 401, retryable ? "temporarily_unavailable" : "invalid_client",
                retryable ? "the client's federation registration has expired and its trust chain cannot be checked right now"
                        : "the client's federation registration has expired and could not be renewed: " + reason.getMessage(),
                reason.kind(), reason);
    }

    /**
     * Disables a client whose registration expired, marking it ({@link FederationClientParams#DISABLED_AT}) so that
     * a renewal knows the disable was this module's to undo.
     */
    static void disableExpired(ClientStore store, Client client, long now) {
        Map<String, ParamValues> params = client.getExtendedParams() == null ? new HashMap<>() : new HashMap<>(client.getExtendedParams());
        FederationClientBuilder.addParamValue(params, FederationClientParams.DISABLED_AT, Long.toString(now));
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

    private static <V> Map<String, V> lru(int capacity) {
        return java.util.Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, V> eldest) {
                return this.size() > capacity;
            }
        });
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

    // ---- channels -----------------------------------------------------------------------------------------

    /** How an automatic registration arrives, and what that path adds to it. */
    interface Channel {
        /** For the audit record: {@code token}, {@code authorization} or {@code par}. */
        String endpoint();

        /** Whether a client this server has never seen is found by discovery when the request carries no chain. */
        boolean discoversUnknownClients();

        /** What can be checked before anything is fetched. */
        void precheck() throws RegistrationRejectedException;

        /** Which of the leaf's client metadata is registered. */
        String entityType(TrustChainValidationResult validation) throws RegistrationRejectedException;

        /** The keys the client is registered with. */
        RpKeyMaterial.Keys keys(Map<String, Object> metadata, TrustChainValidationResult validation, String entityType, String clientId)
                throws RegistrationRejectedException;

        /** The client to store. */
        Client build(String clientId, Map<String, Object> metadata, RpKeyMaterial.Keys keys, FederationClientBuilder.Provenance provenance)
                throws RegistrationRejectedException;

        /** The last check before the store is written. */
        void beforeStore(RpKeyMaterial.Keys keys) throws RegistrationRejectedException;

        /** What a request owes when it goes ahead on the registration its client already has. */
        void admitted(Client existing) throws RegistrationRejectedException;

        /** Whether this endpoint renews {@code existing}'s registration - only one it could have made in that shape. */
        boolean renews(Client existing);
    }

    /**
     * The token endpoint: an agent's {@code oauth_client} metadata when it has some, else an RP's. PingFederate
     * authenticates the request itself, after this, with the keys registered here.
     */
    private final class TokenChannel implements Channel {
        @Override
        public String endpoint() {
            return "token";
        }

        @Override
        public boolean discoversUnknownClients() {
            return false;
        }

        @Override
        public void precheck() {
        }

        @Override
        public String entityType(TrustChainValidationResult validation) {
            return clientEntityType(validation, OAUTH_CLIENT);
        }

        @Override
        public RpKeyMaterial.Keys keys(Map<String, Object> metadata, TrustChainValidationResult validation, String entityType, String clientId)
                throws RegistrationRejectedException {
            return RegistrationService.this.keysFor(entityType, metadata, validation, clientId);
        }

        @Override
        public Client build(String clientId, Map<String, Object> metadata, RpKeyMaterial.Keys keys, FederationClientBuilder.Provenance provenance) {
            return FederationClientBuilder.agent(clientId, metadata, keys, provenance);
        }

        @Override
        public void beforeStore(RpKeyMaterial.Keys keys) {
        }

        /** Nothing: PingFederate authenticates the client next, with the keys it is registered with. */
        @Override
        public void admitted(Client existing) {
        }

        /**
         * Not an RP registered at the authorization or PAR endpoint: rebuilt here it would lose what that endpoint gave it -
         * its default grant, its signed requests, its PAR - and fail every request after. It is renewed where it was
         * registered, with its next authorization request.
         */
        @Override
        public boolean renews(Client existing) {
            return !FederationClientBuilder.registeredAtTheFrontChannel(existing);
        }
    }

    /**
     * The authorization or PAR endpoint (§12.1.1): only an RP, registered with the keys it publishes for
     * {@code openid_relying_party}, and only once the request has shown it holds one of them - checked before
     * the store is written, so a request that cannot prove itself registers nothing.
     */
    Channel frontChannel(String endpoint, String clientId, String opIssuer, RequestObject proof, RegistrationRejectedException unreadableProof,
                         RequestObject.ReplayGuard replay, AutoRegistrationSettings settings) {
        return new FrontChannel(endpoint, clientId, opIssuer, proof, unreadableProof, replay, settings);
    }

    private final class FrontChannel implements Channel {
        private final String endpoint;
        private final String clientId;
        private final String opIssuer;
        private final RequestObject proof;
        private final RegistrationRejectedException unreadableProof;
        private final RequestObject.ReplayGuard replay;
        private final AutoRegistrationSettings settings;

        private FrontChannel(String endpoint, String clientId, String opIssuer, RequestObject proof, RegistrationRejectedException unreadableProof,
                             RequestObject.ReplayGuard replay, AutoRegistrationSettings settings) {
            this.endpoint = endpoint;
            this.clientId = clientId;
            this.opIssuer = opIssuer;
            this.proof = proof;
            this.unreadableProof = unreadableProof;
            this.replay = replay;
            this.settings = settings;
        }

        @Override
        public String endpoint() {
            return this.endpoint;
        }

        @Override
        public boolean discoversUnknownClients() {
            return true;
        }

        @Override
        public void precheck() throws RegistrationRejectedException {
            if (this.unreadableProof != null) {
                throw this.unreadableProof;
            }
            if (this.proof == null) {
                throw RegistrationRejectedException.request(400, "invalid_request", "an OpenID Federation RP's request here needs a signed"
                        + " request object or, at the PAR endpoint, a client assertion, to show it holds the RP's keys (OpenID Federation 1.0 §12.1.1)");
            }
            if (this.proof.encrypted() && !this.settings.allowEncryptedRequestObjects()) {
                throw RegistrationRejectedException.request(400, "invalid_request_object",
                        "an encrypted request object cannot register a client here; send it signed only, or use PAR");
            }
            this.proof.checkProfile(this.clientId, this.opIssuer, RegistrationService.this.lifetime.now(), this.settings.maxRequestObjectBytes());
        }

        @Override
        public String entityType(TrustChainValidationResult validation) throws RegistrationRejectedException {
            if (validation.metadataFor(RELYING_PARTY).isEmpty()) {
                throw new RegistrationRejectedException(400, "invalid_client_metadata", this.clientId
                        + " has no openid_relying_party metadata, which is what registers here (OpenID Federation 1.0 §12.1.1.1.2)");
            }
            return RELYING_PARTY;
        }

        @Override
        public RpKeyMaterial.Keys keys(Map<String, Object> metadata, TrustChainValidationResult validation, String entityType, String clientId)
                throws RegistrationRejectedException {
            return RegistrationService.this.rpKeyMaterial.resolve(metadata, jwksOf(validation), clientId);
        }

        @Override
        public Client build(String clientId, Map<String, Object> metadata, RpKeyMaterial.Keys keys, FederationClientBuilder.Provenance provenance)
                throws RegistrationRejectedException {
            return FederationClientBuilder.relyingParty(clientId, metadata, keys, provenance, this.settings, this.proof.kind(), this.proof.algorithm());
        }

        @Override
        public void beforeStore(RpKeyMaterial.Keys keys) throws RegistrationRejectedException {
            this.proof.verify(keys.verificationKeys(), this.clientId, this.replay, RegistrationService.this.lifetime.now());
        }

        /**
         * §12.1.1: "Authentication requests MUST demonstrate that the requesting Entity controls the Entity's RP keys" -
         * every one, not only the one that registered the RP. So a request on the registration the RP already has is held
         * to §12.1.1.1 as the first was: its proof there, to the profile, signed with a key it is registered with, and its
         * {@code jti} spent.
         */
        @Override
        public boolean renews(Client existing) {
            return true;
        }

        @Override
        public void admitted(Client existing) throws RegistrationRejectedException {
            this.precheck();
            this.proof.verify(RegistrationService.this.rpKeyMaterial.registered(existing.getJwks(), existing.getJwksUrl()), this.clientId,
                    this.replay, RegistrationService.this.lifetime.now());
        }
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
     * The keys a client is registered with: the ones it publishes under the Entity Type it registers from -
     * {@code openid_relying_party} (§5.2.1, §12.1.1.2.1) or {@code oauth_client} (§12.1.2: the OP verifies the
     * client's authentication "using the keys from the Relying Party's metadata"; §3.1.1 says the Federation
     * Entity Keys "SHOULD NOT be used in other protocols"). A client that publishes none is registered with its
     * Federation Entity Keys, as every client was before 0.3.0 - a hosted agent's attestation bridge signs with
     * them, and so does an agent whose configuration carries no protocol keys of its own.
     */
    private RpKeyMaterial.Keys keysFor(String entityType, Map<String, Object> metadata, TrustChainValidationResult validation, String clientId)
            throws RegistrationRejectedException {
        if (metadata.containsKey("jwks") || metadata.containsKey("signed_jwks_uri") || metadata.containsKey("jwks_uri")) {
            return this.rpKeyMaterial.resolve(metadata, jwksOf(validation), clientId);
        }
        return new RpKeyMaterial.Keys(List.of(), org.jose4j.json.JsonUtil.toJson(jwksOf(validation)), null, "federation");
    }

    /**
     * Writes a freshly derived client over the old one. A client this module disabled because its registration
     * expired comes back enabled; one disabled by anyone else - an operator - stays disabled. A new client that
     * another server registered first is left as that server wrote it.
     */
    private void store(Client client, Client existing) throws RegistrationRejectedException {
        this.write(client, existing);
        this.requireMarksKept(client.getClientId());
    }

    private void write(Client client, Client existing) {
        if (existing == null) {
            try {
                this.clientStore.add(client);
            } catch (RuntimeException e) {
                if (this.clientStore.get(client.getClientId()) == null) {
                    throw e;
                }
                LOGGER.info((Object)("Federation client " + client.getClientId() + " was registered by another server first; keeping that"));
            }
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
     * PingFederate drops an extended property it has not been told about, silently, and {@code status} is the only
     * thing that marks a client as this module's (docs/extended-properties.json). A federation client stored without it
     * would look like one an administrator made: never expired, never renewed, its requests held to nothing. So the
     * client is read back, and one that lost its marks is disabled and the registration refused - a deployment that has
     * not declared the properties registers nobody, rather than clients no one manages.
     */
    private void requireMarksKept(String clientId) throws RegistrationRejectedException {
        Client stored = this.clientStore.get(clientId);
        if (stored == null || extendedParamValue(stored, FederationClientParams.STATUS) != null) {
            return;
        }
        this.clientStore.disable(stored);
        LOGGER.error((Object)("PingFederate stored federation client " + LogSafe.value(clientId) + " without this module's extended"
                + " properties, so it is disabled: declare every name in docs/extended-properties.json as an extended property"));
        FederationEvents.event(FederationEvents.REGISTRATION_REFUSED).failure("extended_properties_undeclared").subject(clientId).role("OP")
                .audit().description("PingFederate dropped the federation client's extended properties").emit();
        throw new RegistrationRejectedException(500, "server_error", "the client could not be registered",
                RegistrationRejectedException.Kind.INTERNAL, null);
    }

    /**
     * The audit record of a registration written. A refresh - §12.2.2's "that registration MUST be invalidated",
     * met by replacing it whole - also says when the old one would have ended and whether the keys changed.
     */
    private void registrationEvent(String code, String clientId, String anchor, String type, String endpoint, String entityType,
                                   long expiresAt, Client previous, Client written) {
        com.pingidentity.ps.oidf.federation.event.FederationEvent.Builder event = FederationEvents.event(code).subject(clientId).partner(anchor).role("OP")
                .field("type", type).field("endpoint", endpoint).field("entity_type", entityType).field("expires_at", expiresAt).audit();
        if (previous != null) {
            RegistrationLifetime.storedExpiry(previous).ifPresent(p -> event.field("previous_expires_at", p));
            event.field("keys_changed", !sameKeys(previous.getJwks(), written.getJwks()) || !Objects.equals(previous.getJwksUrl(), written.getJwksUrl()));
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
        FederationEvents.event(FederationEvents.REGISTRATION_REFUSED).failure("invalid_client_metadata").subject(clientId).role("OP").audit()
                .field("entity_type", entityType).description("no metadata_policy constrains the entity type").emit();
        throw new RegistrationRejectedException(400, "invalid_client_metadata",
                "no superior in the trust chain declares a metadata_policy for " + entityType + ", so "
                        + clientId + " would be registered with the scope, grant_types and response_types "
                        + "it published about itself. Publish a metadata_policy at the trust anchor (or an "
                        + "intermediate), or set " + FederationRuntimeConfig.REQUIRE_METADATA_POLICY_ENV
                        + "=false to accept unconstrained federation metadata.", RegistrationRejectedException.Kind.POLICY, null);
    }

    /** The Trust Marks an entity presents, validated at most once per registration, and only when something requires one. */
    private final class PresentedMarks {
        private final TrustChainValidationResult validation;
        private TrustMarkValidator.Result result;

        private PresentedMarks(TrustChainValidationResult validation) {
            this.validation = validation;
        }

        /** Each mark verified against the anchor its chain reached (§7.3) and, when the deployment checks status, active (§8.4). */
        TrustMarkValidator.Result validated() {
            if (this.result == null) {
                FederationRuntimeConfig runtime = FederationRuntimeConfig.get();
                this.result = new TrustMarkValidator(RegistrationService.this.trustChainValidator,
                        RegistrationService.this.configuration.acceptedSigningAlgorithms(), RegistrationService.this.lifetime.clock(),
                        runtime.trustMarkStatusCheck() ? RegistrationService.this.trustMarkStatusClient : null).validate(this.validation);
            }
            return this.result;
        }

        /** The types of the marks that verified, or null when none were checked. */
        List<String> verifiedTypes() {
            return this.result == null ? null : this.result.verified().stream().map(TrustMarkValidator.Verified::type).distinct().toList();
        }
    }

    /**
     * Refuses an entity without a verified mark of each type in {@code required}: those the deployment requires of an entity
     * registered as {@code entityType} ({@link FederationRuntimeConfig#REQUIRED_TRUST_MARKS_ENV}), or those a policy
     * decision requires. Nothing is validated when nothing is required: each issuer costs a chain resolution.
     *
     * @param requiredBy what requires them, for the description: "registering it as oauth_client"
     */
    private void requireTrustMarks(PresentedMarks marks, List<String> required, String entityType, String clientId, String requiredBy)
            throws RegistrationRejectedException {
        if (required.isEmpty()) {
            return;
        }
        TrustMarkValidator.Result result = marks.validated();
        List<String> missing = required.stream().filter(type -> !result.has(type)).toList();
        if (missing.isEmpty()) {
            return;
        }
        StringBuilder why = new StringBuilder();
        for (TrustMarkValidator.Rejected rejected : result.rejected()) {
            why.append(" [").append(LogSafe.value(rejected.type())).append(" from ").append(LogSafe.value(rejected.issuer()))
                    .append(": ").append(LogSafe.value(rejected.reason())).append(']');
        }
        LOGGER.info("Federation client " + LogSafe.value(clientId) + " lacks the Trust Marks " + missing + " required by " + requiredBy
                + (why.length() == 0 ? "; it presents none of them" : "; rejected:" + why));
        FederationEvents.event(FederationEvents.REGISTRATION_REFUSED).failure("invalid_client_metadata").subject(clientId).role("OP").audit()
                .field("entity_type", entityType).field("missing_trust_marks", String.join(" ", missing))
                .description("required Trust Marks missing").emit();
        throw new RegistrationRejectedException(400, "invalid_client_metadata", clientId + " carries no valid Trust Mark of type "
                + String.join(", ", missing) + ", which " + requiredBy + " requires", RegistrationRejectedException.Kind.POLICY, null);
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

    /** First value of a client's extended param, or null when absent. */
    static String extendedParamValue(Client client, String paramName) {
        return FederationClientBuilder.extendedParamValue(client, paramName);
    }
}
