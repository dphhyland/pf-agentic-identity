/*
 * The agent platform backend: enrolment ceremony and attestation issuance.
 */
package com.pingidentity.ps.oidf.enrolment;

import com.pingidentity.ps.oidf.appattest.AppAttestAttestation;
import com.pingidentity.ps.oidf.appattest.AppAttestException;
import com.pingidentity.ps.oidf.appattest.AppAttestVerifier;
import com.pingidentity.ps.oidf.clientattestation.AttestationChallengeService;
import com.pingidentity.ps.oidf.clientattestation.AttestationReplayCache;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.device.AgentInstance;
import com.pingidentity.ps.oidf.device.AuditEntry;
import com.pingidentity.ps.oidf.device.BoundAuthenticator;
import com.pingidentity.ps.oidf.device.ComplianceState;
import com.pingidentity.ps.oidf.device.Device;
import com.pingidentity.ps.oidf.device.DeviceAttestationMinter;
import com.pingidentity.ps.oidf.device.InstanceIdentifiers;
import com.pingidentity.ps.oidf.device.InstanceRegistry;
import com.pingidentity.ps.oidf.device.InstanceStatus;
import com.pingidentity.ps.oidf.device.KeyStorageLevel;
import com.pingidentity.ps.oidf.device.OwnerUser;
import com.pingidentity.ps.oidf.device.RegistryException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * The platform backend. It runs the binding ceremony, owns the registry, and is the Client Attester
 * for device-resident agents.
 *
 * <p>Three primitives meet here and none substitutes for another: <strong>App Attest</strong> shows a
 * genuine unmodified build of our app on genuine Apple hardware; the <strong>IdP</strong> shows which
 * human is present; the <strong>Secure Enclave key</strong> is what signs afterwards. App Attest cannot
 * attest a key the app generated itself, so the only thing tying it to the enclave key is that the
 * app committed {@code SHA-256(enclave JWK thumbprint ‖ challenge)} as the attestation's
 * {@code clientDataHash} — recomputed here from the key and challenge <em>we</em> hold, so a mismatch
 * surfaces as a nonce failure rather than being taken on trust.
 *
 * <p>Residual gap, stated plainly because it belongs in the threat model rather than in a footnote:
 * this proves a genuine app asked us to certify a key, not that the key is in hardware. The EUDI ARF
 * considered and rejected an equivalent binding for exactly this reason — a compromised instance can
 * ask for a certification naming whatever it likes. Android Key Attestation does not have this gap;
 * Apple provides no equivalent.
 */
public final class EnrolmentService {

    private static final Log LOGGER = LogFactory.getLog(EnrolmentService.class);

    /** How long a verified user authentication keeps an agent able to mint. The server-side time-box. */
    public static final Duration DEFAULT_USER_VERIFICATION_MAX_AGE = Duration.ofMinutes(5);

    /** Binding a signing key requires at least this much assurance (NIST SP 800-63B §6.1.2.1). */
    public static final UserAuthentication.AssuranceLevel REQUIRED_ASSURANCE =
            UserAuthentication.AssuranceLevel.AAL2;

    private final AppAttestVerifier appAttest;
    private final UserAuthenticationVerifier userAuthentication;
    private final InstanceRegistry registry;
    private final DeviceAttestationMinter minter;
    private final AttestationChallengeService challenges;
    private final AttestationReplayCache replayCache;
    private final EnclaveKeyProofValidator keyProofs;
    private final JwsSigner signer;
    private final String audience;
    private final Duration userVerificationMaxAge;
    private final boolean requireCompliantDevice;
    private final BindingNotifier notifier;
    private final AgentOptions agents;

    /** Environment prefix marking a device enrolled for a federation-hosted connector agent (the Mac path). */
    static final String CONNECTOR_PREFIX = "connector:";

    public EnrolmentService(AppAttestVerifier appAttest, UserAuthenticationVerifier userAuthentication,
                            InstanceRegistry registry, DeviceAttestationMinter minter,
                            AttestationChallengeService challenges, AttestationReplayCache replayCache,
                            JwsSigner signer, String audience) {
        this(appAttest, userAuthentication, registry, minter, challenges, replayCache, signer, audience,
                DEFAULT_USER_VERIFICATION_MAX_AGE, true);
    }

    /**
     * @param userVerificationMaxAge how stale a verified user authentication may be before minting is
     *                               refused. This is the control that actually bounds agent activity —
     *                               the device-side window is app-enforced and cannot be relied on
     * @param requireCompliantDevice when true, a device that is not compliant (including one never
     *                               assessed) cannot mint. Fails closed on {@code UNKNOWN} deliberately
     */
    public EnrolmentService(AppAttestVerifier appAttest, UserAuthenticationVerifier userAuthentication,
                            InstanceRegistry registry, DeviceAttestationMinter minter,
                            AttestationChallengeService challenges, AttestationReplayCache replayCache,
                            JwsSigner signer, String audience, Duration userVerificationMaxAge,
                            boolean requireCompliantDevice) {
        this(appAttest, userAuthentication, registry, minter, challenges, replayCache, signer, audience,
                userVerificationMaxAge, requireCompliantDevice, BindingNotifier.logOnly());
    }

    /**
     * The full constructor.
     *
     * @param notifier the out-of-band channel that tells an owner a device key was bound to them
     *                 (NIST SP 800-63B §6.1.2.1). {@link BindingNotifier#logOnly()} is the default and
     *                 is deliberately noisy, so a deployment with no channel wired cannot stay quietly
     *                 non-compliant
     */
    public EnrolmentService(AppAttestVerifier appAttest, UserAuthenticationVerifier userAuthentication,
                            InstanceRegistry registry, DeviceAttestationMinter minter,
                            AttestationChallengeService challenges, AttestationReplayCache replayCache,
                            JwsSigner signer, String audience, Duration userVerificationMaxAge,
                            boolean requireCompliantDevice, BindingNotifier notifier) {
        this(Objects.requireNonNull(appAttest, "appAttest"), userAuthentication, registry, minter, challenges,
                replayCache, signer, audience, userVerificationMaxAge, requireCompliantDevice, notifier,
                AgentOptions.none());
    }

    /**
     * With the connector-agent path enabled: an agent whose owner authenticated with a passkey, bound by a
     * nonce to its keys, onboarded as a hosted entity in the bank's federation. {@code appAttest} may be null
     * here, in which case App Attest evidence is refused and the other evidence types still work.
     */
    public EnrolmentService(AppAttestVerifier appAttest, UserAuthenticationVerifier userAuthentication,
                            InstanceRegistry registry, DeviceAttestationMinter minter,
                            AttestationChallengeService challenges, AttestationReplayCache replayCache,
                            JwsSigner signer, String audience, Duration userVerificationMaxAge,
                            boolean requireCompliantDevice, BindingNotifier notifier, AgentOptions agents) {
        this.appAttest = appAttest;
        this.agents = Objects.requireNonNull(agents, "agents");
        this.userAuthentication = Objects.requireNonNull(userAuthentication, "userAuthentication");
        this.registry = Objects.requireNonNull(registry, "registry");
        this.minter = Objects.requireNonNull(minter, "minter");
        this.challenges = Objects.requireNonNull(challenges, "challenges");
        this.replayCache = Objects.requireNonNull(replayCache, "replayCache");
        this.keyProofs = new EnclaveKeyProofValidator();
        this.signer = Objects.requireNonNull(signer, "signer");
        this.audience = Objects.requireNonNull(audience, "audience");
        this.userVerificationMaxAge = Objects.requireNonNull(userVerificationMaxAge, "userVerificationMaxAge");
        this.requireCompliantDevice = requireCompliantDevice;
        this.notifier = Objects.requireNonNull(notifier, "notifier");
    }

    /** Issues a one-time challenge. At least 16 bytes, per Apple's guidance for {@code clientDataHash}. */
    public Challenge issueChallenge() {
        return new Challenge(this.challenges.issue(), this.challenges.ttlSeconds());
    }

    /**
     * Runs the binding ceremony and returns the instance's first attestation.
     *
     * <p>Order matters. The human is verified before anything is written, so a failed proofing leaves no
     * record to clean up; App Attest is verified before the registry is touched, so an untrusted device
     * cannot create rows.
     */
    public Enrolled enrol(EnrolmentRequest request) throws EnrolmentException {
        Objects.requireNonNull(request, "request");
        require(request.enclavePublicJwk() != null && !request.enclavePublicJwk().isEmpty(),
                "enclave_public_jwk is required");
        require(notBlank(request.challenge()), "challenge is required");
        // The connector path: the enrolling client also brings a Federation Entity Key, because the agent
        // is about to become a hosted Leaf Entity whose Entity Configuration it signs itself.
        boolean hostedAgent = request.federationPublicJwk() != null && !request.federationPublicJwk().isEmpty();
        if (!hostedAgent) {
            require(request.appAttestObject() != null && request.appAttestObject().length > 0,
                    "appattest_object is required");
        }
        String enclaveJkt = thumbprint(request.enclavePublicJwk());
        String federationJkt = hostedAgent ? thumbprint(request.federationPublicJwk()) : null;
        if (hostedAgent && enclaveJkt.equals(federationJkt)) {
            throw EnrolmentException.invalidRequest("the federation key and the instance key must be different keys");
        }

        // 1. The human. Verified first so a failure writes nothing. On the connector path the IdP evidence
        //    must carry a nonce binding THIS challenge and THESE keys: the passkey ceremony behind it cannot
        //    then be spent on some other key pair, which a browser passkey (signing a random challenge)
        //    otherwise would allow.
        UserAuthentication authentication = this.userAuthentication.verify(request.userAuthenticationEvidence(),
                hostedAgent ? enrolmentNonce(request.challenge(), enclaveJkt, federationJkt) : null);
        if (!authentication.meetsAssurance(REQUIRED_ASSURANCE)) {
            throw EnrolmentException.insufficientAssurance(
                    "binding a signing key requires " + REQUIRED_ASSURANCE + " but the user reached "
                            + authentication.assuranceLevel());
        }

        // 2. The challenge. One-time, so a captured enrolment cannot be replayed onto another device.
        if (!this.challenges.consume(request.challenge())) {
            throw EnrolmentException.invalidChallenge("challenge is unknown, expired, or already used");
        }

        // 3. Possession of every key being bound (connector path). Evidence about a key is not proof that
        //    the caller holds it - a PIV attestation certificate carries no nonce at all.
        if (hostedAgent) {
            this.verifyEnrolmentKeyProof(request.keyProofs(), "instance", enclaveJkt, request.challenge());
            this.verifyEnrolmentKeyProof(request.keyProofs(), "federation", federationJkt, request.challenge());
        }

        // 4. What the device can show about where the instance key lives.
        VerifiedEvidence evidence = this.verifyEvidence(request.evidenceType(), request, enclaveJkt, hostedAgent);

        // 5. Record, onboard, mint. The owner is the only row naming a person.
        try {
            OwnerUser owner = this.registry.upsertOwner(authentication.subject());
            String deviceId = InstanceIdentifiers.newDeviceId();
            this.registry.registerDevice(new Device(deviceId, request.platform(), request.model(),
                    request.osVersion(), evidence.deviceKeyRef(), evidence.environment(),
                    0L, ComplianceState.UNKNOWN, null, owner.id()));

            this.registry.bindAuthenticator(new BoundAuthenticator(
                    InstanceIdentifiers.newOwnerUserId(), deviceId, authentication.credentialId(),
                    authentication.aaguid(), "passkey", authentication.authenticatedAt()));

            String instanceId = hostedAgent ? InstanceIdentifiers.newFederationSafeInstanceId()
                    : InstanceIdentifiers.newInstanceId();
            String entityId = null;
            if (hostedAgent) {
                entityId = this.agents.federation().register(instanceId, request.federationPublicJwk(),
                        this.agents.federationMetadata(), this.agents.metadataPolicy(), "owner:" + owner.id());
            }
            AgentInstance instance = new AgentInstance(
                    instanceId, this.minterPlatform(), request.agentBuild(),
                    enclaveJkt, InstanceStatus.ACTIVE, deviceId, Instant.now(), null,
                    authentication.authenticatedAt());
            this.registry.register(instance);

            DeviceAttestationMinter.Minted minted = this.minter.mint(instance,
                    request.enclavePublicJwk(), authentication.credentialId(),
                    this.userVerificationMaxAge.toSeconds(), this.signer, this.profileFor(evidence.environment()));
            this.registry.recordAttestationExpiry(instance.id(), minted.expiresAt());

            LOGGER.info((Object) ("Enrolled agent instance " + instance.id() + " (" + evidence.environment() + ")"
                    + (entityId == null ? "" : " as federation entity " + entityId)
                    + " (owner is recorded in the registry only)"));

            // NIST SP 800-63B §6.1.2.1: tell the owner, through a channel independent of this
            // transaction. Deliberately after the binding is durable and never fatal.
            try {
                this.notifier.authenticatorBound(authentication.subject(),
                        describe(request), instance.id());
            } catch (RuntimeException e) {
                LOGGER.warn((Object) ("the binding notification failed for instance " + instance.id()
                        + "; the binding stands and the owner has not been told"), e);
            }

            return new Enrolled(instance.id(), minted.attestation(), minted.expiresInSeconds(),
                    evidence.deviceKeyRef(), entityId, this.agents.federation().authorityEntityId(), evidence.facts());
        } catch (RegistryException e) {
            throw EnrolmentException.serverError("could not record the enrolment: " + e.getMessage(), e);
        }
    }

    /**
     * The OIDC nonce a connector enrolment is bound by: {@code base64url(SHA-256(challenge "|" instance-jkt
     * "|" federation-jkt))}. The client computes it before sending the owner to the IdP; this recomputes it
     * from what the request carries.
     */
    static String enrolmentNonce(String challenge, String instanceJkt, String federationJkt) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest((challenge + "|" + instanceJkt + "|" + federationJkt).getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private void verifyEnrolmentKeyProof(Map<String, String> proofs, String which, String expectedJkt, String challenge)
            throws EnrolmentException {
        String proof = proofs == null ? null : proofs.get(which);
        if (!notBlank(proof)) {
            throw EnrolmentException.invalidKeyProof("key_proofs." + which + " is required: prove possession of the "
                    + which + " key by signing the challenge");
        }
        EnclaveKeyProofValidator.Result result = this.keyProofs.validate(proof, expectedJkt, this.audience);
        if (!challenge.equals(result.challenge())) {
            throw EnrolmentException.invalidKeyProof("key_proofs." + which + " does not answer this enrolment's challenge");
        }
        if (!this.replayCache.firstSeen("enrol:" + expectedJkt, result.jti(), 300L)) {
            throw EnrolmentException.invalidKeyProof("key_proofs." + which + " has already been used (replay)");
        }
    }

    /** Verifies the evidence for the instance key and says what it supports. */
    private VerifiedEvidence verifyEvidence(String type, EnrolmentRequest request, String enclaveJkt, boolean hostedAgent)
            throws EnrolmentException {
        String prefix = hostedAgent ? CONNECTOR_PREFIX : "";
        switch (type) {
            case "app-attest": {
                if (this.appAttest == null) {
                    throw EnrolmentException.invalidAttestation("App Attest is not configured on this attester");
                }
                require(request.appAttestObject() != null && request.appAttestObject().length > 0,
                        "appattest_object is required for app-attest evidence");
                // The app and the device - and, through clientDataHash, the enclave key. App Attest cannot
                // attest a key the app generated itself, so the app committed SHA-256(jkt | challenge).
                byte[] clientDataHash = clientDataHash(enclaveJkt, request.challenge());
                AppAttestAttestation attested;
                try {
                    attested = this.appAttest.verifyAttestation(
                            request.appAttestObject(), clientDataHash, request.appAttestKeyId());
                } catch (AppAttestException e) {
                    // The nonce check failing here is the interesting case: it means the app committed to some
                    // other key, so the enclave key we were handed is not the one Apple's attestation covers.
                    throw new EnrolmentException(EnrolmentException.INVALID_ATTESTATION, 401,
                            "App Attest verification failed (" + e.reason() + "): " + e.getMessage(), e);
                }
                String env = attested.environment().name().equals("DEVELOPMENT") ? "appattestdevelop" : "appattest";
                Map<String, Object> facts = new LinkedHashMap<>();
                facts.put("type", "app-attest");
                facts.put("environment", env);
                return new VerifiedEvidence(attested.keyIdBase64Url(), prefix + env, facts);
            }
            case "yubikey-piv": {
                if (!hostedAgent) {
                    throw EnrolmentException.invalidRequest("yubikey-piv evidence is accepted only on the connector path");
                }
                if (this.agents.piv() == null) {
                    throw EnrolmentException.invalidAttestation(
                            "YubiKey PIV attestation is not configured on this attester (YUBICO_PIV_ROOTS)");
                }
                Map<String, Object> ev = request.evidence();
                String f9 = stringField(ev, "f9");
                List<String> intermediates = stringList(ev.get("intermediates"));
                PivAttestationVerifier.Attested instanceKey = this.agents.piv().verify(
                        stringField(mapField(ev, "instance"), "leaf"), f9, intermediates, request.enclavePublicJwk());
                PivAttestationVerifier.Attested federationKey = this.agents.piv().verify(
                        stringField(mapField(ev, "federation"), "leaf"), f9, intermediates, request.federationPublicJwk());
                if (instanceKey.serial() != federationKey.serial()) {
                    throw EnrolmentException.invalidAttestation("the instance and federation keys are on different YubiKeys");
                }
                Map<String, Object> facts = new LinkedHashMap<>();
                facts.put("type", "yubikey-piv");
                facts.put("serial", instanceKey.serial());
                facts.put("firmware", instanceKey.firmware());
                facts.put("pin_policy", instanceKey.pinPolicy().name().toLowerCase());
                facts.put("touch_policy", instanceKey.touchPolicy().name().toLowerCase());
                facts.put("form_factor", instanceKey.formFactor());
                facts.put("fips", instanceKey.fips());
                facts.put("cspn", instanceKey.cspn());
                return new VerifiedEvidence("piv:" + instanceKey.serial(),
                        prefix + "yubikey-piv" + (instanceKey.userPresencePerUse() ? ":presence" : ""), facts);
            }
            case "secure-enclave-self-asserted": {
                if (!hostedAgent) {
                    throw EnrolmentException.invalidRequest("self-asserted evidence is accepted only on the connector path");
                }
                if (!this.agents.allowSelfAssertedKeys()) {
                    throw EnrolmentException.invalidAttestation("this attester does not accept self-asserted key storage");
                }
                return new VerifiedEvidence("self:" + enclaveJkt, prefix + "secure-enclave-self-asserted",
                        Map.of("type", "secure-enclave-self-asserted"));
            }
            default:
                throw EnrolmentException.invalidRequest("unsupported evidence type: " + type);
        }
    }

    /**
     * The evidence-dependent attestation claims for a device, read back from how it was enrolled - so a
     * re-mint says exactly what the enrolment proved, never more.
     */
    DeviceAttestationMinter.MintProfile profileFor(String environment) {
        if (environment == null || !environment.startsWith(CONNECTOR_PREFIX)) {
            return this.minter.defaultProfile();
        }
        String kind = environment.substring(CONNECTOR_PREFIX.length());
        List<Map<String, Object>> authz = this.agents.authorizationDetails();
        if (kind.startsWith("appattest")) {
            return new DeviceAttestationMinter.MintProfile(KeyStorageLevel.MODERATE, KeyStorageLevel.MODERATE,
                    "app-attest", authz);
        }
        if (kind.startsWith("yubikey-piv")) {
            return new DeviceAttestationMinter.MintProfile(KeyStorageLevel.MODERATE,
                    kind.endsWith(":presence") ? KeyStorageLevel.MODERATE : KeyStorageLevel.BASIC,
                    "yubikey-piv-attestation", authz);
        }
        // Self-asserted: no key_storage and no user_authentication claim. Absent is the honest value.
        return new DeviceAttestationMinter.MintProfile(null, null, "self-asserted", authz);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mapField(Map<String, Object> map, String name) throws EnrolmentException {
        Object v = map == null ? null : map.get(name);
        if (!(v instanceof Map)) {
            throw EnrolmentException.invalidRequest("evidence." + name + " must be an object");
        }
        return (Map<String, Object>) v;
    }

    private static String stringField(Map<String, Object> map, String name) throws EnrolmentException {
        Object v = map == null ? null : map.get(name);
        if (!(v instanceof String) || ((String) v).isBlank()) {
            throw EnrolmentException.invalidRequest("evidence field '" + name + "' is required");
        }
        return (String) v;
    }

    private static List<String> stringList(Object v) {
        if (!(v instanceof List)) {
            return List.of();
        }
        return ((List<?>) v).stream().filter(String.class::isInstance).map(String.class::cast).toList();
    }

    /** What verified evidence establishes: the device record's key reference and environment, and facts to return. */
    record VerifiedEvidence(String deviceKeyRef, String environment, Map<String, Object> facts) {
    }

    /**
     * Re-mints an attestation for an already-enrolled instance.
     *
     * <p>This is the hot path — an agent hits it every fifteen minutes — and it is where the time-box is
     * enforced. The enclave key proof shows the key is present, but not that the user was verified
     * recently: the app may be holding a pre-authenticated context, which Apple documents no expiry
     * for. So {@code uv_last_verified_at} is checked independently, and when it has aged out the client
     * is told to put the human back in front of the phone.
     */
    public Reissued reissue(ReissueRequest request) throws EnrolmentException {
        Objects.requireNonNull(request, "request");
        require(notBlank(request.instanceId()), "instance_id is required");

        AgentInstance instance = findInstance(request.instanceId());
        if (!instance.status().canObtainTokens()) {
            throw EnrolmentException.instanceNotActive(
                    "instance " + instance.id() + " is " + instance.status());
        }

        EnclaveKeyProofValidator.Result proof =
                this.keyProofs.validate(request.keyProof(), instance.cnfJkt(), this.audience);
        if (notBlank(proof.challenge()) && !this.challenges.consume(proof.challenge())) {
            throw EnrolmentException.invalidChallenge("challenge is unknown, expired, or already used");
        }
        if (!this.replayCache.firstSeen(instance.id(), proof.jti(), 300L)) {
            throw EnrolmentException.invalidKeyProof("key proof jti has already been used (replay)");
        }

        Device device = findDevice(instance.deviceId());
        if (this.requireCompliantDevice && device.complianceState() != ComplianceState.COMPLIANT) {
            // UNKNOWN fails too: never assessed is not the same as assessed and clean.
            throw EnrolmentException.deviceNotCompliant(
                    "device compliance is " + device.complianceState());
        }

        if (!instance.userVerificationFreshAt(Instant.now(), this.userVerificationMaxAge)) {
            throw EnrolmentException.userVerificationRequired(
                    "user verification is older than " + this.userVerificationMaxAge
                            + "; re-authenticate the owner and retry");
        }

        try {
            DeviceAttestationMinter.Minted minted = this.minter.mint(instance, proof.publicJwk(),
                    null, this.userVerificationMaxAge.toSeconds(), this.signer,
                    this.profileFor(device.appAttestEnvironment()));
            this.registry.recordAttestationExpiry(instance.id(), minted.expiresAt());
            return new Reissued(minted.attestation(), minted.expiresInSeconds());
        } catch (RegistryException e) {
            throw EnrolmentException.serverError("could not record the issuance: " + e.getMessage(), e);
        }
    }

    /**
     * Refreshes the user-verification timestamp from a fresh IdP authentication.
     *
     * <p>Deliberately the <em>only</em> way that timestamp moves. A client assertion that the user is
     * present is worth nothing, and a signature from a biometry-gated key is not evidence of recency
     * either. Requiring a verifiable authentication is what makes the window real.
     */
    public void refreshUserVerification(String instanceId, String userAuthenticationEvidence)
            throws EnrolmentException {
        AgentInstance instance = findInstance(instanceId);
        UserAuthentication authentication = this.userAuthentication.verify(userAuthenticationEvidence);
        if (!authentication.meetsAssurance(REQUIRED_ASSURANCE)) {
            throw EnrolmentException.insufficientAssurance(
                    "refreshing user verification requires " + REQUIRED_ASSURANCE);
        }
        Device device = findDevice(instance.deviceId());
        OwnerUser owner = findOwner(device.ownerUserId());
        if (!owner.pingOneSubject().equals(authentication.subject())) {
            // Someone else's valid authentication must not extend this instance's window.
            throw EnrolmentException.userAuthenticationFailed(
                    "the authenticated user does not own this instance");
        }
        try {
            this.registry.recordUserVerification(instance.id(), authentication.authenticatedAt());
        } catch (RegistryException e) {
            throw EnrolmentException.serverError("could not record user verification", e);
        }
    }

    /** Applies a compliance signal, and suspends every instance on a device that fell out of compliance. */
    public void applyComplianceChange(String deviceId, ComplianceState state, Instant checkedAt)
            throws EnrolmentException {
        try {
            this.registry.updateCompliance(deviceId, state, checkedAt);
            if (state != ComplianceState.COMPLIANT) {
                for (AgentInstance instance : this.registry.instancesOnDevice(deviceId)) {
                    if (instance.status() == InstanceStatus.ACTIVE) {
                        this.registry.setStatus(instance.id(), InstanceStatus.SUSPENDED,
                                "device compliance became " + state);
                    }
                }
            }
        } catch (RegistryException e) {
            throw EnrolmentException.serverError("could not apply the compliance change", e);
        }
    }

    /**
     * Revokes an instance. The next issuance fails; nothing has to reach the device.
     *
     * <p>{@link InstanceRegistry#revoke} already writes the {@code INSTANCE_REVOKED} audit entry as
     * part of its atomic status change — this method must not audit a second time, or every revocation
     * leaves two rows in what is meant to be the dispute record.
     */
    public void revoke(String instanceId, String reason) throws EnrolmentException {
        try {
            this.registry.revoke(instanceId, reason);
        } catch (RegistryException e) {
            throw EnrolmentException.serverError("could not revoke the instance", e);
        }
    }

    // ---- internals ---------------------------------------------------------------------------

    /**
     * The commitment that ties App Attest to the enclave key: {@code SHA-256(jkt ‖ challenge)},
     * recomputed from what we hold rather than accepted from the client.
     */
    static byte[] clientDataHash(String enclaveJkt, String challenge) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest((enclaveJkt + "|" + challenge).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private String minterPlatform() {
        return this.audience;
    }

    private String thumbprint(Map<String, Object> jwk) throws EnrolmentException {
        try {
            Jwks.assertPublicOnly(jwk);
            return Jwks.thumbprint(jwk);
        } catch (Exception e) {
            throw EnrolmentException.invalidRequest("enclave_public_jwk is not a usable public JWK");
        }
    }

    private AgentInstance findInstance(String instanceId) throws EnrolmentException {
        try {
            return this.registry.findInstance(instanceId)
                    .orElseThrow(() -> EnrolmentException.unknownInstance("unknown instance: " + instanceId));
        } catch (RegistryException e) {
            throw EnrolmentException.serverError("could not read the instance", e);
        }
    }

    private Device findDevice(String deviceId) throws EnrolmentException {
        try {
            return this.registry.findDevice(deviceId)
                    .orElseThrow(() -> EnrolmentException.serverError(
                            "instance references a device that does not exist: " + deviceId, null));
        } catch (RegistryException e) {
            throw EnrolmentException.serverError("could not read the device", e);
        }
    }

    private OwnerUser findOwner(String ownerId) throws EnrolmentException {
        try {
            return this.registry.findOwner(ownerId)
                    .orElseThrow(() -> EnrolmentException.serverError(
                            "device references an owner that does not exist: " + ownerId, null));
        } catch (RegistryException e) {
            throw EnrolmentException.serverError("could not read the owner", e);
        }
    }

    private static void require(boolean condition, String message) throws EnrolmentException {
        if (!condition) {
            throw EnrolmentException.invalidRequest(message);
        }
    }

    /** A human-readable device description for the notification. No identifiers, just recognisability. */
    private static String describe(EnrolmentRequest request) {
        String model = request.model() == null ? "an unknown device" : request.model();
        return request.osVersion() == null ? model : model + " (" + request.platform() + " "
                + request.osVersion() + ")";
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }

    // ---- request and response shapes -----------------------------------------------------------

    /** A one-time challenge and its lifetime. */
    public record Challenge(String challenge, long expiresInSeconds) {
    }

    /**
     * @param appAttestKeyId the key id the app claims, cross-checked against the attested key
     */
    public record EnrolmentRequest(
            byte[] appAttestObject,
            byte[] appAttestKeyId,
            Map<String, Object> enclavePublicJwk,
            String challenge,
            String userAuthenticationEvidence,
            String platform,
            String model,
            String osVersion,
            String agentBuild,
            Map<String, Object> federationPublicJwk,
            Map<String, String> keyProofs,
            Map<String, Object> evidence) {

        /** The iOS request: App Attest over one enclave key, no federation key. */
        public EnrolmentRequest(byte[] appAttestObject, byte[] appAttestKeyId, Map<String, Object> enclavePublicJwk,
                                String challenge, String userAuthenticationEvidence, String platform, String model,
                                String osVersion, String agentBuild) {
            this(appAttestObject, appAttestKeyId, enclavePublicJwk, challenge, userAuthenticationEvidence, platform,
                    model, osVersion, agentBuild, null, null, null);
        }

        /** {@code evidence.type} when given; App Attest otherwise (the iOS request carries no evidence object). */
        public String evidenceType() {
            Object type = this.evidence == null ? null : this.evidence.get("type");
            return type instanceof String && !((String) type).isBlank() ? (String) type : "app-attest";
        }
    }

    /** The instance identifier is the client's handle from here on; it never learns the device id. */
    public record Enrolled(String instanceId, String attestation, long expiresInSeconds,
                           String appAttestKeyId, String entityId, String authorityEntityId,
                           Map<String, Object> evidence) {

        public Enrolled(String instanceId, String attestation, long expiresInSeconds, String appAttestKeyId) {
            this(instanceId, attestation, expiresInSeconds, appAttestKeyId, null, null, Map.of());
        }
    }

    /**
     * The connector-agent path's configuration. Everything defaults to off: no federation onboarding, no
     * PIV evidence, no self-asserted keys, no entitlement ceiling.
     *
     * @param authorizationDetails the RFC 9396 ceiling every connector attestation carries (profile §7)
     * @param federationMetadata the metadata the authority records for the hosted entity
     * @param metadataPolicy what the authority's Subordinate Statement imposes on the agent's own metadata
     */
    public record AgentOptions(HostedEntityRegistrar federation, PivAttestationVerifier piv, boolean allowSelfAssertedKeys,
                               List<Map<String, Object>> authorizationDetails, Map<String, Object> federationMetadata,
                               Map<String, Object> metadataPolicy) {
        public AgentOptions {
            federation = federation == null ? HostedEntityRegistrar.disabled() : federation;
            authorizationDetails = authorizationDetails == null ? List.of() : List.copyOf(authorizationDetails);
            federationMetadata = federationMetadata == null ? Map.of() : federationMetadata;
            metadataPolicy = metadataPolicy == null ? Map.of() : metadataPolicy;
        }

        public static AgentOptions none() {
            return new AgentOptions(null, null, false, null, null, null);
        }
    }

    public record ReissueRequest(String instanceId, String keyProof) {
    }

    public record Reissued(String attestation, long expiresInSeconds) {
    }
}
