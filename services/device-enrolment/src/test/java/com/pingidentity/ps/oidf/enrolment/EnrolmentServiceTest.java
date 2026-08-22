package com.pingidentity.ps.oidf.enrolment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.appattest.AppAttestConfig;
import com.pingidentity.ps.oidf.appattest.AppAttestFixtures;
import com.pingidentity.ps.oidf.appattest.AppAttestEnvironment;
import com.pingidentity.ps.oidf.appattest.AppAttestVerifier;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationChallengeService;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.jose.LocalJwkSigner;
import com.pingidentity.ps.oidf.device.AuditEntry;
import com.pingidentity.ps.oidf.device.ComplianceState;
import com.pingidentity.ps.oidf.device.DeviceAttestationMinter;
import com.pingidentity.ps.oidf.device.InMemoryInstanceRegistry;
import com.pingidentity.ps.oidf.device.InstanceRegistry;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The ceremony end to end, against a synthetic Apple chain and a fake IdP.
 *
 * <p>The cases that matter most are the negative ones: an attestation committing to somebody else's
 * key, a development attestation on a production verifier, and a user verification that has aged out.
 */
class EnrolmentServiceTest {

    private static final String AUDIENCE = "https://platform.example.com";

    private EnrolmentFixtures fixtures;
    private InstanceRegistry registry;
    private FakeUserAuthentication idp;
    private InMemoryAttestationChallengeService challenges;
    private EnrolmentService service;
    private PublicJsonWebKey enclaveKey;
    private Map<String, Object> enclavePublicJwk;

    @BeforeEach
    void setUp() throws Exception {
        fixtures = new EnrolmentFixtures();
        registry = new InMemoryInstanceRegistry();
        idp = new FakeUserAuthentication();
        challenges = new InMemoryAttestationChallengeService();
        enclaveKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        enclaveKey.setKeyId("enclave-1");
        enclavePublicJwk = publicParams(enclaveKey);
        service = newService(EnumSet.of(AppAttestEnvironment.PRODUCTION), true);
    }

    private EnrolmentService newService(EnumSet<AppAttestEnvironment> environments, boolean requireCompliant) {
        PublicJsonWebKey platformKey = fixtures.platformSigningKey();
        JwsSigner signer = new LocalJwkSigner(privateParams(platformKey));
        return new EnrolmentService(
                new AppAttestVerifier(fixtures.appAttestConfig(environments)),
                idp, registry, new DeviceAttestationMinter(AUDIENCE),
                challenges, new InMemoryAttestationReplayCache(), signer, AUDIENCE,
                Duration.ofMinutes(5), requireCompliant);
    }

    private EnrolmentService.EnrolmentRequest enrolmentRequest(String challenge,
                                                               Map<String, Object> jwkCommittedTo,
                                                               AppAttestEnvironment environment)
            throws Exception {
        byte[] clientDataHash = EnrolmentService.clientDataHash(Jwks.thumbprint(jwkCommittedTo), challenge);
        EnrolmentFixtures.Attestation built = fixtures.attestation(clientDataHash, environment);
        return new EnrolmentService.EnrolmentRequest(built.cbor(), built.keyId(), enclavePublicJwk,
                challenge, "valid-idp-result", "ios", "iPhone16,2", "18.5", "agent/1.0");
    }

    private EnrolmentService.Enrolled enrol() throws Exception {
        String challenge = service.issueChallenge().challenge();
        return service.enrol(enrolmentRequest(challenge, enclavePublicJwk, AppAttestEnvironment.PRODUCTION));
    }

    // ---- the happy path ---------------------------------------------------------------------------

    @Test
    void enrolmentBindsTheEnclaveKeyAndReturnsAnAttestation() throws Exception {
        EnrolmentService.Enrolled enrolled = enrol();

        assertNotNull(enrolled.instanceId());
        assertEquals(900L, enrolled.expiresInSeconds());
        JwtClaims claims = parse(enrolled.attestation());
        assertEquals(enrolled.instanceId(), claims.getSubject());
        assertEquals("iso_18045_moderate", claims.getClaimValueAsString("key_storage"));

        // The registry, and only the registry, can walk instance -> device -> human.
        var instance = registry.findInstance(enrolled.instanceId()).orElseThrow();
        var device = registry.findDevice(instance.deviceId()).orElseThrow();
        assertEquals("pingone|alice", registry.findOwner(device.ownerUserId()).orElseThrow().pingOneSubject());
    }

    /**
     * The binding that the whole design rests on. The app commits to an enclave key thumbprint inside
     * App Attest's clientDataHash; if it commits to a different key, the nonce no longer matches what we
     * recompute, and enrolment must fail. Without this the chain of custody is decorative.
     */
    @Test
    void anAttestationCommittingToSomebodyElsesKeyIsRefused() throws Exception {
        PublicJsonWebKey attackerKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        attackerKey.setKeyId("attacker");
        String challenge = service.issueChallenge().challenge();

        // The attestation commits to the attacker's key, but the request presents ours.
        EnrolmentService.EnrolmentRequest request =
                enrolmentRequest(challenge, publicParams(attackerKey), AppAttestEnvironment.PRODUCTION);

        EnrolmentException e = assertThrows(EnrolmentException.class, () -> service.enrol(request));
        assertEquals(EnrolmentException.INVALID_ATTESTATION, e.error());
        assertTrue(e.getMessage().contains("nonce_mismatch"), e.getMessage());
    }

    @Test
    void aDevelopmentAttestationIsRefusedByAProductionService() throws Exception {
        String challenge = service.issueChallenge().challenge();
        EnrolmentService.EnrolmentRequest request =
                enrolmentRequest(challenge, enclavePublicJwk, AppAttestEnvironment.DEVELOPMENT);

        EnrolmentException e = assertThrows(EnrolmentException.class, () -> service.enrol(request));
        assertEquals(EnrolmentException.INVALID_ATTESTATION, e.error());
        assertTrue(e.getMessage().contains("environment_not_accepted"), e.getMessage());
    }

    @Test
    void aDevelopmentEnrolmentIsFlaggedWhenExplicitlyAllowed() throws Exception {
        service = newService(EnumSet.allOf(AppAttestEnvironment.class), true);
        String challenge = service.issueChallenge().challenge();
        EnrolmentService.Enrolled enrolled = service.enrol(
                enrolmentRequest(challenge, enclavePublicJwk, AppAttestEnvironment.DEVELOPMENT));

        var instance = registry.findInstance(enrolled.instanceId()).orElseThrow();
        assertTrue(registry.findDevice(instance.deviceId()).orElseThrow().isDevelopmentEnrolment(),
                "a development enrolment must stay distinguishable forever");
    }

    @Test
    void aChallengeCannotBeUsedTwice() throws Exception {
        String challenge = service.issueChallenge().challenge();
        service.enrol(enrolmentRequest(challenge, enclavePublicJwk, AppAttestEnvironment.PRODUCTION));

        EnrolmentService.EnrolmentRequest replay =
                enrolmentRequest(challenge, enclavePublicJwk, AppAttestEnvironment.PRODUCTION);
        assertEquals(EnrolmentException.INVALID_CHALLENGE,
                assertThrows(EnrolmentException.class, () -> service.enrol(replay)).error());
    }

    // ---- assurance --------------------------------------------------------------------------------

    @Test
    void bindingRequiresAtLeastAal2() throws Exception {
        idp.assuranceLevel = UserAuthentication.AssuranceLevel.AAL1;
        String challenge = service.issueChallenge().challenge();
        EnrolmentService.EnrolmentRequest request =
                enrolmentRequest(challenge, enclavePublicJwk, AppAttestEnvironment.PRODUCTION);

        assertEquals(EnrolmentException.INSUFFICIENT_ASSURANCE,
                assertThrows(EnrolmentException.class, () -> service.enrol(request)).error());
    }

    @Test
    void aFailedUserAuthenticationWritesNothing() throws Exception {
        idp.fail = true;
        String challenge = service.issueChallenge().challenge();
        EnrolmentService.EnrolmentRequest request =
                enrolmentRequest(challenge, enclavePublicJwk, AppAttestEnvironment.PRODUCTION);

        assertThrows(EnrolmentException.class, () -> service.enrol(request));
        // The challenge is still unconsumed, and no rows exist — the human is verified first for exactly
        // this reason.
        assertTrue(challenges.consume(challenge), "the challenge should not have been consumed");
    }

    // ---- re-issuance and the server-side time-box ---------------------------------------------------

    @Test
    void reissueSucceedsWhileUserVerificationIsFresh() throws Exception {
        EnrolmentService.Enrolled enrolled = enrol();
        makeCompliant(enrolled.instanceId());

        EnrolmentService.Reissued reissued = service.reissue(new EnrolmentService.ReissueRequest(
                enrolled.instanceId(), keyProof(service.issueChallenge().challenge())));
        assertEquals(900L, reissued.expiresInSeconds());
    }

    /**
     * The control that actually holds. The enclave key still signs — the client can produce a perfectly
     * valid proof — but the server refuses because the human has not been verified recently. Apple
     * documents no expiry on a held LAContext, so this is the only bound an attacker on the device
     * cannot extend.
     */
    @Test
    void reissueIsRefusedOnceUserVerificationHasAgedOut() throws Exception {
        EnrolmentService.Enrolled enrolled = enrol();
        makeCompliant(enrolled.instanceId());
        registry.recordUserVerification(enrolled.instanceId(), Instant.now().minus(Duration.ofHours(3)));

        String validProof = keyProof(service.issueChallenge().challenge());
        EnrolmentException e = assertThrows(EnrolmentException.class, () -> service.reissue(
                new EnrolmentService.ReissueRequest(enrolled.instanceId(), validProof)));
        assertEquals(EnrolmentException.USER_VERIFICATION_REQUIRED, e.error());
    }

    @Test
    void afterReAuthenticatingTheOwnerReissueWorksAgain() throws Exception {
        EnrolmentService.Enrolled enrolled = enrol();
        makeCompliant(enrolled.instanceId());
        registry.recordUserVerification(enrolled.instanceId(), Instant.now().minus(Duration.ofHours(3)));

        service.refreshUserVerification(enrolled.instanceId(), "valid-idp-result");

        assertNotNull(service.reissue(new EnrolmentService.ReissueRequest(
                enrolled.instanceId(), keyProof(service.issueChallenge().challenge()))).attestation());
    }

    @Test
    void anotherUsersAuthenticationCannotExtendThisInstancesWindow() throws Exception {
        EnrolmentService.Enrolled enrolled = enrol();
        idp.subject = "pingone|mallory";

        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> service.refreshUserVerification(enrolled.instanceId(), "valid-idp-result"));
        assertEquals(EnrolmentException.USER_AUTHENTICATION_FAILED, e.error());
    }

    @Test
    void aProofSignedByADifferentKeyIsRefused() throws Exception {
        EnrolmentService.Enrolled enrolled = enrol();
        makeCompliant(enrolled.instanceId());
        PublicJsonWebKey other = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        other.setKeyId("other");

        String foreignProof = signProof(other, service.issueChallenge().challenge());
        EnrolmentException e = assertThrows(EnrolmentException.class, () -> service.reissue(
                new EnrolmentService.ReissueRequest(enrolled.instanceId(), foreignProof)));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, e.error());
        assertTrue(e.getMessage().contains("not the one bound"), e.getMessage());
    }

    @Test
    void aReplayedProofIsRefused() throws Exception {
        EnrolmentService.Enrolled enrolled = enrol();
        makeCompliant(enrolled.instanceId());
        String proof = keyProof(null);   // no challenge, so only the jti replay cache guards it

        service.reissue(new EnrolmentService.ReissueRequest(enrolled.instanceId(), proof));
        EnrolmentException e = assertThrows(EnrolmentException.class, () -> service.reissue(
                new EnrolmentService.ReissueRequest(enrolled.instanceId(), proof)));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, e.error());
        assertTrue(e.getMessage().contains("replay"), e.getMessage());
    }

    // ---- device state -------------------------------------------------------------------------------

    @Test
    void aDeviceNeverAssessedCannotMint() throws Exception {
        EnrolmentService.Enrolled enrolled = enrol();
        // Compliance is UNKNOWN straight after enrolment, and unknown is not clean.
        EnrolmentException e = assertThrows(EnrolmentException.class, () -> service.reissue(
                new EnrolmentService.ReissueRequest(enrolled.instanceId(),
                        keyProof(service.issueChallenge().challenge()))));
        assertEquals(EnrolmentException.DEVICE_NOT_COMPLIANT, e.error());
    }

    @Test
    void aComplianceFailureSuspendsEveryInstanceOnTheDevice() throws Exception {
        EnrolmentService.Enrolled enrolled = enrol();
        var instance = registry.findInstance(enrolled.instanceId()).orElseThrow();
        makeCompliant(enrolled.instanceId());

        service.applyComplianceChange(instance.deviceId(), ComplianceState.NOT_COMPLIANT, Instant.now());

        assertEquals(EnrolmentException.INSTANCE_NOT_ACTIVE,
                assertThrows(EnrolmentException.class, () -> service.reissue(
                        new EnrolmentService.ReissueRequest(enrolled.instanceId(),
                                keyProof(service.issueChallenge().challenge())))).error());
    }

    @Test
    void revocationStopsIssuanceWithoutReachingTheDevice() throws Exception {
        EnrolmentService.Enrolled enrolled = enrol();
        makeCompliant(enrolled.instanceId());
        service.revoke(enrolled.instanceId(), "owner reported the phone stolen");

        assertEquals(EnrolmentException.INSTANCE_NOT_ACTIVE,
                assertThrows(EnrolmentException.class, () -> service.reissue(
                        new EnrolmentService.ReissueRequest(enrolled.instanceId(),
                                keyProof(service.issueChallenge().challenge())))).error());
    }

    /**
     * {@link InstanceRegistry#revoke} already writes the {@code instance_revoked} audit entry as part
     * of its atomic status change; {@link EnrolmentService#revoke} must not write a second one, or the
     * append-only log — the dispute record — carries two rows for one event.
     */
    @Test
    void revocationWritesExactlyOneAuditEntry() throws Exception {
        EnrolmentService.Enrolled enrolled = enrol();
        makeCompliant(enrolled.instanceId());
        service.revoke(enrolled.instanceId(), "owner reported the phone stolen");

        long revocations = registry.auditTrail(enrolled.instanceId()).stream()
                .filter(e -> AuditEntry.INSTANCE_REVOKED.equals(e.eventCode()))
                .count();
        assertEquals(1L, revocations, "a single revoke() call must not double-audit");
    }

    @Test
    void anUnknownInstanceIsNotFound() {
        assertEquals(EnrolmentException.UNKNOWN_INSTANCE,
                assertThrows(EnrolmentException.class, () -> service.reissue(
                        new EnrolmentService.ReissueRequest("ghost", "x"))).error());
    }

    // ---- helpers -------------------------------------------------------------------------------------

    private void makeCompliant(String instanceId) throws Exception {
        var instance = registry.findInstance(instanceId).orElseThrow();
        registry.updateCompliance(instance.deviceId(), ComplianceState.COMPLIANT, Instant.now());
    }

    private String keyProof(String challenge) throws Exception {
        return signProof(enclaveKey, challenge);
    }

    private String signProof(PublicJsonWebKey key, String challenge) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setAudience(AUDIENCE);
        claims.setClaim("jti", UUID.randomUUID().toString());
        claims.setIssuedAtToNow();
        if (challenge != null) {
            claims.setClaim("challenge", challenge);
        }
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", EnclaveKeyProofValidator.TYP);
        jws.getHeaders().setObjectHeaderValue("jwk", publicParams(key));
        return jws.getCompactSerialization();
    }

    private static JwtClaims parse(String jwt) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(jwt);
        return JwtClaims.parse(jws.getUnverifiedPayload());
    }

    private static Map<String, Object> publicParams(JsonWebKey jwk) {
        return new LinkedHashMap<>(jwk.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
    }

    private static Map<String, Object> privateParams(JsonWebKey jwk) {
        return new LinkedHashMap<>(jwk.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
    }

    /** A stand-in IdP, so the ceremony is testable without a live PingOne tenant. */
    private static final class FakeUserAuthentication implements UserAuthenticationVerifier {
        String subject = "pingone|alice";
        UserAuthentication.AssuranceLevel assuranceLevel = UserAuthentication.AssuranceLevel.AAL2;
        boolean fail = false;

        @Override
        public UserAuthentication verify(String evidence) throws EnrolmentException {
            if (this.fail) {
                throw EnrolmentException.userAuthenticationFailed("the fake IdP was told to refuse");
            }
            return new UserAuthentication(this.subject, Instant.now(), this.assuranceLevel,
                    "cred-abc", "aaguid-1");
        }
    }

    /**
     * Wraps the App Attest fixture chain (shared via that module's test-jar) and adds the platform's own
     * attestation signing key, which is this service's concern rather than Apple's.
     */
    private static final class EnrolmentFixtures {
        private final AppAttestFixtures appAttest = new AppAttestFixtures();
        private final PublicJsonWebKey platformKey;

        EnrolmentFixtures() throws Exception {
            this.platformKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
            this.platformKey.setKeyId("platform-1");
        }

        AppAttestConfig appAttestConfig(EnumSet<AppAttestEnvironment> environments) {
            return this.appAttest.config(environments);
        }

        PublicJsonWebKey platformSigningKey() {
            return this.platformKey;
        }

        Attestation attestation(byte[] clientDataHash, AppAttestEnvironment environment) throws Exception {
            AppAttestFixtures.Attestation built = this.appAttest.attestation(clientDataHash, environment,
                    0L, AppAttestFixtures.TEAM_ID + "." + AppAttestFixtures.BUNDLE_ID, true);
            return new Attestation(built.cbor(), built.keyId());
        }

        record Attestation(byte[] cbor, byte[] keyId) {
        }
    }
}
