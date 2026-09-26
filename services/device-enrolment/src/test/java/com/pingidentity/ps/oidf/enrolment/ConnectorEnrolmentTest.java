package com.pingidentity.ps.oidf.enrolment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.appattest.AppAttestEnvironment;
import com.pingidentity.ps.oidf.appattest.AppAttestFixtures;
import com.pingidentity.ps.oidf.appattest.AppAttestVerifier;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationChallengeService;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.device.DeviceAttestationMinter;
import com.pingidentity.ps.oidf.device.InMemoryInstanceRegistry;
import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.jose.LocalJwkSigner;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The connector-agent enrolment path (the Mac connector experiment): a passkey-authenticated owner, an
 * ID token whose nonce binds the challenge and both keys, possession proofs for each key, evidence per
 * type, and onboarding as a hosted federation entity.
 */
class ConnectorEnrolmentTest {

    private static final String AUDIENCE = "http://localhost:7200";
    private static final String CLIENT_ID = "claude-bank-connector";
    private static final List<Map<String, Object>> CEILING = List.of(
            Map.of("type", "https://schemas.idpartners.com.au/agentic/account_information/v1", "actions", List.of("read")));

    private InMemoryInstanceRegistry registry;
    private InMemoryAttestationChallengeService challenges;
    private NonceBoundIdp idp;
    private RecordingRegistrar federation;
    private PublicJsonWebKey instanceKey;
    private PublicJsonWebKey federationKey;
    private SyntheticYubico yubico;

    @BeforeEach
    void setUp() throws Exception {
        registry = new InMemoryInstanceRegistry();
        challenges = new InMemoryAttestationChallengeService();
        idp = new NonceBoundIdp();
        federation = new RecordingRegistrar();
        instanceKey = ec("instance");
        federationKey = ec("federation");
        yubico = new SyntheticYubico();
    }

    private EnrolmentService service(boolean allowSelfAsserted, PivAttestationVerifier piv) throws Exception {
        PublicJsonWebKey platformKey = ec("attester");
        return new EnrolmentService(null, idp, registry, new DeviceAttestationMinter(AUDIENCE, CLIENT_ID),
                challenges, new InMemoryAttestationReplayCache(),
                new LocalJwkSigner(new LinkedHashMap<>(platformKey.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE))),
                AUDIENCE, Duration.ofMinutes(60), false, BindingNotifier.logOnly(),
                new EnrolmentService.AgentOptions(federation, piv, allowSelfAsserted, CEILING,
                        Map.of("oauth_client", Map.of("software_id", CLIENT_ID)),
                        Map.of("oauth_client", Map.of("software_id", Map.of("value", CLIENT_ID)))));
    }

    private EnrolmentService.EnrolmentRequest request(String challenge, Map<String, Object> evidence,
                                                      Map<String, String> proofs, String idToken) throws Exception {
        return new EnrolmentService.EnrolmentRequest(null, null, pub(instanceKey), challenge, idToken,
                "macos", "Mac14,9", "26.6", "connector/0.1.0", pub(federationKey), proofs, evidence);
    }

    private Map<String, String> proofs(String challenge) throws Exception {
        return Map.of("instance", proof(instanceKey, challenge), "federation", proof(federationKey, challenge));
    }

    private String boundIdToken(String challenge) throws Exception {
        return NonceBoundIdp.token(EnrolmentService.enrolmentNonce(challenge,
                Jwks.thumbprint(pub(instanceKey)), Jwks.thumbprint(pub(federationKey))));
    }

    private EnrolmentService.Enrolled enrolSelfAsserted(EnrolmentService service) throws Exception {
        String challenge = service.issueChallenge().challenge();
        return service.enrol(request(challenge, Map.of("type", "secure-enclave-self-asserted"), proofs(challenge),
                boundIdToken(challenge)));
    }

    // ---- self-asserted (Secure Enclave without App Attest) ----------------------------------------------

    @Test
    void aSelfAssertedEnrolmentIsAttestedWithoutAnyKeyStorageClaim() throws Exception {
        EnrolmentService.Enrolled enrolled = enrolSelfAsserted(service(true, null));

        JwtClaims claims = parse(enrolled.attestation());
        assertEquals(CLIENT_ID, claims.getSubject(), "sub is the agent type (profile §6), never the instance");
        assertEquals(enrolled.instanceId(), claims.getClaimValueAsString("agent_id"));
        assertFalse(claims.hasClaim("key_storage"), "nobody verified where this key lives: no key_storage claim");
        assertFalse(claims.hasClaim("user_authentication"));
        assertEquals("self-asserted", claims.getClaimValueAsString("key_storage_evidence"));
        assertEquals(CEILING, claims.getClaimValue("authorization_details"));
        @SuppressWarnings("unchecked")
        Map<String, Object> cnf = (Map<String, Object>) claims.getClaimValue("cnf");
        assertEquals(Jwks.thumbprint(pub(instanceKey)), Jwks.thumbprint((Map<String, Object>) cnf.get("jwk")));
    }

    @Test
    void theAgentIsOnboardedAsAHostedEntityUnderAFederationSafeId() throws Exception {
        EnrolmentService.Enrolled enrolled = enrolSelfAsserted(service(true, null));

        assertTrue(enrolled.instanceId().matches("^[0-9a-f]{32}$"), "agent_id must be a valid hosted-entity slug");
        assertEquals("https://bank.example/federation/agents/" + enrolled.instanceId(), enrolled.entityId());
        assertEquals(Jwks.thumbprint(pub(federationKey)), Jwks.thumbprint(federation.federationJwk),
                "the authority must vouch for the agent's FEDERATION key, not the instance key");
        assertNotNull(federation.metadataPolicy.get("oauth_client"));
    }

    @Test
    void selfAssertedKeysAreRefusedUnlessTheAttesterAllowsThem() throws Exception {
        EnrolmentException e = assertThrows(EnrolmentException.class, () -> enrolSelfAsserted(service(false, null)));
        assertEquals(EnrolmentException.INVALID_ATTESTATION, e.error());
    }

    @Test
    void aReMintSaysNoMoreThanTheEnrolmentProved() throws Exception {
        EnrolmentService service = service(true, null);
        EnrolmentService.Enrolled enrolled = enrolSelfAsserted(service);
        String reissued = service.reissue(new EnrolmentService.ReissueRequest(enrolled.instanceId(),
                proof(instanceKey, service.issueChallenge().challenge()))).attestation();
        JwtClaims claims = parse(reissued);
        assertFalse(claims.hasClaim("key_storage"));
        assertEquals(CEILING, claims.getClaimValue("authorization_details"));
    }

    // ---- the bindings ----------------------------------------------------------------------------------

    @Test
    void theIdTokenNonceMustBindThisChallengeAndTheseKeys() throws Exception {
        EnrolmentService service = service(true, null);
        String challenge = service.issueChallenge().challenge();
        // A token bound to the same challenge but a DIFFERENT federation key: a passkey ceremony spent on
        // someone else's key pair.
        String stolen = NonceBoundIdp.token(EnrolmentService.enrolmentNonce(challenge,
                Jwks.thumbprint(pub(instanceKey)), Jwks.thumbprint(pub(ec("attacker")))));
        EnrolmentException e = assertThrows(EnrolmentException.class, () -> service.enrol(
                request(challenge, Map.of("type", "secure-enclave-self-asserted"), proofs(challenge), stolen)));
        assertEquals(EnrolmentException.USER_AUTHENTICATION_FAILED, e.error());
    }

    @Test
    void everyBoundKeyMustProvePossessionOverThisChallenge() throws Exception {
        EnrolmentService service = service(true, null);
        Map<String, Object> selfAsserted = Map.of("type", "secure-enclave-self-asserted");

        String c1 = service.issueChallenge().challenge();
        EnrolmentException missing = assertThrows(EnrolmentException.class, () -> service.enrol(
                request(c1, selfAsserted, Map.of("instance", proof(instanceKey, c1)), boundIdToken(c1))));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, missing.error());

        String c2 = service.issueChallenge().challenge();
        EnrolmentException wrongKey = assertThrows(EnrolmentException.class, () -> service.enrol(request(c2, selfAsserted,
                Map.of("instance", proof(instanceKey, c2), "federation", proof(ec("other"), c2)), boundIdToken(c2))));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, wrongKey.error());

        String c3 = service.issueChallenge().challenge();
        EnrolmentException staleChallenge = assertThrows(EnrolmentException.class, () -> service.enrol(request(c3,
                selfAsserted, Map.of("instance", proof(instanceKey, c3), "federation", proof(federationKey, "old")),
                boundIdToken(c3))));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, staleChallenge.error());
    }

    @Test
    void theFederationKeyMustBeADifferentKey() throws Exception {
        EnrolmentService service = service(true, null);
        String challenge = service.issueChallenge().challenge();
        federationKey = instanceKey;
        EnrolmentException e = assertThrows(EnrolmentException.class, () -> service.enrol(request(challenge,
                Map.of("type", "secure-enclave-self-asserted"), proofs(challenge), boundIdToken(challenge))));
        assertEquals(EnrolmentException.INVALID_REQUEST, e.error());
    }

    // ---- YubiKey PIV ---------------------------------------------------------------------------------

    @Test
    void aYubiKeyAttestedEnrolmentIsModerateAndTouchBacksUserAuthentication() throws Exception {
        EnrolmentService service = service(false, yubico.verifier());
        String challenge = service.issueChallenge().challenge();
        Map<String, Object> evidence = yubico.evidence(instanceKey.getPublicKey(), federationKey.getPublicKey(), 12345678L,
                (byte) 0x02, (byte) 0x02);
        EnrolmentService.Enrolled enrolled = service.enrol(request(challenge, evidence, proofs(challenge),
                boundIdToken(challenge)));

        JwtClaims claims = parse(enrolled.attestation());
        assertEquals("iso_18045_moderate", claims.getClaimValueAsString("key_storage"));
        assertEquals("iso_18045_moderate", claims.getClaimValueAsString("user_authentication"),
                "touch=always on the instance key: someone was at the token for every signature");
        assertEquals("yubikey-piv-attestation", claims.getClaimValueAsString("key_storage_evidence"));
        assertEquals(12345678L, ((Number) enrolled.evidence().get("serial")).longValue());
        assertEquals("5.7.4", enrolled.evidence().get("firmware"));
        assertEquals("always", enrolled.evidence().get("touch_policy"));
    }

    @Test
    void aYubiKeyWithoutPerUsePresenceIsOnlyBasicUserAuthentication() throws Exception {
        EnrolmentService service = service(false, yubico.verifier());
        String challenge = service.issueChallenge().challenge();
        Map<String, Object> evidence = yubico.evidence(instanceKey.getPublicKey(), federationKey.getPublicKey(), 42L,
                (byte) 0x02, (byte) 0x01);
        JwtClaims claims = parse(service.enrol(request(challenge, evidence, proofs(challenge), boundIdToken(challenge)))
                .attestation());
        assertEquals("iso_18045_moderate", claims.getClaimValueAsString("key_storage"));
        assertEquals("iso_18045_basic", claims.getClaimValueAsString("user_authentication"));
    }

    @Test
    void aGenuineAttestationOfSomeOtherKeyIsRefused() throws Exception {
        EnrolmentService service = service(false, yubico.verifier());
        String challenge = service.issueChallenge().challenge();
        Map<String, Object> evidence = yubico.evidence(ec("elsewhere").getPublicKey(), federationKey.getPublicKey(), 7L,
                (byte) 0x02, (byte) 0x02);
        EnrolmentException e = assertThrows(EnrolmentException.class, () -> service.enrol(
                request(challenge, evidence, proofs(challenge), boundIdToken(challenge))));
        assertEquals(EnrolmentException.INVALID_ATTESTATION, e.error());
    }

    @Test
    void keysOnTwoDifferentYubiKeysAreRefused() throws Exception {
        EnrolmentService service = service(false, yubico.verifier());
        String challenge = service.issueChallenge().challenge();
        Map<String, Object> evidence = new LinkedHashMap<>(yubico.evidence(instanceKey.getPublicKey(),
                federationKey.getPublicKey(), 1L, (byte) 0x02, (byte) 0x02));
        evidence.put("federation", Map.of("leaf", yubico.leafPem(federationKey.getPublicKey(), 2L, (byte) 0x02, (byte) 0x01)));
        EnrolmentException e = assertThrows(EnrolmentException.class, () -> service.enrol(
                request(challenge, evidence, proofs(challenge), boundIdToken(challenge))));
        assertEquals(EnrolmentException.INVALID_ATTESTATION, e.error());
    }

    @Test
    void aChainThatDoesNotReachAPinnedRootIsRefused() throws Exception {
        EnrolmentService service = service(false, new SyntheticYubico().verifier());   // a DIFFERENT root
        String challenge = service.issueChallenge().challenge();
        Map<String, Object> evidence = yubico.evidence(instanceKey.getPublicKey(), federationKey.getPublicKey(), 9L,
                (byte) 0x02, (byte) 0x02);
        EnrolmentException e = assertThrows(EnrolmentException.class, () -> service.enrol(
                request(challenge, evidence, proofs(challenge), boundIdToken(challenge))));
        assertEquals(EnrolmentException.INVALID_ATTESTATION, e.error());
    }

    // ---- PingOne ID token nonce ------------------------------------------------------------------------

    @Test
    void thePingOneVerifierEnforcesTheNonce() throws Exception {
        PublicJsonWebKey rsa = RsaJwkGenerator.generateJwk(2048);
        rsa.setKeyId("p1");
        PingOneIdTokenVerifier verifier = new PingOneIdTokenVerifier("https://auth.example/as", "connector-app",
                kid -> "p1".equals(kid) ? rsa : null, Map.of("Connector_Passkey", UserAuthentication.AssuranceLevel.AAL2));
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("https://auth.example/as");
        claims.setAudience("connector-app");
        claims.setSubject("user-1");
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(5);
        claims.setClaim("auth_time", NumericDate.now().getValue());
        claims.setClaim("acr", "Connector_Passkey");
        claims.setClaim("nonce", "the-nonce");
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(rsa.getPrivateKey());
        jws.setKeyIdHeaderValue("p1");
        jws.setAlgorithmHeaderValue("RS256");
        String token = jws.getCompactSerialization();

        assertEquals(UserAuthentication.AssuranceLevel.AAL2, verifier.verify(token, "the-nonce").assuranceLevel());
        assertThrows(EnrolmentException.class, () -> verifier.verify(token, "another-nonce"));
        // The legacy call still works for the iOS path, which has no nonce binding.
        assertNotNull(verifier.verify(token));
    }

    // ---- App Attest on a Mac (macOS 27) ------------------------------------------------------------------

    private static final String BUILD = sha256b64("connector.mjs, as sealed in the app bundle");

    private EnrolmentService service(AppAttestVerifier appAttest, boolean macKeyPolicy, Set<String> builds,
                                     boolean renewalAssertion) throws Exception {
        PublicJsonWebKey platformKey = ec("attester");
        return new EnrolmentService(appAttest, idp, registry, new DeviceAttestationMinter(AUDIENCE, CLIENT_ID),
                challenges, new InMemoryAttestationReplayCache(),
                new LocalJwkSigner(new LinkedHashMap<>(platformKey.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE))),
                AUDIENCE, Duration.ofMinutes(60), false, BindingNotifier.logOnly(),
                new EnrolmentService.AgentOptions(federation, null, false, CEILING, Map.of(), Map.of(),
                        macKeyPolicy, builds, renewalAssertion));
    }

    private EnrolmentService macService(AppAttestFixtures apple) throws Exception {
        return service(new AppAttestVerifier(apple.config(Set.of(AppAttestEnvironment.PRODUCTION))), true, Set.of(), true);
    }

    private EnrolmentService.EnrolmentRequest appAttestRequest(String challenge, AppAttestFixtures.Attestation att,
                                                               String platform, String build) throws Exception {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("type", "app-attest");
        if (build != null) {
            evidence.put("connector_build", build);
        }
        return new EnrolmentService.EnrolmentRequest(att.cbor(), att.keyId(), pub(instanceKey), challenge,
                boundIdToken(challenge), platform, "Mac14,9", "27.2", "connector/0.2.0", pub(federationKey),
                proofs(challenge), evidence);
    }

    private byte[] commitment(String challenge, String build) throws Exception {
        String jkt = Jwks.thumbprint(pub(instanceKey));
        return build == null ? EnrolmentService.clientDataHash(jkt, challenge)
                : EnrolmentService.clientDataHash(jkt, challenge, build);
    }

    @Test
    void aMacEnrolmentRecordsWhatAppleSaysAboutTheMac() throws Exception {
        AppAttestFixtures apple = new AppAttestFixtures();
        EnrolmentService service = macService(apple);
        String challenge = service.issueChallenge().challenge();
        EnrolmentService.Enrolled enrolled = service.enrol(appAttestRequest(challenge,
                apple.macAttestation(commitment(challenge, null)), "macos", null));

        assertEquals("macosx 27.2 (26B5091g)", enrolled.evidence().get("os"));
        assertEquals("ok oa odel osgn:rsec(6=1)", enrolled.evidence().get("key_policy"));
        assertEquals(Boolean.TRUE, enrolled.evidence().get("full_security"));
        assertEquals("app-attest", parse(enrolled.attestation()).getClaimValueAsString("key_storage_evidence"));
    }

    @Test
    void aMacThatDoesNotShowFullSecurityIsRefused() throws Exception {
        AppAttestFixtures apple = new AppAttestFixtures();
        EnrolmentService service = macService(apple);
        String challenge = service.issueChallenge().challenge();
        EnrolmentException e = assertThrows(EnrolmentException.class, () -> service.enrol(appAttestRequest(challenge,
                apple.attestation(commitment(challenge, null)), "macos", null)));
        assertEquals(EnrolmentException.INVALID_ATTESTATION, e.error());
        assertTrue(e.getMessage().contains("Full Security"));

        // Signing always allowed: a policy, but not the one macOS 27 writes.
        byte[] ungated = HexFormat.of().parseHex("3026a3240422" + "30200c023131" + "301a"
                + "300b0c046f73676ea1030101ff" + "300b0c046f64656ca1030101ff");
        String again = service.issueChallenge().challenge();
        EnrolmentException weak = assertThrows(EnrolmentException.class, () -> service.enrol(appAttestRequest(again,
                apple.attestation(commitment(again, null), Map.of("1.2.840.113635.100.8.6", ungated,
                        "1.2.840.113635.100.8.7", AppAttestFixtures.MACOS_PLATFORM)), "macos", null)));
        assertTrue(weak.getMessage().contains("osgn odel"));
    }

    @Test
    void theKeyPolicyCanBeWaivedOnPurpose() throws Exception {
        AppAttestFixtures apple = new AppAttestFixtures();
        EnrolmentService service = service(new AppAttestVerifier(apple.config(Set.of(AppAttestEnvironment.PRODUCTION))),
                false, Set.of(), true);
        String challenge = service.issueChallenge().challenge();
        EnrolmentService.Enrolled enrolled = service.enrol(appAttestRequest(challenge,
                apple.attestation(commitment(challenge, null)), "macos", null));
        assertFalse(enrolled.evidence().containsKey("key_policy"));
    }

    @Test
    void thePlatformMustBeTheOneAppleSigned() throws Exception {
        AppAttestFixtures apple = new AppAttestFixtures();
        EnrolmentService service = macService(apple);
        String challenge = service.issueChallenge().challenge();
        EnrolmentException e = assertThrows(EnrolmentException.class, () -> service.enrol(appAttestRequest(challenge,
                apple.macAttestation(commitment(challenge, null)), "ios", null)));
        assertTrue(e.getMessage().contains("Apple's attestation says macosx 27.2"));

        byte[] iphone = HexFormat.of().parseHex("300e" + "bf88020a" + "0408" + "6970686f6e656f73");
        String again = service.issueChallenge().challenge();
        EnrolmentException other = assertThrows(EnrolmentException.class, () -> service.enrol(appAttestRequest(again,
                apple.attestation(commitment(again, null), Map.of("1.2.840.113635.100.8.7", iphone)), "macos", null)));
        assertTrue(other.getMessage().contains("says iphoneos"));
    }

    @Test
    void theConnectorBuildIsCommittedThroughAppAttest() throws Exception {
        AppAttestFixtures apple = new AppAttestFixtures();
        EnrolmentService service = macService(apple);
        String challenge = service.issueChallenge().challenge();
        EnrolmentService.Enrolled enrolled = service.enrol(appAttestRequest(challenge,
                apple.macAttestation(commitment(challenge, BUILD)), "macos", BUILD));
        assertEquals(BUILD, enrolled.evidence().get("connector_build"));

        // Naming a different build than the one Apple's attestation covers breaks the nonce.
        String again = service.issueChallenge().challenge();
        AppAttestFixtures.Attestation att = apple.macAttestation(commitment(again, BUILD));
        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> service.enrol(appAttestRequest(again, att, "macos", sha256b64("some other build"))));
        assertEquals(401, e.status());
        assertTrue(e.getMessage().contains("NONCE_MISMATCH") || e.getMessage().contains("nonce"));
    }

    @Test
    void anAttesterCanAcceptOnlyTheBuildsItKnows() throws Exception {
        AppAttestFixtures apple = new AppAttestFixtures();
        AppAttestVerifier verifier = new AppAttestVerifier(apple.config(Set.of(AppAttestEnvironment.PRODUCTION)));
        EnrolmentService strict = service(verifier, true, Set.of(BUILD), true);
        String challenge = strict.issueChallenge().challenge();
        assertEquals(BUILD, strict.enrol(appAttestRequest(challenge, apple.macAttestation(commitment(challenge, BUILD)),
                "macos", BUILD)).evidence().get("connector_build"));

        String unknown = sha256b64("a build the bank never released");
        String c2 = strict.issueChallenge().challenge();
        EnrolmentException e = assertThrows(EnrolmentException.class, () -> strict.enrol(appAttestRequest(c2,
                apple.macAttestation(commitment(c2, unknown)), "macos", unknown)));
        assertTrue(e.getMessage().contains("is not one this attester accepts"));

        String c3 = strict.issueChallenge().challenge();
        EnrolmentException none = assertThrows(EnrolmentException.class, () -> strict.enrol(appAttestRequest(c3,
                apple.macAttestation(commitment(c3, null)), "macos", null)));
        assertTrue(none.getMessage().contains("names none"));
    }

    @Test
    void aBuildMustLookLikeAHash() throws Exception {
        AppAttestFixtures apple = new AppAttestFixtures();
        EnrolmentService service = macService(apple);
        String challenge = service.issueChallenge().challenge();
        EnrolmentException e = assertThrows(EnrolmentException.class, () -> service.enrol(appAttestRequest(challenge,
                apple.macAttestation(commitment(challenge, null)), "macos", "not-a-hash")));
        assertEquals(EnrolmentException.INVALID_REQUEST, e.error());
    }

    @Test
    void everyRenewalCarriesAFreshAssertionFromTheSameApp() throws Exception {
        AppAttestFixtures apple = new AppAttestFixtures();
        EnrolmentService service = macService(apple);
        String challenge = service.issueChallenge().challenge();
        AppAttestFixtures.Attestation att = apple.macAttestation(commitment(challenge, BUILD));
        EnrolmentService.Enrolled enrolled = service.enrol(appAttestRequest(challenge, att, "macos", BUILD));
        String appId = AppAttestFixtures.TEAM_ID + "." + AppAttestFixtures.BUNDLE_ID;

        // No assertion: refused.
        EnrolmentException missing = assertThrows(EnrolmentException.class, () -> service.reissue(
                new EnrolmentService.ReissueRequest(enrolled.instanceId(), proof(instanceKey, null))));
        assertEquals(401, missing.status());
        assertTrue(missing.getMessage().contains("app_attest_assertion is required"));

        // An assertion over this key proof, counter 1: renewed, and the counter recorded.
        String keyProof = proof(instanceKey, null);
        byte[] assertion = apple.assertion(att.attestedKey(), sha256(keyProof), 1L, appId);
        assertNotNull(service.reissue(new EnrolmentService.ReissueRequest(enrolled.instanceId(), keyProof,
                b64(assertion))).attestation());
        String deviceId = registry.findInstance(enrolled.instanceId()).orElseThrow().deviceId();
        assertEquals(1L, registry.findDevice(deviceId).orElseThrow().appAttestSignCount());

        // The same assertion cannot cover a different key proof.
        EnrolmentException moved = assertThrows(EnrolmentException.class, () -> service.reissue(
                new EnrolmentService.ReissueRequest(enrolled.instanceId(), proof(instanceKey, null), b64(assertion))));
        assertEquals(401, moved.status());

        // A counter that does not advance is a replay.
        String next = proof(instanceKey, null);
        EnrolmentException replay = assertThrows(EnrolmentException.class, () -> service.reissue(
                new EnrolmentService.ReissueRequest(enrolled.instanceId(), next,
                        b64(apple.assertion(att.attestedKey(), sha256(next), 1L, appId)))));
        assertTrue(replay.getMessage().contains("BAD_COUNTER") || replay.getMessage().contains("counter"));

        // Not base64url at all.
        EnrolmentException garbled = assertThrows(EnrolmentException.class, () -> service.reissue(
                new EnrolmentService.ReissueRequest(enrolled.instanceId(), proof(instanceKey, null), "***")));
        assertEquals(EnrolmentException.INVALID_REQUEST, garbled.error());
    }

    @Test
    void renewalWithoutAnAssertionCanBeAllowedOnPurpose() throws Exception {
        AppAttestFixtures apple = new AppAttestFixtures();
        EnrolmentService service = service(new AppAttestVerifier(apple.config(Set.of(AppAttestEnvironment.PRODUCTION))),
                true, Set.of(), false);
        String challenge = service.issueChallenge().challenge();
        EnrolmentService.Enrolled enrolled = service.enrol(appAttestRequest(challenge,
                apple.macAttestation(commitment(challenge, null)), "macos", null));
        assertNotNull(service.reissue(new EnrolmentService.ReissueRequest(enrolled.instanceId(),
                proof(instanceKey, null))).attestation());
    }

    private static byte[] sha256(String s) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256b64(String s) {
        try {
            return b64(sha256(s));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // ---- fixtures ----------------------------------------------------------------------------------------

    private static PublicJsonWebKey ec(String kid) throws Exception {
        PublicJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId(kid + "-" + UUID.randomUUID());
        return key;
    }

    private static Map<String, Object> pub(JsonWebKey key) {
        return new LinkedHashMap<>(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
    }

    private static String proof(PublicJsonWebKey key, String challenge) throws Exception {
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
        jws.getHeaders().setObjectHeaderValue("jwk", pub(key));
        return jws.getCompactSerialization();
    }

    private static JwtClaims parse(String jwt) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(jwt);
        return JwtClaims.parse(jws.getUnverifiedPayload());
    }

    /** Accepts "nonce:<value>" tokens and checks the value against the expected binding. */
    private static final class NonceBoundIdp implements UserAuthenticationVerifier {
        static String token(String nonce) {
            return "nonce:" + nonce;
        }

        @Override
        public UserAuthentication verify(String evidence) throws EnrolmentException {
            throw EnrolmentException.userAuthenticationFailed("the connector path must always bind a nonce");
        }

        @Override
        public UserAuthentication verify(String evidence, String expectedNonce) throws EnrolmentException {
            if (expectedNonce == null || !("nonce:" + expectedNonce).equals(evidence)) {
                throw EnrolmentException.userAuthenticationFailed("nonce does not bind this enrolment");
            }
            return new UserAuthentication("pingone|dave", Instant.now(), UserAuthentication.AssuranceLevel.AAL2,
                    "cred-1", "aaguid-1");
        }
    }

    private static final class RecordingRegistrar implements HostedEntityRegistrar {
        Map<String, Object> federationJwk;
        Map<String, Object> metadataPolicy;

        @Override
        public String register(String agentId, Map<String, Object> jwk, Map<String, Object> metadata,
                               Map<String, Object> policy, String ownerRef) {
            this.federationJwk = jwk;
            this.metadataPolicy = policy;
            return "https://bank.example/federation/agents/" + agentId;
        }

        @Override
        public String authorityEntityId() {
            return "https://bank.example";
        }
    }

    /** A stand-in Yubico PKI: root -> F9 -> slot certificates carrying Yubico's attestation extensions. */
    private static final class SyntheticYubico {
        private final KeyPair root;
        private final KeyPair f9;
        private final X509Certificate rootCert;
        private final X509Certificate f9Cert;
        private final X500Name rootName = new X500Name("CN=Yubico PIV Root CA Serial 263751");
        private final X500Name f9Name = new X500Name("CN=Yubico PIV Attestation");

        SyntheticYubico() throws Exception {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec("secp256r1"));
            this.root = gen.generateKeyPair();
            this.f9 = gen.generateKeyPair();
            this.rootCert = cert(this.rootName, this.rootName, this.root.getPublic(), this.root.getPrivate(), true, null);
            this.f9Cert = cert(this.rootName, this.f9Name, this.f9.getPublic(), this.root.getPrivate(), true, null);
        }

        PivAttestationVerifier verifier() {
            return new PivAttestationVerifier(List.of(this.rootCert));
        }

        Map<String, Object> evidence(PublicKey instance, PublicKey federation, long serial, byte pin, byte touch)
                throws Exception {
            Map<String, Object> ev = new LinkedHashMap<>();
            ev.put("type", "yubikey-piv");
            ev.put("instance", Map.of("leaf", leafPem(instance, serial, pin, touch)));
            ev.put("federation", Map.of("leaf", leafPem(federation, serial, pin, (byte) 0x01)));
            ev.put("f9", pem(this.f9Cert));
            return ev;
        }

        String leafPem(PublicKey key, long serial, byte pin, byte touch) throws Exception {
            Map<String, byte[]> ext = new LinkedHashMap<>();
            ext.put(PivAttestationVerifier.OID_FIRMWARE, new byte[]{5, 7, 4});
            ext.put(PivAttestationVerifier.OID_SERIAL, new ASN1Integer(BigInteger.valueOf(serial)).getEncoded());
            ext.put(PivAttestationVerifier.OID_POLICY, new byte[]{pin, touch});
            ext.put(PivAttestationVerifier.OID_FORM_FACTOR, new byte[]{0x01});
            return pem(cert(this.f9Name, new X500Name("CN=YubiKey PIV Attestation 83"), key, this.f9.getPrivate(), false, ext));
        }

        private static X509Certificate cert(X500Name issuer, X500Name subject, PublicKey key, PrivateKey signer,
                                            boolean ca, Map<String, byte[]> extensions) throws Exception {
            Date from = Date.from(Instant.now().minusSeconds(3600));
            Date to = Date.from(Instant.now().plusSeconds(86400L * 365));
            X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(System.nanoTime()),
                    from, to, subject, key);
            if (ca) {
                b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            }
            if (extensions != null) {
                for (Map.Entry<String, byte[]> e : extensions.entrySet()) {
                    b.addExtension(new ASN1ObjectIdentifier(e.getKey()), false, e.getValue());
                }
            }
            return new JcaX509CertificateConverter().getCertificate(
                    b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer)));
        }

        private static String pem(X509Certificate cert) throws Exception {
            return "-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded())
                    + "\n-----END CERTIFICATE-----\n";
        }
    }
}
