package com.pingidentity.ps.oidf.appattest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AppAttestVerifierTest {

    private AppAttestFixtures fixtures;
    private byte[] clientDataHash;

    @BeforeEach
    void setUp() throws Exception {
        fixtures = new AppAttestFixtures();
        // In the real flow this is SHA-256(Secure Enclave JWK thumbprint ‖ server challenge).
        clientDataHash = AppAttestFixtures.sha256("se-thumbprint|challenge".getBytes(StandardCharsets.UTF_8));
    }

    private AppAttestVerifier productionVerifier() {
        return new AppAttestVerifier(fixtures.config(EnumSet.of(AppAttestEnvironment.PRODUCTION)));
    }

    @Test
    void happyPathYieldsTheAttestedKeyAndKeyId() throws Exception {
        AppAttestFixtures.Attestation built = fixtures.attestation(clientDataHash);

        AppAttestAttestation result =
                productionVerifier().verifyAttestation(built.cbor(), clientDataHash, built.keyId());

        assertArrayEquals(built.keyId(), result.keyId());
        assertEquals(AppAttestEnvironment.PRODUCTION, result.environment());
        assertEquals(0L, result.signCount());
        assertNotNull(result.attestedKey());
        assertNotNull(result.receipt());
        // The key id is the hash of the attested key — that is what makes it unforgeable.
        assertArrayEquals(
                AppAttestFixtures.sha256(AppAttestVerifier.uncompressedPoint(result.attestedKey())),
                result.keyId());
    }

    @Test
    void aDifferentClientDataHashBreaksTheNonce() throws Exception {
        AppAttestFixtures.Attestation built = fixtures.attestation(clientDataHash);
        byte[] otherHash = AppAttestFixtures.sha256("someone else's key".getBytes(StandardCharsets.UTF_8));

        AppAttestException e = assertThrows(AppAttestException.class,
                () -> productionVerifier().verifyAttestation(built.cbor(), otherHash, built.keyId()));
        assertEquals(AppAttestException.NONCE_MISMATCH, e.reason());
    }

    /**
     * The single most important negative case for this platform: the nonce is the only thing binding
     * Apple's attestation to the Secure Enclave key we actually care about. If a credCert committing to
     * a different nonce were accepted, the whole chain of custody would be decorative.
     */
    @Test
    void aCredCertCommittingToADifferentNonceIsRejected() throws Exception {
        AppAttestFixtures.Attestation built = fixtures.attestation(
                clientDataHash, AppAttestEnvironment.PRODUCTION, 0L,
                AppAttestFixtures.TEAM_ID + "." + AppAttestFixtures.BUNDLE_ID, false);

        AppAttestException e = assertThrows(AppAttestException.class,
                () -> productionVerifier().verifyAttestation(built.cbor(), clientDataHash, built.keyId()));
        assertEquals(AppAttestException.NONCE_MISMATCH, e.reason());
    }

    @Test
    void anAttestationForADifferentAppIsRejected() throws Exception {
        AppAttestFixtures.Attestation built = fixtures.attestation(
                clientDataHash, AppAttestEnvironment.PRODUCTION, 0L, "ZZZZZ99999.com.attacker.app", true);

        AppAttestException e = assertThrows(AppAttestException.class,
                () -> productionVerifier().verifyAttestation(built.cbor(), clientDataHash, built.keyId()));
        assertEquals(AppAttestException.APP_ID_MISMATCH, e.reason());
    }

    @Test
    void aKeyIdTheClientDidNotActuallyAttestIsRejected() throws Exception {
        AppAttestFixtures.Attestation built = fixtures.attestation(clientDataHash);
        byte[] claimedKeyId = AppAttestFixtures.sha256("not the attested key".getBytes(StandardCharsets.UTF_8));

        AppAttestException e = assertThrows(AppAttestException.class,
                () -> productionVerifier().verifyAttestation(built.cbor(), clientDataHash, claimedKeyId));
        assertEquals(AppAttestException.KEY_ID_MISMATCH, e.reason());
    }

    @Test
    void aChainRootedElsewhereIsRejected() throws Exception {
        AppAttestFixtures other = new AppAttestFixtures();
        AppAttestFixtures.Attestation foreign = other.attestation(clientDataHash);

        // Verified against OUR root, not the one that issued it.
        AppAttestException e = assertThrows(AppAttestException.class,
                () -> productionVerifier().verifyAttestation(foreign.cbor(), clientDataHash, foreign.keyId()));
        assertEquals(AppAttestException.UNTRUSTED_CHAIN, e.reason());
    }

    @Test
    void anAttestationWithANonZeroCounterIsRejected() throws Exception {
        AppAttestFixtures.Attestation built = fixtures.attestation(
                clientDataHash, AppAttestEnvironment.PRODUCTION, 7L,
                AppAttestFixtures.TEAM_ID + "." + AppAttestFixtures.BUNDLE_ID, true);

        AppAttestException e = assertThrows(AppAttestException.class,
                () -> productionVerifier().verifyAttestation(built.cbor(), clientDataHash, built.keyId()));
        assertEquals(AppAttestException.BAD_COUNTER, e.reason());
    }

    // ---- the development-environment gate ------------------------------------------------------

    /**
     * A development attestation reaching a production verifier must be refused. A verifier that accepts
     * both by default is a hole that survives into production, so this is an explicit test rather than
     * a configuration note.
     */
    @Test
    void aDevelopmentAttestationIsRefusedByAProductionVerifier() throws Exception {
        AppAttestFixtures.Attestation built = fixtures.attestation(
                clientDataHash, AppAttestEnvironment.DEVELOPMENT, 0L,
                AppAttestFixtures.TEAM_ID + "." + AppAttestFixtures.BUNDLE_ID, true);

        AppAttestException e = assertThrows(AppAttestException.class,
                () -> productionVerifier().verifyAttestation(built.cbor(), clientDataHash, built.keyId()));
        assertEquals(AppAttestException.ENVIRONMENT_NOT_ACCEPTED, e.reason());
    }

    @Test
    void aDevelopmentAttestationIsAcceptedOnlyWhenExplicitlyAllowed() throws Exception {
        AppAttestFixtures.Attestation built = fixtures.attestation(
                clientDataHash, AppAttestEnvironment.DEVELOPMENT, 0L,
                AppAttestFixtures.TEAM_ID + "." + AppAttestFixtures.BUNDLE_ID, true);

        AppAttestVerifier permissive = new AppAttestVerifier(
                fixtures.config(EnumSet.allOf(AppAttestEnvironment.class)));
        AppAttestAttestation result = permissive.verifyAttestation(built.cbor(), clientDataHash, built.keyId());

        // Accepted, but the environment is carried through so it is recorded against the instance and a
        // development enrolment can never later be mistaken for a production one.
        assertEquals(AppAttestEnvironment.DEVELOPMENT, result.environment());
    }

    @Test
    void theProductionFactoryDoesNotAcceptDevelopment() {
        AppAttestConfig config = AppAttestConfig.production("ABCDE12345", "com.example.agent");
        assertTrue(config.accepts(AppAttestEnvironment.PRODUCTION));
        assertEquals(false, config.accepts(AppAttestEnvironment.DEVELOPMENT));
        assertEquals("ABCDE12345.com.example.agent", config.appId());
    }

    // ---- malformed input ------------------------------------------------------------------------

    @Test
    void nonCborIsRejectedAsMalformed() {
        AppAttestException e = assertThrows(AppAttestException.class, () -> productionVerifier()
                .verifyAttestation("not cbor at all".getBytes(StandardCharsets.UTF_8), clientDataHash, null));
        assertEquals(AppAttestException.MALFORMED, e.reason());
    }

    @Test
    void anEmptyAttestationIsRejected() {
        assertEquals(AppAttestException.MALFORMED,
                assertThrows(AppAttestException.class,
                        () -> productionVerifier().verifyAttestation(new byte[0], clientDataHash, null)).reason());
    }

    @Test
    void aMissingClientDataHashIsRejected() throws Exception {
        AppAttestFixtures.Attestation built = fixtures.attestation(clientDataHash);
        assertEquals(AppAttestException.MALFORMED,
                assertThrows(AppAttestException.class,
                        () -> productionVerifier().verifyAttestation(built.cbor(), null, null)).reason());
    }

    // ---- malformed attStmt -----------------------------------------------------------------------

    private static final ObjectMapper CBOR = new ObjectMapper(new CBORFactory());

    @Test
    void anAttStmtWithNoX5cIsRejectedAsMalformed() throws Exception {
        ObjectNode root = CBOR.createObjectNode();
        root.put("fmt", "apple-appattest");
        root.putObject("attStmt"); // no x5c at all
        root.put("authData", new byte[64]);

        AppAttestException e = assertThrows(AppAttestException.class, () -> productionVerifier()
                .verifyAttestation(CBOR.writeValueAsBytes(root), clientDataHash, null));
        assertEquals(AppAttestException.MALFORMED, e.reason());
    }

    @Test
    void anAttStmtWithAnEmptyX5cIsRejectedAsMalformed() throws Exception {
        ObjectNode root = CBOR.createObjectNode();
        root.put("fmt", "apple-appattest");
        ObjectNode attStmt = root.putObject("attStmt");
        attStmt.putArray("x5c"); // present, but empty
        root.put("authData", new byte[64]);

        AppAttestException e = assertThrows(AppAttestException.class, () -> productionVerifier()
                .verifyAttestation(CBOR.writeValueAsBytes(root), clientDataHash, null));
        assertEquals(AppAttestException.MALFORMED, e.reason());
    }

    @Test
    void anUnsupportedFormatIsRejected() throws Exception {
        ObjectNode root = CBOR.createObjectNode();
        root.put("fmt", "packed"); // a real WebAuthn format, not App Attest's
        root.putObject("attStmt");
        root.put("authData", new byte[64]);

        AppAttestException e = assertThrows(AppAttestException.class, () -> productionVerifier()
                .verifyAttestation(CBOR.writeValueAsBytes(root), clientDataHash, null));
        assertEquals(AppAttestException.UNSUPPORTED_FORMAT, e.reason());
    }

    // ---- assertions -----------------------------------------------------------------------------

    @Test
    void anAssertionVerifiesAndAdvancesTheCounter() throws Exception {
        AppAttestFixtures.Attestation built = fixtures.attestation(clientDataHash);
        AppAttestAttestation attested =
                productionVerifier().verifyAttestation(built.cbor(), clientDataHash, built.keyId());

        byte[] requestHash = AppAttestFixtures.sha256("request 1".getBytes(StandardCharsets.UTF_8));
        byte[] assertion = fixtures.assertion(built.attestedKey(), requestHash, 1L,
                AppAttestFixtures.TEAM_ID + "." + AppAttestFixtures.BUNDLE_ID);

        long counter = productionVerifier()
                .verifyAssertion(assertion, requestHash, attested.attestedKey(), 0L);
        assertEquals(1L, counter);
    }

    @Test
    void areplayedAssertionCounterIsRejected() throws Exception {
        AppAttestFixtures.Attestation built = fixtures.attestation(clientDataHash);
        AppAttestAttestation attested =
                productionVerifier().verifyAttestation(built.cbor(), clientDataHash, built.keyId());

        byte[] requestHash = AppAttestFixtures.sha256("request".getBytes(StandardCharsets.UTF_8));
        byte[] assertion = fixtures.assertion(built.attestedKey(), requestHash, 5L,
                AppAttestFixtures.TEAM_ID + "." + AppAttestFixtures.BUNDLE_ID);

        // Same counter already seen — a replay.
        AppAttestException e = assertThrows(AppAttestException.class, () -> productionVerifier()
                .verifyAssertion(assertion, requestHash, attested.attestedKey(), 5L));
        assertEquals(AppAttestException.COUNTER_NOT_ADVANCED, e.reason());
    }

    @Test
    void anAssertionOverDifferentClientDataIsRejected() throws Exception {
        AppAttestFixtures.Attestation built = fixtures.attestation(clientDataHash);
        AppAttestAttestation attested =
                productionVerifier().verifyAttestation(built.cbor(), clientDataHash, built.keyId());

        byte[] signedHash = AppAttestFixtures.sha256("what was signed".getBytes(StandardCharsets.UTF_8));
        byte[] checkedHash = AppAttestFixtures.sha256("what we check".getBytes(StandardCharsets.UTF_8));
        byte[] assertion = fixtures.assertion(built.attestedKey(), signedHash, 1L,
                AppAttestFixtures.TEAM_ID + "." + AppAttestFixtures.BUNDLE_ID);

        AppAttestException e = assertThrows(AppAttestException.class, () -> productionVerifier()
                .verifyAssertion(assertion, checkedHash, attested.attestedKey(), 0L));
        assertEquals(AppAttestException.BAD_SIGNATURE, e.reason());
    }

    @Test
    void anAssertionSignedByAnotherKeyIsRejected() throws Exception {
        AppAttestFixtures.Attestation mine = fixtures.attestation(clientDataHash);
        AppAttestFixtures.Attestation theirs = fixtures.attestation(clientDataHash);
        AppAttestAttestation attested =
                productionVerifier().verifyAttestation(mine.cbor(), clientDataHash, mine.keyId());

        byte[] requestHash = AppAttestFixtures.sha256("request".getBytes(StandardCharsets.UTF_8));
        byte[] assertion = fixtures.assertion(theirs.attestedKey(), requestHash, 1L,
                AppAttestFixtures.TEAM_ID + "." + AppAttestFixtures.BUNDLE_ID);

        AppAttestException e = assertThrows(AppAttestException.class, () -> productionVerifier()
                .verifyAssertion(assertion, requestHash, attested.attestedKey(), 0L));
        assertEquals(AppAttestException.BAD_SIGNATURE, e.reason());
    }
}
