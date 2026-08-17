/*
 * In-process self-verification for the Attestation Issuance endpoint (/federation/attestation).
 *
 * Ported from pf-oidf-modules (2026-08-18) when that repo was reduced to the demo UI + shell probes.
 * Imports updated for the unwound package layout (...oidf.common -> ...oidf.issuer / ...oidf.clientattestation
 * / ...oidf.jose); every method signature it calls was checked against the current classes first — no
 * other change was needed.
 *
 *   issuance-selfverify
 *       Runs the issuance flow in-process (no network, no PF) using the module's REAL public building
 *       blocks — SpiffeSvidValidator, AttestationIssuanceConfig, InstanceKeyProofValidator,
 *       AttesterSigningKey, AttestationMinter — exactly as AttestationIssuanceServlet orchestrates them,
 *       then proves the minted attestation verifies through the module's own ClientAttestationVerifier.
 *
 *   Asserts: (1) a valid SVID + instance proof yields an attestation that round-trips through the
 *   verifier; (2) an SVID whose SPIFFE ID is not bound to the client is refused; (3) an instance proof
 *   signed by the wrong key is refused.
 *
 * Classpath: jose4j + attestation-issuer + client-attestation. See services/harness/README.md.
 */
package com.pingidentity.ps.oidf.harness;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;

import com.pingidentity.ps.oidf.issuer.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.issuer.AttestationMinter;
import com.pingidentity.ps.oidf.clientattestation.AttesterKeyResolver;
import com.pingidentity.ps.oidf.issuer.AttesterSigningKey;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationResult;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationVerifier;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationChallengeService;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.issuer.InstanceKeyProofValidator;
import com.pingidentity.ps.oidf.issuer.IssuanceException;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.issuer.SpiffeBinding;
import com.pingidentity.ps.oidf.issuer.SpiffeSvid;
import com.pingidentity.ps.oidf.issuer.SpiffeSvidValidator;
import com.pingidentity.ps.oidf.clientattestation.StaticAttesterKeyResolver;

public final class AttestationIssuanceHarness {
    private static final String ISSUER = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com";
    private static final String OP_ISSUER = "https://op.example.com";
    private static final String TOKEN_ENDPOINT = OP_ISSUER + "/as/token.oauth2";
    private static final String SPIFFE_ID = "spiffe://banking.demo/payment-agent";

    private static PublicJsonWebKey bundleKey;
    private static PublicJsonWebKey attesterKey;
    private static PublicJsonWebKey instanceKey;
    private static AttestationIssuanceConfig config;
    private static int checks;

    public static void main(String[] args) throws Exception {
        bundleKey = ec("svid-key-1");
        attesterKey = ec("attester-1");
        instanceKey = ec("instance-1");
        config = buildConfig();

        System.out.println("== Attestation Issuance self-verify ==");
        happyPathRoundTrips();
        unauthorizedSpiffeIdRefused();
        tamperedProofRefused();
        System.out.println("\nALL " + checks + " CHECKS PASSED");
    }

    /** A valid SVID + instance proof -> a minted attestation that verifies through ClientAttestationVerifier. */
    private static void happyPathRoundTrips() throws Exception {
        String attestation = issue(SPIFFE_ID, ISSUER, proof(instanceKey, UUID.randomUUID().toString()));
        verify(attestation);
        pass("happy path: SVID -> attestation minted and verified end-to-end");
    }

    private static void unauthorizedSpiffeIdRefused() throws Exception {
        SpiffeSvidValidator validator = new SpiffeSvidValidator();
        SpiffeSvid svid = validator.validate(
                svid(bundleKey, "spiffe://banking.demo/stranger", ISSUER, 600L),
                config.bundleKeys(), config.issuer(), null);
        if (config.bindingFor(svid.spiffeId()).isEmpty()) {
            pass("unauthorized SPIFFE ID has no binding -> refused (spiffe_id_not_authorized)");
        } else {
            fail("an unregistered SPIFFE ID was accepted");
        }
    }

    private static void tamperedProofRefused() throws Exception {
        PublicJsonWebKey attacker = ec("attacker-1");
        try {
            new InstanceKeyProofValidator().validate(
                    proof(attacker, UUID.randomUUID().toString()), publicParams(instanceKey), ISSUER);
            fail("a proof signed by the wrong key was accepted");
        } catch (IssuanceException e) {
            if ("invalid_instance_proof".equals(e.error())) {
                pass("instance proof signed by the wrong key -> refused (invalid_instance_proof)");
            } else {
                fail("unexpected error for tampered proof: " + e.error());
            }
        }
    }

    // ---- the servlet flow, via public building blocks --------------------------------------------

    private static String issue(String spiffeId, String svidAudience, String proofJwt) throws Exception {
        SpiffeSvid svid = new SpiffeSvidValidator().validate(
                svid(bundleKey, spiffeId, svidAudience, 600L), config.bundleKeys(), config.issuer(), null);
        SpiffeBinding binding = config.bindingFor(svid.spiffeId()).orElseThrow(
                () -> IssuanceException.spiffeIdNotAuthorized(svid.spiffeId()));
        InstanceKeyProofValidator.Result proof =
                new InstanceKeyProofValidator().validate(proofJwt, publicParams(instanceKey), config.issuer());
        // (challenge/replay omitted here — exercised by the JUnit servlet test)
        JwsSigner signer = new AttesterSigningKey(null, null).signerFor(config.signingKeyRef(), config.signingJwk());
        return AttestationMinter.mint(config.issuer(), CLIENT_ID, publicParams(instanceKey), svid,
                binding.metadata(), config.effectiveCeiling(binding), config.ttlSeconds(), signer);
    }

    private static void verify(String attestation) throws Exception {
        JsonWebKey attesterPub = JsonWebKey.Factory.newJwk(publicParams(attesterKey));
        AttesterKeyResolver resolver = new StaticAttesterKeyResolver(Map.of(ISSUER, List.of(attesterPub)));
        ClientAttestationConfig cfg = ClientAttestationConfig.builder()
                .addAcceptedAudience(OP_ISSUER)
                .expectedHtu(TOKEN_ENDPOINT)
                .build();
        ClientAttestationVerifier verifier = new ClientAttestationVerifier(
                resolver, cfg, new InMemoryAttestationReplayCache(), new InMemoryAttestationChallengeService());
        JwtClaims pop = new JwtClaims();
        pop.setIssuer(CLIENT_ID);
        pop.setAudience(OP_ISSUER);
        pop.setJwtId("pop-" + UUID.randomUUID());
        pop.setIssuedAtToNow();
        String popJwt = sign(instanceKey, "oauth-client-attestation-pop+jwt", pop);
        ClientAttestationResult result = verifier.verify(attestation, popJwt, null, "POST", TOKEN_ENDPOINT, CLIENT_ID);
        if (!CLIENT_ID.equals(result.clientId()) || !ISSUER.equals(result.attesterIssuer())) {
            fail("verifier did not confirm the expected client/attester");
        }
    }

    private static AttestationIssuanceConfig buildConfig() throws Exception {
        String bundle = new JsonWebKeySet(JsonWebKey.Factory.newJwk(publicParams(bundleKey))).toJson();
        java.util.HashMap<String, String> props = new java.util.HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ISSUER);
        props.put(AttestationIssuanceConfig.P_BUNDLE, bundle);
        props.put(AttestationIssuanceConfig.P_SIGNING_JWK, JsonUtil.toJson(privateParams(attesterKey)));
        props.put(AttestationIssuanceConfig.P_INSTANCES,
                "[{\"spiffe_id\":\"" + SPIFFE_ID + "\","
                        + "\"entitlement\":[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}],"
                        + "\"metadata\":{\"region\":\"EMEA\"}}]");
        return AttestationIssuanceConfig.fromProperties(props);
    }

    // ---- jose helpers ----------------------------------------------------------------------------

    private static PublicJsonWebKey ec(String kid) throws Exception {
        PublicJsonWebKey jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        jwk.setKeyId(kid);
        return jwk;
    }

    private static Map<String, Object> publicParams(JsonWebKey jwk) {
        return jwk.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
    }

    private static Map<String, Object> privateParams(JsonWebKey jwk) {
        return jwk.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
    }

    private static String svid(PublicJsonWebKey signingKey, String sub, String audience, long expOffset)
            throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setSubject(sub);
        claims.setAudience(audience);
        claims.setIssuedAtToNow();
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + expOffset));
        return sign(signingKey, "JWT", claims);
    }

    private static String proof(PublicJsonWebKey signingKey, String jti) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setAudience(ISSUER);
        claims.setJwtId(jti);
        claims.setIssuedAtToNow();
        return sign(signingKey, InstanceKeyProofValidator.TYP, claims);
    }

    private static String sign(PublicJsonWebKey signingKey, String typ, JwtClaims claims) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(signingKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", typ);
        if (signingKey.getKeyId() != null) {
            jws.setKeyIdHeaderValue(signingKey.getKeyId());
        }
        return jws.getCompactSerialization();
    }

    private static void pass(String message) {
        checks++;
        System.out.println("  ✓ " + message);
    }

    private static void fail(String message) {
        throw new AssertionError("FAILED: " + message);
    }
}
