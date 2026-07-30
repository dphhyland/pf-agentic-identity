package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.Test;

/**
 * The registry is the single source of truth for what evidence types exist and what each requires. These
 * tests pin that contract — in particular that adding a type needs no edit anywhere else.
 */
class InstanceAttestationValidatorsTest {

    /** A throwaway evidence type, registered only by this test. */
    private static final class FakeDeviceValidator implements InstanceAttestationValidator {
        @Override
        public String id() {
            return "test-device-attestation";
        }

        @Override
        public String format() {
            return "device";
        }

        @Override
        public boolean requiresTrustDomain() {
            return true;
        }

        @Override
        public boolean requiresTrustBundle() {
            return false;
        }

        @Override
        public String title() {
            return "Test device attestation";
        }

        @Override
        public String description() {
            return "A stand-in device attestation used to prove the registry is pluggable.";
        }

        @Override
        public InstanceIdentity validate(String presented, List<JsonWebKey> bundleKeys,
                                         AttestationIssuanceConfig config) {
            return new InstanceIdentity("device", "device:" + presented, "test.device",
                    Map.of("kty", "EC"), Map.of("device_id", presented), 0L);
        }
    }

    @Test
    void defaultsCarryEveryBuiltInEvidenceType() {
        List<String> ids = InstanceAttestationValidators.defaults().ids();
        assertTrue(ids.containsAll(List.of(
                AttestationIssuanceConfig.EVIDENCE_SPIFFE_JWT,
                AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN,
                AttestationIssuanceConfig.EVIDENCE_GCP_ID_TOKEN,
                AttestationIssuanceConfig.EVIDENCE_EKS_SA_TOKEN,
                AttestationIssuanceConfig.EVIDENCE_AWS_STS_WEB_IDENTITY,
                AttestationIssuanceConfig.EVIDENCE_WALLET_INSTANCE_ATTESTATION)));
    }

    @Test
    void theCloudTypesShareTheSpiffeFormatFamily() {
        InstanceAttestationValidators registry = InstanceAttestationValidators.defaults();
        assertEquals(List.of("spiffe", "wallet"), registry.formats());
        assertEquals(List.of(
                        AttestationIssuanceConfig.EVIDENCE_SPIFFE_JWT,
                        AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN,
                        AttestationIssuanceConfig.EVIDENCE_GCP_ID_TOKEN,
                        AttestationIssuanceConfig.EVIDENCE_EKS_SA_TOKEN,
                        AttestationIssuanceConfig.EVIDENCE_AWS_STS_WEB_IDENTITY),
                registry.idsForFormat("spiffe"));
    }

    @Test
    void eachTypeDeclaresWhetherItNeedsATrustDomainAndBundle() {
        InstanceAttestationValidators r = InstanceAttestationValidators.defaults();
        // SPIFFE carries its own trust domain in the SVID.
        assertFalse(r.requiresTrustDomain(AttestationIssuanceConfig.EVIDENCE_SPIFFE_JWT));
        assertTrue(r.requiresTrustBundle(AttestationIssuanceConfig.EVIDENCE_SPIFFE_JWT));
        // The cloud types synthesise or namespace a SPIFFE ID, so they need one.
        assertTrue(r.requiresTrustDomain(AttestationIssuanceConfig.EVIDENCE_AWS_STS_WEB_IDENTITY));
        assertTrue(r.requiresTrustDomain(AttestationIssuanceConfig.EVIDENCE_GCP_ID_TOKEN));
        // A wallet trusts its provider, not a SPIFFE bundle.
        assertFalse(r.requiresTrustBundle(AttestationIssuanceConfig.EVIDENCE_WALLET_INSTANCE_ATTESTATION));
    }

    @Test
    void unknownTypeIsUnsupportedAndRejectedAsAClientFault() {
        InstanceAttestationValidators r = InstanceAttestationValidators.defaults();
        assertFalse(r.supports("no-such-evidence"));
        assertTrue(r.find("no-such-evidence").isEmpty());
        IssuanceException e = assertThrows(IssuanceException.class, () -> r.require("no-such-evidence"));
        assertEquals("invalid_client", e.error());
        // Conservative default: an unknown type is assumed to need a bundle.
        assertTrue(r.requiresTrustBundle("no-such-evidence"));
    }

    @Test
    void duplicateIdsAreAConfigurationError() {
        assertThrows(IllegalArgumentException.class, () -> new InstanceAttestationValidators(
                List.of(new SpiffeInstanceAttestationValidator(), new SpiffeInstanceAttestationValidator())));
    }

    @Test
    void withReplacesAnEntryOfTheSameIdRatherThanDuplicatingIt() {
        InstanceAttestationValidators base = InstanceAttestationValidators.defaults();
        int before = base.ids().size();
        AttesterKeyResolver resolver = (issuer, chain) -> List.of();
        InstanceAttestationValidators wired = base.with(new WalletInstanceAttestationValidator(resolver));
        assertEquals(before, wired.ids().size());
        assertTrue(wired.supports(AttestationIssuanceConfig.EVIDENCE_WALLET_INSTANCE_ATTESTATION));
    }

    @Test
    void sniffReadsTheFormatFamilyFromAnUnverifiedToken() throws Exception {
        // A spiffe:// subject marks a SPIFFE SVID.
        JwtClaims spiffe = new JwtClaims();
        spiffe.setSubject("spiffe://gke.demo/ns/demo/sa/agent");
        spiffe.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 300));
        assertEquals("spiffe",
                InstanceAttestationValidators.sniff(TestJwts.sign(TestJwts.ec("k"), "ES256", null, spiffe)));

        // A WIA typ marks a wallet attestation.
        JwtClaims wia = new JwtClaims();
        wia.setSubject("urn:wallet:instance:1");
        wia.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 300));
        assertEquals("wallet", InstanceAttestationValidators.sniff(
                TestJwts.sign(TestJwts.ec("k"), "ES256", "wallet-instance-attestation+jwt", wia)));

        // So does a cnf claim, absent a recognised typ.
        JwtClaims cnf = new JwtClaims();
        cnf.setSubject("urn:wallet:instance:2");
        cnf.setClaim("cnf", Map.of("jwk", Map.of("kty", "EC")));
        cnf.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 300));
        assertEquals("wallet",
                InstanceAttestationValidators.sniff(TestJwts.sign(TestJwts.ec("k"), "ES256", null, cnf)));
    }

    @Test
    void sniffFallsBackToSpiffeForAnythingUnreadable() {
        assertEquals("spiffe", InstanceAttestationValidators.sniff(null));
        assertEquals("spiffe", InstanceAttestationValidators.sniff(""));
        assertEquals("spiffe", InstanceAttestationValidators.sniff("not.a.jwt"));
    }

    /**
     * The point of the exercise: a brand-new evidence type is recognised, dispatchable and advertised purely
     * by registering it — no whitelist, no dispatch switch, no discovery list to edit.
     */
    @Test
    void registeringANewTypeMakesItSupportedDispatchableAndAdvertised() throws Exception {
        InstanceAttestationValidators registry =
                InstanceAttestationValidators.defaults().with(new FakeDeviceValidator());

        assertTrue(registry.supports("test-device-attestation"));
        assertTrue(registry.ids().contains("test-device-attestation"));
        assertTrue(registry.formats().contains("device"));
        assertTrue(registry.requiresTrustDomain("test-device-attestation"));
        assertFalse(registry.requiresTrustBundle("test-device-attestation"));

        // It dispatches, and its identity flows through with its own format and bound key.
        InstanceIdentity id = registry.require("test-device-attestation").validate("abc", List.of(), null);
        assertEquals("device", id.format());
        assertEquals("device:abc", id.subject());
        assertEquals("abc", id.workloadClaims().get("device_id"));

        // And it is self-described in the discovery catalogue.
        Map<String, Object> descriptor = registry.supported().stream()
                .filter(m -> "test-device-attestation".equals(m.get("id")))
                .findFirst()
                .orElseThrow();
        assertEquals("device", descriptor.get("format"));
        assertEquals("Test device attestation", descriptor.get("title"));
        assertEquals(Boolean.TRUE, descriptor.get("requires_trust_domain"));
    }
}
