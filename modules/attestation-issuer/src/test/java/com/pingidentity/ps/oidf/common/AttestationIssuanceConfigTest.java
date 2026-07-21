package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.junit.jupiter.api.Test;

class AttestationIssuanceConfigTest {
    private static final String ISSUER = "https://attester.example.com";
    private static final String ID_EMEA = "spiffe://banking.demo/payment-agent";
    private static final String ID_BARE = "spiffe://banking.demo/reporting-agent";

    private Map<String, String> baseProps() throws Exception {
        JsonWebKey pub = JsonWebKey.Factory.newJwk(TestJwts.publicParams(TestJwts.ec("svid-key-1")));
        String bundle = new JsonWebKeySet(pub).toJson();
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ISSUER);
        props.put(AttestationIssuanceConfig.P_BUNDLE, bundle);
        props.put(AttestationIssuanceConfig.P_ENTITLEMENT,
                "[{\"type\":\"sales_agent\",\"actions\":[\"read_accounts\",\"create_opportunity\"],"
                        + "\"sales_regions\":[\"EMEA\",\"APAC\"]}]");
        props.put(AttestationIssuanceConfig.P_INSTANCES,
                "[{\"spiffe_id\":\"" + ID_EMEA + "\","
                        + "\"entitlement\":[{\"type\":\"sales_agent\",\"actions\":[\"read_accounts\"],\"sales_regions\":[\"EMEA\"]}],"
                        + "\"metadata\":{\"region\":\"EMEA\",\"environment\":\"prod\"}},"
                        + "{\"spiffe_id\":\"" + ID_BARE + "\"}]");
        return props;
    }

    @Test
    void parsesBindingsMetadataAndEntitlement() throws Exception {
        AttestationIssuanceConfig config = AttestationIssuanceConfig.fromProperties(baseProps());
        assertEquals(ISSUER, config.issuer());
        assertEquals(300L, config.ttlSeconds());
        assertEquals(2, config.bindings().size());

        SpiffeBinding emea = config.bindingFor(ID_EMEA).orElseThrow();
        assertEquals("EMEA", emea.metadata().get("region"));
        assertEquals("sales_agent", emea.entitlement().get(0).get("type"));

        // Per-instance entitlement is the effective ceiling for that instance.
        assertEquals(emea.entitlement(), config.effectiveCeiling(emea));
        // A bare binding defers to the client-level ceiling.
        SpiffeBinding bare = config.bindingFor(ID_BARE).orElseThrow();
        assertTrue(bare.entitlement().isEmpty());
        assertEquals(config.clientCeiling(), config.effectiveCeiling(bare));
    }

    @Test
    void unknownSpiffeIdHasNoBinding() throws Exception {
        AttestationIssuanceConfig config = AttestationIssuanceConfig.fromProperties(baseProps());
        assertTrue(config.bindingFor("spiffe://banking.demo/nope").isEmpty());
    }

    @Test
    void missingIssuerIsRejected() throws Exception {
        Map<String, String> props = baseProps();
        props.remove(AttestationIssuanceConfig.P_ISSUER);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> AttestationIssuanceConfig.fromProperties(props));
        assertEquals("invalid_client", e.error());
    }

    @Test
    void missingBundleIsRejected() throws Exception {
        Map<String, String> props = baseProps();
        props.remove(AttestationIssuanceConfig.P_BUNDLE);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> AttestationIssuanceConfig.fromProperties(props));
        assertEquals("invalid_client", e.error());
    }

    @Test
    void instanceEntitlementExceedingClientCeilingIsRejected() throws Exception {
        Map<String, String> props = baseProps();
        // sales_regions LATAM is not within the client ceiling {EMEA, APAC}.
        props.put(AttestationIssuanceConfig.P_INSTANCES,
                "[{\"spiffe_id\":\"" + ID_EMEA + "\","
                        + "\"entitlement\":[{\"type\":\"sales_agent\",\"sales_regions\":[\"LATAM\"]}]}]");
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> AttestationIssuanceConfig.fromProperties(props));
        assertEquals("invalid_client", e.error());
    }
}
