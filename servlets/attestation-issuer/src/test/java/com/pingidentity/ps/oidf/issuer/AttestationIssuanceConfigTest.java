package com.pingidentity.ps.oidf.issuer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import com.pingidentity.ps.oidf.conformance.Requirement;
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
    @Requirement("CAS §7")
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

    // ---- archetype (wildcard) matching -------------------------------------------------------------

    @Test
    void aWildcardArchetypeCoversEveryInstanceUnderItsPrefix() throws Exception {
        Map<String, String> props = baseProps();
        props.put(AttestationIssuanceConfig.P_INSTANCES,
                "[{\"spiffe_id\":\"spiffe://banking.demo/agents/*\","
                        + "\"metadata\":{\"archetype\":\"fleet\"}}]");
        AttestationIssuanceConfig config = AttestationIssuanceConfig.fromProperties(props);

        SpiffeBinding replicaOne = config.bindingFor("spiffe://banking.demo/agents/replica-1").orElseThrow();
        SpiffeBinding replicaTwo = config.bindingFor("spiffe://banking.demo/agents/replica-2").orElseThrow();
        assertEquals("fleet", replicaOne.metadata().get("archetype"));
        assertEquals("fleet", replicaTwo.metadata().get("archetype"));
        assertTrue(config.bindingFor("spiffe://banking.demo/other/replica-1").isEmpty());
    }

    @Test
    void anExactEntryIsPreferredOverAnOverlappingWildcardArchetype() throws Exception {
        // A fleet-wide archetype and one instance's own, more specific entry can coexist: the specific
        // entry (e.g. a pinned, elevated ceiling for one particular replica) must win, not the wildcard.
        Map<String, String> props = baseProps();
        props.put(AttestationIssuanceConfig.P_INSTANCES,
                "[{\"spiffe_id\":\"spiffe://banking.demo/agents/*\",\"metadata\":{\"tier\":\"standard\"}},"
                        + "{\"spiffe_id\":\"spiffe://banking.demo/agents/replica-1\",\"metadata\":{\"tier\":\"pinned\"}}]");
        AttestationIssuanceConfig config = AttestationIssuanceConfig.fromProperties(props);

        assertEquals("pinned", config.bindingFor("spiffe://banking.demo/agents/replica-1").orElseThrow()
                .metadata().get("tier"));
        assertEquals("standard", config.bindingFor("spiffe://banking.demo/agents/replica-2").orElseThrow()
                .metadata().get("tier"));
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

    // Ported from pf-oidf-modules (2026-08-15): fromProperties() already guards these, but this repo
    // had no assertion of it before now.
    @Test
    void ttlNotANumberIsRejected() throws Exception {
        Map<String, String> props = baseProps();
        props.put(AttestationIssuanceConfig.P_TTL, "abc");
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> AttestationIssuanceConfig.fromProperties(props));
        assertEquals("invalid_client", e.error());
    }

    @Test
    void nonPositiveTtlIsRejected() throws Exception {
        Map<String, String> props = baseProps();
        props.put(AttestationIssuanceConfig.P_TTL, "-5");
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> AttestationIssuanceConfig.fromProperties(props));
        assertEquals("invalid_client", e.error());
    }

    @Test
    void bundleUrlAloneIsAnAcceptedBundleSource() throws Exception {
        Map<String, String> props = baseProps();
        props.remove(AttestationIssuanceConfig.P_BUNDLE);
        props.put(AttestationIssuanceConfig.P_BUNDLE_URL, "https://cluster.example/jwks");
        AttestationIssuanceConfig config = AttestationIssuanceConfig.fromProperties(props);
        assertEquals("https://cluster.example/jwks", config.bundleUrl());
        assertTrue(config.bundleKeys().isEmpty());
        assertEquals(AttestationIssuanceConfig.EVIDENCE_SPIFFE_JWT, config.evidenceType());
    }

    @Test
    void gkeEvidenceRequiresATrustDomain() throws Exception {
        Map<String, String> props = baseProps();
        props.put(AttestationIssuanceConfig.P_EVIDENCE, AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> AttestationIssuanceConfig.fromProperties(props));
        assertEquals("invalid_client", e.error());

        props.put(AttestationIssuanceConfig.P_TRUST_DOMAIN, "demo-project.svc.id.goog");
        props.put(AttestationIssuanceConfig.P_EVIDENCE_ISSUER,
                "https://container.googleapis.com/v1/projects/demo-project/locations/us-central1-a/clusters/spiffe-demo");
        AttestationIssuanceConfig config = AttestationIssuanceConfig.fromProperties(props);
        assertEquals(AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN, config.evidenceType());
        assertEquals("demo-project.svc.id.goog", config.expectedTrustDomain());
        assertTrue(config.evidenceIssuer().startsWith("https://container.googleapis.com/"));
    }

    @Test
    void unknownEvidenceTypeIsRejected() throws Exception {
        Map<String, String> props = baseProps();
        props.put(AttestationIssuanceConfig.P_EVIDENCE, "x509-svid");
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> AttestationIssuanceConfig.fromProperties(props));
        assertEquals("invalid_client", e.error());
    }

    @Test
    @Requirement("CAS §6.1")
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

    // ---- S1b: both ceilings held to the containment model; an instance's kept as authorized (F-0034) ----------

    private static final com.pingidentity.ps.oidf.rar.model.RarModels MODELS =
            com.pingidentity.ps.oidf.rar.model.RarModels.builtIn();

    /**
     * CAS §7: "instances[i].entitlement ⊆ entitlement MUST hold at registration time". The instance ceiling is
     * {@code authorize(instance, client, INHERIT)} and the result is what the binding keeps: a field the client's
     * ceiling constrains and the instance's leaves out is the client's. This used to check the instance's and keep
     * it as written, so an instance that left out {@code max_txn_eur} was unconstrained on it however the client
     * was constrained - wider than its client (the plan's "Found while designing" item 5, F-0034).
     */
    @Test
    @Requirement({"CAS §7", "CAS §6.1"})
    void anInstanceCeilingKeepsWhatTheClientsConstrainsAndItLeavesOut() throws Exception {
        Map<String, String> props = baseProps();
        props.put(AttestationIssuanceConfig.P_ENTITLEMENT,
                "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\",\"APAC\"],\"max_txn_eur\":5000}]");
        props.put(AttestationIssuanceConfig.P_INSTANCES,
                "[{\"spiffe_id\":\"" + ID_EMEA + "\",\"entitlement\":[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]}]");

        SpiffeBinding emea = AttestationIssuanceConfig.fromProperties(props, MODELS).bindingFor(ID_EMEA).orElseThrow();

        assertEquals(1, emea.entitlement().size());
        assertEquals(java.util.List.of("EMEA"), emea.entitlement().get(0).get("sales_regions"));
        assertEquals(0, new java.math.BigDecimal("5000").compareTo((java.math.BigDecimal) emea.entitlement().get(0).get("max_txn_eur")),
                "the client's limit is the instance's too, where the instance says nothing");
    }

    /** Blocker B1 at registration: a scalar above the client's is refused, not waved through with the arrays. */
    @Test
    @Requirement({"CAS §7", "CAS §6.1"})
    void anInstanceLimitAboveTheClientsIsRefused() throws Exception {
        Map<String, String> props = baseProps();
        props.put(AttestationIssuanceConfig.P_ENTITLEMENT,
                "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":5000}]");
        props.put(AttestationIssuanceConfig.P_INSTANCES, "[{\"spiffe_id\":\"" + ID_EMEA + "\",\"entitlement\":"
                + "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":5000.01}]}]");

        IssuanceException e = assertThrows(IssuanceException.class, () -> AttestationIssuanceConfig.fromProperties(props, MODELS));

        assertEquals("invalid_client", e.error());
        assertTrue(e.getMessage().contains("exceeds the client-level ceiling"), e.getMessage());
    }

    @Test
    void aCeilingTheModelRefusesMakesTheConfigurationInvalid() throws Exception {
        Map<String, String> clientBad = baseProps();
        clientBad.put(AttestationIssuanceConfig.P_ENTITLEMENT, "[{\"type\":\"no-such-type\"}]");
        IssuanceException client = assertThrows(IssuanceException.class,
                () -> AttestationIssuanceConfig.fromProperties(clientBad, MODELS));
        assertEquals("invalid_client", client.error());
        assertTrue(client.getMessage().startsWith(AttestationIssuanceConfig.P_ENTITLEMENT
                + " is not a valid authorization_details array: "), client.getMessage());

        Map<String, String> instanceBad = baseProps();
        instanceBad.put(AttestationIssuanceConfig.P_INSTANCES, "[{\"spiffe_id\":\"" + ID_EMEA + "\",\"entitlement\":"
                + "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"colour\":\"red\"}]}]");
        IssuanceException instance = assertThrows(IssuanceException.class,
                () -> AttestationIssuanceConfig.fromProperties(instanceBad, MODELS));
        assertEquals("invalid_client", instance.error());
        assertTrue(instance.getMessage().contains("entitlement is not a valid authorization_details array"),
                instance.getMessage());

        Map<String, String> notJson = baseProps();
        notJson.put(AttestationIssuanceConfig.P_INSTANCES, "[{\"spiffe_id\":");
        assertEquals("invalid_client", assertThrows(IssuanceException.class,
                () -> AttestationIssuanceConfig.fromProperties(notJson, MODELS)).error());
    }

    /**
     * CAS §6.1: an instance's entitlement "MUST be a subset of the client-level entitlement when both are present",
     * and the client-level one is "OPTIONAL". With none, the instance's is held to the model and kept as written.
     */
    @Test
    @Requirement("CAS §6.1")
    void withNoClientCeilingAnInstanceCeilingIsHeldToTheModelAndKeptAsWritten() throws Exception {
        Map<String, String> props = baseProps();
        props.remove(AttestationIssuanceConfig.P_ENTITLEMENT);
        props.put(AttestationIssuanceConfig.P_INSTANCES,
                "[{\"spiffe_id\":\"" + ID_EMEA + "\",\"entitlement\":[{\"type\":\"sales_agent\",\"sales_regions\":[\"LATAM\"]}]}]");
        assertEquals(java.util.List.of("LATAM"), AttestationIssuanceConfig.fromProperties(props, MODELS)
                .bindingFor(ID_EMEA).orElseThrow().entitlement().get(0).get("sales_regions"));

        props.put(AttestationIssuanceConfig.P_INSTANCES,
                "[{\"spiffe_id\":\"" + ID_EMEA + "\",\"entitlement\":[{\"type\":\"no-such-type\"}]}]");
        assertEquals("invalid_client", assertThrows(IssuanceException.class,
                () -> AttestationIssuanceConfig.fromProperties(props, MODELS)).error());
    }

    /** Read by the model's reader: a limit is kept exactly as configured, not as the nearest double. */
    @Test
    void aConfiguredLimitIsKeptExactly() throws Exception {
        Map<String, String> props = baseProps();
        props.put(AttestationIssuanceConfig.P_ENTITLEMENT,
                "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":12345678901234567.5}]");

        AttestationIssuanceConfig config = AttestationIssuanceConfig.fromProperties(props, MODELS);

        assertEquals(new java.math.BigDecimal("12345678901234567.5"), config.clientCeiling().get(0).get("max_txn_eur"));
    }

    /** The one-argument parse takes this classloader's models, and says so when they could not be loaded. */
    @Test
    void theClassloadersModelsAreUsedAndTheirFailureIsAServerError() throws Exception {
        java.lang.reflect.Method reset = com.pingidentity.ps.oidf.clientattestation.AttestationRarModels.class
                .getDeclaredMethod("resetForTest", Map.class);
        reset.setAccessible(true);
        try {
            reset.invoke(null, Map.of(com.pingidentity.ps.oidf.rar.model.RarModels.ENV_MODELS, "{\"types\":"));
            IssuanceException e = assertThrows(IssuanceException.class,
                    () -> AttestationIssuanceConfig.fromProperties(baseProps()));
            assertEquals("server_error", e.error());

            reset.invoke(null, Map.of());
            assertEquals(ISSUER, AttestationIssuanceConfig.fromProperties(baseProps()).issuer());
        } finally {
            reset.invoke(null, (Object) null);
        }
    }
}
