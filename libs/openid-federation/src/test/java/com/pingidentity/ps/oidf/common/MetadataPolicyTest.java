package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Metadata policy composition and application.
 *
 * <p>The tests that matter are the ones asserting a policy can only ever narrow: a bug that widens
 * scope here hands a subordinate capabilities its superior withheld, and would do so silently.
 */
class MetadataPolicyTest {

    private static MetadataPolicy policy(Map<String, Object> raw) throws Exception {
        return MetadataPolicy.parse(raw, null);
    }

    // ---- the milestone acceptance: narrowing at the parent reduces what a subordinate obtains ----

    @Test
    void narrowingAtTheParentMeasurablyReducesWhatASubordinateObtains() throws Exception {
        Map<String, Object> subordinateMetadata = Map.of(
                "grant_types", List.of("authorization_code", "client_credentials", "implicit"));

        // Permissive parent: everything the subordinate asks for survives.
        MetadataPolicy permissive = policy(Map.of("grant_types", Map.of(
                "subset_of", List.of("authorization_code", "client_credentials", "implicit"))));
        assertEquals(List.of("authorization_code", "client_credentials", "implicit"),
                permissive.apply(subordinateMetadata).get("grant_types"));

        // The parent narrows. Nothing about the subordinate changed.
        MetadataPolicy narrowed = policy(Map.of("grant_types", Map.of(
                "subset_of", List.of("authorization_code"))));
        assertEquals(List.of("authorization_code"),
                narrowed.apply(subordinateMetadata).get("grant_types"));
    }

    @Test
    void aSubordinateCannotWidenASupersetOfItsSuperior() throws Exception {
        MetadataPolicy superior = policy(Map.of("grant_types", Map.of(
                "subset_of", List.of("authorization_code"))));
        MetadataPolicy subordinate = policy(Map.of("grant_types", Map.of(
                "subset_of", List.of("authorization_code", "client_credentials"))));

        // Composition intersects, so the subordinate's extra grant type does not survive.
        MetadataPolicy composed = superior.composeWith(subordinate);
        assertEquals(List.of("authorization_code"),
                composed.operatorsFor("grant_types").get("subset_of"));

        assertEquals(List.of("authorization_code"), composed.apply(Map.of(
                "grant_types", List.of("authorization_code", "client_credentials"))).get("grant_types"));
    }

    @Test
    void aSubordinateMayNarrowFurther() throws Exception {
        MetadataPolicy superior = policy(Map.of("grant_types", Map.of(
                "subset_of", List.of("authorization_code", "client_credentials"))));
        MetadataPolicy subordinate = policy(Map.of("grant_types", Map.of(
                "subset_of", List.of("authorization_code"))));

        assertEquals(List.of("authorization_code"),
                superior.composeWith(subordinate).operatorsFor("grant_types").get("subset_of"));
    }

    @Test
    void aSubordinateAddThatIntroducesNewValuesIsRefused() throws Exception {
        MetadataPolicy superior = policy(Map.of("grant_types", Map.of("add", List.of("refresh_token"))));
        MetadataPolicy subordinate = policy(Map.of("grant_types", Map.of(
                "add", List.of("refresh_token", "implicit"))));

        MetadataPolicy.PolicyException e = assertThrows(MetadataPolicy.PolicyException.class,
                () -> superior.composeWith(subordinate));
        assertTrue(e.getMessage().contains("cannot widen"), e.getMessage());
        assertTrue(e.getMessage().contains("implicit"), e.getMessage());
    }

    @Test
    void anEssentialParameterCannotBeMadeOptionalBySubordinate() throws Exception {
        MetadataPolicy superior = policy(Map.of("contacts", Map.of("essential", true)));
        MetadataPolicy subordinate = policy(Map.of("contacts", Map.of("essential", false)));
        assertEquals(Boolean.TRUE,
                superior.composeWith(subordinate).operatorsFor("contacts").get("essential"));
    }

    // ---- failing closed ----------------------------------------------------------------------------

    @Test
    void disjointRestrictionsAreRefusedRatherThanResolvingToNothing() throws Exception {
        MetadataPolicy superior = policy(Map.of("token_endpoint_auth_method", Map.of(
                "one_of", List.of("private_key_jwt"))));
        MetadataPolicy subordinate = policy(Map.of("token_endpoint_auth_method", Map.of(
                "one_of", List.of("client_secret_basic"))));

        // An empty intersection could be read as "no restriction" by a careless implementation.
        MetadataPolicy.PolicyException e = assertThrows(MetadataPolicy.PolicyException.class,
                () -> superior.composeWith(subordinate));
        assertTrue(e.getMessage().contains("do not overlap"), e.getMessage());
    }

    @Test
    void conflictingFixedValuesAreRefused() throws Exception {
        MetadataPolicy superior = policy(Map.of("issuer", Map.of("value", "https://a.example")));
        MetadataPolicy subordinate = policy(Map.of("issuer", Map.of("value", "https://b.example")));
        assertThrows(MetadataPolicy.PolicyException.class, () -> superior.composeWith(subordinate));
    }

    @Test
    void metadataViolatingOneOfIsRefusedRatherThanPassedThrough() throws Exception {
        MetadataPolicy p = policy(Map.of("token_endpoint_auth_method", Map.of(
                "one_of", List.of("private_key_jwt", "attest_jwt_client_auth"))));

        MetadataPolicy.PolicyException e = assertThrows(MetadataPolicy.PolicyException.class,
                () -> p.apply(Map.of("token_endpoint_auth_method", "client_secret_basic")));
        assertTrue(e.getMessage().contains("not one_of"), e.getMessage());
    }

    @Test
    void metadataMissingASupersetRequirementIsRefused() throws Exception {
        MetadataPolicy p = policy(Map.of("grant_types", Map.of(
                "superset_of", List.of("authorization_code", "refresh_token"))));
        assertThrows(MetadataPolicy.PolicyException.class,
                () -> p.apply(Map.of("grant_types", List.of("authorization_code"))));
    }

    @Test
    void anEssentialParameterMissingFromMetadataIsRefused() throws Exception {
        MetadataPolicy p = policy(Map.of("jwks_uri", Map.of("essential", true)));
        assertThrows(MetadataPolicy.PolicyException.class, () -> p.apply(Map.of()));
    }

    @Test
    void aSubsetThatRemovesEveryValueIsRefused() throws Exception {
        MetadataPolicy p = policy(Map.of("grant_types", Map.of("subset_of", List.of("device_code"))));
        // Leaving an empty array behind would read as "unrestricted" to a naive consumer.
        assertThrows(MetadataPolicy.PolicyException.class,
                () -> p.apply(Map.of("grant_types", List.of("authorization_code"))));
    }

    // ---- application semantics ----------------------------------------------------------------------

    @Test
    void valueOverridesWhateverTheSubordinateDeclared() throws Exception {
        MetadataPolicy p = policy(Map.of("token_endpoint_auth_method", Map.of(
                "value", "attest_jwt_client_auth")));
        assertEquals("attest_jwt_client_auth",
                p.apply(Map.of("token_endpoint_auth_method", "client_secret_basic"))
                        .get("token_endpoint_auth_method"));
    }

    @Test
    void defaultOnlyFillsAnAbsentParameter() throws Exception {
        MetadataPolicy p = policy(Map.of("scope", Map.of("default", "openid")));
        assertEquals("openid", p.apply(Map.of()).get("scope"));
        assertEquals("profile", p.apply(Map.of("scope", "profile")).get("scope"));
    }

    @Test
    void subsetOfKeepsOnlyThePermittedValues() throws Exception {
        MetadataPolicy p = policy(Map.of("grant_types", Map.of(
                "subset_of", List.of("authorization_code", "refresh_token"))));
        assertEquals(List.of("authorization_code"), p.apply(Map.of(
                "grant_types", List.of("authorization_code", "implicit"))).get("grant_types"));
    }

    /**
     * The application order is normative and counter-intuitive: {@code add} runs near the end, after
     * {@code subset_of}. Running it earlier would let an added value be silently removed by the subset
     * check — or, worse in a different ordering, let one escape it.
     */
    @Test
    void addIsAppliedAfterSubsetOfPerTheSpecifiedOrder() throws Exception {
        MetadataPolicy p = policy(Map.of("grant_types", Map.of(
                "subset_of", List.of("authorization_code"),
                "add", List.of("refresh_token"))));

        Object resolved = p.apply(Map.of("grant_types", List.of("authorization_code", "implicit")))
                .get("grant_types");
        // subset_of strips implicit first; add then contributes refresh_token, which survives because
        // add runs afterwards.
        assertEquals(List.of("authorization_code", "refresh_token"), resolved);
    }

    @Test
    void theApplicationOrderMatchesTheSpecification() {
        assertEquals(List.of("value", "default", "one_of", "subset_of", "superset_of", "add", "essential"),
                MetadataPolicy.APPLICATION_ORDER);
    }

    @Test
    void metadataUntouchedByAnyPolicyPassesThrough() throws Exception {
        MetadataPolicy p = policy(Map.of("grant_types", Map.of("subset_of", List.of("authorization_code"))));
        assertEquals("https://rp.example", p.apply(Map.of(
                "grant_types", List.of("authorization_code"),
                "client_uri", "https://rp.example")).get("client_uri"));
    }

    // ---- metadata_policy_crit ------------------------------------------------------------------------

    /** §3.1.3: an unrecognised critical operator makes the subordinate statement invalid. */
    @Test
    void anUnknownCriticalOperatorInvalidatesTheStatement() {
        MetadataPolicy.PolicyException e = assertThrows(MetadataPolicy.PolicyException.class,
                () -> MetadataPolicy.parse(Map.of("grant_types", Map.of("regexp", ".*")),
                        List.of("regexp")));
        assertTrue(e.getMessage().contains("does not understand"), e.getMessage());
    }

    @Test
    void aKnownOperatorListedAsCriticalIsAccepted() throws Exception {
        MetadataPolicy p = MetadataPolicy.parse(
                Map.of("grant_types", Map.of("subset_of", List.of("authorization_code"))),
                List.of("subset_of"));
        assertTrue(p.parameters().contains("grant_types"));
    }

    @Test
    void anUnknownOperatorIsRefusedDuringComposition() throws Exception {
        MetadataPolicy superior = policy(Map.of("grant_types", Map.of("regexp", ".*")));
        MetadataPolicy subordinate = policy(Map.of("grant_types", Map.of("regexp", ".*")));
        assertThrows(MetadataPolicy.PolicyException.class, () -> superior.composeWith(subordinate));
    }

    // ---- composition down a chain ----------------------------------------------------------------------

    @Test
    void compositionIsAssociativeDownAThreeLevelChain() throws Exception {
        MetadataPolicy anchor = policy(Map.of("grant_types", Map.of(
                "subset_of", List.of("authorization_code", "client_credentials", "refresh_token"))));
        MetadataPolicy intermediate = policy(Map.of("grant_types", Map.of(
                "subset_of", List.of("authorization_code", "refresh_token"))));
        MetadataPolicy leaf = policy(Map.of("grant_types", Map.of(
                "subset_of", List.of("authorization_code"))));

        MetadataPolicy composed = anchor.composeWith(intermediate).composeWith(leaf);
        assertEquals(List.of("authorization_code"),
                composed.operatorsFor("grant_types").get("subset_of"));
    }

    @Test
    void anEmptyPolicyComposesToTheOther() throws Exception {
        MetadataPolicy real = policy(Map.of("grant_types", Map.of("subset_of", List.of("authorization_code"))));
        assertEquals(List.of("authorization_code"),
                MetadataPolicy.empty().composeWith(real).operatorsFor("grant_types").get("subset_of"));
        assertEquals(List.of("authorization_code"),
                real.composeWith(MetadataPolicy.empty()).operatorsFor("grant_types").get("subset_of"));
    }

    @Test
    void anEmptyPolicyLeavesMetadataAlone() throws Exception {
        Map<String, Object> metadata = Map.of("grant_types", List.of("authorization_code"));
        assertEquals(metadata, MetadataPolicy.empty().apply(metadata));
    }
}
