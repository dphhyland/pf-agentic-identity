package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.testkit.SpecExamples;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Metadata policy against OpenID Federation 1.0 Final §6.1.3 and §6.1.4: every operator's action, its
 * place in the application order, its merge rule, the combinations it allows, the JSON types it accepts,
 * and the worked example of §6.1.5 reproduced exactly.
 *
 * <p>The tests that matter most assert a policy can only ever narrow: a bug that widens scope hands a
 * subordinate capabilities its superior withheld, and does so silently.
 */
class MetadataPolicyTest {

    private static MetadataPolicy policy(Map<String, Object> raw) throws Exception {
        return MetadataPolicy.parse(raw, null);
    }

    private static Map<String, Object> param(String name, Map<String, Object> operators) {
        return Map.of(name, operators);
    }

    private static Map<String, Object> ops(Object... pairs) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            out.put((String) pairs[i], pairs[i + 1]);
        }
        return out;
    }

    private static Map<String, Object> apply(Map<String, Object> rawPolicy, Map<String, Object> metadata) throws Exception {
        return policy(rawPolicy).apply(metadata);
    }

    // ---- actions --------------------------------------------------------------------------------

    @Test
    @Requirement("OIDFED §6.1.3.1.1(2)")
    void valueAssignsTheParameterAndNullRemovesIt() throws Exception {
        assertEquals("pairwise", apply(param("subject_type", ops("value", "pairwise")), Map.of("subject_type", "public"))
                .get("subject_type"));
        Map<String, Object> resolved = apply(param("jwks_uri", ops("value", null)), Map.of("jwks_uri", "https://x"));
        assertFalse(resolved.containsKey("jwks_uri"));
    }

    @Test
    @Requirement("OIDFED §6.1.3(2.8)")
    void noOperatorEverOutputsANullParameter() throws Exception {
        Map<String, Object> resolved = apply(param("jwks_uri", ops("value", null)), Map.of());
        assertFalse(resolved.containsKey("jwks_uri"));
        assertFalse(resolved.containsValue(null));
    }

    @Test
    @Requirement("OIDFED §6.1.3.1.2(2)")
    void addAppendsNewValuesOnceAndInitialisesAnAbsentParameter() throws Exception {
        Map<String, Object> add = param("contacts", ops("add", List.of("ops@example.org", "admin@example.org")));
        assertEquals(List.of("admin@example.org", "ops@example.org"),
                apply(add, Map.of("contacts", List.of("admin@example.org"))).get("contacts"));
        assertEquals(List.of("ops@example.org", "admin@example.org"), apply(add, Map.of()).get("contacts"));
    }

    @Test
    @Requirement("OIDFED §6.1.3.1.3(2)")
    void defaultFillsOnlyAnAbsentParameter() throws Exception {
        Map<String, Object> def = param("id_token_signed_response_alg", ops("default", "ES256"));
        assertEquals("ES256", apply(def, Map.of()).get("id_token_signed_response_alg"));
        assertEquals("PS256", apply(def, Map.of("id_token_signed_response_alg", "PS256")).get("id_token_signed_response_alg"));
    }

    @Test
    @Requirement("OIDFED §6.1.3.1.4(2)")
    void oneOfChecksAPresentValueAndIgnoresAnAbsentOne() throws Exception {
        Map<String, Object> oneOf = param("token_endpoint_auth_method", ops("one_of", List.of("private_key_jwt", "attest_jwt_client_auth")));
        assertEquals("private_key_jwt", apply(oneOf, Map.of("token_endpoint_auth_method", "private_key_jwt"))
                .get("token_endpoint_auth_method"));
        MetadataPolicy.PolicyException e = assertThrows(MetadataPolicy.PolicyException.class,
                () -> apply(oneOf, Map.of("token_endpoint_auth_method", "client_secret_basic")));
        assertTrue(e.getMessage().contains("not one_of"), e.getMessage());
        assertFalse(apply(oneOf, Map.of()).containsKey("token_endpoint_auth_method"));
    }

    @Test
    @Requirement({"OIDFED §6.1.3(2.2)", "OIDFED §6.1.3.1.4(4.1)"})
    void oneOfRefusesAParameterThatIsNotASingleValue() {
        assertThrows(MetadataPolicy.PolicyException.class, () -> apply(
                param("token_endpoint_auth_method", ops("one_of", List.of("a"))), Map.of("token_endpoint_auth_method", List.of("a"))));
    }

    @Test
    @Requirement("OIDFED §6.1.3.1.5(2)")
    void subsetOfIntersectsAndMayLeaveAnEmptyArray() throws Exception {
        Map<String, Object> subset = param("grant_types", ops("subset_of", List.of("authorization_code")));
        assertEquals(List.of("authorization_code"),
                apply(subset, Map.of("grant_types", List.of("authorization_code", "implicit"))).get("grant_types"));
        assertEquals(List.of(), apply(subset, Map.of("grant_types", List.of("implicit"))).get("grant_types"),
                "the specification allows the intersection to be []");
        assertFalse(apply(subset, Map.of()).containsKey("grant_types"));
    }

    @Test
    @Requirement("OIDFED §6.1.3.1.6(2)")
    void supersetOfRequiresEveryValueWhenPresentAndIsSkippedWhenAbsent() throws Exception {
        Map<String, Object> superset = param("grant_types", ops("superset_of", List.of("authorization_code", "refresh_token")));
        assertThrows(MetadataPolicy.PolicyException.class,
                () -> apply(superset, Map.of("grant_types", List.of("authorization_code"))));
        assertEquals(List.of("refresh_token", "authorization_code"),
                apply(superset, Map.of("grant_types", List.of("refresh_token", "authorization_code"))).get("grant_types"));
        assertFalse(apply(superset, Map.of()).containsKey("grant_types"), "an absent parameter is not a violation");
    }

    @Test
    @Requirement("OIDFED §6.1.3.1.7(2)")
    void anEssentialParameterMustBePresentAndAVoluntaryOneMayBeAbsent() throws Exception {
        assertThrows(MetadataPolicy.PolicyException.class, () -> apply(param("contacts", ops("essential", true)), Map.of()));
        assertEquals(Map.of(), apply(param("contacts", ops("essential", false)), Map.of()));
    }

    // ---- order -----------------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §6.1.3.1.1(9)", "OIDFED §6.1.3.1.2(9)", "OIDFED §6.1.3.1.3(9)", "OIDFED §6.1.3.1.4(9)",
            "OIDFED §6.1.3.1.5(9)", "OIDFED §6.1.3.1.6(9)", "OIDFED §6.1.3.1.7(9)"})
    void theApplicationOrderIsTheOneEachOperatorDeclares() {
        assertEquals(List.of("value", "add", "default", "one_of", "subset_of", "superset_of", "essential"),
                MetadataPolicy.APPLICATION_ORDER);
    }

    @Test
    @Requirement({"OIDFED §6.1.3.1.2(9)", "OIDFED §6.1.3.1.3(9)"})
    void addRunsBeforeDefaultSoAnAbsentParameterTakesOnlyTheAddedValues() throws Exception {
        Map<String, Object> resolved = apply(param("contacts", ops("default", List.of("fallback@example.org"),
                "add", List.of("helpdesk@example.org"))), Map.of());
        assertEquals(List.of("helpdesk@example.org"), resolved.get("contacts"),
                "add initialises the parameter first, so default then has nothing to fill");
    }

    @Test
    @Requirement("OIDFED §6.1.4.2(3)")
    void aValueAddedByAddSurvivesTheSubsetCheckBecauseTheCombinationRuleGuaranteesIt() throws Exception {
        Map<String, Object> resolved = apply(param("grant_types", ops("add", List.of("refresh_token"),
                "subset_of", List.of("authorization_code", "refresh_token"))), Map.of("grant_types", List.of("authorization_code", "implicit")));
        assertEquals(List.of("authorization_code", "refresh_token"), resolved.get("grant_types"));
    }

    // ---- merge -----------------------------------------------------------------------------------

    @Test
    @Requirement("OIDFED §6.1.3.1.1(10)")
    void valuesMergeOnlyWhenEqual() throws Exception {
        MetadataPolicy a = policy(param("issuer", ops("value", "https://a.example")));
        assertEquals("https://a.example", a.composeWith(policy(param("issuer", ops("value", "https://a.example"))))
                .operatorsFor("issuer").get("value"));
        assertThrows(MetadataPolicy.PolicyException.class, () -> a.composeWith(policy(param("issuer", ops("value", "https://b.example")))));
        MetadataPolicy nulls = policy(param("jwks_uri", ops("value", null)));
        assertNull(nulls.composeWith(policy(param("jwks_uri", ops("value", null)))).operatorsFor("jwks_uri").get("value"));
    }

    @Test
    @Requirement("OIDFED §6.1.3.1.2(10)")
    void addMergesAsTheUnion() throws Exception {
        MetadataPolicy superior = policy(param("contacts", ops("add", List.of("a@example.org"))));
        MetadataPolicy subordinate = policy(param("contacts", ops("add", List.of("a@example.org", "b@example.org"))));
        assertEquals(List.of("a@example.org", "b@example.org"),
                superior.composeWith(subordinate).operatorsFor("contacts").get("add"));
    }

    @Test
    @Requirement("OIDFED §6.1.3.1.3(10)")
    void defaultsMergeOnlyWhenEqual() throws Exception {
        MetadataPolicy a = policy(param("response_types", ops("default", List.of("code"))));
        assertEquals(List.of("code"), a.composeWith(a).operatorsFor("response_types").get("default"));
        assertThrows(MetadataPolicy.PolicyException.class,
                () -> a.composeWith(policy(param("response_types", ops("default", List.of("id_token"))))));
    }

    @Test
    @Requirement("OIDFED §6.1.3.1.4(10)")
    void oneOfMergesAsTheIntersectionAndAnEmptyOneIsAnError() throws Exception {
        MetadataPolicy superior = policy(param("token_endpoint_auth_method", ops("one_of", List.of("private_key_jwt", "tls_client_auth"))));
        assertEquals(List.of("private_key_jwt"), superior.composeWith(policy(param("token_endpoint_auth_method",
                ops("one_of", List.of("private_key_jwt", "client_secret_basic"))))).operatorsFor("token_endpoint_auth_method").get("one_of"));
        MetadataPolicy.PolicyException e = assertThrows(MetadataPolicy.PolicyException.class, () -> superior.composeWith(
                policy(param("token_endpoint_auth_method", ops("one_of", List.of("client_secret_basic"))))));
        assertTrue(e.getMessage().contains("do not overlap"), e.getMessage());
    }

    @Test
    @Requirement("OIDFED §6.1.3.1.5(10)")
    void subsetOfMergesAsTheIntersectionEvenWhenItIsEmpty() throws Exception {
        MetadataPolicy superior = policy(param("grant_types", ops("subset_of", List.of("authorization_code"))));
        MetadataPolicy disjoint = policy(param("grant_types", ops("subset_of", List.of("client_credentials"))));

        MetadataPolicy merged = superior.composeWith(disjoint);

        assertEquals(List.of(), merged.operatorsFor("grant_types").get("subset_of"));
        assertEquals(List.of(), merged.apply(Map.of("grant_types", List.of("authorization_code"))).get("grant_types"),
                "nothing is permitted - and that narrows, it does not widen");
    }

    @Test
    @Requirement("OIDFED §6.1.3.1.6(10)")
    void supersetOfMergesAsTheUnion() throws Exception {
        MetadataPolicy merged = policy(param("grant_types", ops("superset_of", List.of("authorization_code"))))
                .composeWith(policy(param("grant_types", ops("superset_of", List.of("refresh_token")))));
        assertEquals(List.of("authorization_code", "refresh_token"), merged.operatorsFor("grant_types").get("superset_of"));
    }

    @Test
    @Requirement("OIDFED §6.1.3.1.7(10)")
    void essentialMergesAsLogicalOrSoASubordinateCannotRelaxIt() throws Exception {
        MetadataPolicy merged = policy(param("contacts", ops("essential", true)))
                .composeWith(policy(param("contacts", ops("essential", false))));
        assertEquals(Boolean.TRUE, merged.operatorsFor("contacts").get("essential"));
        assertEquals(Boolean.FALSE, policy(param("contacts", ops("essential", false)))
                .composeWith(policy(param("contacts", ops("essential", false)))).operatorsFor("contacts").get("essential"));
    }

    @Test
    @Requirement({"OIDFED §6.1.4.1(10.2)", "OIDFED §6.1.4.1(12.2)", "OIDFED §6.1.4.1(14.2)"})
    void aMergeCopiesParametersOnlyOneSideHasAndAnEmptyPolicyComposesToTheOther() throws Exception {
        MetadataPolicy superior = policy(param("contacts", ops("add", List.of("a@example.org"))));
        MetadataPolicy subordinate = policy(param("grant_types", ops("subset_of", List.of("authorization_code"))));
        MetadataPolicy merged = superior.composeWith(subordinate);
        assertEquals(java.util.Set.of("contacts", "grant_types"), merged.parameters());
        assertEquals(superior.toRawMap(), MetadataPolicy.empty().composeWith(superior).toRawMap());
        assertEquals(superior.toRawMap(), superior.composeWith(MetadataPolicy.empty()).toRawMap());
        assertTrue(MetadataPolicy.empty().isEmpty());
    }

    // ---- combinations ----------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §6.1.3.1.1(8.1)", "OIDFED §6.1.3.1.2(8.1)"})
    void addWithValueMustBeASubsetOfValue() throws Exception {
        policy(param("contacts", ops("value", List.of("a", "b"), "add", List.of("a"))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("contacts", ops("value", List.of("a"), "add", List.of("c")))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("contacts", ops("value", null, "add", List.of("c")))));
    }

    @Test
    @Requirement({"OIDFED §6.1.3.1.1(8.2)", "OIDFED §6.1.3.1.3(8.1)"})
    void defaultWithValueNeedsANonNullValue() throws Exception {
        policy(param("subject_type", ops("value", "pairwise", "default", "public")));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("subject_type", ops("value", null, "default", "public"))));
    }

    @Test
    @Requirement({"OIDFED §6.1.3.1.1(8.3)", "OIDFED §6.1.3.1.4(8.1)"})
    void valueWithOneOfMustBeAmongTheOneOfValues() throws Exception {
        policy(param("subject_type", ops("value", "pairwise", "one_of", List.of("pairwise", "public"))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("subject_type", ops("value", "x", "one_of", List.of("pairwise")))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("subject_type", ops("value", List.of("pairwise"), "one_of", List.of("pairwise")))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("subject_type", ops("value", null, "one_of", List.of("pairwise")))));
    }

    @Test
    @Requirement({"OIDFED §6.1.3.1.1(8.4)", "OIDFED §6.1.3.1.5(8.1)"})
    void valueWithSubsetOfMustBeASubset() throws Exception {
        policy(param("grant_types", ops("value", List.of("authorization_code"), "subset_of", List.of("authorization_code", "refresh_token"))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("grant_types",
                ops("value", List.of("implicit"), "subset_of", List.of("authorization_code")))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("grant_types",
                ops("value", null, "subset_of", List.of("authorization_code")))));
    }

    @Test
    @Requirement({"OIDFED §6.1.3.1.1(8.5)", "OIDFED §6.1.3.1.6(8.1)"})
    void valueWithSupersetOfMustBeASuperset() throws Exception {
        policy(param("grant_types", ops("value", List.of("authorization_code", "refresh_token"), "superset_of", List.of("authorization_code"))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("grant_types",
                ops("value", List.of("refresh_token"), "superset_of", List.of("authorization_code")))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("grant_types",
                ops("value", null, "superset_of", List.of("authorization_code")))));
    }

    @Test
    @Requirement({"OIDFED §6.1.3.1.1(8.6)", "OIDFED §6.1.3.1.7(8.1)"})
    void aNullValueMayNotBeEssential() throws Exception {
        policy(param("jwks_uri", ops("value", null, "essential", false)));
        policy(param("jwks_uri", ops("value", "https://x", "essential", true)));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("jwks_uri", ops("value", null, "essential", true))));
    }

    @Test
    @Requirement({"OIDFED §6.1.3.1.2(8.3)", "OIDFED §6.1.3.1.5(8.2)"})
    void addWithSubsetOfMustBeASubsetOfIt() throws Exception {
        policy(param("grant_types", ops("add", List.of("refresh_token"), "subset_of", List.of("authorization_code", "refresh_token"))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("grant_types",
                ops("add", List.of("implicit"), "subset_of", List.of("authorization_code")))));
    }

    @Test
    @Requirement({"OIDFED §6.1.3.1.5(8.4)", "OIDFED §6.1.3.1.6(8.4)"})
    void subsetOfWithSupersetOfMustContainIt() throws Exception {
        policy(param("grant_types", ops("subset_of", List.of("a", "b"), "superset_of", List.of("a", "b"))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("grant_types",
                ops("subset_of", List.of("a"), "superset_of", List.of("a", "b")))));
    }

    @Test
    @Requirement("OIDFED §6.1.3(2.5)")
    void oneOfCombinesOnlyWithValueDefaultAndEssential() throws Exception {
        policy(param("x", ops("one_of", List.of("a"), "default", "a", "essential", true)));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("x", ops("one_of", List.of("a"), "add", List.of("a")))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("x", ops("one_of", List.of("a"), "subset_of", List.of("a")))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("x", ops("one_of", List.of("a"), "superset_of", List.of("a")))));
    }

    @Test
    @Requirement("OIDFED §6.1.4.1(12.1)")
    void aCombinationThatOnlyAppearsAfterMergingIsStillAnError() throws Exception {
        MetadataPolicy superior = policy(param("grant_types", ops("subset_of", List.of("authorization_code"))));
        MetadataPolicy subordinate = policy(param("grant_types", ops("superset_of", List.of("client_credentials"))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> superior.composeWith(subordinate));
    }

    // ---- types -----------------------------------------------------------------------------------

    @Test
    @Requirement("OIDFED §6.1.3(2.4)")
    void anOperandOfAnUnsupportedTypeIsAPolicyError() {
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("x", ops("essential", "true"))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("x", ops("one_of", "a"))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("x", ops("add", List.of(Map.of("a", 1))))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("x", ops("value", Map.of("a", 1)))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("x", ops("value", List.of(Map.of())))));
        Map<String, Object> nullDefault = new HashMap<>();
        nullDefault.put("default", null);
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("x", nullDefault)));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("x", ops("default", Map.of()))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(Map.of("x", "not an object")));
    }

    @Test
    @Requirement("OIDFED §6.1.3(2.2)")
    void aParameterOfAnUnsupportedTypeIsAPolicyError() {
        assertThrows(MetadataPolicy.PolicyException.class,
                () -> apply(param("grant_types", ops("subset_of", List.of("a"))), Map.of("grant_types", "a")));
        assertThrows(MetadataPolicy.PolicyException.class,
                () -> apply(param("grant_types", ops("add", List.of("a"))), Map.of("grant_types", "a")));
        assertThrows(MetadataPolicy.PolicyException.class,
                () -> apply(param("grant_types", ops("superset_of", List.of("a"))), Map.of("grant_types", List.of(Map.of()))));
    }

    @Test
    @Requirement({"OIDFED §6.1.3(2.4)", "OIDFED §6.1.3.1.2(6.1)", "OIDFED §6.1.3.1.4(6.1)", "OIDFED §6.1.3.1.5(6.1)",
            "OIDFED §6.1.3.1.6(6.1)"})
    void theArrayOperatorsTakeArraysOfStringsOrOfNumbersAndNothingElse() throws Exception {
        policy(param("x", ops("subset_of", List.of())));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("x", ops("add", List.of(true)))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("x", ops("subset_of", List.of("a", 1)))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("x", ops("superset_of", List.of(List.of("a"))))));
    }

    @Test
    @Requirement({"OIDFED §6.1.3(2.2)", "OIDFED §6.1.3.1.1(4.1)", "OIDFED §6.1.3.1.3(4.1)", "OIDFED §6.1.3.1.4(4.2)",
            "OIDFED §6.1.3.1.7(4.1)"})
    void eachOperatorChecksTheParameterTypesItSupports() throws Exception {
        assertThrows(MetadataPolicy.PolicyException.class,
                () -> apply(param("p", ops("value", "x")), Map.of("p", Map.of("k", "v"))));
        assertThrows(MetadataPolicy.PolicyException.class,
                () -> apply(param("p", ops("default", "x")), Map.of("p", Map.of("k", "v"))));
        assertThrows(MetadataPolicy.PolicyException.class,
                () -> apply(param("p", ops("one_of", List.of("true"))), Map.of("p", true)));
        assertEquals(7, apply(param("p", ops("one_of", List.of(7, 8))), Map.of("p", 7)).get("p"),
                "one_of may check a number, which the specification makes optional");
        assertEquals(Map.of("k", "v"), apply(param("p", ops("essential", true)), Map.of("p", Map.of("k", "v"))).get("p"),
                "essential supports every type, objects included");
        assertEquals(List.of("a"), apply(param("p", ops("value", List.of("a"))), Map.of("p", List.of(Map.of()))).get("p"));
    }

    @Test
    @Requirement("OIDFED §6.1.3(2.8)")
    void aNullParameterIsAPolicyErrorWhateverTheOperator() {
        Map<String, Object> nullParameter = new HashMap<>();
        nullParameter.put("p", null);
        assertThrows(MetadataPolicy.PolicyException.class, () -> apply(param("p", ops("essential", false)), nullParameter));
        assertThrows(MetadataPolicy.PolicyException.class, () -> apply(param("p", ops("value", "x")), nullParameter));
    }

    @Test
    void numbersCompareByValueNotByJavaClass() throws Exception {
        assertEquals(List.of(1), apply(param("n", ops("subset_of", List.of(1, 2))), Map.of("n", List.of(1, 3))).get("n"));
        assertEquals(List.of(1L), apply(param("n", ops("subset_of", List.of(1.0, 2.0))), Map.of("n", List.of(1L, 3L))).get("n"));
        MetadataPolicy merged = policy(param("n", ops("value", 3600))).composeWith(policy(param("n", ops("value", 3600.0))));
        assertEquals(3600, merged.operatorsFor("n").get("value"));
        assertThrows(MetadataPolicy.PolicyException.class,
                () -> policy(param("n", ops("value", List.of(1)))).composeWith(policy(param("n", ops("value", List.of(1, 2))))));
        assertThrows(MetadataPolicy.PolicyException.class,
                () -> policy(param("n", ops("value", List.of(1, 2)))).composeWith(policy(param("n", ops("value", List.of(1, 3))))));
        assertEquals(List.of(Double.NaN), apply(param("n", ops("subset_of", List.of(Double.NaN))), Map.of("n", List.of(Double.NaN)))
                .get("n"), "a number no JSON document can carry falls back to Java equality rather than failing");
    }

    // ---- scope -------------------------------------------------------------------------------------

    @Test
    @Requirement("OIDFED §6.1.3.1.8(3)")
    void scopeIsProcessedAsAnArrayAndWrittenBackAsAString() throws Exception {
        assertEquals("openid email", apply(param("scope", ops("subset_of", List.of("openid", "email"))),
                Map.of("scope", "openid email phone")).get("scope"));
        assertEquals("openid offline_access", apply(param("scope", ops("add", List.of("offline_access"))),
                Map.of("scope", "openid")).get("scope"));
        assertEquals("openid profile", apply(param("scope", ops("default", "openid profile")), Map.of()).get("scope"));
        assertEquals("openid", apply(param("scope", ops("value", "openid", "superset_of", List.of("openid"))),
                Map.of("scope", "anything")).get("scope"));
        assertEquals("", apply(param("scope", ops("subset_of", List.of("x"))), Map.of("scope", "openid")).get("scope"));
    }

    @Test
    @Requirement("OIDFED §6.1.3.1.8(4)")
    void tableOneEssentialAndSubsetOfCombinations() throws Exception {
        Map<String, Object> ae = ops("subset_of", List.of("a", "b", "c"));
        assertEquals(List.of("a"), apply(param("p", ops("essential", true, "subset_of", List.of("a", "b", "c"))),
                Map.of("p", List.of("a", "e"))).get("p"));
        assertEquals(List.of("a"), apply(param("p", ops("essential", false, "subset_of", List.of("a", "b", "c"))),
                Map.of("p", List.of("a", "e"))).get("p"));
        assertEquals(List.of(), apply(param("p", ops("essential", true, "subset_of", List.of("a", "b", "c"))),
                Map.of("p", List.of("d", "e"))).get("p"));
        assertEquals(List.of(), apply(param("p", ops("essential", false, "subset_of", List.of("a", "b", "c"))),
                Map.of("p", List.of("d", "e"))).get("p"));
        assertThrows(MetadataPolicy.PolicyException.class,
                () -> apply(param("p", ops("essential", true, "subset_of", List.of("a", "b", "c"))), Map.of()));
        assertFalse(apply(param("p", ops("essential", false, "subset_of", List.of("a", "b", "c"))), Map.of()).containsKey("p"));
        assertEquals(List.of("a"), apply(param("p", ae), Map.of("p", List.of("a"))).get("p"));
    }

    // ---- additional operators and metadata_policy_crit ----------------------------------------------

    @Test
    @Requirement("OIDFED §6.1.3.2(4)")
    void anAdditionalOperatorThatIsNotCriticalIsIgnored() throws Exception {
        MetadataPolicy p = policy(param("contacts", ops("regexp", "^.*@example.org$", "add", List.of("a@example.org"))));
        assertEquals(Map.of("add", List.of("a@example.org")), p.operatorsFor("contacts"));
        assertTrue(policy(param("contacts", ops("regexp", "x"))).isEmpty());
    }

    @Test
    @Requirement({"OIDFED §3.1.3(1.6)", "OIDFED §6.1.3.2(4)", "OIDFED §6.1.4.1(4)"})
    void aCriticalOperatorThisImplementationDoesNotUnderstandInvalidatesThePolicy() {
        MetadataPolicy.PolicyException e = assertThrows(MetadataPolicy.PolicyException.class,
                () -> MetadataPolicy.parse(param("contacts", ops("regexp", "x")), List.of("regexp")));
        assertTrue(e.getMessage().contains("regexp"), e.getMessage());
    }

    @Test
    @Requirement({"OIDFED §3.2(2.18)", "OIDFED §3.1.3(1.6)"})
    void aStandardOperatorListedAsCriticalIsASyntaxError() {
        assertThrows(MetadataPolicy.PolicyException.class,
                () -> MetadataPolicy.parse(param("contacts", ops("add", List.of("a"))), List.of("add")));
    }

    // ---- the worked example ------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §6.1.4.1(3)", "OIDFED §6.1.4.1(14.1)", "OIDFED §6.1.5"})
    void theWorkedExampleMergesToTheSpecificationsOwnResult() throws Exception {
        MetadataPolicy anchor = MetadataPolicy.parse(SpecExamples.path(SpecExamples.load("6.1.5-trust-anchor-policy.json"),
                "metadata_policy", "openid_relying_party"), null);
        MetadataPolicy intermediate = MetadataPolicy.parse(SpecExamples.path(SpecExamples.load("6.1.5-intermediate-statement.json"),
                "metadata_policy", "openid_relying_party"), null);

        MetadataPolicy merged = anchor.composeWith(intermediate);

        assertEquals(SpecExamples.canonical(SpecExamples.load("6.1.5-merged-policy.json"), true),
                SpecExamples.canonical(merged.toRawMap(), true));
    }

    @Test
    @Requirement({"OIDFED §6.1.4.2(1)", "OIDFED §6.1.4.2(3)", "OIDFED §6.1.5"})
    void theWorkedExampleResolvesToTheSpecificationsOwnMetadata() throws Exception {
        MetadataPolicy merged = MetadataPolicy.parse(SpecExamples.load("6.1.5-merged-policy.json"), null);
        Map<String, Object> leaf = new LinkedHashMap<>(SpecExamples.path(SpecExamples.load("6.1.5-leaf-metadata.json"),
                "metadata", "openid_relying_party"));
        // The Intermediate's own metadata values for its Immediate Subordinates are applied first (§6.1.4.2).
        leaf.putAll(SpecExamples.path(SpecExamples.load("6.1.5-intermediate-statement.json"), "metadata", "openid_relying_party"));

        Map<String, Object> resolved = merged.apply(leaf);

        assertEquals(SpecExamples.canonical(SpecExamples.load("6.1.5-resolved-metadata.json"), false),
                SpecExamples.canonical(resolved, false));
    }

    // ---- edges ---------------------------------------------------------------------------------------

    @Test
    @Requirement("OIDFED §6.1.3.1.7(10)")
    void aSubordinateMayMakeAVoluntaryParameterEssential() throws Exception {
        MetadataPolicy merged = policy(param("contacts", ops("essential", false)))
                .composeWith(policy(param("contacts", ops("essential", true))));
        assertEquals(Boolean.TRUE, merged.operatorsFor("contacts").get("essential"));
    }

    @Test
    @Requirement("OIDFED §6.1.3.1.2(2)")
    void addLeavesTheParametersOwnValuesAsTheyAre() throws Exception {
        assertEquals(List.of("a", "a", "b"), apply(param("p", ops("add", List.of("a", "b"))), Map.of("p", List.of("a", "a"))).get("p"));
    }

    @Test
    void subsetOfReturnsEachSurvivingValueOnce() throws Exception {
        assertEquals(List.of("a"), apply(param("p", ops("subset_of", List.of("a"))), Map.of("p", List.of("a", "a"))).get("p"));
        MetadataPolicy merged = policy(param("p", ops("superset_of", List.of("a", "a"))))
                .composeWith(policy(param("p", ops("superset_of", List.of("b")))));
        assertEquals(List.of("a", "b"), merged.operatorsFor("p").get("superset_of"));
    }

    @Test
    @Requirement({"OIDFED §6.1.3.1.1(8.1)", "OIDFED §6.1.3.1.1(8.4)", "OIDFED §6.1.3.1.1(8.5)"})
    void aSingleValueCombinesAsASetOfOne() throws Exception {
        policy(param("p", ops("value", "a", "subset_of", List.of("a", "b"), "superset_of", List.of("a"))));
        policy(param("p", ops("value", "a", "add", List.of("a"))));
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("p", ops("value", "a", "superset_of", List.of("a", "b")))));
    }

    @Test
    @Requirement({"OIDFED §6.1.3.1.1(6.1)", "OIDFED §6.1.3.1.1(10)"})
    void valueAcceptsBooleansAndMergesOnlyWithTheSameJsonType() throws Exception {
        assertEquals(true, apply(param("p", ops("value", true)), Map.of()).get("p"));
        assertEquals(List.of(true, false), apply(param("p", ops("value", List.of(true, false))), Map.of("p", "x")).get("p"));
        assertThrows(MetadataPolicy.PolicyException.class,
                () -> policy(param("p", ops("value", List.of("a")))).composeWith(policy(param("p", ops("value", "a")))));
        assertThrows(MetadataPolicy.PolicyException.class,
                () -> policy(param("p", ops("value", 1))).composeWith(policy(param("p", ops("value", "1")))));
    }

    @Test
    @Requirement("OIDFED §6.1.3.1.8(3)")
    void scopeEdgeCases() throws Exception {
        assertEquals("openid", apply(param("scope", ops("subset_of", List.of("openid", "email"))),
                Map.of("scope", "openid  openid ")).get("scope"), "repeats and extra spaces collapse");
        assertEquals("", apply(param("scope", ops("subset_of", List.of("openid"))), Map.of("scope", "")).get("scope"));
        assertEquals("openid", apply(param("scope", ops("subset_of", List.of("openid"))),
                Map.of("scope", List.of("openid", "email"))).get("scope"), "an array-valued scope is read as it is");
        assertEquals(42, apply(param("scope", ops("essential", true)), Map.of("scope", 42)).get("scope"),
                "essential supports any type and leaves the value alone");
        assertThrows(MetadataPolicy.PolicyException.class, () -> policy(param("scope", ops("essential", "true"))));
    }

    // ---- the narrow-only property --------------------------------------------------------------------

    @Test
    void narrowingAtTheParentMeasurablyReducesWhatASubordinateObtains() throws Exception {
        Map<String, Object> subordinateMetadata = Map.of(
                "grant_types", List.of("authorization_code", "client_credentials", "implicit"));
        assertEquals(List.of("authorization_code", "client_credentials", "implicit"), policy(param("grant_types",
                ops("subset_of", List.of("authorization_code", "client_credentials", "implicit")))).apply(subordinateMetadata).get("grant_types"));
        assertEquals(List.of("authorization_code"), policy(param("grant_types",
                ops("subset_of", List.of("authorization_code")))).apply(subordinateMetadata).get("grant_types"));
    }

    @Test
    void compositionIsAssociativeDownAThreeLevelChain() throws Exception {
        MetadataPolicy a = policy(param("grant_types", ops("subset_of", List.of("a", "b", "c"))));
        MetadataPolicy b = policy(param("grant_types", ops("subset_of", List.of("a", "b"))));
        MetadataPolicy c = policy(param("grant_types", ops("subset_of", List.of("b", "c"))));
        assertEquals(a.composeWith(b).composeWith(c).toRawMap(), a.composeWith(b.composeWith(c)).toRawMap());
    }

    @Test
    void metadataUntouchedByAnyPolicyPassesThrough() throws Exception {
        Map<String, Object> metadata = Map.of("client_name", "agent", "grant_types", List.of("client_credentials"));
        assertEquals(metadata, policy(param("contacts", ops("essential", false))).apply(metadata));
        assertEquals(Map.of(), MetadataPolicy.empty().apply(null));
        assertTrue(MetadataPolicy.parse(Map.of(), null).isEmpty());
        assertTrue(MetadataPolicy.parse(null, List.of()).isEmpty());
    }
}
