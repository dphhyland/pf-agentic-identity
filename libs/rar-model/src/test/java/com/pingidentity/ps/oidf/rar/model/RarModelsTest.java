/*
 * The facade: loading from the environment, the fingerprint, and the clauses the operations pin.
 */
package com.pingidentity.ps.oidf.rar.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RarModelsTest {

    private static final String SA = "sales_agent";
    private static final String PI = "payment_initiation";
    private static final String AI = "account_information";

    private final RarModels models = RarModels.builtIn();

    private static List<Map<String, Object>> details(String json) throws RarModelException {
        return RarModels.parseDetails(json);
    }

    // ---- environment and loading ----

    @Test
    void builtInsAreTheThreeTypesWithNoFallback() {
        assertEquals(List.of(SA, PI, AI), new ArrayList<>(models.types()));
        assertFalse(models.commonFieldsFallback());
        assertEquals(64, models.fingerprint().length());
        assertTrue(models.fingerprint().matches("[0-9a-f]{64}"));
        assertTrue(models.canonicalJson().startsWith("{\"common_fields_fallback\":false,\"types\":{\"account_information\":{\"fields\":{"));
    }

    @Test
    void fingerprintIsStableAndSensitive() throws Exception {
        assertEquals(models.fingerprint(), RarModels.builtIn().fingerprint());
        assertEquals(models.fingerprint(), RarModels.load(null, false).fingerprint());
        assertEquals(models.fingerprint(), RarModels.load("{\"types\":{}}", false).fingerprint());
        assertNotEquals(models.fingerprint(), RarModels.load(null, true).fingerprint(), "the fallback is part of the model");
        assertNotEquals(models.fingerprint(), RarModels.load("{\"types\":{\"x\":{\"fields\":{\"a\":\"set\"}}}}", false).fingerprint());
        assertEquals(RarModels.load("{\"types\":{\"x\":{\"fields\":{\"a\":\"set\",\"b\":\"equal\"}}}}", false).fingerprint(),
                RarModels.load("{\"types\":{\"x\":{\"fields\":{\"b\":\"equal\",\"a\":\"set\"}}}}", false).fingerprint(),
                "field order in the document does not change the model");
    }

    @Test
    void environmentPicksFileOrInlineAndTheProfile(@TempDir Path dir) throws Exception {
        Map<String, String> env = new HashMap<>();
        RarModels none = RarModels.fromEnvironment(env);
        assertEquals(models.fingerprint(), none.fingerprint());
        assertFalse(none.commonFieldsFallback());

        env.put(RarModels.ENV_MODELS, " {\"types\":{\"x\":{\"fields\":{\"a\":\"set\"}}}} ");
        assertTrue(RarModels.fromEnvironment(env).types().contains("x"));

        Path file = dir.resolve("models.json");
        Files.writeString(file, "{\"types\":{\"y\":{\"fields\":{\"a\":\"set\"}}}}", StandardCharsets.UTF_8);
        env.put(RarModels.ENV_MODELS_FILE, file.toString());
        RarModelException both = assertThrows(RarModelException.class, () -> RarModels.fromEnvironment(env));
        assertEquals(RarModelException.Reason.MODEL_INVALID, both.reason());
        assertTrue(both.getMessage().contains("both set"), both.getMessage());

        env.put(RarModels.ENV_MODELS, " ");
        assertTrue(RarModels.fromEnvironment(env).types().contains("y"), "a blank inline value is unset");

        env.put(RarModels.ENV_MODELS_FILE, dir.resolve("missing.json").toString());
        RarModelException missing = assertThrows(RarModelException.class, () -> RarModels.fromEnvironment(env));
        assertEquals(RarModelException.Reason.MODEL_INVALID, missing.reason());
        assertTrue(missing.getMessage().startsWith(RarModels.ENV_MODELS_FILE + " could not be read"), missing.getMessage());

        env.put(RarModels.ENV_MODELS_FILE, "models\0.json");
        assertEquals(RarModelException.Reason.MODEL_INVALID,
                assertThrows(RarModelException.class, () -> RarModels.fromEnvironment(env)).reason(), "an invalid path is a read failure too");

        env.remove(RarModels.ENV_MODELS_FILE);
        env.remove(RarModels.ENV_MODELS);
        env.put(RarModels.ENV_PROFILE, "development");
        assertTrue(RarModels.fromEnvironment(env).commonFieldsFallback());
        env.put(RarModels.ENV_PROFILE, " development ");
        assertTrue(RarModels.fromEnvironment(env).commonFieldsFallback());
        env.put(RarModels.ENV_PROFILE, "Development");
        assertFalse(RarModels.fromEnvironment(env).commonFieldsFallback(), "only the exact value");
        env.put(RarModels.ENV_PROFILE, "production");
        assertFalse(RarModels.fromEnvironment(env).commonFieldsFallback());
        env.put(RarModels.ENV_PROFILE, "");
        assertFalse(RarModels.fromEnvironment(env).commonFieldsFallback());
    }

    @Test
    void processEnvironmentIsReadable() throws Exception {
        // The process environment of a test run names none of the three variables, so this is the built-ins.
        assertEquals(models.types(), RarModels.fromEnvironment().types());
    }

    @Test
    void modelLookup() throws Exception {
        assertEquals(SA, models.model(SA).type());
        RarModelException e = assertThrows(RarModelException.class, () -> models.model("x"));
        assertEquals(RarModelException.Reason.UNMODELLED_TYPE, e.reason());
        assertEquals("no model for authorization_details type 'x'", e.getMessage());
        RarModels dev = RarModels.load(null, true);
        assertEquals(BuiltIn.COMMON_FIELDS, dev.model("x").type());
        assertEquals(SA, dev.model(SA).type(), "a modelled type never falls back");
    }

    @Test
    void detailsAndParseDetails() throws Exception {
        assertEquals(List.of(), RarModels.parseDetails(null));
        assertEquals(List.of(), RarModels.parseDetails(" "));
        assertEquals(List.of(Map.of("type", SA)), RarModels.parseDetails("[{\"type\":\"sales_agent\"}]"));
        for (String bad : List.of("{", "{}", "[1]", "\"x\"", "[{}, \"x\"]")) {
            RarModelException e = assertThrows(RarModelException.class, () -> RarModels.parseDetails(bad), bad);
            assertEquals(RarModelException.Reason.MALFORMED, e.reason(), bad);
        }
        assertEquals(RarModelException.Reason.MALFORMED, assertThrows(RarModelException.class, () -> RarModels.details(null)).reason());
    }

    @Test
    void validateNamesTheSideAndTheEntry() {
        RarModelException e = assertThrows(RarModelException.class,
                () -> models.validate(List.of(Map.of("type", SA), Map.of("type", SA, "actions", List.of())), "ceiling"));
        assertEquals("ceiling authorization_details[1].actions must not be an empty array", e.getMessage());
        assertEquals("candidate authorization_details[0] has no 'type'",
                assertThrows(RarModelException.class, () -> models.validate(List.of(Map.of("type", "")), "candidate")).getMessage());
        Map<String, Object> nullType = new HashMap<>();
        nullType.put("type", null);
        assertEquals(RarModelException.Reason.MALFORMED,
                assertThrows(RarModelException.class, () -> models.validate(List.of(nullType), "candidate")).reason());
    }

    // ---- what the operations pin ----

    /**
     * CAS §7 rule 1: "The issued authorization_details MUST be a subset of the applicable ceiling. Subset
     * semantics are defined per authorization_details type, following [RFC9396]: for a candidate to be
     * within the ceiling there must be a ceiling object of the same type whose constraints it does not
     * exceed (arrays: subset; numeric limits: ≤; absent ceiling field: unconstrained)."
     */
    @Test
    @Requirement("CAS §7(1)")
    void subsetSemanticsArePerTypeArraysSubsetLimitsAtMostAbsentUnconstrained() throws Exception {
        List<Map<String, Object>> ceiling = details("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\",\"APAC\"],\"max_txn_eur\":5000}]");
        assertTrue(models.contains(ceiling, details("[{\"type\":\"sales_agent\",\"sales_regions\":[\"APAC\"],\"max_txn_eur\":5000,"
                + "\"actions\":[\"anything at all\"]}]")), "array subset, limit equal, absent field unconstrained");
        assertFalse(models.contains(ceiling, details("[{\"type\":\"sales_agent\",\"sales_regions\":[\"AMER\"],\"max_txn_eur\":1}]")),
                "array not a subset");
        assertFalse(models.contains(ceiling, details("[{\"type\":\"sales_agent\",\"sales_regions\":[\"APAC\"],\"max_txn_eur\":5000.01}]")),
                "limit exceeded");
        assertFalse(models.contains(ceiling, details("[{\"type\":\"payment_initiation\",\"actions\":[\"initiate\"]}]")),
                "no ceiling object of the same type");
    }

    /** CAS §7 rule 1, "a ceiling object": one object, never the union of several of the same type. */
    @Test
    @Requirement("CAS §7(1)")
    void aCandidateMustFitOneCeilingObject() throws Exception {
        List<Map<String, Object>> ceiling = details("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]},"
                + "{\"type\":\"sales_agent\",\"sales_regions\":[\"APAC\"]}]");
        assertFalse(models.contains(ceiling, details("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\",\"APAC\"]}]")));
        assertTrue(models.contains(ceiling, details("[{\"type\":\"sales_agent\",\"sales_regions\":[\"APAC\"]}]")));
    }

    /**
     * CAS §7 rule 2: "An empty or absent authorization_details request means the instance asks for its
     * full ceiling; the CAS issues the ceiling of the matched binding." {@link RarModels#fullCeiling} is
     * the ceiling, validated, as a copy the caller may issue; the ceiling is within itself.
     */
    @Test
    @Requirement("CAS §7(2)")
    void fullCeilingIsTheCeilingItselfValidatedAndCopied() throws Exception {
        List<Map<String, Object>> ceiling = details("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]},"
                + "{\"type\":\"payment_initiation\",\"instructedAmount\":{\"currency\":\"EUR\",\"amount\":\"100\"}}]");
        List<Map<String, Object>> full = models.fullCeiling(ceiling);
        assertEquals(Json.write(ceiling), Json.write(full));
        assertNotSame(ceiling.get(0), full.get(0));
        assertTrue(models.contains(ceiling, full));
        assertEquals(List.of(), models.authorize(List.of(), ceiling, Omission.INHERIT), "authorize itself grants nothing for nothing");
        assertEquals(RarModelException.Reason.MALFORMED, assertThrows(RarModelException.class,
                () -> models.fullCeiling(details("[{\"type\":\"sales_agent\",\"sales_regions\":[]}]"))).reason());
    }

    /**
     * CAS §7 rule 3: "A request exceeding the ceiling is handled per the advertised narrowing_behavior:
     * "reject" → access_denied; "narrow" → issue the intersection." Reject is {@link RarModels#authorize}
     * refusing with {@code EXCEEDS_CEILING}; narrow is {@link RarModels#intersect}.
     */
    @Test
    @Requirement("CAS §7(3)")
    void rejectRefusesAndNarrowIsTheIntersection() throws Exception {
        List<Map<String, Object>> ceiling = details("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":5000}]");
        List<Map<String, Object>> request = details("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\",\"APAC\"],\"max_txn_eur\":9000}]");
        RarModelException e = assertThrows(RarModelException.class, () -> models.authorize(request, ceiling, Omission.INHERIT));
        assertEquals(RarModelException.Reason.EXCEEDS_CEILING, e.reason());
        assertEquals("candidate authorization_details[0] of type 'sales_agent' is not within the ceiling", e.getMessage());
        List<Map<String, Object>> narrowed = models.intersect(request, ceiling);
        assertEquals("[{\"max_txn_eur\":5000,\"sales_regions\":[\"EMEA\"],\"type\":\"sales_agent\"}]", Json.write(narrowed));
        assertTrue(models.contains(ceiling, narrowed));
    }

    /**
     * CAS §7.1: an authorization server "MUST, when authenticating a client via an attestation
     * containing authorization_details, ensure that any authority granted in issued tokens is a subset
     * of the attestation's authorization_details (same subset semantics as Section 7 rule 1), and MUST
     * reject requests exceeding it with invalid_authorization_details [RFC9396]." What
     * {@link RarModels#authorize} returns is within the ceiling by its own post-condition, and what
     * exceeds it is refused with a reason the AS maps to that error.
     */
    @Test
    @Requirement("CAS §7.1")
    void grantedAuthorityIsWithinTheAttestedCeilingAndExcessIsRefused() throws Exception {
        List<Map<String, Object>> attested = details("[{\"type\":\"payment_initiation\",\"actions\":[\"initiate\",\"status\"],"
                + "\"instructedAmount\":{\"currency\":\"EUR\",\"amount\":\"123.50\"}}]");
        List<Map<String, Object>> granted = models.authorize(details("[{\"type\":\"payment_initiation\",\"actions\":[\"initiate\"]}]"),
                attested, Omission.INHERIT);
        assertTrue(models.contains(attested, granted));
        assertEquals("[{\"actions\":[\"initiate\"],\"instructedAmount\":{\"amount\":\"123.50\",\"currency\":\"EUR\"},"
                + "\"type\":\"payment_initiation\"}]", Json.write(granted));
        RarModelException e = assertThrows(RarModelException.class, () -> models.authorize(
                details("[{\"type\":\"payment_initiation\",\"actions\":[\"initiate\"],\"instructedAmount\":{\"currency\":\"EUR\",\"amount\":\"200\"}}]"),
                attested, Omission.INHERIT));
        assertEquals(RarModelException.Reason.EXCEEDS_CEILING, e.reason());
    }

    /** The post-condition guard fires on a grant outside the ceiling, which only a defect could produce. */
    @Test
    void thePostConditionGuardFiresOnADefectiveGrant() throws Exception {
        List<Map<String, Object>> ceiling = details("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]");
        models.assertWithin(ceiling, details("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]"));
        assertThrows(IllegalStateException.class,
                () -> models.assertWithin(ceiling, details("[{\"type\":\"sales_agent\",\"sales_regions\":[\"APAC\"]}]")));
    }

    /**
     * RFC 9396 §6.1: "Since the semantics of the fields in the authorization_details will be
     * implementation specific to a given API or set of APIs, there is no standardized mechanism to
     * compare two arbitrary authorization detail requests. An AS should not rely on simple object
     * comparison in most cases". The comparison is the type's model, so a field no model declares is
     * refused rather than compared as a bare object, and the section's own example - "verify that the
     * authorization code issued in the previous step contains an authorization details object of type
     * account_information, verify whether the approved list of actions contains list_accounts, and
     * verify whether the locations value includes only previously approved locations" - holds.
     */
    @Test
    @Requirement("RFC9396 §6.1")
    void comparisonIsTheTypesOwnNotObjectComparison() throws Exception {
        List<Map<String, Object>> approved = details("[{\"type\":\"account_information\",\"actions\":[\"list_accounts\",\"read_balances\","
                + "\"read_transactions\"],\"locations\":[\"https://example.com/accounts\"]},{\"type\":\"payment_initiation\","
                + "\"actions\":[\"initiate\",\"status\",\"cancel\"],\"locations\":[\"https://example.com/payments\"]}]");
        assertTrue(models.contains(approved, details("[{\"type\":\"account_information\",\"actions\":[\"list_accounts\"],"
                + "\"locations\":[\"https://example.com/accounts\"]}]")), "Figure 10, the reduced privileges");
        assertFalse(models.contains(approved, details("[{\"type\":\"account_information\",\"actions\":[\"list_accounts\"],"
                + "\"locations\":[\"https://other.example.com/accounts\"]}]")), "a location not previously approved");
        RarModelException e = assertThrows(RarModelException.class,
                () -> models.contains(approved, details("[{\"type\":\"account_information\",\"actions\":[\"list_accounts\"],\"tier\":\"gold\"}]")));
        assertEquals(RarModelException.Reason.UNDECLARED_FIELD, e.reason(), "a field the type does not define is not compared, it is refused");
    }

    /**
     * RFC 9396 §2.2: "locations: An array of strings", "actions: An array of strings", "datatypes: An
     * array of strings", "identifier: A string identifier indicating a specific resource", "privileges:
     * An array of strings". Every built-in type carries the five with those shapes.
     */
    @Test
    @Requirement("RFC9396 §2.2")
    void commonDataFieldsAreArraysOfStringsAndAnIdentifier() throws Exception {
        for (String type : List.of(SA, PI, AI)) {
            TypeModel m = models.model(type);
            for (String set : List.of("locations", "actions", "datatypes", "privileges")) {
                assertEquals(Rule.SET, m.fields().get(set).rule(), type + "." + set);
            }
            assertEquals(Rule.EQUAL, m.fields().get("identifier").rule(), type + ".identifier");
            List<Map<String, Object>> ceiling = details("[{\"type\":\"" + type + "\",\"locations\":[\"https://a\",\"https://b\"],"
                    + "\"actions\":[\"read\",\"write\"],\"datatypes\":[\"contacts\",\"photos\"],\"privileges\":[\"admin\"],\"identifier\":\"r1\"}]");
            assertTrue(models.contains(ceiling, details("[{\"type\":\"" + type + "\",\"locations\":[\"https://a\"],\"actions\":[\"read\"],"
                    + "\"datatypes\":[\"photos\"],\"privileges\":[\"admin\"],\"identifier\":\"r1\"}]")), type);
            assertFalse(models.contains(ceiling, details("[{\"type\":\"" + type + "\",\"locations\":[\"https://a\"],\"actions\":[\"read\"],"
                    + "\"datatypes\":[\"photos\"],\"privileges\":[\"admin\"],\"identifier\":\"r2\"}]")), type + " identifier");
            RarModelException e = assertThrows(RarModelException.class,
                    () -> models.contains(ceiling, details("[{\"type\":\"" + type + "\",\"actions\":\"read\"}]")));
            assertEquals(RarModelException.Reason.MALFORMED, e.reason(), type + " actions must be an array");
        }
    }

    /**
     * PROFILE §7(1): a deployment "SHALL treat the claim as attester-asserted authority, not
     * caller-supplied - an authorization server MUST NOT accept a value for this claim from anywhere
     * other than the verified attestation itself." Where the ceiling comes from is the authenticator's
     * job (wired in S1b); what this library pins is the "not caller-supplied" half: nothing in a
     * candidate can stand in for, widen or replace the ceiling's value of a field - not a wider value,
     * not the bookkeeping names this repo's own components add after the check.
     */
    @Test
    @Requirement("PROFILE §7(1)")
    void nothingTheCallerSendsBecomesCeiling() throws Exception {
        List<Map<String, Object>> ceiling = details("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":100}]");
        assertFalse(models.contains(ceiling, details("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\",\"APAC\"],\"max_txn_eur\":100}]")));
        assertFalse(models.contains(ceiling, details("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":101}]")));
        for (String smuggled : List.of("_agent_id", "_principal_sub")) {
            RarModelException e = assertThrows(RarModelException.class, () -> models.contains(ceiling,
                    details("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":100,\"" + smuggled + "\":\"x\"}]")));
            assertEquals(RarModelException.Reason.MALFORMED, e.reason(), smuggled);
            assertTrue(e.getMessage().contains("forbidden"), e.getMessage());
        }
        List<Map<String, Object>> granted = models.authorize(details("[{\"type\":\"sales_agent\"}]"), ceiling, Omission.INHERIT);
        assertEquals(Json.write(ceiling), Json.write(granted), "what the caller left silent is the ceiling's, never wider");
    }

    /**
     * PROFILE §7(2): a deployment "SHOULD enforce that any authorization_details granted downstream is
     * a subset of the attested entitlement ("containment": requested ⊆ attested)."
     */
    @Test
    @Requirement("PROFILE §7(2)")
    void grantedDetailsAreASubsetOfTheAttestedEntitlement() throws Exception {
        List<Map<String, Object>> attested = details("[{\"type\":\"account_information\",\"accounts\":[{\"iban\":\"DE1\"},{\"iban\":\"DE2\"}],"
                + "\"validUntil\":\"2026-12-31\"}]");
        for (Omission mode : Omission.values()) {
            List<Map<String, Object>> granted = models.authorize(details("[{\"type\":\"account_information\",\"accounts\":[{\"iban\":\"DE2\"}],"
                    + "\"validUntil\":\"2026-06-30T00:00:00Z\"}]"), attested, mode);
            assertTrue(models.contains(attested, granted), mode.name());
            RarModelException e = assertThrows(RarModelException.class, () -> models.authorize(
                    details("[{\"type\":\"account_information\",\"accounts\":[{\"iban\":\"DE3\"}],\"validUntil\":\"2026-06-30T00:00:00Z\"}]"),
                    attested, mode), mode.name());
            assertEquals(RarModelException.Reason.EXCEEDS_CEILING, e.reason(), mode.name());
        }
    }

    @Test
    void authorizeUnderStrictChecksTheCandidateBeforeFitting() throws Exception {
        List<Map<String, Object>> ceiling = details("[{\"type\":\"sales_agent\"}]");
        RarModelException e = assertThrows(RarModelException.class,
                () -> models.authorize(details("[{\"type\":\"sales_agent\",\"discount\":1}]"), ceiling, Omission.STRICT));
        assertEquals(RarModelException.Reason.UNDECLARED_FIELD, e.reason());
        assertEquals("candidate authorization_details[0] carries 'discount', which type 'sales_agent' does not declare", e.getMessage());
    }

    @Test
    void outputsNeverAliasInputs() throws Exception {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("type", SA);
        entry.put("sales_regions", new ArrayList<>(List.of("EMEA")));
        List<Map<String, Object>> ceiling = List.of(entry);
        List<Map<String, Object>> granted = models.authorize(details("[{\"type\":\"sales_agent\"}]"), ceiling, Omission.INHERIT);
        List<Map<String, Object>> strict = models.authorize(ceiling, ceiling, Omission.STRICT);
        List<Map<String, Object>> meet = models.intersect(ceiling, ceiling);
        ((List<Object>) entry.get("sales_regions")).add("APAC");
        assertEquals(List.of("EMEA"), granted.get(0).get("sales_regions"));
        assertEquals(List.of("EMEA"), strict.get(0).get("sales_regions"));
        assertEquals(List.of("EMEA"), meet.get(0).get("sales_regions"));
    }
}
