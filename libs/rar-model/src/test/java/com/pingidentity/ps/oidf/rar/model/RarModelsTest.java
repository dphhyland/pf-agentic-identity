/*
 * The facade: loading from the environment, the fingerprint, and the clauses the operations pin.
 */
package com.pingidentity.ps.oidf.rar.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
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
        assertTrue(models.canonicalJson().startsWith("{\"common_fields_fallback\":false,\"semantics\":1,\"types\":{\"account_information\":{\"fields\":{"),
                models.canonicalJson());
        assertTrue(models.canonicalJson().contains("\"payment_initiation\":{\"alternatives\":[[[\"instructedAmount\"],[\"amount\",\"currency\"]]],"),
                "the alternatives are part of the model the fingerprint covers");
    }

    /** The public load is production's: only the environment's profile turns the fallback on. */
    @Test
    void publicLoadHasNoFallback() throws Exception {
        RarModels loaded = RarModels.load("{\"types\":{\"x\":{\"fields\":{\"a\":\"set\"}}}}");
        assertFalse(loaded.commonFieldsFallback());
        assertEquals(RarModelException.Reason.UNMODELLED_TYPE, assertThrows(RarModelException.class, () -> loaded.model("y")).reason());
        assertEquals(models.fingerprint(), RarModels.load(null).fingerprint());
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
        RarModelException junk = assertThrows(RarModelException.class, () -> models.authorize(
                details("[{\"type\":\"sales_agent\",\"actions\":[\"a\"]}]"), List.of(), Omission.INHERIT));
        assertEquals("candidate authorization_details[0] of type 'sales_agent' is not within the ceiling", junk.getMessage());
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
     * An array of strings". Every built-in type carries the five with those shapes: four sets of
     * strings, and an identifier that is a string - a number or an object there is malformed.
     */
    @Test
    @Requirement("RFC9396 §2.2")
    void commonDataFieldsAreArraysOfStringsAndAnIdentifier() throws Exception {
        for (String type : List.of(SA, PI, AI)) {
            TypeModel m = models.model(type);
            for (String set : List.of("locations", "actions", "datatypes", "privileges")) {
                assertEquals(Rule.SET, m.fields().get(set).rule(), type + "." + set);
            }
            assertEquals(Rule.STRING, m.fields().get("identifier").rule(), type + ".identifier");
            for (String bad : List.of("42", "{\"$ne\":null}", "[\"r1\"]")) {
                RarModelException e = assertThrows(RarModelException.class,
                        () -> models.validate(details("[{\"type\":\"" + type + "\",\"identifier\":" + bad + "}]"), "candidate"));
                assertEquals(RarModelException.Reason.MALFORMED, e.reason(), type + " identifier " + bad);
            }
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

    /** Names from a request reach a message escaped and cut, so a name cannot forge a log line or fill one. */
    @Test
    void namesInMessagesAreQuotedEscapedAndCut() throws Exception {
        assertEquals("'a'", RarModelException.quote("a"));
        assertEquals("'a\\u000ab\\u0027c\\u005cd\\u007f'", RarModelException.quote("a\nb'c\\d\u007f"));
        assertEquals("'" + "x".repeat(64) + "...'", RarModelException.quote("x".repeat(65)));
        assertEquals("'" + "x".repeat(64) + "'", RarModelException.quote("x".repeat(64)));
        assertEquals("'a\\u0085b\\u2028c\\u2029d\\u202ee\\u200bf\\ufeffg\\u009bh'",
                RarModelException.quote("a\u0085b c d‮e​f﻿g\u009bh"),
                "NEL and the separators end a line for some log pipelines; the bidi override and zero-width characters change what an operator reads");
        assertEquals("'\\ud83d\\ude00'", RarModelException.quote("😀"), "each half of a surrogate pair, so a cut never splits one");
        assertEquals("'" + "x".repeat(63) + "\\ud83d...'", RarModelException.quote("x".repeat(63) + "😀"));
        assertEquals("'café 日本'", RarModelException.quote("café 日本"), "letters from any script are shown as they are");
        assertEquals("null", RarModelException.quote(null));
        RarModelException e = assertThrows(RarModelException.class,
                () -> models.contains(List.of(Map.of("type", SA)), List.of(Map.of("type", SA, "bad\nname", 1))));
        assertEquals("candidate authorization_details[0] carries 'bad\\u000aname', which type 'sales_agent' does not declare", e.getMessage());
        RarModelException nel = assertThrows(RarModelException.class,
                () -> models.contains(List.of(Map.of("type", SA)), List.of(Map.of("type", SA, "x\u0085y z‮", 1))));
        assertEquals("candidate authorization_details[0] carries 'x\\u0085y\\u2028z\\u202e', which type 'sales_agent' does not declare",
                nel.getMessage());
        RarModelException t = assertThrows(RarModelException.class, () -> models.model("x\u0000y"));
        assertEquals("no model for authorization_details type 'x\\u0000y'", t.getMessage());
        RarModelException deep = assertThrows(RarModelException.class, () -> models.validate(
                List.of(Map.of("type", PI, "creditorAccount", Map.of("k\ty", "x".repeat(2049)))), "candidate"));
        assertEquals("candidate authorization_details[0].'creditorAccount'.'k\\u0009y' is a string longer than 2048", deep.getMessage(),
                "the size walk runs before any name is known to be declared, so it quotes every one");
    }

    /** Under INHERIT a malformed candidate is malformed whatever the ceiling holds, and a limit without its unit waits for inheritance. */
    @Test
    void inheritChecksValuesBeforeFittingAndPairingAfter() throws Exception {
        RarModelException e = assertThrows(RarModelException.class,
                () -> models.authorize(details("[{\"type\":\"sales_agent\",\"actions\":[]}]"), List.of(), Omission.INHERIT));
        assertEquals(RarModelException.Reason.MALFORMED, e.reason(), "not EXCEEDS_CEILING: the shape is wrong before the ceiling matters");
        RarModelException u = assertThrows(RarModelException.class,
                () -> models.authorize(details("[{\"type\":\"payment_initiation\",\"discount\":1}]"), List.of(), Omission.INHERIT));
        assertEquals(RarModelException.Reason.UNDECLARED_FIELD, u.reason());
        List<Map<String, Object>> granted = models.authorize(details("[{\"type\":\"payment_initiation\",\"amount\":\"42.00\"}]"),
                details("[{\"type\":\"payment_initiation\",\"amount\":\"100.00\",\"currency\":\"EUR\"}]"), Omission.INHERIT);
        assertEquals("[{\"amount\":\"42.00\",\"currency\":\"EUR\",\"type\":\"payment_initiation\"}]", Json.write(granted));
        RarModelException p = assertThrows(RarModelException.class,
                () -> models.authorize(details("[{\"type\":\"payment_initiation\",\"amount\":\"42.00\"}]"),
                        details("[{\"type\":\"payment_initiation\"}]"), Omission.INHERIT));
        assertEquals(RarModelException.Reason.MALFORMED, p.reason(), "no currency to inherit: the pairing rule refuses the fitted detail");
    }

    /** The same inheritance one level down: a limit inside an object takes its unit from the entry's object. */
    @Test
    void inheritPairsANestedLimitWithTheCeilingsUnit() throws Exception {
        RarModels nested = RarModels.load("{\"types\":{\"t\":{\"fields\":{\"o\":{\"rule\":\"object\",\"fields\":{"
                + "\"budget\":{\"rule\":\"limit\",\"unit_field\":\"cur\"},\"cur\":\"string\"}}}}}}");
        List<Map<String, Object>> ceiling = details("[{\"type\":\"t\",\"o\":{\"budget\":10,\"cur\":\"EUR\"}}]");
        List<Map<String, Object>> candidate = details("[{\"type\":\"t\",\"o\":{\"budget\":5}}]");
        assertEquals("[{\"o\":{\"budget\":5,\"cur\":\"EUR\"},\"type\":\"t\"}]", Json.write(nested.authorize(candidate, ceiling, Omission.INHERIT)));
        RarModelException strict = assertThrows(RarModelException.class, () -> nested.authorize(candidate, ceiling, Omission.STRICT));
        assertEquals(RarModelException.Reason.MALFORMED, strict.reason());
        assertTrue(strict.getMessage().endsWith(".o.budget needs cur beside it"), strict.getMessage());
        RarModelException none = assertThrows(RarModelException.class,
                () -> nested.authorize(candidate, details("[{\"type\":\"t\"}]"), Omission.INHERIT));
        assertEquals(RarModelException.Reason.MALFORMED, none.reason(), "an entry with no unit to give leaves the limit unpaired");
        assertThrows(RarModelException.class, () -> nested.validate(candidate, "candidate"), "validate pairs units at every depth");
        RarModelException over = assertThrows(RarModelException.class,
                () -> nested.authorize(details("[{\"type\":\"t\",\"o\":{\"budget\":11}}]"), ceiling, Omission.INHERIT));
        assertEquals(RarModelException.Reason.EXCEEDS_CEILING, over.reason());
    }

    /** A null or blank type is a malformed request and a null rule name an invalid model, never a NullPointerException. */
    @Test
    void aNullTypeOrRuleIsRefusedWithItsReason() throws Exception {
        RarModels development = RarModels.load(null, true);
        for (String type : new String[] {null, "", " \t"}) {
            RarModelException e = assertThrows(RarModelException.class, () -> models.model(type));
            assertEquals(RarModelException.Reason.MALFORMED, e.reason());
            assertEquals("an authorization_details type must be a non-blank string", e.getMessage());
            RarModelException d = assertThrows(RarModelException.class, () -> development.model(type));
            assertEquals(RarModelException.Reason.MALFORMED, d.reason(), "not the common-fields fallback, even in development");
        }
        RarModelException r = assertThrows(RarModelException.class, () -> Rule.fromJson(null));
        assertEquals(RarModelException.Reason.MODEL_INVALID, r.reason());
        assertEquals("unknown rule null", r.getMessage());
    }

    @Test
    void authorizeNeedsAMode() throws Exception {
        List<Map<String, Object>> ceiling = details("[{\"type\":\"sales_agent\"}]");
        assertThrows(NullPointerException.class, () -> models.authorize(ceiling, ceiling, null));
    }

    /**
     * CAS §7 rule 1: "for a candidate to be within the ceiling there must be a ceiling object of the same
     * type whose constraints it does not exceed". A constraint on an amount is one constraint however the
     * amount is spelt, so the review's cross-spelling cases (2026-09-27), each of which was granted before
     * alternatives, are refused: a ceiling that constrains the amount one way holds the request to that way.
     */
    @Test
    @Requirement("CAS §7(1)")
    void anAmountSaidTheOtherWayIsNotWithinTheCeiling() throws Exception {
        List<Map<String, Object>> instructed = details("[{\"type\":\"payment_initiation\",\"instructedAmount\":{\"amount\":\"100\",\"currency\":\"EUR\"}}]");
        assertEquals(RarModelException.Reason.MALFORMED, assertThrows(RarModelException.class, () -> models.contains(instructed,
                details("[{\"type\":\"payment_initiation\",\"instructedAmount\":{\"amount\":\"50\",\"currency\":\"EUR\"},"
                        + "\"amount\":\"1000000\",\"currency\":\"USD\"}]"))).reason(), "both spellings in one detail");
        assertEquals(RarModelException.Reason.EXCEEDS_CEILING, assertThrows(RarModelException.class, () -> models.authorize(
                details("[{\"type\":\"payment_initiation\",\"amount\":\"1000000\",\"currency\":\"USD\"}]"), instructed, Omission.INHERIT))
                .reason(), "the flat amount is not filled with instructedAmount beside it and granted");
        List<Map<String, Object>> flat = details("[{\"type\":\"payment_initiation\",\"amount\":\"42\",\"currency\":\"AUD\"}]");
        assertFalse(models.contains(flat, details("[{\"type\":\"payment_initiation\",\"amount\":\"42\",\"currency\":\"AUD\"},"
                + "{\"type\":\"payment_initiation\",\"instructedAmount\":{\"amount\":\"1000000\",\"currency\":\"AUD\"}}]")));
    }

    /** RFC 9396 §7.1's access object is not in the built-in account_information, so an account cannot be named a second way. */
    @Test
    void accountsHaveOneSpelling() throws Exception {
        List<Map<String, Object>> ceiling = details("[{\"type\":\"account_information\",\"accounts\":[\"A\"]}]");
        RarModelException e = assertThrows(RarModelException.class, () -> models.authorize(
                details("[{\"type\":\"account_information\",\"access\":{\"transactions\":[\"B\"]}}]"), ceiling, Omission.INHERIT));
        assertEquals(RarModelException.Reason.UNDECLARED_FIELD, e.reason());
    }

    /** A meet is a list like any other: past sixteen entries nothing could take it, so it is refused. */
    @Test
    void aMeetOfMoreThanSixteenEntriesIsTooLarge() throws Exception {
        List<Map<String, Object>> regions = new ArrayList<>();
        List<Map<String, Object>> actions = new ArrayList<>();
        for (int i = 0; i < Limits.MAX_DETAILS; i++) {
            regions.add(Map.of("type", SA, "sales_regions", List.of("r" + i)));
            actions.add(Map.of("type", SA, "actions", List.of("a" + i)));
        }
        RarModelException e = assertThrows(RarModelException.class, () -> models.intersect(regions, actions));
        assertEquals(RarModelException.Reason.TOO_LARGE, e.reason());
        assertEquals("the intersection has more than 16 entries", e.getMessage());
        assertEquals(Limits.MAX_DETAILS, models.intersect(regions, List.of(Map.of("type", SA, "actions", List.of("a")))).size());
    }

    /** Text is bounded before the reader starts, and what the reader refuses for size is too large, not malformed. */
    @Test
    void parseDetailsRefusesSizeAsTooLarge() {
        String padded = "[" + " ".repeat(Limits.MAX_TEXT) + "]";
        RarModelException text = assertThrows(RarModelException.class, () -> RarModels.parseDetails(padded));
        assertEquals(RarModelException.Reason.TOO_LARGE, text.reason());
        assertEquals("authorization_details is longer than 262144 characters", text.getMessage());
        RarModelException number = assertThrows(RarModelException.class,
                () -> RarModels.parseDetails("[{\"type\":\"sales_agent\",\"max_txn_eur\":1" + "0".repeat(200) + "}]"));
        assertEquals(RarModelException.Reason.TOO_LARGE, number.reason());
        assertTrue(number.getMessage().startsWith("authorization_details is too large to read: JSON: a number longer than 128"),
                number.getMessage());
        RarModelException nested = assertThrows(RarModelException.class, () -> RarModels.parseDetails("[".repeat(40) + "]".repeat(40)));
        assertEquals(RarModelException.Reason.TOO_LARGE, nested.reason());
    }

    /**
     * The review's measurements (2026-09-27): a 60-byte detail allocated a gigabyte, others threw
     * exceptions outside the contract, a 100 KB literal took 8 s. Each is now a refusal with its reason,
     * at once.
     */
    @Test
    void numbersAndDatesCannotRunAwayWithTheWork() {
        List<Map<String, Object>> ceiling;
        try {
            ceiling = details("[{\"type\":\"payment_initiation\",\"amount\":100,\"currency\":\"EUR\"}]");
        } catch (RarModelException e) {
            throw new AssertionError(e);
        }
        for (String number : List.of("1e999999999", "1e2147483647", "100e2147483647", "1e-999999999")) {
            String request = "[{\"type\":\"payment_initiation\",\"amount\":\"50\",\"currency\":" + number + "}]";
            RarModelException e = assertThrows(RarModelException.class, () -> models.contains(ceiling, details(request)), number);
            assertEquals(RarModelException.Reason.TOO_LARGE, e.reason(), number);
            RarModelException a = assertThrows(RarModelException.class,
                    () -> models.authorize(details(request), ceiling, Omission.INHERIT), number);
            assertEquals(RarModelException.Reason.TOO_LARGE, a.reason(), number);
        }
        RarModelException date = assertThrows(RarModelException.class, () -> models.contains(
                details("[{\"type\":\"account_information\"}]"),
                details("[{\"type\":\"account_information\",\"validUntil\":\"+999999999-12-31\"}]")));
        assertEquals(RarModelException.Reason.MALFORMED, date.reason());
        String literal = "[{\"type\":\"sales_agent\",\"max_txn_eur\":1" + "0".repeat(100_000) + "}]";
        RarModelException big = assertTimeout(Duration.ofSeconds(5),
                () -> assertThrows(RarModelException.class, () -> models.contains(ceiling, details(literal))));
        assertEquals(RarModelException.Reason.TOO_LARGE, big.reason());
    }

    @Test
    void outputsNeverAliasInputs() throws Exception {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("type", SA);
        entry.put("sales_regions", new ArrayList<>(List.of("EMEA")));
        List<Map<String, Object>> ceiling = List.of(entry);
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("type", SA);
        request.put("actions", new ArrayList<>(List.of("read")));
        List<Map<String, Object>> granted = models.authorize(details("[{\"type\":\"sales_agent\"}]"), ceiling, Omission.INHERIT);
        List<Map<String, Object>> inherited = models.authorize(List.of(request), ceiling, Omission.INHERIT);
        List<Map<String, Object>> strict = models.authorize(ceiling, ceiling, Omission.STRICT);
        List<Map<String, Object>> meet = models.intersect(ceiling, ceiling);
        ((List<Object>) entry.get("sales_regions")).add("APAC");
        ((List<Object>) request.get("actions")).add("write");
        assertEquals(List.of("EMEA"), granted.get(0).get("sales_regions"));
        assertEquals(List.of("read"), inherited.get(0).get("actions"), "the candidate's own values are copied too");
        assertEquals(List.of("EMEA"), strict.get(0).get("sales_regions"));
        assertEquals(List.of("EMEA"), meet.get(0).get("sales_regions"));
    }
}
