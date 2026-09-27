package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModelException.Reason;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The authorization server's ceiling check, on its own: a request's {@code authorization_details} text against
 * the {@code authorization_details} claim of a Client Attestation the verifier has already verified. The gate
 * never looks at the signature, so the attestations here are payloads with a placeholder header and signature;
 * {@link ClientAttestationVerifierTest} and {@link AsVectorRunnerTest} drive it through a real verification.
 *
 * <p>CAS §7.1, the rule this enforces: "an authorization server participating in a deployment of this
 * specification MUST, when authenticating a client via an attestation containing {@code authorization_details},
 * ensure that any authority granted in issued tokens is a subset of the attestation's
 * {@code authorization_details} (same subset semantics as Section 7 rule 1), and MUST reject requests exceeding
 * it with {@code invalid_authorization_details} [RFC9396]."
 */
class AuthorizationDetailsGateTest {
    private static final RarModels MODELS = RarModels.builtIn();

    private static final String SALES_CEILING = "[{\"type\":\"sales_agent\","
            + "\"actions\":[\"read_accounts\",\"create_opportunity\"],\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":5000}]";

    /** A compact JWS whose payload is {@code claimsJson}; the gate reads only the payload. */
    private static String attestation(String claimsJson) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString("{\"alg\":\"ES256\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(claimsJson.getBytes(StandardCharsets.UTF_8)) + ".c2lnbmF0dXJl";
    }

    private static String withCeiling(String ceilingJson) {
        return attestation("{\"iss\":\"https://attester.example.com\",\"sub\":\"https://rp.example.com\","
                + "\"authorization_details\":" + ceilingJson + "}");
    }

    private static ClientAttestationException refused(String requested, String attestationJwt) {
        return assertThrows(ClientAttestationException.class,
                () -> AuthorizationDetailsGate.check(MODELS, requested, attestationJwt));
    }

    private static Reason causeOf(ClientAttestationException e) {
        return assertInstanceOf(RarModelException.class, e.getCause(), "the model's reason rides as the cause").reason();
    }

    // ---- within, and not ------------------------------------------------------------------------------

    @Test
    @Requirement("CAS §7.1")
    void aRequestWithinTheAttestationsDetailsIsGrantedAsSent() throws Exception {
        String requested = "[{\"type\":\"sales_agent\",\"actions\":[\"create_opportunity\"],"
                + "\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":\"250.00\"}]";

        List<Map<String, Object>> granted = AuthorizationDetailsGate.check(MODELS, requested, withCeiling(SALES_CEILING));

        assertEquals(1, granted.size());
        assertEquals(List.of("create_opportunity"), granted.get(0).get("actions"));
        assertEquals("250.00", granted.get(0).get("max_txn_eur"), "the grant is the request's own, not a filled copy");
    }

    /**
     * Blocker B1: a scalar the old check never compared. CAS §7 rule 1 gives "numeric limits: ≤", and the
     * attestation's {@code max_txn_eur} is 5000.
     */
    @Test
    @Requirement({"CAS §7.1", "CAS §7(1)"})
    void aLimitAboveTheAttestationsIsRefusedAsExceedingIt() {
        String requested = "[{\"type\":\"sales_agent\",\"actions\":[\"create_opportunity\"],"
                + "\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":5000.01}]";

        ClientAttestationException e = refused(requested, withCeiling(SALES_CEILING));

        assertEquals(ClientAttestationException.INVALID_AUTHORIZATION_DETAILS, e.error());
        assertEquals(AuthorizationDetailsGate.EXCEEDS, e.getMessage());
        assertEquals(Reason.EXCEEDS_CEILING, causeOf(e));
        assertTrue(e.getCause().getMessage().contains("authorization_details[0]") && e.getCause().getMessage().contains("'sales_agent'")
                        && !e.getCause().getMessage().contains("5000.01"),
                "the log line names the detail and its type, never the value: " + e.getCause().getMessage());
    }

    /**
     * The log's reason for "not within" is the model's own: the first detail no attestation entry contains. Asked
     * only once {@code contains} has said no; were the strict {@code authorize} to grant after all, the reason stays
     * a generic one rather than none.
     */
    @Test
    void theReasonForNotWithinNamesTheFirstDetailOutside() throws Exception {
        java.util.List<Map<String, Object>> ceiling = RarModels.parseDetails(SALES_CEILING);
        java.util.List<Map<String, Object>> twoDetails = RarModels.parseDetails(
                "[{\"type\":\"sales_agent\",\"actions\":[\"read_accounts\"],\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":1},"
                        + "{\"type\":\"sales_agent\",\"actions\":[\"read_accounts\"],\"sales_regions\":[\"APAC\"],\"max_txn_eur\":1}]");
        RarModelException why = AuthorizationDetailsGate.whyNotWithin(MODELS, ceiling, twoDetails);
        assertEquals(Reason.EXCEEDS_CEILING, why.reason());
        assertTrue(why.getMessage().contains("authorization_details[1]"), why.getMessage());

        RarModelException generic = AuthorizationDetailsGate.whyNotWithin(MODELS, ceiling, twoDetails.subList(0, 1));
        assertEquals(Reason.EXCEEDS_CEILING, generic.reason(), "a detail that is within gets the generic reason");
        assertEquals("authorization_details is not within the client attestation's", generic.getMessage());
    }

    /** Blocker B1 for a payment: a different creditor account is not within an attestation that names one. */
    @Test
    @Requirement({"CAS §7.1", "CAS §7(1)"})
    void aPaymentToAnotherCreditorIsRefused() {
        String ceiling = "[{\"type\":\"payment_initiation\",\"instructedAmount\":{\"currency\":\"EUR\",\"amount\":\"500.00\"},"
                + "\"creditorAccount\":{\"iban\":\"DE02100100109307118603\"}}]";
        String requested = "[{\"type\":\"payment_initiation\",\"instructedAmount\":{\"currency\":\"EUR\",\"amount\":\"20.00\"},"
                + "\"creditorAccount\":{\"iban\":\"GB29NWBK60161331926819\"}}]";

        assertEquals(AuthorizationDetailsGate.EXCEEDS, refused(requested, withCeiling(ceiling)).getMessage());
    }

    /**
     * The gate is strict: a field the attestation constrains and the request leaves out is not contained, and is
     * not filled in. What passes here is what PingFederate issues, and a detail with no {@code sales_regions}
     * constrains no region.
     */
    @Test
    @Requirement("CAS §7.1")
    void aFieldTheAttestationConstrainsAndTheRequestLeavesOutIsRefusedNotFilledIn() {
        String requested = "[{\"type\":\"sales_agent\",\"actions\":[\"create_opportunity\"],\"max_txn_eur\":100}]";

        ClientAttestationException e = refused(requested, withCeiling(SALES_CEILING));

        assertEquals(ClientAttestationException.INVALID_AUTHORIZATION_DETAILS, e.error());
        assertEquals(AuthorizationDetailsGate.EXCEEDS, e.getMessage());
    }

    /** CAS §7 rule 1: "absent ceiling field: unconstrained". */
    @Test
    @Requirement("CAS §7(1)")
    void aFieldTheAttestationLeavesOutIsUnconstrained() throws Exception {
        String ceiling = "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]";
        String requested = "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"actions\":[\"anything\"],"
                + "\"max_txn_eur\":999999}]";

        assertEquals(1, AuthorizationDetailsGate.check(MODELS, requested, withCeiling(ceiling)).size());
    }

    /**
     * RFC 9396 §2.2, the common data fields a built-in type carries: "actions:  An array of strings representing the
     * kinds of actions to be taken at the resource." and "identifier:  A string identifier indicating a specific
     * resource available at the API." An array is within an array when its values are among the attestation's;
     * an identifier only when it is the same string.
     */
    @Test
    @Requirement("RFC9396 §2.2")
    void theCommonDataFieldsAreComparedAsTheirShapesSay() throws Exception {
        String ceiling = "[{\"type\":\"account_information\",\"actions\":[\"list_accounts\",\"read_balances\"],"
                + "\"locations\":[\"https://example.com/accounts\"],\"identifier\":\"acct-123\"}]";

        assertEquals(1, AuthorizationDetailsGate.check(MODELS, "[{\"type\":\"account_information\","
                + "\"actions\":[\"read_balances\"],\"locations\":[\"https://example.com/accounts\"],\"identifier\":\"acct-123\"}]",
                withCeiling(ceiling)).size());
        assertEquals(AuthorizationDetailsGate.EXCEEDS, refused("[{\"type\":\"account_information\","
                + "\"actions\":[\"read_balances\"],\"locations\":[\"https://example.com/accounts\"],\"identifier\":\"acct-999\"}]",
                withCeiling(ceiling)).getMessage());
        assertEquals("authorization_details is malformed", refused("[{\"type\":\"account_information\","
                + "\"actions\":\"read_balances\",\"locations\":[\"https://example.com/accounts\"],\"identifier\":\"acct-123\"}]",
                withCeiling(ceiling)).getMessage());
    }

    /**
     * RFC 9396 §6.1: "The details of this comparison are dependent on the definition of the type of authorization
     * request and outside the scope of this specification". A limit is compared as a decimal by its type's rule, so
     * "5000.00" is within 5000 and a number with more digits than a {@code double} holds is compared exactly: the
     * attestation's payload is read by the model's own reader, not jose4j's, which would round both of these
     * values to 12345678901234568 and let the request through.
     */
    @Test
    @Requirement("RFC9396 §6.1")
    void aLimitIsComparedAsADecimalExactlyAsTheAttesterWroteIt() throws Exception {
        String request = "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":\"%s\"}]";
        assertEquals(1, AuthorizationDetailsGate.check(MODELS, String.format(request, "5000.00"),
                withCeiling("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":5000}]")).size());

        String exactCeiling = withCeiling("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],"
                + "\"max_txn_eur\":12345678901234567.5}]");
        assertEquals(AuthorizationDetailsGate.EXCEEDS,
                refused(String.format(request, "12345678901234567.9"), exactCeiling).getMessage());
        assertEquals(1, AuthorizationDetailsGate.check(MODELS, String.format(request, "12345678901234567.4"),
                exactCeiling).size());
    }

    // ---- RFC 9396 §5: what the request itself gets wrong ---------------------------------------------------

    /**
     * RFC 9396 §5: "The AS MUST refuse to process any unknown authorization details type or authorization details
     * not conforming to the respective type definition. The AS MUST abort processing and respond with an error
     * invalid_authorization_details to the client if any of the following are true of the objects in the
     * authorization_details structure: contains an unknown authorization details type value, ..."
     */
    @Test
    @Requirement("RFC9396 §5")
    void anUnknownTypeIsRefused() {
        ClientAttestationException e = refused("[{\"type\":\"https://scheme.example.org/files\",\"actions\":[\"read\"]}]",
                withCeiling(SALES_CEILING));

        assertEquals(ClientAttestationException.INVALID_AUTHORIZATION_DETAILS, e.error());
        assertEquals("authorization_details names a type this server does not support", e.getMessage());
        assertEquals(Reason.UNMODELLED_TYPE, causeOf(e));
    }

    /** RFC 9396 §5: "is an object of known type but containing unknown fields". */
    @Test
    @Requirement("RFC9396 §5")
    void anUnknownFieldIsRefused() {
        ClientAttestationException e = refused("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"discount\":10}]",
                withCeiling(SALES_CEILING));

        assertEquals(ClientAttestationException.INVALID_AUTHORIZATION_DETAILS, e.error());
        assertEquals("authorization_details carries a field its type does not define", e.getMessage());
        assertEquals(Reason.UNDECLARED_FIELD, causeOf(e));
    }

    /**
     * RFC 9396 §5: "contains fields of the wrong type for the authorization details type", "contains fields with
     * invalid values for the authorization details type", and "is missing required fields for the authorization
     * details type" - here an array where a number goes, a negative limit, and a detail with no {@code type}.
     */
    @Test
    @Requirement("RFC9396 §5")
    void aWrongTypeAnInvalidValueAndAMissingTypeAreMalformed() {
        for (String requested : List.of(
                "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":[5]}]",
                "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"max_txn_eur\":-1}]",
                "[{\"sales_regions\":[\"EMEA\"]}]",
                "[{\"type\":\"sales_agent\",\"sales_regions\":null}]",
                "[\"sales_agent\"]",
                "{\"type\":\"sales_agent\"}",
                "not json")) {
            ClientAttestationException e = refused(requested, withCeiling(SALES_CEILING));
            assertEquals(ClientAttestationException.INVALID_AUTHORIZATION_DETAILS, e.error(), requested);
            assertEquals("authorization_details is malformed", e.getMessage(), requested);
            assertEquals(Reason.MALFORMED, causeOf(e), requested);
        }
    }

    @Test
    @Requirement("RFC9396 §5")
    void aRequestPastASizeLimitIsRefused() {
        StringBuilder seventeen = new StringBuilder("[");
        for (int i = 0; i < 17; i++) {
            seventeen.append(i == 0 ? "" : ",").append("{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}");
        }
        ClientAttestationException e = refused(seventeen.append("]").toString(), withCeiling(SALES_CEILING));

        assertEquals(ClientAttestationException.INVALID_AUTHORIZATION_DETAILS, e.error());
        assertEquals("authorization_details exceeds a size limit", e.getMessage());
        assertEquals(Reason.TOO_LARGE, causeOf(e));
    }

    // ---- this repository's markers --------------------------------------------------------------------------

    /**
     * {@code _principal_sub} (a BFF's principal) and {@code _agent_id} (the filter's agent marker) are taken off
     * before the model is asked - the model refuses both as forbidden, so without this every BFF request would be
     * malformed - and the grant does not carry them. The request's own maps are left as they were: PingFederate
     * and the RAR plugin still read the markers from the parameter.
     */
    @Test
    void theTwoMarkersAreTakenOffBeforeTheModelIsAskedAndNotGranted() throws Exception {
        String requested = "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"actions\":[\"read_accounts\"],"
                + "\"max_txn_eur\":10,\"_principal_sub\":\"alice\",\"_agent_id\":\"a client wrote this\"}]";

        List<Map<String, Object>> granted = AuthorizationDetailsGate.check(MODELS, requested, withCeiling(SALES_CEILING));

        assertEquals(1, granted.size());
        assertFalse(granted.get(0).containsKey(AuthorizationDetailsGate.PRINCIPAL_MARKER));
        assertFalse(granted.get(0).containsKey(AuthorizationDetailsGate.AGENT_MARKER));
        assertEquals(List.of("EMEA"), granted.get(0).get("sales_regions"));
    }

    @Test
    void withoutMarkersCopiesAndLeavesTheCallersDetailsAlone() {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("type", "sales_agent");
        detail.put("_principal_sub", "alice");
        detail.put("_agent_id", "agent-7");

        List<Map<String, Object>> stripped = AuthorizationDetailsGate.withoutMarkers(List.of(detail));

        assertEquals(Map.of("type", "sales_agent"), stripped.get(0));
        assertEquals(3, detail.size(), "the caller's map is not modified");
    }

    /** An attester never writes a marker: one in the attestation's own details is a malformed ceiling. */
    @Test
    void aMarkerInTheAttestationsDetailsIsNotStripped() {
        ClientAttestationException e = refused("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]",
                withCeiling("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"],\"_principal_sub\":\"alice\"}]"));

        assertEquals(ClientAttestationException.INVALID_CLIENT, e.error());
        assertEquals(Reason.MALFORMED, causeOf(e));
    }

    // ---- nothing requested, and the attestation's own details -----------------------------------------------

    /**
     * A request that asks for nothing is not checked, whatever the attestation carries: there is nothing here to
     * compare. What PingFederate issues from details stored earlier is plan item S4d.
     */
    @Test
    void aRequestThatAsksForNothingIsNotChecked() throws Exception {
        String unreadable = withCeiling("[{\"type\":\"no-such-type\"}]");
        for (String requested : new String[] {null, "", "   ", "[]"}) {
            assertEquals(List.of(), AuthorizationDetailsGate.check(MODELS, requested, unreadable), String.valueOf(requested));
        }
    }

    /**
     * An attestation whose own details the model refuses is the credential's fault, not the request's: the
     * attester wrote a type this server has no model for, or the two disagree about one. {@code invalid_client},
     * with a fixed description, and the model's reason in the log.
     */
    @Test
    void anAttestationWhoseDetailsTheModelRefusesIsInvalidClient() {
        for (String ceiling : List.of("[{\"type\":\"no-such-type\"}]", "[{\"type\":\"sales_agent\",\"colour\":\"red\"}]",
                "[{\"type\":\"sales_agent\"}, 42]", "{\"type\":\"sales_agent\"}", "null")) {
            ClientAttestationException e = refused("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]",
                    withCeiling(ceiling));
            assertEquals(ClientAttestationException.INVALID_CLIENT, e.error(), ceiling);
            assertEquals(AuthorizationDetailsGate.CEILING_UNUSABLE, e.getMessage(), ceiling);
        }
    }

    /** Nothing is within an attestation that carries no details at all. */
    @Test
    @Requirement("CAS §7.1")
    void nothingIsWithinAnAttestationWithNoDetails() {
        ClientAttestationException e = refused("[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]",
                attestation("{\"iss\":\"https://attester.example.com\",\"sub\":\"https://rp.example.com\"}"));

        assertEquals(ClientAttestationException.INVALID_AUTHORIZATION_DETAILS, e.error());
        assertEquals(AuthorizationDetailsGate.EXCEEDS, e.getMessage());
    }

    @Test
    void theCeilingIsReadFromTheVerifiedPayloadAndRefusedWhenItCannotBe() throws Exception {
        assertEquals(List.of(), AuthorizationDetailsGate.ceilingOf(attestation("{\"iss\":\"x\"}")));
        assertEquals(1, AuthorizationDetailsGate.ceilingOf(withCeiling(SALES_CEILING)).size());

        assertEquals(Reason.MALFORMED, assertThrows(RarModelException.class,
                () -> AuthorizationDetailsGate.ceilingOf("only.two")).reason());
        assertEquals(Reason.MALFORMED, assertThrows(RarModelException.class,
                () -> AuthorizationDetailsGate.ceilingOf("a.!!!.c")).reason(), "not base64url");
        assertEquals(Reason.MALFORMED, assertThrows(RarModelException.class,
                () -> AuthorizationDetailsGate.ceilingOf(attestation("[1,2]"))).reason(), "not an object");
        assertEquals(Reason.MALFORMED, assertThrows(RarModelException.class,
                () -> AuthorizationDetailsGate.ceilingOf(attestation("{\"a\":1,\"a\":2}"))).reason(), "a duplicate name");
        String deep = "{\"x\":" + "[".repeat(40) + "]".repeat(40) + "}";
        assertEquals(Reason.TOO_LARGE, assertThrows(RarModelException.class,
                () -> AuthorizationDetailsGate.ceilingOf(attestation(deep))).reason(), "nesting past the reader's cap");
    }

    /** The fixed descriptions: what was wrong, never where or with what value. */
    @Test
    void eachReasonHasItsOwnDescriptionAndNoneCarriesTheRequest() {
        assertEquals("authorization_details is malformed", AuthorizationDetailsGate.describe(Reason.MALFORMED));
        assertEquals("authorization_details exceeds a size limit", AuthorizationDetailsGate.describe(Reason.TOO_LARGE));
        assertEquals("authorization_details carries a field its type does not define",
                AuthorizationDetailsGate.describe(Reason.UNDECLARED_FIELD));
        assertEquals("authorization_details names a type this server does not support",
                AuthorizationDetailsGate.describe(Reason.UNMODELLED_TYPE));
        assertEquals(AuthorizationDetailsGate.EXCEEDS, AuthorizationDetailsGate.describe(Reason.EXCEEDS_CEILING));
        assertEquals("authorization_details is malformed", AuthorizationDetailsGate.describe(Reason.MODEL_INVALID));
        for (Reason reason : Reason.values()) {
            String text = AuthorizationDetailsGate.describe(reason);
            assertTrue(text.chars().allMatch(c -> c >= 0x20 && c <= 0x7e && c != '"' && c != '\\'),
                    "inside RFC 6749 §5.2's error_description character set: " + text);
        }
    }
}
