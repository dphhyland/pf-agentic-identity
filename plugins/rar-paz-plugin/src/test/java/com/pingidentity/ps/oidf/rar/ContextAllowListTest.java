package com.pingidentity.ps.oidf.rar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetail;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailContext;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetailProcessingException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;

/**
 * Plan item H-RAR-1, finding F-0065: an AuthZEN decision's {@code context} reaches a detail only through the members the
 * allow-list names for the detail's type. A member it does not name is dropped and counted, in both forms; a member it
 * names that would widen the detail is still refused by the model.
 */
class ContextAllowListTest {

    private static final ModelGate BUILT_IN = ModelGate.of(RarModels.builtIn());
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static ContextAllowList list(String field) {
        return ContextAllowList.of(field, BUILT_IN::declaredMembers);
    }

    // ---- the field --------------------------------------------------------------------------------------------

    @Test
    void theDefaultMergesNothingIntoAPaymentAndTheModelsMembersIntoTheOthers() {
        ContextAllowList defaults = list(null);
        assertEquals(Set.of(), defaults.allowed("payment_initiation"), "a payment takes nothing from a PDP's context");
        assertEquals(Set.of("actions", "locations", "datatypes", "privileges", "identifier", "purpose", "sales_regions",
                "max_txn_eur"), defaults.allowed("sales_agent"));
        assertEquals(Set.of("actions", "locations", "datatypes", "privileges", "identifier", "purpose", "accounts",
                "validUntil", "recurringIndicator"), defaults.allowed("account_information"));
        assertEquals(Set.of(), defaults.allowed("transfer"), "a type the field does not name merges nothing");
        assertEquals(Set.of(), list("transfer: @model").allowed("transfer"), "nor one no model names, in production");
        assertEquals(Set.of("sales_regions"), list(";sales_agent: sales_regions;;").allowed("sales_agent"), "empty entries are nothing");
        assertEquals(defaults.allowed("sales_agent"), list("  ").allowed("sales_agent"), "blank is the default");
        assertEquals(Set.of(), list("-").allowed("sales_agent"), "a single - is none for every type");
        assertEquals(Set.of(), ModelGate.fromEnvironment(Map.of("OIDF_RAR_MODELS", "{")).declaredMembers("sales_agent"),
                "no model set, no @model");
    }

    @Test
    void membersAreNamedPerTypeAndTheModelExpandsBesideThem() {
        ContextAllowList field = list("payment_initiation: instructedAmount\nsales_agent: @model, access ; account_information: -");
        assertEquals(Set.of("instructedAmount"), field.allowed("payment_initiation"));
        assertTrue(field.allowed("sales_agent").containsAll(Set.of("sales_regions", "access")));
        assertEquals(Set.of(), field.allowed("account_information"));
    }

    @Test
    void aFieldThatCannotBeReadIsRefusedOnSaveAndAtConfigure() throws ValidationException {
        for (String bad : List.of("sales_agent", "sales_agent: a; sales_agent: b", "sales_agent: access.limits",
                "sales_agent: type", "sales_agent: _principal_sub", "sales_agent: _agent_id", ": a", "sales agent: a")) {
            String problem = ContextAllowList.problem(bad);
            assertNotNull(problem, bad);
            assertTrue(problem.startsWith(ContextAllowList.FIELD), problem);
            assertThrows(IllegalStateException.class, () -> list(bad), bad);
            Configuration configuration = new Configuration();
            configuration.addField(new Field(ContextAllowList.FIELD, bad));
            assertThrows(ValidationException.class, () -> new ContextAllowList.Validator().validate(configuration), bad);
            configuration.addField(new Field("PDP URL", "https://pdp.example/access/v1/evaluation"));
            assertThrows(IllegalStateException.class,
                    () -> new AttestationAwareRarProcessor().configure(configuration, "development"), bad);
        }
        new ContextAllowList.Validator().validate(new Configuration());
        assertNull(ContextAllowList.problem(ContextAllowList.DEFAULT));
    }

    @Test
    void aStatementsMemberIsTheFirstPartOfItsName() {
        assertEquals("access", ContextAllowList.memberOf("access.limits"));
        assertEquals("sales_regions", ContextAllowList.memberOf("sales_regions"));
        assertNull(ContextAllowList.memberOf(null));
        assertNull(ContextAllowList.memberOf(" "));
        assertEquals("(not a member name)", ContextAllowList.printable("a\nforged line"));
        assertEquals("(not a member name)", ContextAllowList.printable(null));
    }

    // ---- through the AuthZEN client ---------------------------------------------------------------------------

    private static DecisionResponse answer(ContextAllowList allowList, String type, String body) throws Exception {
        GovernanceEngineConfig config = GovernanceEngineConfig.builder().pdpUrl("https://pdp/access/v1/evaluation").build();
        HttpTransport transport = (url, sent, headers) -> new HttpTransport.Response(200, body);
        return new AuthZenPdpClient(config, transport, new AuthZenRequestBuilder(config), MAPPER, null, allowList)
                .decide(type, Map.of("type", type), AttestationSubject.empty(), "alice", "client-1", "authenticated");
    }

    @Test
    void aMemberTheListDoesNotNameIsDroppedAndCounted() throws Exception {
        long before = ContextAllowList.dropped(ContextAllowList.FORM_MEMBER);
        DecisionResponse r = answer(list(null), "payment_initiation",
                "{\"decision\":true,\"context\":{\"id\":\"e1\",\"creditorAccount\":{\"iban\":\"X\"},\"amount\":\"1\"}}");
        assertEquals(List.of(), r.getStatements(), "a payment takes no member by default");
        assertEquals(before + 2, ContextAllowList.dropped(ContextAllowList.FORM_MEMBER), "each dropped member counted; id is metadata");
    }

    /** A PDP can name members without end: each is counted, and only the first few distinct ones are logged. */
    @Test
    void everyDropIsCountedAndTheLogIsBounded() {
        long before = ContextAllowList.dropped(ContextAllowList.FORM_MEMBER);
        // The same member twice is logged once (nothing else here fills the log, so it has room for this first).
        List<DecisionResponse.Statement> twice = List.of(new DecisionResponse.Statement("repeated", "x"),
                new DecisionResponse.Statement("repeated", "y"));
        assertEquals(List.of(), list("-").filter("sales_agent", twice, ContextAllowList.FORM_MEMBER));
        assertEquals(before + 2, ContextAllowList.dropped(ContextAllowList.FORM_MEMBER), "each counted");
        before = ContextAllowList.dropped(ContextAllowList.FORM_MEMBER);
        List<DecisionResponse.Statement> many = new java.util.ArrayList<>();
        for (int i = 0; i < ContextAllowList.MAX_WARNED + 6; i++) {
            many.add(new DecisionResponse.Statement("member_" + i, "x"));
        }
        assertEquals(List.of(), list("-").filter("sales_agent", many, ContextAllowList.FORM_MEMBER));
        assertEquals(before + many.size(), ContextAllowList.dropped(ContextAllowList.FORM_MEMBER));
    }

    @Test
    void theSymmetricFormIsHeldToTheSameList() throws Exception {
        long before = ContextAllowList.dropped(ContextAllowList.FORM_STATEMENT);
        DecisionResponse r = answer(list(null), "sales_agent", "{\"decision\":true,\"context\":{\"statements\":["
                + "{\"name\":\"sales_regions\",\"payload\":[\"EMEA\"]},{\"name\":\"access.limits\",\"payload\":1},"
                + "{\"name\":\"type\",\"payload\":\"payment_initiation\"},{\"payload\":\"no name\"}]}}");
        assertEquals(List.of("sales_regions"), r.getStatements().stream().map(DecisionResponse.Statement::getName).toList());
        assertEquals(before + 2, ContextAllowList.dropped(ContextAllowList.FORM_STATEMENT),
                "access and type dropped; a statement with no name is nothing to count");
    }

    @Test
    void theBatchHoldsEachAnswerToItsOwnTypesList() throws Exception {
        GovernanceEngineConfig config = GovernanceEngineConfig.builder().pdpUrl("https://pdp/access/v1/evaluation").build();
        String body = "{\"evaluations\":[{\"decision\":true,\"context\":{\"sales_regions\":[\"EMEA\"]}},"
                + "{\"decision\":true,\"context\":{\"sales_regions\":[\"EMEA\"]}}]}";
        HttpTransport transport = (url, sent, headers) -> new HttpTransport.Response(200, body);
        AuthZenPdpClient client = new AuthZenPdpClient(config, transport, new AuthZenRequestBuilder(config), MAPPER,
                "https://pdp/access/v1/evaluations", list(null));
        List<DecisionResponse> answers = client.decideAll(List.of(
                new PdpDecisions.Ask("sales_agent", Map.of("type", "sales_agent"), AttestationSubject.empty(), "alice", "c", "authenticated"),
                new PdpDecisions.Ask("payment_initiation", Map.of("type", "payment_initiation"), AttestationSubject.empty(), "alice", "c",
                        "authenticated")));
        assertEquals(1, answers.get(0).getStatements().size(), "sales_agent takes sales_regions");
        assertEquals(0, answers.get(1).getStatements().size(), "payment_initiation takes nothing");
    }

    // ---- through enrich ---------------------------------------------------------------------------------------

    private static AuthorizationDetailContext context() {
        return new AuthorizationDetailContext.Builder().withClientId("agent-client").withUserKey("alice").build();
    }

    private static AuthorizationDetail salesAgent(List<String> regions) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("type", "sales_agent");
        detail.put("sales_regions", regions);
        return new AuthorizationDetail(detail);
    }

    private static AttestationAwareRarProcessor processor(String context, ContextAllowList allowList) {
        GovernanceEngineConfig config = GovernanceEngineConfig.builder().pdpUrl("https://pdp/access/v1/evaluation").build();
        HttpTransport transport = (url, sent, headers) -> new HttpTransport.Response(200,
                "{\"decision\":true,\"context\":" + context + "}");
        return new AttestationAwareRarProcessor(new AuthZenPdpClient(config, transport, new AuthZenRequestBuilder(config),
                MAPPER, null, allowList), config);
    }

    @Test
    void aDroppedMemberNeverReachesTheGrantAndANamedOneNarrowsIt() throws Exception {
        AuthorizationDetail dropped = processor("{\"downscoped\":[\"EMEA\"]}", list(null))
                .enrich(salesAgent(List.of("EMEA", "APAC")), context(), Map.of());
        assertEquals(Map.of("type", "sales_agent", "sales_regions", List.of("EMEA", "APAC")), dropped.getDetail(),
                "granted as requested, without the member");

        AuthorizationDetail narrowed = processor("{\"sales_regions\":[\"EMEA\"]}", list(null))
                .enrich(salesAgent(List.of("EMEA", "APAC")), context(), Map.of());
        assertEquals(List.of("EMEA"), narrowed.getDetail().get("sales_regions"), "a listed member narrows");
    }

    @Test
    void aListedMemberThatWouldWidenTheDetailIsStillRefused() {
        AuthorizationDetailProcessingException e = assertThrows(AuthorizationDetailProcessingException.class,
                () -> processor("{\"sales_regions\":[\"EMEA\",\"AMER\"]}", list(null))
                        .enrich(salesAgent(List.of("EMEA")), context(), Map.of()));
        assertTrue(e.getMessage().contains("never widen"), e.getMessage());
    }
}
