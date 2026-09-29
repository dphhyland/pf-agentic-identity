package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The PDP step's routes: the per-request memo, the decision cache and the AuthZEN batch. Each answers exactly the
 * question it was asked, and the batch's answer is read as strictly as a single one.
 */
class PdpDecisionsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String MEMO = "memo";
    private final GovernanceEngineConfig config = GovernanceEngineConfig.builder().pdpUrl("https://pdp.example/access/v1/evaluation")
            .secretHeader("CLIENT-TOKEN").secret("s").build();

    /** A servlet request whose attributes and one parameter behave as a container's do. */
    static HttpServletRequest request(String authorizationDetails) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        Map<String, Object> attributes = new HashMap<>();
        when(request.getAttribute(anyString())).thenAnswer(i -> attributes.get(i.<String>getArgument(0)));
        doAnswer(i -> attributes.put(i.getArgument(0), i.getArgument(1))).when(request).setAttribute(anyString(), any());
        when(request.getParameter("authorization_details")).thenReturn(authorizationDetails);
        return request;
    }

    private static PdpDecisions.Ask ask(String type, Object... fieldsAndValues) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("type", type);
        for (int i = 0; i + 1 < fieldsAndValues.length; i += 2) {
            detail.put((String) fieldsAndValues[i], fieldsAndValues[i + 1]);
        }
        return new PdpDecisions.Ask(type, detail, AttestationSubject.empty(), "alice", "agent-client", "authenticated");
    }

    private static DecisionResponse permit() {
        return new DecisionResponse("PERMIT", true, List.of(new DecisionResponse.Statement("access",
                new LinkedHashMap<>(Map.of("limits", "x")))), "{}");
    }

    /** A transport that answers each post with the next scripted response and keeps what it was sent. */
    private static final class Recording implements HttpTransport {
        final List<String> urls = new ArrayList<>();
        final List<String> bodies = new ArrayList<>();
        final List<Object> answers = new ArrayList<>();

        Recording answer(Object response) {
            answers.add(response);
            return this;
        }

        @Override
        public Response post(String url, String body, Map<String, String> headers) throws IOException {
            urls.add(url);
            bodies.add(body);
            Object next = answers.isEmpty() ? new Response(200, "{\"decision\":true}") : answers.remove(0);
            if (next instanceof IOException e) {
                throw e;
            }
            return (Response) next;
        }
    }

    private AuthZenPdpClient authzen(Recording transport, String batchUrl) {
        return new AuthZenPdpClient(config, transport, new AuthZenRequestBuilder(config), MAPPER, batchUrl);
    }

    // ---- the memo ---------------------------------------------------------------------------------------------

    @Test
    void theMemoAnswersARepeatedQuestionOnceAndADifferentOneAgain() throws Exception {
        PdpClient client = mock(PdpClient.class);
        AtomicInteger calls = new AtomicInteger();
        when(client.decide(anyString(), any(), any(), any(), any(), any())).thenAnswer(i -> {
            calls.incrementAndGet();
            return permit();
        });
        PdpDecisions decisions = new PdpDecisions(client, null, "", MEMO);
        HttpServletRequest request = request(null);
        long memoBefore = PdpMetrics.answers(PdpMetrics.SOURCE_MEMO);
        DecisionResponse first = decisions.decide(request, ask("sales_agent", "sales_regions", List.of("EMEA")), null);
        DecisionResponse again = decisions.decide(request, ask("sales_agent", "sales_regions", List.of("EMEA")), null);
        assertEquals(1, calls.get(), "PingFederate asked twice; the PDP was asked once");
        assertEquals(memoBefore + 1, PdpMetrics.answers(PdpMetrics.SOURCE_MEMO));
        assertTrue(again.isPermit());
        // The memo hands out a copy: a statement applied to one answer does not reach the next.
        ((Map<String, Object>) again.getStatements().get(0).getPayload()).put("limits", "changed");
        assertEquals("x", ((Map<?, ?>) decisions.decide(request, ask("sales_agent", "sales_regions", List.of("EMEA")), null)
                .getStatements().get(0).getPayload()).get("limits"));
        assertNotNull(first);

        decisions.decide(request, ask("sales_agent", "sales_regions", List.of("APAC")), null);
        assertEquals(2, calls.get(), "a different detail is its own question");
        decisions.decide(request(null), ask("sales_agent", "sales_regions", List.of("EMEA")), null);
        assertEquals(3, calls.get(), "another HTTP request has its own memo");
        decisions.decide(null, ask("sales_agent", "sales_regions", List.of("EMEA")), null);
        assertEquals(4, calls.get(), "no request, no memo");
    }

    @Test
    void theMemoRemembersAFailureSoEveryAskOfItFailsTheSameWay() throws Exception {
        PdpClient client = mock(PdpClient.class);
        PdpUnavailableException down = new PdpUnavailableException("down");
        when(client.decide(anyString(), any(), any(), any(), any(), any())).thenThrow(down);
        PdpDecisions decisions = new PdpDecisions(client, null, "", MEMO);
        HttpServletRequest request = request(null);
        assertSame(down, assertThrows(PdpUnavailableException.class, () -> decisions.decide(request, ask("sales_agent"), null)));
        assertSame(down, assertThrows(PdpUnavailableException.class, () -> decisions.decide(request, ask("sales_agent"), null)));
        org.mockito.Mockito.verify(client, org.mockito.Mockito.times(1)).decide(anyString(), any(), any(), any(), any(), any());
    }

    @Test
    void aRequestThatWillNotHoldAnAttributeHasNoMemo() throws Exception {
        assertNull(DecisionMemo.of(null, MEMO));
        HttpServletRequest forgetful = mock(HttpServletRequest.class);
        assertNull(DecisionMemo.of(forgetful, MEMO), "a request that drops attributes cannot remember");
        HttpServletRequest broken = mock(HttpServletRequest.class);
        when(broken.getAttribute(anyString())).thenThrow(new IllegalStateException("recycled"));
        assertNull(DecisionMemo.of(broken, MEMO));
        HttpServletRequest request = request(null);
        DecisionMemo memo = DecisionMemo.of(request, MEMO);
        assertSame(memo, DecisionMemo.of(request, MEMO));
        for (int i = 0; i < DecisionMemo.MAX_ENTRIES + 10; i++) {
            memo.remember("k" + i, permit());
        }
        assertEquals(DecisionMemo.MAX_ENTRIES, memo.size(), "bounded");
        assertNull(memo.answer("absent"));
        DecisionResponse none = DecisionMemo.copyOf(new DecisionResponse("DENY", false, null, "{}"));
        assertEquals(List.of(), none.getStatements(), "none reads as an empty list");
        assertEquals(List.of(1, Map.of("a", List.of(2))), DecisionMemo.copyValue(List.of(1, Map.of("a", List.of(2)))));
    }

    /** The key is the whole question: each part that the PDP is told changes it, and map order does not. */
    @Test
    void theKeyIsEveryPartOfTheQuestion() {
        PdpDecisions.Ask base = ask("payment_initiation", "amount", "42.00", "currency", "AUD");
        Map<String, Object> reordered = new LinkedHashMap<>();
        reordered.put("currency", "AUD");
        reordered.put("amount", "42.00");
        reordered.put("type", "payment_initiation");
        String key = PdpDecisions.keyOf(base);
        assertEquals(key, PdpDecisions.keyOf(new PdpDecisions.Ask("payment_initiation", reordered, AttestationSubject.empty(),
                "alice", "agent-client", "authenticated")));
        AttestationSubject attested = new AttestationSubject("agent-client", "agent-client", List.of(), Map.of(), null);
        for (PdpDecisions.Ask other : List.of(
                new PdpDecisions.Ask("payment_initiation", base.detail(), AttestationSubject.empty(), "bob", "agent-client", "authenticated"),
                new PdpDecisions.Ask("payment_initiation", base.detail(), AttestationSubject.empty(), "alice", "other-client", "authenticated"),
                new PdpDecisions.Ask("payment_initiation", base.detail(), AttestationSubject.empty(), "alice", "agent-client", "client"),
                new PdpDecisions.Ask("payment_initiation", base.detail(), attested, "alice", "agent-client", "authenticated"),
                new PdpDecisions.Ask("payment_initiation", base.detail(), attested.withAgentId("agent-7"), "alice", "agent-client", "authenticated"),
                new PdpDecisions.Ask("payment_initiation", base.detail(), new AttestationSubject("agent-client", "agent-client",
                        List.of(), Map.of(), null, "agent-7", "https://attester.example", null), "alice", "agent-client", "authenticated"),
                ask("payment_initiation", "amount", "43.00", "currency", "AUD"))) {
            assertNotEquals(key, PdpDecisions.keyOf(other), other.toString());
        }
        Map<String, Object> unwritable = new LinkedHashMap<>(base.detail());
        unwritable.put("self", new Object());
        assertNull(PdpDecisions.keyOf(new PdpDecisions.Ask("payment_initiation", unwritable, null, null, null, null)),
                "a question JSON cannot hold is only ever asked");
    }

    @Test
    void anUnwritableQuestionIsAskedEveryTime() throws Exception {
        PdpClient client = mock(PdpClient.class);
        when(client.decide(anyString(), any(), any(), any(), any(), any())).thenReturn(permit());
        PdpDecisions decisions = new PdpDecisions(client, new DecisionCache(Set.of("sales_agent"), 30), "", MEMO);
        HttpServletRequest request = request(null);
        PdpDecisions.Ask odd = new PdpDecisions.Ask("sales_agent", new LinkedHashMap<>(Map.of("x", new Object())),
                AttestationSubject.empty(), null, null, null);
        decisions.decide(request, odd, null);
        decisions.decide(request, odd, null);
        org.mockito.Mockito.verify(client, org.mockito.Mockito.times(2)).decide(anyString(), any(), any(), any(), any(), any());
    }

    // ---- the cache --------------------------------------------------------------------------------------------

    @Test
    void theCacheAnswersAListedTypeAcrossRequestsUntilItsTtl() throws Exception {
        AtomicLong now = new AtomicLong();
        DecisionCache cache = new DecisionCache(Set.of("sales_agent"), 20, now::get);
        PdpClient client = mock(PdpClient.class);
        AtomicInteger calls = new AtomicInteger();
        when(client.decide(anyString(), any(), any(), any(), any(), any())).thenAnswer(i -> {
            calls.incrementAndGet();
            return permit();
        });
        PdpDecisions decisions = new PdpDecisions(client, cache, "https://pdp\nfingerprint", MEMO);
        long cachedBefore = PdpMetrics.answers(PdpMetrics.SOURCE_CACHE);
        decisions.decide(request(null), ask("sales_agent", "sales_regions", List.of("EMEA")), null);
        DecisionResponse hit = decisions.decide(request(null), ask("sales_agent", "sales_regions", List.of("EMEA")), null);
        assertEquals(1, calls.get(), "a second request within the TTL is answered from the cache");
        assertTrue(hit.isPermit());
        assertEquals(cachedBefore + 1, PdpMetrics.answers(PdpMetrics.SOURCE_CACHE));
        now.addAndGet(TimeUnit.SECONDS.toNanos(20));
        decisions.decide(request(null), ask("sales_agent", "sales_regions", List.of("EMEA")), null);
        assertEquals(2, calls.get(), "past the TTL the PDP is asked again");
        decisions.decide(request(null), ask("account_information", "accounts", List.of("1")), null);
        decisions.decide(request(null), ask("account_information", "accounts", List.of("1")), null);
        assertEquals(4, calls.get(), "a type not listed is never cached");

        PdpDecisions otherPdp = new PdpDecisions(client, cache, "https://other-pdp\nfingerprint", MEMO);
        otherPdp.decide(request(null), ask("sales_agent", "sales_regions", List.of("EMEA")), null);
        assertEquals(5, calls.get(), "another PDP or another model set is another key");
    }

    @Test
    void theCacheAnswersWithoutARequestToo() throws Exception {
        PdpClient client = mock(PdpClient.class);
        when(client.decide(anyString(), any(), any(), any(), any(), any())).thenReturn(permit());
        PdpDecisions decisions = new PdpDecisions(client, new DecisionCache(Set.of("sales_agent"), 30), "", MEMO);
        decisions.decide(null, ask("sales_agent"), null);
        assertTrue(decisions.decide(null, ask("sales_agent"), null).isPermit());
        org.mockito.Mockito.verify(client, org.mockito.Mockito.times(1)).decide(anyString(), any(), any(), any(), any(), any());
    }

    @Test
    void theCacheNeverKeepsAFailure() throws Exception {
        DecisionCache cache = new DecisionCache(Set.of("sales_agent"), 30);
        PdpClient client = mock(PdpClient.class);
        when(client.decide(anyString(), any(), any(), any(), any(), any()))
                .thenThrow(new PdpUnavailableException("down")).thenReturn(permit());
        PdpDecisions decisions = new PdpDecisions(client, cache, "", MEMO);
        assertThrows(PdpUnavailableException.class, () -> decisions.decide(request(null), ask("sales_agent"), null));
        assertTrue(decisions.decide(request(null), ask("sales_agent"), null).isPermit());
        assertEquals(1, cache.size());
        assertSame(cache, decisions.cache());
    }

    @Test
    void theCacheIsBoundedAndItsTtlHeldToSixtySeconds() {
        AtomicLong now = new AtomicLong();
        DecisionCache cache = new DecisionCache(Set.of("sales_agent"), 3_600, now::get);
        assertEquals(TimeUnit.SECONDS.toNanos(60), cache.ttlNanos());
        assertEquals(TimeUnit.SECONDS.toNanos(30), new DecisionCache(Set.of(), 0).ttlNanos());
        for (int i = 0; i < DecisionCache.MAX_ENTRIES + 5; i++) {
            cache.put("k" + i, permit());
        }
        assertEquals(DecisionCache.MAX_ENTRIES, cache.size());
        assertNull(cache.get("k0"), "the oldest went first");
        assertNotNull(cache.get("k" + (DecisionCache.MAX_ENTRIES + 4)));
        cache.put("k10", permit());
        assertEquals(DecisionCache.MAX_ENTRIES, cache.size(), "a key put again replaces itself");
        assertEquals(Set.of("sales_agent"), cache.types());
    }

    @Test
    void paymentsAndPrincipalTypesCanNeverBeCached() {
        Set<String> principalTypes = GovernanceEngineConfig.DEFAULT_AUTHENTICATED_PRINCIPAL_TYPES;
        assertNull(DecisionCache.refusal(Set.of("sales_agent"), principalTypes));
        assertNull(DecisionCache.refusal(Set.of(), principalTypes));
        String payment = DecisionCache.refusal(Set.of("sales_agent", "payment_initiation"), Set.of());
        assertTrue(payment.contains("payment_initiation"), payment);
        String principal = DecisionCache.refusal(Set.of("account_information", "sales_agent"), principalTypes);
        assertTrue(principal.contains("[account_information]"), principal);
        String custom = DecisionCache.refusal(Set.of("transfer"), Set.of("transfer"));
        assertTrue(custom.contains("transfer"), custom);
        assertEquals(Set.of("a", "b"), PdpDecisions.typesOf(" a, b ,, a "));
        assertEquals(Set.of(), PdpDecisions.typesOf("-"));
        assertEquals(Set.of(), PdpDecisions.typesOf(null));
    }

    // ---- the batch --------------------------------------------------------------------------------------------

    private static String decisions(String... elements) {
        return "{\"evaluations\":[" + String.join(",", elements) + "]}";
    }

    @Test
    void theFirstAskOfARequestSendsEveryDetailInOneCallAndTheMemoAnswersTheRest() throws Exception {
        Recording transport = new Recording().answer(new HttpTransport.Response(200, decisions(
                "{\"decision\":true,\"context\":{\"access\":{\"limits\":\"a\"}}}",
                "{\"decision\":false}",
                "{\"decision\":true}")));
        PdpDecisions decisions = new PdpDecisions(authzen(transport, "https://pdp.example/access/v1/evaluations"), null, "", MEMO);
        HttpServletRequest request = request(null);
        PdpDecisions.Ask a = ask("sales_agent", "sales_regions", List.of("EMEA"));
        PdpDecisions.Ask b = ask("sales_agent", "sales_regions", List.of("AMER"));
        PdpDecisions.Ask c = ask("account_information", "accounts", List.of("1"));
        AtomicInteger asked = new AtomicInteger();
        java.util.function.Supplier<List<PdpDecisions.Ask>> all = () -> {
            asked.incrementAndGet();
            return List.of(a, b, a, c);
        };
        long memoBefore = PdpMetrics.answers(PdpMetrics.SOURCE_MEMO);
        long pdpBefore = PdpMetrics.answers(PdpMetrics.SOURCE_PDP);
        DecisionResponse first = decisions.decide(request, a, all);
        assertTrue(first.isPermit());
        assertEquals("access", first.getStatements().get(0).getName());
        assertFalse(decisions.decide(request, b, all).isPermit());
        assertTrue(decisions.decide(request, c, all).isPermit());
        assertTrue(decisions.decide(request, a, all).isPermit());
        assertEquals(List.of("https://pdp.example/access/v1/evaluations"), transport.urls, "one call, to the batch URL");
        assertEquals(1, asked.get(), "the request's details are read once");
        JsonNode sent = MAPPER.readTree(transport.bodies.get(0));
        assertEquals(3, sent.get("evaluations").size(), "every distinct detail once, the asking one first");
        assertEquals(1, sent.size(), "no top-level defaults and no options: execute_all is the default");
        assertEquals(MAPPER.readTree(MAPPER.writeValueAsString(new AuthZenRequestBuilder(config).build(a.type(), a.detail(),
                a.subject(), a.owner(), a.clientId(), a.source()))), sent.get("evaluations").get(0),
                "each evaluation is what the single call would have sent");
        assertEquals("EMEA", sent.get("evaluations").get(0).path("resource").path("properties").path("sales_regions").get(0).asText());
        assertEquals("AMER", sent.get("evaluations").get(1).path("resource").path("properties").path("sales_regions").get(0).asText());
        assertEquals(pdpBefore + 1, PdpMetrics.answers(PdpMetrics.SOURCE_PDP), "the asking detail is the PDP's answer");
        assertEquals(memoBefore + 3, PdpMetrics.answers(PdpMetrics.SOURCE_MEMO), "the other three asks are the memo's");
    }

    @Test
    void aRequestWithOneDetailOrNoBatchUrlUsesTheSingleEvaluation() throws Exception {
        Recording transport = new Recording();
        PdpDecisions batching = new PdpDecisions(authzen(transport, "https://pdp.example/access/v1/evaluations"), null, "", MEMO);
        PdpDecisions.Ask a = ask("sales_agent", "sales_regions", List.of("EMEA"));
        batching.decide(request(null), a, () -> List.of(a));
        batching.decide(request(null), a, () -> null);
        batching.decide(request(null), a, null);
        assertEquals(List.of(config.getPdpUrl(), config.getPdpUrl(), config.getPdpUrl()), transport.urls);

        Recording single = new Recording();
        PdpDecisions plain = new PdpDecisions(authzen(single, " "), null, "", MEMO);
        plain.decide(request(null), a, () -> List.of(a, ask("sales_agent", "sales_regions", List.of("APAC"))));
        assertEquals(List.of(config.getPdpUrl()), single.urls, "a blank batch URL is none");
        assertThrows(IllegalStateException.class, () -> authzen(single, null).decideAll(List.of(a)));

        Recording many = new Recording();
        PdpDecisions tooMany = new PdpDecisions(authzen(many, "https://pdp.example/access/v1/evaluations"), null, "", MEMO);
        List<PdpDecisions.Ask> lots = new ArrayList<>();
        for (int i = 0; i < PdpDecisions.MAX_BATCH + 1; i++) {
            lots.add(ask("sales_agent", "sales_regions", List.of("R" + i)));
        }
        tooMany.decide(request(null), lots.get(0), () -> lots);
        assertEquals(List.of(config.getPdpUrl()), many.urls, "past the limit, no batch");
    }

    @Test
    void theBatchLeavesOutWhatTheMemoOrTheCacheAlreadyAnswers() throws Exception {
        Recording transport = new Recording()
                .answer(new HttpTransport.Response(200, "{\"decision\":true}"))
                .answer(new HttpTransport.Response(200, decisions("{\"decision\":true}", "{\"decision\":true}")));
        DecisionCache cache = new DecisionCache(Set.of("sales_agent"), 30);
        PdpDecisions decisions = new PdpDecisions(authzen(transport, "https://pdp.example/access/v1/evaluations"), cache, "", MEMO);
        PdpDecisions.Ask cached = ask("sales_agent", "sales_regions", List.of("EMEA"));
        decisions.decide(request(null), cached, null); // single call, no memo batch yet on this request: fills the cache
        PdpDecisions.Ask b = ask("account_information", "accounts", List.of("1"));
        PdpDecisions.Ask c = ask("account_information", "accounts", List.of("2"));
        decisions.decide(request(null), b, () -> List.of(cached, b, c));
        JsonNode sent = MAPPER.readTree(transport.bodies.get(1));
        assertEquals(2, sent.get("evaluations").size(), "the cached detail is not asked again");

        // In one request: the cached detail first (the cache answers, the memo remembers), then the batch without it.
        transport.answer(new HttpTransport.Response(200, decisions("{\"decision\":true}", "{\"decision\":true}")));
        HttpServletRequest one = request(null);
        decisions.decide(one, cached, () -> List.of(cached, b, c));
        PdpDecisions.Ask d = ask("account_information", "accounts", List.of("3"));
        decisions.decide(one, d, () -> List.of(cached, d, c));
        JsonNode third = MAPPER.readTree(transport.bodies.get(2));
        assertEquals(2, third.get("evaluations").size(), "what the memo holds is not asked again");
    }

    /** One batch per request: a detail the batch did not carry is asked on its own; one the key cannot hold is left out. */
    @Test
    void afterTheBatchADetailItDidNotCarryIsAskedAlone() throws Exception {
        Recording transport = new Recording()
                .answer(new HttpTransport.Response(200, decisions("{\"decision\":true}", "{\"decision\":true}")))
                .answer(new HttpTransport.Response(200, "{\"decision\":false}"));
        PdpDecisions decisions = new PdpDecisions(authzen(transport, "https://pdp.example/access/v1/evaluations"), null, "", MEMO);
        HttpServletRequest request = request(null);
        PdpDecisions.Ask a = ask("sales_agent", "sales_regions", List.of("EMEA"));
        PdpDecisions.Ask b = ask("sales_agent", "sales_regions", List.of("AMER"));
        PdpDecisions.Ask odd = new PdpDecisions.Ask("sales_agent", new LinkedHashMap<>(Map.of("x", new Object())),
                AttestationSubject.empty(), null, null, null);
        decisions.decide(request, a, () -> List.of(a, odd, b));
        assertEquals(2, MAPPER.readTree(transport.bodies.get(0)).get("evaluations").size(), "the unwritable one is left out");
        PdpDecisions.Ask late = ask("sales_agent", "sales_regions", List.of("APAC"));
        assertFalse(decisions.decide(request, late, () -> List.of(a, b, late)).isPermit());
        assertEquals(List.of("https://pdp.example/access/v1/evaluations", config.getPdpUrl()), transport.urls);
    }

    @Test
    void eachMalformedBatchAnswerIsRefusedForEveryDetailInIt() throws Exception {
        for (String body : List.of(
                "{\"decision\":true}",
                "{\"evaluations\":{}}",
                decisions("{\"decision\":true}"),
                decisions("{\"decision\":true}", "{\"decision\":true}", "{\"decision\":true}"),
                decisions("{\"decision\":true}", "true"),
                decisions("{\"decision\":true}", "{\"decision\":\"true\"}"),
                decisions("{\"decision\":true}", "{}"),
                "{\"evaluations\":[{\"decision\":true},{\"decision\":true,\"decision\":false}]}",
                decisions("{\"decision\":true}", "{\"decision\":true}") + " trailing",
                "[]")) {
            Recording transport = new Recording().answer(new HttpTransport.Response(200, body));
            PdpDecisions decisions = new PdpDecisions(authzen(transport, "https://pdp.example/access/v1/evaluations"), null, "", MEMO);
            HttpServletRequest request = request(null);
            PdpDecisions.Ask a = ask("sales_agent", "sales_regions", List.of("EMEA"));
            PdpDecisions.Ask b = ask("sales_agent", "sales_regions", List.of("AMER"));
            IOException first = assertThrows(IOException.class, () -> decisions.decide(request, a, () -> List.of(a, b)), body);
            assertFalse(first instanceof PdpUnavailableException, "a malformed answer is not an outage: " + body);
            assertSame(first, assertThrows(IOException.class, () -> decisions.decide(request, b, () -> List.of(a, b))),
                    "the other detail fails the same way, without another call: " + body);
            assertEquals(1, transport.urls.size(), body);
        }
    }

    @Test
    void aBatchThePdpCouldNotServeIsUnavailableForEveryDetailInIt() throws Exception {
        for (Object answer : List.of(new HttpTransport.Response(503, "{}"), new PdpUnavailableException("reset"))) {
            Recording transport = new Recording().answer(answer);
            PdpDecisions decisions = new PdpDecisions(authzen(transport, "https://pdp.example/access/v1/evaluations"), null, "", MEMO);
            HttpServletRequest request = request(null);
            PdpDecisions.Ask a = ask("sales_agent", "sales_regions", List.of("EMEA"));
            PdpDecisions.Ask b = ask("sales_agent", "sales_regions", List.of("AMER"));
            assertThrows(PdpUnavailableException.class, () -> decisions.decide(request, a, () -> List.of(a, b)));
            assertThrows(PdpUnavailableException.class, () -> decisions.decide(request, b, () -> List.of(a, b)));
            assertEquals(1, transport.urls.size());
        }
        Recording refused = new Recording().answer(new HttpTransport.Response(401, "{}"));
        PdpDecisions decisions = new PdpDecisions(authzen(refused, "https://pdp.example/access/v1/evaluations"), null, "", MEMO);
        PdpDecisions.Ask a = ask("sales_agent", "sales_regions", List.of("EMEA"));
        IOException e = assertThrows(IOException.class,
                () -> decisions.decide(request(null), a, () -> List.of(a, ask("sales_agent", "sales_regions", List.of("AMER")))));
        assertFalse(e instanceof PdpUnavailableException, "a 401 to the batch is a refusal, as it is to one evaluation");
    }

    @Test
    void theBatchCarriesTheSharedSecretAndTheTopLevelDecisionIsIgnored() throws Exception {
        Recording transport = new Recording().answer(new HttpTransport.Response(200,
                "{\"decision\":false,\"evaluations\":[{\"decision\":true},{\"decision\":true}]}"));
        AuthZenPdpClient client = authzen(transport, "https://pdp.example/access/v1/evaluations");
        assertTrue(client.batches());
        assertEquals("https://pdp.example/access/v1/evaluations", client.batchUrl());
        List<DecisionResponse> answers = client.decideAll(List.of(ask("sales_agent"), ask("account_information")));
        assertEquals(2, answers.size());
        assertTrue(answers.get(0).isPermit() && answers.get(1).isPermit(), "section 7.2: a top-level decision can be ignored");
    }
}
