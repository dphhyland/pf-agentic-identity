package au.com.idpartners.gm.servlet;

import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link GrantOperations#evaluate} and {@link GrantOperations#search} against a real (loopback)
 * PDP, covering what {@link GrantEvaluatorTest} cannot: turning a PDP response into a
 * {@link GrantOperations.Decision}, and the section 8.4.3 rule that only {@code reason_user}
 * ever reaches the caller.
 *
 * <p>{@code describe}/{@code revoke}/{@code lookup} are not covered here: they call
 * {@code AccessGrantManagerAccessor}, a PF SDK type reachable only inside a running server.
 */
class GrantOperationsTest {

    private static final String SUB = "alice";
    private static final String CLIENT = "acme-budgeting";

    private HttpServer server;

    @AfterEach
    void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    private GrantOperations opsAnswering(int status, String body) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(status, bytes.length);
            try (OutputStream out = ex.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        return new GrantOperations(
                new PfTokenVerifier((com.pingidentity.access.JwksEndpointKeyAccessor) null, "aud"),
                new PdpClient(base, null, 2000));
    }

    private static GrantView grant() {
        Map<String, Object> consent = new LinkedHashMap<>();
        consent.put("type", "account_information");
        consent.put("actions", List.of("read_balance"));
        return new GrantView("grant-123", SUB, CLIENT,
                List.of("accounts.read", GrantEvaluator.SCOPE_EVALUATE),
                System.currentTimeMillis() + 86_400_000L, List.of(consent));
    }

    private static TokenClaims validToken() {
        return new TokenClaims(SUB, CLIENT, "grant-123",
                List.of("accounts.read", GrantEvaluator.SCOPE_EVALUATE));
    }

    // ---- evaluate: turning a PDP response into a Decision ------------------------------------

    @Test
    void aPermitFromThePdpIsAPermittedDecision() throws Exception {
        GrantOperations ops = opsAnswering(200, "{\"decision\":true}");

        GrantOperations.Decision d = ops.evaluate(grant(), validToken(),
                "account", "111", "read_balance", null, null);

        assertTrue(d.permitted());
        assertTrue(d.fromPdp(), "the PDP was actually consulted");
        assertFalse(d.retryable(), "a permit is never retryable");
    }

    @Test
    void onlyReasonUserReachesTheCallerNeverReasonAdmin() throws Exception {
        // Section 8.4.3: reason_admin may name internal policy detail and must not reach the
        // client. A regression here is a data leak, not a cosmetic bug.
        String body = "{\"decision\":false,\"context\":{\"id\":\"subject_not_entitled\","
                + "\"reason_user\":{\"en\":\"You no longer have access to this account.\"},"
                + "\"reason_admin\":{\"en\":\"policy rule acct-guard-17 matched on ledger shard 3\"}}}";
        GrantOperations ops = opsAnswering(200, body);

        GrantOperations.Decision d = ops.evaluate(grant(), validToken(),
                "account", "222", "read_balance", null, null);

        assertFalse(d.permitted());
        assertEquals("subject_not_entitled", d.reasonId());
        assertEquals("You no longer have access to this account.", d.message());
        assertFalse(d.message().contains("acct-guard-17"), "reason_admin must never reach the caller");
        assertFalse(d.retryable(), "the subject does not hold the access; re-consenting cannot fix it");
    }

    @Test
    void aReasonUserWithNoEnglishFallsBackToTheFirstLocale() throws Exception {
        String body = "{\"decision\":false,\"context\":{\"id\":\"resource_not_consented\","
                + "\"reason_user\":{\"fr\":\"Vous n'avez pas consenti à cela.\"}}}";
        GrantOperations ops = opsAnswering(200, body);

        GrantOperations.Decision d = ops.evaluate(grant(), validToken(),
                "account", "333", "read_balance", null, null);

        assertEquals("Vous n'avez pas consenti à cela.", d.message());
        assertTrue(d.retryable(), "a consent problem, re-consenting could fix it");
    }

    @Test
    void noReasonUserAtAllYieldsAnEmptyReason() throws Exception {
        GrantOperations ops = opsAnswering(200, "{\"decision\":false,\"context\":{}}");

        GrantOperations.Decision d = ops.evaluate(grant(), validToken(),
                "account", "444", "read_balance", null, null);

        assertEquals("", d.reasonId());
        assertEquals("", d.message());
    }

    // ---- an AS-side refusal never reaches the PDP at all --------------------------------------

    @Test
    void anAsSideRefusalIsADecisionNotAnException() throws Exception {
        // Point at a dead port: if this refusal reached the PDP, the call would throw
        // UnavailableException instead of returning cleanly.
        int deadPort;
        try (ServerSocket s = new ServerSocket(0)) {
            deadPort = s.getLocalPort();
        }
        GrantOperations ops = new GrantOperations(
                new PfTokenVerifier((com.pingidentity.access.JwksEndpointKeyAccessor) null, "aud"),
                new PdpClient("http://127.0.0.1:" + deadPort, null, 500));

        TokenClaims noScope = new TokenClaims(SUB, CLIENT, "grant-123", List.of("accounts.read"));
        GrantOperations.Decision d = ops.evaluate(grant(), noScope,
                "account", "111", "read_balance", null, null);

        assertFalse(d.permitted());
        assertFalse(d.fromPdp(), "the AS refused before asking the PDP");
        assertEquals("insufficient_scope", d.reasonId());
    }

    // ---- an unreachable or incoherent PDP is an outage, never a denial ------------------------

    @Test
    void aPdpErrorResponseThrowsRatherThanDenying() throws Exception {
        GrantOperations ops = opsAnswering(500, "{\"error\":\"boom\"}");

        assertThrows(GrantOperations.UnavailableException.class,
                () -> ops.evaluate(grant(), validToken(), "account", "111", "read_balance", null, null));
    }

    @Test
    void aNullPdpDocumentThrowsRatherThanDenying() throws Exception {
        GrantOperations ops = opsAnswering(200, "null");

        assertThrows(GrantOperations.UnavailableException.class,
                () -> ops.evaluate(grant(), validToken(), "account", "111", "read_balance", null, null));
    }

    // ---- search: the permitted set -------------------------------------------------------------

    @Test
    void searchReturnsThePermittedIdsInOrder() throws Exception {
        String body = "{\"results\":[{\"type\":\"account\",\"id\":\"111\"},"
                + "{\"type\":\"account\",\"id\":\"444\"}]}";
        GrantOperations ops = opsAnswering(200, body);

        List<String> ids = ops.search(grant(), validToken(), "account", "search_accounts", null);

        assertEquals(List.of("111", "444"), ids);
    }

    @Test
    void searchIgnoresResultsWithNoOrBlankId() throws Exception {
        String body = "{\"results\":[{\"type\":\"account\",\"id\":\"111\"},"
                + "{\"type\":\"account\"},{\"type\":\"account\",\"id\":\"  \"}]}";
        GrantOperations ops = opsAnswering(200, body);

        List<String> ids = ops.search(grant(), validToken(), "account", "search_accounts", null);

        assertEquals(List.of("111"), ids);
    }

    @Test
    void searchWithNoResultsFieldIsAnEmptySetNotAnError() throws Exception {
        GrantOperations ops = opsAnswering(200, "{}");

        List<String> ids = ops.search(grant(), validToken(), "account", "search_accounts", null);

        assertTrue(ids.isEmpty());
    }

    @Test
    void searchStillRefusesBeforeAskingThePdp() throws Exception {
        GrantOperations ops = opsAnswering(200, "{\"results\":[]}");
        TokenClaims noScope = new TokenClaims(SUB, CLIENT, "grant-123", List.of("accounts.read"));

        assertThrows(GrantEvaluator.RefusedException.class,
                () -> ops.search(grant(), noScope, "account", "search_accounts", null));
    }
}
