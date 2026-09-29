package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.TrustChainValidationException.Kind;
import com.pingidentity.ps.oidf.federation.testkit.Federation;
import com.pingidentity.ps.oidf.federation.testkit.ServingMap;
import com.pingidentity.ps.oidf.jose.HttpGetClient;
import com.pingidentity.ps.oidf.jose.JdkHttpClient;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.platform.http.Deadline;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * One budget per resolution (plan item S5b): every request a validation causes - the gateway's own included - is
 * paid for from it and made by its deadline, and a peer chain spends from it too, so no chain's shape can make a
 * resolution cost more than its budget.
 */
class TrustChainValidatorBudgetTest {
    private static final String TA = "https://ta.example";
    private static final String INT = "https://int.example";
    private static final String LEAF = "https://rp.example";
    private static final String OP = "https://op.example";

    private static Federation threeLevels() {
        return Federation.builder().anchor(TA).intermediate(INT, TA).leaf(LEAF, INT).build();
    }

    private static TrustChainValidator validator(HttpGetClient http, Federation f, ValidatorOptions options) {
        return new TrustChainValidator(new HttpTrustControllerGateway(http, TA), TrustAnchorSet.of(f.trustAnchor(TA)), Set.of(), options);
    }

    // ---- the wall clock --------------------------------------------------------------------------------

    /**
     * Serves a federation's statements over real loopback HTTP, each body sent a few bytes at a time over
     * {@code bodyTime}: a peer that answers at once and then takes its time over the body.
     */
    private static final class SlowPeers implements AutoCloseable {
        private final HttpServer server;
        private final ExecutorService pool = Executors.newCachedThreadPool();
        private final AtomicInteger requests = new AtomicInteger();
        private final JdkHttpClient client;

        SlowPeers(ServingMap statements, Duration bodyTime) throws IOException {
            this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 50);
            this.server.setExecutor(this.pool);
            this.server.createContext("/", exchange -> {
                this.requests.incrementAndGet();
                String url = URLDecoder.decode(exchange.getRequestURI().getRawQuery().substring("u=".length()), StandardCharsets.UTF_8);
                byte[] body;
                try {
                    body = statements.get(url, "application/entity-statement+jwt").getBytes(StandardCharsets.UTF_8);
                } catch (Exception e) {
                    exchange.sendResponseHeaders(404, -1);
                    exchange.close();
                    return;
                }
                exchange.sendResponseHeaders(200, body.length);
                int chunks = 10;
                try (OutputStream out = exchange.getResponseBody()) {
                    for (int i = 0; i < chunks; i++) {
                        out.write(body, i * body.length / chunks, (i + 1) * body.length / chunks - i * body.length / chunks);
                        out.flush();
                        Thread.sleep(bodyTime.toMillis() / chunks);
                    }
                } catch (IOException | InterruptedException gone) {
                    // the client gave up at its deadline
                }
            });
            this.server.start();
            // A request timeout far longer than any budget here: only the resolution's deadline can stop a slow body.
            this.client = new JdkHttpClient(false, OutboundUrlPolicy.permissive(), Duration.ofSeconds(2), Duration.ofSeconds(30));
        }

        /** The federation's https URLs, fetched from this server by the real transport. */
        HttpGetClient http() {
            return new HttpGetClient() {
                @Override
                public String get(String url, String accept) throws Exception {
                    return SlowPeers.this.client.get(local(url), accept);
                }

                @Override
                public String get(String url, String accept, Deadline deadline) throws Exception {
                    return SlowPeers.this.client.get(local(url), accept, deadline);
                }
            };
        }

        private String local(String url) {
            return "http://127.0.0.1:" + this.server.getAddress().getPort() + "/?u=" + URLEncoder.encode(url, StandardCharsets.UTF_8);
        }

        int requests() {
            return this.requests.get();
        }

        @Override
        public void close() {
            this.server.stop(0);
            this.pool.shutdownNow();
        }
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void aSlowPeersBodySpendsTheResolutionsWallClockAcrossHops() throws Exception {
        Federation f = threeLevels();
        try (SlowPeers peers = new SlowPeers(f.http(), Duration.ofMillis(400))) {
            // Five requests of 0.4 s each against a wall clock of 1 s: the third is cut off in its body.
            TrustChainValidator impatient = validator(peers.http(), f, ValidatorOptions.defaults().withResolutionWallClock(Duration.ofMillis(1000)));
            long started = System.nanoTime();
            TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                    () -> impatient.validate(ValidationRequest.forSubject(LEAF).build()));
            long elapsed = (System.nanoTime() - started) / 1_000_000L;

            assertEquals(Kind.BUDGET, e.kind(), e.getMessage());
            assertEquals(FederationError.INVALID_TRUST_CHAIN, e.error());
            assertTrue(e.getMessage().contains("ran out of time") && e.getMessage().contains("1000 ms"), e.getMessage());
            assertFalse(e.getMessage().contains(".example"), "the refusal names no peer: " + e.getMessage());
            assertTrue(peers.requests() >= 3, "it got across hops before the time ran out: " + peers.requests());
            assertTrue(elapsed < 1800, "the slow body is stopped at the resolution's deadline, not the request timeout: " + elapsed + " ms");
        }
    }

    @Test
    void theSameSlowChainResolvesWithinALongerWallClock() throws Exception {
        Federation f = threeLevels();
        try (SlowPeers peers = new SlowPeers(f.http(), Duration.ofMillis(200))) {
            TrustChainValidationResult result = validator(peers.http(), f, ValidatorOptions.defaults()
                    .withResolutionWallClock(Duration.ofSeconds(20))).validate(ValidationRequest.forSubject(LEAF).build());

            assertEquals(TA, result.trustAnchorIssuer());
            assertEquals(5, peers.requests());
            // The intermediate's configuration, asked for once more on the way up, comes from the staged writes: paid
            // for, not fetched. So the budget covers every request, with one to spare.
            assertEquals(6, result.fetchesUsed());
        }
    }

    @Test
    void aCallersBudgetWhoseTimeHasPassedFetchesNothing() throws Exception {
        Federation f = threeLevels();
        ResolutionBudget spent = ResolutionBudget.of(Duration.ofMillis(1), 10);
        Thread.sleep(10);

        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> f.validator(TA).validate(ValidationRequest.forSubject(LEAF).budget(spent).build()));

        assertEquals(Kind.BUDGET, e.kind());
        assertTrue(e.getMessage().contains("ran out of time"), e.getMessage());
        assertEquals(List.of(), f.http().requests());
    }

    // ---- the gateway's own requests ------------------------------------------------------------------

    /**
     * LEAF -> INT -> TA, nothing presented: the leaf's configuration, then for each Subordinate Statement its
     * issuer's configuration (to find the fetch endpoint) and the statement - five requests, where the old fetch
     * budget counted three.
     */
    @Test
    @Requirement("OIDFED §18.1(3)")
    void theAuthoritysConfigurationLookupIsCounted() {
        Federation f = threeLevels();

        TrustChainValidationResult result = f.validator(TA).validate(ValidationRequest.forSubject(LEAF).build());

        assertEquals(5, f.http().requests().size(), f.http().requests().toString());
        assertTrue(result.fetchesUsed() >= 5, "each of them paid for: " + result.fetchesUsed());
    }

    /** However small the budget, the chain never makes more requests than it holds. */
    @Test
    void noBudgetIsOverspentWhateverItsSize() {
        int needed = threeLevels().validator(TA).validate(ValidationRequest.forSubject(LEAF).build()).fetchesUsed();
        for (int n = 1; n < needed; n++) {
            Federation f = threeLevels();
            int budget = n;
            TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                    () -> f.validator(ValidatorOptions.defaults().withMaxFetches(budget), TA).validate(ValidationRequest.forSubject(LEAF).build()));
            assertEquals(Kind.BUDGET, e.kind(), "budget " + n + ": " + e.getMessage());
            assertTrue(e.getMessage().contains("ran out of requests") && e.getMessage().contains("budget of " + n + " requests"), e.getMessage());
            assertTrue(f.http().requests().size() <= n, "budget " + n + " made " + f.http().requests().size() + " requests");
        }
    }

    /**
     * §11.3: an anchor configuration that does not verify with the pinned keys is retrieved again. The second
     * retrieval is a request like any other: paid for, and refused when the budget has none left.
     */
    @Test
    @Requirement("OIDFED §11.3")
    void theSecondRetrievalOfAnAnchorsConfigurationIsCounted() {
        String anchorUrl = TA + "/.well-known/openid-federation";
        Federation f = Federation.builder().anchor(TA).leaf(LEAF, TA).build();
        String impostor = Federation.builder().anchor(TA).leaf(LEAF, TA).build().entityConfiguration(TA);
        f.http().sequence(anchorUrl, impostor, f.entityConfiguration(TA));

        TrustChainValidationResult result = f.validator(TA).validate(ValidationRequest.forSubject(LEAF).build());

        assertEquals(2, f.http().hits(anchorUrl));
        assertEquals(4, f.http().requests().size(), "the leaf, the anchor twice, the statement");
        assertEquals(4, result.fetchesUsed());

        Federation g = Federation.builder().anchor(TA).leaf(LEAF, TA).build();
        g.http().sequence(anchorUrl, Federation.builder().anchor(TA).leaf(LEAF, TA).build().entityConfiguration(TA), g.entityConfiguration(TA));
        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> g.validator(ValidatorOptions.defaults().withMaxFetches(3), TA).validate(ValidationRequest.forSubject(LEAF).build()));
        assertEquals(Kind.BUDGET, e.kind(), e.getMessage());
        assertEquals(1, g.http().hits(anchorUrl), "the second retrieval was not made");
    }

    /** The anchor configuration a caller asks to end the chain with is paid for, and its retrieval again too. */
    @Test
    void anAnchorConfigurationAskedForIsPaidFor() {
        Federation f = Federation.builder().anchor(TA).leaf(LEAF, TA).build();
        List<String> presented = List.of(f.entityConfiguration(LEAF), f.subordinateStatement(TA, LEAF));

        TrustChainValidationResult result = f.validator(TA).validate(ValidationRequest.forSubject(LEAF).presentedChain(presented)
                .includeAnchorConfiguration(true).build());

        assertEquals(3, result.trustChain().size());
        assertEquals(1, f.http().requests().size());
        assertEquals(1, result.fetchesUsed());

        // With nothing to spend the configuration is left out (§4 allows it), and nothing is fetched.
        Federation g = Federation.builder().anchor(TA).leaf(LEAF, TA).build();
        TrustChainValidationResult bare = g.validator(TA).validate(ValidationRequest.forSubject(LEAF)
                .presentedChain(List.of(g.entityConfiguration(LEAF), g.subordinateStatement(TA, LEAF)))
                .includeAnchorConfiguration(true).maxFetches(0).build());
        assertEquals(2, bare.trustChain().size());
        assertEquals(List.of(), g.http().requests());
    }

    // ---- one budget for everything the resolution does -----------------------------------------------

    @Test
    @Requirement("OIDFED §4.4(1)")
    void aPeerChainSpendsTheSameBudget() {
        Federation f = Federation.builder().anchor(TA).intermediate(INT, TA).leaf(LEAF, INT).leaf(OP, TA).build();
        // The leaf's chain presented whole, the OP's configuration alone: only the peer chain fetches.
        ValidationRequest request = ValidationRequest.forSubject(LEAF).opIssuer(OP).presentedChain(f.chain(LEAF, TA))
                .peerTrustChain(List.of(f.entityConfiguration(OP))).build();

        TrustChainValidationResult result = f.validator(TA).validate(request);

        assertEquals(OP, result.peerChain().orElseThrow().leafSubject());
        assertEquals(2, f.http().requests().size(), "the anchor's configuration and its statement about the OP");
        assertEquals(2, result.fetchesUsed(), "the peer chain's requests are the validation's");

        Federation g = Federation.builder().anchor(TA).intermediate(INT, TA).leaf(LEAF, INT).leaf(OP, TA).build();
        ValidationRequest same = ValidationRequest.forSubject(LEAF).opIssuer(OP).presentedChain(g.chain(LEAF, TA))
                .peerTrustChain(List.of(g.entityConfiguration(OP))).build();
        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> g.validator(ValidatorOptions.defaults().withMaxFetches(1), TA).validate(same));
        assertEquals(Kind.BUDGET, e.kind(), "running out in the peer chain ends the validation, as a budget refusal: " + e.getMessage());
        assertTrue(g.http().requests().size() <= 1);
    }

    @Test
    void aCallersBudgetIsSpentByTheValidationAndLimitedByTheRequest() {
        Federation f = threeLevels();
        ResolutionBudget mine = ResolutionBudget.of(Duration.ofSeconds(30), 100);

        TrustChainValidationResult result = f.validator(TA).validate(ValidationRequest.forSubject(LEAF).budget(mine).build());

        assertEquals(result.fetchesUsed(), mine.used(), "the validation spent the caller's budget");
        // A request's own limit still holds within the caller's budget.
        Federation g = threeLevels();
        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> g.validator(TA).validate(ValidationRequest.forSubject(LEAF).budget(mine).maxFetches(2).build()));
        assertTrue(e.getMessage().contains("budget of 2 requests"), e.getMessage());
        // And the caller's budget bounds the validation's, whatever the validator allows.
        Federation h = threeLevels();
        ResolutionBudget small = ResolutionBudget.of(Duration.ofSeconds(30), 2);
        TrustChainValidationException byCaller = assertThrows(TrustChainValidationException.class,
                () -> h.validator(TA).validate(ValidationRequest.forSubject(LEAF).budget(small).build()));
        assertTrue(byCaller.getMessage().contains("budget of 2 requests"), byCaller.getMessage());
        assertTrue(h.http().requests().size() <= 2);
    }

    /** A gateway that answers from the deployment itself costs a request of the budget but none on the network. */
    @Test
    void aLocalStatementCostsNoRequestOnTheNetwork() {
        Federation f = threeLevels();
        LocalStatementSource local = new LocalStatementSource() {
            @Override
            public String entityConfiguration(String entityId) {
                return EntityId.same(entityId, TA) ? f.entityConfiguration(TA) : null;
            }

            @Override
            public String subordinateStatement(String issuer, String subject) {
                return EntityId.same(issuer, TA) ? f.subordinateStatement(TA, subject) : null;
            }
        };
        TrustChainValidator validator = new TrustChainValidator(new LocalFirstTrustControllerGateway(f.gateway(TA), local),
                f.trustAnchors(), Set.of(), ValidatorOptions.defaults());

        TrustChainValidationResult result = validator.validate(ValidationRequest.forSubject(LEAF).includeAnchorConfiguration(true).build());

        assertEquals(0, f.http().hits(TA + "/.well-known/openid-federation"), "the anchor's statements came from the deployment");
        assertTrue(f.http().requests().size() <= result.fetchesUsed());
    }

    /** A gateway's own refusal that is not about the budget is a failed fetch, as any other: the route's, not the resolution's. */
    @Test
    void aGatewayFailureThatIsNotTheBudgetsLeavesTheRouteToFail() {
        Federation f = threeLevels();
        TrustControllerGateway refusing = new TrustControllerGateway() {
            @Override
            public org.jose4j.jwt.JwtClaims fetchEntityConfiguration() {
                throw new UnsupportedOperationException();
            }

            @Override
            public java.util.List<String> fetchMembers() {
                throw new UnsupportedOperationException();
            }

            @Override
            public String fetchEntityStatement(String issuer) throws Exception {
                return f.http().get(issuer + "/.well-known/openid-federation", "application/entity-statement+jwt");
            }

            @Override
            public String fetchSubordinateStatement(String issuer, String subject) {
                throw new TrustChainValidationException(Kind.SYNTAX, issuer, subject, "not a statement");
            }
        };
        TrustChainValidator validator = new TrustChainValidator(refusing, f.trustAnchors(), Set.of(), ValidatorOptions.defaults());

        TrustChainValidationException e = assertThrows(TrustChainValidationException.class,
                () -> validator.validate(ValidationRequest.forSubject(LEAF).build()));

        assertEquals(Kind.ROUTE, e.kind(), e.getMessage());
    }

    @Test
    void aConfigurationFetchedOutsideAResolutionHasABudgetOfItsOwn() throws Exception {
        Federation f = threeLevels();

        assertEquals(LEAF, f.gateway(TA).fetchEntityConfigurationOf(LEAF, null).getSubject());
        assertEquals(1, f.http().requests().size());
    }

    @Test
    void aBudgetAskedWhyItRanOutBeforeItHasSaysRequests() {
        TrustChainValidationException e = ResolutionBudget.of(Duration.ofSeconds(30), 5).exhausted();
        assertEquals(Kind.BUDGET, e.kind());
        assertTrue(e.getMessage().contains("budget of 5 requests"), e.getMessage());
    }
}
