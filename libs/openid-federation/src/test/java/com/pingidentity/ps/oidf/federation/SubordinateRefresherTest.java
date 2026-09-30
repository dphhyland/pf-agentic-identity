package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.jose.HttpGetClient;
import com.pingidentity.ps.oidf.jose.JdkHttpGetClient;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutor;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutors;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The subordinate refresher keeps each configured subordinate's entity configuration cached off the request path:
 * a round at once, then every interval, on one managed executor for the JVM; a subordinate that cannot be reached
 * does not stop the round, and shutdown ends a round at the next subordinate.
 */
class SubordinateRefresherTest {

    private static final String ANCHOR = "https://anchor.example.com";
    private static final String DOWN = "https://down.example.com";
    private static final String LEAF = "https://leaf.example.com";

    private final List<String> fetched = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() {
        ManagedExecutors.live(FederationService.SUBORDINATE_REFRESH).ifPresent(ManagedExecutor::close);
    }

    private static FederationService anchor(List<String> subordinates, HttpGetClient fetcher) throws Exception {
        FederationConfiguration config = new FederationConfiguration(
                List.of(ANCHOR), subordinates, null, false, false, null, null, null, 0, "RS256", null);
        return new FederationService(config, keys("anchor-key"), fetcher);
    }

    private static ManagedExecutor refresher() {
        return ManagedExecutors.live(FederationService.SUBORDINATE_REFRESH).orElseThrow();
    }

    private static void awaitRuns(ManagedExecutor executor, long runs) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
        while (executor.runs() < runs) {
            assertTrue(System.nanoTime() < deadline, "timed out waiting for " + runs + " run(s)");
            Thread.sleep(10);
        }
    }

    @Test
    void theFirstRoundRunsAtOnceAndAnUnreachableSubordinateDoesNotStopIt() throws Exception {
        String leafConfig = new FederationService(new FederationConfiguration(
                List.of(ANCHOR), List.of(), null, false, false, null, null, null, 0, "RS256", null), keys("leaf-key"))
                .createEntityConfigurationJwt(LEAF);
        FederationService anchor = anchor(List.of(DOWN, LEAF), (url, accept) -> {
            this.fetched.add(url);
            if (url.startsWith(DOWN)) {
                throw new IOException("connection refused");
            }
            return leafConfig;
        });

        anchor.prewarmSubordinatesAsync();
        ManagedExecutor executor = refresher();
        assertEquals("oidf-subordinate-refresh", executor.threadNamePrefix());
        awaitRuns(executor, 1);

        assertEquals(List.of(DOWN + "/.well-known/openid-federation", LEAF + "/.well-known/openid-federation"), this.fetched,
                "one round, both subordinates, the second despite the first failing");
        assertEquals(0, executor.failures(), "the refresher's own catch logs each failure");
        anchor.createEntityStatement(LEAF, null, ANCHOR);
        assertEquals(2, this.fetched.size(), "the statement is served from what the round cached, with no fetch");
    }

    @Test
    void oneRefresherRunsInTheJvm() throws Exception {
        CountDownLatch fetching = new CountDownLatch(1);
        FederationService first = anchor(List.of(LEAF), (url, accept) -> {
            fetching.countDown();
            throw new IOException("down");
        });
        first.prewarmSubordinatesAsync();
        assertTrue(fetching.await(10, TimeUnit.SECONDS));
        ManagedExecutor running = refresher();

        anchor(List.of(LEAF), (url, accept) -> {
            throw new AssertionError("a second refresher must not start");
        }).prewarmSubordinatesAsync();
        assertEquals(running, refresher(), "a servlet initialised twice, or another loader's copy, starts nothing");
    }

    @Test
    void shutdownEndsARoundAtTheNextSubordinate() throws Exception {
        CountDownLatch fetching = new CountDownLatch(1);
        FederationService anchor = anchor(List.of(DOWN, LEAF), (url, accept) -> {
            this.fetched.add(url);
            fetching.countDown();
            // As HttpClient.send does: the InterruptedException is thrown with the thread's flag already cleared.
            Thread.sleep(10_000);
            return "";
        });
        anchor.prewarmSubordinatesAsync();
        assertTrue(fetching.await(10, TimeUnit.SECONDS));
        ManagedExecutor executor = refresher();

        assertTrue(executor.close(java.time.Duration.ofSeconds(5)), "the round ended within the wait");
        assertEquals(List.of(DOWN + "/.well-known/openid-federation"), this.fetched, "the next subordinate was not tried");
        assertEquals(0, executor.failures());
        assertEquals(Optional.empty(), ManagedExecutors.live(FederationService.SUBORDINATE_REFRESH));
    }

    @Test
    void shutdownEndsARoundAtTheNextSubordinateWithTheProductionClient() throws Exception {
        // A subordinate that accepts the connection and never answers: the round is stuck in HttpClient.send when
        // the executor closes, and the second subordinate must not be fetched after it.
        try (ServerSocket silent = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            CountDownLatch accepted = new CountDownLatch(1);
            List<Socket> held = new CopyOnWriteArrayList<>();
            Thread acceptor = new Thread(() -> {
                try {
                    while (true) {
                        held.add(silent.accept());
                        accepted.countDown();
                    }
                } catch (IOException closed) {
                    // the test is over
                }
            });
            acceptor.setDaemon(true);
            acceptor.start();
            String base = "http://127.0.0.1:" + silent.getLocalPort();
            FederationService anchor = anchor(List.of(base + "/a", base + "/b"),
                    new JdkHttpGetClient(false, OutboundUrlPolicy.permissive()));
            anchor.prewarmSubordinatesAsync();
            assertTrue(accepted.await(10, TimeUnit.SECONDS));
            ManagedExecutor executor = refresher();

            assertTrue(executor.close(java.time.Duration.ofSeconds(5)), "the round ended within the wait");
            assertEquals(1, held.size(), "the next subordinate was not tried");
            assertEquals(0, executor.failures());
            for (Socket socket : held) {
                socket.close();
            }
        }
    }

    @Test
    void nothingStartsWithoutAFetcherOrSubordinates() throws Exception {
        anchor(List.of(), (url, accept) -> "").prewarmSubordinatesAsync();
        FederationConfiguration config = new FederationConfiguration(
                List.of(ANCHOR), List.of(LEAF), null, false, false, null, null, null, 0, "RS256", null);
        new FederationService(config, keys("anchor-key")).prewarmSubordinatesAsync();
        assertEquals(Optional.empty(), ManagedExecutors.live(FederationService.SUBORDINATE_REFRESH));
    }

    private static SigningKeyProvider keys(String keyId) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        return new SigningKeyProvider() {
            @Override
            public String keyId() {
                return keyId;
            }

            @Override
            public RSAPrivateKey privateKey() {
                return (RSAPrivateKey) keyPair.getPrivate();
            }

            @Override
            public RSAPublicKey publicKey() {
                return (RSAPublicKey) keyPair.getPublic();
            }
        };
    }
}
