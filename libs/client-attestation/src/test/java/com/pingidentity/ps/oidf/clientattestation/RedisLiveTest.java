package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.pingidentity.ps.oidf.clientattestation.AttestationChallengeService.Consumption;
import com.pingidentity.ps.oidf.clientattestation.AttestationReplayCache.Verdict;
import com.pingidentity.ps.oidf.clientattestation.EvidenceBindingStore.Binding;
import java.net.URI;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The stores against a real Redis, which the fake server cannot stand in for: the TLS handshake with a
 * certificate, its hostname check, and the commands as Redis itself parses them. Skipped, with the reason,
 * unless the environment names a server:
 *
 * <ul>
 *   <li>{@code OIDF_TEST_REDIS_URL} - a plaintext {@code redis://} URL, password included;</li>
 *   <li>{@code OIDF_TEST_REDIS_TLS_URL} - a {@code rediss://} URL whose host the server's certificate names;</li>
 *   <li>{@code OIDF_TEST_REDIS_CA_FILE} - the PEM CA that issued that certificate.</li>
 * </ul>
 *
 * <p>Locally: {@code redis:7-alpine} with {@code --requirepass}, and a second one with {@code --tls-port} and a
 * self-signed certificate for {@code localhost} (the README of this module has the commands, and
 * {@code tools/ci/start-tls-redis.sh} starts the second). In CI, build.yml's java job runs both halves: its
 * {@code redis} service for the plain one, and the TLS Redis that script starts for the other.
 */
class RedisLiveTest {
    private static final String PLAIN = System.getenv("OIDF_TEST_REDIS_URL");
    private static final String TLS = System.getenv("OIDF_TEST_REDIS_TLS_URL");
    private static final String CA = System.getenv("OIDF_TEST_REDIS_CA_FILE");

    private static void needPlain() {
        assumeTrue(PLAIN != null && !PLAIN.isBlank(), "set OIDF_TEST_REDIS_URL to run the live Redis tests");
    }

    private static void needTls() {
        assumeTrue(TLS != null && !TLS.isBlank() && CA != null && !CA.isBlank(),
                "set OIDF_TEST_REDIS_TLS_URL and OIDF_TEST_REDIS_CA_FILE to run the live TLS Redis tests");
    }

    private static long now() {
        return Instant.now().getEpochSecond();
    }

    private static String unique(String prefix) {
        return prefix + "-" + UUID.randomUUID();
    }

    @Test
    void challengesReplayAndBindingsWorkAgainstRedis() throws Exception {
        needPlain();
        try (MiniRedisClient client = new MiniRedisClient(PLAIN, null, false);
             RedisAttestationStore store = new RedisAttestationStore(client, true, StoreNamespace.CAS, 300L, java.time.Clock.systemUTC())) {
            String challenge = store.issue();
            assertEquals(Consumption.CONSUMED, store.consumeChallenge(challenge));
            assertEquals(Consumption.UNKNOWN, store.consumeChallenge(challenge));

            String client1 = unique("https://client.example/");
            assertEquals(Verdict.FIRST_USE, store.record(client1, "jti-1", 300L));
            assertEquals(Verdict.REPLAY, store.record(client1, "jti-1", 300L));

            String digest = unique("sha");
            assertEquals(Binding.BOUND, store.bind(digest, "jkt-1", client1, now() + 120L).binding());
            assertEquals(Binding.BOUND, store.bind(digest, "jkt-1", client1, now() + 120L).binding());
            assertEquals(Binding.CONFLICT, store.bind(digest, "jkt-2", client1, now() + 120L).binding());
            assertEquals("jkt-1", store.bind(digest, "jkt-2", client1, now() + 120L).holderJkt());
            assertEquals(Binding.CONFLICT, store.bind(digest, "jkt-1", client1 + "x", now() + 120L).binding());

            // The keys are where the README says, and Redis holds the binding's TTL.
            Object ttl = client.call("TTL", "oidf:cas:evidence:" + digest);
            assertTrue(ttl instanceof Long && (Long) ttl > 0L && (Long) ttl <= 120L, String.valueOf(ttl));
            assertEquals(1L, client.call("EXISTS", "oidf:cas:jti:" + client1 + " jti-1"));
            client.call("DEL", "oidf:cas:evidence:" + digest, "oidf:cas:jti:" + client1 + " jti-1");
        }
    }

    @Test
    void theClientAuthenticatesOverTlsAfterVerifyingTheServer() throws Exception {
        needTls();
        try (RedisAttestationStore store = new RedisAttestationStore(new MiniRedisClient(TLS, CA, true), true,
                StoreNamespace.AS, 300L, java.time.Clock.systemUTC())) {
            String challenge = store.issue();
            assertNotNull(challenge);
            assertEquals(Consumption.CONSUMED, store.consumeChallenge(challenge));
        }
    }

    @Test
    void aServerWhoseCertificateDoesNotNameTheHostIsRefusedBeforeAuth() throws Exception {
        needTls();
        URI tls = URI.create(TLS);
        assumeTrue(!MiniRedisClient.isIpLiteral(tls.getHost()), "the TLS URL must use the certificate's name, so an address can be the mismatch");
        String byAddress = TLS.replace(tls.getHost(), "127.0.0.1");
        try (RedisAttestationStore store = new RedisAttestationStore(new MiniRedisClient(byAddress, CA, true), true,
                StoreNamespace.AS, 300L, java.time.Clock.systemUTC())) {
            StoreUnavailableException e = assertThrows(StoreUnavailableException.class, store::issue);
            assertNotNull(e.getCause(), "the handshake failure is the cause: the certificate names the host, not the address");
            assertEquals(Consumption.STORE_UNAVAILABLE, store.consumeChallenge("x"));
        }
    }

    @Test
    void aServerTheCaFileDidNotIssueIsRefused() throws Exception {
        needTls();
        try (RedisAttestationStore store = new RedisAttestationStore(new MiniRedisClient(TLS, null, true), true,
                StoreNamespace.AS, 300L, java.time.Clock.systemUTC())) {
            assertThrows(StoreUnavailableException.class, store::issue,
                    "the JVM's CAs did not issue the test certificate");
        }
    }

    @Test
    void plaintextIsRefusedUnderProductionEvenWhenTheServerIsThere() {
        needPlain();
        assertThrows(IllegalArgumentException.class, () -> new MiniRedisClient(PLAIN, null, true));
    }
}
