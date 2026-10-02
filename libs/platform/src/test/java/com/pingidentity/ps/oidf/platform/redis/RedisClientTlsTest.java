package com.pingidentity.ps.oidf.platform.redis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The S3a guard on a real socket, inside the JVM, so a build without a TLS Redis still catches its loss. Each server's
 * certificate, made by {@code keytool} for this run and trusted through the CA file, names {@code localhost} and not
 * {@code 127.0.0.1}. Addressed by the name it carries, the client verifies the peer, sends the name as SNI,
 * authenticates and pings. Addressed by the address it does not carry, the handshake fails on the name and the
 * server reads nothing - no {@code AUTH}, so no password. The same holds through Sentinel: the sentinels are verified
 * against their own names, and a master a sentinel gives by address against the URL's host.
 * {@link RedisLiveTest} repeats the refusal against a real Redis when one is configured.
 */
class RedisClientTlsTest {
    private static final String PASSWORD = "not-a-real-password";

    @TempDir
    static Path dir;
    private static SSLContext serverContext;
    private static Path caFile;

    @BeforeAll
    static void makeACertificateThatNamesOnlyLocalhost() throws Exception {
        Path keystore = dir.resolve("redis.p12");
        Path ca = dir.resolve("redis-ca.pem");
        String storePass = "changeit-" + System.nanoTime();
        keytool("-genkeypair", "-alias", "redis", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=localhost",
                "-ext", "SAN=dns:localhost", "-validity", "2", "-keystore", keystore.toString(), "-storetype", "PKCS12",
                "-storepass", storePass, "-keypass", storePass);
        keytool("-exportcert", "-rfc", "-alias", "redis", "-keystore", keystore.toString(), "-storetype", "PKCS12",
                "-storepass", storePass, "-file", ca.toString());
        caFile = ca;
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            keys.load(in, storePass.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keys, storePass.toCharArray());
        serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), null, null);
    }

    @AfterAll
    static void nothingOutlivesTheClass() {
        serverContext = null;
    }

    private static RedisClient client(String url) {
        return new RedisClient(RedisConfig.builder(url).caFile(caFile).build());
    }

    @Test
    void theNameTheCertificateCarriesIsVerifiedSentAsSniAndThenAuthenticated() throws Exception {
        try (FakeRedis server = new FakeRedis(PASSWORD, FakeRedis.Role.MASTER, serverContext);
             RedisClient client = client("rediss://:" + PASSWORD + "@localhost:" + server.port())) {
            assertTrue(client.ping());
            assertEquals(List.of("AUTH " + PASSWORD, "PING"), server.commands());
            assertEquals(List.of("localhost"), server.sniNames(), "the host goes out as SNI");
        }
    }

    @Test
    void anAddressTheCertificateDoesNotCarryFailsTheHandshakeBeforeAnyCommand() throws Exception {
        try (FakeRedis server = new FakeRedis(PASSWORD, FakeRedis.Role.MASTER, serverContext);
             RedisClient client = client("rediss://:" + PASSWORD + "@127.0.0.1:" + server.port())) {
            SSLHandshakeException e = assertThrows(SSLHandshakeException.class, client::ping);
            assertTrue(String.valueOf(e.getMessage()).contains("127.0.0.1"), e.getMessage());
            server.awaitHandshakes(1);
            assertEquals(List.of(), server.commands(), "nothing was sent: the password never left");
        }
    }

    @Test
    void theJvmsCasDidNotIssueTheTestCertificate() throws Exception {
        try (FakeRedis server = new FakeRedis(PASSWORD, FakeRedis.Role.MASTER, serverContext);
             RedisClient client = new RedisClient(RedisConfig.builder("rediss://:" + PASSWORD + "@localhost:" + server.port()).build())) {
            assertThrows(SSLHandshakeException.class, client::ping);
            server.awaitHandshakes(1);
            assertEquals(List.of(), server.commands());
        }
    }

    @Test
    void throughSentinelTheSentinelsAndTheMasterAreVerifiedTheSameWay() throws Exception {
        try (FakeRedis sentinel = new FakeRedis(null, FakeRedis.Role.SENTINEL, serverContext);
             FakeRedis master = new FakeRedis(PASSWORD, FakeRedis.Role.MASTER, serverContext)) {
            // The sentinel reports an address, as Sentinel does by default: the master is checked against the URL's host.
            sentinel.master("mymaster", "127.0.0.1", master.port());
            try (RedisClient client = sentinelClient("localhost", "localhost:" + sentinel.port())) {
                assertTrue(client.ping());
                assertEquals(List.of("localhost"), sentinel.sniNames());
                assertEquals(List.of("localhost"), master.sniNames());
                assertEquals(List.of("AUTH " + PASSWORD, "ROLE", "PING"), master.commands());
            }
            master.clearCommands();
            sentinel.clearCommands();
            try (RedisClient client = sentinelClient("redis.example", "localhost:" + sentinel.port())) {
                assertThrows(IOException.class, client::ping, "the master's certificate does not name the URL's host");
                master.awaitHandshakes(1);
                assertEquals(List.of(), master.commands(), "nothing was sent to it");
            }
            // A sentinel that announces host names: the name it gives is the one checked.
            sentinel.master("mymaster", "localhost", master.port());
            master.clearCommands();
            try (RedisClient client = sentinelClient("redis.example", "localhost:" + sentinel.port())) {
                assertTrue(client.ping());
            }
            sentinel.clearCommands();
            try (RedisClient client = sentinelClient("localhost", "127.0.0.1:" + sentinel.port())) {
                IOException e = assertThrows(IOException.class, client::ping);
                assertTrue(e.getMessage().contains("no sentinel named the master"), e.getMessage());
                sentinel.awaitHandshakes(1);
                assertEquals(List.of(), sentinel.commands(), "a sentinel dialled by an address its certificate lacks is asked nothing");
            }
        }
    }

    private static RedisClient sentinelClient(String urlHost, String sentinel) {
        return new RedisClient(RedisConfig.builder("rediss://:" + PASSWORD + "@" + urlHost + ":6379").caFile(caFile)
                .profile(DeploymentProfile.PRODUCTION).sentinel("mymaster", List.of(sentinel), null).build());
    }

    private static void keytool(String... args) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
        Collections.addAll(command, args);
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IllegalStateException("keytool failed: " + output);
        }
    }
}
