package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What the client does before a password crosses the wire: verify the peer's name (S3a), send SNI, trust the
 * CA file it was given, and refuse plaintext where the profile is production. The live half - a real
 * handshake against a Redis with a certificate - is {@link RedisLiveTest}.
 */
class MiniRedisClientTest {

    /** A self-signed test CA, generated for these tests and valid for a century; nothing trusts it but them. */
    static final String CA_PEM = "-----BEGIN CERTIFICATE-----\n"
            + "MIIBkDCCATWgAwIBAgIUT7W0E2vQt2hkDq1dm4YOELWoK4owCgYIKoZIzj0EAwIw\n"
            + "HDEaMBgGA1UEAwwRcGZhaS1wMWV2IHRlc3QgQ0EwIBcNMjYwOTI3MDIxODQ0WhgP\n"
            + "MjEyNjA5MDMwMjE4NDRaMBwxGjAYBgNVBAMMEXBmYWktcDFldiB0ZXN0IENBMFkw\n"
            + "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZ04uBUEPrPwPQIccCbNssWOACKDrKSZt\n"
            + "iMECl/Ozss4Su+cwUDUKRs7jV9HWFLFlUMOXVR0WKmnQZCh2oxJfzqNTMFEwHQYD\n"
            + "VR0OBBYEFKjiCvpM9+CEUQeJ5DT0eFpO1gH6MB8GA1UdIwQYMBaAFKjiCvpM9+CE\n"
            + "UQeJ5DT0eFpO1gH6MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIh\n"
            + "AKDFssXzUor82tzfoBvP4b4GoiCKm3UrhfhwpYlK9D/gAiEAt4LlfYE7R7sDWXj1\n"
            + "PPaY/awp9tZpmfKHF8fe4ZTLd9I=\n"
            + "-----END CERTIFICATE-----\n";

    @Test
    void tlsParametersVerifyThePeerNameAndSendIt() {
        SSLParameters p = MiniRedisClient.sslParametersFor(new SSLParameters(), "cache.example.com");
        assertEquals("HTTPS", p.getEndpointIdentificationAlgorithm(),
                "the certificate must name the host, as RFC 2818 §3.1 checks it");
        assertEquals(List.of(new SNIHostName("cache.example.com")), p.getServerNames());
    }

    @Test
    void anIpLiteralIsVerifiedButNotSentAsSni() {
        SSLParameters v4 = MiniRedisClient.sslParametersFor(new SSLParameters(), "127.0.0.1");
        assertEquals("HTTPS", v4.getEndpointIdentificationAlgorithm());
        assertNull(v4.getServerNames(), "RFC 6066 §3 permits no IP literal in SNI");
        SSLParameters v6 = MiniRedisClient.sslParametersFor(new SSLParameters(), "[::1]");
        assertNull(v6.getServerNames());
        assertTrue(MiniRedisClient.isIpLiteral("10.0.0.1"));
        assertTrue(MiniRedisClient.isIpLiteral("[fe80::1]"));
        assertFalse(MiniRedisClient.isIpLiteral("localhost"));
        assertFalse(MiniRedisClient.isIpLiteral("10.0.0.1.example"));
    }

    @Test
    void plaintextIsRefusedUnderTheProductionProfile() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new MiniRedisClient("redis://:pw@cache.example.com:6379", null, true));
        assertTrue(e.getMessage().contains("rediss://"), e.getMessage());
        assertTrue(e.getMessage().contains(DeploymentProfile.PROFILE_ENV), e.getMessage());
    }

    @Test
    void plaintextIsAllowedInDevelopmentAndTlsIsAllowedEverywhere() {
        try (MiniRedisClient dev = new MiniRedisClient("redis://cache.example.com", null, false)) {
            assertFalse(dev.tls());
        }
        try (MiniRedisClient prod = new MiniRedisClient("rediss://cache.example.com", null, true)) {
            assertTrue(prod.tls(), "the constructor does not connect; the URL alone is judged here");
        }
    }

    @Test
    void theEnvironmentConstructorReadsTheProfileAndAllowsPlaintextOnlyInDevelopment() {
        // The one-argument constructor reads OIDF_DEPLOYMENT_PROFILE from the real environment, which the
        // build does not set: production, so plaintext is refused there too.
        if (DeploymentProfile.isProduction(System::getenv)) {
            assertThrows(IllegalArgumentException.class, () -> new MiniRedisClient("redis://cache.example.com"));
        }
        try (MiniRedisClient c = new MiniRedisClient("rediss://cache.example.com")) {
            assertTrue(c.tls());
        }
    }

    @Test
    void urlShapesStillParse() {
        assertThrows(IllegalArgumentException.class, () -> new MiniRedisClient("http://cache.example.com", null, false));
        assertThrows(IllegalArgumentException.class, () -> new MiniRedisClient("redis:///nohost", null, false));
        assertThrows(IllegalArgumentException.class, () -> new MiniRedisClient("redis://cache.example.com/x", null, false));
        new MiniRedisClient("redis://user:p%40ss@cache.example.com:6380/2", null, false).close();
        new MiniRedisClient("redis://p%40ss@cache.example.com", null, false).close();
    }

    @Test
    void aCaFileIsTrustedInsteadOfTheJvmsStore(@TempDir Path dir) throws Exception {
        Path ca = dir.resolve("redis-ca.pem");
        Files.writeString(ca, CA_PEM);
        SSLContext context = MiniRedisClient.sslContextFor(ca.toString());
        assertNotNull(context);
        try (MiniRedisClient c = new MiniRedisClient("rediss://cache.example.com", ca.toString(), true)) {
            assertTrue(c.tls());
        }
        assertNotNull(MiniRedisClient.sslContextFor(null), "no file: the JVM default");
        assertNotNull(MiniRedisClient.sslContextFor("  "));
    }

    @Test
    void aCaFileThatCannotBeUsedIsRefusedNamingTheVariable(@TempDir Path dir) throws Exception {
        IllegalArgumentException missing = assertThrows(IllegalArgumentException.class,
                () -> MiniRedisClient.sslContextFor(dir.resolve("absent.pem").toString()));
        assertTrue(missing.getMessage().contains(MiniRedisClient.CA_FILE_ENV), missing.getMessage());
        Path empty = dir.resolve("empty.pem");
        Files.writeString(empty, "not a certificate\n");
        IllegalArgumentException noCert = assertThrows(IllegalArgumentException.class,
                () -> MiniRedisClient.sslContextFor(empty.toString()));
        assertTrue(noCert.getMessage().contains(MiniRedisClient.CA_FILE_ENV), noCert.getMessage());
    }

    @Test
    void theCaFileComesFromThePropertyThenTheVariable() {
        assertEquals("/p", MiniRedisClient.caFileFromEnvironment(Map.of("oidf.redis.ca.file", " /p ")::get, k -> "/e"));
        assertEquals("/e", MiniRedisClient.caFileFromEnvironment(k -> null, Map.of("OIDF_REDIS_CA_FILE", "/e")::get));
        assertEquals("/e", MiniRedisClient.caFileFromEnvironment(k -> " ", Map.of("OIDF_REDIS_CA_FILE", "/e")::get));
        assertNull(MiniRedisClient.caFileFromEnvironment(k -> null, k -> null));
        assertNull(MiniRedisClient.caFileFromEnvironment(k -> null, k -> " "));
    }
}
