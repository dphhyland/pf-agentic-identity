package com.pingidentity.ps.oidf.platform.redis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What a client is built from, before anything connects: the URL (0.4.0's shapes, with the userinfo never in a
 * message), the plaintext rule under the production profile, the CA file, and the catalogue's settings for the pool,
 * the deadlines and Sentinel, parsed strictly.
 */
class RedisConfigTest {

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

    private static RedisConfig.Builder dev(String url) {
        return RedisConfig.builder(url).profile(DeploymentProfile.DEVELOPMENT);
    }

    private static Settings settings(Map<String, String> env, Map<String, String> props) {
        return Settings.of(Catalogue.load(RedisConfigTest.class.getClassLoader(), RedisConfig.COMPONENT),
                Sources.of(env::get, props::get, null));
    }

    // --- the URL -------------------------------------------------------------------------------------------------

    @Test
    void urlShapesParseAsZeroFourZeroParsedThem() {
        RedisUrl full = RedisUrl.parse(" rediss://user:p%40ss@cache.example.com:6380/2 ");
        assertTrue(full.tls);
        assertEquals("cache.example.com", full.host);
        assertEquals(6380, full.port);
        assertEquals("user", full.username);
        assertEquals("p@ss", full.password);
        assertEquals(2, full.db);
        assertTrue(full.authenticates());

        RedisUrl bare = RedisUrl.parse("redis://p%40ss@cache.example.com");
        assertFalse(bare.tls);
        assertNull(bare.username, "a bare userinfo is the password");
        assertEquals("p@ss", bare.password);
        assertEquals(6379, bare.port);
        assertEquals(0, bare.db);

        RedisUrl emptyUser = RedisUrl.parse("redis://:pw@h/");
        assertNull(emptyUser.username);
        assertEquals("pw", emptyUser.password);
        assertEquals(0, emptyUser.db, "a path of / is database 0");

        RedisUrl none = RedisUrl.parse("REDIS://h");
        assertNull(none.password);
        assertFalse(none.authenticates());
        assertFalse(RedisUrl.parse("redis://:@h").authenticates(), "an empty password sends no AUTH");
        assertFalse(RedisUrl.parse("redis://@h").authenticates());
    }

    @Test
    void theUserinfoIsDecodedTwiceAsInZeroFourZero() {
        // F-0180: URI decodes the escapes, then URLDecoder decodes again, so '+' is a space and %2525 is '%'.
        assertEquals("a b", RedisUrl.parse("redis://:a+b@h").password);
        assertEquals("a%b", RedisUrl.parse("redis://:a%2525b@h").password);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> RedisUrl.parse("redis://:s%25zz@h"));
        assertFalse(e.getMessage().contains("zz"), e.getMessage());
    }

    @Test
    void urlsThisClientDoesNotTakeAreRefusedWithoutTheirUserinfo() {
        assertTrue(assertThrows(IllegalArgumentException.class, () -> RedisUrl.parse("http://h")).getMessage().contains("scheme"));
        assertThrows(IllegalArgumentException.class, () -> RedisUrl.parse("h:6379"));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> RedisUrl.parse("cache.example.com")).getMessage()
                .contains("scheme: null"), "no scheme at all");
        IllegalArgumentException noHost = assertThrows(IllegalArgumentException.class, () -> RedisUrl.parse("rediss://:s3cret@redis_cache:6379"));
        assertFalse(noHost.getMessage().contains("s3cret"), noHost.getMessage());
        IllegalArgumentException bad = assertThrows(IllegalArgumentException.class, () -> RedisUrl.parse("rediss://:s3 cret@cache.example.com"));
        assertFalse(bad.getMessage().contains("s3"), bad.getMessage());
        assertThrows(IllegalArgumentException.class, () -> RedisUrl.parse("redis://cache.example.com/x"));
    }

    @Test
    void redactTakesEverythingBetweenTheSchemeAndTheLastAt() {
        assertEquals("rediss://***@h:1/0", RedisUrl.redact("rediss://u:p@ss/w@h:1/0"));
        assertEquals("rediss://h:1", RedisUrl.redact("rediss://h:1"));
        assertEquals("no-scheme@h", RedisUrl.redact("no-scheme@h"));
        assertNull(RedisUrl.redact(null));
    }

    // --- the transport -------------------------------------------------------------------------------------------

    @Test
    void plaintextIsRefusedUnderProductionThroughTheProfileGuard() {
        assertNull(RedisClient.transportRefusal(true, DeploymentProfile.PRODUCTION));
        assertNull(RedisClient.transportRefusal(true, DeploymentProfile.DEVELOPMENT));
        assertNull(RedisClient.transportRefusal(false, DeploymentProfile.DEVELOPMENT));
        String refusal = RedisClient.transportRefusal(false, DeploymentProfile.PRODUCTION);
        assertTrue(refusal.contains("rediss://") && refusal.contains(DeploymentProfile.SETTING), refusal);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new RedisClient(RedisConfig.builder("redis://:pw@cache.example.com:6379").build()));
        assertEquals(refusal, e.getMessage());
        assertFalse(e.getMessage().contains("pw"), e.getMessage());
        try (RedisClient plain = new RedisClient(dev("redis://cache.example.com").build());
             RedisClient tls = new RedisClient(RedisConfig.builder("rediss://cache.example.com").build())) {
            assertFalse(plain.tls());
            assertTrue(tls.tls(), "the constructor does not connect; the URL alone is judged here");
            assertFalse(tls.sentinel());
        }
    }

    @Test
    void tlsVerifiesTheNameAndSendsItAsSni() {
        SSLParameters named = RedisTls.sslParametersFor(new SSLParameters(), "cache.example.com");
        assertEquals("HTTPS", named.getEndpointIdentificationAlgorithm());
        assertEquals(List.of(new SNIHostName("cache.example.com")), named.getServerNames());
        SSLParameters v4 = RedisTls.sslParametersFor(new SSLParameters(), "127.0.0.1");
        assertEquals("HTTPS", v4.getEndpointIdentificationAlgorithm(), "an address is still checked, against the certificate");
        assertTrue(v4.getServerNames() == null || v4.getServerNames().isEmpty(), "no IP literal in SNI");
        assertTrue(RedisTls.isIpLiteral("[fe80::1]"));
        assertTrue(RedisTls.isIpLiteral("fe80::1"), "a sentinel reports an IPv6 address without brackets");
        assertTrue(RedisTls.isIpLiteral("10.0.0.1"));
        assertFalse(RedisTls.isIpLiteral("localhost"));
        assertFalse(RedisTls.isIpLiteral("10.0.0.1.example"));
    }

    @Test
    void aCaFileIsTrustedInsteadOfTheJvmsStoreAndOneThatCannotBeUsedIsRefusedNamingTheSetting(@TempDir Path dir) throws Exception {
        Path ca = dir.resolve("redis-ca.pem");
        Files.writeString(ca, CA_PEM);
        assertNotNull(RedisTls.sslContextFor(ca));
        assertNotNull(RedisTls.sslContextFor(null), "no file: the JVM default");
        assertNotNull(RedisTls.jvmDefaultContext());
        try (RedisClient c = new RedisClient(RedisConfig.builder("rediss://cache.example.com").caFile(ca).build())) {
            assertTrue(c.tls());
        }

        IllegalArgumentException missing = assertThrows(IllegalArgumentException.class, () -> RedisTls.sslContextFor(dir.resolve("absent.pem")));
        assertTrue(missing.getMessage().contains(RedisConfig.CA_FILE_SETTING), missing.getMessage());
        Path junk = dir.resolve("junk.pem");
        Files.writeString(junk, "not a certificate\n");
        assertTrue(assertThrows(IllegalArgumentException.class, () -> RedisTls.sslContextFor(junk)).getMessage()
                .contains(RedisConfig.CA_FILE_SETTING));
        Path empty = dir.resolve("empty.pem");
        Files.writeString(empty, "");
        assertTrue(assertThrows(IllegalArgumentException.class, () -> RedisTls.sslContextFor(empty)).getMessage()
                .contains("holds no certificate"));
    }

    // --- the builder ---------------------------------------------------------------------------------------------

    @Test
    void theBuilderStartsFromTheCatalogueDefaultsAndChecksEachValue() {
        RedisConfig config = RedisConfig.builder(" rediss://h ").build();
        assertEquals("rediss://h", config.url());
        assertEquals(DeploymentProfile.PRODUCTION, config.profile());
        assertEquals(8, config.poolSize());
        assertEquals(Duration.ofMillis(1000), config.borrowTimeout());
        assertEquals(Duration.ofMillis(3000), config.commandTimeout());
        assertNull(config.caFile());
        assertNull(config.sentinelMaster());
        assertEquals(List.of(), config.sentinels());

        assertThrows(IllegalArgumentException.class, () -> RedisConfig.builder(null));
        assertThrows(IllegalArgumentException.class, () -> RedisConfig.builder(" "));
        assertThrows(NullPointerException.class, () -> RedisConfig.builder("rediss://h").profile(null));
        assertThrows(IllegalArgumentException.class, () -> RedisConfig.builder("rediss://h").poolSize(0));
        assertThrows(IllegalArgumentException.class, () -> RedisConfig.builder("rediss://h").poolSize(257));
        assertEquals(256, RedisConfig.builder("rediss://h").poolSize(256).build().poolSize());
        assertThrows(IllegalArgumentException.class, () -> RedisConfig.builder("rediss://h").borrowTimeout(null));
        assertThrows(IllegalArgumentException.class, () -> RedisConfig.builder("rediss://h").borrowTimeout(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> RedisConfig.builder("rediss://h").commandTimeout(Duration.ofMillis(-1)));
    }

    @Test
    void sentinelTakesAMasterNameAndAtLeastOneSentinel() {
        RedisConfig config = RedisConfig.builder("rediss://:pw@cache.example.com")
                .sentinel(" mymaster ", List.of("s1", "s2:26380", "[::1]:26381", "[fe80::1]"), "sentinel-secret").build();
        assertEquals("mymaster", config.sentinelMaster());
        assertEquals(List.of(new RedisConfig.HostPort("s1", 26379), new RedisConfig.HostPort("s2", 26380),
                new RedisConfig.HostPort("::1", 26381), new RedisConfig.HostPort("fe80::1", 26379)), config.sentinels());
        assertEquals("sentinel-secret", config.sentinelPassword());
        assertEquals("[::1]:26381", config.sentinels().get(2).toString());
        assertEquals("s1:26379", config.sentinels().get(0).toString());
        String shown = config.toString();
        assertFalse(shown.contains("pw") || shown.contains("sentinel-secret"), shown);
        assertTrue(shown.contains("sentinelPassword=[secret]") && shown.contains("mymaster"), shown);
        assertFalse(RedisConfig.builder("rediss://h").sentinel("m", List.of("s"), null).build().toString().contains("sentinelPassword"));
        assertNull(RedisConfig.builder("rediss://h").sentinel("m", List.of("s"), "").build().sentinelPassword());
        assertFalse(RedisConfig.builder("rediss://h").build().toString().contains("sentinel"));

        assertThrows(IllegalArgumentException.class, () -> RedisConfig.builder("rediss://h").sentinel(null, List.of("s"), null));
        assertThrows(IllegalArgumentException.class, () -> RedisConfig.builder("rediss://h").sentinel(" ", List.of("s"), null));
        assertThrows(IllegalArgumentException.class, () -> RedisConfig.builder("rediss://h").sentinel("m", List.of(), null));
        assertThrows(NullPointerException.class, () -> new RedisConfig.HostPort(null, 1));
    }

    @Test
    void aSentinelEntryIsHostOrHostAndPort() {
        for (String bad : new String[]{"", ":26379", "h:", "h:x", "h:0", "h:65536", "a:b:c", "[::1", "[::1]x", "[::1]:", "[]:1"}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> RedisConfig.HostPort.parse(bad), bad);
            assertTrue(e.getMessage().contains(RedisConfig.SENTINELS_SETTING), e.getMessage());
        }
        assertEquals(new RedisConfig.HostPort("h", 65535), RedisConfig.HostPort.parse(" h:65535 "));
        assertEquals(new RedisConfig.HostPort("h", 1), RedisConfig.HostPort.parse("h:1"));
    }

    // --- the catalogue -------------------------------------------------------------------------------------------

    @Test
    void theCatalogueLoadsAndDeclaresTodaysNamesAndTheNewOnes() {
        Catalogue catalogue = Catalogue.load(RedisConfigTest.class.getClassLoader(), RedisConfig.COMPONENT);
        assertEquals("com.pingidentity.ps.oidf.platform.redis", catalogue.owningPackage());
        assertEquals(List.of("OIDF_REDIS_"), catalogue.families());
        Set<String> names = catalogue.declaredEnvironmentNames();
        for (String name : List.of("OIDF_REDIS_URL", "REDIS_URL", "OIDF_REDIS_CA_FILE", "OIDF_REDIS_POOL_SIZE",
                "OIDF_REDIS_BORROW_TIMEOUT_MS", "OIDF_REDIS_COMMAND_TIMEOUT_MS", "OIDF_REDIS_SENTINEL_MASTER",
                "OIDF_REDIS_SENTINELS", "OIDF_REDIS_SENTINEL_PASSWORD", "OIDF_REDIS_SENTINEL_PASSWORD_FILE")) {
            assertTrue(names.contains(name), name);
        }
    }

    @Test
    void noUrlMeansNoRedis() {
        assertNull(RedisConfig.fromSettings(settings(Map.of(), Map.of()), DeploymentProfile.PRODUCTION));
        assertNull(RedisConfig.fromSettings(settings(Map.of("OIDF_REDIS_URL", " "), Map.of()), DeploymentProfile.PRODUCTION));
    }

    @Test
    void theUrlComesFromThePropertyThenOidfRedisUrlThenRedisUrl() {
        Map<String, String> env = new HashMap<>(Map.of("REDIS_URL", "rediss://third", "OIDF_REDIS_URL", "rediss://second"));
        assertEquals("rediss://first", RedisConfig.fromSettings(settings(env, Map.of("oidf.redis.url", " rediss://first ")),
                DeploymentProfile.PRODUCTION).url());
        assertEquals("rediss://second", RedisConfig.fromSettings(settings(env, Map.of()), DeploymentProfile.PRODUCTION).url());
        env.remove("OIDF_REDIS_URL");
        assertEquals("rediss://third", RedisConfig.fromSettings(settings(env, Map.of()), DeploymentProfile.PRODUCTION).url());
    }

    @Test
    void theCaFileComesFromThePropertyThenTheVariable() {
        Map<String, String> env = Map.of("OIDF_REDIS_URL", "rediss://h", "OIDF_REDIS_CA_FILE", "/e");
        assertEquals(Path.of("/p"), RedisConfig.fromSettings(settings(env, Map.of("oidf.redis.ca.file", " /p ")),
                DeploymentProfile.PRODUCTION).caFile());
        assertEquals(Path.of("/e"), RedisConfig.fromSettings(settings(env, Map.of("oidf.redis.ca.file", " ")),
                DeploymentProfile.PRODUCTION).caFile());
        assertNull(RedisConfig.fromSettings(settings(Map.of("OIDF_REDIS_URL", "rediss://h"), Map.of()),
                DeploymentProfile.PRODUCTION).caFile());
    }

    @Test
    void thePoolDeadlinesAndSentinelAreReadStrictly() {
        Map<String, String> env = Map.of("OIDF_REDIS_URL", "rediss://h", "OIDF_REDIS_POOL_SIZE", "3",
                "OIDF_REDIS_BORROW_TIMEOUT_MS", "250", "OIDF_REDIS_COMMAND_TIMEOUT_MS", "900",
                "OIDF_REDIS_SENTINEL_MASTER", "mymaster", "OIDF_REDIS_SENTINELS", "s1:26379, s2",
                "OIDF_REDIS_SENTINEL_PASSWORD", "sp");
        RedisConfig config = RedisConfig.fromSettings(settings(env, Map.of()), DeploymentProfile.DEVELOPMENT);
        assertEquals(DeploymentProfile.DEVELOPMENT, config.profile());
        assertEquals(3, config.poolSize());
        assertEquals(Duration.ofMillis(250), config.borrowTimeout());
        assertEquals(Duration.ofMillis(900), config.commandTimeout());
        assertEquals("mymaster", config.sentinelMaster());
        assertEquals(List.of(new RedisConfig.HostPort("s1", 26379), new RedisConfig.HostPort("s2", 26379)), config.sentinels());
        assertEquals("sp", config.sentinelPassword());
        assertEquals("s", RedisConfig.fromSettings(settings(Map.of("OIDF_REDIS_URL", "rediss://h", "OIDF_REDIS_SENTINEL_MASTER", "m",
                "OIDF_REDIS_SENTINELS", "s"), Map.of()), DeploymentProfile.PRODUCTION).sentinels().get(0).host());

        for (Map.Entry<String, String> wrong : Map.of("OIDF_REDIS_POOL_SIZE", "0", "OIDF_REDIS_BORROW_TIMEOUT_MS", "soon",
                "OIDF_REDIS_COMMAND_TIMEOUT_MS", "60001").entrySet()) {
            SettingRefused e = assertThrows(SettingRefused.class, () -> RedisConfig.fromSettings(
                    settings(Map.of("OIDF_REDIS_URL", "rediss://h", wrong.getKey(), wrong.getValue()), Map.of()),
                    DeploymentProfile.PRODUCTION), wrong.getKey());
            assertEquals(wrong.getKey(), e.setting());
        }
        // Sentinel settings that do not go together, or a sentinel that is not host[:port], are a setting refused
        // (SettingRefused, naming it), as a pool or deadline value is - never taken for a bad URL.
        for (Map.Entry<Map<String, String>, String> wrong : Map.of(
                Map.of("OIDF_REDIS_URL", "rediss://h", "OIDF_REDIS_SENTINEL_MASTER", "m"), "OIDF_REDIS_SENTINELS",
                Map.of("OIDF_REDIS_URL", "rediss://h", "OIDF_REDIS_SENTINELS", "s"), "OIDF_REDIS_SENTINEL_MASTER",
                Map.of("OIDF_REDIS_URL", "rediss://h", "OIDF_REDIS_SENTINEL_MASTER", "m", "OIDF_REDIS_SENTINELS", "s:x"),
                "OIDF_REDIS_SENTINELS").entrySet()) {
            SettingRefused e = assertThrows(SettingRefused.class, () -> RedisConfig.fromSettings(settings(wrong.getKey(), Map.of()),
                    DeploymentProfile.PRODUCTION), wrong.getKey().toString());
            assertEquals(wrong.getValue(), e.setting());
            assertTrue(e.getMessage().contains("OIDF_REDIS_SENTINEL"), e.getMessage());
        }
    }

    @Test
    void currentReadsThisProcess() {
        // The build sets no OIDF_REDIS_URL or REDIS_URL (build.yml sets only OIDF_TEST_REDIS_*), so there is none.
        boolean set = System.getenv("OIDF_REDIS_URL") != null || System.getenv("REDIS_URL") != null;
        String before = System.getProperty("oidf.redis.url");
        try {
            System.setProperty("oidf.redis.url", "rediss://from-a-property");
            assertEquals("rediss://from-a-property", RedisConfig.current().url());
            assertTrue(RedisConfig.isConfigured());
            assertEquals("rediss://other", RedisConfig.currentFor("rediss://other").url());
        } finally {
            if (before == null) {
                System.clearProperty("oidf.redis.url");
            } else {
                System.setProperty("oidf.redis.url", before);
            }
        }
        if (!set && before == null) {
            assertNull(RedisConfig.current());
            assertFalse(RedisConfig.isConfigured());
        }
    }
}
