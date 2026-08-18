package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The rules that stand between a caller-supplied federation identifier and an outbound fetch.
 * Resolution is stubbed so these assert the policy, not DNS.
 */
class OutboundUrlPolicyTest {

    /** Every host resolves to whatever the map says; unknown hosts resolve to a public address. */
    private static OutboundUrlPolicy policy(Map<String, String> env, Map<String, String> dns) {
        return OutboundUrlPolicy.from(env::get).withResolver(host -> {
            try {
                String ip = dns.getOrDefault(host, "93.184.216.34");
                return new InetAddress[] { InetAddress.getByName(ip) };
            }
            catch (Exception e) {
                throw new IllegalArgumentException(e);
            }
        });
    }

    private static OutboundUrlPolicy strict() {
        return policy(Map.of(), Map.of());
    }

    @Test
    void allowsAnOrdinaryHttpsUrl() {
        assertEquals("https://anchor.example/.well-known/openid-federation",
                strict().check("https://anchor.example/.well-known/openid-federation").toString());
    }

    @Test
    void refusesTheCloudMetadataService() {
        // The canonical SSRF target: link-local, and it answers.
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> policy(Map.of(), Map.of("metadata.example", "169.254.169.254"))
                        .check("https://metadata.example/latest/meta-data/iam/security-credentials/"));
        assertTrue(e.getMessage().contains("169.254.169.254"), e.getMessage());
    }

    @Test
    void refusesLoopbackAndPrivateRanges() {
        for (String ip : new String[] { "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "100.64.0.1", "::1", "fd00::1" }) {
            assertThrows(IllegalArgumentException.class,
                    () -> policy(Map.of(), Map.of("internal.example", ip)).check("https://internal.example/x"),
                    ip + " must be refused");
        }
    }

    @Test
    void refusesAHostWithEvenOneNonPublicRecord() {
        // The subtle one: checking only the first address lets a mixed record through.
        OutboundUrlPolicy p = OutboundUrlPolicy.from(Map.<String, String>of()::get).withResolver(host -> {
            try {
                return new InetAddress[] { InetAddress.getByName("93.184.216.34"), InetAddress.getByName("127.0.0.1") };
            }
            catch (Exception e) {
                throw new IllegalArgumentException(e);
            }
        });

        assertThrows(IllegalArgumentException.class, () -> p.check("https://split-horizon.example/x"));
    }

    @Test
    void refusesPlaintextHttpUnlessAllowed() {
        assertThrows(IllegalArgumentException.class, () -> strict().check("http://anchor.example/x"));
        assertDoesNotThrow(() -> policy(Map.of(OutboundUrlPolicy.ALLOW_HTTP_ENV, "true"), Map.of())
                .check("http://anchor.example/x"));
    }

    @Test
    void refusesNonHttpSchemesAndCredentialsAndHostlessUrls() {
        assertThrows(IllegalArgumentException.class, () -> strict().check("file:///etc/passwd"));
        assertThrows(IllegalArgumentException.class, () -> strict().check("gopher://anchor.example/x"));
        assertThrows(IllegalArgumentException.class, () -> strict().check("https://user:pw@anchor.example/x"));
        assertThrows(IllegalArgumentException.class, () -> strict().check("https:///no-host"));
        assertThrows(IllegalArgumentException.class, () -> strict().check("not a url at all"));
    }

    @Test
    void allowlistSuffixMatchingIsOnALabelBoundary() {
        OutboundUrlPolicy p = policy(Map.of(OutboundUrlPolicy.HOST_ALLOWLIST_ENV, "example.com"),
                Map.of("host.example.com", "10.0.0.1", "notexample.com", "10.0.0.2"));

        assertDoesNotThrow(() -> p.check("https://host.example.com/x"));
        assertThrows(IllegalArgumentException.class, () -> p.check("https://notexample.com/x"),
                "suffix matching must be on a label boundary, not a substring");
    }

    @Test
    void trustingExemptsOperatorConfiguredHostsOnly() {
        OutboundUrlPolicy p = policy(Map.of(), Map.of(
                "trust-controller.railway.internal", "10.0.0.7", "attacker.example", "10.0.0.8"))
                .trusting("http://trust-controller.railway.internal:8080/oidf");

        assertDoesNotThrow(() -> p.check("http://trust-controller.railway.internal:8080/oidf/.well-known/openid-federation"),
                "an operator-configured private endpoint is configuration, not attacker input");
        assertThrows(IllegalArgumentException.class, () -> p.check("https://attacker.example/x"),
                "the exemption must not generalise to other private hosts");
    }

    @Test
    void trustingDoesNotExemptOtherPortsOrSchemesOnTheSameHost() {
        // The bypass an adversarial review found: the exemption used to match the bare HOST, and the
        // same policy screens wholly caller-supplied identifiers. So a caller could name a different
        // PORT on the operator's own trust controller and have scheme, port and address checks all
        // waved through - an internal port scan pivoting off the operator's configuration.
        OutboundUrlPolicy p = policy(Map.of(), Map.of("controller.internal", "10.0.0.7"))
                .trusting("https://controller.internal/oidf");

        assertDoesNotThrow(() -> p.check("https://controller.internal/oidf/.well-known/openid-federation"));
        assertThrows(IllegalArgumentException.class, () -> p.check("http://controller.internal:6379/x?q="),
                "a different port and scheme on an exempt host must NOT be exempt");
        assertThrows(IllegalArgumentException.class, () -> p.check("https://controller.internal:8443/x"),
                "a different port on an exempt host must NOT be exempt");
        assertThrows(IllegalArgumentException.class, () -> p.check("https://controller.internal/elsewhere"),
                "a path outside the configured prefix must NOT be exempt");
    }

    @Test
    void anExemptionWithNoPathCoversThatOriginOnly() {
        OutboundUrlPolicy p = policy(Map.of(), Map.of("controller.internal", "10.0.0.7"))
                .trusting("https://controller.internal");

        assertDoesNotThrow(() -> p.check("https://controller.internal/.well-known/openid-federation"));
        assertThrows(IllegalArgumentException.class, () -> p.check("http://controller.internal/x"));
    }

    @Test
    void theAllowlistExemptsFromTheAddressRuleRatherThanRestrictingEveryOtherHost() {
        // It used to be AND-ed with the address check, so naming a private host achieved nothing -
        // while the refusal message told operators to do exactly that. And being exclusive, one entry
        // refused every public federation fetch process-wide.
        OutboundUrlPolicy p = policy(Map.of(OutboundUrlPolicy.HOST_ALLOWLIST_ENV, "spire.internal"),
                Map.of("spire.internal", "10.0.0.9"));

        assertDoesNotThrow(() -> p.check("https://spire.internal/entries"),
                "naming a private host in the allowlist must actually permit it");
        assertDoesNotThrow(() -> p.check("https://anchor.example/x"),
                "an allowlist entry must not refuse every other (public) host");
        assertThrows(IllegalArgumentException.class,
                () -> policy(Map.of(OutboundUrlPolicy.HOST_ALLOWLIST_ENV, "spire.internal"),
                        Map.of("other.internal", "10.0.0.10")).check("https://other.internal/x"),
                "a private host NOT named must still be refused");
    }

    @Test
    void trustingIgnoresNullAndBlankConfiguration() {
        assertDoesNotThrow(() -> strict().trusting(null, "", "   ").check("https://anchor.example/x"));
    }

    @Test
    void bodyCapDefaultsAndIsOverridable() {
        assertEquals(OutboundUrlPolicy.DEFAULT_MAX_BODY_BYTES, strict().maxBodyBytes());
        assertEquals(4096L, policy(Map.of(OutboundUrlPolicy.MAX_BODY_ENV, "4096"), Map.of()).maxBodyBytes());
        assertEquals(OutboundUrlPolicy.DEFAULT_MAX_BODY_BYTES,
                policy(Map.of(OutboundUrlPolicy.MAX_BODY_ENV, "rubbish"), Map.of()).maxBodyBytes(),
                "an unparseable cap must fall back to the default, never to unbounded");
    }

    @Test
    void permissiveAllowsWhatStrictRefuses() {
        assertDoesNotThrow(() -> OutboundUrlPolicy.permissive().check("http://127.0.0.1:9999/x"));
    }
}
