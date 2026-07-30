/*
 * SpireSelectorIntrospector projects SPIRE selectors into workload attributes.
 */
package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SpireSelectorIntrospectorTest {

    private static InstanceIdentity svid(String id) {
        return InstanceIdentity.ofSpiffe(rawSvid(id));
    }

    private static SpiffeSvid rawSvid(String id) {
        return new SpiffeSvid(id, "gke.banking.demo", "/ns/demo/sa/payment-agent",
                List.of("https://attester.example.com"), 0, 0, "raw");
    }

    @Test
    @SuppressWarnings("unchecked")
    void projectsSelectorsIntoFlatAndGroupedAttributes() {
        String response = "{\"selectors\":["
                + "{\"type\":\"k8s\",\"value\":\"ns:demo\"},"
                + "{\"type\":\"k8s\",\"value\":\"sa:payment-agent\"},"
                + "{\"type\":\"unix\",\"value\":\"uid:0\"}]}";
        SpireSelectorIntrospector introspector = new SpireSelectorIntrospector("https://spire.example/api",
                (url, accept) -> {
                    assertTrue(url.contains("spiffe_id="), "queries by SPIFFE ID");
                    return response;
                });

        Map<String, Object> attrs = introspector.introspect(svid("spiffe://gke.banking.demo/ns/demo/sa/payment-agent"));
        List<String> flat = (List<String>) attrs.get("selectors");
        assertTrue(flat.contains("k8s:ns:demo"));
        assertTrue(flat.contains("k8s:sa:payment-agent"));
        assertTrue(flat.contains("unix:uid:0"));

        Map<String, List<String>> byType = (Map<String, List<String>>) attrs.get("spire");
        assertEquals(List.of("ns:demo", "sa:payment-agent"), byType.get("k8s"));
        assertEquals(List.of("uid:0"), byType.get("unix"));
    }

    @Test
    void lookupFailureIsBestEffortAndReturnsEmpty() {
        SpireSelectorIntrospector introspector = new SpireSelectorIntrospector("https://spire.example/api",
                (url, accept) -> { throw new IllegalStateException("SPIRE server unreachable"); });
        assertTrue(introspector.introspect(svid("spiffe://gke.banking.demo/x")).isEmpty());
    }

    @Test
    void noSelectorsReturnsEmpty() {
        SpireSelectorIntrospector introspector = new SpireSelectorIntrospector("https://spire.example/api",
                (url, accept) -> "{\"selectors\":[]}");
        assertTrue(introspector.introspect(svid("spiffe://gke.banking.demo/x")).isEmpty());
    }
}
