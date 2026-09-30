/*
 * Every URL the transmitter advertises is one a servlet answers.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfPaths;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Plan item H-SSF-3: {@code OIDF_SSF_BASE_PATH} moved the URLs the transmitter advertised and not the servlets'
 * {@code @WebServlet} paths, so anything but {@code /ssf} sent receivers to endpoints nothing served. It is removed, and
 * every URL is the issuer and an {@link SsfPaths} constant; this holds each constant to a pattern a servlet is mapped to.
 */
class SsfPathsTest {

    @Test
    void everyAdvertisedPathIsAMappedPattern() {
        for (String path : List.of(SsfPaths.STREAMS, SsfPaths.STATUS, SsfPaths.SUBJECTS_ADD, SsfPaths.SUBJECTS_REMOVE, SsfPaths.VERIFY,
                SsfPaths.POLL, SsfPaths.SCIM_USERS)) {
            assertTrue(SsfRoutes.BY_PATTERN.containsKey(path), path);
        }
        assertTrue(SsfRoutes.BY_PATTERN.containsKey(SsfPaths.SCIM_USERS + "/*"));
    }

    /** SSF 1.0 §7.1's endpoint members, each the issuer and a mapped path. */
    @Test
    @Requirement("SSF §7.1")
    void theMetadataEndpointsAreTheIssuerAndTheMappedPaths() {
        Map<String, Object> m = SsfConfigurationServlet.metadata(new SsfConfiguration.Builder().issuer("https://op.example.com").build());
        assertEquals("https://op.example.com/ssf/streams", m.get("configuration_endpoint"));
        assertEquals("https://op.example.com/ssf/status", m.get("status_endpoint"));
        assertEquals("https://op.example.com/ssf/subjects:add", m.get("add_subject_endpoint"));
        assertEquals("https://op.example.com/ssf/subjects:remove", m.get("remove_subject_endpoint"));
        assertEquals("https://op.example.com/ssf/verify", m.get("verification_endpoint"));
        assertEquals(List.of("spec_version", "issuer", "jwks_uri", "delivery_methods_supported", "configuration_endpoint",
                "status_endpoint", "add_subject_endpoint", "remove_subject_endpoint", "verification_endpoint", "default_subjects",
                "events_supported", "all_events_supported", "authorization_schemes"), List.copyOf(m.keySet()),
                "every §7.1 member but critical_subject_members, which has no elements and so MUST be omitted (§7.2.3)");
    }
}
