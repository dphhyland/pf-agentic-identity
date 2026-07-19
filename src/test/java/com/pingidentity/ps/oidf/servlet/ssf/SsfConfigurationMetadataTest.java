/*
 * The ssf-configuration metadata document exposes the SSF-mandated fields.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SsfConfigurationMetadataTest {

    @Test
    void metadataAdvertisesEndpointsDeliveryMethodsAndJwks() {
        SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com").build();
        Map<String, Object> m = SsfConfigurationServlet.metadata(cfg);

        assertEquals("https://op.example.com", m.get("issuer"));
        assertEquals("https://op.example.com/pf/JWKS", m.get("jwks_uri"));

        @SuppressWarnings("unchecked")
        List<String> delivery = (List<String>) m.get("delivery_methods_supported");
        assertTrue(delivery.contains("urn:ietf:rfc:8935"), "push (RFC 8935) advertised");
        assertTrue(delivery.contains("urn:ietf:rfc:8936"), "poll (RFC 8936) advertised");

        assertEquals("https://op.example.com/ssf/streams", m.get("configuration_endpoint"));
        assertEquals("https://op.example.com/ssf/status", m.get("status_endpoint"));
        assertEquals("https://op.example.com/ssf/subjects:add", m.get("add_subject_endpoint"));
        assertEquals("https://op.example.com/ssf/subjects:remove", m.get("remove_subject_endpoint"));
        assertEquals("https://op.example.com/ssf/verify", m.get("verification_endpoint"));
        assertEquals("NONE", m.get("default_subjects"));

        @SuppressWarnings("unchecked")
        List<String> allEvents = (List<String>) m.get("all_events_supported");
        assertTrue(allEvents.contains("https://schemas.openid.net/secevent/caep/event-type/session-revoked"));
        assertTrue(allEvents.contains("https://schemas.openid.net/secevent/risc/event-type/account-disabled"));
    }
}
