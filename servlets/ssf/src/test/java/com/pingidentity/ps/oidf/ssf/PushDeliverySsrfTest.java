/*
 * A push stream is a standing instruction to POST at a URL the RECEIVER chose. Screening it.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import java.net.InetAddress;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * SSF push delivery is an SSRF sink with an unusual shape: the destination is supplied by a receiver
 * over an authenticated API, stored, and then fetched repeatedly by a background loop. Authentication
 * is not authorisation to reach an arbitrary address, and "authenticated" is what made this easy to
 * overlook — the same class the Tier 1 {@link OutboundUrlPolicy} exists to prevent on the inbound
 * federation side.
 *
 * <p>Screening happens twice, and both matter: at configuration, so the caller gets an actionable
 * rejection on the API call it just made; and at every send, because a stream may predate the
 * screening, may have been written straight into the store, or may name a host whose DNS answer
 * changed after it was accepted.
 */
class PushDeliverySsrfTest {

    private final TestSigningKeyProvider keys = new TestSigningKeyProvider("test-set-key");
    private InMemorySsfStore store;
    private StreamManagementService svc;

    /** Public by default; the two names below are the ones an attacker would actually reach for. */
    private static OutboundUrlPolicy policy() {
        return OutboundUrlPolicy.from(Map.<String, String>of()::get).withResolver(host -> {
            try {
                String ip;
                if ("metadata.internal".equals(host)) {
                    ip = "169.254.169.254";            // cloud instance metadata
                } else if ("redis.railway.internal".equals(host)) {
                    ip = "10.0.0.7";                   // a private service on the same network
                } else {
                    ip = "93.184.216.34";
                }
                return new InetAddress[] { InetAddress.getByName(ip) };
            }
            catch (Exception e) {
                throw new IllegalArgumentException(e);
            }
        });
    }

    @BeforeEach
    void setUp() {
        store = new InMemorySsfStore();
        SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com").build();
        svc = new StreamManagementService(store, new SetMinter("RS256", keys), cfg, SetPublisher.NOOP, policy());
    }

    private static Map<String, Object> pushTo(String endpointUrl) {
        return Map.of(
                "aud", "https://receiver.example.com",
                "events_requested", List.of("https://schemas.openid.net/secevent/caep/event-type/session-revoked"),
                "delivery", Map.of("method", DeliveryMethod.PUSH.urn(), "endpoint_url", endpointUrl));
    }

    // ---- refused at configuration ------------------------------------------------------------------

    @Test
    void aStreamNamingCloudInstanceMetadataIsRefusedAtCreation() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> svc.createStream(pushTo("http://metadata.internal/latest/meta-data/iam/security-credentials/")));

        assertTrue(e.getMessage().contains("endpoint_url"), e.getMessage());
        assertTrue(store.listStreams().isEmpty(), "a refused stream must not be stored");
    }

    @Test
    void aStreamNamingAPrivateServiceIsRefusedAtCreation() {
        assertThrows(IllegalArgumentException.class,
                () -> svc.createStream(pushTo("http://redis.railway.internal:6379/")));
        assertTrue(store.listStreams().isEmpty());
    }

    @Test
    void aPublicEndpointIsAccepted() {
        Map<String, Object> created = svc.createStream(pushTo("https://receiver.example.com/set"));
        assertNotNull(created.get("stream_id"));
    }

    /**
     * PATCH is the interesting one: create a stream at an acceptable destination, then repoint it. A
     * check only on the create path is no check at all.
     */
    @Test
    void anExistingStreamCannotBeRepointedAtAPrivateAddress() {
        Map<String, Object> created = svc.createStream(pushTo("https://receiver.example.com/set"));
        String id = (String) created.get("stream_id");

        assertThrows(IllegalArgumentException.class, () -> svc.updateStream(id, Map.of(
                "delivery", Map.of("method", DeliveryMethod.PUSH.urn(),
                        "endpoint_url", "http://metadata.internal/latest/meta-data/"))));

        assertEquals("https://receiver.example.com/set",
                ((Map<?, ?>) svc.getStream(id).get("delivery")).get("endpoint_url"),
                "the stored endpoint must be unchanged after a refused update");
    }

    // ---- refused again at send, and PERMANENTLY ----------------------------------------------------

    /**
     * The classification is the subtle half. {@code httpClient}'s catch-all treats failures as
     * retryable, which for a refused destination would mean re-attempting the same SSRF on every
     * backoff tick until the stream dead-letters — turning one rejected request into a slow scan. A
     * destination the policy refuses will never become acceptable by trying again, so it is permanent.
     */
    @Test
    void deliveryToARefusedEndpointIsPermanentNotRetryable() {
        PushDeliveryService.SetDeliveryClient client = PushDeliveryService.httpClient(policy());

        PushDeliveryService.DeliveryResult r =
                client.deliver("http://metadata.internal/latest/meta-data/", null, "eyJ.set.jws");

        assertEquals(PushDeliveryService.Outcome.PERMANENT, r.outcome(),
                "a retryable classification would re-attempt this on every tick");
    }

    @Test
    void deliveryScreensEvenWhenTheStreamWasStoredWithoutScreening() {
        // Straight into the store, bypassing createStream entirely - a stream that predates the check.
        Stream smuggled = Stream.builder()
                .id("smuggled")
                .audience("https://receiver.example.com")
                .deliveryMethod(DeliveryMethod.PUSH)
                .pushEndpointUrl("http://redis.railway.internal:6379/")
                .eventsRequested(List.of("https://schemas.openid.net/secevent/caep/event-type/session-revoked"))
                .eventsDelivered(List.of("https://schemas.openid.net/secevent/caep/event-type/session-revoked"))
                .status(StreamStatus.ENABLED)
                .createdAt(SetMinter.nowSeconds())
                .build();
        store.createStream(smuggled);

        PushDeliveryService.DeliveryResult r = PushDeliveryService.httpClient(policy())
                .deliver(smuggled.pushEndpointUrl(), null, "eyJ.set.jws");

        assertEquals(PushDeliveryService.Outcome.PERMANENT, r.outcome(),
                "the send-time check is what covers a stream the API never saw");
    }
}
