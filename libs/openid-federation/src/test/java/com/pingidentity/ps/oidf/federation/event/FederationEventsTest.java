package com.pingidentity.ps.oidf.federation.event;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The event API: codes and categories, the builder's privacy rule, the sink holder's first-wins
 * contract, and the line format - above all that no token, newline or oversized value reaches a log.
 */
class FederationEventsTest {

    @AfterEach
    void reset() {
        FederationEvents.reset();
        LogSafe.configureMaxValueLength(LogSafe.DEFAULT_MAX_VALUE_LENGTH);
    }

    @Test
    void anEventCarriesItsCodeOutcomeAndCategory() {
        FederationEvent event = FederationEvents.event(FederationEvents.REGISTRATION_REFUSED)
                .failure("no_policy").subject("https://rp.example").partner("https://ta.example").role("OP")
                .description("refused").field("scope", List.of("openid", "email")).field("absent", null)
                .requestJti("j-1").audit().build();

        assertEquals("registration", event.category());
        assertTrue(event.isFailure());
        assertEquals("no_policy", event.reason());
        assertEquals("openid email", event.fields().get("scope"));
        assertFalse(event.fields().containsKey("absent"));
        assertTrue(event.audit());
        assertEquals("OP", event.role());
        assertThrows(UnsupportedOperationException.class, () -> event.fields().put("x", "y"));
        assertEquals("success", FederationEvent.Outcome.SUCCESS.code());
        assertEquals("pdp", FederationEvent.builder("federation.pdp.consulted").success().build().category());
        assertEquals("custom", FederationEvent.builder("federation.pdp.consulted").category("custom").build().category());
        assertEquals("solo", FederationEvent.builder("solo").build().category());
        assertEquals("a", new FederationEvent("a.b", null, null, null, null, null, null, null, null, false, " ").category());
        assertEquals("attestation", FederationEvent.builder(FederationEvents.ATTESTATION_REFUSED).build().category());
    }

    @Test
    void anInstanceSubjectIsNeverRecordedBesideAnAgentId() {
        FederationEvent withAgent = FederationEvents.event(FederationEvents.ATTESTATION_VERIFIED)
                .field("agent_id", "agt-123").field("instance_subject", "spiffe://td/ns/a").field("spiffe_id", "spiffe://td/x")
                .field("client_id", "c").build();
        assertFalse(withAgent.fields().containsKey("instance_subject"));
        assertFalse(withAgent.fields().containsKey("spiffe_id"));
        assertEquals("c", withAgent.fields().get("client_id"));

        FederationEvent withoutAgent = FederationEvents.event(FederationEvents.ATTESTATION_VERIFIED)
                .field("instance_subject", "spiffe://td/ns/a").build();
        assertEquals("spiffe://td/ns/a", withoutAgent.fields().get("instance_subject"));
    }

    @Test
    void theFirstConfiguredSinkWinsAndEmitNeverThrows() {
        try (EventCapture capture = EventCapture.install()) {
            FederationEvents.configure(e -> {
                throw new IllegalStateException("should never be installed");
            });
            assertSame(capture, FederationEvents.sink());
            assertTrue(FederationEvents.isConfigured());

            FederationEvents.event(FederationEvents.CHAIN_VALIDATED).subject("https://rp.example").emit();
            FederationEvents.emit(null);

            assertEquals(List.of(FederationEvents.CHAIN_VALIDATED), capture.codes());
            assertEquals("https://rp.example", capture.only(FederationEvents.CHAIN_VALIDATED).subject());
            assertThrows(AssertionError.class, () -> capture.only(FederationEvents.CHAIN_REFUSED));
            assertEquals(1, capture.withCode(FederationEvents.CHAIN_VALIDATED).size());
            capture.clear();
            assertTrue(capture.events().isEmpty());
        }
        FederationEvents.configure(e -> {
            throw new IllegalStateException("a sink that throws");
        });
        FederationEvents.event("x.y.z").emit();
    }

    @Test
    void withNothingConfiguredEventsGoToTheLoggingSink() {
        FederationEvents.reset();
        assertFalse(FederationEvents.isConfigured());
        assertInstanceOf(LoggingEventSink.class, FederationEvents.sink());
        FederationEvents.event(FederationEvents.FETCH).field("host", "ta.example").emit();
        FederationEvents.event(FederationEvents.CHAIN_REFUSED).failure("signature").audit().emit();
        FederationEvents.event(FederationEvents.CHAIN_VALIDATED).emit();
    }

    // ---- the line ----------------------------------------------------------------------------------

    @Test
    void theLineIsKeyValueWithQuotingWhereNeeded() {
        FederationEvent event = FederationEvents.event(FederationEvents.REGISTRATION_CREATED)
                .subject("https://rp.example").partner("https://ta.example").field("scope", "openid email")
                .field("odd key=", "v").requestJti("j").description("registered from trust chain").build();

        String line = LoggingEventSink.format(event);

        assertEquals("event=federation.registration.created outcome=success subject=https://rp.example "
                + "partner=https://ta.example scope=\"openid email\" odd_key_=v request_jti=j "
                + "desc=\"registered from trust chain\"", line);
        assertTrue(LoggingEventSink.format(FederationEvents.event("a.b.c").failure("r").build()).contains("reason=r"));
    }

    @Test
    void aTokenNeverReachesTheLine() {
        String jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2EifQ.c2lnbmF0dXJl";
        FederationEvent event = FederationEvents.event(FederationEvents.CHAIN_REFUSED)
                .failure("signature").field("statement", jwt).description("bad token " + jwt + " seen").build();

        String line = LoggingEventSink.format(event);

        assertFalse(line.contains("eyJpc3MiOiJodHRwczovL2EifQ"), line);
        assertTrue(line.contains(LogSafe.jwtDigest(jwt)), line);
        try (EventCapture capture = EventCapture.install()) {
            FederationEvents.emit(event);
            capture.assertNoJwtIn();
            capture.assertNoStackTraceIn();
        }
    }

    @Test
    void aForgedLogLineIsNeutralised() {
        String line = LoggingEventSink.format(FederationEvents.event("a.b.c")
                .subject("https://rp.example\nevent=federation.registration.created outcome=success").build());
        assertFalse(line.contains("\n"), line);
        assertEquals(1, line.lines().count());
    }

    // ---- LogSafe -----------------------------------------------------------------------------------

    @Test
    void valuesAreCappedAndControlCharactersReplaced() {
        LogSafe.configureMaxValueLength(4);
        assertEquals(16, LogSafe.maxValueLength());
        LogSafe.configureMaxValueLength(20);
        assertEquals("0123456789abcdefghij…", LogSafe.value("0123456789abcdefghijklmnop"));
        assertEquals("a_b_c", LogSafe.value("a\rb\tc"));
        assertNull(LogSafe.value(null));
        assertEquals("-", LogSafe.quoted(null));
        assertEquals("\"\"", LogSafe.quoted(""));
        assertEquals("\"say \\\"hi\\\"\"", LogSafe.quoted("say \"hi\""));
        assertEquals("plain", LogSafe.quoted("plain"));
        assertEquals("no eyJ token here", LogSafe.value("no eyJ token here"));
        assertTrue(LogSafe.jwtDigest("x").startsWith("jwt:sha256:"));
        assertEquals(23, LogSafe.jwtDigest("x").length());
    }

    @Test
    void aJweIsDigestedToo() {
        String jwe = "eyJhbGciOiJSU0EtT0FFUCJ9.a2V5.aXY.Y2lwaGVy.dGFn";
        assertEquals(LogSafe.jwtDigest(jwe), LogSafe.value(jwe));
        assertEquals(Map.of(), FederationEvent.builder("a.b.c").build().fields());
    }
}
