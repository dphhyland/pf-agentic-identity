/*
 * The event record, its builder and the privacy rule.
 */
package com.pingidentity.ps.oidf.platform.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class EventTest {

    @AfterEach
    void reset() {
        Events.reset();
    }

    @Test
    void anEventCarriesItsCodeOutcomePartiesAndFields() {
        Event event = Event.builder("shop", "shop.order.refused").failure("no_stock").subject("c-1").partner("p-1")
                .role("OP").description("refused").field("item", List.of("tea", "cake")).field("absent", null)
                .field(null, "x").requestJti("j-1").audit().build();

        assertEquals("shop", event.component());
        assertEquals("shop", event.category());
        assertTrue(event.isFailure());
        assertEquals("no_stock", event.reason());
        assertEquals("tea cake", event.fields().get("item"));
        assertEquals(List.of("item"), List.copyOf(event.fields().keySet()));
        assertTrue(event.audit());
        assertEquals("OP", event.role());
        assertEquals("c-1", event.subject());
        assertEquals("p-1", event.partner());
        assertEquals("j-1", event.requestJti());
        assertEquals("refused", event.description());
        assertThrows(UnsupportedOperationException.class, () -> event.fields().put("x", "y"));
        assertEquals("7", Event.builder("shop", "a.b").field("n", 7).build().fields().get("n"));
    }

    @Test
    void successClearsAnEarlierFailure() {
        Event event = Event.builder("shop", "a.b").failure("r").success().build();
        assertFalse(event.isFailure());
        assertNull(event.reason());
        assertEquals("success", Event.Outcome.SUCCESS.code());
        assertEquals("failure", Event.Outcome.FAILURE.code());
    }

    @Test
    void theCategoryIsTheSecondSegmentOfAFederationCodeAndTheFirstOfAnyOther() {
        assertEquals("registration", Event.categoryOf("federation.registration.created"));
        assertEquals("federation", Event.categoryOf("federation.x"));
        assertEquals("attestation", Event.categoryOf("attestation.client.verified"));
        assertEquals("solo", Event.categoryOf("solo"));
        assertEquals("custom", Event.builder("shop", "federation.pdp.consulted").category("custom").build().category());
    }

    @Test
    void theConstructorFillsWhatWasLeftOut() {
        Event event = new Event("a.b", null, null, null, null, null, null, null, null, false, " ", " ");
        assertEquals(Event.Outcome.SUCCESS, event.outcome());
        assertEquals(Map.of(), event.fields());
        assertEquals("a", event.category());
        assertEquals(Event.DEFAULT_COMPONENT, event.component());
        assertEquals(Event.DEFAULT_COMPONENT,
                new Event("a.b", null, null, null, null, null, null, null, null, false, null, null).component());
        assertThrows(NullPointerException.class, () -> Event.builder("shop", null));
        assertThrows(NullPointerException.class,
                () -> new Event(null, null, null, null, null, null, null, null, null, false, null, null));
    }

    @Test
    void anInstanceSubjectIsNeverRecordedBesideAnAgentId() {
        Event withAgent = Event.builder("shop", "a.b").field("agent_id", "agt-123").field("instance_subject", "spiffe://td/a")
                .field("spiffe_id", "spiffe://td/x").field("client_id", "c").build();
        assertFalse(withAgent.fields().containsKey("instance_subject"));
        assertFalse(withAgent.fields().containsKey("spiffe_id"));
        assertEquals("c", withAgent.fields().get("client_id"));

        Event withoutAgent = Event.builder("shop", "a.b").field("instance_subject", "spiffe://td/a").build();
        assertEquals("spiffe://td/a", withoutAgent.fields().get("instance_subject"));

        Map<String, String> input = new LinkedHashMap<>(Map.of("agent_id", "a", "spiffe_id", "s"));
        assertEquals(Map.of("agent_id", "a"), Event.withoutInstanceBesideAgent(input));
        assertEquals(2, input.size(), "the caller's map is not changed");
    }

    @Test
    void aComponentNobodyNamedIsTheOneWhoseCatalogueDeclaresTheCode() {
        EventCatalogues catalogues = TestCatalogues.shopAndBank();
        assertEquals("named", Event.resolve("named", "bank.transfer.made", catalogues));
        assertEquals("bank", Event.resolve(null, "bank.transfer.made", catalogues));
        assertEquals(Event.DEFAULT_COMPONENT, Event.resolve(null, "unknown.code", catalogues));

        EventCatalogues.install(catalogues);
        assertEquals("bank", Event.builder(null, "bank.transfer.made").build().component());
        assertEquals("bank", Events.event(null, "bank.transfer.made").build().component());
    }

    @Test
    void withFieldsAndWithPartiesKeepEverythingElse() {
        Event event = Event.builder("shop", "shop.order.placed").failure("r").subject("s").partner("p").role("OP")
                .description("d").field("item", "tea").requestJti("j").audit().category("c").build();
        Event other = event.withFields(Map.of("buyer", "b")).withParties("s2", "p2");
        assertEquals(new Event("shop.order.placed", Event.Outcome.FAILURE, "r", "s2", "p2", "OP", "d", Map.of("buyer", "b"),
                "j", true, "c", "shop"), other);
    }
}
