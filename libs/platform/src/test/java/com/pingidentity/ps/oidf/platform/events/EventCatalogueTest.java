/*
 * The catalogue format, and everything it refuses.
 */
package com.pingidentity.ps.oidf.platform.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class EventCatalogueTest {

    @Test
    void aValidCatalogueReadsWhole() {
        EventCatalogue shop = TestCatalogues.shop();

        assertEquals("shop", shop.component());
        assertEquals("libs/shop", shop.module());
        assertEquals("A shop.", shop.description());
        assertEquals("com.example.shop.event", shop.logger());
        assertEquals("Shop", shop.auditProtocol());
        assertEquals(List.of("item", "buyer"), List.copyOf(shop.fields().keySet()));
        assertEquals(Optional.of(PiiClass.DIRECT_ID), shop.classOf("buyer"));
        assertEquals(Optional.empty(), shop.classOf("card_number"));
        assertEquals("Who ordered it.", shop.fields().get("buyer").description());

        EventCatalogue.Code placed = shop.code("shop.order.placed").orElseThrow();
        assertEquals("shop", placed.component());
        assertEquals("An order.", placed.description());
        assertFalse(placed.audit());
        assertEquals(Set.of(Event.Outcome.SUCCESS), placed.outcomes());
        assertEquals(EventCatalogue.Level.INFO, placed.level());
        assertTrue(placed.declares("buyer"));
        assertFalse(placed.declares("card_number"));
        assertFalse(placed.declaredOnly());

        EventCatalogue.Code checked = shop.codes().get("shop.stock.checked");
        assertTrue(checked.declaredOnly());
        assertEquals(EventCatalogue.Level.DEBUG, checked.level());
        assertEquals(Set.of(Event.Outcome.SUCCESS, Event.Outcome.FAILURE), checked.outcomes());
        assertTrue(shop.code("shop.order.refused").orElseThrow().audit());
        assertEquals(Optional.empty(), shop.code("nothing.here"));
    }

    private static void refused(String json, String expected) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> EventCatalogue.parse(json));
        assertTrue(e.getMessage().contains(expected), e.getMessage());
    }

    private static String shopWith(String from, String to) {
        assertTrue(TestCatalogues.SHOP.contains(from), from);
        return TestCatalogues.SHOP.replace(from, to);
    }

    @Test
    void aDocumentThatIsNotAnObjectOrNotJsonIsRefused() {
        refused("{", "not valid JSON");
        refused("[]", "must be a JSON object");
    }

    @Test
    void unknownAndMissingMembersAreRefused() {
        refused(shopWith("\"module\"", "\"modul\""), "unknown member 'modul'");
        refused(shopWith("\"module\": \"libs/shop\",", ""), "lacks the member module");
        refused(shopWith("\"pii\": \"OPERATIONAL\", \"description\"", "\"pii\": \"OPERATIONAL\", \"colour\": \"red\", \"description\""),
                "field item has an unknown member");
        refused(shopWith("\"declaredOnly\": true", "\"declaredOnly\": true, \"extra\": 1"),
                "event shop.stock.checked has an unknown member");
    }

    @Test
    void namesThatBreakTheirRulesAreRefused() {
        refused(shopWith("\"component\": \"shop\"", "\"component\": \"Shop\""), "breaks the naming rule");
        refused(shopWith("\"logger\": \"com.example.shop.event\"", "\"logger\": \"com..shop\""), "breaks the naming rule");
        refused(shopWith("\"item\": {", "\"Item\": {"), "field 'Item' breaks the naming rule");
        refused(shopWith("\"shop.order.placed\"", "\"shop\""), "event 'shop' breaks the naming rule");
    }

    @Test
    void valuesOfTheWrongKindAreRefused() {
        refused(shopWith("\"description\": \"A shop.\"", "\"description\": \" \""), "description must be a non-empty string");
        refused(shopWith("\"description\": \"A shop.\"", "\"description\": 3"), "description must be a non-empty string");
        refused(shopWith("\"fields\": {\n", "\"fields\": [], \"x\": {\n"), "unknown member");
        refused(shopWith("\"pii\": \"DIRECT_ID\"", "\"pii\": \"SECRET\""), "pii 'SECRET' is not one of");
        refused(shopWith("\"item\": {\"pii\": \"OPERATIONAL\", \"description\": \"What was ordered.\"}", "\"item\": 1"),
                "field item must be a JSON object");
        refused(shopWith("\"shop.stock.checked\": {", "\"shop.stock.checked\": 1, \"x.y\": {"),
                "event shop.stock.checked must be a JSON object");
        refused(shopWith("\"audit\": false, \"outcomes\": [\"success\"],", "\"audit\": \"no\", \"outcomes\": [\"success\"],"),
                "audit must be true or false");
        refused(shopWith("\"level\": \"debug\"", "\"level\": \"trace\""), "level 'trace' is neither debug nor info");
        refused(shopWith("\"fields\": [], \"declaredOnly\": true", "\"fields\": {}, \"declaredOnly\": true"),
                "fields must be a JSON array");
    }

    @Test
    void theEventsAndFieldsSectionsMustBeObjects() {
        String noFields = """
                {"component": "c", "module": "m", "description": "d", "logger": "l", "auditProtocol": "p",
                 "fields": [], "events": {}}
                """;
        refused(noFields, "event catalogue c: fields must be a JSON object");
        String noEvents = """
                {"component": "c", "module": "m", "description": "d", "logger": "l", "auditProtocol": "p",
                 "fields": {}, "events": []}
                """;
        refused(noEvents, "event catalogue c: events must be a JSON object");
        String empty = """
                {"component": "c", "module": "m", "description": "d", "logger": "l", "auditProtocol": "p",
                 "fields": {}, "events": {}}
                """;
        refused(empty, "declares no events");
    }

    @Test
    void outcomesAreSuccessFailureOrBothOnceEach() {
        refused(shopWith("\"outcomes\": [\"success\", \"failure\"]", "\"outcomes\": []"), "must name success, failure or both");
        refused(shopWith("\"outcomes\": [\"success\", \"failure\"]", "\"outcomes\": [\"success\", \"success\"]"),
                "not 'success'");
        refused(shopWith("\"outcomes\": [\"success\", \"failure\"]", "\"outcomes\": [\"maybe\"]"), "not 'maybe'");
        refused(shopWith("\"outcomes\": [\"success\", \"failure\"]", "\"outcomes\": [1]"), "not 1");
        refused(shopWith("\"outcomes\": [\"success\", \"failure\"]", "\"outcomes\": {}"), "outcomes must be a JSON array");
    }

    @Test
    void everyFieldAnEventCarriesIsClassifiedAndEveryClassifiedFieldIsCarried() {
        refused(shopWith("\"fields\": [\"buyer\"]", "\"fields\": [\"buyer\", \"card_number\"]"),
                "carries 'card_number', which the catalogue's fields do not classify");
        refused(shopWith("\"fields\": [\"buyer\"]", "\"fields\": [\"buyer\", 7]"), "carries 7");
        refused(shopWith("\"fields\": [\"buyer\"]", "\"fields\": [\"buyer\", \"buyer\"]"), "lists the field buyer twice");
        refused(shopWith("\"fields\": [\"item\", \"buyer\"]", "\"fields\": [\"buyer\"]"),
                "classifies the field item, which no event carries");
    }
}
