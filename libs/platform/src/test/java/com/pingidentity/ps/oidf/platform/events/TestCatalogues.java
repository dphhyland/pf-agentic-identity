/*
 * Catalogue documents for the events tests.
 */
package com.pingidentity.ps.oidf.platform.events;

import java.util.List;

/** Small, valid catalogue documents, and the same with one thing changed. */
final class TestCatalogues {
    private TestCatalogues() {
    }

    /**
     * {@code shop}: {@code shop.order.placed} (info, success, fields {@code item} OPERATIONAL and {@code buyer}
     * DIRECT_ID), {@code shop.order.refused} (audit, failure, {@code buyer}) and {@code shop.stock.checked} (debug,
     * both outcomes, no fields, declared only).
     */
    static final String SHOP = """
            {
              "component": "shop",
              "module": "libs/shop",
              "description": "A shop.",
              "logger": "com.example.shop.event",
              "auditProtocol": "Shop",
              "fields": {
                "item": {"pii": "OPERATIONAL", "description": "What was ordered."},
                "buyer": {"pii": "DIRECT_ID", "description": "Who ordered it."}
              },
              "events": {
                "shop.order.placed": {"description": "An order.", "audit": false, "outcomes": ["success"],
                                      "level": "info", "fields": ["item", "buyer"], "declaredOnly": false},
                "shop.order.refused": {"description": "A refusal.", "audit": true, "outcomes": ["failure"],
                                       "level": "info", "fields": ["buyer"], "declaredOnly": false},
                "shop.stock.checked": {"description": "A check.", "audit": false, "outcomes": ["success", "failure"],
                                       "level": "debug", "fields": [], "declaredOnly": true}
              }
            }
            """;

    /** {@code bank}: {@code bank.transfer.made} with the field {@code account} (PSEUDONYMOUS_ID). */
    static final String BANK = """
            {"component": "bank", "module": "libs/bank", "description": "A bank.", "logger": "com.example.bank.event",
             "auditProtocol": "Bank",
             "fields": {"account": {"pii": "PSEUDONYMOUS_ID", "description": "The account."}},
             "events": {"bank.transfer.made": {"description": "A transfer.", "audit": true, "outcomes": ["success"],
                        "level": "info", "fields": ["account"], "declaredOnly": false}}}
            """;

    static EventCatalogue shop() {
        return EventCatalogue.parse(SHOP);
    }

    static EventCatalogue bank() {
        return EventCatalogue.parse(BANK);
    }

    static EventCatalogues shopAndBank() {
        return EventCatalogues.of(List.of(shop(), bank()));
    }
}
