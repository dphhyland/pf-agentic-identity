/*
 * What each class of personal data may do in each log.
 */
package com.pingidentity.ps.oidf.platform.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.junit.jupiter.api.Test;

class PiiPolicyTest {
    private static final EventCatalogues CATALOGUES = TestCatalogues.shopAndBank();

    @Test
    void theDefaultKeepsEveryClassInBothLogs() {
        for (PiiPolicy.Destination destination : PiiPolicy.Destination.values()) {
            for (PiiClass pii : PiiClass.values()) {
                assertEquals(PiiPolicy.Treatment.KEEP, PiiPolicy.DEFAULT.treatment(destination, pii), destination + " " + pii);
            }
        }
        Event event = CATALOGUES.admit(Event.builder(null, "shop.order.placed").subject("s").partner("p").field("buyer", "jane").build());
        assertSame(event, PiiPolicy.DEFAULT.apply(event, PiiPolicy.Destination.SERVER_LOG, CATALOGUES));
    }

    @Test
    void aClassCanBeDigestedOrDroppedInOneLogAndKeptInTheOther() {
        PiiPolicy policy = PiiPolicy.DEFAULT
                .with(PiiPolicy.Destination.SERVER_LOG, PiiClass.DIRECT_ID, PiiPolicy.Treatment.DIGEST)
                .with(PiiPolicy.Destination.SERVER_LOG, PiiClass.OPERATIONAL, PiiPolicy.Treatment.DROP);
        Event event = CATALOGUES.admit(Event.builder(null, "shop.order.placed").field("buyer", "jane").field("item", "tea").build());

        Event server = policy.apply(event, PiiPolicy.Destination.SERVER_LOG, CATALOGUES);
        Event audit = policy.apply(event, PiiPolicy.Destination.AUDIT_LOG, CATALOGUES);

        assertEquals(Map.of("buyer", "sha256:" + LogSafe.sha256Hex12("jane")), server.fields());
        assertSame(event, audit);
        assertEquals(PiiPolicy.Treatment.KEEP, policy.treatment(PiiPolicy.Destination.AUDIT_LOG, PiiClass.DIRECT_ID));
    }

    @Test
    void theSubjectAndPartnerArePseudonymousIdentifiers() {
        PiiPolicy policy = PiiPolicy.DEFAULT.with(PiiPolicy.Destination.AUDIT_LOG, PiiClass.PSEUDONYMOUS_ID, PiiPolicy.Treatment.DROP);
        Event event = Event.builder(null, "bank.transfer.made").subject("s").partner("p").field("account", "a").build();

        Event audit = policy.apply(CATALOGUES.admit(event), PiiPolicy.Destination.AUDIT_LOG, CATALOGUES);

        assertNull(audit.subject());
        assertNull(audit.partner());
        assertEquals(Map.of(), audit.fields());
        Event subjectOnly = Event.builder(null, "bank.transfer.made").subject("s").build();
        assertNull(policy.apply(subjectOnly, PiiPolicy.Destination.AUDIT_LOG, CATALOGUES).subject());
        Event partnerOnly = Event.builder(null, "bank.transfer.made").partner("p").build();
        assertNull(policy.apply(partnerOnly, PiiPolicy.Destination.AUDIT_LOG, CATALOGUES).partner());
    }

    @Test
    void aFieldWithNoClassIsDropped() {
        Event unclassified = Event.builder("shop", "shop.order.placed").field("card_number", "4111").field("item", "tea").build();
        assertEquals(Map.of("item", "tea"),
                PiiPolicy.DEFAULT.apply(unclassified, PiiPolicy.Destination.SERVER_LOG, CATALOGUES).fields());
        Event noCatalogue = Event.builder("nobody", "x.y").field("item", "tea").build();
        assertEquals(Map.of(), PiiPolicy.DEFAULT.apply(noCatalogue, PiiPolicy.Destination.SERVER_LOG, CATALOGUES).fields());
    }

    @Test
    void treatingANullIsNull() {
        PiiPolicy digest = PiiPolicy.DEFAULT.with(PiiPolicy.Destination.SERVER_LOG, PiiClass.NETWORK, PiiPolicy.Treatment.DIGEST);
        assertNull(digest.treat(PiiPolicy.Destination.SERVER_LOG, PiiClass.NETWORK, null));
        assertEquals("203.0.113.9", digest.treat(PiiPolicy.Destination.AUDIT_LOG, PiiClass.NETWORK, "203.0.113.9"));
        assertThrows(NullPointerException.class, () -> PiiPolicy.DEFAULT.with(null, PiiClass.NETWORK, PiiPolicy.Treatment.KEEP));
        assertThrows(NullPointerException.class,
                () -> PiiPolicy.DEFAULT.with(PiiPolicy.Destination.SERVER_LOG, null, PiiPolicy.Treatment.KEEP));
        assertThrows(NullPointerException.class,
                () -> PiiPolicy.DEFAULT.with(PiiPolicy.Destination.SERVER_LOG, PiiClass.NETWORK, null));
    }
}
