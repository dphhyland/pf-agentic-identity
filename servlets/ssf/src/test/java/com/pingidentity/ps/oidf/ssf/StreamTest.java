/*
 * The owner on the stream model: carried through every copy, and one spelling of "none".
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class StreamTest {

    private static Stream.Builder poll() {
        return Stream.builder().id("s1").audience("https://receiver.example.com").deliveryMethod(DeliveryMethod.POLL);
    }

    /**
     * Every write to a stream is a copy of it. A copy that lost the owner would, in a store that replaces
     * the whole record, leave a stream its own receiver can no longer reach - and the push executor makes
     * exactly such a copy, with no receiver anywhere near, when it pauses a stream that keeps failing.
     */
    @Test
    void theOwnerIsCarriedThroughACopy() {
        Stream owned = poll().ownerClientId("receiver-a").build();

        assertEquals("receiver-a", owned.toBuilder().build().ownerClientId());
        assertEquals("receiver-a", owned.withStatus(StreamStatus.PAUSED, "dead-letter", 5L).ownerClientId());
        assertEquals(StreamStatus.PAUSED, owned.withStatus(StreamStatus.PAUSED, "dead-letter", 5L).status()); // control
    }

    @Test
    void aStreamBuiltWithoutAnOwnerHasNone() {
        assertNull(poll().build().ownerClientId());
        assertNull(poll().build().toBuilder().build().ownerClientId());
    }

    /** A blank read back from a store is no owner, never a client whose id is the empty string. */
    @Test
    void aBlankOwnerIsNoOwner() {
        assertNull(poll().ownerClientId("").build().ownerClientId());
        assertNull(poll().ownerClientId("   ").build().ownerClientId());
        assertEquals(" receiver-a ", poll().ownerClientId(" receiver-a ").build().ownerClientId(),
                "control: only blank is normalised - an id is otherwise kept exactly as the token gave it");
    }
}
