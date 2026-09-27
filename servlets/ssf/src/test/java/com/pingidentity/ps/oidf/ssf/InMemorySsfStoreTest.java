/*
 * In-memory store: the SsfStore contract, and what only this store promises.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/** {@link InMemorySsfStore} held to {@link SsfStoreContract}, the contract the two durable stores are held to on Postgres. */
class InMemorySsfStoreTest extends SsfStoreContract {

    @Override
    protected SsfStore newStore() {
        return new InMemorySsfStore();
    }

    /** This store returns the stream as stored; the durable stores return the argument (SsfStore#updateStream). */
    @Test
    void anUpdateReturnsTheStreamAsStoredWithItsOwner() {
        String id = newId();
        this.store.createStream(pollStream(id).toBuilder().ownerClientId("receiver-a").build());

        Stream moved = this.store.updateStream(pollStream(id).toBuilder().ownerClientId("receiver-b").build());

        assertEquals("receiver-a", moved.ownerClientId(), "what is returned is what was stored");
    }

    /** The durable stores refuse a taken id with their database's error; this one says which id. */
    @Test
    void aTakenIdIsRefusedAsAnIllegalArgument() {
        String id = newId();
        this.store.createStream(pollStream(id));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> this.store.createStream(pollStream(id)));
        assertEquals("stream already exists: " + id, e.getMessage());
    }
}
