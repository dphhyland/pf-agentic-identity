package com.pingidentity.ps.oidf.keyhistory;

/** The in-memory history, held to the same contract as the durable one. */
class InMemoryKeyHistoryStoreTest extends KeyHistoryStoreContract {
    @Override
    protected KeyHistoryStore newStore() {
        return new InMemoryKeyHistoryStore();
    }
}
