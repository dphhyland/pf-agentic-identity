/*
 * H-SSF-7 on a store, on PostgreSQL: the push authorization_header is sealed in the database, read back, rotated, and a
 * clear value from an earlier version is migrated on the stream's next write. Held by the tables and the ldm stores.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

/** What a store under test writes and how the test reads its column raw. */
abstract class PushHeaderAtRestContract {
    abstract SsfStore store(PushHeaderCipher headers);

    abstract String raw(String streamId) throws SQLException;

    /** Writes a clear header behind the store's back, as a version before 0.6.0 left it. */
    abstract void writeClear(String streamId, String header) throws SQLException;

    @Test
    void theHeaderIsSealedInTheDatabaseAndReadBackInClear() throws Exception {
        SsfStore store = store(cipher(PushHeaderCipherTest.KEY_1, null));
        String id = SsfStoreContract.newId();
        store.createStream(pushWithHeader(id, HEADER));
        String raw = raw(id);
        assertTrue(raw.startsWith("ssfenc:v1:" + cipher(PushHeaderCipherTest.KEY_1, null).kid() + ":"), raw);
        assertFalse(raw.contains("receiver-endpoint-token"));
        assertEquals(HEADER, store.getStream(id).orElseThrow().pushAuthorizationHeader());
        assertEquals(HEADER, store.listStreams().stream().filter(s -> s.id().equals(id)).findFirst().orElseThrow()
                .pushAuthorizationHeader());

        store.updateStream(store.getStream(id).orElseThrow().withStatus(StreamStatus.PAUSED, "test", 2L));
        assertTrue(PushHeaderCipher.isSealed(raw(id)), "an update seals it again");
        assertEquals(HEADER, store.getStream(id).orElseThrow().pushAuthorizationHeader());
    }

    @Test
    void aRotatedKeyStillOpensAndTheNextWriteSealsUnderTheNewKey() throws Exception {
        String id = SsfStoreContract.newId();
        store(cipher(PushHeaderCipherTest.KEY_1, null)).createStream(pushWithHeader(id, HEADER));
        PushHeaderCipher rotated = cipher(PushHeaderCipherTest.KEY_2, PushHeaderCipherTest.KEY_1);
        SsfStore store = store(rotated);
        Stream read = store.getStream(id).orElseThrow();
        assertEquals(HEADER, read.pushAuthorizationHeader());
        assertTrue(raw(id).contains(":" + cipher(PushHeaderCipherTest.KEY_1, null).kid() + ":"), "untouched until written");

        store.updateStream(read.withStatus(StreamStatus.ENABLED, null, 3L));
        assertTrue(raw(id).startsWith("ssfenc:v1:" + rotated.kid() + ":"), "sealed under the new key on the next write");
        assertEquals(HEADER, store(cipher(PushHeaderCipherTest.KEY_2, null)).getStream(id).orElseThrow().pushAuthorizationHeader(),
                "and the old key is no longer needed");
    }

    @Test
    void aClearLegacyHeaderIsReadAndMigratedOnTheNextWrite() throws Exception {
        String id = SsfStoreContract.newId();
        store(PushHeaderCipher.CLEAR).createStream(pushWithHeader(id, "placeholder"));
        writeClear(id, HEADER);
        SsfStore store = store(cipher(PushHeaderCipherTest.KEY_1, null));
        Stream read = store.getStream(id).orElseThrow();
        assertEquals(HEADER, read.pushAuthorizationHeader(), "a clear value an earlier version stored reads as it is");
        assertEquals(HEADER, raw(id));

        store.updateStream(read.withStatus(StreamStatus.ENABLED, null, 4L));
        assertTrue(PushHeaderCipher.isSealed(raw(id)));
        assertEquals(HEADER, store.getStream(id).orElseThrow().pushAuthorizationHeader());
    }

    @Test
    void productionWithoutAKeyStoresNoHeaderAndRefusesToStart() throws Exception {
        SsfStore store = store(cipher(null, null));
        assertThrows(PushHeaderCipher.KeyMissing.class, () -> cipher(null, null).refuseWithoutKey(store), "whatever the store holds");
        String id = SsfStoreContract.newId();
        assertThrows(PushHeaderCipher.KeyMissing.class, () -> store.createStream(pushWithHeader(id, HEADER)));
        assertTrue(store.getStream(id).isEmpty());
        store.createStream(pushWithHeader(id, null)); // no header: nothing to refuse

        String held = SsfStoreContract.newId();
        store(PushHeaderCipher.CLEAR).createStream(pushWithHeader(held, HEADER));
        assertThrows(PushHeaderCipher.KeyMissing.class, () -> cipher(null, null).refuseWithoutKey(store));
    }

    @Test
    void aHeaderSealedForOneStreamDoesNotOpenOnAnother() throws Exception {
        SsfStore store = store(cipher(PushHeaderCipherTest.KEY_1, null));
        String a = SsfStoreContract.newId();
        String b = SsfStoreContract.newId();
        store.createStream(pushWithHeader(a, HEADER));
        store.createStream(pushWithHeader(b, "Bearer other"));
        writeClear(b, raw(a)); // a database writer copies a's sealed header onto b
        assertEquals(raw(a), store.getStream(b).orElseThrow().pushAuthorizationHeader(), "left sealed, never a's token");
    }

    static final String HEADER = "Bearer receiver-endpoint-token";

    static PushHeaderCipher cipher(String current, String previous) {
        return PushHeaderCipher.of(current, previous, true);
    }

    static Stream pushWithHeader(String id, String header) {
        return SsfStoreContract.pushStream(id, StreamStatus.ENABLED).toBuilder().pushAuthorizationHeader(header).build();
    }

    static String query(DataSource ds, String sql, String arg) throws SQLException {
        try (Connection c = ds.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, arg);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        }
    }

    static void update(DataSource ds, String sql, String first, String second) throws SQLException {
        try (Connection c = ds.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, first);
            ps.setString(2, second);
            assertEquals(1, ps.executeUpdate());
        }
    }
}
