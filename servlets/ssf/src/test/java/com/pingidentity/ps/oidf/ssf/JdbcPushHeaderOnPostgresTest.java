/*
 * H-SSF-7 on the tables store, on PostgreSQL with the DDL it applies itself.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.testkit.PostgresDatabase;
import java.sql.SQLException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.RegisterExtension;

class JdbcPushHeaderOnPostgresTest extends PushHeaderAtRestContract {

    @RegisterExtension
    static final PostgresDatabase POSTGRES = new PostgresDatabase();

    @BeforeAll
    static void schema() {
        new JdbcSsfStore(POSTGRES.dataSource()).ensureSchema();
    }

    @Override
    SsfStore store(PushHeaderCipher headers) {
        return new JdbcSsfStore(POSTGRES.dataSource(), headers);
    }

    @Override
    String raw(String streamId) throws SQLException {
        return query(POSTGRES.dataSource(), "SELECT push_auth_header FROM ssf_streams WHERE stream_id = ?", streamId);
    }

    @Override
    void writeClear(String streamId, String header) throws SQLException {
        update(POSTGRES.dataSource(), "UPDATE ssf_streams SET push_auth_header = ? WHERE stream_id = ?", header, streamId);
    }
}
