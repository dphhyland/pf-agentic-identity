/*
 * H-SSF-7 on the Identity Object Model store, on PostgreSQL with the model repo's own migrations (the IOM fixture).
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.testkit.Migrations;
import com.pingidentity.ps.oidf.testkit.PostgresDatabase;
import java.sql.SQLException;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.RegisterExtension;

class LdmPushHeaderOnPostgresTest extends PushHeaderAtRestContract {

    @RegisterExtension
    static final PostgresDatabase POSTGRES = new PostgresDatabase();

    @BeforeAll
    static void modelSchema() throws Exception {
        Migrations.applyResources(POSTGRES.dataSource(), LdmPushHeaderOnPostgresTest.class,
                "/idm/0000-base-schema.sql", "/idm/0001-add-shared-signals-ssf.sql");
    }

    @Override
    SsfStore store(PushHeaderCipher headers) {
        return new LdmSsfStore(POSTGRES.dataSource(), headers);
    }

    @Override
    String raw(String streamId) throws SQLException {
        String attrs = query(POSTGRES.dataSource(), "SELECT attrs::text FROM idm.entry WHERE entry_uuid = ?::uuid", streamId);
        try {
            return (String) JsonUtil.parseJson(attrs).get("pushAuthorizationHeader");
        } catch (org.jose4j.lang.JoseException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    void writeClear(String streamId, String header) throws SQLException {
        update(POSTGRES.dataSource(), "UPDATE idm.entry SET attrs = jsonb_set(attrs, '{pushAuthorizationHeader}', to_jsonb(?::text))"
                + " WHERE entry_uuid = ?::uuid", header, streamId);
    }
}
