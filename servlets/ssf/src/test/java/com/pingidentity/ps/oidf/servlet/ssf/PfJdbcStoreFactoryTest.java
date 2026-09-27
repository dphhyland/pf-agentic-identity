package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import java.util.List;
import org.junit.jupiter.api.Test;

/** H2 and HSQLDB were dropped in 0.5.0: an SSF store URL naming either stops the store at start-up, and says what to use. */
class PfJdbcStoreFactoryTest {

    private static SsfConfiguration withJdbcUrl(String url) {
        return new SsfConfiguration.Builder().issuer("https://op.example.com").jdbcUrl(url).build();
    }

    @Test
    void anH2OrHsqldbStoreUrlIsRefusedWithAMessageNamingPostgres() {
        for (String url : List.of("jdbc:hsqldb:mem:ssf", "jdbc:h2:mem:ssf;MODE=PostgreSQL", "Jdbc:Hsqldb:file:/opt/pf/ssf")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> new PfJdbcStoreFactory().create(withJdbcUrl(url)), url);

            assertTrue(e.getMessage().contains("PostgreSQL"), e.getMessage());
            assertTrue(e.getMessage().contains("dropped in 0.5.0"), e.getMessage());
        }
    }

    @Test
    void theRefusalDoesNotRepeatTheUrl() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> PfJdbcStoreFactory.refuseDroppedDatabase("jdbc:hsqldb:hsql://db/ssf;password=hunter2"));

        assertFalse(e.getMessage().contains("hunter2"), e.getMessage());
    }

    @Test
    void aPostgresUrlIsNotRefused() {
        PfJdbcStoreFactory.refuseDroppedDatabase("jdbc:postgresql://db:5432/ssf");
        PfJdbcStoreFactory.refuseDroppedDatabase("jdbc:h2x:not-h2");
    }
}
