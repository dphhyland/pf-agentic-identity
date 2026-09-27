package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/** H2 and HSQLDB were dropped in 0.5.0: a direct URL naming either stops the component at start-up, and says what to use. */
class PfDataSourcesTest {

    @Test
    void anH2OrHsqldbUrlIsRefusedWithAMessageNamingPostgres() {
        for (String url : List.of("jdbc:h2:mem:authority;MODE=PostgreSQL", "jdbc:hsqldb:mem:authority", "JDBC:H2:file:/tmp/x",
                "jdbc:HSQLDB:hsql://localhost/pf")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> PfDataSources.direct(url, "sa", ""), url);

            assertTrue(e.getMessage().contains("PostgreSQL"), e.getMessage());
            assertTrue(e.getMessage().contains("dropped in 0.5.0"), e.getMessage());
        }
    }

    /** The rest of a JDBC URL can carry a password; the refusal names only the prefix. */
    @Test
    void theRefusalDoesNotRepeatTheUrl() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> PfDataSources.direct("jdbc:h2:tcp://db/x;PASSWORD=hunter2", "sa", ""));

        assertFalse(e.getMessage().contains("hunter2"), e.getMessage());
    }

    @Test
    void anyOtherUrlIsLeftToTheDriverManager() {
        assertNotNull(PfDataSources.direct("jdbc:nowhere:authority", "u", "p"));
        assertNotNull(PfDataSources.direct("jdbc:h2x:not-h2", "u", "p"), "a prefix match, not a substring one");
    }
}
