/*
 * FAPI registers its part at init: ready when it names a client, disabled when it names none, failed on a throw.
 */
package com.pingidentity.ps.oidf.servlet.fapi2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.health.PartStatus;
import com.pingidentity.ps.oidf.platform.health.Startup;
import jakarta.servlet.FilterConfig;
import org.junit.jupiter.api.Test;

class Fapi2ProfileFilterComponentTest {

    static PartStatus part(String name) {
        return Startup.parts().parts().stream().filter(p -> p.part().equals(name)).findFirst().orElseThrow();
    }

    @Test
    void namingAClientMakesFapiReady() {
        FilterConfig config = mock(FilterConfig.class);
        when(config.getInitParameter("clients")).thenReturn("client-1");
        new Fapi2ProfileFilter(r -> "https://op.example", name -> null).init(config);
        assertEquals(ComponentState.READY, part("Fapi2ProfileFilter").state());
        assertEquals(Startup.FAPI, part("Fapi2ProfileFilter").component());
    }

    @Test
    void namingNoClientLeavesFapiDisabled() {
        new Fapi2ProfileFilter(r -> "https://op.example", name -> null).init(null);
        assertEquals(ComponentState.DISABLED, part("Fapi2ProfileFilter").state());
    }

    @Test
    void anExceptionFromInitIsRecordedAndRethrownUnchanged() {
        IllegalStateException boom = new IllegalStateException("the environment could not be read");
        Fapi2ProfileFilter filter = new Fapi2ProfileFilter(r -> "https://op.example", name -> {
            throw boom;
        });
        assertSame(boom, assertThrows(IllegalStateException.class, () -> filter.init(null)));
        assertEquals(ComponentState.FAILED_CONFIG, part("Fapi2ProfileFilter").state());
        assertEquals("the environment could not be read", part("Fapi2ProfileFilter").reason());
    }
}
