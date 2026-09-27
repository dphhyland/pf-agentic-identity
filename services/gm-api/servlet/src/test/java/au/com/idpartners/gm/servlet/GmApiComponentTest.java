package au.com.idpartners.gm.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.ComponentStatus;
import com.pingidentity.ps.oidf.platform.component.Components;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import java.lang.reflect.Proxy;
import org.junit.jupiter.api.Test;

/**
 * gm-api's two load-on-startup servlets register the GM_API component's parts, so this war's own health and
 * start-up audit (plan items O-4 and F-2) read DOWN, with the reason, when either fails to start.
 */
class GmApiComponentTest {

    private static ServletConfig noInitParams() {
        return (ServletConfig) Proxy.newProxyInstance(ServletConfig.class.getClassLoader(), new Class<?>[] {ServletConfig.class},
                (proxy, m, args) -> switch (m.getName()) {
                    case "getServletName" -> "gm-api-test";
                    default -> null;
                });
    }

    private static ComponentStatus gmApi() {
        return Components.status(GrantsServlet.COMPONENT).orElseThrow();
    }

    @Test
    void eitherServletFailingToStartLeavesGmApiFailedConfigWithTheReason() {
        assumeTrue(System.getenv("AUTHZEN_BASE_URL") == null, "the fallback for a missing pdpUrl is set in this environment");
        ServletException grants = assertThrows(ServletException.class, () -> new GrantsServlet().init(noInitParams()));
        assertEquals(ComponentState.FAILED_CONFIG, gmApi().state());
        assertTrue(gmApi().reason().contains(grants.getMessage()), gmApi().reason());

        assertThrows(ServletException.class, () -> new McpServlet().init(noInitParams()));
        assertEquals(ComponentState.FAILED_CONFIG, gmApi().state());
        assertTrue(gmApi().reason().contains("McpServlet"), gmApi().reason());
    }
}
