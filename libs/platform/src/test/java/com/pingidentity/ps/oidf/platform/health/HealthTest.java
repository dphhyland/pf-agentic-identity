/*
 * Readiness is DOWN for an enabled component that is not ready; the detail document carries every component.
 */
package com.pingidentity.ps.oidf.platform.health;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.ComponentStatus;
import com.pingidentity.ps.oidf.platform.json.Json;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class HealthTest {

    private static final Instant T = Instant.parse("2026-09-28T01:02:03Z");

    private static ComponentStatus status(String name, boolean enabled, ComponentState state, String reason) {
        return new ComponentStatus(name, enabled, state, reason, T);
    }

    @Test
    void readinessIsUpWithNothingRegisteredAndWithOnlyDisabledComponents() {
        assertEquals(Health.Status.UP, Health.readiness(List.of()));
        assertEquals(Health.Status.UP, Health.readiness(List.of(status("SSF", false, ComponentState.DISABLED, ""))));
    }

    @Test
    void readinessCountsReadyAndDegradedAsServingAndNothingElse() {
        for (ComponentState state : ComponentState.values()) {
            if (state == ComponentState.DISABLED) {
                continue;
            }
            Health.Status expected = state == ComponentState.READY || state == ComponentState.DEGRADED ? Health.Status.UP : Health.Status.DOWN;
            assertEquals(expected, Health.readiness(List.of(status("FEDERATION", true, ComponentState.READY, ""),
                    status("SSF", true, state, "x"))), state.name());
        }
        assertTrue(Health.serving(ComponentState.DEGRADED));
        assertFalse(Health.serving(ComponentState.STARTING));
    }

    @Test
    void theStatusDocumentSaysOnlyTheStatus() {
        assertEquals("{\"status\":\"UP\"}", Json.write(Health.status(Health.Status.UP)));
        assertEquals("{\"status\":\"DOWN\"}", Json.write(Health.status(Health.Status.DOWN)));
    }

    @Test
    void theDetailCarriesEveryComponentItsPartsTheProfileAndTheVersions() {
        Map<String, Object> versions = new LinkedHashMap<>();
        versions.put("agentic-identity", "0.5.0");
        versions.put("commit", null);
        List<ComponentStatus> components = List.of(status("AUTO_REGISTRATION", true, ComponentState.FAILED_CONFIG,
                "TokenEndpointAutoRegistrationFilter: no keys"), status("SSF", false, ComponentState.DISABLED, ""));
        List<PartStatus> parts = List.of(
                new PartStatus("AUTO_REGISTRATION", "FrontChannelAutoRegistrationFilter", ComponentState.DISABLED, "", T),
                new PartStatus("AUTO_REGISTRATION", "TokenEndpointAutoRegistrationFilter", ComponentState.FAILED_CONFIG, "no keys", T),
                new PartStatus("SSF", "SsfConfigurationServlet", ComponentState.DISABLED, "", T));

        String json = Json.write(Health.detail(components, parts, "development", versions));

        assertEquals("{\"components\":["
                + "{\"enabled\":true,\"name\":\"AUTO_REGISTRATION\",\"parts\":["
                + "{\"name\":\"FrontChannelAutoRegistrationFilter\",\"reason\":\"\",\"since\":\"2026-09-28T01:02:03Z\",\"state\":\"DISABLED\"},"
                + "{\"name\":\"TokenEndpointAutoRegistrationFilter\",\"reason\":\"no keys\",\"since\":\"2026-09-28T01:02:03Z\",\"state\":\"FAILED_CONFIG\"}],"
                + "\"reason\":\"TokenEndpointAutoRegistrationFilter: no keys\",\"since\":\"2026-09-28T01:02:03Z\",\"state\":\"FAILED_CONFIG\"},"
                + "{\"enabled\":false,\"name\":\"SSF\",\"parts\":["
                + "{\"name\":\"SsfConfigurationServlet\",\"reason\":\"\",\"since\":\"2026-09-28T01:02:03Z\",\"state\":\"DISABLED\"}],"
                + "\"reason\":\"\",\"since\":\"2026-09-28T01:02:03Z\",\"state\":\"DISABLED\"}],"
                + "\"profile\":\"development\",\"status\":\"DOWN\",\"versions\":{\"agentic-identity\":\"0.5.0\",\"commit\":null}}", json);
    }
}
