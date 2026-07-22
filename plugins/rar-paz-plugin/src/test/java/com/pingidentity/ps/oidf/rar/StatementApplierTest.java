package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StatementApplierTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @SuppressWarnings("unchecked")
    void appliesNestedObjectPayloadByDotPath() {
        Map<String, Object> detail = new HashMap<>();
        detail.put("type", "payment_initiation");
        List<DecisionResponse.Statement> statements =
                List.of(new DecisionResponse.Statement("access.limits", Map.of("maxAmount", "100.00")));

        StatementApplier.apply(statements, detail, mapper);

        Map<String, Object> access = (Map<String, Object>) detail.get("access");
        Map<String, Object> limits = (Map<String, Object>) access.get("limits");
        assertEquals("100.00", limits.get("maxAmount"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void parsesJsonStringPayload() {
        Map<String, Object> detail = new HashMap<>();
        List<DecisionResponse.Statement> statements =
                List.of(new DecisionResponse.Statement("filter", "{\"allow\":true}"));

        StatementApplier.apply(statements, detail, mapper);

        assertTrue(detail.get("filter") instanceof Map);
        assertEquals(Boolean.TRUE, ((Map<String, Object>) detail.get("filter")).get("allow"));
    }

    @Test
    void nullStatementsAreNoOp() {
        Map<String, Object> detail = new HashMap<>();
        detail.put("type", "sales_agent");
        StatementApplier.apply(null, detail, mapper);
        assertEquals(1, detail.size());
    }
}
