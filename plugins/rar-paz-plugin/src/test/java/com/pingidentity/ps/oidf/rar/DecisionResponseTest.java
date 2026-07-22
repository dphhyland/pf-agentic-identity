package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DecisionResponseTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void permitViaAuthorisedTrue() throws Exception {
        DecisionResponse r = DecisionResponse.fromJson("{\"decision\":\"PERMIT\",\"authorised\":true,\"statements\":[]}", mapper);
        assertTrue(r.isPermit());
        assertEquals("PERMIT", r.getDecision());
    }

    @Test
    void denyViaAuthorisedFalse() throws Exception {
        DecisionResponse r = DecisionResponse.fromJson("{\"decision\":\"DENY\",\"authorised\":false}", mapper);
        assertFalse(r.isPermit());
    }

    @Test
    void notApplicableIsNotPermit() throws Exception {
        DecisionResponse r = DecisionResponse.fromJson("{\"decision\":\"NOT_APPLICABLE\",\"authorised\":false,\"statements\":[]}", mapper);
        assertFalse(r.isPermit());
    }

    @Test
    void permitViaDecisionWhenAuthorisedAbsent() throws Exception {
        DecisionResponse r = DecisionResponse.fromJson("{\"decision\":\"PERMIT\"}", mapper);
        assertTrue(r.isPermit());
    }

    @Test
    void statementsAreParsed() throws Exception {
        DecisionResponse r = DecisionResponse.fromJson(
                "{\"decision\":\"PERMIT\",\"authorised\":true,\"statements\":[{\"name\":\"access.limit\",\"payload\":{\"max\":100}}]}", mapper);
        assertEquals(1, r.getStatements().size());
        assertEquals("access.limit", r.getStatements().get(0).getName());
    }
}
