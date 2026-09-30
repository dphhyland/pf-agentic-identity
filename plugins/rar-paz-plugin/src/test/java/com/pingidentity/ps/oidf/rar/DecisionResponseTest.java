package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    /** A null member is an absent one: no decision, and not a permit. */
    @Test
    void aNullDecisionOrAuthorisedIsAbsent() throws Exception {
        DecisionResponse r = DecisionResponse.fromJson("{\"decision\":null,\"authorised\":null}", mapper);
        assertNull(r.getDecision());
        assertNull(r.getAuthorised());
        assertFalse(r.isPermit());
        assertTrue(DecisionResponse.fromJson("{\"decision\":\"PERMIT\",\"authorised\":null}", mapper).isPermit());
    }

    /**
     * Only the engine's own types are read. Jackson's asBoolean reads "true" and 1 as true, so a string or number
     * {@code authorised} used to permit; each wrong type, and a body a lenient reader would have accepted, is
     * refused here (the PDP answered, and the answer is not a permit).
     */
    @Test
    void aWrongTypeOrAMalformedBodyIsRefused() {
        for (String body : new String[] {
                "{\"authorised\":\"true\"}",
                "{\"authorised\":1}",
                "{\"authorised\":{\"value\":true}}",
                "{\"decision\":1}",
                "{\"decision\":[\"PERMIT\"]}",
                "{\"decision\":true}",
                "{\"decision\":\"PERMIT\"} trailing junk",
                "{\"decision\":\"DENY\",\"decision\":\"PERMIT\"}",
                "{\"authorised\":false,\"authorised\":true}"}) {
            IOException e = assertThrows(IOException.class, () -> DecisionResponse.fromJson(body, mapper), body);
            assertFalse(e instanceof PdpUnavailableException, body);
        }
    }

    @Test
    void statementsAreParsed() throws Exception {
        DecisionResponse r = DecisionResponse.fromJson(
                "{\"decision\":\"PERMIT\",\"authorised\":true,\"statements\":[{\"name\":\"access.limit\",\"payload\":{\"max\":100}}]}", mapper);
        assertEquals(1, r.getStatements().size());
        assertEquals("access.limit", r.getStatements().get(0).getName());
    }
}
