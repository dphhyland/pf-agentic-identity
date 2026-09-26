package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.pingidentity.ps.oidf.federation.testkit.Federation;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** This deployment's own statements come from itself; everything else from the wrapped gateway. */
class LocalFirstTrustControllerGatewayTest {
    private static final String TA = "https://ta.example";
    private static final String LEAF = "https://rp.example";

    private static LocalStatementSource answering(Map<String, String> configurations, Map<String, String> statements) {
        return new LocalStatementSource() {
            @Override
            public String entityConfiguration(String entityId) {
                return configurations.get(entityId);
            }

            @Override
            public String subordinateStatement(String issuer, String subject) {
                return statements.get(issuer + " " + subject);
            }
        };
    }

    @Test
    void localStatementsAreAnsweredInProcessAndTheRestAreFetched() throws Exception {
        Federation f = Federation.builder().anchor(TA).leaf(LEAF, TA).build();
        HttpTrustControllerGateway http = f.gateway(TA);
        LocalFirstTrustControllerGateway gateway = new LocalFirstTrustControllerGateway(http,
                answering(Map.of(TA, "local-ec"), Map.of(TA + " " + LEAF, "local-ss")));

        assertEquals("local-ec", gateway.fetchEntityStatement(TA));
        assertEquals("local-ss", gateway.fetchSubordinateStatement(TA, LEAF));
        assertEquals("local-ec", gateway.anchorConfiguration(f.trustAnchor(TA), Set.of(), null));
        assertEquals(List.of(), f.http().requests());

        LocalFirstTrustControllerGateway passThrough = new LocalFirstTrustControllerGateway(http, answering(Map.of(), Map.of()));
        assertEquals(f.entityConfiguration(LEAF), passThrough.fetchEntityStatement(LEAF));
        assertEquals(f.subordinateStatement(TA, LEAF), passThrough.fetchSubordinateStatement(TA, LEAF));
        passThrough.bindTrustAnchors(f.trustAnchors(), Set.of());
        passThrough.bindTrustAnchor(f.trustAnchor(TA), Set.of());
        assertEquals(f.entityConfiguration(TA), passThrough.anchorConfiguration(f.trustAnchor(TA), Set.of(), null));
        assertEquals(TA, passThrough.fetchEntityConfiguration().getSubject(), "the wrapped gateway's own trust controller");
        passThrough.evictCachedStatement(TA, LEAF);
        assertEquals(0, passThrough.newPendingWrites().stagedCount());
    }

    @Test
    void membersComeFromTheWrappedGateway() throws Exception {
        Federation f = Federation.builder().anchor(TA).leaf(LEAF, TA).build();
        f.http().put(TA + "/list", "[\"" + LEAF + "\"]");
        HttpTrustControllerGateway http = f.gateway(TA);

        assertEquals(List.of(LEAF), new LocalFirstTrustControllerGateway(http, answering(Map.of(), Map.of())).fetchMembers());
    }
}
