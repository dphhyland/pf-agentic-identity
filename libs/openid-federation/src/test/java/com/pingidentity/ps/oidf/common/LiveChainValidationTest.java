package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Fix B loop-closer: our real {@link TrustChainValidator} validates the LIVE re-minted federation —
 * every entity statement was fetched over HTTP from Lighthouse (the anchor) and fedhost (the entities)
 * and dropped into /tmp/live-chain. Anchored at the live Lighthouse trust anchor, no re-signing.
 */
class LiveChainValidationTest {
    private static final Path DIR = Path.of("/tmp/live-chain");
    private static final String TA = "https://lighthouse-staging-e017.up.railway.app";
    private static final String FH = "https://fedhost-staging.up.railway.app";

    private final Map<String, String> entityConfigs = new HashMap<>();
    private final Map<String, String> subStatements = new HashMap<>();
    private final List<String> allStatements = new ArrayList<>();

    @BeforeEach
    void loadLiveStatements() throws Exception {
        Assumptions.assumeTrue(Files.isDirectory(DIR), "live chain not present at " + DIR);
        try (Stream<Path> s = Files.list(DIR)) {
            for (Path p : s.filter(x -> x.toString().endsWith(".jwt")).toList()) {
                String jwt = Files.readString(p).trim();
                if (jwt.chars().filter(ch -> ch == '.').count() != 2) continue;
                JwtClaims c = JwtCodec.parseUnverifiedClaims(jwt);
                allStatements.add(jwt);
                if (c.getIssuer().equals(c.getSubject())) entityConfigs.put(c.getIssuer(), jwt);
                else subStatements.put(c.getIssuer() + "|" + c.getSubject(), jwt);
            }
        }
    }

    private TrustControllerGateway liveGateway() {
        return new TrustControllerGateway() {
            @Override public JwtClaims fetchEntityConfiguration() throws Exception {
                return JwtCodec.parseUnverifiedClaims(entityConfigs.get(TA));
            }
            @Override public List<String> fetchMembers() { return List.copyOf(entityConfigs.keySet()); }
            @Override public String fetchEntityStatement(String issuer) { return entityConfigs.get(issuer); }
            @Override public String fetchSubordinateStatement(String authority, String subject) {
                return subStatements.get(authority + "|" + subject);
            }
        };
    }

    private TrustChainValidationResult validate(String leaf) throws Exception {
        return new TrustChainValidator(liveGateway(), TA).validate(allStatements, leaf, leaf);
    }

    @Test
    void directLeafValidatesToLighthouse() throws Exception {
        TrustChainValidationResult r = validate(FH + "/e/payment-agent");
        assertEquals(TA, r.trustAnchorIssuer());
        assertEquals(FH + "/e/payment-agent", r.leafSubject());
    }

    @Test
    void crossOrgLeafValidatesThroughAsToLighthouse() throws Exception {
        TrustChainValidationResult r = validate(FH + "/e/agentic-cba");
        assertEquals(TA, r.trustAnchorIssuer());
        assertEquals(FH + "/e/agentic-cba", r.leafSubject());
    }
}
