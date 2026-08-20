package com.pingidentity.ps.oidf.federation;

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
import com.pingidentity.ps.oidf.jose.JwtCodec;

/**
 * Loop-closer: the real {@link TrustChainValidator} validating a LIVE federation — every entity
 * statement fetched over HTTP from a trust anchor and an entity host, dropped into a directory, and
 * validated here with no re-signing.
 *
 * <p>Opt-in, and deliberately not pinned to any particular deployment. This module is capability: it
 * must build with no network dependency on a host someone else operates, and the two anchors it used
 * to name belong to a demo environment this repo no longer deploys. Supply them, along with the
 * fetched statements, to run it:
 *
 * <pre>
 *   mvn test -Doidf.live.dir=/tmp/live-chain \
 *            -Doidf.live.trustAnchor=https://anchor.example \
 *            -Doidf.live.entityHost=https://entities.example
 * </pre>
 *
 * <p>With any of the three unset the test skips rather than failing, and skips loudly enough to say
 * why — an unset live rig is not a defect.
 */
class LiveChainValidationTest {
    private static final String DIR_PROP = "oidf.live.dir";
    private static final String TA_PROP = "oidf.live.trustAnchor";
    private static final String FH_PROP = "oidf.live.entityHost";

    private static final Path DIR = Path.of(System.getProperty(DIR_PROP, "/tmp/live-chain"));
    private static final String TA = System.getProperty(TA_PROP, "");
    private static final String FH = System.getProperty(FH_PROP, "");

    private final Map<String, String> entityConfigs = new HashMap<>();
    private final Map<String, String> subStatements = new HashMap<>();
    private final List<String> allStatements = new ArrayList<>();

    @BeforeEach
    void loadLiveStatements() throws Exception {
        Assumptions.assumeTrue(Files.isDirectory(DIR),
                "no live chain at " + DIR + " - set -D" + DIR_PROP + " to a directory of fetched statements");
        Assumptions.assumeFalse(TA.isBlank(),
                "no trust anchor - set -D" + TA_PROP + " to the anchor the statements are anchored at");
        Assumptions.assumeFalse(FH.isBlank(),
                "no entity host - set -D" + FH_PROP + " to the host the entity statements came from");
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
