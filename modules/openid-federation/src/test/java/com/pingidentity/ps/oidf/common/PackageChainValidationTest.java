package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
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
 * Fix A demo harness: feed our real {@link TrustChainValidator} the pre-signed statements from the
 * Banking Demo federation package (anchored at https://demo.example.com) and confirm it validates
 * trust chains end-to-end — no hosting, no re-signing. Reads the package from /tmp/fedpkg.
 */
class PackageChainValidationTest {
    private static final Path PKG = Path.of("/tmp/fedpkg");
    private static final String TA = "https://demo.example.com";

    // A gateway backed entirely by the package's signed statements (the federation served from memory).
    private final Map<String, String> entityConfigs = new HashMap<>();          // iss==sub  -> EC jwt
    private final Map<String, String> subStatements = new HashMap<>();          // "iss|sub" -> subordinate jwt
    private final List<String> allStatements = new ArrayList<>();

    @BeforeEach
    void loadPackage() throws Exception {
        Assumptions.assumeTrue(Files.isDirectory(PKG), "federation package not present at " + PKG);
        indexDir(PKG.resolve("entities"));
        indexDir(PKG.resolve("relationships"));
    }

    private void indexDir(Path dir) throws Exception {
        try (Stream<Path> s = Files.list(dir)) {
            for (Path p : s.filter(x -> x.toString().endsWith(".jwt")).toList()) {
                String jwt = Files.readString(p).trim();
                JwtClaims c = JwtCodec.parseUnverifiedClaims(jwt);
                String iss = c.getIssuer();
                String sub = c.getSubject();
                allStatements.add(jwt);
                if (iss.equals(sub)) {
                    entityConfigs.put(iss, jwt);
                } else {
                    subStatements.put(iss + "|" + sub, jwt);
                }
            }
        }
    }

    private TrustControllerGateway packageGateway() {
        return new TrustControllerGateway() {
            @Override public JwtClaims fetchEntityConfiguration() throws Exception {
                return JwtCodec.parseUnverifiedClaims(entityConfigs.get(TA));
            }
            @Override public List<String> fetchMembers() {
                return List.copyOf(entityConfigs.keySet());
            }
            @Override public String fetchEntityStatement(String issuer) {
                return entityConfigs.get(issuer);
            }
            @Override public String fetchSubordinateStatement(String authorityIssuer, String subject) {
                return subStatements.get(authorityIssuer + "|" + subject);
            }
        };
    }

    private TrustChainValidationResult validateLeaf(String leaf) throws Exception {
        TrustChainValidator v = new TrustChainValidator(packageGateway(), TA);
        // Fix A: hand it the whole set of signed statements; it selects the leaf and routes to the TA.
        return v.validate(allStatements, leaf, leaf);
    }

    @Test
    void directLeafValidatesToTrustAnchor() throws Exception {
        // payment agent — 3-hop chain: leaf EC, TA subordinate stmt, TA EC
        TrustChainValidationResult r = validateLeaf("https://demo.example.com/payment-agent/agent");
        assertEquals(TA, r.trustAnchorIssuer());
        assertEquals("https://demo.example.com/payment-agent/agent", r.leafSubject());
        assertNotNull(r.leafEntityStatement());
    }

    @Test
    void crossOrgLeafValidatesThroughIntermediate() throws Exception {
        // CBA payment API — 5-hop cross-org chain: leaf EC, as->cba stmt, as EC, demo->as stmt, demo EC
        TrustChainValidationResult r = validateLeaf("https://agentic.cba.com.au/payment/api");
        assertEquals(TA, r.trustAnchorIssuer());
        assertEquals("https://agentic.cba.com.au/payment/api", r.leafSubject());
    }
}
