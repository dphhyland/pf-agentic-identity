/*
 * device-enrolment's registrar against a running PingFederate built from this repository.
 */
package com.pingidentity.ps.oidf.enrolment;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.nio.file.Path;
import java.util.Map;
import java.util.UUID;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;

/**
 * Skipped unless {@code OIDF_TEST_AUTHORITY_RIG} names a JSON file: {@code authority} (the authority's entity id),
 * {@code url} (where to reach it), {@code profile}, {@code dpop_client} and {@code dpop_secret} (a client with
 * {@code oidf.admin.entities} and Require DPoP) and, optionally, {@code bearer_client} and {@code bearer_secret} (the
 * same without Require DPoP). The rig's certificate is self-signed, so the registrar trusts any chain for the host.
 */
class AuthorityCredentialsRigTest {
    private static final String FILE = System.getenv("OIDF_TEST_AUTHORITY_RIG");

    private static JsonNode rig() throws Exception {
        assumeTrue(FILE != null && !FILE.isBlank(), "set OIDF_TEST_AUTHORITY_RIG to run against a PingFederate rig");
        return new ObjectMapper().readTree(Path.of(FILE).toFile());
    }

    private static HostedEntityRegistrar.PingFederate registrar(JsonNode rig, String client, String secret) {
        return HostedEntityRegistrar.PingFederate.of(rig.path("authority").asText(), new AuthorityCredentials.Settings(
                rig.path("url").asText(), null, client, secret, null, null), true,
                DeploymentProfile.of(name -> "OIDF_DEPLOYMENT_PROFILE".equals(name) ? rig.path("profile").asText() : null));
    }

    private static String enrol(HostedEntityRegistrar registrar) throws Exception {
        String id = "s8b-" + UUID.randomUUID().toString().substring(0, 8);
        Map<String, Object> jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256)
                .toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        jwk.put("kid", id);
        return registrar.register(id, jwk, Map.of("oauth_client", Map.of("client_name", "S8B rig agent")), null, "s8b-rig");
    }

    @Test
    void aDpopBoundClientCredentialsTokenFromPingFederateEnrolsAHostedEntity() throws Exception {
        JsonNode rig = rig();
        String entityId = enrol(registrar(rig, rig.path("dpop_client").asText(), rig.path("dpop_secret").asText()));
        assertTrue(entityId.startsWith(rig.path("authority").asText() + "/federation/agents/s8b-"), entityId);
    }

    @Test
    void aTokenPingFederateDidNotBindIsNeverSentInProduction() throws Exception {
        JsonNode rig = rig();
        assumeTrue(rig.has("bearer_client") && "production".equals(rig.path("profile").asText()));
        EnrolmentException refused = assertThrows(EnrolmentException.class,
                () -> enrol(registrar(rig, rig.path("bearer_client").asText(), rig.path("bearer_secret").asText())));
        assertTrue(refused.getMessage().contains("not a DPoP-bound one"), refused.getMessage());
    }
}
