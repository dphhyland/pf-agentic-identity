package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * PF rejects an extended-property name it has not been told about, so every deployment running these
 * modules must declare all of them. This pins the contract that tells a deployment which ones.
 *
 * <p>The check used to read {@code ../../deploy/pingfederate/terraform/extended-properties.tf} directly,
 * behind an {@code assumeTrue(Files.exists(...))} guard. That only worked while this repo also owned the
 * deployment: once the deploy tree moved out, the guard would have skipped every run and the test would
 * have passed forever without asserting anything — a silent green, which is worse than no test.
 *
 * <p>So the direction is inverted. The Java constant is the source of truth, {@code
 * docs/extended-properties.json} publishes it, and this test holds the two together. Consuming repos
 * diff their own Terraform against the published file in their own CI, where the Terraform actually
 * lives. Neither side can drift without something failing.
 */
class FederationClientParamsTest {

    /** Published contract, at the repo root — this module sits two levels down. */
    private static final Path PUBLISHED = Path.of("../../docs/extended-properties.json");

    @Test
    void thePublishedContractMatchesTheNamesThisModuleWrites() throws Exception {
        assertTrue(Files.exists(PUBLISHED),
                "docs/extended-properties.json is missing — it is the contract every consuming "
                        + "deployment declares its extended properties from, not an optional artifact");

        JsonNode root = new ObjectMapper().readTree(Files.readString(PUBLISHED));
        List<String> published = new ArrayList<>();
        root.withArray("extended_properties").forEach(n -> published.add(n.asText()));

        assertEquals(FederationClientParams.EXTENDED_PARAM_NAMES, published,
                "docs/extended-properties.json has drifted from FederationClientParams."
                        + "EXTENDED_PARAM_NAMES. The Java list is the source of truth: regenerate the "
                        + "file. A name written onto a client but not declared server-side is one PF "
                        + "will reject or silently drop.");
    }

    /** {@code status} is what distinguishes a module-registered client from an administrator's. */
    @Test
    void statusIsPublished() throws Exception {
        JsonNode root = new ObjectMapper().readTree(Files.readString(PUBLISHED));
        List<String> published = new ArrayList<>();
        root.withArray("extended_properties").forEach(n -> published.add(n.asText()));

        assertTrue(published.contains(FederationClientParams.STATUS),
                "both registration paths refuse to touch a client without 'status'; a deployment that "
                        + "does not declare it cannot register anything");
    }
}
