package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * The one string that carries the attested entitlement across a deliberate module boundary.
 *
 * <p>{@code servlets/pf-integration} writes the verified attestation context onto the request;
 * {@code plugins/rar-paz-plugin} reads it as {@code AttestationSubject.REQUEST_ATTRIBUTE} and turns it
 * into the ceiling the PDP evaluates against. The two modules do not — and should not — depend on each
 * other: the plugin loads on PingFederate's per-plugin isolated classloader and shades its own jackson,
 * so a shared constant is not available to it. The contract is therefore a string literal duplicated on
 * both sides, which is exactly the kind of coupling that drifts silently.
 *
 * <p>Drifting is not a compile error and not a test failure anywhere else. It is a
 * {@code fromAttribute(null)} returning {@code empty()}, the PDP request falling back to the client as
 * its own subject, and the attested ceiling quietly vanishing — with every other test in both modules
 * still green. This test is the only thing that would catch it, so it reads the plugin's source rather
 * than asserting the constant against itself, which would prove nothing.
 */
class RarContextKeyTest {

    /**
     * Where the plugin's half of the contract lives, relative to this module's basedir (surefire runs
     * with the module directory as the working directory).
     */
    private static final Path PLUGIN_SOURCE = Path.of(
            "../../plugins/rar-paz-plugin/src/main/java/com/pingidentity/ps/oidf/rar/AttestationSubject.java");

    private static final Pattern REQUEST_ATTRIBUTE = Pattern.compile(
            "REQUEST_ATTRIBUTE\\s*=\\s*\"([^\"]+)\"");

    @Test
    void theRarContextKeyIsIdenticalOnBothSidesOfTheModuleBoundary() throws IOException {
        assertTrue(Files.isRegularFile(PLUGIN_SOURCE),
                "expected the rar-paz-plugin source at " + PLUGIN_SOURCE.toAbsolutePath()
                        + ". If that class moved, this contract still exists and still needs pinning — "
                        + "update the path here rather than deleting the test.");

        String source = Files.readString(PLUGIN_SOURCE);
        Matcher m = REQUEST_ATTRIBUTE.matcher(source);
        assertTrue(m.find(),
                "could not find REQUEST_ATTRIBUTE in AttestationSubject. If the plugin stopped reading a "
                        + "request attribute the contract has changed shape, not disappeared.");

        assertEquals(m.group(1), ClientAttestationUtils.RAR_ATTESTATION_CONTEXT_ATTRIBUTE,
                "the writer (pf-integration) and the reader (rar-paz-plugin) disagree about the request "
                        + "attribute carrying the attested entitlement. Nothing else fails when these "
                        + "drift: the RAR processor simply sees no attestation and falls back to the "
                        + "client as its own subject, silently dropping the ceiling.");
    }
}
