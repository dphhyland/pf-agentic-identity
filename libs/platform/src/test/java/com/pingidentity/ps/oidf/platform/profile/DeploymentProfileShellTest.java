/*
 * The image's entrypoint and the Java rule read OIDF_DEPLOYMENT_PROFILE the same way.
 */
package com.pingidentity.ps.oidf.platform.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * Runs one table through {@link DeploymentProfile#parse} and through {@code is_development} in
 * build/pingfederate/pf-entrypoint.sh, the shell rule that decides whether a plaintext config archive may boot.
 * The shell is taken from the script as it is - its {@code PROFILE=} line and its {@code is_development} function
 * - and run by {@code /bin/sh}, which the script's shebang names, so an edit to either side that changes an answer
 * fails here.
 *
 * <p>They differ in one way, pinned below: the shell does not trim, so a value with a space or a tab around
 * {@code development} is production to the entrypoint and development to Java (finding F-0161). The shell is the
 * stricter side, and the plaintext archive it guards stays refused.
 */
class DeploymentProfileShellTest {

    private static final Path SCRIPT = Path.of("..", "..", "build", "pingfederate", "pf-entrypoint.sh");

    /** The two lines of the entrypoint that read the profile. */
    static String shellRule() throws IOException {
        String profile = null;
        String function = null;
        for (String line : Files.readAllLines(SCRIPT, StandardCharsets.UTF_8)) {
            if (line.startsWith("PROFILE=")) {
                profile = line;
            } else if (line.startsWith("is_development()")) {
                function = line;
            }
        }
        assertTrue(profile != null && function != null, "pf-entrypoint.sh has no PROFILE= line or is_development function");
        return profile + "\n" + function + "\n";
    }

    /** What the shell rule answers for a value, or for an unset variable when {@code value} is null. */
    static String shell(String rule, String value) throws Exception {
        ProcessBuilder builder = new ProcessBuilder("/bin/sh", "-c", rule + "if is_development; then echo development; else echo production; fi");
        builder.environment().remove(DeploymentProfile.SETTING);
        if (value != null) {
            builder.environment().put(DeploymentProfile.SETTING, value);
        }
        Process process = builder.redirectErrorStream(true).start();
        String out = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        assertTrue(process.waitFor(30, TimeUnit.SECONDS), "the shell did not finish");
        assertEquals(0, process.exitValue(), out);
        return out;
    }

    @Test
    void theEntrypointAndTheJavaRuleAgreeOnEveryValueButPaddedOnes() throws Exception {
        String rule = shellRule();
        Map<String, String> agreed = new LinkedHashMap<>();
        agreed.put(null, "production");
        agreed.put("", "production");
        agreed.put("production", "production");
        agreed.put("staging", "production");
        agreed.put("dev", "production");
        agreed.put("developement", "production");
        agreed.put("development1", "production");
        agreed.put("development", "development");
        agreed.put("Development", "development");
        agreed.put("DEVELOPMENT", "development");
        agreed.put("development\n", "development");
        List<String> wrong = new ArrayList<>();
        for (Map.Entry<String, String> row : agreed.entrySet()) {
            String java = DeploymentProfile.parse(row.getKey()).value();
            String sh = shell(rule, row.getKey());
            if (!row.getValue().equals(java) || !row.getValue().equals(sh)) {
                wrong.add("'" + row.getKey() + "': expected " + row.getValue() + ", Java " + java + ", shell " + sh);
            }
        }
        assertEquals(List.of(), wrong);
    }

    @Test
    void paddingIsTheOneDifferenceAndTheShellIsTheStricterSide() throws Exception {
        String rule = shellRule();
        for (String padded : new String[] {" development", "development ", "\tdevelopment"}) {
            assertEquals("development", DeploymentProfile.parse(padded).value(), "'" + padded + "' in Java");
            assertEquals("production", shell(rule, padded), "'" + padded + "' in the entrypoint (F-0161)");
        }
    }
}
