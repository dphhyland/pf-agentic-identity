package com.pingidentity.ps.oidf.warassembler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The MANIFEST v2 checks the shell script made, now in the assembler: the same refusals, the same words. */
class StagedManifestTest {
    @TempDir
    Path dir;

    private String refusal(Path modules, String profile) {
        return assertThrows(Refusal.class, () -> StagedManifest.check(modules, profile)).getMessage();
    }

    @Test
    void aMatchingStageIsAcceptedInNameOrder() throws Exception {
        Path modules = Fixtures.stage(dir);
        Files.writeString(modules.resolve("MANIFEST"), Files.readString(modules.resolve("MANIFEST")) + "\n[libs]\n");
        StagedManifest.Staged s = StagedManifest.check(modules, "production");
        assertEquals(List.of(modules.resolve("oidf.jar"), modules.resolve("ssf-0.5.0-SNAPSHOT.jar")), s.jars());
        assertTrue(s.header().startsWith("MANIFEST/2 profile=production "));
    }

    @Test
    void noManifest() throws IOException {
        Path modules = Files.createDirectories(dir.resolve("modules"));
        assertTrue(refusal(modules, "production").contains("has no MANIFEST - it was not produced by build/pingfederate/stage-modules.sh."));
    }

    @Test
    void aV1OrEmptyManifest() throws IOException {
        Path modules = Fixtures.stage(dir);
        Files.writeString(modules.resolve("MANIFEST"), "oidf.jar\nssf-0.5.0-SNAPSHOT.jar\n");
        assertTrue(refusal(modules, "production").contains("is not a v2 MANIFEST (its first line is 'oidf.jar')."));
        Files.writeString(modules.resolve("MANIFEST"), "");
        assertTrue(refusal(modules, "production").contains("is not a v2 MANIFEST (its first line is '')."));
    }

    @Test
    void theOtherProfile() throws IOException {
        Path modules = Fixtures.stage(dir);
        assertEquals("ERROR: modules/ was staged for the production profile, and this image is being built for conformance.\n"
                + "       Re-run build/pingfederate/stage-modules.sh --profile conformance, or build for production.",
                refusal(modules, "conformance"));
    }

    @Test
    void aJarWithAnotherDigest() throws IOException {
        Path modules = Fixtures.stage(dir);
        Files.write(modules.resolve("oidf.jar"), new byte[] {1}, java.nio.file.StandardOpenOption.APPEND);
        assertTrue(refusal(modules, "production").startsWith("ERROR: oidf.jar is not the jar that was staged: MANIFEST says sha256 "));
    }

    @Test
    void aMissingJar() throws IOException {
        Path modules = Fixtures.stage(dir);
        Files.delete(modules.resolve("ssf-0.5.0-SNAPSHOT.jar"));
        assertTrue(refusal(modules, "production").startsWith(
                "ERROR: staged modules/ is incomplete - MANIFEST names jars that are not present: ssf-0.5.0-SNAPSHOT.jar\n"));
    }

    @Test
    void aStrayJar() throws IOException {
        Path modules = Fixtures.stage(dir);
        Files.write(modules.resolve("stray.jar"), new byte[0]);
        assertTrue(refusal(modules, "production").startsWith("ERROR: stray.jar is in modules/ but not in MANIFEST - a stale or hand-added jar."));
    }

    @Test
    void aLineThatIsNeitherASectionNorAJar() throws IOException {
        Path modules = Fixtures.stage(dir);
        Files.writeString(modules.resolve("MANIFEST"), Files.readString(modules.resolve("MANIFEST")) + "[libs\n");
        assertTrue(refusal(modules, "production").endsWith("has a line that is neither a section nor a jar: '[libs'"));
    }

    @Test
    void aManifestNamingNoJar() throws IOException {
        Path modules = Fixtures.stage(dir, "production", Map.of());
        assertTrue(refusal(modules, "production").endsWith("names no jar.\n"
                + "       Re-run build/pingfederate/stage-modules.sh --profile production after 'mvn package'."));
    }

    @Test
    void theDigestIsSha256sumsHex() throws IOException {
        Path f = dir.resolve("f");
        Files.writeString(f, "abc");
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", StagedManifest.sha256(f));
    }

    @Test
    void jarsAreReadFromTheirBytes() throws Refusal {
        byte[] jakarta = Fixtures.zip(Map.of("README", new byte[0], "a/B.class", Fixtures.classBytes("jakarta")));
        assertTrue(Jars.references(jakarta, "jakarta/servlet/", "a.jar"));
        assertFalse(Jars.references(jakarta, "javax/servlet/", "a.jar"));
        byte[] noise = new byte[10_000];
        new java.util.Random(7).nextBytes(noise);
        byte[] truncated = Arrays.copyOf(Fixtures.zip(Map.of("a/Big.class", noise)), 1_000);
        assertTrue(assertThrows(Refusal.class, () -> Jars.references(truncated, "javax/servlet/", "t.jar")).getMessage()
                .startsWith("ERROR: t.jar is not a readable jar: "));
        assertTrue(Jars.contains("abc".getBytes(StandardCharsets.US_ASCII), "bc".getBytes(StandardCharsets.US_ASCII)));
        assertFalse(Jars.contains("ab".getBytes(StandardCharsets.US_ASCII), "abc".getBytes(StandardCharsets.US_ASCII)));
    }
}
