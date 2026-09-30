package com.pingidentity.ps.oidf.warassembler;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The MANIFEST v2 that build/pingfederate/stage-modules.sh writes beside the jars it stages: a header naming
 * the format, the profile, the build time and the commit; a [section] per module group; one
 * "&lt;sha256&gt;  &lt;file&gt;" line per jar. A directory is accepted only when it matches its MANIFEST
 * exactly - every jar present with the digest it was staged with, no other jar - and was staged for the
 * profile the image is being built for.
 */
final class StagedManifest {
    private static final Pattern HEADER =
            Pattern.compile("MANIFEST/2 profile=(production|conformance) built=[^ ]+ commit=[^ ]+");
    private static final Pattern ENTRY = Pattern.compile("([0-9a-f]{64})  ([^/ ]+\\.jar)");

    /** The header line of an accepted MANIFEST, and the jars it names, in name order. */
    record Staged(String header, List<Path> jars) {
    }

    private StagedManifest() {
    }

    static Staged check(Path modules, String profile) throws Refusal, IOException {
        Path manifest = modules.resolve("MANIFEST");
        String rerun = "       Re-run build/pingfederate/stage-modules.sh --profile " + profile + " after 'mvn package'.";
        if (!Files.isRegularFile(manifest)) {
            throw new Refusal("ERROR: " + modules + " has no MANIFEST - it was not produced by build/pingfederate/stage-modules.sh.\n"
                    + "       Run 'mvn -q -DskipTests package && build/pingfederate/stage-modules.sh --profile " + profile + "'.\n"
                    + "       Hand-copying jars here is how modules have gone missing before.");
        }
        List<String> lines = Files.readAllLines(manifest, StandardCharsets.UTF_8);
        String header = lines.isEmpty() ? "" : lines.get(0);
        Matcher h = HEADER.matcher(header);
        if (!h.matches()) {
            throw new Refusal("ERROR: " + manifest + " is not a v2 MANIFEST (its first line is '" + header + "').\n"
                    + "       Re-run build/pingfederate/stage-modules.sh --profile " + profile + " after 'mvn package'.");
        }
        String staged = h.group(1);
        if (!staged.equals(profile)) {
            throw new Refusal("ERROR: modules/ was staged for the " + staged + " profile, and this image is being built for "
                    + profile + ".\n       Re-run build/pingfederate/stage-modules.sh --profile " + profile
                    + ", or build for " + staged + ".");
        }
        Set<String> listed = new TreeSet<>();
        List<String> missing = new ArrayList<>();
        for (String line : lines) {
            if (line.isEmpty() || line.startsWith("MANIFEST/2 ") || (line.startsWith("[") && line.endsWith("]"))) {
                continue;
            }
            Matcher m = ENTRY.matcher(line);
            if (!m.matches()) {
                throw new Refusal("ERROR: " + manifest + " has a line that is neither a section nor a jar: '" + line + "'");
            }
            String want = m.group(2);
            listed.add(want);
            Path jar = modules.resolve(want);
            if (!Files.isRegularFile(jar)) {
                missing.add(want);
                continue;
            }
            String have = sha256(jar);
            if (!have.equals(m.group(1))) {
                throw new Refusal("ERROR: " + want + " is not the jar that was staged: MANIFEST says sha256 " + m.group(1)
                        + ", the file is " + have + ".\n" + rerun);
            }
        }
        if (!missing.isEmpty()) {
            throw new Refusal("ERROR: staged modules/ is incomplete - MANIFEST names jars that are not present: "
                    + String.join(" ", missing) + "\n" + rerun);
        }
        try (DirectoryStream<Path> present = Files.newDirectoryStream(modules, "*.jar")) {
            for (Path p : present) {
                if (!listed.contains(p.getFileName().toString())) {
                    throw new Refusal("ERROR: " + p.getFileName() + " is in modules/ but not in MANIFEST - a stale or hand-added jar.\n"
                            + "       Re-run build/pingfederate/stage-modules.sh --profile " + profile
                            + " so the directory matches the build.");
                }
            }
        }
        if (listed.isEmpty()) {
            throw new Refusal("ERROR: " + manifest + " names no jar.\n" + rerun);
        }
        List<Path> jars = new ArrayList<>();
        for (String name : listed) {
            jars.add(modules.resolve(name));
        }
        return new Staged(header, jars);
    }

    static String sha256(Path file) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("every Java platform has SHA-256", e);
        }
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buffer = new byte[8192];
            for (int n; (n = in.read(buffer)) > 0; ) {
                digest.update(buffer, 0, n);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }
}
