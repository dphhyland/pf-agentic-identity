package com.pingidentity.ps.oidf.warassembler;

import static com.pingidentity.ps.oidf.warassembler.Fixtures.run;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.PrintStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The command line end to end: what is written, what is refused, and that a refusal leaves no war. */
class AssemblerTest {
    @TempDir
    Path dir;

    private String filters() {
        return Fixtures.shippedFilters().toString();
    }

    private Path stockLike(String fixture) throws IOException {
        return Fixtures.war(dir, Fixtures.resource("fixtures/" + fixture));
    }

    /** OUT_WAR already exists with other content, so a refusal is seen to delete it, as the script's trap did. */
    private Path existingOut() throws IOException {
        Path out = dir.resolve("out.war");
        Files.writeString(out, "an older war");
        return out;
    }

    @Test
    void assemblesTheStockLikeWarWithTheSevenFiltersAppendedAsTheShellScriptDid() throws IOException {
        Path out = existingOut();
        Fixtures.Run r = run("--filters", filters(), stockLike("stock-like-web.xml").toString(),
                Fixtures.stage(dir).toString(), "-", out.toString());
        assertEquals(0, r.exit(), r.err());
        String stock = Fixtures.text("fixtures/stock-like-web.xml");
        String merged = Fixtures.webXml(out);
        int end = stock.lastIndexOf("</web-app>");
        assertEquals(stock.substring(0, end) + Fixtures.text("golden/shell-assembler-additions.txt") + stock.substring(end),
                merged, "PingFederate's text untouched, and the block inserted before </web-app> is the shell script's");
        assertNotNull(Fixtures.entry(out, "WEB-INF/lib/oidf.jar"));
        assertNotNull(Fixtures.entry(out, "WEB-INF/lib/ssf-0.5.0-SNAPSHOT.jar"));
        assertNotNull(Fixtures.entry(out, "META-INF/MANIFEST.MF"));
        assertTrue(r.out().contains("modules/: 2 jars, matching MANIFEST (MANIFEST/2 profile=production"), r.out());
        assertTrue(r.out().contains("namespace: jakarta.servlet (per the stock war); no staged jar references javax.servlet"));
        assertTrue(r.out().contains("web.xml: registered Fapi2Profile over /as/par.oauth2, /as/token.oauth2"));
        assertTrue(r.out().contains("chain /as/token.oauth2 (protocol): requestTracing > Fapi2Profile > OAuthErrorDescription"
                + " > OidfAutoRegistration > ClientAttestationAuth > responseCaching"), r.out());
        assertTrue(r.out().contains("4 order rules hold; no listener declared"), r.out());
        assertEquals("", r.err());
        try (var files = Files.list(dir)) {
            assertTrue(files.noneMatch(p -> p.getFileName().toString().endsWith(".tmp")), "no temporary file left");
        }
    }

    @Test
    void runningOnItsOwnOutputChangesNothing() throws IOException {
        Path modules = Fixtures.stage(dir);
        Path first = dir.resolve("first.war");
        Path second = dir.resolve("second.war");
        assertEquals(0, run("--filters", filters(), stockLike("stock-like-web.xml").toString(), modules.toString(), "-",
                first.toString()).exit());
        Fixtures.Run again = run("--filters", filters(), first.toString(), modules.toString(), "-", second.toString());
        assertEquals(0, again.exit(), again.err());
        assertArrayEquals(Files.readAllBytes(first), Files.readAllBytes(second), "the war, byte for byte");
        assertTrue(again.out().contains("web.xml: ClientAttestationAuth already registered as declared - leaving as is"));
        assertFalse(again.out().contains("web.xml: registered"));
    }

    @Test
    void theConformanceProfileAssemblesAStageMadeForIt() throws IOException {
        Path out = dir.resolve("out.war");
        Fixtures.Run r = run("--filters", filters(), stockLike("stock-like-web.xml").toString(),
                Fixtures.stage(dir, "conformance", Fixtures.moduleJars("jakarta")).toString(), "-", out.toString(), "conformance");
        assertEquals(0, r.exit(), r.err());
        assertTrue(Files.exists(out));
    }

    @Test
    void aDuplicateMappingIsRefused() throws IOException {
        Path out = existingOut();
        Fixtures.Run r = run("--filters", filters(), stockLike("duplicate-mapping-web.xml").toString(),
                Fixtures.stage(dir).toString(), "-", out.toString());
        assertEquals(1, r.exit());
        assertTrue(r.err().contains("already registers OidfAutoRegistration, but not as filters.xml declares it: it has 2"
                + " <filter-mapping> elements for OidfAutoRegistration, and must have exactly one"), r.err());
        assertFalse(Files.exists(out), "a refusal leaves no war");
    }

    @Test
    void aPathTheStockDescriptorDoesNotServeIsRefused() throws IOException {
        Path out = existingOut();
        Fixtures.Run r = run("--filters", filters(), stockLike("missing-path-web.xml").toString(),
                Fixtures.stage(dir).toString(), "-", out.toString());
        assertEquals(1, r.exit());
        assertTrue(r.err().contains("paths no <servlet-mapping> in stock.war WEB-INF/web.xml serves: Fapi2Profile over"
                + " /as/bc-auth.ciba; OAuthErrorDescription over /as/bc-auth.ciba."), r.err());
        assertFalse(Files.exists(out));
    }

    @Test
    void aWrongOrderIsRefused() throws IOException {
        Path out = existingOut();
        Fixtures.Run r = run("--filters", filters(), stockLike("wrong-order-web.xml").toString(),
                Fixtures.stage(dir).toString(), "-", out.toString());
        assertEquals(1, r.exit());
        assertTrue(r.err().contains("filter order wrong in out.war WEB-INF/web.xml - OidfAutoRegistration (filter-mapping 10)"
                + " must be mapped before ClientAttestationAuth (filter-mapping 4): ClientAttestationAuth replaces"
                + " client_assertion"), r.err());
        assertFalse(Files.exists(out));
    }

    @Test
    void metadataCompleteIsRefused() throws IOException {
        Path out = existingOut();
        Fixtures.Run r = run("--filters", filters(), stockLike("metadata-complete-web.xml").toString(),
                Fixtures.stage(dir).toString(), "-", out.toString());
        assertEquals(1, r.exit());
        assertTrue(r.err().contains("says metadata-complete=\"true\". The container would then scan no annotation"), r.err());
        assertFalse(Files.exists(out));
    }

    @Test
    void aJarBuiltForTheOtherNamespaceIsRefused() throws IOException {
        Map<String, byte[]> jars = new LinkedHashMap<>(Fixtures.moduleJars("jakarta"));
        jars.put("old-module.jar", Fixtures.zip(Map.of("x/Old.class", Fixtures.classBytes("javax"))));
        Path out = existingOut();
        Fixtures.Run r = run("--filters", filters(), stockLike("stock-like-web.xml").toString(),
                Fixtures.stage(dir, "production", jars).toString(), "-", out.toString());
        assertEquals(1, r.exit());
        assertTrue(r.err().contains("stock.war speaks jakarta.servlet, but these staged jars are compiled\n"
                + "       against javax.servlet: old-module.jar"), r.err());
        assertFalse(Files.exists(out));
    }

    @Test
    void aJavaxDescriptorRefusesJakartaJars() throws IOException {
        String javax = Fixtures.text("fixtures/stock-like-web.xml").replace(WebXml.JAKARTA_EE, WebXml.JAVA_EE_JCP);
        Fixtures.Run r = run("--filters", filters(), Fixtures.war(dir, javax.getBytes(StandardCharsets.UTF_8)).toString(),
                Fixtures.stage(dir).toString(), "-", dir.resolve("out.war").toString());
        assertEquals(1, r.exit());
        assertTrue(r.err().contains("speaks javax.servlet, but these staged jars are compiled\n       against jakarta.servlet: oidf.jar"
                + " ssf-0.5.0-SNAPSHOT.jar"), r.err());
    }

    @Test
    void aDeclaredListenerWhoseClassIsInNoJarIsRefused() throws IOException {
        Path declaration = withListener("example.lifecycle.AbsentListener");
        Path out = existingOut();
        Fixtures.Run r = run("--filters", declaration.toString(), stockLike("stock-like-web.xml").toString(),
                Fixtures.stage(dir).toString(), "-", out.toString());
        assertEquals(1, r.exit());
        assertTrue(r.err().contains("filters.xml declares classes no jar in the war holds: the listener"
                + " example.lifecycle.AbsentListener."), r.err());
        assertFalse(Files.exists(out));
    }

    @Test
    void aDeclaredListenerIsRegisteredOnceAndLeftAloneTheSecondTime() throws IOException {
        String listener = "com.pingidentity.ps.oidf.platform.pf.Lifecycle";
        Path declaration = withListener(listener);
        Map<String, byte[]> jars = new LinkedHashMap<>(Fixtures.moduleJars("jakarta"));
        jars.put("platform-pf.jar", Fixtures.zip(Map.of(Fixtures.classEntry(listener), Fixtures.classBytes("jakarta"))));
        Path modules = Fixtures.stage(dir, "production", jars);
        Path first = dir.resolve("first.war");
        Fixtures.Run r = run("--filters", declaration.toString(), stockLike("stock-like-web.xml").toString(),
                modules.toString(), "-", first.toString());
        assertEquals(0, r.exit(), r.err());
        assertTrue(Fixtures.webXml(first).contains("  <listener>\n    <listener-class>" + listener
                + "</listener-class>\n  </listener>\n</web-app>"));
        assertTrue(r.out().contains("1 listeners registered"), r.out());
        Fixtures.Run again = run("--filters", declaration.toString(), first.toString(), modules.toString(), "-",
                dir.resolve("second.war").toString());
        assertEquals(0, again.exit(), again.err());
        assertTrue(again.out().contains("the listener " + listener + " already registered - leaving as is"));
        assertArrayEquals(Files.readAllBytes(first), Files.readAllBytes(dir.resolve("second.war")));
    }

    @Test
    void aListenerTheStockRegistersTwiceIsRefused() throws IOException {
        String listener = "example.lifecycle.Twice";
        String twice = Fixtures.text("fixtures/stock-like-web.xml").replace("</web-app>",
                "<listener><listener-class>" + listener + "</listener-class></listener>\n"
                        + "<listener><listener-class>" + listener + "</listener-class></listener>\n</web-app>");
        Fixtures.Run r = run("--filters", withListener(listener).toString(),
                Fixtures.war(dir, twice.getBytes(StandardCharsets.UTF_8)).toString(), Fixtures.stage(dir).toString(), "-",
                dir.resolve("out.war").toString());
        assertEquals(1, r.exit());
        assertTrue(r.err().contains("registers the listener example.lifecycle.Twice 2 times; filters.xml declares it once."));
    }

    @Test
    void aFilterClassInNoJarIsRefused() throws IOException {
        Map<String, byte[]> jars = new LinkedHashMap<>(Fixtures.moduleJars("jakarta"));
        jars.remove("ssf-0.5.0-SNAPSHOT.jar");
        Fixtures.Run r = run("--filters", filters(), stockLike("stock-like-web.xml").toString(),
                Fixtures.stage(dir, "production", jars).toString(), "-", dir.resolve("out.war").toString());
        assertEquals(1, r.exit());
        assertTrue(r.err().contains("no jar in the war holds: the filter SsfLogoutSignal ("
                + Fixtures.SSF_FILTER + ")"), r.err());
    }

    @Test
    void aClassTheStockWarAlreadyCarriesCounts() throws IOException {
        // The logout filter in the stock war's WEB-INF/classes, and the pf-integration ones in a jar in its
        // WEB-INF/lib: nothing staged needs to carry them.
        Map<String, byte[]> extra = new LinkedHashMap<>();
        extra.put("WEB-INF/classes/" + Fixtures.classEntry(Fixtures.SSF_FILTER), Fixtures.classBytes("jakarta"));
        extra.put("WEB-INF/classes/readme.txt", new byte[0]);
        extra.put("WEB-INF/lib/oidf.jar", Fixtures.moduleJars("jakarta").get("oidf.jar"));
        extra.put("WEB-INF/lib/notes.txt", new byte[0]);
        Path stock = Fixtures.war(dir, "stock.war", Fixtures.resource("fixtures/stock-like-web.xml"), extra);
        Path single = dir.resolve("unrelated.jar");
        Files.write(single, Fixtures.zip(Map.of("x/Unrelated.class", Fixtures.classBytes("jakarta"))));
        Fixtures.Run r = run("--filters", filters(), stock.toString(), single.toString(), "-", dir.resolve("out.war").toString());
        assertEquals(0, r.exit(), r.err());
        assertNotNull(Fixtures.entry(dir.resolve("out.war"), "WEB-INF/lib/oidf.jar"), "the stock war's own jar kept");
        assertNotNull(Fixtures.entry(dir.resolve("out.war"), "WEB-INF/lib/" + Assembler.MODULE_NAME));
    }

    @Test
    void aSingleModuleJarGoesInUnderTheMonolithsNameAndJose4jUnderItsOwn() throws IOException {
        Map<String, byte[]> all = new LinkedHashMap<>();
        for (byte[] jar : Fixtures.moduleJars("jakarta").values()) {
            try (var in = new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(jar))) {
                for (java.util.zip.ZipEntry e; (e = in.getNextEntry()) != null; ) {
                    all.put(e.getName(), in.readAllBytes());
                }
            }
        }
        Path monolith = dir.resolve("pf-oidf-modules.jar");
        Files.write(monolith, Fixtures.zip(all));
        Path jose4j = dir.resolve("jose4j-0.9.6.jar");
        Files.write(jose4j, Fixtures.zip(Map.of("org/jose4j/Jwt.class", "plain".getBytes(StandardCharsets.US_ASCII))));
        Path out = dir.resolve("out.war");
        Fixtures.Run r = run("--filters", filters(), stockLike("stock-like-web.xml").toString(), monolith.toString(),
                jose4j.toString(), out.toString());
        assertEquals(0, r.exit(), r.err());
        assertNotNull(Fixtures.entry(out, "WEB-INF/lib/" + Assembler.MODULE_NAME));
        assertNotNull(Fixtures.entry(out, "WEB-INF/lib/jose4j-0.9.6.jar"));
    }

    @Test
    void jose4jThatIsNotAFileOrClashesIsRefused() throws IOException {
        Path modules = Fixtures.stage(dir);
        Fixtures.Run missing = run("--filters", filters(), stockLike("stock-like-web.xml").toString(), modules.toString(),
                dir.resolve("nope.jar").toString(), dir.resolve("out.war").toString());
        assertEquals(1, missing.exit());
        assertTrue(missing.err().contains("JOSE4J_JAR (" + dir.resolve("nope.jar") + ") is not a file; pass - to skip it"));
        Path clash = Files.createDirectories(dir.resolve("other")).resolve("oidf.jar");
        Files.write(clash, Fixtures.zip(Map.of("x/Y.class", Fixtures.classBytes("jakarta"))));
        Fixtures.Run twice = run("--filters", filters(), stockLike("stock-like-web.xml").toString(), modules.toString(),
                clash.toString(), dir.resolve("out.war").toString());
        assertEquals(1, twice.exit());
        assertTrue(twice.err().contains("two jars would both be WEB-INF/lib/oidf.jar."));
    }

    @Test
    void modulesThatAreNeitherADirectoryNorAJarAreRefused() throws IOException {
        Fixtures.Run r = run("--filters", filters(), stockLike("stock-like-web.xml").toString(),
                dir.resolve("absent").toString(), "-", dir.resolve("out.war").toString());
        assertEquals(1, r.exit());
        assertTrue(r.err().contains("is neither a directory staged by stage-modules.sh nor a jar."));
    }

    @Test
    void aStagedFileThatIsNotAJarIsRefused() throws IOException {
        Map<String, byte[]> jars = new LinkedHashMap<>(Fixtures.moduleJars("jakarta"));
        jars.put("broken.jar", "not a zip".getBytes(StandardCharsets.US_ASCII));
        Fixtures.Run r = run("--filters", filters(), stockLike("stock-like-web.xml").toString(),
                Fixtures.stage(dir, "production", jars).toString(), "-", dir.resolve("out.war").toString());
        assertEquals(1, r.exit());
        assertTrue(r.err().contains("broken.jar is not a jar (no zip entry could be read from it)."), r.err());
    }

    @Test
    void aStockWarWithNoDescriptorIsRefused() throws IOException {
        Fixtures.Run r = run("--filters", filters(), Fixtures.war(dir, null).toString(), Fixtures.stage(dir).toString(), "-",
                dir.resolve("out.war").toString());
        assertEquals(1, r.exit());
        assertTrue(r.err().contains("has no WEB-INF/web.xml - it is not PingFederate's pf-runtime.war."));
    }

    @Test
    void aDescriptorInAnUnknownNamespaceOrNotAWebAppIsRefused() throws IOException {
        String other = Fixtures.text("fixtures/stock-like-web.xml").replace(WebXml.JAKARTA_EE, "urn:example:web");
        Fixtures.Run r = run("--filters", filters(), Fixtures.war(dir, other.getBytes(StandardCharsets.UTF_8)).toString(),
                Fixtures.stage(dir).toString(), "-", dir.resolve("out.war").toString());
        assertEquals(1, r.exit());
        assertTrue(r.err().contains("is in the namespace 'urn:example:web', which is neither Jakarta EE's nor Java EE's"));

        Fixtures.Run notWebApp = run("--filters", filters(),
                Fixtures.war(dir, "<application/>".getBytes(StandardCharsets.UTF_8)).toString(), Fixtures.stage(dir).toString(),
                "-", dir.resolve("out.war").toString());
        assertEquals(1, notWebApp.exit());
        assertTrue(notWebApp.err().contains("is not a deployment descriptor: its root element is <application>"));
    }

    @Test
    void usageErrorsExitTwoAndTouchNothing() throws IOException {
        Path out = existingOut();
        assertEquals(2, run().exit());
        assertEquals(2, run("--filters", filters(), "a", "b", "c").exit());
        assertEquals(2, run("a", "b", "c", "d", "e", "f").exit());
        assertEquals(2, run("--filters", filters(), "a", "b", "c", "d", "production", "extra").exit());
        Fixtures.Run badProfile = run("--filters", filters(), "a", "b", "-", out.toString(), "staging");
        assertEquals(2, badProfile.exit());
        assertEquals("ERROR: the profile must be production or conformance, not 'staging'\n", badProfile.err());
        assertTrue(Files.exists(out), "a usage error deletes nothing, as the script's profile check did not");
        Path stock = stockLike("stock-like-web.xml");
        Fixtures.Run same = run("--filters", filters(), stock.toString(), Fixtures.stage(dir).toString(), "-", stock.toString());
        assertEquals(2, same.exit());
        assertTrue(same.err().contains("STOCK_WAR and OUT_WAR are the same file"));
        assertTrue(Files.exists(stock));
    }

    @Test
    void aStockWarThatDoesNotExistIsRefusedAndTheOutputRemoved() throws IOException {
        Path out = existingOut();
        Fixtures.Run r = run("--filters", filters(), dir.resolve("absent.war").toString(), Fixtures.stage(dir).toString(),
                "-", out.toString());
        assertEquals(1, r.exit());
        assertTrue(r.err().startsWith("ERROR: java.nio.file.NoSuchFileException"), r.err());
        assertFalse(Files.exists(out));
    }

    @Test
    void anOutputDirectoryThatDoesNotExistIsAnError() throws IOException {
        Fixtures.Run r = run("--filters", filters(), stockLike("stock-like-web.xml").toString(), Fixtures.stage(dir).toString(),
                "-", dir.resolve("no/such/dir/out.war").toString());
        assertEquals(1, r.exit());
        assertTrue(r.err().startsWith("ERROR: java.nio.file.NoSuchFileException"), r.err());
    }

    @Test
    void verifyWarRefusesAWarMissingAStagedJarOrItsDescriptor() throws IOException, Refusal {
        Declaration d = Declaration.parse(Files.readAllBytes(Fixtures.shippedFilters()), "filters.xml");
        List<Assembler.Staged> staged = List.of(new Assembler.Staged("oidf.jar", dir.resolve("oidf.jar")));
        Path noJar = Fixtures.war(dir, "a.war", Fixtures.resource("fixtures/stock-like-web.xml"), Map.of());
        Refusal missing = assertThrows(Refusal.class, () -> Assembler.verifyWar(noJar, staged, d, "a.war"));
        assertEquals("ERROR: module jar oidf.jar not present in a.war", missing.getMessage());
        Path noXml = Fixtures.war(dir, "b.war", null, Map.of("WEB-INF/lib/oidf.jar", new byte[0]));
        Refusal noDescriptor = assertThrows(Refusal.class, () -> Assembler.verifyWar(noXml, staged, d, "b.war"));
        assertEquals("ERROR: b.war has no WEB-INF/web.xml after assembly", noDescriptor.getMessage());
    }

    @Test
    void theJarReportsItsVersionOrThatItIsUnpackaged() {
        assertEquals("(unpackaged)", Assembler.version(), "run from target/classes, there is no jar manifest");
    }

    @Test
    void noArgumentsIsAUsageError() {
        PrintStream quiet = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
        assertEquals(2, Assembler.run(new String[0], quiet, quiet));
    }

    private Path withListener(String listener) throws IOException {
        String declaration = Files.readString(Fixtures.shippedFilters())
                .replace("</war-filters>", "  <listener class=\"" + listener + "\"/>\n</war-filters>");
        Path p = dir.resolve("filters-with-listener.xml");
        Files.writeString(p, declaration);
        return p;
    }
}
