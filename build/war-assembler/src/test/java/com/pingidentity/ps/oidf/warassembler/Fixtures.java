package com.pingidentity.ps.oidf.warassembler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Wars, jars and staged directories built for the tests, from nothing PingFederate ships. */
final class Fixtures {
    static final String PFI = "com.pingidentity.ps.oidf.servlet.";
    static final String[] PF_INTEGRATION_FILTERS = {
        PFI + "fapi2.Fapi2ProfileFilter",
        PFI + "fapi1.FapiResourceServerFilter",
        PFI + "oauth.OAuthErrorDescriptionFilter",
        PFI + "clientregistration.FrontChannelAutoRegistrationFilter",
        PFI + "clientregistration.TokenEndpointAutoRegistrationFilter",
        PFI + "clientregistration.IssuedDetailsBelt",
        PFI + "clientregistration.ClientAttestationAuthFilter",
        PFI + "oauth.AttestationMetadataFilter",
    };
    static final String SSF_FILTER = PFI + "ssf.LogoutEventFilter";
    /** The listener filters.xml declares (plan item F-2), in platform-pf's jar. */
    static final String LIFECYCLE_LISTENER = "com.pingidentity.ps.oidf.platform.pf.lifecycle.LifecycleListener";
    /** What the assembler inserts for it, after the filters. */
    static final String LIFECYCLE_LISTENER_BLOCK = "  <listener>\n    <listener-class>" + LIFECYCLE_LISTENER
            + "</listener-class>\n  </listener>\n";
    /** ClientAttestationAuth's mapping as the shell assembler wrote it (golden/shell-assembler-additions.txt): token and PAR. */
    static final String CLIENT_ATTESTATION_MAPPING_SHELL = "  <filter-mapping>\n    <filter-name>ClientAttestationAuth</filter-name>\n"
            + "    <url-pattern>/as/token.oauth2</url-pattern>\n    <url-pattern>/as/par.oauth2</url-pattern>\n  </filter-mapping>\n";
    /**
     * ClientAttestationAuth's mapping as the shipped filters.xml declares it since plan item S4d (2026-09-30): every PF
     * endpoint that authenticates a client, and the authorization endpoint. The golden comparisons swap it for the
     * shell's and compare the rest, as they take F-2's listener out.
     */
    static final String CLIENT_ATTESTATION_MAPPING = "  <filter-mapping>\n    <filter-name>ClientAttestationAuth</filter-name>\n"
            + "    <url-pattern>/as/token.oauth2</url-pattern>\n    <url-pattern>/as/par.oauth2</url-pattern>\n"
            + "    <url-pattern>/as/bc-auth.ciba</url-pattern>\n    <url-pattern>/as/device_authz.oauth2</url-pattern>\n"
            + "    <url-pattern>/as/introspect.oauth2</url-pattern>\n    <url-pattern>/as/revoke_token.oauth2</url-pattern>\n"
            + "    <url-pattern>/as/authorization.oauth2</url-pattern>\n  </filter-mapping>\n";
    /**
     * The response belt's filter and mapping as the assembler writes them (plan item S4d, S4D3, 2026-09-30): inserted just
     * before ClientAttestationAuth's filter, which the golden comparisons do to the shell's additions.
     */
    static final String ISSUED_DETAILS_BELT_BLOCK = "  <filter>\n    <filter-name>IssuedDetailsBelt</filter-name>\n"
            + "    <filter-class>" + PFI + "clientregistration.IssuedDetailsBelt</filter-class>\n  </filter>\n"
            + "  <filter-mapping>\n    <filter-name>IssuedDetailsBelt</filter-name>\n"
            + "    <url-pattern>/as/token.oauth2</url-pattern>\n  </filter-mapping>\n";
    /**
     * The attestation metadata filter and its mapping as the assembler writes them (plan item S-4, S4M, 2026-10-01): the
     * last filter declared, so after ClientAttestationAuth's mapping and before F-2's listener.
     */
    static final String ATTESTATION_METADATA_BLOCK = "  <filter>\n    <filter-name>AttestationMetadata</filter-name>\n"
            + "    <filter-class>" + PFI + "oauth.AttestationMetadataFilter</filter-class>\n  </filter>\n"
            + "  <filter-mapping>\n    <filter-name>AttestationMetadata</filter-name>\n"
            + "    <url-pattern>/.well-known/openid-configuration</url-pattern>\n"
            + "    <url-pattern>/.well-known/oauth-authorization-server</url-pattern>\n  </filter-mapping>\n";
    /** Where ClientAttestationAuth's filter starts in the shell's additions: the belt goes in before it. */
    static final String CLIENT_ATTESTATION_FILTER_START = "  <filter>\n    <filter-name>ClientAttestationAuth</filter-name>\n";
    static final long TIME = 1_790_000_000_000L;

    record Run(int exit, String out, String err) {
    }

    private Fixtures() {
    }

    static byte[] resource(String path) {
        try (InputStream in = Fixtures.class.getResourceAsStream("/" + path)) {
            if (in == null) {
                throw new IllegalArgumentException("no test resource " + path);
            }
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static String text(String path) {
        return new String(resource(path), StandardCharsets.UTF_8);
    }

    /** The declaration the image build uses: build/pingfederate/filters.xml. */
    static Path shippedFilters() {
        return Path.of(System.getProperty("warAssembler.filtersXml", "../pingfederate/filters.xml"));
    }

    /** A fake class file: enough bytes to carry a constant-pool reference into a servlet namespace. */
    static byte[] classBytes(String namespace) {
        return ("Êþº¾" + namespace + "/servlet/Filter").getBytes(StandardCharsets.ISO_8859_1);
    }

    static String classEntry(String className) {
        return className.replace('.', '/') + ".class";
    }

    static byte[] zip(Map<String, byte[]> entries) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            for (var e : entries.entrySet()) {
                ZipEntry entry = new ZipEntry(e.getKey());
                entry.setTime(TIME);
                if (e.getKey().endsWith("/")) {
                    entry.setMethod(ZipEntry.STORED);
                    entry.setSize(0);
                    entry.setCompressedSize(0);
                    entry.setCrc(new CRC32().getValue());
                }
                zip.putNextEntry(entry);
                zip.write(e.getValue());
                zip.closeEntry();
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return bytes.toByteArray();
    }

    /** A war shaped like the stock one: a manifest, WEB-INF/ and WEB-INF/web.xml, plus any extra entries. */
    static Path war(Path dir, String name, byte[] webXml, Map<String, byte[]> extra) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("META-INF/", new byte[0]);
        entries.put("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        entries.put("WEB-INF/", new byte[0]);
        if (webXml != null) {
            entries.put("WEB-INF/web.xml", webXml);
        }
        entries.putAll(extra);
        Path war = dir.resolve(name);
        Files.write(war, zip(entries));
        return war;
    }

    static Path war(Path dir, byte[] webXml) throws IOException {
        return war(dir, "stock.war", webXml, Map.of());
    }

    /** The module jars: oidf.jar with the six pf-integration filters, ssf with the logout filter, platform-pf with the listener. */
    static Map<String, byte[]> moduleJars(String namespace) {
        Map<String, byte[]> oidf = new LinkedHashMap<>();
        for (String c : PF_INTEGRATION_FILTERS) {
            oidf.put(classEntry(c), classBytes(namespace));
        }
        Map<String, byte[]> jars = new LinkedHashMap<>();
        jars.put("oidf.jar", zip(oidf));
        jars.put("ssf-0.5.0-SNAPSHOT.jar", zip(Map.of(classEntry(SSF_FILTER), classBytes(namespace))));
        jars.put("platform-pf-0.5.0-SNAPSHOT.jar", zip(Map.of(classEntry(LIFECYCLE_LISTENER), classBytes(namespace))));
        return jars;
    }

    /** A directory as stage-modules.sh leaves it: the jars and a MANIFEST v2 naming each with its digest. */
    static Path stage(Path dir, String profile, Map<String, byte[]> jars) throws IOException {
        Path modules = Files.createDirectories(dir.resolve("modules"));
        StringBuilder manifest = new StringBuilder("MANIFEST/2 profile=" + profile + " built=2026-09-28T00:00:00Z commit=abc123\n[servlets]\n");
        for (var e : jars.entrySet()) {
            Path jar = modules.resolve(e.getKey());
            Files.write(jar, e.getValue());
            Files.setLastModifiedTime(jar, java.nio.file.attribute.FileTime.fromMillis(TIME));
            manifest.append(StagedManifest.sha256(jar)).append("  ").append(e.getKey()).append('\n');
        }
        Files.writeString(modules.resolve("MANIFEST"), manifest.toString());
        return modules;
    }

    static Path stage(Path dir) throws IOException {
        return stage(dir, "production", moduleJars("jakarta"));
    }

    static Run run(String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int exit = Assembler.run(args, new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
        return new Run(exit, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }

    /** One entry of a war or jar, or null. */
    static byte[] entry(Path zip, String name) throws IOException {
        try (var in = new java.util.zip.ZipInputStream(Files.newInputStream(zip))) {
            for (ZipEntry e; (e = in.getNextEntry()) != null; ) {
                if (e.getName().equals(name)) {
                    return in.readAllBytes();
                }
            }
        }
        return null;
    }

    static String webXml(Path war) throws IOException {
        byte[] b = entry(war, "WEB-INF/web.xml");
        return b == null ? null : new String(b, StandardCharsets.UTF_8);
    }
}
