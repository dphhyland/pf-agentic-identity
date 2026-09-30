/*
 * The versions /agentic-identity/info and the health detail report.
 */
package com.pingidentity.ps.oidf.platform.pf.health;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.jar.Manifest;

/**
 * What this deployment runs, read from the jars on the loader each time it is asked: this repository's version from
 * platform-pf's own {@code pom.properties} (Maven writes one into every jar it builds), PingFederate's from
 * {@code pf-commons.jar}'s - the file PingFederate's own {@code org.sourceid.common.VersionUtil} reads (checked in
 * the 13.1.3 image on 2026-09-28: {@code version=13.1.3.0}) - and the JVM's. The commit is the {@value #COMMIT}
 * entry of platform-pf's own manifest, which the build writes from the Maven property {@code oidf.build.commit}:
 * CI passes {@code GITHUB_SHA}, and a build that passes nothing writes {@code unknown}, which reads as null, as a
 * manifest that cannot be read does (finding F-0190).
 */
public final class BuildInfo {

    /** Where Maven puts platform-pf's own version. */
    static final String OWN_POM = "META-INF/maven/com.pingidentity.ps.oidf/platform-pf/pom.properties";
    /** Where PingFederate's pf-commons.jar carries PingFederate's version. */
    static final String PINGFEDERATE_POM = "META-INF/maven/pingfederate/pf-commons/pom.properties";
    /** The manifest attribute platform-pf's pom writes the commit into. */
    static final String COMMIT = "Build-Commit";
    /** What the build writes when it is given no commit. */
    static final String UNKNOWN = "unknown";

    private BuildInfo() {
    }

    /**
     * The versions as the info document shows them: {@code agentic-identity}, {@code commit}, {@code pingfederate}
     * and {@code java}. A version that cannot be read is null.
     */
    public static Map<String, Object> read(ClassLoader loader) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("agentic-identity", version(loader, OWN_POM));
        out.put("commit", commit(loader));
        out.put("pingfederate", version(loader, PINGFEDERATE_POM));
        out.put("java", Runtime.version().toString());
        return out;
    }

    /**
     * The {@value #COMMIT} of the jar platform-pf's own {@code pom.properties} is in - found through that file, so it
     * is this jar's manifest and not whichever {@code META-INF/MANIFEST.MF} the loader finds first - or null when
     * there is none to read or it says {@value #UNKNOWN}.
     */
    static String commit(ClassLoader loader) {
        URL pom = loader == null ? null : loader.getResource(OWN_POM);
        if (pom == null) {
            return null;
        }
        String where = pom.toString();
        try {
            URLConnection connection = URI.create(where.substring(0, where.length() - OWN_POM.length()) + "META-INF/MANIFEST.MF")
                    .toURL().openConnection();
            connection.setUseCaches(false);
            try (InputStream in = connection.getInputStream()) {
                String commit = new Manifest(in).getMainAttributes().getValue(COMMIT);
                return commit == null || commit.isBlank() || UNKNOWN.equals(commit.strip()) ? null : commit.strip();
            }
        } catch (IOException | IllegalArgumentException e) {
            return null;
        }
    }

    /** The {@code version} in the {@code pom.properties} at {@code path}, or null when there is none to read. */
    static String version(ClassLoader loader, String path) {
        URL url = loader == null ? null : loader.getResource(path);
        if (url == null) {
            return null;
        }
        try {
            URLConnection connection = url.openConnection();
            // Not through the JDK's jar cache, so reading it does not hold a webapp's jar open after an undeploy.
            connection.setUseCaches(false);
            Properties properties = new Properties();
            try (InputStream in = connection.getInputStream()) {
                properties.load(in);
            }
            String version = properties.getProperty("version");
            return version == null || version.isBlank() ? null : version.strip();
        } catch (IOException | IllegalArgumentException e) {
            return null;
        }
    }
}
