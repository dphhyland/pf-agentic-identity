/*
 * The versions /agentic-identity/info and the health detail report.
 */
package com.pingidentity.ps.oidf.platform.pf.health;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * What this deployment runs, read from the jars on the loader each time it is asked: this repository's version from
 * platform-pf's own {@code pom.properties} (Maven writes one into every jar it builds), PingFederate's from
 * {@code pf-commons.jar}'s - the file PingFederate's own {@code org.sourceid.common.VersionUtil} reads (checked in
 * the 13.1.3 image on 2026-09-28: {@code version=13.1.3.0}) - and the JVM's. No build of this repository records
 * the commit it was built from in what it ships (finding F-0190), so {@code commit} is null until one does.
 */
public final class BuildInfo {

    /** Where Maven puts platform-pf's own version. */
    static final String OWN_POM = "META-INF/maven/com.pingidentity.ps.oidf/platform-pf/pom.properties";
    /** Where PingFederate's pf-commons.jar carries PingFederate's version. */
    static final String PINGFEDERATE_POM = "META-INF/maven/pingfederate/pf-commons/pom.properties";

    private BuildInfo() {
    }

    /**
     * The versions as the info document shows them: {@code agentic-identity}, {@code commit}, {@code pingfederate}
     * and {@code java}. A version that cannot be read is null.
     */
    public static Map<String, Object> read(ClassLoader loader) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("agentic-identity", version(loader, OWN_POM));
        out.put("commit", null);
        out.put("pingfederate", version(loader, PINGFEDERATE_POM));
        out.put("java", Runtime.version().toString());
        return out;
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
