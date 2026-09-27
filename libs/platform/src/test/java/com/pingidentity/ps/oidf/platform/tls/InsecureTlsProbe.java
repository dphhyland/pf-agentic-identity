/*
 * One GET, run in a JVM of its own so the JDK reads the hostname property fresh.
 */
package com.pingidentity.ps.oidf.platform.tls;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * {@code InsecureTlsProbe <url> <trust-all true|false>}: prints the status of a GET, or the root cause of its failure.
 * The JDK reads {@code jdk.internal.httpclient.disableHostnameVerification} once per JVM, so a test that needs it set
 * runs this in a new one.
 */
public final class InsecureTlsProbe {
    private InsecureTlsProbe() {
    }

    public static void main(String[] args) throws Exception {
        HttpClient client = InsecureTls.trustAnyCertificate(HttpClient.newBuilder(), "probe", Boolean.parseBoolean(args[1])).build();
        try {
            HttpResponse<String> response = client.send(HttpRequest.newBuilder(URI.create(args[0])).build(),
                    HttpResponse.BodyHandlers.ofString());
            System.out.println("status " + response.statusCode());
        } catch (java.io.IOException e) {
            Throwable root = e;
            while (root.getCause() != null) {
                root = root.getCause();
            }
            System.out.println("failed " + root.getClass().getName() + ": " + root.getMessage());
        }
    }
}
