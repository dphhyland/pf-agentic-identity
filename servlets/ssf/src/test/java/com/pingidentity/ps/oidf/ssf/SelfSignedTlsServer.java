/*
 * An HTTPS server on localhost with a self-signed certificate for one name, for the insecure-TLS site test.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.platform.tls.InsecureTls;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/**
 * The certificate is made by {@code keytool} for this run (no key is committed) and names only {@code dnsName};
 * the server is reached as {@code localhost}, so {@code wrong.example} is a certificate for the wrong name. Every
 * request gets {@code status} and {@code body} as JSON. The same fixture as platform's InsecureTlsTest uses.
 */
final class SelfSignedTlsServer implements AutoCloseable {
    private final HttpsServer server;

    SelfSignedTlsServer(Path dir, String dnsName, int status, String body) throws Exception {
        Path keystore = dir.resolve(dnsName + "-" + System.nanoTime() + ".p12");
        String storePass = "changeit-" + System.nanoTime();
        keytool("-genkeypair", "-alias", "server", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=" + dnsName,
                "-ext", "SAN=dns:" + dnsName, "-validity", "2", "-keystore", keystore.toString(), "-storetype", "PKCS12",
                "-storepass", storePass, "-keypass", storePass);
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            keys.load(in, storePass.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keys, storePass.toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), null, null);
        this.server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        this.server.setHttpsConfigurator(new HttpsConfigurator(context));
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        this.server.createContext("/", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        this.server.start();
    }

    /** {@code https://localhost:<port>} followed by {@code path}. */
    String url(String path) {
        return "https://localhost:" + this.server.getAddress().getPort() + path;
    }

    @Override
    public void close() {
        this.server.stop(0);
    }

    private static void keytool(String... args) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
        Collections.addAll(command, args);
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IllegalStateException("keytool failed: " + output);
        }
    }

    /** Whether a failure is the host name check: the JDK names the host it dialled in the handshake failure. */
    static boolean isWrongName(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof javax.net.ssl.SSLHandshakeException && String.valueOf(t.getMessage()).contains("localhost")) {
                return true;
            }
            if (String.valueOf(t.getMessage()).contains("No subject alternative DNS name matching localhost")) {
                return true;
            }
        }
        return false;
    }

    /**
     * The settings platform's InsecureTls records while {@code build} runs, starting from an empty record, so a
     * site that records its use under another setting's name fails its test. InsecureTls's reset is
     * package-private, so this reaches it by reflection.
     */
    static Set<String> settingsRecordedBy(Callable<?> build) throws Exception {
        Method reset = InsecureTls.class.getDeclaredMethod("reset");
        reset.setAccessible(true);
        reset.invoke(null);
        build.call();
        Set<String> settings = new TreeSet<>();
        for (InsecureTls.Use use : InsecureTls.uses()) {
            settings.add(use.setting());
        }
        return settings;
    }
}
