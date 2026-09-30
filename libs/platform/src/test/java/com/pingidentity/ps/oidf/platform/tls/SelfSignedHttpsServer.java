/*
 * An HTTPS server on localhost whose certificate is self-signed and names only the host it is told to.
 */
package com.pingidentity.ps.oidf.platform.tls;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/**
 * The certificate is made by {@code keytool} for this run, so no key is committed. It is served on the loopback
 * address and reached as {@code localhost}: a certificate for {@code wrong.example} is one for the wrong name.
 */
final class SelfSignedHttpsServer implements AutoCloseable {
    private final HttpsServer server;

    SelfSignedHttpsServer(Path dir, String dnsName) throws Exception {
        Path keystore = dir.resolve(dnsName + ".p12");
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
        this.server.createContext("/", exchange -> {
            byte[] body = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        this.server.start();
    }

    int port() {
        return this.server.getAddress().getPort();
    }

    /** The URL a client dials: {@code https://localhost:<port>/}. */
    String url() {
        return "https://localhost:" + port() + "/";
    }

    @Override
    public void close() {
        this.server.stop(0);
    }

    static void keytool(String... args) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
        Collections.addAll(command, args);
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IllegalStateException("keytool failed: " + output);
        }
    }
}
