package com.pingidentity.ps.oidf.platform.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/**
 * A certificate authority made by {@code keytool} for one test run, and server keys it signed: one for
 * {@code pinned.test} (and the address 127.0.0.1), one for {@code other.test}, and a self-signed
 * {@code pinned.test} no CA vouches for. Nothing here is written anywhere but a temporary directory.
 */
final class TestPki {
    static final String PASSWORD = "changeit";
    private static TestPki instance;

    final Path dir;
    final Path caPem;
    final X509Certificate ca;

    private TestPki() throws Exception {
        this.dir = Files.createTempDirectory("s5a-pki");
        this.dir.toFile().deleteOnExit();
        keytool("-genkeypair", "-alias", "ca", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=S5A test CA",
                "-ext", "bc:c=ca:true", "-validity", "2", "-keystore", store("ca"), "-storetype", "PKCS12",
                "-storepass", PASSWORD, "-keypass", PASSWORD);
        this.caPem = this.dir.resolve("ca.pem");
        keytool("-exportcert", "-rfc", "-alias", "ca", "-keystore", store("ca"), "-storetype", "PKCS12",
                "-storepass", PASSWORD, "-file", this.caPem.toString());
        try (InputStream in = Files.newInputStream(this.caPem)) {
            this.ca = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
        leaf("pinned", "pinned.test", "SAN=dns:pinned.test,ip:127.0.0.1");
        leaf("other", "other.test", "SAN=dns:other.test");
        keytool("-genkeypair", "-alias", "leaf", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=pinned.test",
                "-ext", "SAN=dns:pinned.test", "-validity", "2", "-keystore", store("selfsigned"), "-storetype", "PKCS12",
                "-storepass", PASSWORD, "-keypass", PASSWORD);
    }

    static synchronized TestPki get() throws Exception {
        if (instance == null) {
            instance = new TestPki();
        }
        return instance;
    }

    /** A server context holding the key of {@code name}: pinned, other or selfsigned. */
    SSLContext server(String name) throws Exception {
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(Path.of(store(name)))) {
            keys.load(in, PASSWORD.toCharArray());
        }
        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keys, PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(factory.getKeyManagers(), null, null);
        return context;
    }

    /** The client's trust: this CA and nothing else. */
    TlsTrust trust() throws Exception {
        return TlsTrust.caCertificates(List.of(this.ca));
    }

    private void leaf(String name, String cn, String san) throws Exception {
        String csr = this.dir.resolve(name + ".csr").toString();
        String pem = this.dir.resolve(name + ".pem").toString();
        keytool("-genkeypair", "-alias", "leaf", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=" + cn,
                "-validity", "2", "-keystore", store(name), "-storetype", "PKCS12", "-storepass", PASSWORD,
                "-keypass", PASSWORD);
        keytool("-certreq", "-alias", "leaf", "-keystore", store(name), "-storetype", "PKCS12", "-storepass", PASSWORD,
                "-file", csr);
        keytool("-gencert", "-alias", "ca", "-keystore", store("ca"), "-storetype", "PKCS12", "-storepass", PASSWORD,
                "-infile", csr, "-outfile", pem, "-rfc", "-ext", san, "-validity", "2");
        keytool("-importcert", "-noprompt", "-alias", "ca", "-file", this.caPem.toString(), "-keystore", store(name),
                "-storetype", "PKCS12", "-storepass", PASSWORD);
        keytool("-importcert", "-noprompt", "-alias", "leaf", "-file", pem, "-keystore", store(name), "-storetype",
                "PKCS12", "-storepass", PASSWORD);
    }

    private String store(String name) {
        return this.dir.resolve(name + ".p12").toString();
    }

    private static void keytool(String... args) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
        command.addAll(List.of(args));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        process.getInputStream().transferTo(output);
        if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IOException("keytool " + args[0] + " failed: " + output.toString(StandardCharsets.UTF_8));
        }
    }
}
