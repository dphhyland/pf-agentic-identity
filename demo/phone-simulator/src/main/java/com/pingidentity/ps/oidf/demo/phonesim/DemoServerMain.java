/*
 * Main.java's own wiring, with one substitution: a shared synthetic App Attest trust root instead of
 * Apple's, since nothing but real hardware can produce a chain to Apple's real root.
 */
package com.pingidentity.ps.oidf.demo.phonesim;

import com.pingidentity.ps.oidf.appattest.AppAttestConfig;
import com.pingidentity.ps.oidf.appattest.AppAttestEnvironment;
import com.pingidentity.ps.oidf.appattest.AppAttestFixtures;
import com.pingidentity.ps.oidf.appattest.AppAttestVerifier;
import com.pingidentity.ps.oidf.common.InMemoryAttestationChallengeService;
import com.pingidentity.ps.oidf.common.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.common.JwsSigner;
import com.pingidentity.ps.oidf.common.LocalJwkSigner;
import com.pingidentity.ps.oidf.device.DeviceAttestationMinter;
import com.pingidentity.ps.oidf.device.InstanceRegistry;
import com.pingidentity.ps.oidf.device.JdbcInstanceRegistry;
import com.pingidentity.ps.oidf.enrolment.EnrolmentHttpServer;
import com.pingidentity.ps.oidf.enrolment.EnrolmentService;
import com.pingidentity.ps.oidf.enrolment.Main;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.EnumSet;
import java.util.Set;
import javax.sql.DataSource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;
import org.postgresql.ds.PGSimpleDataSource;

/**
 * Everything else in this class is {@link Main}'s wiring, deliberately kept in lock-step with it —
 * {@link Main#pingOneVerifier()} is called directly, not reimplemented, so the demo's user-authentication
 * checking can never quietly drift from production's.
 *
 * <p>The one substitution: {@code AppAttestConfig} is built from a trust root bundled with this jar
 * (see {@code demo/appattest-root-cert.pem}) instead of Apple's real root. {@link PhoneSimulatorCli}
 * signs its synthetic attestations with the matching private key, bundled alongside it. Neither file is
 * a secret in any sense that matters — the "private" key is published in this repo's own history, same
 * as {@code deploy/device-enrolment/docker-compose.yml}'s RFC 7515 signing key — but a verifier trusting
 * it is only ever appropriate here, never in {@link Main}, which is why the substitution lives in its
 * own class rather than a flag on the real one. A production entry point should not ship a switch that
 * makes it accept an arbitrary root.
 *
 * <p>Because {@code APPLE_TEAM_ID}/{@code APPLE_BUNDLE_ID} are not configurable here: the App ID an
 * attestation is bound to must equal the fixture's own constants, or nothing this class mints would
 * verify against what {@link PhoneSimulatorCli} builds. Hardcoding removes the one way that could
 * silently drift out of sync.
 */
public final class DemoServerMain {

    private static final Log LOGGER = LogFactory.getLog(DemoServerMain.class);
    private static final String TRUST_ROOT_RESOURCE = "/demo/appattest-root-cert.pem";

    private DemoServerMain() {
    }

    public static void main(String[] args) throws Exception {
        String issuer = required("ENROLMENT_ISSUER");
        boolean allowDevelopment = Boolean.parseBoolean(env("APPLE_ALLOW_DEVELOPMENT", "true"));
        int port = Integer.parseInt(env("PORT", "8080"));
        long uvMaxAge = Long.parseLong(env("UV_MAX_AGE_SECONDS", "300"));
        boolean requireCompliant = Boolean.parseBoolean(env("REQUIRE_COMPLIANT_DEVICE", "false"));

        X509Certificate trustRoot = loadTrustRoot();
        Set<AppAttestEnvironment> accepted = allowDevelopment
                ? EnumSet.allOf(AppAttestEnvironment.class)
                : EnumSet.of(AppAttestEnvironment.PRODUCTION);
        AppAttestConfig appAttestConfig = AppAttestConfig.withTrustRoot(
                AppAttestFixtures.TEAM_ID, AppAttestFixtures.BUNDLE_ID,
                accepted, trustRoot);

        DataSource dataSource = dataSource(required("DATABASE_URL"));
        InstanceRegistry registry = new JdbcInstanceRegistry(dataSource);

        JwsSigner signer = new LocalJwkSigner(parseJwk(required("ENROLMENT_SIGNING_JWK")));
        DeviceAttestationMinter minter = new DeviceAttestationMinter(issuer);

        EnrolmentService service = new EnrolmentService(
                new AppAttestVerifier(appAttestConfig),
                Main.pingOneVerifier(),
                registry, minter,
                new InMemoryAttestationChallengeService(),
                new InMemoryAttestationReplayCache(),
                signer, issuer, Duration.ofSeconds(uvMaxAge), requireCompliant);

        EnrolmentHttpServer server = new EnrolmentHttpServer(service, signer, port);
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
        server.start();
        LOGGER.warn((Object) ("THIS IS THE DEMO SERVER, NOT Main — it trusts a synthetic App Attest "
                + "root bundled in this jar, not Apple's. It exists only so the ceremony can be shown "
                + "working over real HTTP and real Postgres without a physical iPhone. Never deploy it."));
        LOGGER.info((Object) ("issuer=" + issuer + " appId=" + AppAttestFixtures.TEAM_ID + "."
                + AppAttestFixtures.BUNDLE_ID + " uvMaxAge=" + uvMaxAge
                + "s requireCompliantDevice=" + requireCompliant + " acceptedEnvironments=" + accepted));
    }

    private static X509Certificate loadTrustRoot() throws Exception {
        try (InputStream in = DemoServerMain.class.getResourceAsStream(TRUST_ROOT_RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("demo App Attest trust root missing from the jar at "
                        + TRUST_ROOT_RESOURCE);
            }
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    private static DataSource dataSource(String url) {
        PGSimpleDataSource source = new PGSimpleDataSource();
        source.setUrl(url);
        return source;
    }

    private static java.util.Map<String, Object> parseJwk(String json) {
        try {
            return JsonUtil.parseJson(json);
        } catch (Exception e) {
            throw new IllegalArgumentException("ENROLMENT_SIGNING_JWK is not a JSON JWK", e);
        }
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " must be set");
        }
        return value.trim();
    }
}
