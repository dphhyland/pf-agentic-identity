/*
 * Wires the enrolment service from the environment and starts it.
 */
package com.pingidentity.ps.oidf.enrolment;

import com.pingidentity.ps.oidf.appattest.AppAttestConfig;
import com.pingidentity.ps.oidf.appattest.AppAttestVerifier;
import com.pingidentity.ps.oidf.common.InMemoryAttestationChallengeService;
import com.pingidentity.ps.oidf.common.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.common.JwsSigner;
import com.pingidentity.ps.oidf.common.LocalJwkSigner;
import com.pingidentity.ps.oidf.device.DeviceAttestationMinter;
import com.pingidentity.ps.oidf.device.InstanceRegistry;
import com.pingidentity.ps.oidf.device.JdbcInstanceRegistry;
import java.time.Duration;
import java.util.Map;
import javax.sql.DataSource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;
import org.postgresql.ds.PGSimpleDataSource;

/**
 * Entry point. Everything is configured by environment variable, as the other deployables in this repo
 * are.
 *
 * <pre>
 *   PORT                          listen port (default 8080)
 *   ENROLMENT_ISSUER              this service's entity id — the attestation iss, and the proof aud
 *   ENROLMENT_SIGNING_JWK         the attester's private JWK (dev). Production should use a vault-backed
 *                                 JwsSigner instead; the seam already exists
 *   DATABASE_URL                  Postgres JDBC URL. Absent → refuses to start
 *   APPLE_TEAM_ID / APPLE_BUNDLE_ID   the App ID an attestation must be bound to
 *   APPLE_ALLOW_DEVELOPMENT       "true" to accept development App Attest. Off by default, on purpose
 *   UV_MAX_AGE_SECONDS            the server-side time-box (default 300)
 *   REQUIRE_COMPLIANT_DEVICE      "false" to allow minting on an unassessed device (default true)
 * </pre>
 *
 * <p>Two defaults are deliberately strict, because the failure mode of getting them wrong is silent:
 * development App Attest is refused unless asked for, and a device whose compliance is unknown cannot
 * mint. Both fail closed.
 */
public final class Main {

    private static final Log LOGGER = LogFactory.getLog(Main.class);

    private Main() {
    }

    public static void main(String[] args) throws Exception {
        String issuer = required("ENROLMENT_ISSUER");
        String teamId = required("APPLE_TEAM_ID");
        String bundleId = required("APPLE_BUNDLE_ID");
        boolean allowDevelopment = Boolean.parseBoolean(env("APPLE_ALLOW_DEVELOPMENT", "false"));
        int port = Integer.parseInt(env("PORT", "8080"));
        long uvMaxAge = Long.parseLong(env("UV_MAX_AGE_SECONDS", "300"));
        boolean requireCompliant = Boolean.parseBoolean(env("REQUIRE_COMPLIANT_DEVICE", "true"));

        AppAttestConfig appAttestConfig = allowDevelopment
                ? AppAttestConfig.allowingDevelopment(teamId, bundleId)
                : AppAttestConfig.production(teamId, bundleId);
        if (allowDevelopment) {
            // Loud on purpose: this weakens the strongest assertion the service makes.
            LOGGER.warn((Object) "APPLE_ALLOW_DEVELOPMENT is set — development App Attest objects will "
                    + "be accepted. Every such enrolment is flagged in the registry, but this must not "
                    + "be set in production.");
        }

        DataSource dataSource = dataSource(required("DATABASE_URL"));
        InstanceRegistry registry = new JdbcInstanceRegistry(dataSource);

        JwsSigner signer = new LocalJwkSigner(parseJwk(required("ENROLMENT_SIGNING_JWK")));
        DeviceAttestationMinter minter = new DeviceAttestationMinter(issuer);

        EnrolmentService service = new EnrolmentService(
                new AppAttestVerifier(appAttestConfig),
                pingOneVerifier(),
                registry, minter,
                new InMemoryAttestationChallengeService(),
                new InMemoryAttestationReplayCache(),
                signer, issuer, Duration.ofSeconds(uvMaxAge), requireCompliant);

        EnrolmentHttpServer server = new EnrolmentHttpServer(service, signer, port);
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
        server.start();
        LOGGER.info((Object) ("issuer=" + issuer + " appId=" + teamId + "." + bundleId
                + " uvMaxAge=" + uvMaxAge + "s requireCompliantDevice=" + requireCompliant));
    }

    /**
     * The IdP seam. Not yet implemented against a live PingOne tenant — no tenant exists in this
     * repository — so this refuses rather than pretending. Milestone 2 wires the real verifier; until
     * then the service is exercised through its tests, which supply their own.
     */
    private static UserAuthenticationVerifier pingOneVerifier() {
        String issuer = System.getenv("PINGONE_ISSUER");
        if (issuer == null || issuer.isBlank()) {
            LOGGER.warn((Object) "PINGONE_ISSUER is unset — user authentication will be refused. "
                    + "Enrolment cannot complete until the IdP verifier is configured.");
            return evidence -> {
                throw EnrolmentException.userAuthenticationFailed(
                        "no IdP is configured on this deployment");
            };
        }
        throw new UnsupportedOperationException(
                "the PingOne verifier is not implemented yet; see docs/unverified.md item 7");
    }

    private static DataSource dataSource(String url) {
        PGSimpleDataSource source = new PGSimpleDataSource();
        source.setUrl(url);
        return source;
    }

    private static Map<String, Object> parseJwk(String json) {
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
