/*
 * What a verifier accepts: which app, which environments, and which root of trust.
 */
package com.pingidentity.ps.oidf.appattest;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * The verification policy: the App ID an attestation must be bound to, the environments accepted, and
 * the trust root.
 *
 * <p>The default trust root is Apple's <em>App Attestation Root CA</em>, bundled as a resource
 * (subject and issuer {@code CN=Apple App Attestation Root CA, O=Apple Inc., ST=California}, P-384,
 * valid to 2045, SHA-256 fingerprint
 * {@code 1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32}).
 * It is pinned rather than taken from the JVM trust store: this chain must terminate at Apple's App
 * Attest root specifically, not at any CA the platform happens to trust.
 *
 * <p><strong>Development attestations are refused unless explicitly allowed.</strong> Use
 * {@link #production(String, String)} for anything real; {@link #allowingDevelopment(String, String)}
 * exists so a development build can be verified deliberately, and its use should be visible in
 * configuration rather than defaulted.
 */
public final class AppAttestConfig {

    private static final String ROOT_CA_RESOURCE = "/apple/Apple_App_Attestation_Root_CA.pem";

    private final String teamId;
    private final String bundleId;
    private final Set<AppAttestEnvironment> acceptedEnvironments;
    private final X509Certificate trustRoot;

    private AppAttestConfig(String teamId, String bundleId, Set<AppAttestEnvironment> accepted,
                            X509Certificate trustRoot) {
        this.teamId = requireNonBlank(teamId, "teamId");
        this.bundleId = requireNonBlank(bundleId, "bundleId");
        if (accepted == null || accepted.isEmpty()) {
            throw new IllegalArgumentException("at least one App Attest environment must be accepted");
        }
        this.acceptedEnvironments = Set.copyOf(accepted);
        this.trustRoot = Objects.requireNonNull(trustRoot, "trustRoot");
    }

    /** Accepts production attestations only. This is the correct choice for a deployed service. */
    public static AppAttestConfig production(String teamId, String bundleId) {
        return new AppAttestConfig(teamId, bundleId,
                EnumSet.of(AppAttestEnvironment.PRODUCTION), appleRootCa());
    }

    /**
     * Accepts development attestations <em>as well as</em> production. Deliberately awkward to reach:
     * a development attestation carries materially weaker assurance, and accepting one in production
     * would mean trusting an app build Apple never vetted for release.
     */
    public static AppAttestConfig allowingDevelopment(String teamId, String bundleId) {
        return new AppAttestConfig(teamId, bundleId,
                EnumSet.allOf(AppAttestEnvironment.class), appleRootCa());
    }

    /** As {@link #production}, with a caller-supplied trust root — for tests using a synthetic chain. */
    public static AppAttestConfig withTrustRoot(String teamId, String bundleId,
                                                Set<AppAttestEnvironment> accepted, X509Certificate trustRoot) {
        return new AppAttestConfig(teamId, bundleId, accepted, trustRoot);
    }

    /**
     * The App ID an attestation's {@code rpIdHash} must cover: {@code <teamID>.<bundleID>}.
     */
    public String appId() {
        return this.teamId + "." + this.bundleId;
    }

    public String teamId() {
        return this.teamId;
    }

    public String bundleId() {
        return this.bundleId;
    }

    public Set<AppAttestEnvironment> acceptedEnvironments() {
        return this.acceptedEnvironments;
    }

    public X509Certificate trustRoot() {
        return this.trustRoot;
    }

    public boolean accepts(AppAttestEnvironment environment) {
        return environment != null && this.acceptedEnvironments.contains(environment);
    }

    /** Loads the bundled Apple App Attestation Root CA. */
    public static X509Certificate appleRootCa() {
        try (InputStream in = AppAttestConfig.class.getResourceAsStream(ROOT_CA_RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("Apple App Attestation Root CA is missing from the jar at "
                        + ROOT_CA_RESOURCE);
            }
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(in);
        } catch (IOException | CertificateException e) {
            throw new IllegalStateException("Apple App Attestation Root CA could not be parsed", e);
        }
    }

    private static String requireNonBlank(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value.trim();
    }
}
