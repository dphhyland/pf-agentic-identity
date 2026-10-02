/*
 * Attestation member sets for tests outside this package: pf-integration's discovery filter, attestation-issuer's
 * cross-document test.
 */
package com.pingidentity.ps.oidf.federation;

import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.util.List;
import java.util.Map;

/** {@link AttestationMetadataConfig}s built as the federation servlet builds them, for tests in other modules. */
public final class AttestationMetadataConfigs {

    private AttestationMetadataConfigs() {
    }

    /** The catalogue's defaults, {@code ATTESTATION_AUTH} not switched off. */
    public static AttestationMetadataConfig defaults() {
        return AttestationMetadataConfig.defaults();
    }

    /** The catalogue's defaults, read with {@code OIDF_ATTESTATION_AUTH_ENABLED=false}. */
    public static AttestationMetadataConfig switchedOff() {
        return read(Map.of(), Map.of(ComponentSwitches.ATTESTATION_AUTH, "false"));
    }

    /** The catalogue's defaults with the challenge endpoint not advertised. */
    public static AttestationMetadataConfig withoutChallenge() {
        return read(Map.of("attestationChallengeEndpointEnabled", "false"), Map.of());
    }

    /** Only the PoP JWT method, no DPoP combined mode and no pop methods list. */
    public static AttestationMetadataConfig popJwtOnly() {
        return new AttestationMetadataConfig(List.of("private_key_jwt", "attest_jwt_client_auth"), List.of("ES256"), List.of("ES256"),
                List.of("ES256"), List.of("jwt"), List.of(), true);
    }

    /** No ABCA-10 method configured: nothing is advertised. */
    public static AttestationMetadataConfig noAttestationMethod() {
        return new AttestationMetadataConfig(List.of("private_key_jwt"), List.of("ES256"), List.of("ES256"), List.of("ES256"),
                List.of("jwt"), List.of(), true);
    }

    /** What {@link AttestationMetadataConfig#current} answers, forgotten. */
    public static void resetCurrent() {
        AttestationMetadataConfig.resetForTests();
    }

    /** A federation configuration naming {@code issuer} its trust anchor, with {@code members}. */
    public static FederationConfiguration configuration(String issuer, AttestationMetadataConfig members) {
        return new FederationConfiguration(List.of(issuer), List.of(), false, false, null, null, null, 0, "RS256", members);
    }

    private static AttestationMetadataConfig read(Map<String, String> initParams, Map<String, String> env) {
        Settings settings = Settings.load(AttestationMetadataConfig.class.getClassLoader(), FederationConfiguration.CATALOGUE)
                .with(Sources.of(env, Map.of()).withInitParams(initParams::get));
        return AttestationMetadataConfig.from(settings, ComponentSwitches.of(env::get, name -> null));
    }
}
