/*
 * OP metadata describing attestation-based client authentication support (advertised in the
 * Entity Configuration's openid_provider metadata).
 */
package com.pingidentity.ps.oidf.federation;

import com.pingidentity.ps.oidf.platform.settings.Settings;
import java.util.List;

/**
 * Capability lists advertised under {@code metadata.openid_provider} for attestation-based client
 * authentication (draft-ietf-oauth-attestation-based-client-auth Section 8): the supported token
 * endpoint auth methods, the attestation / PoP / DPoP signing algorithm sets, the accepted
 * proof-of-possession methods (draft-10 registry), plus whether the challenge endpoint is
 * advertised. All values default sensibly and may be overridden via servlet init-params, read through the
 * {@code federation-entity} settings catalogue ({@link #from}).
 */
public final class AttestationMetadataConfig {
    private static final List<String> DEFAULT_AUTH_METHODS = List.of("private_key_jwt", "attest_jwt_client_auth", "attest_jwt_client_auth_dpop");
    private static final List<String> DEFAULT_ATTESTATION_ALGS = List.of("RS256", "PS256", "ES256");
    private static final List<String> DEFAULT_POP_ALGS = List.of("ES256", "RS256", "PS256");
    private static final List<String> DEFAULT_DPOP_ALGS = List.of("ES256", "RS256", "PS256");
    private static final List<String> DEFAULT_FORMATS = List.of("jwt");
    private static final List<String> DEFAULT_POP_METHODS = List.of("attestation_pop_jwt", "dpop_combined");

    private final List<String> tokenEndpointAuthMethodsSupported;
    private final List<String> clientAttestationSigningAlgValuesSupported;
    private final List<String> clientAttestationPopSigningAlgValuesSupported;
    private final List<String> dpopSigningAlgValuesSupported;
    private final List<String> clientAttestationFormatsSupported;
    private final List<String> clientAttestationPopMethodsSupported;
    private final boolean challengeEndpointEnabled;

    AttestationMetadataConfig(List<String> tokenEndpointAuthMethodsSupported,
                             List<String> clientAttestationSigningAlgValuesSupported,
                             List<String> clientAttestationPopSigningAlgValuesSupported,
                             List<String> dpopSigningAlgValuesSupported,
                             List<String> clientAttestationFormatsSupported,
                             List<String> clientAttestationPopMethodsSupported,
                             boolean challengeEndpointEnabled) {
        this.tokenEndpointAuthMethodsSupported = List.copyOf(tokenEndpointAuthMethodsSupported);
        this.clientAttestationSigningAlgValuesSupported = List.copyOf(clientAttestationSigningAlgValuesSupported);
        this.clientAttestationPopSigningAlgValuesSupported = List.copyOf(clientAttestationPopSigningAlgValuesSupported);
        this.dpopSigningAlgValuesSupported = List.copyOf(dpopSigningAlgValuesSupported);
        this.clientAttestationFormatsSupported = List.copyOf(clientAttestationFormatsSupported);
        this.clientAttestationPopMethodsSupported = List.copyOf(clientAttestationPopMethodsSupported);
        this.challengeEndpointEnabled = challengeEndpointEnabled;
    }

    static AttestationMetadataConfig defaults() {
        return new AttestationMetadataConfig(DEFAULT_AUTH_METHODS, DEFAULT_ATTESTATION_ALGS, DEFAULT_POP_ALGS, DEFAULT_DPOP_ALGS, DEFAULT_FORMATS, DEFAULT_POP_METHODS, true);
    }

    /**
     * The capability lists and the challenge switch as {@code settings} (the federation servlet's, init-params included)
     * give them: each an init-param of the {@code federation-entity} catalogue, parsed strictly - a list of nothing, or
     * a switch that is not {@code true} or {@code false}, stops the servlet starting, naming it (plan item ST-5).
     */
    static AttestationMetadataConfig from(Settings settings) {
        return new AttestationMetadataConfig(
                List.copyOf(settings.words("tokenEndpointAuthMethodsSupported")),
                List.copyOf(settings.words("clientAttestationSigningAlgValuesSupported")),
                List.copyOf(settings.words("clientAttestationPopSigningAlgValuesSupported")),
                List.copyOf(settings.words("dpopSigningAlgValuesSupported")),
                List.copyOf(settings.words("clientAttestationFormatsSupported")),
                List.copyOf(settings.words("clientAttestationPopMethodsSupported")),
                settings.bool("attestationChallengeEndpointEnabled"));
    }

    List<String> tokenEndpointAuthMethodsSupported() {
        return this.tokenEndpointAuthMethodsSupported;
    }

    List<String> clientAttestationSigningAlgValuesSupported() {
        return this.clientAttestationSigningAlgValuesSupported;
    }

    List<String> clientAttestationPopSigningAlgValuesSupported() {
        return this.clientAttestationPopSigningAlgValuesSupported;
    }

    List<String> dpopSigningAlgValuesSupported() {
        return this.dpopSigningAlgValuesSupported;
    }

    List<String> clientAttestationFormatsSupported() {
        return this.clientAttestationFormatsSupported;
    }

    List<String> clientAttestationPopMethodsSupported() {
        return this.clientAttestationPopMethodsSupported;
    }

    boolean challengeEndpointEnabled() {
        return this.challengeEndpointEnabled;
    }
}
