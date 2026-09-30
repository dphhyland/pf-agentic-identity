/*
 * The authorization server's attestation-based client authentication members, advertised wherever its metadata is
 * served: the Entity Configuration's openid_provider and oauth_authorization_server blocks, and PingFederate's own two
 * discovery documents.
 */
package com.pingidentity.ps.oidf.federation;

import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Capability lists advertised for attestation-based client authentication (draft-ietf-oauth-attestation-based-client-auth
 * Section 8): the supported token endpoint auth methods, the attestation / PoP / DPoP signing algorithm sets, the accepted
 * proof-of-possession methods (draft-10 registry; {@code openid_provider} only, see {@link #extend}), plus whether the
 * challenge endpoint is advertised. All values default
 * sensibly and may be overridden via servlet init-params, read through the {@code federation-entity} settings catalogue
 * ({@link #from}).
 *
 * <p>One member set (plan item S-4, F-0115): {@code openid_provider} carries it as it always has, and {@link #extend} adds
 * it to any other RFC 8414 document - the Entity Configuration's {@code oauth_authorization_server} block and, through
 * pf-integration's {@code AttestationMetadataFilter}, PingFederate's {@code /.well-known/openid-configuration} and
 * {@code /.well-known/oauth-authorization-server}. ABCA-10 §6.1 (read 2026-10-01): an authorization server that offers a
 * challenge endpoint and "supports metadata as defined in [RFC8414] ... MUST signal support for the challenge endpoint by
 * including the metadata entry challenge_endpoint". With {@code ATTESTATION_AUTH} switched off
 * ({@code OIDF_ATTESTATION_AUTH_ENABLED=false}) nothing verifies an attestation, so no document advertises a member
 * (plan item S9b's rule for a disabled component).
 */
public final class AttestationMetadataConfig {
    /** ABCA-10 §8's two {@code token_endpoint_auth_methods_supported} values, in its order. */
    public static final List<String> ATTESTATION_METHODS = List.of("attest_jwt_client_auth", "attest_jwt_client_auth_dpop");
    /** The authorization server's challenge endpoint, under the context path (client-attestation's ClientAttestationChallengeServlet). */
    public static final String CHALLENGE_PATH = "/federation/attestation-challenge";
    /** The configuration the federation servlet read last in this loader: what {@link #current} answers. */
    private static volatile AttestationMetadataConfig published;
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
    /** {@code ATTESTATION_AUTH} is switched off: no attestation member is advertised. */
    private final boolean attestationAuthDisabled;

    AttestationMetadataConfig(List<String> tokenEndpointAuthMethodsSupported,
                             List<String> clientAttestationSigningAlgValuesSupported,
                             List<String> clientAttestationPopSigningAlgValuesSupported,
                             List<String> dpopSigningAlgValuesSupported,
                             List<String> clientAttestationFormatsSupported,
                             List<String> clientAttestationPopMethodsSupported,
                             boolean challengeEndpointEnabled) {
        this(tokenEndpointAuthMethodsSupported, clientAttestationSigningAlgValuesSupported, clientAttestationPopSigningAlgValuesSupported,
                dpopSigningAlgValuesSupported, clientAttestationFormatsSupported, clientAttestationPopMethodsSupported,
                challengeEndpointEnabled, false);
    }

    AttestationMetadataConfig(List<String> tokenEndpointAuthMethodsSupported,
                             List<String> clientAttestationSigningAlgValuesSupported,
                             List<String> clientAttestationPopSigningAlgValuesSupported,
                             List<String> dpopSigningAlgValuesSupported,
                             List<String> clientAttestationFormatsSupported,
                             List<String> clientAttestationPopMethodsSupported,
                             boolean challengeEndpointEnabled,
                             boolean attestationAuthDisabled) {
        this.tokenEndpointAuthMethodsSupported = List.copyOf(tokenEndpointAuthMethodsSupported);
        this.clientAttestationSigningAlgValuesSupported = List.copyOf(clientAttestationSigningAlgValuesSupported);
        this.clientAttestationPopSigningAlgValuesSupported = List.copyOf(clientAttestationPopSigningAlgValuesSupported);
        this.dpopSigningAlgValuesSupported = List.copyOf(dpopSigningAlgValuesSupported);
        this.clientAttestationFormatsSupported = List.copyOf(clientAttestationFormatsSupported);
        this.clientAttestationPopMethodsSupported = List.copyOf(clientAttestationPopMethodsSupported);
        this.challengeEndpointEnabled = challengeEndpointEnabled;
        this.attestationAuthDisabled = attestationAuthDisabled;
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
        return from(settings, ComponentSwitches.process());
    }

    /**
     * {@link #from(Settings)} with {@code switches} for this process's: {@code ATTESTATION_AUTH} switched off advertises
     * nothing. The result is what {@link #current} answers from then on.
     */
    static AttestationMetadataConfig from(Settings settings, ComponentSwitches switches) {
        AttestationMetadataConfig read = new AttestationMetadataConfig(
                List.copyOf(settings.words("tokenEndpointAuthMethodsSupported")),
                List.copyOf(settings.words("clientAttestationSigningAlgValuesSupported")),
                List.copyOf(settings.words("clientAttestationPopSigningAlgValuesSupported")),
                List.copyOf(settings.words("dpopSigningAlgValuesSupported")),
                List.copyOf(settings.words("clientAttestationFormatsSupported")),
                List.copyOf(settings.words("clientAttestationPopMethodsSupported")),
                settings.bool("attestationChallengeEndpointEnabled"),
                switches.verdict(Startup.ATTESTATION_AUTH).kind() == ComponentSwitches.Kind.DISABLED);
        published = read;
        return read;
    }

    /**
     * The member set the federation servlet publishes in this loader, for a surface that serves this authorization
     * server's metadata outside it (pf-integration's {@code AttestationMetadataFilter}): the servlet's own configuration,
     * init-params included, once it has read it; until then - or when it never does, with {@code FEDERATION} switched off -
     * the {@code federation-entity} catalogue's values from this process, which for the war's annotation-mapped servlet
     * are the same ones.
     *
     * @throws com.pingidentity.ps.oidf.platform.settings.SettingRefused when this process's settings refuse a value
     */
    public static AttestationMetadataConfig current() {
        AttestationMetadataConfig known = published;
        return known != null ? known
                : from(Settings.load(AttestationMetadataConfig.class.getClassLoader(), FederationConfiguration.CATALOGUE));
    }

    /** Test seam: forgets what {@link #current} answers. */
    static void resetForTests() {
        published = null;
    }

    /**
     * {@code token_endpoint_auth_methods_supported} for {@code openid_provider}: as configured, less ABCA-10's two methods
     * while {@code ATTESTATION_AUTH} is switched off.
     */
    List<String> tokenEndpointAuthMethodsSupported() {
        if (!this.attestationAuthDisabled) {
            return this.tokenEndpointAuthMethodsSupported;
        }
        List<String> kept = new ArrayList<>(this.tokenEndpointAuthMethodsSupported);
        kept.removeAll(ATTESTATION_METHODS);
        return List.copyOf(kept);
    }

    /** The configured methods that are ABCA-10 §8's, in the configured order; none while {@code ATTESTATION_AUTH} is off. */
    public List<String> attestationMethods() {
        if (this.attestationAuthDisabled) {
            return List.of();
        }
        return this.tokenEndpointAuthMethodsSupported.stream().filter(ATTESTATION_METHODS::contains).toList();
    }

    /** Whether any document advertises attestation: an ABCA-10 method configured, and {@code ATTESTATION_AUTH} not off. */
    public boolean advertised() {
        return !this.attestationMethods().isEmpty();
    }

    /**
     * {@code metadata}, an RFC 8414 document this authorization server serves, with the attestation members added: a copy,
     * {@code metadata}'s own members first and unchanged, in their order. ABCA-10 §8 (read 2026-10-01): the server "SHOULD
     * communicate support ... by using the value attest_jwt_client_auth [and attest_jwt_client_auth_dpop] in the
     * token_endpoint_auth_methods_supported", and "MUST include client_attestation_signing_alg_values_supported and
     * client_attestation_pop_signing_alg_values_supported in its published metadata if the Client Attestation PoP JWT
     * mechanism is used" and "MUST include dpop_signing_alg_values_supported as defined in [RFC9449], if DPoP is used as
     * the Proof of Possession in combined mode"; §6.1's {@code challenge_endpoint} when the challenge endpoint is enabled.
     *
     * <ul>
     *   <li>{@code token_endpoint_auth_methods_supported}: the document's list with each configured ABCA-10 method it lacks
     *       appended; a document without one gets the configured list, as {@code openid_provider} does (RFC 8414 §2: "If
     *       omitted, the default is "client_secret_basic"", which an attestation-only list would silently withdraw).</li>
     *   <li>Every other member only where the document has none, so the document's own - PingFederate's
     *       {@code dpop_signing_alg_values_supported}, which its DPoP validation holds proofs to - is never replaced.</li>
     *   <li>Never {@code client_attestation_pop_methods_supported}: ABCA-10 §7.6 (read 2026-10-01) makes it a demand on
     *       every client - "When the parameter is present and does not include none, a Client SHOULD include the Client
     *       Attestation and its Proof of Possession in its requests to that server" - and these documents are read by
     *       every client of the authorization server, most of which are not asked for an attestation (F-0412).</li>
     * </ul>
     *
     * @param challengeEndpoint the authorization server's challenge endpoint URL, published when the challenge endpoint is
     *                          enabled; never the attester's
     * @return the extended copy; an unchanged copy when nothing is advertised; {@code null} when the document's
     *         {@code token_endpoint_auth_methods_supported} is not an array of strings, which cannot be extended without
     *         changing what the document says
     */
    public Map<String, Object> extend(Map<String, Object> metadata, String challengeEndpoint) {
        Map<String, Object> out = new LinkedHashMap<>(metadata);
        List<String> methods = this.attestationMethods();
        if (methods.isEmpty()) {
            return out;
        }
        Object own = out.get("token_endpoint_auth_methods_supported");
        if (own == null) {
            out.put("token_endpoint_auth_methods_supported", this.tokenEndpointAuthMethodsSupported);
        } else if (own instanceof List<?> list && list.stream().allMatch(String.class::isInstance)) {
            List<Object> extended = new ArrayList<>(list);
            methods.stream().filter(m -> !list.contains(m)).forEach(extended::add);
            out.put("token_endpoint_auth_methods_supported", extended);
        } else {
            return null;
        }
        out.putIfAbsent("client_attestation_signing_alg_values_supported", this.clientAttestationSigningAlgValuesSupported);
        out.putIfAbsent("client_attestation_pop_signing_alg_values_supported", this.clientAttestationPopSigningAlgValuesSupported);
        if (methods.contains("attest_jwt_client_auth_dpop")) {
            out.putIfAbsent("dpop_signing_alg_values_supported", this.dpopSigningAlgValuesSupported);
        }
        if (this.challengeEndpointEnabled && challengeEndpoint != null) {
            out.putIfAbsent("challenge_endpoint", challengeEndpoint);
        }
        return out;
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
