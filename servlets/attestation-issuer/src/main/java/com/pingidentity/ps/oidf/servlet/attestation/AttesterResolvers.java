/*
 * Chooses the attester's client resolvers from the environment: a federation entity, a CIMD document, the PF client store.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import com.pingidentity.ps.oidf.federation.HttpTrustControllerGateway;
import com.pingidentity.ps.oidf.federation.SubordinateStatementCache;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import com.pingidentity.ps.oidf.issuer.ChainClientResolver;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.issuer.CimdClientResolver;
import com.pingidentity.ps.oidf.issuer.IssuanceClientResolver;
import com.pingidentity.ps.oidf.issuer.OpenIdFederationClientResolver;
import com.pingidentity.ps.oidf.jose.JdkHttpGetClient;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.PfMgmtClientStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Selects where the attester reads its SPIFFE-ID → client mapping: an OpenID Federation entity whose chain
 * validates to a pinned anchor ({@code oidf.attester.federation.entity} / {@code OIDF_ATTESTER_FEDERATION_ENTITY}),
 * a hosted Client ID Metadata Document ({@code oidf.attester.cimd.url} / {@code OIDF_ATTESTER_CIMD_URL}), and
 * PingFederate's own client store, in that order of precedence. Mirrors the {@code oidf.mock.attesters} switch
 * used on the verification side.
 */
final class AttesterResolvers {
    private static final Log LOGGER = LogFactory.getLog(AttesterResolvers.class);

    static final String CIMD_URL_PROPERTY = "oidf.attester.cimd.url";
    static final String CIMD_URL_ENV = "OIDF_ATTESTER_CIMD_URL";
    static final String FEDERATION_ENTITY_PROPERTY = "oidf.attester.federation.entity";
    static final String FEDERATION_ENTITY_ENV = "OIDF_ATTESTER_FEDERATION_ENTITY";
    static final String SIGNING_JWK_PROPERTY = "oidf.attester.signing.jwk";
    static final String SIGNING_JWK_ENV = "OIDF_ATTESTER_SIGNING_JWK";

    private AttesterResolvers() {
    }

    /**
     * Builds the active resolver chain from configuration. The PingFederate client store is always a
     * plugin; an OpenID Federation entity and/or a CIMD document are added when configured, in that order of
     * precedence - the source a trust anchor vouches for first. With none of the external sources set, this is
     * just the PF store (backwards compatible).
     *
     * @throws IllegalStateException when a federation entity is named but no trust anchor is pinned: its clients
     *                               can only be trusted through a chain to one
     */
    static IssuanceClientResolver fromEnvironment() {
        return fromEnvironment(System::getProperty, System::getenv);
    }

    /**
     * As above, over the given property and environment reads.
     *
     * <p>{@code OIDF_ATTESTER_CIMD_URL} is honoured only under {@code OIDF_DEPLOYMENT_PROFILE=development} (plan
     * item M-1, finding F-0067): the CIMD document hands the attester every client's bindings and trust roots,
     * so whoever answers at that URL chooses the keys the attester accepts. Outside development the variable is
     * refused - logged at ERROR naming it, and the plugin left out, so clients that document alone describes are
     * unknown here and the discovery document's {@code resolver_plugins_active} omits {@code cimd} - while the
     * federation and PingFederate sources keep serving. Refusing the one source, rather than the attester, keeps
     * the blast radius to the clients that source describes. X-B02 (Phase 5) is the full fix and removes the
     * variable. The profile is platform's {@link DeploymentProfile} (PR-1).
     */
    static IssuanceClientResolver fromEnvironment(Function<String, String> props, Function<String, String> env) {
        String signingJwk = firstSet(props.apply(SIGNING_JWK_PROPERTY), env.apply(SIGNING_JWK_ENV));
        List<IssuanceClientResolver> plugins = new ArrayList<>();

        String fedEntity = firstSet(props.apply(FEDERATION_ENTITY_PROPERTY), env.apply(FEDERATION_ENTITY_ENV));
        if (fedEntity != null) {
            LOGGER.info((Object) ("Attester resolver plugin: openid-federation -> " + fedEntity));
            plugins.add(new OpenIdFederationClientResolver(fedEntity, federationValidator(FederationRuntimeConfig.get(), fedEntity), signingJwk));
        }
        String cimdUrl = firstSet(props.apply(CIMD_URL_PROPERTY), env.apply(CIMD_URL_ENV));
        if (cimdUrl != null && DeploymentProfile.of(env).isProduction()) {
            LOGGER.error((Object) (CIMD_URL_ENV + " is set but " + DeploymentProfile.SETTING + " is not development: the CIMD"
                    + " source is refused (M-1, F-0067), so clients only that document describes cannot be issued attestations."
                    + " Unset it, or set " + DeploymentProfile.SETTING + "=development on a rig"));
        } else if (cimdUrl != null) {
            LOGGER.info((Object) ("Attester resolver plugin: cimd -> " + cimdUrl));
            plugins.add(new CimdClientResolver(cimdUrl, signingJwk));
        }
        // The PF client store is always available as a plugin (registered client metadata).
        plugins.add(new PfIssuanceClientResolver(new PfMgmtClientStore()));

        return plugins.size() == 1 ? plugins.get(0) : new ChainClientResolver(plugins);
    }

    /**
     * A validator over the deployment's pinned trust anchors ({@link FederationRuntimeConfig#trustAnchors()}), the
     * same ones every other federation check here uses. The trust controller and the entity itself are the
     * operator's own configuration, so the outbound URL policy lets them through.
     */
    static TrustChainValidator federationValidator(FederationRuntimeConfig runtime, String entityUrl) {
        String host = runtime.trustControllerHost();
        String baseUrl = runtime.trustControllerBaseUrl();
        String[] operatorUrls = java.util.stream.Stream.of(baseUrl, host, entityUrl).filter(u -> u != null && !u.isBlank()).toArray(String[]::new);
        return new TrustChainValidator(new HttpTrustControllerGateway(new JdkHttpGetClient(runtime.ignoreSslErrors(),
                OutboundUrlPolicy.fromEnvironment().trusting(operatorUrls)), baseUrl, host, new SubordinateStatementCache(256)),
                runtime.trustAnchors(), Set.of(), ValidatorOptions.defaults());
    }

    /** The distinct plugin ids in an active resolver (for the discovery document). */
    static List<String> activePluginIds(IssuanceClientResolver resolver) {
        if (resolver instanceof ChainClientResolver) {
            return ((ChainClientResolver) resolver).activePluginIds();
        }
        return List.of(resolver.pluginId());
    }

    private static String firstSet(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a.trim();
        }
        if (b != null && !b.isBlank()) {
            return b.trim();
        }
        return null;
    }
}
