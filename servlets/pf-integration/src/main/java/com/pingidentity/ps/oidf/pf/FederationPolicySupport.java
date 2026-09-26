/*
 * Who decides federation requests beyond the federation's own checks.
 */
package com.pingidentity.ps.oidf.pf;

import com.pingidentity.ps.oidf.federation.policy.AuthZenFederationPolicyDecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.CachingPolicyDecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.CompositePolicyDecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.DecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.FederationPolicyDecisionPoint;
import com.pingidentity.ps.oidf.federation.policy.LocalFederationPolicyDecisionPoint;
import com.pingidentity.ps.oidf.jose.HttpGetClient;
import com.pingidentity.ps.oidf.jose.HttpPostClient;
import com.pingidentity.ps.oidf.jose.JdkHttpClient;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpAuth;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpMode;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.PdpSettings;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/**
 * The deployment's policy decision points, built once per classloader from {@link FederationRuntimeConfig#pdp()}:
 * nobody ({@code OIDF_PDP_MODE=off}); this deployment's own policy - the scopes a federation client may keep, when
 * {@code OIDF_REGISTRATION_ALLOWED_SCOPES} lists them - for every registration ({@code local}, the default); or that, then
 * an AuthZEN 1.0 PDP for the decisions {@code OIDF_PDP_DECISION_POINTS} names ({@code authzen}). A local refusal would be
 * final - the PDP is not asked - though the local policy only narrows.
 *
 * <p>The PDP is reached through the outbound URL policy with its own timeouts. Its configured URLs are trusted as an
 * operator's - a PDP on a private network is the usual case - and a discovered evaluation endpoint elsewhere is screened
 * like any other fetch. Decisions are kept for {@code OIDF_PDP_CACHE_TTL_SECONDS} when that is set; failures never are.
 */
public final class FederationPolicySupport {
    private static Policies policies;

    /** The decision points a configuration yields: the local policy, null when it has nothing to say; the PDP, when there is one. */
    record Policies(PdpSettings settings, FederationPolicyDecisionPoint local, FederationPolicyDecisionPoint external) {
        /** Who decides {@code point}: null when nobody does. */
        FederationPolicyDecisionPoint forPoint(DecisionPoint point) {
            if (this.settings.mode() == PdpMode.OFF) {
                return null;
            }
            boolean external = this.settings.asksExternally(point);
            if (point != DecisionPoint.EXPLICIT_REGISTRATION && point != DecisionPoint.AUTOMATIC_REGISTRATION) {
                // The local policy is about what a client may register with; an enrolment or a token asks for nothing it narrows.
                return external ? this.external : null;
            }
            if (!external) {
                return this.local;
            }
            return this.local == null ? this.external : new CompositePolicyDecisionPoint(this.local, this.external);
        }
    }

    private FederationPolicySupport() {
    }

    /** Who decides {@code point} in this deployment: null when nobody does. */
    public static FederationPolicyDecisionPoint decisionPointFor(DecisionPoint point) {
        return policies().forPoint(point);
    }

    /** The settings the decision points were built from. */
    public static PdpSettings settings() {
        return policies().settings();
    }

    private static synchronized Policies policies() {
        if (policies == null) {
            PdpSettings settings = FederationRuntimeConfig.get().pdp();
            JdkHttpClient http = new JdkHttpClient(false, OutboundUrlPolicy.fromEnvironment().trusting(trustedUrls(settings)),
                    Duration.ofMillis(settings.connectTimeoutMs()), Duration.ofMillis(settings.requestTimeoutMs()));
            policies = build(settings, http, http, Clock.systemUTC());
        }
        return policies;
    }

    /** Test seam: decision points built from {@code settings} over the given transport. */
    public static synchronized void configure(PdpSettings settings, HttpPostClient post, HttpGetClient get, Clock clock) {
        policies = build(settings, post, get, clock);
    }

    /** Test seam: forgets what was built, so the next caller builds again. */
    public static synchronized void resetForTests() {
        policies = null;
    }

    static Policies build(PdpSettings settings, HttpPostClient post, HttpGetClient get, Clock clock) {
        Objects.requireNonNull(settings, "settings");
        // Without an allow-list the local policy narrows nothing, so it is not asked - and leaves no audit line saying it was.
        FederationPolicyDecisionPoint local = settings.allowedScopes() == null ? null : new LocalFederationPolicyDecisionPoint(settings.allowedScopes());
        if (settings.mode() != PdpMode.AUTHZEN) {
            return new Policies(settings, local, null);
        }
        AuthZenFederationPolicyDecisionPoint.Endpoint endpoint = settings.evaluationUrl() != null
                ? AuthZenFederationPolicyDecisionPoint.exactly(settings.evaluationUrl())
                : settings.discover() ? AuthZenFederationPolicyDecisionPoint.discovered(get, settings.url())
                : AuthZenFederationPolicyDecisionPoint.at(settings.url());
        FederationPolicyDecisionPoint external = new AuthZenFederationPolicyDecisionPoint(post, endpoint, authHeaders(settings),
                settings.rejectUnknownContext(), clock);
        if (settings.cacheTtlSeconds() > 0) {
            external = new CachingPolicyDecisionPoint(external, Duration.ofSeconds(settings.cacheTtlSeconds()), clock);
        }
        return new Policies(settings, local, external);
    }

    /** How this deployment authenticates to the PDP: a bearer token, or a shared secret in a header of its own. */
    static Map<String, String> authHeaders(PdpSettings settings) {
        if (settings.auth() == PdpAuth.BEARER) {
            return Map.of("Authorization", "Bearer " + settings.authToken());
        }
        if (settings.auth() == PdpAuth.HEADER) {
            return Map.of(settings.authHeader(), settings.authToken());
        }
        return Map.of();
    }

    /**
     * The URLs an operator configured, which the outbound policy lets through wherever they resolve: the PDP, its
     * evaluation endpoint, and - when discovering - its metadata document (AuthZEN 1.0 §9.2), which sits at the root of
     * the PDP's host, outside a PDP path such as {@code /tenant1}.
     */
    static String[] trustedUrls(PdpSettings settings) {
        if (settings.url() == null) {
            return settings.evaluationUrl() == null ? new String[0] : new String[] {settings.evaluationUrl()};
        }
        URI pdp = URI.create(settings.url());
        String metadata = pdp.getScheme() + "://" + pdp.getRawAuthority() + "/.well-known/authzen-configuration";
        return settings.evaluationUrl() == null ? new String[] {settings.url(), metadata}
                : new String[] {settings.url(), metadata, settings.evaluationUrl()};
    }
}
