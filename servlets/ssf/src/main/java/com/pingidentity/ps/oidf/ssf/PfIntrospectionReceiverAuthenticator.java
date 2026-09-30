/*
 * Receiver authenticator backed by PingFederate's RFC 7662 token introspection endpoint, through platform's
 * TokenIntrospector.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.platform.auth.ClientAuthentication;
import com.pingidentity.ps.oidf.platform.auth.Introspection;
import com.pingidentity.ps.oidf.platform.auth.IntrospectionException;
import com.pingidentity.ps.oidf.platform.auth.TokenIntrospector;
import com.pingidentity.ps.oidf.platform.http.AddressPolicy;
import com.pingidentity.ps.oidf.platform.http.OutboundHttp;
import com.pingidentity.ps.oidf.platform.http.TlsTrust;
import java.net.URI;
import java.time.Clock;
import java.util.LinkedHashSet;
import java.util.Objects;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Validates a receiver's or a provisioner's bearer token by asking PingFederate's OAuth 2.0 token introspection endpoint
 * (RFC 7662) - the token was issued by PingFederate itself, so PingFederate is the authority on whether it is active and
 * which scopes it carries. A thin adapter over platform's {@link TokenIntrospector} (plan items S8b and S5d's SSF
 * introspection site), which bounds the call - 1 s to connect, 2.5 s in all, a 64 KiB answer - and reads the answer
 * strictly; SSF's own JDK client, which had no timeout, is gone.
 *
 * <p>What it holds the answer to:
 * <ul>
 *   <li>{@code active} must be {@code true}; anything else is an inactive token (401).</li>
 *   <li>{@code exp}, when present, must be in the future and {@code nbf}, when present, not: a token past its lifetime
 *       is refused even if the server's answer was stale.</li>
 *   <li>{@code aud}, when the answer carries one, must contain the transmitter's issuer ({@code OIDF_SSF_ISSUER}): a
 *       token PingFederate minted for another resource is not a key to this one. An answer with no {@code aud} is
 *       accepted, as RFC 7662 §2.2 makes the member optional and PingFederate's reference tokens carry none unless the
 *       access token manager adds one.</li>
 *   <li>{@code client_id} must be present: the stream a receiver may touch is decided by it ({@link StreamAccess}).</li>
 *   <li>A token bound to a key or a certificate ({@code cnf.jkt} or {@code cnf.x5t#S256}, which PingFederate 13.1.3
 *       returns for a DPoP-bound token - finding U-0030) is refused: the SSF endpoints take a plain {@code Bearer}
 *       token and have no proof to check it against, and RFC 9449 §7.2 says a resource that takes both "MUST reject a
 *       DPoP-bound access token received as a bearer token". The SSF receivers this repository knows - the conformance
 *       suite's and pf-oidf-modules' probe - send bearer tokens (checked 2026-09-30), so SSF's receivers stay on bearer
 *       tokens; they are not operators, and the operator authenticator's DPoP rule is not theirs.</li>
 * </ul>
 * No usable answer - the endpoint unreachable, slow, answering anything but 200 or a body RFC 7662 does not allow - is a
 * {@link ReceiverAuthException}, which the servlets answer 503: the token is neither accepted nor called inactive when
 * PingFederate has not said which it is.
 *
 * <p>Introspection is a confidential-client call: the module authenticates to the endpoint with its own client id and
 * secret ({@code client_secret_basic}). Configure the endpoint (default {@code <issuer>/as/introspect.oauth2}) and
 * credentials through {@link SsfConfiguration}.
 */
public final class PfIntrospectionReceiverAuthenticator implements ReceiverAuthenticator {

    private static final Log LOGGER = LogFactory.getLog(PfIntrospectionReceiverAuthenticator.class);

    /** The switch that trusts any certificate on the introspection call (init-param {@code introspectionInsecureTls}). */
    static final String INTROSPECTION_INSECURE_TLS = "OIDF_SSF_INTROSPECTION_INSECURE_TLS";

    private final TokenIntrospector introspector;
    private final String audience;
    private final Clock clock;

    /**
     * @param introspector the introspection client
     * @param audience     the transmitter's issuer: an answer's {@code aud}, when it has one, must contain it; null
     *                     checks no audience
     */
    public PfIntrospectionReceiverAuthenticator(TokenIntrospector introspector, String audience, Clock clock) {
        this.introspector = Objects.requireNonNull(introspector, "introspector");
        this.audience = audience;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * The runtime authenticator: {@code endpoint} asked through platform's outbound HTTP with {@code client_secret_basic}.
     * {@code trustAllTls} trusts any certificate chain through platform's {@link TlsTrust#insecureIf}, for a development
     * PingFederate serving self-signed TLS; the host name is still checked.
     *
     * @param audience the transmitter's issuer ({@code OIDF_SSF_ISSUER}), which an answer's {@code aud} must contain
     */
    public static PfIntrospectionReceiverAuthenticator forEndpoint(String endpoint, String clientId, String clientSecret,
                                                                   boolean trustAllTls, String audience) {
        Objects.requireNonNull(endpoint, "introspection endpoint");
        OutboundHttp http = OutboundHttp.builder(AddressPolicy.builder().trusting(endpoint).build())
                .tls(TlsTrust.insecureIf(INTROSPECTION_INSECURE_TLS, trustAllTls))
                .build();
        TokenIntrospector introspector = TokenIntrospector.builder(http, URI.create(endpoint),
                ClientAuthentication.clientSecretBasic(clientId, () -> clientSecret)).build();
        return new PfIntrospectionReceiverAuthenticator(introspector, audience, Clock.systemUTC());
    }

    @Override
    public AuthContext authenticate(String bearerToken) throws ReceiverAuthException {
        Introspection answer;
        try {
            answer = this.introspector.introspect(bearerToken);
        } catch (IntrospectionException e) {
            throw new ReceiverAuthException("token introspection failed: " + e.getMessage(), e);
        }
        String refusal = refusal(answer, this.audience, this.clock.instant().getEpochSecond());
        if (refusal != null) {
            if (answer.active()) {
                LOGGER.info((Object) ("SSF refused an active token: " + refusal));
            }
            return AuthContext.inactive();
        }
        return AuthContext.active(answer.clientId(), new LinkedHashSet<>(answer.scopes()));
    }

    /** Why {@code answer} does not admit a caller at {@code nowSeconds}, or null when it does. */
    static String refusal(Introspection answer, String audience, long nowSeconds) {
        if (!answer.active()) {
            return "not active";
        }
        if (answer.exp() != null && answer.exp() <= nowSeconds) {
            return "expired";
        }
        if (answer.nbf() != null && answer.nbf() > nowSeconds) {
            return "not yet valid";
        }
        if (audience != null && !answer.audience().isEmpty() && !answer.audience().contains(audience)) {
            return "its aud does not name this transmitter (" + audience + ")";
        }
        if (answer.clientId() == null || answer.clientId().isBlank()) {
            return "it names no client_id";
        }
        if (answer.bound()) {
            return "it is bound to a key or a certificate (cnf), and the SSF endpoints take bearer tokens only";
        }
        return null;
    }
}
