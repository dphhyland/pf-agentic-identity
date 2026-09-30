/*
 * device-enrolment's outbound calls - the authority's hosted-entity API, its token endpoint and PingOne's JWKS -
 * through platform's OutboundHttp: each ends at its deadline however the peer stalls, reads no more than the cap, and
 * checks the peer's certificate names its host.
 */
package com.pingidentity.ps.oidf.enrolment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.http.AddressPolicy;
import com.pingidentity.ps.oidf.platform.http.OutboundHttp;
import com.pingidentity.ps.oidf.platform.http.TlsTrust;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class EnrolmentTransportTest {

    private static final Duration SHORT = Duration.ofMillis(600);
    private static final String CREATED = "{\"entityId\":\"https://authority.example/federation/agents/a1\"}";

    private static HostedEntityRegistrar.PingFederate registrar(String url, TlsTrust trust, Duration total) {
        return new HostedEntityRegistrar.PingFederate("https://authority.example", url, null, trust, total,
                http -> new AuthorityCredentials.StaticBearer("admin-token"));
    }

    private static String register(HostedEntityRegistrar registrar) throws EnrolmentException {
        return registrar.register("a1", Map.of("kty", "EC"), Map.of(), null, null);
    }

    private static OutboundHttp open(TlsTrust trust) {
        return OutboundHttp.builder(AddressPolicy.builder().allowHttp(true).allowPrivateNetworks(true).build()).tls(trust)
                .build();
    }

    /** Runs {@code call}, which must fail as {@code error} about {@code deadline} in, naming one of {@code reasons}. */
    private static EnrolmentException failsAt(Duration deadline, String error, Executable call, String... reasons) {
        long started = System.nanoTime();
        EnrolmentException e = assertThrows(EnrolmentException.class, call);
        long elapsedMs = (System.nanoTime() - started) / 1_000_000;
        assertTrue(elapsedMs >= deadline.toMillis() - 50 && elapsedMs < deadline.toMillis() + 1_500,
                "gave up after " + elapsedMs + " ms against a " + deadline.toMillis() + " ms deadline");
        assertEquals(error, e.error(), e.getMessage());
        assertTrue(List.of(reasons).stream().anyMatch(r -> e.getMessage().contains(": " + r + ": ")), e.getMessage());
        return e;
    }

    @Test
    void theDeadlinesAreTenSecondsOnTheWholeExchange() {
        assertEquals(Duration.ofSeconds(10), HostedEntityRegistrar.PingFederate.TOTAL_TIMEOUT);
        assertEquals(Duration.ofSeconds(10), PingOneIdTokenVerifier.HttpJwksSource.TOTAL_TIMEOUT);
    }

    // ─────────────────────────────── the authority ───────────────────────────────

    @Test
    void anAuthorityThatNeverAnswersOrDribblesEndsAtTheDeadline() throws Exception {
        try (OutboundPeer stalling = OutboundPeer.stalling(); OutboundPeer dribbling = OutboundPeer.dribbling(201)) {
            failsAt(SHORT, EnrolmentException.SERVER_ERROR, () -> register(registrar(stalling.url(""), TlsTrust.jvmDefault(),
                    SHORT)), "HEADER_TIMEOUT", "DEADLINE");
            failsAt(SHORT, EnrolmentException.SERVER_ERROR, () -> register(registrar(dribbling.url(""), TlsTrust.jvmDefault(),
                    SHORT)), "DEADLINE");
            assertEquals("closed", stalling.closed());
            assertEquals("closed", dribbling.closed());
        }
    }

    @Test
    void anAuthorityAnswerOverTheCapIsRefused() throws Exception {
        try (OutboundPeer peer = OutboundPeer.plain(OutboundPeer.oversize(201, 300 * 1024))) {
            EnrolmentException e = assertThrows(EnrolmentException.class,
                    () -> register(registrar(peer.url(""), TlsTrust.jvmDefault(), SHORT)));
            assertTrue(e.getMessage().contains(": BODY_TOO_LARGE: "), e.getMessage());
        }
    }

    @Test
    void theAuthoritysTokenEndpointEndsAtItsDeadline() throws Exception {
        try (OutboundPeer peer = OutboundPeer.stalling()) {
            AuthorityCredentials.ClientCredentials credentials = new AuthorityCredentials.ClientCredentials(
                    URI.create(peer.url("/as/token.oauth2")), AuthorityCredentials.ClientAuth.clientSecretBasic("c", "s"),
                    DeploymentProfile.DEVELOPMENT, open(TlsTrust.jvmDefault()), SHORT, Clock.systemUTC());
            failsAt(SHORT, EnrolmentException.SERVER_ERROR, () -> credentials.headers("POST",
                    URI.create("https://authority.example/federation/agents")), "HEADER_TIMEOUT", "DEADLINE");
            assertEquals("POST /as/token.oauth2 HTTP/1.1", peer.requests.poll(1, TimeUnit.SECONDS).requestLine());
        }
    }

    /**
     * The URLs the operator configured are exempt from the scheme and address rules - here both on loopback over
     * http, the token endpoint on another origin - and nothing else is.
     */
    @Test
    void theConfiguredAuthorityAndTokenEndpointAreReachedAndNothingElse() throws Exception {
        try (OutboundPeer api = OutboundPeer.plain(OutboundPeer.answer(201, CREATED));
             OutboundPeer token = OutboundPeer.plain(OutboundPeer.answer(200,
                     "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":300}"))) {
            HostedEntityRegistrar.PingFederate registrar = HostedEntityRegistrar.PingFederate.of("https://authority.example",
                    new AuthorityCredentials.Settings(api.url(""), null, "c", "s", null, token.url("/as/token.oauth2")), false,
                    DeploymentProfile.DEVELOPMENT);
            assertEquals("https://authority.example/federation/agents/a1", register(registrar));
            assertEquals("Bearer at", api.requests.poll(1, TimeUnit.SECONDS).header("Authorization"));

            AddressPolicy policy = AddressPolicy.builder().trusting(api.url(""), null).build();
            assertThrows(Exception.class, () -> policy.check(token.url("/as/token.oauth2")),
                    "an address the operator did not configure is held to the rules");
        }
    }

    /**
     * TLS: an authority whose certificate a CA made for this run signed, trusted by that CA alone, answers; one whose
     * certificate names another host is refused in the handshake.
     */
    @Test
    void theAuthoritysCertificateMustNameItsHost() throws Exception {
        OutboundPeer.TestCa ca = OutboundPeer.TestCa.get();
        TlsTrust trust = TlsTrust.caCertificates(List.of(ca.ca));
        try (OutboundPeer right = OutboundPeer.tls(ca.server("localhost"), OutboundPeer.answer(201, CREATED));
             OutboundPeer wrong = OutboundPeer.tls(ca.server("other.test"), OutboundPeer.answer(201, CREATED))) {
            assertEquals("https://authority.example/federation/agents/a1",
                    register(registrar(right.url(""), trust, Duration.ofSeconds(5))));
            EnrolmentException e = assertThrows(EnrolmentException.class,
                    () -> register(registrar(wrong.url(""), trust, Duration.ofSeconds(5))));
            assertTrue(e.getMessage().contains(": TLS: "), e.getMessage());
        }
    }

    // ─────────────────────────────── PingOne's JWKS ───────────────────────────────

    private static PingOneIdTokenVerifier.HttpJwksSource jwks(String url, TlsTrust trust, Duration total) {
        return new PingOneIdTokenVerifier.HttpJwksSource(url, 60, open(trust), total);
    }

    @Test
    void aJwksEndpointThatNeverAnswersOrDribblesEndsAtTheDeadline() throws Exception {
        try (OutboundPeer stalling = OutboundPeer.stalling(); OutboundPeer dribbling = OutboundPeer.dribbling(200)) {
            failsAt(SHORT, EnrolmentException.USER_AUTHENTICATION_FAILED,
                    () -> jwks(stalling.url("/jwks"), TlsTrust.jvmDefault(), SHORT).find("k"), "HEADER_TIMEOUT", "DEADLINE");
            failsAt(SHORT, EnrolmentException.USER_AUTHENTICATION_FAILED,
                    () -> jwks(dribbling.url("/jwks"), TlsTrust.jvmDefault(), SHORT).find("k"), "DEADLINE");
        }
    }

    @Test
    void aJwksOverTheCapOrNotOkIsRefused() throws Exception {
        try (OutboundPeer big = OutboundPeer.plain(OutboundPeer.oversize(200, 300 * 1024));
             OutboundPeer missing = OutboundPeer.plain(OutboundPeer.answer(404, "{}"))) {
            EnrolmentException e = assertThrows(EnrolmentException.class,
                    () -> jwks(big.url("/jwks"), TlsTrust.jvmDefault(), SHORT).find("k"));
            assertTrue(e.getMessage().contains(": BODY_TOO_LARGE: "), e.getMessage());
            EnrolmentException notFound = assertThrows(EnrolmentException.class,
                    () -> jwks(missing.url("/jwks"), TlsTrust.jvmDefault(), SHORT).find("k"));
            assertEquals("PingOne JWKS returned HTTP 404", notFound.getMessage());
        }
    }

    @Test
    void aJwksThatIsNotAKeySetIsRefused() throws Exception {
        try (OutboundPeer peer = OutboundPeer.plain(OutboundPeer.answer(200, "not a key set"))) {
            EnrolmentException e = assertThrows(EnrolmentException.class,
                    () -> jwks(peer.url("/jwks"), TlsTrust.jvmDefault(), SHORT).find("k"));
            assertEquals(EnrolmentException.USER_AUTHENTICATION_FAILED, e.error());
            assertEquals("PingOne JWKS is not a valid key set", e.getMessage());
        }
    }

    /** PingOne is public: the fetch rules refuse a plaintext or private JWKS unless OIDF_FETCH_* widen them. */
    @Test
    void pingOnesJwksIsHeldToTheFetchRules() throws Exception {
        try (OutboundPeer peer = OutboundPeer.plain(OutboundPeer.answer(200, "{\"keys\":[]}"))) {
            EnrolmentException e = assertThrows(EnrolmentException.class,
                    () -> new PingOneIdTokenVerifier.HttpJwksSource(peer.url("/jwks"), 60).find("k"));
            assertTrue(e.getMessage().contains(": REFUSED_URL: "), e.getMessage());
            assertTrue(peer.requests.isEmpty(), "nothing was sent");
        }
    }

    @Test
    void pingOnesCertificateMustNameItsHost() throws Exception {
        OutboundPeer.TestCa ca = OutboundPeer.TestCa.get();
        TlsTrust trust = TlsTrust.caCertificates(List.of(ca.ca));
        try (OutboundPeer right = OutboundPeer.tls(ca.server("localhost"), OutboundPeer.answer(200, "{\"keys\":[]}"));
             OutboundPeer wrong = OutboundPeer.tls(ca.server("other.test"), OutboundPeer.answer(200, "{\"keys\":[]}"))) {
            assertEquals(null, jwks(right.url("/jwks"), trust, Duration.ofSeconds(5)).find("k"), "an empty set has no key");
            EnrolmentException e = assertThrows(EnrolmentException.class,
                    () -> jwks(wrong.url("/jwks"), trust, Duration.ofSeconds(5)).find("k"));
            assertTrue(e.getMessage().contains(": TLS: "), e.getMessage());
        }
    }
}
