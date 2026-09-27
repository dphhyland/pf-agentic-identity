package com.pingidentity.ps.oidf.rar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.rar.PrincipalResolver.Flow;
import com.pingidentity.ps.oidf.rar.PrincipalResolver.Principal;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The principal per flow, from what PingFederate 13.1.3 passes as the user key (plan "Found while
 * designing" item 1, read with javap 2026-09-27: {@code ClientCredentialsGrantProcessor} passes
 * {@code client.getClientId()}, {@code RefreshTokenGrantProcessor} the grant's unique user identifier,
 * {@code CibaAuthenticationRequestHandler} the {@code IDENTITY_HINT_SUBJECT} attribute, and
 * {@code TokenExchangeRequest} {@code null}).
 */
class PrincipalResolverTest {

    private static final Flow TOKEN_CC = new Flow("client_credentials", "/as/token.oauth2");
    private static final Flow TOKEN_REFRESH = new Flow("refresh_token", "/as/token.oauth2");
    private static final Flow TOKEN_EXCHANGE = new Flow(PrincipalResolver.GRANT_TOKEN_EXCHANGE, "/as/token.oauth2");
    private static final Flow CIBA = new Flow(null, "/as/bc-auth.ciba");
    private static final Flow AUTHORIZE = new Flow(null, "/as/authorization.oauth2");

    private static Principal resolve(Flow flow, String userKey) {
        return PrincipalResolver.resolve(flow, userKey, "client-1", AttestationSubject.empty(), null, false);
    }

    @Test
    void clientCredentialsIsTheClient() {
        assertEquals(new Principal("client-1", "client"), resolve(TOKEN_CC, "client-1"));
        // By grant type even if the key were something else, and by value even if the grant type were unknown.
        assertEquals(new Principal("client-1", "client"), resolve(TOKEN_CC, null));
        assertEquals(new Principal("client-1", "client"), resolve(Flow.UNKNOWN, "client-1"));
        assertEquals(new Principal("client-1", "client"), resolve(AUTHORIZE, "client-1"));
    }

    @Test
    void refreshIsAuthenticatedViaTheGrant() {
        assertEquals(new Principal("alice", "authenticated"), resolve(TOKEN_REFRESH, "alice"));
        assertEquals(new Principal(null, "none"), resolve(TOKEN_REFRESH, " "));
    }

    @Test
    void cibaIsTheIdentityHint() {
        assertEquals(new Principal("alice", "identity_hint"), resolve(CIBA, "alice"));
        assertEquals(new Principal(null, "none"), resolve(CIBA, null));
    }

    @Test
    void theAuthorizationEndpointAndAnyOtherKeyIsAuthenticated() {
        assertEquals(new Principal("alice", "authenticated"), resolve(AUTHORIZE, "alice"));
        assertEquals(new Principal("alice", "authenticated"), resolve(Flow.UNKNOWN, "alice"));
        assertEquals(new Principal("alice", "authenticated"), resolve(null, "alice"));
        assertEquals(new Principal(null, "none"), resolve(null, null));
    }

    @Test
    void tokenExchangeIsTheVerifiedSubjectTokenSubjectOrNobody() {
        assertEquals(new Principal(null, "none"), resolve(TOKEN_EXCHANGE, null));
        // Even a user key would not be believed on this grant; PingFederate passes none, and a filter that verified
        // the subject token publishes its subject under the one key the resolver reads.
        assertEquals(new Principal(null, "none"), resolve(TOKEN_EXCHANGE, "alice"));
        AttestationSubject verified = new AttestationSubject("c", "c", List.of(), Map.of(), null, null, null, "alice");
        assertEquals(new Principal("alice", "subject_token"),
                PrincipalResolver.resolve(TOKEN_EXCHANGE, null, "client-1", verified, null, false));
        assertEquals(new Principal(null, "none"),
                PrincipalResolver.resolve(TOKEN_EXCHANGE, null, "client-1", null, null, false));
    }

    @Test
    void aCallerAssertedNameFillsOnlyAGapAndOnlyWhenHonoured() {
        assertEquals(new Principal("alice", "client_asserted"),
                PrincipalResolver.resolve(AUTHORIZE, null, "client-1", AttestationSubject.empty(), "alice", true));
        assertEquals(new Principal(null, "none"),
                PrincipalResolver.resolve(AUTHORIZE, null, "client-1", AttestationSubject.empty(), "alice", false));
        assertEquals(new Principal(null, "none"),
                PrincipalResolver.resolve(AUTHORIZE, null, "client-1", AttestationSubject.empty(), " ", true));
        assertEquals(new Principal("bob", "authenticated"),
                PrincipalResolver.resolve(AUTHORIZE, "bob", "client-1", AttestationSubject.empty(), "alice", true));
        assertEquals(new Principal("client-1", "client"),
                PrincipalResolver.resolve(TOKEN_CC, "client-1", "client-1", AttestationSubject.empty(), "alice", true),
                "a client-credentials caller cannot name a user even in development");
    }

    @Test
    void theTypesThatNeedAPersonRefuseNobodyAndTheClient() {
        Set<String> types = Set.of("payment_initiation");
        assertTrue(PrincipalResolver.requiresAuthenticatedPrincipal("payment_initiation", new Principal(null, "none"), types));
        assertTrue(PrincipalResolver.requiresAuthenticatedPrincipal("payment_initiation", new Principal("c", "client"), types));
        assertTrue(PrincipalResolver.requiresAuthenticatedPrincipal("payment_initiation", null, types));
        assertFalse(PrincipalResolver.requiresAuthenticatedPrincipal("payment_initiation", new Principal("a", "authenticated"), types));
        assertFalse(PrincipalResolver.requiresAuthenticatedPrincipal("payment_initiation", new Principal("a", "identity_hint"), types));
        assertFalse(PrincipalResolver.requiresAuthenticatedPrincipal("payment_initiation", new Principal("a", "subject_token"), types));
        assertFalse(PrincipalResolver.requiresAuthenticatedPrincipal("payment_initiation", new Principal("a", "client_asserted"), types));
        assertFalse(PrincipalResolver.requiresAuthenticatedPrincipal("sales_agent", new Principal(null, "none"), types));
        assertFalse(PrincipalResolver.requiresAuthenticatedPrincipal(null, new Principal(null, "none"), types));
        assertFalse(PrincipalResolver.requiresAuthenticatedPrincipal("payment_initiation", new Principal(null, "none"), null));
    }

    @Test
    void theFlowReadsItself() {
        assertTrue(TOKEN_CC.isClientCredentials());
        assertTrue(TOKEN_REFRESH.isRefresh());
        assertTrue(TOKEN_EXCHANGE.isTokenExchange());
        assertTrue(CIBA.isCiba());
        assertFalse(AUTHORIZE.isCiba());
        assertFalse(Flow.UNKNOWN.isCiba());
        assertFalse(Flow.UNKNOWN.isClientCredentials());
        assertFalse(Flow.UNKNOWN.isRefresh());
        assertFalse(Flow.UNKNOWN.isTokenExchange());
    }

    @Test
    void thePrincipalIsLoggedAsAHash() {
        String alice = PrincipalResolver.hashForLog("alice");
        assertTrue(alice.matches("sha256:[0-9a-f]{16}"), alice);
        assertEquals(alice, PrincipalResolver.hashForLog("alice"));
        assertNotEquals(alice, PrincipalResolver.hashForLog("alicE"));
        assertEquals("-", PrincipalResolver.hashForLog(null));
        // SHA-256("alice") starts 2bd806c9...: the first 16 hex characters, and nothing of the name itself.
        assertEquals("sha256:2bd806c97f0e00af", alice);
        assertNull(new Principal(null, "none").subject());
    }
}
