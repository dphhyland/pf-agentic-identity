/*
 * The filter around the policy: whose requests it examines, what reaches PingFederate, what a refusal looks like.
 */
package com.pingidentity.ps.oidf.servlet.fapi2;

import static com.pingidentity.ps.oidf.servlet.fapi2.Fapi2RequestPolicyTest.jwt;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;

class Fapi2ProfileFilterTest {

    private static final String ISSUER = "https://as.example.com";
    private static final String TOKEN_ENDPOINT = ISSUER + "/as/token.oauth2";
    private static final String FAPI_CLIENT = "bank-app";
    private static final String OTHER_CLIENT = "ssf-receiver";

    private static final String RS256_PROOF = jwt("{\"typ\":\"dpop+jwt\",\"alg\":\"RS256\"}", "{}");
    private static final String ES256_PROOF = jwt("{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\"}", "{}");

    private static String assertion(String client, String aud) {
        return jwt("{\"alg\":\"PS256\"}", "{\"iss\":\"" + client + "\",\"sub\":\"" + client + "\",\"aud\":\"" + aud + "\"}");
    }

    private final StringWriter body = new StringWriter();
    private final HttpServletResponse response = mock(HttpServletResponse.class);
    private final FilterChain chain = mock(FilterChain.class);

    /** A filter whose client list comes from the environment, as it does in a deployment. */
    private Fapi2ProfileFilter filterFor(String clients) throws Exception {
        return initialised(mock(FilterConfig.class), name -> Fapi2ProfileFilter.CLIENTS_ENV.equals(name) ? clients : null);
    }

    private Fapi2ProfileFilter initialised(FilterConfig config, Function<String, String> environment) throws Exception {
        when(response.getWriter()).thenReturn(new PrintWriter(body, true));
        Fapi2ProfileFilter f = new Fapi2ProfileFilter(request -> ISSUER, environment);
        f.init(config);
        return f;
    }

    /** A request as the filter sees one. Every argument may be null; proofs are the DPoP headers, in order. */
    private static HttpServletRequest request(String uri, String[] assertions, String clientIdParam, String authorization,
            String... proofs) {
        HttpServletRequest r = mock(HttpServletRequest.class);
        when(r.getMethod()).thenReturn("POST");
        when(r.getServletPath()).thenReturn(uri);
        when(r.getRequestURI()).thenReturn(uri);
        when(r.getParameterValues("client_assertion")).thenReturn(assertions);
        when(r.getParameter("client_id")).thenReturn(clientIdParam);
        when(r.getHeader("Authorization")).thenReturn(authorization);
        when(r.getHeaders("DPoP")).thenReturn(Collections.enumeration(List.of(proofs)));
        return r;
    }

    private static HttpServletRequest tokenRequest(String assertion, String... proofs) {
        return request("/as/token.oauth2", new String[] { assertion }, null, null, proofs);
    }

    private String refusedWith() throws Exception {
        return (String) JsonUtil.parseJson(body.toString()).get("error");
    }

    // ─────────────────────────────── whether it is on, and for whom ───────────────────────────────

    /** Off is the default, and off means untouched - including what it would otherwise refuse. */
    @Test
    void withNoClientNamedItPassesEverythingThrough() throws Exception {
        HttpServletRequest bad = tokenRequest(assertion(FAPI_CLIENT, TOKEN_ENDPOINT), RS256_PROOF);
        for (String setting : new String[] { null, "", "  ", " , ,, " }) {
            FilterChain c = mock(FilterChain.class);
            filterFor(setting).doFilter(bad, response, c);
            verify(c).doFilter(bad, response);
        }
        verify(response, never()).setStatus(anyInt());
    }

    /**
     * The case this design exists for. The OpenID conformance suite's Shared Signals client is not a
     * FAPI client and addresses its assertion to the token endpoint, as OIDC Core says it should. On a
     * server that also has FAPI 2.0 clients, that has to keep working.
     */
    @Test
    void aClientThatIsNotListedIsLeftEntirelyAlone() throws Exception {
        HttpServletRequest ordinary = tokenRequest(assertion(OTHER_CLIENT, TOKEN_ENDPOINT), RS256_PROOF);

        filterFor(FAPI_CLIENT + ", another-bank-app").doFilter(ordinary, response, chain);

        verify(chain).doFilter(ordinary, response);
        verify(response, never()).setStatus(anyInt());
    }

    @Test
    @Requirement({"FAPI2-SP §5.3.2.1(2.8)", "FAPI2-SP §5.4.1(2.1.2.2)"})
    void aListedClientsConformantRequestReachesPingFederateExactlyAsItArrived() throws Exception {
        HttpServletRequest ok = tokenRequest(assertion(FAPI_CLIENT, ISSUER), ES256_PROOF);

        filterFor(" " + FAPI_CLIENT + " ").doFilter(ok, response, chain);

        verify(chain).doFilter(ok, response); // the same object: nothing wrapped, nothing rewritten
        verify(response, never()).setStatus(anyInt());
    }

    /**
     * Where the list is read from, nearest first: the filter's own init-param, then the system property
     * (PingFederate loads run.properties as system properties), then the environment. A blank value at
     * one level is not an answer, so the next is asked.
     */
    @Test
    void theListIsReadFromInitParamThenSystemPropertyThenEnvironment() throws Exception {
        HttpServletRequest bad = tokenRequest(assertion(FAPI_CLIENT, TOKEN_ENDPOINT));
        String saved = System.getProperty(Fapi2ProfileFilter.CLIENTS_PROPERTY);
        try {
            System.clearProperty(Fapi2ProfileFilter.CLIENTS_PROPERTY);
            assertRefuses(initialised(configWith(FAPI_CLIENT), name -> OTHER_CLIENT), bad, "the init-param outranks the environment");
            assertRefuses(initialised(null, name -> FAPI_CLIENT), bad, "no FilterConfig at all: the environment still answers");

            System.setProperty(Fapi2ProfileFilter.CLIENTS_PROPERTY, FAPI_CLIENT);
            assertRefuses(initialised(configWith("  "), name -> OTHER_CLIENT), bad, "a blank init-param defers to the system property");

            System.setProperty(Fapi2ProfileFilter.CLIENTS_PROPERTY, "");
            assertRefuses(initialised(configWith(null), name -> FAPI_CLIENT), bad, "a blank system property defers to the environment");
        }
        finally {
            if (saved == null) {
                System.clearProperty(Fapi2ProfileFilter.CLIENTS_PROPERTY);
            } else {
                System.setProperty(Fapi2ProfileFilter.CLIENTS_PROPERTY, saved);
            }
        }
    }

    private static FilterConfig configWith(String clients) {
        FilterConfig config = mock(FilterConfig.class);
        when(config.getInitParameter("clients")).thenReturn(clients);
        return config;
    }

    private void assertRefuses(Fapi2ProfileFilter f, HttpServletRequest bad, String why) throws Exception {
        FilterChain c = mock(FilterChain.class);
        f.doFilter(bad, response, c);
        verify(c, never().description(why)).doFilter(any(), any());
    }

    // ─────────────────────────────── whose request it is ───────────────────────────────

    /** No assertion - mTLS client authentication, say - so the client_id parameter says who is asking. */
    @Test
    @Requirement("FAPI2-SP §5.4.1(2.1.2.2)")
    void withoutAnAssertionTheClientIdParameterNamesTheClient() throws Exception {
        Fapi2ProfileFilter f = filterFor(FAPI_CLIENT);
        HttpServletRequest listed = request("/as/token.oauth2", null, FAPI_CLIENT, null, RS256_PROOF);
        HttpServletRequest unlisted = request("/as/token.oauth2", new String[0], OTHER_CLIENT, null, RS256_PROOF);

        f.doFilter(listed, response, chain);
        f.doFilter(unlisted, response, chain);

        verify(response).setStatus(400);
        verify(chain, never()).doFilter(eq(listed), any());
        verify(chain).doFilter(unlisted, response);
    }

    /** At UserInfo there is only the token, and a JWT access token says whose it is. */
    @Test
    @Requirement({"FAPI2-SP §5.4.1(2.1.2.2)", "RFC9449 §7.1"})
    void atUserInfoTheAccessTokenNamesTheClientAndAWeakProofIs401() throws Exception {
        Fapi2ProfileFilter f = filterFor(FAPI_CLIENT);
        String theirs = "DPoP " + jwt("{\"alg\":\"PS256\"}", "{\"client_id\":\"" + FAPI_CLIENT + "\"}");
        String someoneElses = "DPoP " + jwt("{\"alg\":\"PS256\"}", "{\"client_id\":\"" + OTHER_CLIENT + "\"}");
        HttpServletRequest listed = request("/idp/userinfo.openid", null, " ", theirs, RS256_PROOF);
        HttpServletRequest unlisted = request("/idp/userinfo.openid", null, null, someoneElses, RS256_PROOF);

        f.doFilter(listed, response, chain);
        f.doFilter(unlisted, response, chain);

        verify(response).setStatus(401);
        verify(response).setHeader("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\", algs=\"ES256 EdDSA PS256\"");
        verify(chain, never()).doFilter(eq(listed), any());
        verify(chain).doFilter(unlisted, response);
    }

    /**
     * A reference token names nobody, so under a list the request is not examined - and under "*", which
     * asks no one who they are, it is.
     */
    @Test
    @Requirement("FAPI2-SP §5.4.1(2.1.2.2)")
    void aRequestWhoseClientCannotBeToldIsExaminedOnlyWhenEveryClientIs() throws Exception {
        HttpServletRequest anonymous = request("/idp/userinfo.openid", null, null, "DPoP an-opaque-reference-token", RS256_PROOF);

        filterFor(FAPI_CLIENT).doFilter(anonymous, response, chain);
        verify(chain).doFilter(anonymous, response);

        FilterChain second = mock(FilterChain.class);
        filterFor("*").doFilter(anonymous, response, second);
        verify(second, never()).doFilter(any(), any());
        verify(response).setStatus(401);
    }

    /**
     * Not knowing whose assertion it is must never become a reason to let it past. There is no list to
     * look nobody up in; and PingFederate would refuse it too, since it names no client to authenticate.
     */
    @Test
    void anAssertionThatNamesNobodyIsRefusedWhoeverIsListed() throws Exception {
        for (String unattributable : new String[] { "not-a-jwt", jwt("{\"alg\":\"PS256\"}", "{\"aud\":\"" + ISSUER + "\"}") }) {
            body.getBuffer().setLength(0);
            FilterChain c = mock(FilterChain.class);
            filterFor(FAPI_CLIENT).doFilter(tokenRequest(unattributable), response, c);
            assertEquals("invalid_client", refusedWith());
            verify(c, never()).doFilter(any(), any());
        }
    }

    // ─────────────────────────────── what a listed client may not send ───────────────────────────────

    @Test
    @Requirement("FAPI2-SP §5.3.2.1(2.8)")
    void aMisaddressedAssertionIs401InvalidClientAndNeverReachesPingFederate() throws Exception {
        Fapi2ProfileFilter f = filterFor(FAPI_CLIENT);
        for (String uri : new String[] { "/as/token.oauth2", "/as/par.oauth2", "/as/introspect.oauth2" }) {
            body.getBuffer().setLength(0);
            f.doFilter(request(uri, new String[] { assertion(FAPI_CLIENT, TOKEN_ENDPOINT) }, null, null), response, chain);
            assertEquals("invalid_client", refusedWith(), uri);
        }
        verify(response, times(3)).setStatus(401);
        verify(chain, never()).doFilter(any(), any());
    }

    /**
     * The decoy. Nothing here checks a signature, so a well-addressed assertion is free to forge; if it
     * could stand in front of a genuine one addressed to the token endpoint, the rule would be decoration.
     * Refused in either order, before anyone asks which of the two names the client - and so also when
     * the decoy names a client that is not listed at all.
     */
    @Test
    @Requirement("FAPI2-SP §5.3.2.1(2.8)")
    void aWellAddressedAssertionCannotShieldAMisaddressedOneSentWithIt() throws Exception {
        String good = assertion(FAPI_CLIENT, ISSUER);
        String bad = assertion(FAPI_CLIENT, TOKEN_ENDPOINT);
        String unlistedDecoy = assertion(OTHER_CLIENT, ISSUER);
        Fapi2ProfileFilter f = filterFor(FAPI_CLIENT);
        for (String[] pair : new String[][] { { good, bad }, { bad, good }, { unlistedDecoy, bad }, { good, good } }) {
            body.getBuffer().setLength(0);
            f.doFilter(request("/as/token.oauth2", pair, null, null), response, chain);
            assertEquals("invalid_request", refusedWith());
        }
        verify(response, times(4)).setStatus(400);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    @Requirement({"FAPI2-SP §5.4.1(2.1.2.2)", "RFC9449 §5"})
    void aWeakProofAtAnAuthorizationServerEndpointIs400InvalidDpopProof() throws Exception {
        filterFor(FAPI_CLIENT).doFilter(tokenRequest(assertion(FAPI_CLIENT, ISSUER), RS256_PROOF), response, chain);

        verify(response).setStatus(400);
        assertEquals("invalid_dpop_proof", refusedWith());
        verify(response, never()).setHeader(eq("WWW-Authenticate"), any());
        verify(chain, never()).doFilter(any(), any());
    }

    /** PingFederate refuses two DPoP headers, but only once it is reached; the second must not ride in on the first. */
    @Test
    @Requirement("FAPI2-SP §5.4.1(2.1.2.2)")
    void everyDpopHeaderIsExaminedNotOnlyTheFirst() throws Exception {
        filterFor(FAPI_CLIENT).doFilter(tokenRequest(assertion(FAPI_CLIENT, ISSUER), ES256_PROOF, RS256_PROOF), response, chain);

        verify(response).setStatus(400);
        verify(chain, never()).doFilter(any(), any());
    }

    /** A listed client with nothing to examine: a UserInfo call with a bearer token and no proof. */
    @Test
    void aListedClientsRequestWithNeitherAnAssertionNorAProofPasses() throws Exception {
        HttpServletRequest plain = request("/idp/userinfo.openid", null, FAPI_CLIENT, null);
        HttpServletRequest noHeaders = request("/idp/userinfo.openid", null, FAPI_CLIENT, null);
        when(noHeaders.getHeaders("DPoP")).thenReturn(null); // a container may say null rather than empty

        Fapi2ProfileFilter f = filterFor(FAPI_CLIENT);
        f.doFilter(plain, response, chain);
        f.doFilter(noHeaders, response, chain);

        verify(chain).doFilter(plain, response);
        verify(chain).doFilter(noHeaders, response);
    }

    // ─────────────────────────────── the edges ───────────────────────────────

    /** Not HTTP, so nothing it knows how to read or refuse: handed on, not dropped and not thrown at. */
    @Test
    void aRequestThatIsNotHttpIsHandedOn() throws Exception {
        ServletRequest notHttp = mock(ServletRequest.class);
        ServletResponse notHttpResponse = mock(ServletResponse.class);
        HttpServletRequest http = tokenRequest(assertion(FAPI_CLIENT, TOKEN_ENDPOINT));
        Fapi2ProfileFilter f = filterFor("*");

        f.doFilter(notHttp, response, chain);
        f.doFilter(http, notHttpResponse, chain);

        verify(chain).doFilter(notHttp, response);
        verify(chain).doFilter(http, notHttpResponse);
    }

    @Test
    void aRefusalIsJsonThatMayNotBeCached() throws Exception {
        filterFor("*").doFilter(tokenRequest(assertion(FAPI_CLIENT, TOKEN_ENDPOINT)), response, chain);

        verify(response).setContentType("application/json");
        verify(response).setHeader("Cache-Control", "no-store");
        assertTrue(JsonUtil.parseJson(body.toString()).containsKey("error_description"));
    }
}
