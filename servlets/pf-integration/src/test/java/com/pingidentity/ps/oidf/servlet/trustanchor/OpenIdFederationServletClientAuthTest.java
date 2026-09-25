package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.EndpointAuthPolicy;
import com.pingidentity.ps.oidf.federation.FederationConfiguration;
import com.pingidentity.ps.oidf.federation.FederationService;
import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import com.pingidentity.ps.oidf.federation.testkit.Federation;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.federation.testkit.Statements;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.trustmark.InMemoryTrustMarkRegistry;
import com.pingidentity.ps.oidf.trustmark.TrustMarkIssuer;
import com.pingidentity.ps.oidf.trustmark.TrustMarkType;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.Test;

/**
 * Client authentication at the federation endpoints over HTTP (OpenID Federation 1.0 §8.8): an endpoint that requires it
 * refuses a GET, a client that authenticates POSTs its assertion and the endpoint's parameters in the body, an endpoint
 * that takes none refuses an assertion, and what a client asks for once it is known.
 */
class OpenIdFederationServletClientAuthTest {
    private static final String PF = "https://pf.example";
    private static final String TA = "https://ta.example.com";
    private static final String CLIENT = "https://client.example.com";
    private static final String HOSTED = "https://pf.example/agents/a1";
    private static final String OPEN = "https://pf.example/marks/open";
    private static final String TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final PublicJsonWebKey PF_KEY = Keys.rsa("pf-1");
    private static final PublicJsonWebKey HOSTED_KEY = Keys.ec("a1-1");

    private final MutableClock clock = MutableClock.startingNow();
    private final Federation federation = Federation.builder(this.clock).anchor(TA).leaf(CLIENT, TA).build();
    private final InMemoryTrustMarkRegistry registry = new InMemoryTrustMarkRegistry(this.clock);
    private final Set<String> spent = new HashSet<>();
    private int jti;

    private OpenIdFederationServlet servlet(String endpointAuth) {
        Map<String, String> params = Map.of("trustAnchorIssuers", PF, "resolveDiscovery", "any");
        FederationConfiguration configuration = FederationConfiguration.fromServletConfig(new ServletConfig() {
            @Override
            public String getServletName() {
                return "federation";
            }

            @Override
            public ServletContext getServletContext() {
                return null;
            }

            @Override
            public String getInitParameter(String name) {
                return params.get(name);
            }

            @Override
            public Enumeration<String> getInitParameterNames() {
                return Collections.enumeration(params.keySet());
            }
        });
        FederationService service = FederationService.builder(configuration, Keys.signingKeys(PF_KEY))
                .hostedSubordinateLookup(sub -> HOSTED.equals(sub) ? Map.of("jwks", Keys.publicJwks(HOSTED_KEY)) : null)
                .hosting(() -> true)
                .resolver(this.federation.trustAnchors(), this.federation.gateway(TA), Set.of(), ValidatorOptions.defaults().withClock(this.clock))
                .trustMarkIssuing(new TrustMarkIssuer(Map.of(OPEN, new TrustMarkType(OPEN, 3600, TrustMarkType.Subjects.ANY, null, null, null)),
                        this.registry, id -> false, this.clock))
                .endpointAuth(EndpointAuthPolicy.parse(endpointAuth, List.of("ES256")), (client, id, ttl) -> this.spent.add(client + " " + id))
                .clock(this.clock)
                .build();
        return new OpenIdFederationServlet(service, configuration, req -> PF);
    }

    /** A client assertion from CLIENT for this entity, with a new jti each time. */
    private String assertion() {
        return Statements.spec(null).claim("iss", CLIENT).claim("sub", CLIENT).claim("aud", PF).claim("jti", "jti-" + ++this.jti)
                .exp(this.clock.instant().getEpochSecond() + 60).sign(this.federation.key(CLIENT), this.clock);
    }

    /** One request, answered. */
    private static final class Exchange {
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final StringWriter body = new StringWriter();

        Exchange(OpenIdFederationServlet servlet, String method, String path, Map<String, String> params, String queryString) throws Exception {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getServletPath()).thenReturn(path);
            when(request.getQueryString()).thenReturn(queryString);
            for (Map.Entry<String, String> param : params.entrySet()) {
                when(request.getParameter(param.getKey())).thenReturn(param.getValue());
                when(request.getParameterValues(param.getKey())).thenReturn(new String[] {param.getValue()});
            }
            when(this.response.getWriter()).thenReturn(new PrintWriter(this.body));
            if ("POST".equals(method)) {
                servlet.doPost(request, this.response);
            } else {
                servlet.doGet(request, this.response);
            }
        }

        Map<String, Object> error(int status) throws Exception {
            verify(this.response).setStatus(status);
            verify(this.response).setContentType("application/json");
            return JsonUtil.parseJson(this.body.toString());
        }
    }

    private Exchange get(String endpointAuth, String path, Map<String, String> params) throws Exception {
        return new Exchange(this.servlet(endpointAuth), "GET", path, params, "q");
    }

    private Exchange post(String endpointAuth, String path, Map<String, String> params) throws Exception {
        return new Exchange(this.servlet(endpointAuth), "POST", path, params, null);
    }

    private Map<String, String> authenticated(String... params) {
        Map<String, String> all = new java.util.HashMap<>(Map.of("client_assertion", this.assertion(), "client_assertion_type", TYPE));
        for (int i = 0; i < params.length; i += 2) {
            all.put(params[i], params[i + 1]);
        }
        return all;
    }

    @Test
    @Requirement({"OIDFED §8.8(1)", "OIDFED §8.8(2)"})
    void anEndpointThatRequiresClientAuthenticationRefusesAGet() throws Exception {
        Exchange exchange = this.get("{\"federation_fetch_endpoint\": \"required\"}", "/federation/fetch", Map.of("sub", HOSTED));

        assertEquals("invalid_client", exchange.error(401).get("error"));
        assertEquals("invalid_client", this.post("{\"federation_fetch_endpoint\": \"required\"}", "/federation/fetch", Map.of("sub", HOSTED))
                .error(401).get("error"), "nor does a POST without an assertion get through");
    }

    @Test
    @Requirement({"OIDFED §8.8(2)", "OIDFED §8.1.1(3)"})
    void aClientThatAuthenticatesPostsTheEndpointsParametersInTheBody() throws Exception {
        Exchange exchange = this.post("{\"federation_fetch_endpoint\": \"required\"}", "/federation/fetch", this.authenticated("sub", HOSTED));

        verify(exchange.response).setStatus(200);
        verify(exchange.response).setContentType("application/entity-statement+jwt");
        assertEquals(HOSTED, JwtCodec.parseUnverifiedClaims(exchange.body.toString()).getSubject());
    }

    @Test
    @Requirement("OIDFED §8.8(2)")
    void anAssertionIsNeverTakenFromAQueryString() throws Exception {
        assertEquals("invalid_request", this.get("{\"federation_resolve_endpoint\": \"optional\"}", "/federation/resolve",
                this.authenticated("sub", CLIENT, "trust_anchor", TA)).error(400).get("error"));
        assertEquals("invalid_request", this.get("{\"federation_resolve_endpoint\": \"optional\"}", "/federation/resolve",
                Map.of("client_assertion_type", TYPE)).error(400).get("error"));
        Exchange queried = new Exchange(this.servlet("{\"federation_resolve_endpoint\": \"optional\"}"), "POST", "/federation/resolve",
                this.authenticated("sub", CLIENT, "trust_anchor", TA), "sub=" + CLIENT);
        assertEquals("invalid_request", queried.error(400).get("error"), "an authenticated request's parameters are in its body");
        assertEquals(0, this.spent.size(), "refused before its assertion was looked at");
    }

    @Test
    @Requirement({"OIDFED §8.3.1(3)", "OIDFED §8.3.2(7)", "OIDFED §8.8.1(3)"})
    void anOptionalEndpointTakesAnUnauthenticatedGetOrAnAuthenticatedPostAndAddressesTheAnswerToTheClient() throws Exception {
        String optional = "{\"federation_resolve_endpoint\": \"optional\"}";
        Exchange anonymous = this.get(optional, "/federation/resolve", Map.of("sub", CLIENT, "trust_anchor", TA));
        verify(anonymous.response).setStatus(200);
        assertNull(JwtCodec.parseUnverifiedClaims(anonymous.body.toString()).getClaimValue("aud"), "no aud for an unauthenticated request");

        Exchange known = this.post(optional, "/federation/resolve", this.authenticated("sub", CLIENT, "trust_anchor", TA));
        verify(known.response).setStatus(200);
        verify(known.response).setContentType("application/resolve-response+jwt");
        assertEquals(CLIENT, JwtCodec.parseUnverifiedClaims(known.body.toString()).getClaimValue("aud"),
                "the requesting party's Entity Identifier, and nothing else");

        assertEquals("invalid_request", this.post(optional, "/federation/resolve", Map.of("sub", CLIENT, "trust_anchor", TA))
                .error(400).get("error"), "a POST here is how a client authenticates, so one that doesn't is refused");
    }

    @Test
    @Requirement({"OIDFED §8.8(1)", "OIDFED §8.8.1(6)"})
    void anEndpointThatTakesNoneRefusesAnAssertionAndAPost() throws Exception {
        String none = "{\"federation_fetch_endpoint\": \"required\"}";
        assertEquals("invalid_request", this.post(none, "/federation/list", this.authenticated()).error(400).get("error"));

        Exchange post = this.post(none, "/federation/list", Map.of());
        assertEquals("invalid_request", post.error(405).get("error"));
        verify(post.response).setHeader("Allow", "GET");
        Exchange configuration = this.post(none, "/.well-known/openid-federation", Map.of());
        assertEquals("invalid_request", configuration.error(405).get("error"), "the Entity Configuration is never a §8.8 endpoint");
    }

    @Test
    @Requirement({"OIDFED §8.6.1(3)", "OIDFED §8.8(2)"})
    void anAuthenticatedClientIsGivenItsOwnTrustMarks() throws Exception {
        this.registry.grant(OPEN, CLIENT, null, null);
        this.registry.grant(OPEN, HOSTED, null, null);
        String required = "{\"federation_trust_mark_endpoint\": \"required\"}";

        Exchange own = this.post(required, "/federation/trust_mark", this.authenticated("trust_mark_type", OPEN, "sub", CLIENT));
        verify(own.response).setStatus(200);
        verify(own.response).setContentType("application/trust-mark+jwt");
        assertEquals(CLIENT, JwtCodec.parseUnverifiedClaims(own.body.toString()).getSubject());

        assertEquals("invalid_request", this.post(required, "/federation/trust_mark",
                this.authenticated("trust_mark_type", OPEN, "sub", HOSTED)).error(400).get("error"));
        assertEquals("invalid_request", this.post(required, "/federation/trust_mark", this.authenticated("trust_mark_type", OPEN))
                .error(400).get("error"), "and still has to name itself");
        assertEquals("invalid_client", this.get(required, "/federation/trust_mark", Map.of("trust_mark_type", OPEN, "sub", CLIENT))
                .error(401).get("error"));
    }

    @Test
    @Requirement({"OIDFED §8.4.1(3)", "OIDFED §8.8(1)"})
    void theStatusEndpointCanRequireClientAuthenticationToo() throws Exception {
        this.registry.grant(OPEN, CLIENT, null, null);
        String mark = this.get("{}", "/federation/trust_mark", Map.of("trust_mark_type", OPEN, "sub", CLIENT)).body.toString();
        String required = "{\"federation_trust_mark_status_endpoint\": \"required\"}";

        assertEquals("invalid_client", this.post(required, "/federation/trust_mark_status", Map.of("trust_mark", mark)).error(401).get("error"));
        Exchange known = this.post(required, "/federation/trust_mark_status", this.authenticated("trust_mark", mark));
        verify(known.response).setStatus(200);
        assertEquals("active", JwtCodec.parseUnverifiedClaims(known.body.toString()).getClaimValue("status"));
        Exchange get = this.get(required, "/federation/trust_mark_status", Map.of("trust_mark", mark));
        assertEquals("invalid_request", get.error(405).get("error"), "still POST only");
    }

    @Test
    @Requirement("OIDFED §8.8(2)")
    void aClientThatDoesNotAuthenticateIsRefusedAsInvalidClient() throws Exception {
        Map<String, String> replayed = this.authenticated("sub", HOSTED);
        String required = "{\"federation_fetch_endpoint\": \"required\"}";
        verify(this.post(required, "/federation/fetch", replayed).response).setStatus(200);

        assertEquals("invalid_client", this.post(required, "/federation/fetch", replayed).error(401).get("error"), "a jti is spent once");
        assertEquals("invalid_client", this.post(required, "/federation/fetch", Map.of("client_assertion", "junk", "client_assertion_type", TYPE,
                "sub", HOSTED)).error(401).get("error"));
        assertEquals("invalid_client", this.post(required, "/federation/fetch", Map.of("client_assertion_type", TYPE, "sub", HOSTED))
                .error(401).get("error"), "a type without an assertion authenticates nobody");
    }
}
