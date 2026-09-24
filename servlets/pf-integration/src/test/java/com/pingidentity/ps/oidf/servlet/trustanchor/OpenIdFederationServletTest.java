package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.FederationConfiguration;
import com.pingidentity.ps.oidf.federation.FederationService;
import com.pingidentity.ps.oidf.federation.HttpTrustControllerGateway;
import com.pingidentity.ps.oidf.federation.TrustAnchor;
import com.pingidentity.ps.oidf.federation.TrustAnchorSet;
import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.ServingMap;
import com.pingidentity.ps.oidf.federation.testkit.Statements;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Clock;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.Test;

/**
 * The federation endpoints over HTTP (OpenID Federation 1.0 §8): the status and content type of every
 * answer, repeated parameters, and errors as §8.9 JSON with the status each code SHOULD carry.
 */
class OpenIdFederationServletTest {
    private static final String PF = "https://pf.example";
    private static final String HOSTED = "https://pf.example/agents/a1";
    private static final PublicJsonWebKey PF_KEY = Keys.rsa("pf-1");
    private static final PublicJsonWebKey HOSTED_KEY = Keys.ec("a1-1");

    private static ServletConfig servletConfig(Map<String, String> params) {
        return new ServletConfig() {
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
        };
    }

    private static OpenIdFederationServlet servlet(boolean faulty) {
        Map<String, String> params = new HashMap<>();
        params.put("trustAnchorIssuers", PF);
        FederationConfiguration configuration = FederationConfiguration.fromServletConfig(servletConfig(params));
        String hostedEc = Statements.spec(Statements.ENTITY_STATEMENT_TYP).claim("iss", HOSTED).claim("sub", HOSTED)
                .claim("jwks", Keys.publicJwks(HOSTED_KEY)).claim("authority_hints", List.of(PF))
                .claim("metadata", Map.of("oauth_client", Map.of("client_name", "agent"))).sign(HOSTED_KEY, Clock.systemUTC());
        ServingMap http = new ServingMap();
        FederationService service = FederationService.builder(configuration, Keys.signingKeys(PF_KEY))
                .subordinateFetcher(http)
                .hostedSubordinateLookup(sub -> {
                    if (faulty) {
                        throw new IllegalStateException("registry down: jdbc:postgresql://secret-host/idm");
                    }
                    return HOSTED.equals(sub) ? Map.of("jwks", Keys.publicJwks(HOSTED_KEY)) : null;
                })
                .hostedSubordinateIds(type -> List.of(HOSTED))
                .hostedConfiguration(id -> HOSTED.equals(id) ? hostedEc : null)
                .hosting(() -> true)
                .resolver(TrustAnchorSet.of(TrustAnchor.of(PF, Keys.publicJwks(PF_KEY))), new HttpTrustControllerGateway(http, PF),
                        Set.of(), ValidatorOptions.defaults())
                .build();
        return new OpenIdFederationServlet(service, configuration, req -> PF);
    }

    /** One GET, answered. */
    private static final class Exchange {
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final StringWriter body = new StringWriter();

        Exchange(OpenIdFederationServlet servlet, String path, Map<String, String[]> params) throws Exception {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getServletPath()).thenReturn(path);
            for (Map.Entry<String, String[]> param : params.entrySet()) {
                when(request.getParameter(param.getKey())).thenReturn(param.getValue()[0]);
                when(request.getParameterValues(param.getKey())).thenReturn(param.getValue());
            }
            when(this.response.getWriter()).thenReturn(new PrintWriter(this.body));
            servlet.doGet(request, this.response);
        }

        Map<String, Object> error() throws Exception {
            verify(this.response).setContentType("application/json");
            return JsonUtil.parseJson(this.body.toString());
        }
    }

    private static Exchange get(String path, Map<String, String[]> params) throws Exception {
        return new Exchange(servlet(false), path, params);
    }

    private static void assertError(Exchange exchange, int status, String code) throws Exception {
        verify(exchange.response).setStatus(status);
        assertEquals(code, exchange.error().get("error"), exchange.body.toString());
    }

    @Test
    @Requirement("OIDFED §9(1)")
    void theEntityConfigurationIsServedAsAnEntityStatement() throws Exception {
        Exchange exchange = get("/.well-known/openid-federation", Map.of());

        verify(exchange.response).setStatus(200);
        verify(exchange.response).setContentType("application/entity-statement+jwt");
        assertEquals(PF, JwtCodec.parseUnverifiedClaims(exchange.body.toString()).getSubject());
    }

    @Test
    @Requirement({"OIDFED §8.1.1(2.2)", "OIDFED §8.1.2(1)"})
    void fetchAnswersASubordinateStatementForSubAlone() throws Exception {
        Exchange exchange = get("/federation/fetch", Map.of("sub", new String[] {HOSTED}));

        verify(exchange.response).setStatus(200);
        verify(exchange.response).setContentType("application/entity-statement+jwt");
        assertEquals(HOSTED, JwtCodec.parseUnverifiedClaims(exchange.body.toString()).getSubject());
    }

    @Test
    @Requirement({"OIDFED §8.1.2(1)", "OIDFED §8.9(1)", "OIDFED §8.9(2.2.4.3)", "OIDFED §8.9(2.2.4.13)"})
    void fetchRefusalsAreJsonWithTheirStatus() throws Exception {
        assertError(get("/federation/fetch", Map.of()), 400, "invalid_request");
        assertError(get("/federation/fetch", Map.of("sub", new String[] {PF})), 400, "invalid_request");
        assertError(get("/federation/fetch", Map.of("sub", new String[] {HOSTED}, "iss", new String[] {"https://other.example"})),
                404, "invalid_issuer");
        assertError(get("/federation/fetch", Map.of("sub", new String[] {"https://stranger.example"})), 404, "not_found");
    }

    @Test
    @Requirement({"OIDFED §8.2.2(1)", "OIDFED §8.2.1(2.2)"})
    void listTakesRepeatedEntityTypesAndAnswersAJsonArray() throws Exception {
        Exchange exchange = get("/federation/list", Map.of("entity_type", new String[] {"oauth_client", "oauth_client"}));

        verify(exchange.response).setStatus(200);
        verify(exchange.response).setContentType("application/json");
        assertEquals("[\"" + HOSTED + "\"]", exchange.body.toString());
    }

    @Test
    @Requirement({"OIDFED §8.2.1(2.4)", "OIDFED §8.9(2.2.4.15)"})
    void listRefusesAnUnsupportedFilterAndANonBoolean() throws Exception {
        assertError(get("/federation/list", Map.of("trust_marked", new String[] {"true"})), 400, "unsupported_parameter");
        assertError(get("/federation/list", Map.of("intermediate", new String[] {"maybe"})), 400, "invalid_request");
        Exchange unfiltered = get("/federation/list", Map.of("intermediate", new String[] {"FALSE"}, "trust_marked", new String[] {"false"}));
        verify(unfiltered.response).setStatus(200);
    }

    @Test
    @Requirement({"OIDFED §8.3.2(1)", "OIDFED §8.3.1(2.4)"})
    void resolveAnswersASignedResolveResponse() throws Exception {
        Exchange exchange = get("/federation/resolve", Map.of("sub", new String[] {HOSTED}, "trust_anchor", new String[] {"https://unknown.example", PF}));

        verify(exchange.response).setStatus(200);
        verify(exchange.response).setContentType("application/resolve-response+jwt");
        assertEquals("resolve-response+jwt", JwtCodec.getJwtHeaders(exchange.body.toString()).get("typ"));
    }

    @Test
    @Requirement({"OIDFED §8.3.1(2.4)", "OIDFED §8.9(2.2.4.7)"})
    void resolveRefusalsAreJsonWithTheirStatus() throws Exception {
        assertError(get("/federation/resolve", Map.of("sub", new String[] {HOSTED})), 400, "invalid_request");
        assertError(get("/federation/resolve", Map.of("sub", new String[] {HOSTED}, "trust_anchor", new String[] {"https://unknown.example"})),
                404, "invalid_trust_anchor");
        assertError(get("/federation/resolve", Map.of("sub", new String[] {"https://stranger.example"}, "trust_anchor", new String[] {PF})),
                404, "invalid_subject");
    }

    @Test
    void anUnknownPathIsNotFound() throws Exception {
        assertError(get("/federation/elsewhere", Map.of()), 404, "not_found");
    }

    @Test
    @Requirement("OIDFED §8.9(2.2.2.4)")
    void aServerFaultIsA500ThatShowsNothingOfTheFault() throws Exception {
        Exchange exchange = new Exchange(servlet(true), "/federation/fetch", Map.of("sub", new String[] {HOSTED}));

        assertError(exchange, 500, "server_error");
        assertEquals(FederationErrors.SERVER_ERROR_DESCRIPTION, exchange.error().get("error_description"));
        assertTrue(!exchange.body.toString().contains("secret-host"), exchange.body.toString());
    }

    @Test
    @Requirement("OIDFED §8.9(2.2.2.6)")
    void aSubordinateThatCannotBeReachedYetIsTemporarilyUnavailable() throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("trustAnchorIssuers", PF);
        params.put("subordinates", "https://foreign.example");
        FederationConfiguration configuration = FederationConfiguration.fromServletConfig(servletConfig(params));
        ServingMap http = new ServingMap().failing("https://foreign.example/.well-known/openid-federation", new java.io.IOException("down"));
        OpenIdFederationServlet servlet = new OpenIdFederationServlet(FederationService.builder(configuration, Keys.signingKeys(PF_KEY))
                .subordinateFetcher(http).build(), configuration, req -> PF);

        Exchange exchange = new Exchange(servlet, "/federation/fetch", Map.of("sub", new String[] {"https://foreign.example"}));

        assertError(exchange, 503, "temporarily_unavailable");
        assertEquals("the subordinate's entity configuration could not be fetched yet", exchange.error().get("error_description"),
                "a 503 says what is wrong; only a fault of ours hides it");
    }

    @Test
    void theNonStandardEntityEndpointNeedsASubject() throws Exception {
        assertError(get("/federation/entity", Map.of()), 400, "invalid_request");

        Exchange exchange = get("/federation/entity", Map.of("sub", new String[] {HOSTED}));
        verify(exchange.response).setStatus(200);
        verify(exchange.response).setContentType("application/entity-statement+jwt");
    }

    @Test
    void optionsAnswersTheCorsPreflight() throws Exception {
        OpenIdFederationServlet servlet = servlet(false);
        HttpServletResponse response = mock(HttpServletResponse.class);

        servlet.doOptions(mock(HttpServletRequest.class), response);

        verify(response).setStatus(204);
        verify(response).setHeader("Access-Control-Allow-Origin", "*");
    }

    @Test
    void theResolverUsesTheDeploymentsPinnedAnchorsOrNone() {
        String jwks = JsonUtil.toJson(Keys.publicJwks(PF_KEY));
        String map = JsonUtil.toJson(Map.of(PF, Keys.publicJwks(PF_KEY)));

        assertEquals(null, OpenIdFederationServlet.resolverAnchors(com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.from(name -> null, name -> null)));
        assertEquals(List.of(PF), OpenIdFederationServlet.resolverAnchors(com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.from(
                name -> "OIDF_FEDERATION_TRUST_ANCHOR_JWKS".equals(name) ? map : null, name -> null)).entityIds());
        assertEquals(List.of(PF), OpenIdFederationServlet.resolverAnchors(com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.from(
                name -> switch (name) {
                    case "OIDF_FEDERATION_TRUST_CONTROLLER_HOST" -> PF;
                    case "OIDF_FEDERATION_TRUST_ANCHOR_JWKS" -> jwks;
                    default -> null;
                }, name -> null)).entityIds());
        assertEquals(null, OpenIdFederationServlet.resolverAnchors(com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.from(
                name -> "OIDF_FEDERATION_TRUST_CONTROLLER_HOST".equals(name) ? PF : null, name -> null)),
                "a controller named without pinned keys leaves the resolver off rather than trusting whoever answers");
    }
}
