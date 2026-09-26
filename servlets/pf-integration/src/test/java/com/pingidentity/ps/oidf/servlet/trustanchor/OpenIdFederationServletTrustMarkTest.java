package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.FederationConfiguration;
import com.pingidentity.ps.oidf.federation.FederationService;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
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
import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.Test;

/** The three Trust Mark endpoints over HTTP (§8.4-§8.6): methods, media types and §8.9 errors. */
class OpenIdFederationServletTrustMarkTest {
    private static final String PF = "https://pf.example";
    private static final String RP = "https://rp.example";
    private static final String OPEN = "https://pf.example/marks/open";
    private static final PublicJsonWebKey PF_KEY = Keys.rsa("pf-1");

    private final MutableClock clock = MutableClock.startingNow();
    private final InMemoryTrustMarkRegistry registry = new InMemoryTrustMarkRegistry(this.clock);

    private OpenIdFederationServlet servlet() {
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
                return "trustAnchorIssuers".equals(name) ? PF : null;
            }

            @Override
            public Enumeration<String> getInitParameterNames() {
                return Collections.enumeration(List.of("trustAnchorIssuers"));
            }
        });
        FederationService service = FederationService.builder(configuration, Keys.signingKeys(PF_KEY))
                .trustMarkIssuing(new TrustMarkIssuer(Map.of(OPEN, new TrustMarkType(OPEN, 3600, TrustMarkType.Subjects.ANY, null, null, null)),
                        this.registry, id -> false, this.clock))
                .clock(this.clock)
                .build();
        return new OpenIdFederationServlet(service, configuration, req -> PF);
    }

    /** One request, answered. */
    private final class Exchange {
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final StringWriter body = new StringWriter();

        Exchange(String method, String path, Map<String, String> params) throws Exception {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getServletPath()).thenReturn(path);
            for (Map.Entry<String, String> param : params.entrySet()) {
                when(request.getParameter(param.getKey())).thenReturn(param.getValue());
            }
            when(this.response.getWriter()).thenReturn(new PrintWriter(this.body));
            OpenIdFederationServlet servlet = OpenIdFederationServletTrustMarkTest.this.servlet();
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

    @Test
    @Requirement({"OIDFED §8.6.1(1)", "OIDFED §8.6.2(1)"})
    void theTrustMarkEndpointAnswersTheMarkAsATrustMarkJwt() throws Exception {
        this.registry.grant(OPEN, RP, null, null);

        Exchange exchange = new Exchange("GET", "/federation/trust_mark", Map.of("trust_mark_type", OPEN, "sub", RP));

        verify(exchange.response).setStatus(200);
        verify(exchange.response).setContentType("application/trust-mark+jwt");
        assertEquals(RP, JwtCodec.parseUnverifiedClaims(exchange.body.toString()).getSubject());
        assertEquals("not_found", new Exchange("GET", "/federation/trust_mark", Map.of("trust_mark_type", OPEN, "sub", "https://other.example"))
                .error(404).get("error"), "§8.6.2: a mark the entity does not hold is a 404");
    }

    @Test
    @Requirement({"OIDFED §8.4.1(1)", "OIDFED §8.4.2(1)"})
    void theStatusEndpointTakesAFormPostAndAnswersAStatusResponse() throws Exception {
        this.registry.grant(OPEN, RP, null, null);
        String mark = new Exchange("GET", "/federation/trust_mark", Map.of("trust_mark_type", OPEN, "sub", RP)).body.toString();

        Exchange exchange = new Exchange("POST", "/federation/trust_mark_status", Map.of("trust_mark", mark));

        verify(exchange.response).setStatus(200);
        verify(exchange.response).setContentType("application/trust-mark-status-response+jwt");
        assertEquals("active", JwtCodec.parseUnverifiedClaims(exchange.body.toString()).getClaimValue("status"));
        assertEquals("invalid_request", new Exchange("POST", "/federation/trust_mark_status", Map.of()).error(400).get("error"));
    }

    @Test
    @Requirement("OIDFED §8.4.1(1)")
    void theStatusEndpointTakesOnlyPostAndTheOthersOnlyGet() throws Exception {
        Exchange get = new Exchange("GET", "/federation/trust_mark_status", Map.of());
        assertEquals("invalid_request", get.error(405).get("error"));
        verify(get.response).setHeader("Allow", "POST");

        Exchange post = new Exchange("POST", "/federation/trust_marked_list", Map.of());
        assertEquals("invalid_request", post.error(405).get("error"));
        verify(post.response).setHeader("Allow", "GET");
    }

    @Test
    @Requirement({"OIDFED §8.5.1(1)", "OIDFED §8.5.2(1)"})
    void theTrustMarkedListIsAJsonArrayOfEntityIdentifiers() throws Exception {
        this.registry.grant(OPEN, RP, null, null);

        Exchange exchange = new Exchange("GET", "/federation/trust_marked_list", Map.of("trust_mark_type", OPEN));

        verify(exchange.response).setStatus(200);
        verify(exchange.response).setContentType("application/json");
        assertEquals("[\"" + RP + "\"]", exchange.body.toString());
        assertEquals("invalid_request", new Exchange("GET", "/federation/trust_marked_list", Map.of()).error(400).get("error"));
    }

    @Test
    void aStatusRequestThatFailsIsAnsweredAsJson() throws Exception {
        assertEquals("not_found", new Exchange("POST", "/federation/trust_mark_status", Map.of("trust_mark",
                com.pingidentity.ps.oidf.federation.testkit.Statements.spec("trust-mark+jwt").claim("iss", "https://tmi.example")
                        .sign(Keys.ec("tmi-1"), this.clock))).error(404).get("error"));
    }
}
