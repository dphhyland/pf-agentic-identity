package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.FederationConfiguration;
import com.pingidentity.ps.oidf.federation.FederationService;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import com.pingidentity.ps.oidf.keyhistory.HistoricalKey;
import com.pingidentity.ps.oidf.keyhistory.InMemoryKeyHistoryStore;
import com.pingidentity.ps.oidf.keyhistory.KeyHistory;
import com.pingidentity.ps.oidf.keyhistory.KeyHistoryStore;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.Test;

/** The historical keys endpoint over HTTP (§8.7), and the rotation check this entity makes when it starts. */
class OpenIdFederationServletKeyHistoryTest {
    private static final String PF = "https://pf.example";
    private static final PublicJsonWebKey PF_KEY = Keys.rsa("pf-2");

    private final MutableClock clock = MutableClock.startingNow();

    private static FederationConfiguration configuration() {
        return FederationConfiguration.fromServletConfig(new ServletConfig() {
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
    }

    @Test
    @Requirement({"OIDFED §8.7.1(1)", "OIDFED §8.7.2(1)"})
    void theHistoricalKeysAreAnsweredAsASignedJwkSet() throws Exception {
        KeyHistory history = new KeyHistory(new InMemoryKeyHistoryStore(), this.clock, Duration.ofDays(1));
        history.observe(Keys.publicJwk(Keys.rsa("pf-1")));
        history.observe(Keys.publicJwk(PF_KEY));
        FederationService service = FederationService.builder(configuration(), Keys.signingKeys(PF_KEY)).historicalKeys(history).build();
        OpenIdFederationServlet servlet = new OpenIdFederationServlet(service, configuration(), req -> PF);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getServletPath()).thenReturn("/federation/historical_keys");
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter body = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(body));

        servlet.doGet(request, response);

        verify(response).setStatus(200);
        verify(response).setContentType("application/jwk-set+jwt");
        List<?> keys = (List<?>) JwtCodec.parseUnverifiedClaims(body.toString()).getClaimValue("keys");
        assertEquals("pf-1", ((Map<?, ?>) keys.get(0)).get("kid"));
    }

    @Test
    void startingWithAnotherKeyRetiresTheOldOne() throws Exception {
        KeyHistory history = new KeyHistory(new InMemoryKeyHistoryStore(), this.clock, Duration.ofDays(1));
        OpenIdFederationServlet.recordSigningKey(history, Keys.publicJwk(Keys.rsa("pf-1")));

        OpenIdFederationServlet.recordSigningKey(history, Keys.publicJwk(PF_KEY));

        assertEquals(List.of("pf-1"), history.retired().stream().map(HistoricalKey::kid).toList());
    }

    /** PingFederate signs its tokens with the same key: one revoked as compromised must stop it, not go quietly on. */
    @Test
    void startingWithARevokedKeyIsRefused() throws Exception {
        KeyHistory history = new KeyHistory(new InMemoryKeyHistoryStore(), this.clock, Duration.ofDays(1));
        history.observe(Keys.publicJwk(Keys.rsa("pf-1")));
        history.observe(Keys.publicJwk(PF_KEY));
        history.revoke("pf-1", "compromised", null);

        ServletException e = assertThrows(ServletException.class,
                () -> OpenIdFederationServlet.recordSigningKey(history, Keys.publicJwk(Keys.rsa("pf-1"))));

        assertTrue(e.getMessage().contains("revoked"), e.getMessage());
    }

    @Test
    void aHistoryThatCannotBeWrittenOnlyLosesTheRotation() throws Exception {
        KeyHistory broken = new KeyHistory(new KeyHistoryStore() {
            @Override
            public Optional<HistoricalKey> rotateTo(Map<String, Object> publicJwk, Instant now, Instant until) throws AuthorityRegistryException {
                throw new AuthorityRegistryException(AuthorityRegistryException.STORAGE_FAILURE, "down");
            }

            @Override
            public HistoricalKey revoke(String kid, Instant revokedAt, String reason) {
                throw new UnsupportedOperationException();
            }

            @Override
            public List<HistoricalKey> retired() {
                return List.of();
            }
        }, this.clock, Duration.ZERO);

        OpenIdFederationServlet.recordSigningKey(broken, Keys.publicJwk(PF_KEY));
    }
}
