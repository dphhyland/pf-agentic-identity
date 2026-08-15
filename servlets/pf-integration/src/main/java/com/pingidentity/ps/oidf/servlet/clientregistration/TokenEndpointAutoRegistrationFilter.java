package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.jose.JwtCodec;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwt.JwtClaims;
import org.sourceid.oauth20.issuer.OAuthIssuerUtils;

/**
 * OpenID Federation §12.1 Automatic Registration, realised transparently at the OAuth token endpoint.
 *
 * <p>A federation client that has never called {@code /federation/register} can still obtain a token: it
 * presents its Trust Chain inline in the {@code trust_chain} header of its {@code client_assertion}, and the
 * Authorization Server validates the chain and derives the client's metadata on the fly. Because PingFederate
 * must have a persisted client record to authenticate a token request, this filter runs <b>before</b> PF's
 * token-endpoint client authentication: it just-in-time materialises the client from its resolved federation
 * metadata (marking it {@code auto_registered}) so the very same request then authenticates normally. It is
 * idempotent — an already-registered client is left untouched — and fail-open: any provisioning error is
 * logged and the request proceeds unchanged (PF then rejects the unknown/unauthenticated client as usual).
 *
 * <p>Deployment: map this filter over the PF token endpoint in the runtime web application, e.g.
 * <pre>{@code
 *   <filter>
 *     <filter-name>OidfAutoRegistration</filter-name>
 *     <filter-class>com.pingidentity.ps.oidf.servlet.clientregistration.TokenEndpointAutoRegistrationFilter</filter-class>
 *     <init-param><param-name>trustControllerHost</param-name><param-value>https://trust-controller.example</param-value></init-param>
 *     <init-param><param-name>acceptedSigningAlgorithms</param-name><param-value>ES256,RS256</param-value></init-param>
 *   </filter>
 *   <filter-mapping>
 *     <filter-name>OidfAutoRegistration</filter-name>
 *     <url-pattern>/as/token.oauth2</url-pattern>
 *   </filter-mapping>
 * }</pre>
 */
public final class TokenEndpointAutoRegistrationFilter implements Filter {
    private static final Log LOGGER = LogFactory.getLog(TokenEndpointAutoRegistrationFilter.class);
    private volatile RegistrationService service;
    private final Function<HttpServletRequest, String> issuerResolver;

    public TokenEndpointAutoRegistrationFilter() {
        this.issuerResolver = TokenEndpointAutoRegistrationFilter::defaultIssuer;
    }

    /** Test seam: inject a pre-built (typically mocked) registration service. */
    TokenEndpointAutoRegistrationFilter(RegistrationService service) {
        this(service, TokenEndpointAutoRegistrationFilter::defaultIssuer);
    }

    /** Test seam: inject the registration service and the OP-issuer resolver (avoids the PF runtime singleton). */
    TokenEndpointAutoRegistrationFilter(RegistrationService service, Function<HttpServletRequest, String> issuerResolver) {
        this.service = service;
        this.issuerResolver = issuerResolver;
    }

    private static String defaultIssuer(HttpServletRequest request) {
        return OAuthIssuerUtils.getInstance().getIssuerValue(request);
    }

    @Override
    public void init(FilterConfig config) {
        if (this.service != null) {
            return;
        }
        // Same init-param → env fallback as FederationConfiguration.setting: an image-baked PF is
        // configured through deployment env, not a per-deployment web.xml rebuild.
        String trustControllerHost = orBlank(config.getInitParameter("trustControllerHost"));
        if (trustControllerHost.isBlank()) {
            trustControllerHost = orBlank(System.getenv("OIDF_FEDERATION_TRUST_CONTROLLER_HOST"));
        }
        boolean ignoreSslErrors = Boolean.parseBoolean(config.getInitParameter("ignoreSslErrors"))
                || Boolean.parseBoolean(System.getenv("OIDF_FEDERATION_IGNORE_SSL_ERRORS"));
        int cacheMaxEntries = parseInt(config.getInitParameter("subordinateStatementCacheMaxEntries"), 256);
        long trustChainEntryMaxAge = parseLong(config.getInitParameter("trustChainEntryMaxAgeSeconds"), 60L);
        Set<String> acceptedSigningAlgorithms = parseCsv(config.getInitParameter("acceptedSigningAlgorithms"));
        RegistrationConfiguration configuration = new RegistrationConfiguration(trustControllerHost, ignoreSslErrors,
                cacheMaxEntries, trustChainEntryMaxAge, "RS256", acceptedSigningAlgorithms);
        this.service = new RegistrationService(configuration);
        LOGGER.info((Object)("TokenEndpointAutoRegistrationFilter initialised (trust controller " + trustControllerHost + ")"));
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            try {
                this.maybeAutoRegister((HttpServletRequest)request);
            }
            catch (Exception e) {
                // Fail open: never block a token request because auto-registration could not complete.
                LOGGER.info((Object)("Automatic registration skipped: " + e.getMessage()));
            }
        }
        chain.doFilter(request, response);
    }

    private void maybeAutoRegister(HttpServletRequest request) throws Exception {
        String clientAssertion = request.getParameter("client_assertion");
        if (clientAssertion == null || clientAssertion.isBlank()) {
            return;
        }
        List<String> trustChain = TokenEndpointAutoRegistrationFilter.extractTrustChain(clientAssertion);
        if (trustChain.isEmpty()) {
            return;
        }
        JwtClaims claims = JwtCodec.parseUnverifiedClaims(clientAssertion);
        String clientId = claims.getSubject();
        if (clientId == null || clientId.isBlank()) {
            return;
        }
        String opIssuer = this.issuerResolver.apply(request);
        this.service.automaticRegister(trustChain, clientId, opIssuer);
    }

    private static List<String> extractTrustChain(String clientAssertion) {
        Map<String, Object> headers;
        try {
            headers = JwtCodec.getJwtHeaders(clientAssertion);
        }
        catch (Exception e) {
            return Collections.emptyList();
        }
        Object rawTrustChain = headers.get("trust_chain");
        if (!(rawTrustChain instanceof List)) {
            return Collections.emptyList();
        }
        List rawList = (List)rawTrustChain;
        ArrayList<String> trustChainList = new ArrayList<String>(rawList.size());
        for (Object item : rawList) {
            if (item instanceof String) {
                trustChainList.add((String)item);
            }
        }
        return trustChainList;
    }

    @Override
    public void destroy() {
    }

    private static String orBlank(String value) {
        return value == null ? "" : value;
    }

    private static int parseInt(String value, int fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        }
        catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static long parseLong(String value, long fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Long.parseLong(value.trim());
        }
        catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static Set<String> parseCsv(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        ArrayList<String> result = new ArrayList<String>();
        for (String token : value.split(",")) {
            String trimmed = token.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result.isEmpty() ? Set.of() : Set.copyOf(result);
    }
}
