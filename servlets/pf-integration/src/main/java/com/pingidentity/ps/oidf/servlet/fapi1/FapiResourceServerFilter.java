/*
 * The two FAPI resource-server provisions PingFederate's UserInfo endpoint does not meet on its own, for FAPI clients.
 */
package com.pingidentity.ps.oidf.servlet.fapi1;

import com.pingidentity.ps.oidf.platform.pf.settings.InitParams;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import com.pingidentity.ps.oidf.servlet.fapi2.Fapi2ProfileFilter;
import com.pingidentity.ps.oidf.servlet.fapi2.FapiEvents;
import com.pingidentity.ps.oidf.servlet.oauth.OAuthErrorWriter;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Pattern;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * FAPI 1.0 Baseline §6.2.1 lists what "the resource server with the FAPI endpoints" shall do. UserInfo is the one
 * resource PingFederate serves itself, and two of the provisions it does not meet:
 *
 * <ul>
 *   <li>it "shall set the response header x-fapi-interaction-id to the value received from the
 *       corresponding FAPI client request header or to a RFC4122 UUID value if the request header was
 *       not provided", and "shall log the value of x-fapi-interaction-id in the log entry" - UserInfo sends no
 *       such header;</li>
 *   <li>it "shall not accept access tokens in the query parameters stated in Section 2.3 of OAuth 2.0
 *       Bearer Token Usage" - UserInfo accepts {@code ?access_token=}. FAPI 2.0 Security Profile (final) §5.3.4 says the
 *       same of "Resource servers with the FAPI endpoints": they "shall not accept access tokens in the query
 *       parameters stated in Section 2.3 of OAuth 2.0 Bearer Token Usage [RFC6750]".</li>
 * </ul>
 *
 * <p><b>For FAPI clients only</b> (plan item H-FED-6, finding F-0048). Both provisions are of FAPI endpoints, and
 * PingFederate's UserInfo serves every client. The clients are the ones {@code OIDF_FAPI2_CLIENTS} names - the list
 * {@link Fapi2ProfileFilter} holds to the FAPI 2.0 rules at the token endpoint, since the FAPI 2.0 profile has the same
 * resource-server rule - and the ones {@code OIDF_FAPI_RESOURCE_CLIENTS} adds: FAPI 1.0 clients, such as FAPI-CIBA's,
 * which need the resource-server rules but whose client assertions address the token endpoint and would fail the FAPI
 * 2.0 audience rule if they were on the first list. {@code *} on either is every client. A client is attributed the way
 * {@link Fapi2ProfileFilter} attributes one at UserInfo: the {@code client_id} claim of a JWT access token, unverified,
 * from the query or the {@code Authorization} header. A request that
 * names another client to escape the rules has to be served by PingFederate as that client, with a token PingFederate
 * issued to it; a token that names no client (a reference token) is held to them only under {@code *}. With both
 * lists unset, nothing here happens and UserInfo answers as PingFederate does.
 *
 * <p>Mapped over {@code /idp/userinfo.openid} by {@code build/pingfederate/assemble-pf-runtime-war.sh}. The header is
 * set before the chain runs, because a response PingFederate has already committed cannot take one afterwards; a
 * received value is echoed only when it is a UUID, since the profile names the format and a header echoed verbatim is a
 * header a client can put anything into. A token in the query is refused as RFC 6750 §3.1 says to refuse a malformed
 * request: 400, {@code invalid_request}, with the {@code WWW-Authenticate} challenge, and recorded as
 * {@code fapi.request.refused}. The query is read as a server reads it: every parameter, its name percent-decoded and
 * compared without regard to case ({@code access%5Ftoken}, {@code Access_Token}, a repeat). Only the query is looked
 * at, never the body: a form-encoded token is a different section of RFC 6750 and not the one the profile rules out.
 */
public final class FapiResourceServerFilter implements Filter {

    static final String HEADER = "x-fapi-interaction-id";
    static final String TOKEN_PARAMETER = "access_token";
    static final String CLIENTS_ENV = "OIDF_FAPI2_CLIENTS";
    static final String RESOURCE_CLIENTS_ENV = "OIDF_FAPI_RESOURCE_CLIENTS";
    private static final String CATALOGUE = "fapi2-profile";
    private static final String EVERY_CLIENT = "*";
    private static final Log LOGGER = LogFactory.getLog(FapiResourceServerFilter.class);
    private static final Pattern UUID_SHAPE = Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    private final Function<String, String> environment;
    private volatile Set<String> clients = Set.of();

    public FapiResourceServerFilter() {
        this(System::getenv);
    }

    /** Test seam: a test should not depend on the machine's environment. */
    FapiResourceServerFilter(Function<String, String> environment) {
        this.environment = environment;
    }

    @Override
    public void init(FilterConfig config) {
        this.clients = this.clients(InitParams.of(config));
        LOGGER.info((Object) (this.clients.isEmpty()
                ? "FAPI resource-server rules at UserInfo off (" + CLIENTS_ENV + " and " + RESOURCE_CLIENTS_ENV + " name no client)"
                : "FAPI resource-server rules at UserInfo ON for "
                        + (this.clients.contains(EVERY_CLIENT) ? "every client" : this.clients)
                        + ": x-fapi-interaction-id set, access tokens in the query refused"));
    }

    /**
     * The FAPI clients: {@value #CLIENTS_ENV}'s and {@value #RESOURCE_CLIENTS_ENV}'s, from their entries in the
     * {@code fapi2-profile} catalogue, the first read as {@link Fapi2ProfileFilter} reads it. A list that cannot be read
     * (a list of nothing) holds every client, since nobody can then say which clients are FAPI's.
     */
    Set<String> clients(Function<String, String> initParams) {
        Settings settings = Settings.load(FapiResourceServerFilter.class.getClassLoader(), CATALOGUE)
                .with(Sources.of(this.environment, System::getProperty, initParams));
        Set<String> clients = new java.util.LinkedHashSet<>();
        for (String name : List.of(CLIENTS_ENV, RESOURCE_CLIENTS_ENV)) {
            try {
                Set<String> listed = settings.words(name);
                if (listed != null) {
                    clients.addAll(listed);
                }
            } catch (RuntimeException e) {
                LOGGER.warn((Object) (name + " cannot be read (" + e.getMessage()
                        + "); the FAPI resource-server rules apply to every client at UserInfo until it is fixed"));
                return Set.of(EVERY_CLIENT);
            }
        }
        return Set.copyOf(clients);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }
        HttpServletRequest http = (HttpServletRequest) request;
        HttpServletResponse out = (HttpServletResponse) response;
        List<String> tokens = tokensInQuery(http.getQueryString());
        String client = this.fapiClient(http, tokens);
        if (client == null) {
            chain.doFilter(request, response);
            return;
        }
        String interactionId = interactionIdFor(http);
        out.setHeader(HEADER, interactionId);
        LOGGER.info((Object) (HEADER + " " + interactionId + " " + http.getMethod() + " " + http.getRequestURI()));
        if (!tokens.isEmpty()) {
            FapiEvents.refused(http, FapiEvents.RESOURCE_SERVER_FILTER, "access_token_in_query", "invalid_request",
                    client.equals(EVERY_CLIENT) ? null : client);
            out.setHeader("WWW-Authenticate", "Bearer error=\"invalid_request\"");
            OAuthErrorWriter.write(out, 400, "invalid_request", "access tokens are not accepted in the query string ("
                    + tokens.size() + " " + TOKEN_PARAMETER + " parameter(s))");
            return;
        }
        chain.doFilter(request, response);
    }

    /**
     * The FAPI client this request is attributed to, {@value #EVERY_CLIENT} when the list holds every client and no
     * client can be told, or {@code null} when the rules are not this request's: the first listed client named by a
     * token in the query or in the {@code Authorization} header.
     */
    String fapiClient(HttpServletRequest request, List<String> queryTokens) {
        Set<String> listed = this.clients;
        if (listed.isEmpty()) {
            return null;
        }
        List<String> named = new ArrayList<>();
        for (String token : queryTokens) {
            named.add(Fapi2ProfileFilter.clientOfAccessToken("Bearer " + token));
        }
        named.add(Fapi2ProfileFilter.clientOfAccessToken(request.getHeader("Authorization")));
        for (String client : named) {
            if (client != null && (listed.contains(client) || listed.contains(EVERY_CLIENT))) {
                return client;
            }
        }
        return listed.contains(EVERY_CLIENT) ? EVERY_CLIENT : null;
    }

    /** The client's id when it sent a UUID, otherwise a fresh one. */
    static String interactionIdFor(HttpServletRequest request) {
        String given = request.getHeader(HEADER);
        return given != null && UUID_SHAPE.matcher(given.trim()).matches() ? given.trim() : UUID.randomUUID().toString();
    }

    /**
     * RFC 6750 §2.3: every {@code access_token} URI query parameter's value, in order - the query string itself, not the
     * body. A name is percent-decoded and compared without regard to case, so no spelling of the name gets a token past
     * this; a parameter with no value carries an empty one. Empty when there is none.
     */
    static List<String> tokensInQuery(String query) {
        List<String> tokens = new ArrayList<>();
        if (query == null || query.isEmpty()) {
            return tokens;
        }
        for (String pair : query.split("&")) {
            int equals = pair.indexOf('=');
            String name = decoded(equals < 0 ? pair : pair.substring(0, equals));
            if (TOKEN_PARAMETER.equals(name.trim().toLowerCase(Locale.ROOT))) {
                tokens.add(equals < 0 ? "" : decoded(pair.substring(equals + 1)));
            }
        }
        return tokens;
    }

    /** {@code raw} form-decoded as UTF-8, or as it is when it holds a malformed escape. */
    static String decoded(String raw) {
        try {
            return URLDecoder.decode(raw, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return raw;
        }
    }

    @Override
    public void destroy() {
    }
}
