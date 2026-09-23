/*
 * The two FAPI 1.0 resource-server provisions PingFederate's UserInfo endpoint does not meet on its own.
 */
package com.pingidentity.ps.oidf.servlet.fapi1;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * FAPI 1.0 Baseline §6.2.1 lists what a resource server "shall" do. UserInfo is the one resource
 * PingFederate serves itself, and two of the provisions it does not meet:
 *
 * <ul>
 *   <li>it "shall set the response header x-fapi-interaction-id to the value received from the
 *       corresponding FAPI client request header or to a RFC4122 UUID value if the request header was
 *       not provided", and "shall log the value" - UserInfo sends no such header;</li>
 *   <li>it "shall not accept access tokens in the query parameters stated in Section 2.3 of OAuth 2.0
 *       Bearer Token Usage" - UserInfo accepts {@code ?access_token=}.</li>
 * </ul>
 *
 * <p>Mapped over {@code /idp/userinfo.openid} by {@code build/pingfederate/assemble-pf-runtime-war.sh}.
 * The header is set before the chain runs, because a response PingFederate has already committed cannot
 * take one afterwards; a received value is echoed only when it is a UUID, since the profile names the
 * format and a header echoed verbatim is a header a client can put anything into. A token in the query
 * is refused as RFC 6750 §3.1 says to refuse a malformed request: 400, {@code invalid_request}, with the
 * {@code WWW-Authenticate} challenge. Only the query is looked at, never the body: a form-encoded token is
 * a different section of RFC 6750 and not the one the profile rules out.
 */
public final class FapiResourceServerFilter implements Filter {

    static final String HEADER = "x-fapi-interaction-id";
    private static final Log LOGGER = LogFactory.getLog(FapiResourceServerFilter.class);
    private static final Pattern UUID_SHAPE = Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private static final Pattern TOKEN_IN_QUERY = Pattern.compile("(^|&)access_token=");

    @Override
    public void init(FilterConfig config) {
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
        String interactionId = interactionIdFor(http);
        out.setHeader(HEADER, interactionId);
        LOGGER.info((Object) (HEADER + " " + interactionId + " " + http.getMethod() + " " + http.getRequestURI()));
        if (carriesTokenInQuery(http)) {
            out.setStatus(400);
            out.setHeader("WWW-Authenticate", "Bearer error=\"invalid_request\", "
                    + "error_description=\"access tokens are not accepted in the query string\"");
            out.setContentType("application/json");
            out.setHeader("Cache-Control", "no-store");
            java.io.PrintWriter body = out.getWriter();
            body.write("{\"error\":\"invalid_request\","
                    + "\"error_description\":\"access tokens are not accepted in the query string\"}");
            body.flush();
            return;
        }
        chain.doFilter(request, response);
    }

    /** The client's id when it sent a UUID, otherwise a fresh one. */
    static String interactionIdFor(HttpServletRequest request) {
        String given = request.getHeader(HEADER);
        return given != null && UUID_SHAPE.matcher(given.trim()).matches() ? given.trim() : UUID.randomUUID().toString();
    }

    /** RFC 6750 §2.3: {@code access_token} as a URI query parameter - the query string itself, not the body. */
    static boolean carriesTokenInQuery(HttpServletRequest request) {
        String query = request.getQueryString();
        return query != null && TOKEN_IN_QUERY.matcher(query).find();
    }

    @Override
    public void destroy() {
    }
}
