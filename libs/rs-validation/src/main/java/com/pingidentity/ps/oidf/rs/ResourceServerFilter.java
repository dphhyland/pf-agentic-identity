/*
 * A servlet filter that lets a request through only with a valid sender-constrained access token.
 */
package com.pingidentity.ps.oidf.rs;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Applies a {@link DelegatedTokenValidator} to every request it is mapped to. A request that passes goes on with the
 * {@link DelegatedTokenValidator.Result} in the request attribute {@value #RESULT_ATTRIBUTE}; one that does not is
 * answered here, with the status and the {@code WWW-Authenticate} challenge RFC 6750 §3 and RFC 9449 §7.1 describe,
 * and goes no further.
 *
 * <p>Registered programmatically, since it needs a validator: {@code servletContext.addFilter("rs", new
 * ResourceServerFilter(validator, "https://rs.example.com"))}.
 *
 * <ul>
 *   <li><b>No credentials</b> - no {@code Authorization} header, or a scheme this resource does not take: 401 with
 *       a challenge for each scheme it takes and no error. RFC 6750 §3.1: "If the request lacks any authentication
 *       information (e.g., the client was unaware that authentication is necessary or attempted using an
 *       unsupported authentication method), the resource server SHOULD NOT include an error code or other error
 *       information."</li>
 *   <li><b>A refused token or proof</b>: 401 with {@code error} and {@code error_description} in the challenge of
 *       the scheme the client used. RFC 9449 §7.2: "If the mechanism used to attempt authentication could be
 *       established unambiguously, then the corresponding challenge SHOULD be used to deliver error
 *       information".</li>
 *   <li><b>Ambiguous or malformed</b> - more than one {@code Authorization} header, an {@code access_token} in the
 *       query as well, a credential that is not token68: 400 {@code invalid_request}, in every challenge (RFC 9449
 *       figure 19).</li>
 *   <li><b>{@code use_dpop_nonce}</b>: 401 with a {@code DPoP-Nonce} header carrying the nonce to use (RFC 9449
 *       §9). A request that passes with last window's nonce gets the current one in {@code DPoP-Nonce}; both
 *       responses carry {@code Cache-Control: no-store} (RFC 9449 §8.2: "Responses that include the DPoP-Nonce HTTP
 *       header should be uncacheable").</li>
 *   <li><b>Unavailable</b> - the replay store or the key source could not answer: 503, no challenge.</li>
 * </ul>
 *
 * <p>The {@code htu} a proof must name is the configured public base URL followed by the request's path - never the
 * {@code Host} header, which the client controls - so a proof made for another server with the same path is not
 * accepted here.
 */
public final class ResourceServerFilter implements Filter {
    /** Where a passed request carries its {@link DelegatedTokenValidator.Result}. */
    public static final String RESULT_ATTRIBUTE = "com.pingidentity.ps.oidf.rs.Result";
    /** The servlet attribute a container puts the TLS client certificate chain in. */
    static final String CERTIFICATE_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    /** RFC 9449 §7.1's token68, which the DPoP scheme and RFC 6750's Bearer both use. */
    private static final Pattern TOKEN68 = Pattern.compile("[A-Za-z0-9\\-._~+/]+=*");
    private static final Pattern ACCESS_TOKEN_QUERY = Pattern.compile("(^|&)access_token=");
    private static final int DESCRIPTION_LIMIT = 200;

    private final DelegatedTokenValidator validator;
    private final String publicBaseUrl;
    private final String realm;

    /**
     * @param publicBaseUrl the scheme, host and port clients use to reach this resource, with no path, query or
     *                      trailing slash - for example {@code https://rs.example.com}; the {@code htu} of every
     *                      proof must be this followed by the request's path
     */
    public ResourceServerFilter(DelegatedTokenValidator validator, String publicBaseUrl) {
        this.validator = Objects.requireNonNull(validator, "validator");
        this.publicBaseUrl = checkedBaseUrl(publicBaseUrl);
        this.realm = this.publicBaseUrl;
    }

    static String checkedBaseUrl(String url) {
        URI uri;
        try {
            uri = new URI(Objects.requireNonNull(url, "publicBaseUrl"));
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("the public base URL is not a URI: " + url);
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        boolean pathless = uri.getRawPath() == null || uri.getRawPath().isEmpty();
        if (!scheme.matches("https?") || uri.getHost() == null || !pathless || uri.getRawQuery() != null
                || uri.getRawFragment() != null || uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("the public base URL is an http or https origin with no path, query,"
                    + " fragment or user information, for example https://rs.example.com, not " + url);
        }
        return url;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        if (!(req instanceof HttpServletRequest request) || !(res instanceof HttpServletResponse response)) {
            throw new ServletException("ResourceServerFilter serves HTTP requests only");
        }
        DelegatedTokenValidator.Result result;
        DelegatedTokenValidator.Scheme scheme = null;
        try {
            List<String> authorizations = Collections.list(request.getHeaders("Authorization"));
            if (authorizations.isEmpty()) {
                throw new DelegatedTokenValidator.RsException(null, 401, "no credentials");
            }
            if (authorizations.size() > 1) {
                throw new DelegatedTokenValidator.RsException(DelegatedTokenValidator.INVALID_REQUEST, 400,
                        "Multiple methods used to include access token");
            }
            String query = request.getQueryString();
            if (query != null && ACCESS_TOKEN_QUERY.matcher(query).find()) {
                throw new DelegatedTokenValidator.RsException(DelegatedTokenValidator.INVALID_REQUEST, 400,
                        "Multiple methods used to include access token");
            }
            String[] parts = authorizations.get(0).trim().split(" +", 2);
            scheme = scheme(parts[0]);
            if (scheme == null) {
                throw new DelegatedTokenValidator.RsException(null, 401, "unsupported authentication scheme");
            }
            if (parts.length < 2 || !TOKEN68.matcher(parts[1]).matches()) {
                throw new DelegatedTokenValidator.RsException(DelegatedTokenValidator.INVALID_REQUEST, 400,
                        "the credentials are not token68");
            }
            X509Certificate[] chainCerts = (X509Certificate[]) request.getAttribute(CERTIFICATE_ATTRIBUTE);
            result = this.validator.validate(new DelegatedTokenValidator.Presentation(scheme, parts[1],
                    Collections.list(request.getHeaders("DPoP")), request.getMethod(),
                    this.publicBaseUrl + request.getRequestURI(),
                    chainCerts == null || chainCerts.length == 0 ? null : chainCerts[0]));
        } catch (DelegatedTokenValidator.RsException e) {
            this.refuse(response, scheme, e);
            return;
        }
        request.setAttribute(RESULT_ATTRIBUTE, result);
        if (result.nextDpopNonce() != null) {
            response.setHeader("DPoP-Nonce", result.nextDpopNonce());
            response.setHeader("Cache-Control", "no-store");
        }
        chain.doFilter(request, response);
    }

    /** The scheme an {@code Authorization} header names; the name is case-insensitive (RFC 9110 §11.1). */
    static DelegatedTokenValidator.Scheme scheme(String name) {
        if ("DPoP".equalsIgnoreCase(name)) {
            return DelegatedTokenValidator.Scheme.DPOP;
        }
        return "Bearer".equalsIgnoreCase(name) ? DelegatedTokenValidator.Scheme.BEARER : null;
    }

    private void refuse(HttpServletResponse response, DelegatedTokenValidator.Scheme used,
                        DelegatedTokenValidator.RsException e) {
        response.setStatus(e.status());
        response.setHeader("Cache-Control", "no-store");
        for (String challenge : this.challenges(used, e)) {
            response.addHeader("WWW-Authenticate", challenge);
        }
        if (e.dpopNonce() != null) {
            response.setHeader("DPoP-Nonce", e.dpopNonce());
        }
        response.setContentLength(0);
    }

    /**
     * The {@code WWW-Authenticate} challenges for a refusal: one per scheme this resource accepts, the error in the
     * challenge of the scheme the client used, or in every one when the request was ambiguous. None for a 503.
     */
    List<String> challenges(DelegatedTokenValidator.Scheme used, DelegatedTokenValidator.RsException e) {
        List<String> out = new ArrayList<>();
        if (e.status() == 503) {
            return out;
        }
        String error = e.error() == null ? null
                : "error=\"" + e.error() + "\", error_description=\"" + description(e.getMessage()) + "\"";
        if (this.validator.acceptsDpop()) {
            StringBuilder dpop = new StringBuilder("DPoP algs=\"")
                    .append(String.join(" ", new TreeSet<>(this.validator.proofAlgorithms()))).append('"');
            if (error != null && used != DelegatedTokenValidator.Scheme.BEARER) {
                dpop.append(", ").append(error);
            }
            out.add(dpop.toString());
        }
        if (this.validator.acceptsMtls()) {
            // RFC 6750 §3: the Bearer scheme "MUST be followed by one or more auth-param values".
            StringBuilder bearer = new StringBuilder("Bearer realm=\"").append(description(this.realm)).append('"');
            if (error != null && used != DelegatedTokenValidator.Scheme.DPOP) {
                bearer.append(", ").append(error);
            }
            out.add(bearer.toString());
        }
        return out;
    }

    /**
     * A message as an {@code error_description} may carry it. RFC 6750 §3: "Values for the "error" and
     * "error_description" attributes ... MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E."
     * Anything else - a quote, a backslash, a control character, anything past ASCII - becomes '?', and the text is
     * cut at {@value #DESCRIPTION_LIMIT} characters, because some of it comes from the token.
     */
    static String description(String message) {
        String text = message == null ? "" : message;
        StringBuilder out = new StringBuilder(Math.min(text.length(), DESCRIPTION_LIMIT));
        for (int i = 0; i < text.length() && i < DESCRIPTION_LIMIT; i++) {
            char c = text.charAt(i);
            out.append(c >= 0x20 && c <= 0x7e && c != '"' && c != '\\' ? c : '?');
        }
        return out.toString();
    }
}
