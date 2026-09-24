/*
 * Minimal HTTP POST abstraction, the counterpart of HttpGetClient.
 */
package com.pingidentity.ps.oidf.jose;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.StringJoiner;

/**
 * An HTTP POST that reports the status instead of throwing on it.
 *
 * <p>Unlike {@link HttpGetClient#get}, a non-2xx answer is not an exception here: the callers that
 * POST need the status to decide what it means. An AuthZEN PDP's 403 is an error, not a deny; a Trust
 * Mark status endpoint's 404 means "unknown mark". Only transport failures and outbound-policy
 * refusals throw.
 */
public interface HttpPostClient {

    /**
     * @param url         the absolute URL, screened by the implementation's outbound policy first
     * @param contentType the request body's media type
     * @param body        the request body
     * @param headers     extra request headers; {@code null} for none
     * @param accept      the {@code Accept} header value, or {@code null} to send none
     */
    Response post(String url, String contentType, String body, Map<String, String> headers, String accept) throws Exception;

    /** POSTs {@code form} as {@code application/x-www-form-urlencoded}. */
    default Response postForm(String url, Map<String, String> form, Map<String, String> headers, String accept) throws Exception {
        return post(url, "application/x-www-form-urlencoded", formEncode(form), headers, accept);
    }

    /** {@code application/x-www-form-urlencoded} encoding of {@code form}, in iteration order. */
    static String formEncode(Map<String, String> form) {
        StringJoiner encoded = new StringJoiner("&");
        if (form != null) {
            for (Map.Entry<String, String> entry : form.entrySet()) {
                encoded.add(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(entry.getValue() == null ? "" : entry.getValue(), StandardCharsets.UTF_8));
            }
        }
        return encoded.toString();
    }

    /**
     * @param status  the HTTP status code
     * @param body    the response body, read through the implementation's size cap
     * @param headers the response headers
     */
    record Response(int status, String body, Map<String, List<String>> headers) {
        public Response {
            headers = headers == null ? Map.of() : Map.copyOf(headers);
        }

        public boolean isSuccess() {
            return this.status >= 200 && this.status < 300;
        }

        /** The first value of a header, matched case-insensitively. */
        public Optional<String> header(String name) {
            for (Map.Entry<String, List<String>> entry : this.headers.entrySet()) {
                if (entry.getKey() != null && entry.getKey().toLowerCase(Locale.ROOT).equals(name.toLowerCase(Locale.ROOT))
                        && entry.getValue() != null && !entry.getValue().isEmpty()) {
                    return Optional.ofNullable(entry.getValue().get(0));
                }
            }
            return Optional.empty();
        }
    }
}
