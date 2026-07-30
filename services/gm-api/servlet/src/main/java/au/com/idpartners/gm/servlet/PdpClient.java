package au.com.idpartners.gm.servlet;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Calls an AuthZEN 1.0 Policy Decision Point.
 *
 * <p>This is the one thing running inside PingFederate does not make local. The grant is
 * here; the policy is not, and should not be -- a PDP the AS cannot second-guess is the
 * point of the split. So this stays an ordinary HTTP call, and the PDP stays swappable:
 * the bundled demo PDP, PingAuthorize behind its AuthZEN facade, Topaz, OPA.
 */
public final class PdpClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String evaluationUrl;
    private final String resourceSearchUrl;
    private final String bearerToken;
    private final int timeoutMs;

    /**
     * @param baseUrl     the PDP's base URL; the AuthZEN endpoint paths are appended
     * @param bearerToken credential for the PDP, or null/blank for an unprotected one
     * @param timeoutMs   connect and read timeout
     */
    public PdpClient(String baseUrl, String bearerToken, int timeoutMs) {
        String base = baseUrl == null ? "" : baseUrl.replaceAll("/+$", "");
        this.evaluationUrl = base + "/access/v1/evaluation";
        // AuthZEN 1.0 spells resource search /access/v1/search/resource. (The draft-era Go
        // adapter used /access/v1/resourcesearch; PingAuthorize's native servlet is 1.0.)
        this.resourceSearchUrl = base + "/access/v1/search/resource";
        this.bearerToken = bearerToken;
        this.timeoutMs = timeoutMs;
    }

    public String getEvaluationUrl() {
        return evaluationUrl;
    }

    public String getResourceSearchUrl() {
        return resourceSearchUrl;
    }

    /** Thrown when the PDP cannot be reached or does not answer coherently. */
    public static class PdpUnavailableException extends Exception {
        PdpUnavailableException(String message, Throwable cause) {
            super(message, cause);
        }

        PdpUnavailableException(String message) {
            super(message);
        }
    }

    /**
     * Posts an AuthZEN evaluation request and returns the decoded response.
     *
     * <p>Any failure is surfaced rather than swallowed: a PDP we cannot reach is a 503,
     * not a denial and certainly not a permit. Turning "I could not ask" into "no" would
     * be indistinguishable from a real policy decision, and into "yes" would be
     * catastrophic.
     */
    public Map<String, Object> evaluate(Map<String, Object> request) throws PdpUnavailableException {
        return post(evaluationUrl, request);
    }

    /**
     * Posts an AuthZEN resource-search request and returns the decoded response
     * ({@code {"results":[{"type","id"}...],"page":{}}}).
     *
     * <p>Same contract as {@link #evaluate}: an unreachable PDP is an error, never an empty
     * result set. Silently returning "no entitlements" would look identical to a subject who
     * genuinely holds nothing, and the caller would tell the user the wrong thing.
     */
    public Map<String, Object> search(Map<String, Object> request) throws PdpUnavailableException {
        return post(resourceSearchUrl, request);
    }

    private Map<String, Object> post(String url, Map<String, Object> request)
            throws PdpUnavailableException {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            if (bearerToken != null && !bearerToken.isBlank()) {
                conn.setRequestProperty("Authorization", "Bearer " + bearerToken);
            }

            byte[] body = MAPPER.writeValueAsBytes(request);
            try (OutputStream out = conn.getOutputStream()) {
                out.write(body);
            }

            int status = conn.getResponseCode();
            if (status != 200) {
                String err = readAll(conn, true);
                throw new PdpUnavailableException(
                        "PDP returned " + status + " from " + url + ": " + err);
            }
            return MAPPER.readValue(readAll(conn, false), Map.class);
        } catch (IOException e) {
            throw new PdpUnavailableException("could not reach the PDP at " + url, e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private static String readAll(HttpURLConnection conn, boolean error) throws IOException {
        var stream = error ? conn.getErrorStream() : conn.getInputStream();
        if (stream == null) {
            return "";
        }
        try (stream) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
