package au.com.idpartners.gm.servlet;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.platform.http.AddressPolicy;
import com.pingidentity.ps.oidf.platform.http.Deadline;
import com.pingidentity.ps.oidf.platform.http.OutboundHttp;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import com.pingidentity.ps.oidf.platform.http.OutboundRequest;
import com.pingidentity.ps.oidf.platform.http.OutboundResponse;
import com.pingidentity.ps.oidf.platform.http.TlsTrust;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;

/**
 * Calls an AuthZEN 1.0 Policy Decision Point.
 *
 * <p>This is the one thing running inside PingFederate does not make local. The grant is
 * here; the policy is not, and should not be -- a PDP the AS cannot second-guess is the
 * point of the split. So this stays an ordinary HTTP call, and the PDP stays swappable:
 * the bundled demo PDP, PingAuthorize behind its AuthZEN facade, Topaz, OPA.
 *
 * <p>The call goes through platform's {@link OutboundHttp} (plan item S5d). The whole exchange, the
 * answer's body included, ends by {@code pdpTimeoutMs} (10 s unless set): before, that value bounded
 * the connect and each read apart, so a PDP answering a byte at a time held the request open without
 * end. Connecting, TLS included, takes at most platform's default 5 s within it, and the answer at
 * most platform's default cap, 256 KiB. The PDP is internal by design, so the URL it is configured at
 * is exempt from the scheme and address rules - pinned to that URL's scheme, host, port and path -
 * and nothing else is. The JVM's trust store decides its certificate, which must name its host.
 */
public final class PdpClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    /** The {@code pdpTimeoutMs} default (gm-api.json), which a value of zero or below also gets. */
    static final int DEFAULT_TIMEOUT_MS = 10_000;

    private final String evaluationUrl;
    private final String resourceSearchUrl;
    private final String bearerToken;
    private final Duration timeout;
    private final OutboundHttp http;

    /**
     * @param baseUrl     the PDP's base URL; the AuthZEN endpoint paths are appended
     * @param bearerToken credential for the PDP, or null/blank for an unprotected one
     * @param timeoutMs   how long one call may take, connecting, the answer and its body included;
     *                    {@value #DEFAULT_TIMEOUT_MS} when zero or below
     */
    public PdpClient(String baseUrl, String bearerToken, int timeoutMs) {
        this(baseUrl, bearerToken, timeoutMs, TlsTrust.jvmDefault());
    }

    /** The client with its TLS trust given: the test seam. */
    PdpClient(String baseUrl, String bearerToken, int timeoutMs, TlsTrust trust) {
        String base = baseUrl == null ? "" : baseUrl.replaceAll("/+$", "");
        this.evaluationUrl = base + "/access/v1/evaluation";
        // AuthZEN 1.0 spells resource search /access/v1/search/resource. (The draft-era Go
        // adapter used /access/v1/resourcesearch; PingAuthorize's native servlet is 1.0.)
        this.resourceSearchUrl = base + "/access/v1/search/resource";
        this.bearerToken = bearerToken;
        // Zero once meant no timeout at all; there is no unbounded wait any more, so zero and below take the default.
        this.timeout = Duration.ofMillis(timeoutMs > 0 ? timeoutMs : DEFAULT_TIMEOUT_MS);
        this.http = OutboundHttp.builder(AddressPolicy.builder().trusting(base).build())
                .tls(trust)
                .build();
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
        try {
            OutboundRequest.Builder b = OutboundRequest.post(url)
                    .header("Accept", "application/json")
                    .body("application/json", MAPPER.writeValueAsBytes(request));
            if (bearerToken != null && !bearerToken.isBlank()) {
                b.header("Authorization", "Bearer " + bearerToken);
            }
            OutboundResponse response = http.send(b.build(), Deadline.after(timeout));
            if (response.status() != 200) {
                throw new PdpUnavailableException(
                        "PDP returned " + response.status() + " from " + url + ": " + response.bodyText());
            }
            return MAPPER.readValue(response.body(), Map.class);
        } catch (OutboundHttpException e) {
            throw new PdpUnavailableException("could not reach the PDP at " + url + ": " + e.reason()
                    + ": " + e.getMessage(), e);
        } catch (IOException | IllegalArgumentException e) {
            throw new PdpUnavailableException("could not reach the PDP at " + url, e);
        }
    }
}
