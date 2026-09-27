/*
 * What a PDP's HTTP answer means for the decision, before its body is read.
 */
package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;

/**
 * The reading of a PDP's HTTP status and media type that both dialects share, and that decides which
 * failures fail open.
 *
 * <ul>
 *   <li>2xx with a JSON media type: read the body.</li>
 *   <li>429, 502, 503, 504: the PDP, or something in front of it, says it is not serving right now -
 *       {@link PdpUnavailableException}, the one class fail-open may grant through.</li>
 *   <li>Any other status - a 401 or 403 from a wrong secret, a 400 for a request it did not like, a 404 for
 *       a URL that is wrong, a 500 from a policy that threw, a redirect - is a PDP that answered, and the
 *       answer is not PERMIT: a plain {@link IOException}, which fails closed.</li>
 *   <li>A 2xx that is not JSON is the same: something answered on that URL, and it was not the PDP's
 *       evaluation. A body that then fails to parse, parses to something other than an object, carries
 *       content after the object or names a member twice is refused too ({@link #jsonObjectOf}), closed as
 *       well.</li>
 * </ul>
 */
final class PdpResponses {

    static final String APPLICATION_JSON = "application/json";

    private PdpResponses() { }

    /**
     * @return the body of a JSON 2xx answer, never {@code null}
     * @throws PdpUnavailableException for 429, 502, 503 and 504
     * @throws IOException for every other non-2xx status, and for a 2xx whose media type is not JSON
     */
    static String bodyOf(HttpTransport.Response response, String pdpName) throws IOException {
        int status = response.status();
        if (status == 429 || status == 502 || status == 503 || status == 504) {
            throw new PdpUnavailableException(pdpName + " is not available: HTTP " + status);
        }
        if (status < 200 || status >= 300) {
            throw new IOException(pdpName + " returned HTTP " + status + ": " + excerpt(response.body()));
        }
        if (!isJson(response.contentType())) {
            throw new IOException(pdpName + " answered HTTP " + status + " with Content-Type '"
                    + response.contentType() + "', not " + APPLICATION_JSON + ": " + excerpt(response.body()));
        }
        return response.body() == null ? "" : response.body();
    }

    /**
     * The body as a JSON object. A body that is not JSON, or is JSON but not an object ({@code null}, an array,
     * a number), is refused with an {@link IOException}: a malformed answer is not a permit. So is an object
     * followed by more content, and an object that names a member twice - a default reader keeps the first
     * value and the last respectively, so {@code {"decision":"DENY","decision":"PERMIT"}} would have read as a
     * permit. A blank body reads as an empty object, which names no decision, so it is not a permit either.
     */
    static ObjectNode jsonObjectOf(String body, ObjectMapper mapper, String pdpName) throws IOException {
        JsonNode root;
        try {
            root = mapper.reader()
                    .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                    .with(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                    .readTree(body == null || body.isBlank() ? "{}" : body);
        } catch (IOException e) {
            throw new IOException(pdpName + " response is not JSON: " + excerpt(body), e);
        }
        if (!(root instanceof ObjectNode object)) {
            throw new IOException(pdpName + " response is not a JSON object: " + excerpt(body));
        }
        return object;
    }

    /** {@code application/json}, with or without parameters, or a {@code +json} structured syntax suffix. */
    static boolean isJson(String contentType) {
        if (contentType == null) {
            return false;
        }
        String mediaType = contentType.split(";", 2)[0].trim().toLowerCase(java.util.Locale.ROOT);
        return mediaType.equals(APPLICATION_JSON) || mediaType.endsWith("+json");
    }

    /** The first line or so of a body, for a log line - never the whole thing. */
    static String excerpt(String body) {
        if (body == null) {
            return "";
        }
        String oneLine = body.replaceAll("\\s+", " ").trim();
        return oneLine.length() <= 200 ? oneLine : oneLine.substring(0, 200) + "...";
    }
}
