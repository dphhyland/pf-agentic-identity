package com.pingidentity.ps.oidf.jose;

import com.pingidentity.ps.oidf.platform.http.Bulkhead;
import com.pingidentity.ps.oidf.platform.http.Deadline;
import com.pingidentity.ps.oidf.platform.http.HostBulkhead;
import com.pingidentity.ps.oidf.platform.http.OutboundHttp;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import com.pingidentity.ps.oidf.platform.http.OutboundRequest;
import com.pingidentity.ps.oidf.platform.http.OutboundResponse;
import com.pingidentity.ps.oidf.platform.http.TlsTrust;
import com.pingidentity.ps.oidf.platform.tls.InsecureTls;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * GET and POST through platform's {@link OutboundHttp} (plan item S5a), every request screened by an
 * {@link OutboundUrlPolicy} and every response body read through the policy's size cap.
 *
 * <p>The name keeps the class's history; the JDK's {@code java.net.http} client is no longer under it, because that
 * client resolves the host again when it connects. Here the policy resolves the host once, checks every address,
 * and the connection goes to a checked address and nowhere else, with TLS still checking the certificate against
 * the URL's host. What it keeps: the fail-fast timeouts (a remote that stalls costs the caller's thread a few
 * seconds, not an unbounded wait), HTTP/1.1 with a connection per request, so concurrent requests to one host never
 * queue behind one another on a shared connection, no redirects (so one policy check per request is sufficient), and
 * a capped body read. POST reports the status to the caller instead of throwing on it (see {@link HttpPostClient}).
 *
 * <p>The timeouts: the connect timeout bounds connecting and the TLS handshake; the request timeout is the whole
 * exchange's deadline, the body included (the JDK client's stopped at the headers, finding F-0010), and the
 * headers must arrive within it. Every request to one origin also takes a place in a {@link HostBulkhead} shared by
 * every client in this copy of oidf-jose ({@link HostBulkhead#DEFAULT_MAX_PER_ORIGIN} places an origin), waiting for
 * one no longer than the request's deadline.
 *
 * <p>What a caller sees, as before: a policy refusal, a body over the cap and (from {@link #get}) a non-2xx status
 * are an {@link IllegalArgumentException}; a failed exchange - no address accepted, a timeout, a TLS failure, a
 * malformed response, or no place in the bulkhead before the deadline - is an {@link OutboundHttpException}, an
 * {@link java.io.IOException} whose {@code reason()} says which.
 *
 * <p>When constructed with {@code ignoreSslErrors} it trusts any certificate chain - for a development peer over
 * self-signed TLS, never for production. The trust-all is platform's {@link InsecureTls} (plan item PR-1), which
 * warns once and records the use; the certificate must still name the host the URL names, and here nothing turns
 * that off (the JVM-wide {@code jdk.internal.httpclient.disableHostnameVerification} of finding F-0035 governs the JDK
 * client alone).
 */
public final class JdkHttpClient implements HttpGetClient, HttpPostClient {

    public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(8);
    public static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(15);
    /** The setting every {@code ignoreSslErrors} here comes from, and the name InsecureTls records the use under. */
    static final String IGNORE_SSL_SETTING = "OIDF_FEDERATION_IGNORE_SSL_ERRORS";
    /** The bulkhead every client in this copy of oidf-jose shares, so a client made per request is still counted. */
    static final HostBulkhead BULKHEAD = HostBulkhead.withDefaults();

    private final OutboundHttp http;
    private final OutboundUrlPolicy policy;
    private final Duration requestTimeout;

    public JdkHttpClient(boolean ignoreSslErrors, OutboundUrlPolicy policy) {
        this(ignoreSslErrors, policy, DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT);
    }

    public JdkHttpClient(boolean ignoreSslErrors, OutboundUrlPolicy policy, Duration connectTimeout, Duration requestTimeout) {
        this(TlsTrust.insecureIf(IGNORE_SSL_SETTING, ignoreSslErrors), BULKHEAD, policy, connectTimeout, requestTimeout);
    }

    /** Test seam: a supplied trust and bulkhead. */
    JdkHttpClient(TlsTrust tls, Bulkhead bulkhead, OutboundUrlPolicy policy, Duration connectTimeout, Duration requestTimeout) {
        this.policy = Objects.requireNonNull(policy, "policy");
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
        this.http = OutboundHttp.builder(policy.addressPolicy())
                .tls(Objects.requireNonNull(tls, "tls"))
                .bulkhead(Objects.requireNonNull(bulkhead, "bulkhead"))
                .connectTimeout(Objects.requireNonNull(connectTimeout, "connectTimeout"))
                .headerTimeout(requestTimeout)
                .maxBodyBytes(policy.maxBodyBytes())
                .build();
    }

    public OutboundUrlPolicy policy() {
        return this.policy;
    }

    @Override
    public String get(String url, String acceptHeader) throws Exception {
        URI uri = OutboundUrlPolicy.parse(url);
        OutboundResponse response = send(OutboundRequest.builder(OutboundRequest.Method.GET, uri)
                .header("Accept", acceptHeader), uri, url, "GET");
        if (!response.successful()) {
            throw new IllegalArgumentException("GET failed: " + url + " status=" + response.status());
        }
        return response.bodyText();
    }

    @Override
    public Response post(String url, String contentType, String body, Map<String, String> headers, String accept) throws Exception {
        URI uri = OutboundUrlPolicy.parse(url);
        OutboundRequest.Builder request = OutboundRequest.builder(OutboundRequest.Method.POST, uri)
                .body(Objects.requireNonNull(contentType, "contentType"), body == null ? "" : body);
        if (accept != null) {
            request.header("Accept", accept);
        }
        if (headers != null) {
            for (Map.Entry<String, String> header : headers.entrySet()) {
                if (header.getKey() != null && header.getValue() != null) {
                    request.header(header.getKey(), header.getValue());
                }
            }
        }
        OutboundResponse response = send(request, uri, url, "POST");
        return new Response(response.status(), response.bodyText(), headerMap(response));
    }

    /** Sends through the transport within the request timeout; a failure comes back as {@link #failure} says. */
    private OutboundResponse send(OutboundRequest.Builder request, URI uri, String url, String method) throws Exception {
        try {
            return this.http.send(request.build(), Deadline.after(this.requestTimeout));
        } catch (OutboundHttpException e) {
            throw failure(e, uri, url, method);
        }
    }

    /**
     * What a caller sees for a failed request: the refusals it always saw as an {@link IllegalArgumentException} (the
     * policy's, and a body over the cap), and anything else as the transport's own exception, an {@link java.io.IOException}.
     */
    Exception failure(OutboundHttpException e, URI uri, String url, String method) {
        if (e.reason() == OutboundHttpException.Reason.BODY_TOO_LARGE) {
            return new IllegalArgumentException(method + " refused: " + url + ": " + e.getMessage(), e);
        }
        IllegalArgumentException refused = this.policy.refusal(e, uri);
        return refused != null ? refused : e;
    }

    /** The response headers by name, each name's values in the order received; names as the peer spelled them first. */
    static Map<String, List<String>> headerMap(OutboundResponse response) {
        Map<String, List<String>> byLowerName = new LinkedHashMap<>();
        Map<String, List<String>> byName = new LinkedHashMap<>();
        for (OutboundResponse.Header header : response.headers()) {
            List<String> values = byLowerName.get(header.name().toLowerCase(Locale.ROOT));
            if (values == null) {
                values = new ArrayList<>();
                byLowerName.put(header.name().toLowerCase(Locale.ROOT), values);
                byName.put(header.name(), values);
            }
            values.add(header.value());
        }
        return byName;
    }
}
