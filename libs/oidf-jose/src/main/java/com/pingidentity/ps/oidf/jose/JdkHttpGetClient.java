package com.pingidentity.ps.oidf.jose;

import java.net.http.HttpClient;
import java.util.Objects;

/**
 * {@link HttpGetClient} backed by the JDK {@link HttpClient}. When constructed
 * with {@code ignoreSslErrors} it trusts all TLS certificates and disables
 * hostname verification — intended only for talking to a development trust
 * controller over self-signed TLS, never for production.
 *
 * <p>Trust-chain validation runs synchronously on the caller's request thread
 * (see {@code TrustChainValidator}), so every fetch here MUST fail fast rather
 * than hang: a stalled remote entity should cost this thread a few seconds,
 * not tie it up until the CALLER's own timeout gives up (which just produces
 * an orphaned in-flight fetch PF keeps working on after the client is gone —
 * observed in production as a client 499 at ~45s followed by PF completing
 * the same exchange ~30-60s later against a connection nobody's still on).
 * HTTP/1.1 is forced so concurrent fetches to the same host get independent
 * TCP connections instead of potentially serializing over one HTTP/2 stream.
 *
 * <p>Every fetch is screened by an {@link OutboundUrlPolicy} first, because federation resolution
 * follows caller-supplied identifiers (see that class). Redirects are never followed - the JDK
 * default - so one check per request is sufficient; if that ever changes, each hop needs checking.
 * Response bodies are read through a cap rather than with {@code BodyHandlers.ofString}, which would
 * buffer whatever a remote chose to send.
 *
 * <p>The transport lives in {@link JdkHttpClient}, which also POSTs; this class is the GET-only view
 * every existing caller holds.
 */
public final class JdkHttpGetClient implements HttpGetClient {

    private final JdkHttpClient delegate;

    public JdkHttpGetClient(boolean ignoreSslErrors) {
        this(ignoreSslErrors, OutboundUrlPolicy.fromEnvironment());
    }

    public JdkHttpGetClient(boolean ignoreSslErrors, OutboundUrlPolicy policy) {
        this.delegate = new JdkHttpClient(ignoreSslErrors, Objects.requireNonNull(policy, "policy"));
    }

    JdkHttpGetClient(HttpClient httpClient) {
        this(httpClient, OutboundUrlPolicy.fromEnvironment());
    }

    JdkHttpGetClient(HttpClient httpClient, OutboundUrlPolicy policy) {
        this.delegate = new JdkHttpClient(httpClient, Objects.requireNonNull(policy, "policy"), JdkHttpClient.DEFAULT_REQUEST_TIMEOUT);
    }

    @Override
    public String get(String url, String acceptHeader) throws Exception {
        return this.delegate.get(url, acceptHeader);
    }
}
