package com.pingidentity.ps.oidf.jose;

import com.pingidentity.ps.oidf.platform.http.Deadline;
import java.util.Objects;

/**
 * The GET-only view of {@link JdkHttpClient}, which sends through platform's {@code OutboundHttp}. When constructed
 * with {@code ignoreSslErrors} it trusts any certificate chain through platform's InsecureTls; the certificate must
 * still name the host the URL names. Intended only for talking to a development trust controller over self-signed
 * TLS, never for production.
 *
 * <p>Trust-chain validation runs synchronously on the caller's request thread
 * (see {@code TrustChainValidator}), so every fetch here MUST fail fast rather
 * than hang: a stalled remote entity should cost this thread a few seconds,
 * not tie it up until the CALLER's own timeout gives up (which just produces
 * an orphaned in-flight fetch PF keeps working on after the client is gone -
 * observed in production as a client 499 at ~45s followed by PF completing
 * the same exchange ~30-60s later against a connection nobody's still on).
 * Each request gets its own HTTP/1.1 connection, so concurrent fetches to one
 * host never queue behind one another on a shared one.
 *
 * <p>Every fetch is screened by an {@link OutboundUrlPolicy}, because federation resolution follows
 * caller-supplied identifiers (see that class), and connects only to an address the policy checked.
 * Redirects are never followed, so one check per request is sufficient; if that ever changes, each hop
 * needs checking. Response bodies are read through the policy's cap, within the request's deadline.
 */
public final class JdkHttpGetClient implements HttpGetClient {

    private final JdkHttpClient delegate;

    public JdkHttpGetClient(boolean ignoreSslErrors) {
        this(ignoreSslErrors, OutboundUrlPolicy.fromEnvironment());
    }

    public JdkHttpGetClient(boolean ignoreSslErrors, OutboundUrlPolicy policy) {
        this.delegate = new JdkHttpClient(ignoreSslErrors, Objects.requireNonNull(policy, "policy"));
    }

    @Override
    public String get(String url, String acceptHeader) throws Exception {
        return this.delegate.get(url, acceptHeader);
    }

    /** The GET, by the sooner of {@code deadline} and the request timeout (see {@link JdkHttpClient#get(String, String, Deadline)}). */
    @Override
    public String get(String url, String acceptHeader, Deadline deadline) throws Exception {
        return this.delegate.get(url, acceptHeader, deadline);
    }
}
