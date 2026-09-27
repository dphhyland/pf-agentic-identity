/*
 * The one failure class a fail-open deployment grants through: the PDP could not be reached or did not answer in time.
 */
package com.pingidentity.ps.oidf.rar;

import java.io.IOException;

/**
 * A transport failure on the way to the PDP: a connection refused or reset, a name that does not resolve, a
 * deadline passed, or an answer that says the service is not there right now (429, 502, 503, 504). Nothing
 * else is this - not a 401 from a wrong secret, not a body that does not parse, not a TLS handshake that
 * fails - because those are a PDP that answered, and a policy decision point that answered "no" or "what?"
 * must not read as "yes". {@link AttestationAwareRarProcessor#enrich} fails open on this exception alone,
 * and only when the operator asked for that.
 */
public class PdpUnavailableException extends IOException {

    public PdpUnavailableException(String message) {
        super(message);
    }

    public PdpUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
