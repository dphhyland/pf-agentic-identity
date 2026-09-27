/*
 * The shared store could not answer: the caller must refuse the request, never treat it as seen or consumed.
 */
package com.pingidentity.ps.oidf.clientattestation;

/**
 * Thrown by the boolean views of {@link AttestationReplayCache#firstSeen} and
 * {@link AttestationChallengeService#consume}, and by {@link AttestationChallengeService#issue}, when the
 * store behind them (Redis) cannot be reached or answers with an error. The tri-state methods report the
 * same condition as {@code STORE_UNAVAILABLE}; a caller that can only take a boolean gets this instead, so a
 * store outage surfaces as a failed request and is never logged as a replay or an unknown challenge.
 *
 * <p>An {@link IllegalStateException} so that callers written against the 0.3.0 contract, where
 * {@code issue()} threw that type on an outage, keep catching it.
 */
public final class StoreUnavailableException extends IllegalStateException {
    private static final long serialVersionUID = 1L;

    public StoreUnavailableException(String message) {
        super(message);
    }

    public StoreUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
