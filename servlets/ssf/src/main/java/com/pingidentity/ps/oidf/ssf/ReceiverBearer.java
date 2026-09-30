/*
 * The access token the SSF receiver presents to a transmitter's poll and stream endpoints.
 */
package com.pingidentity.ps.oidf.ssf;

/**
 * Where the receiver's outbound calls - the poll ({@link PollReceiverClient}) and stream management
 * ({@link ReceiverStreamClient}) - get the bearer token they present: a {@link ClientCredentialsToken} from the
 * transmitter's authorization server, or, in development only, the static {@code OIDF_SSF_RECEIVER_POLL_TOKEN}. A
 * call answered 401 hands the token back through {@link #rejected}, and asks once more with whatever {@link #token}
 * then gives.
 */
public interface ReceiverBearer {

    /** The token to present now; throws when none can be had (the authorization server refused or is down). */
    String token() throws Exception;

    /** The transmitter answered 401 to {@code token}: forget it, so the next {@link #token} is a new one. */
    void rejected(String token);

    /** A static token (development): {@link #rejected} changes nothing, since there is no other to have. */
    static ReceiverBearer fixed(String token) {
        return new ReceiverBearer() {
            @Override
            public String token() {
                return token;
            }

            @Override
            public void rejected(String rejected) {
                // A static token cannot be replaced; the call fails and is logged.
            }
        };
    }
}
