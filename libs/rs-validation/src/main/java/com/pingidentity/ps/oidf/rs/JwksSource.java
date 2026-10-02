/*
 * Where the authorisation server's signing keys come from.
 */
package com.pingidentity.ps.oidf.rs;

import java.io.IOException;
import java.util.List;

/**
 * The authorisation server's public signing keys, looked up by {@code kid}.
 *
 * <p>The lookup is exact: the keys whose {@code kid} is {@code kid}, character for character, and nothing else.
 * There is no fallback to trying every key - a token names its key, and a token that names none, or names one the
 * server does not publish, is refused.
 */
public interface JwksSource {

    /**
     * The public keys whose {@code kid} equals {@code kid}; empty when there is none.
     *
     * @throws IOException when the keys could not be read and the answer is not known; the request is then refused
     *                     as unavailable, not as an invalid token
     */
    List<org.jose4j.jwk.PublicJsonWebKey> keys(String kid) throws IOException;
}
