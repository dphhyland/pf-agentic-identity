/*
 * Mints agent_id values: 256 random bits, never derived from anything.
 */
package com.pingidentity.ps.oidf.agent;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Pure id generation, split out from {@link AgentRegistry} so both implementations mint identically and
 * neither embeds its own notion of "how many bits is enough."
 *
 * <p>Random, not derived: an id computed from the natural key (e.g. an HMAC over
 * {@code iss|client_id|instance_format|instance_subject}) would be recomputable by anyone who later
 * learns the key material, retroactively de-anonymising every id ever minted with it. 256 bits of
 * {@link SecureRandom}, base64url-encoded with no padding, has no such failure mode.
 */
final class AgentIdMinter {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    private AgentIdMinter() {
    }

    static String mint() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return ENCODER.encodeToString(bytes);
    }
}
