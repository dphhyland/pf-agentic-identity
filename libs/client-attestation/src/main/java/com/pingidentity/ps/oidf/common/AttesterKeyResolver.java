/*
 * Resolves the trusted signing keys of a Client Attester.
 */
package com.pingidentity.ps.oidf.common;

import java.util.List;
import org.jose4j.jwk.JsonWebKey;

/**
 * Resolves the set of signing keys that are trusted to have issued a Client Attestation for a given
 * Attester identifier. Implementations establish trust (e.g. via an OpenID Federation trust chain) and
 * MUST throw if the attester cannot be trusted, rather than returning an empty/unsafe key set.
 */
public interface AttesterKeyResolver {
    /**
     * @param attesterIssuer    the Client Attestation {@code iss} (the Attester's entity identifier)
     * @param trustChainHeader  any {@code trust_chain} carried in the attestation header (may be null/empty)
     * @return the trusted signing keys for the attester (never empty)
     * @throws Exception if the attester is not trusted or its keys cannot be resolved
     */
    List<JsonWebKey> resolve(String attesterIssuer, List<String> trustChainHeader) throws Exception;
}
