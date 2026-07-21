/*
 * Resolves a client's attester signing key (OpenBao transit or inline JWK) into a JwsSigner.
 */
package com.pingidentity.ps.oidf.common;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves the per-client attester signing key into a {@link JwsSigner}, choosing the backing by
 * configuration: an OpenBao transit key reference ({@code attestation_signing_key_ref}) yields an
 * {@link OpenBaoTransitSigner} (private key stays in the vault); an inline private JWK
 * ({@code attestation_signing_jwk}) yields a {@link LocalJwkSigner} (dev/demo). Exactly one must be set.
 *
 * <p>The OpenBao address/token are environment-level (one vault serves all clients); each client only
 * names its transit key. Transit signers are cached by key name (they are immutable and pin their key
 * version on construction, per {@link OpenBaoTransitSigner}).
 */
public final class AttesterSigningKey {

    private final String baoUrl;
    private final String baoToken;
    private final ConcurrentHashMap<String, JwsSigner> transitCache = new ConcurrentHashMap<>();

    public AttesterSigningKey(String baoUrl, String baoToken) {
        this.baoUrl = blankToNull(baoUrl);
        this.baoToken = blankToNull(baoToken);
    }

    /**
     * Resolves the OpenBao address/token from configuration layered as system property → environment
     * variable, following the same convention as the rest of the module. The vault address is read from
     * {@code oidf.openbao.url} / {@code OIDF_OPENBAO_URL} (then {@code OPENBAO_ADDR} / {@code BAO_ADDR} /
     * {@code VAULT_ADDR}); the token from {@code oidf.openbao.token} / {@code OIDF_OPENBAO_TOKEN} (then
     * {@code OPENBAO_TOKEN} / {@code BAO_TOKEN} / {@code VAULT_TOKEN}).
     */
    public static AttesterSigningKey fromEnvironment() {
        return new AttesterSigningKey(
                resolve("oidf.openbao.url", "OIDF_OPENBAO_URL", "OPENBAO_ADDR", "BAO_ADDR", "VAULT_ADDR"),
                resolve("oidf.openbao.token", "OIDF_OPENBAO_TOKEN", "OPENBAO_TOKEN", "BAO_TOKEN", "VAULT_TOKEN"));
    }

    /**
     * @param keyRef    the transit key name ({@code attestation_signing_key_ref}), or null
     * @param inlineJwk the inline private JWK ({@code attestation_signing_jwk}), or null/empty
     * @throws IssuanceException {@code invalid_client} if neither or both are set, or the inline JWK is
     *                           malformed; {@code server_error} if transit signing is selected but no vault
     *                           is configured or it cannot be reached.
     */
    public JwsSigner signerFor(String keyRef, Map<String, Object> inlineJwk) throws IssuanceException {
        boolean hasRef = keyRef != null && !keyRef.isBlank();
        boolean hasJwk = inlineJwk != null && !inlineJwk.isEmpty();
        if (hasRef == hasJwk) {
            throw IssuanceException.invalidClient(
                    "exactly one of attestation_signing_key_ref or attestation_signing_jwk must be configured");
        }
        if (hasRef) {
            if (this.baoUrl == null || this.baoToken == null) {
                throw IssuanceException.serverError(
                        "attestation_signing_key_ref is set but no OpenBao address/token is configured");
            }
            try {
                return this.transitCache.computeIfAbsent(keyRef,
                        k -> new OpenBaoTransitSigner(this.baoUrl, this.baoToken, k));
            } catch (RuntimeException e) {
                throw IssuanceException.serverError("OpenBao transit signer unavailable: " + e.getMessage());
            }
        }
        try {
            return new LocalJwkSigner(inlineJwk);
        } catch (RuntimeException e) {
            throw IssuanceException.invalidClient("attestation_signing_jwk is invalid: " + e.getMessage());
        }
    }

    private static String resolve(String sysProp, String... envVars) {
        String value = System.getProperty(sysProp);
        if (value != null && !value.isBlank()) {
            return value.trim();
        }
        for (String env : envVars) {
            value = System.getenv(env);
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }
}
