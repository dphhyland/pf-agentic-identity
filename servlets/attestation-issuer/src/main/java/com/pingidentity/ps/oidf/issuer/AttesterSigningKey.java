/*
 * Resolves a client's attester signing key (OpenBao transit or inline JWK) into a JwsSigner.
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.jose.OpenBaoTransitSigner;
import com.pingidentity.ps.oidf.jose.LocalJwkSigner;
import com.pingidentity.ps.oidf.platform.settings.Secret;
import com.pingidentity.ps.oidf.platform.settings.Settings;

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
     * The OpenBao address and token from {@code OIDF_OPENBAO_URL} and {@code OIDF_OPENBAO_TOKEN}, read through their
     * entries in openid-federation's {@value #SETTINGS} settings catalogue (plan item ST-5), which the hosted entities'
     * signing keys read too: the system property {@code oidf.openbao.url} / {@code oidf.openbao.token}, then the
     * environment variable, then the superseded names {@code OPENBAO_ADDR} / {@code BAO_ADDR} / {@code VAULT_ADDR} and
     * {@code OPENBAO_TOKEN} / {@code BAO_TOKEN} / {@code VAULT_TOKEN} with a warning. A superseded name that holds
     * another value than the name that supersedes it is refused, naming both and neither value.
     *
     * @throws com.pingidentity.ps.oidf.platform.settings.SettingRefused for a value its entry refuses
     */
    public static AttesterSigningKey fromEnvironment() {
        Settings settings = Settings.of(SETTINGS);
        Secret token = settings.secret("OIDF_OPENBAO_TOKEN");
        return new AttesterSigningKey(settings.string("OIDF_OPENBAO_URL"), token == null ? null : token.reveal());
    }

    /** The settings catalogue OpenBao's address and token are in (openid-federation's). */
    public static final String SETTINGS = "hosted-entity-signing";

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

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }
}
