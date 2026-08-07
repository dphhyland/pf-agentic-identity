/*
 * Mints the Client Attestation JWT for a registered agent instance on a user's device.
 */
package com.pingidentity.ps.oidf.device;

import com.pingidentity.ps.oidf.common.CompactJws;
import com.pingidentity.ps.oidf.common.JwsSigner;
import com.pingidentity.ps.oidf.common.Jwks;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

/**
 * Issues the Client Attestation a device-resident agent presents at PingFederate's token endpoint,
 * per draft-ietf-oauth-attestation-based-client-auth.
 *
 * <p>Two properties of the claim set are load-bearing and easy to erode, so both are enforced here
 * rather than left to the caller:
 *
 * <ul>
 *   <li><strong>The instance identity is pseudonymous.</strong> The opaque instance identifier is
 *       carried as {@code agent_id} (and, until the Phase 2.5 {@code sub} flip below, also as
 *       {@code sub}). This artefact is presented on <em>every</em> token request, so any user
 *       identifier in it would be a permanent cross-resource-server correlation handle. The
 *       instance-to-human mapping exists only in the registry. There is deliberately no way to pass a
 *       user identifier to this minter.</li>
 *   <li><strong>No device data.</strong> Model, OS version and device identifier stay in the registry.
 *       Device data is more sensitive than instance data, and an attestation travels further than a
 *       registry row.</li>
 * </ul>
 *
 * <p><strong>The Phase 2.5 {@code sub} flip.</strong> Historically {@code sub} was the instance
 * identifier, which diverges from the ABCA draft ({@code sub} names the OAuth client) and would need
 * one registered client per device. The target state is {@code sub} = the registered client id, with
 * the instance identity as the {@code agent_id} claim — the same value the instance id already has, so
 * audit joins, CAEP revocation keys and live tokens stay valid across the change. The flip is staged
 * behind configuration ({@code subjectClientId}; wired from {@code OIDF_ATTESTATION_SUB} in the
 * enrolment service's {@code Main}), default off: with no {@code subjectClientId} this minter behaves
 * exactly as before, except that {@code agent_id} is now always emitted alongside.</p>
 *
 * <p>The lifetime is short — {@link #DEFAULT_LIFETIME} — because the attestation asserts device posture
 * and the user-verification policy in force, and both go stale. Re-minting costs one round trip and, so
 * long as the device's authentication context is still live, no user prompt; so the usual argument for
 * long-lived attestations does not apply. See {@code docs/claim-dictionary.md}.
 */
public final class DeviceAttestationMinter {

    /** draft-ietf-oauth-attestation-based-client-auth: the attestation media type. */
    public static final String TYP = "oauth-client-attestation+jwt";

    /** Short enough that a stale posture assertion cannot travel far. */
    public static final Duration DEFAULT_LIFETIME = Duration.ofMinutes(15);

    private final String platformEntityId;
    private final Duration lifetime;
    private final KeyStorageLevel keyStorage;
    private final KeyStorageLevel userAuthentication;
    private final String subjectClientId;

    public DeviceAttestationMinter(String platformEntityId) {
        this(platformEntityId, DEFAULT_LIFETIME, KeyStorageLevel.MODERATE, KeyStorageLevel.MODERATE, null);
    }

    /**
     * @param subjectClientId the registered OAuth client id to mint as {@code sub} (the Phase 2.5 flip —
     *                        see the class javadoc), or {@code null} for the legacy behaviour where
     *                        {@code sub} is the instance identifier
     */
    public DeviceAttestationMinter(String platformEntityId, String subjectClientId) {
        this(platformEntityId, DEFAULT_LIFETIME, KeyStorageLevel.MODERATE, KeyStorageLevel.MODERATE, subjectClientId);
    }

    public DeviceAttestationMinter(String platformEntityId, Duration lifetime,
                                   KeyStorageLevel keyStorage, KeyStorageLevel userAuthentication) {
        this(platformEntityId, lifetime, keyStorage, userAuthentication, null);
    }

    /**
     * @param platformEntityId the agent platform's federation entity id — must be the leaf of the trust
     *                         chain a verifier resolves, since that is how the attester's keys are found
     * @param keyStorage       resistance of the key store. A Secure Enclave is a keystore, not a WSCD, so
     *                         {@link KeyStorageLevel#HIGH} is rejected — see the constructor guard
     * @param subjectClientId  the registered OAuth client id to mint as {@code sub}, or {@code null} for
     *                         the legacy instance-id {@code sub} (the Phase 2.5 flip, see class javadoc)
     */
    public DeviceAttestationMinter(String platformEntityId, Duration lifetime,
                                   KeyStorageLevel keyStorage, KeyStorageLevel userAuthentication,
                                   String subjectClientId) {
        this.platformEntityId = requireText(platformEntityId, "platformEntityId");
        this.lifetime = Objects.requireNonNull(lifetime, "lifetime");
        if (lifetime.isNegative() || lifetime.isZero()) {
            throw new IllegalArgumentException("lifetime must be positive");
        }
        this.keyStorage = rejectOverclaim(keyStorage, "keyStorage");
        this.userAuthentication = rejectOverclaim(userAuthentication, "userAuthentication");
        this.subjectClientId = subjectClientId == null || subjectClientId.isBlank() ? null : subjectClientId.trim();
    }

    /**
     * Refuses {@link KeyStorageLevel#HIGH}. This minter attests keys held in an Apple Secure Enclave,
     * which the EUDI ARF classifies as a <em>keystore</em> rather than a WSCD; only a certified WSCD may
     * assert {@code iso_18045_high}. Asserting it here would be a false security claim that a downstream
     * policy might rely on, so it fails loudly at construction rather than quietly at issuance.
     *
     * <p>If a genuinely certified key store is ever attested by a different minter, that minter — not
     * this one — is where {@code HIGH} belongs.
     */
    private static KeyStorageLevel rejectOverclaim(KeyStorageLevel level, String name) {
        Objects.requireNonNull(level, name);
        if (level == KeyStorageLevel.HIGH) {
            throw new IllegalArgumentException(name + " cannot be " + KeyStorageLevel.HIGH.claimValue()
                    + ": a Secure Enclave is a keystore, not a WSCD, and only a WSCD may assert it");
        }
        return level;
    }

    /**
     * Mints an attestation for an instance.
     *
     * @param instance          the registered instance; its {@code id} becomes {@code sub}
     * @param instancePublicJwk the Secure Enclave public key, bound as {@code cnf.jwk}
     * @param authenticatorRef  reference to the passkey that bound this device to its owner — a
     *                          reference only, never the credential itself
     * @param uvReuseSeconds    the user-verification reuse window the device is operating under,
     *                          published so a policy can reason about how stale the user's presence
     *                          might be
     * @param signer            the platform's attestation signing key
     * @return the compact Client Attestation JWT
     */
    public Minted mint(AgentInstance instance, Map<String, Object> instancePublicJwk,
                       String authenticatorRef, long uvReuseSeconds, JwsSigner signer) {
        Objects.requireNonNull(instance, "instance");
        Objects.requireNonNull(signer, "signer");
        if (instancePublicJwk == null || instancePublicJwk.isEmpty()) {
            throw new IllegalArgumentException("instancePublicJwk must not be empty");
        }
        // A private key in a cnf would leak the instance's signing key to every verifier.
        Jwks.assertPublicOnly(instancePublicJwk);

        // The bound key must be the one the registry recorded, or the attestation would vouch for a key
        // the enrolment ceremony never saw.
        String presentedThumbprint;
        try {
            presentedThumbprint = Jwks.thumbprint(instancePublicJwk);
        } catch (Exception e) {
            throw new IllegalArgumentException("instancePublicJwk is not a well-formed JWK", e);
        }
        if (!presentedThumbprint.equals(instance.cnfJkt())) {
            throw new IllegalArgumentException(
                    "instancePublicJwk does not match the key bound to instance " + instance.id());
        }

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(this.lifetime);

        JwtClaims claims = new JwtClaims();
        // Retained although draft -08 removed it: the attester's signing keys are resolved BY iss
        // through the federation trust chain, and the draft puts attester trust establishment out of
        // scope. Recorded as a deliberate divergence in docs/claim-dictionary.md.
        claims.setIssuer(this.platformEntityId);
        // Phase 2.5: sub is the registered client id when configured (the ABCA-conformant shape),
        // else the legacy instance id. Either way agent_id below carries the instance identity.
        claims.setSubject(this.subjectClientId != null ? this.subjectClientId : instance.id());
        // The pseudonymous per-instance identity — the value the instance id has always had, renamed
        // into its own claim so it survives the sub flip with audit joins and CAEP keys intact.
        claims.setClaim("agent_id", instance.id());
        claims.setIssuedAt(NumericDate.fromSeconds(issuedAt.getEpochSecond()));
        claims.setExpirationTime(NumericDate.fromSeconds(expiresAt.getEpochSecond()));

        Map<String, Object> cnf = new LinkedHashMap<>();
        cnf.put("jwk", instancePublicJwk);
        claims.setClaim("cnf", cnf);

        // OpenID4VCI Appendix D vocabulary rather than invented claims.
        claims.setClaim("key_storage", this.keyStorage.claimValue());
        claims.setClaim("user_authentication", this.userAuthentication.claimValue());

        if (authenticatorRef != null && !authenticatorRef.isBlank()) {
            claims.setClaim("authenticator_ref", authenticatorRef);
        }
        if (instance.agentBuild() != null && !instance.agentBuild().isBlank()) {
            claims.setClaim("agent_build", instance.agentBuild());
        }
        claims.setClaim("uv_policy", Map.of("reuse_seconds", uvReuseSeconds));

        String jwt = CompactJws.sign(TYP, claims.toJson(), signer);
        return new Minted(jwt, expiresAt, this.lifetime.toSeconds());
    }

    public Duration lifetime() {
        return this.lifetime;
    }

    public KeyStorageLevel keyStorage() {
        return this.keyStorage;
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value.trim();
    }

    /** A minted attestation and when it dies. */
    public record Minted(String attestation, Instant expiresAt, long expiresInSeconds) {
    }
}
