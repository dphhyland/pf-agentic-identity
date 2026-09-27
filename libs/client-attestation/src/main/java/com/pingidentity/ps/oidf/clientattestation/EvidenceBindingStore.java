/*
 * Binds a piece of instance evidence to the first instance key that presents it.
 */
package com.pingidentity.ps.oidf.clientattestation;

/**
 * Records which instance key (its RFC 7638 thumbprint) and which client a piece of instance evidence - a
 * JWT-SVID, a cloud platform token, a Wallet Instance Attestation - was first bound to, keyed by the
 * evidence's SHA-256 digest, for as long as the evidence lives. The attester consults it after the key proof
 * verifies: the first presenter wins the binding, the same presenter may present again, and anyone else
 * presenting the same evidence is a conflict.
 *
 * <p>What this buys: evidence whose audience is the attester used to be reusable by anyone who saw an
 * attestation carrying it (finding F-0002). The raw evidence no longer leaves the attester, and a thief
 * who obtains it some other way and presents it second is refused and audited. What it does not buy: a
 * thief who presents first wins, and the rightful holder is the one refused. That is detectable (the
 * conflict event names both keys), not preventable, without evidence that is itself bound to the instance
 * key.
 *
 * <p>Implementations: {@link InMemoryEvidenceBindingStore} (per-node) and {@link RedisAttestationStore}
 * (shared, cluster-safe: {@code SET NX}, whose winner is stable under a race).
 */
public interface EvidenceBindingStore {
    int DEFAULT_MAX_ENTRIES = 8192;

    /** What the store found when asked to bind evidence to a key and client. */
    enum Binding {
        /** The evidence is bound to this key and client: either just now, or already, by the same presenter. */
        BOUND,
        /** The evidence is bound to a different key or a different client. */
        CONFLICT,
        /** The store could not be asked or did not answer; nothing was bound. */
        STORE_UNAVAILABLE
    }

    /**
     * Binds the evidence to {@code (jkt, clientId)} unless it is already bound to something else.
     *
     * @param evidenceDigest        the evidence's SHA-256, lower-case hex
     * @param jkt                   the instance key's RFC 7638 thumbprint
     * @param clientId              the client the attestation is issued for
     * @param evidenceExpEpochSeconds when the evidence expires; the binding is kept until then
     */
    Binding bind(String evidenceDigest, String jkt, String clientId, long evidenceExpEpochSeconds);
}
