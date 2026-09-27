/*
 * Binds a piece of instance evidence to the first instance key that presents it.
 */
package com.pingidentity.ps.oidf.clientattestation;

/**
 * Records which instance key (its RFC 7638 thumbprint) and which client a piece of instance evidence - a
 * JWT-SVID, a cloud platform token, a Wallet Instance Attestation - was first bound to, keyed by the
 * evidence's digest, for as long as the evidence lives. The digest covers only what the evidence's signature
 * covers (its JWS Signing Input), so re-encoding the token - trailing whitespace, a re-encoded or twin
 * signature - does not make it new evidence. The attester consults the store once every other check has
 * passed: the first presenter wins the binding, the same presenter may present again, and anyone else
 * presenting the same evidence is a conflict.
 *
 * <p>What this buys: evidence whose audience is the attester used to be reusable by anyone who saw an
 * attestation carrying it (finding F-0002). The raw evidence no longer leaves the attester, and a thief
 * who obtains it some other way and presents it second is refused and audited. What it does not buy: a
 * thief who presents first wins, and the rightful holder is the one refused. That is detectable (a conflict
 * reports who holds the binding, and the attester's conflict event names both keys), not preventable,
 * without evidence that is itself bound to the instance key.
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

    /** What a bind found, and on a conflict who holds the binding. */
    final class Result {
        private static final Result BOUND = new Result(Binding.BOUND, null, null);
        private static final Result UNAVAILABLE = new Result(Binding.STORE_UNAVAILABLE, null, null);

        private final Binding binding;
        private final String holderJkt;
        private final String holderClientId;

        private Result(Binding binding, String holderJkt, String holderClientId) {
            this.binding = binding;
            this.holderJkt = holderJkt;
            this.holderClientId = holderClientId;
        }

        /** The evidence is bound to the presenter. */
        public static Result bound() {
            return BOUND;
        }

        /** The store did not answer; nothing was bound and nothing is known about the holder. */
        public static Result unavailable() {
            return UNAVAILABLE;
        }

        /** The evidence is bound to {@code holderJkt} for {@code holderClientId} (empty when bound for no client). */
        public static Result conflict(String holderJkt, String holderClientId) {
            return new Result(Binding.CONFLICT, holderJkt, holderClientId);
        }

        public Binding binding() {
            return this.binding;
        }

        /** On a {@link Binding#CONFLICT}, the thumbprint of the key that holds the binding; otherwise null. */
        public String holderJkt() {
            return this.holderJkt;
        }

        /** On a {@link Binding#CONFLICT}, the client the binding is held for; otherwise null. */
        public String holderClientId() {
            return this.holderClientId;
        }

        @Override
        public String toString() {
            return this.binding == Binding.CONFLICT
                    ? "CONFLICT(" + this.holderJkt + " " + this.holderClientId + ")" : this.binding.name();
        }
    }

    /**
     * Binds the evidence to {@code (jkt, clientId)} unless it is already bound to something else.
     *
     * @param evidenceDigest        the evidence's digest, lower-case hex (the SHA-256 of its JWS Signing Input)
     * @param jkt                   the instance key's RFC 7638 thumbprint
     * @param clientId              the client the attestation is issued for
     * @param evidenceExpEpochSeconds when the evidence expires; the binding is kept until then
     * @return the outcome; on a conflict, with the key and client that hold the binding
     */
    Result bind(String evidenceDigest, String jkt, String clientId, long evidenceExpEpochSeconds);
}
