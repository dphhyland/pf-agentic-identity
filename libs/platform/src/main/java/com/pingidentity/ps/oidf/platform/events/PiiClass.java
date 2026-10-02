/*
 * What kind of personal data an event field can hold.
 */
package com.pingidentity.ps.oidf.platform.events;

/**
 * The one class a catalogue gives each field (plan item O-1). {@link PiiPolicy} says what each class may do in
 * each log.
 */
public enum PiiClass {
    /** Says nothing about a person or a party: a mode, a count, an endpoint name, a decision, a time. */
    OPERATIONAL,
    /**
     * Identifies a party without naming a person: a client id, an entity identifier, a key id, a workload's SPIFFE
     * id, an agent id. It links records about one party together and can be looked up in a registry.
     */
    PSEUDONYMOUS_ID,
    /** Can name a person directly: a caller's self-declared name, an e-mail address, a username. */
    DIRECT_ID,
    /** Where a request came from or went to: an IP address, a host name. */
    NETWORK,
    /** A digest or thumbprint of a credential - a key's JWK thumbprint, evidence's SHA-256 - never the credential. */
    CREDENTIAL_DIGEST
}
