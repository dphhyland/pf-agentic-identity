/*
 * The fixed registry of risks a production deployment may accept by name.
 */
package com.pingidentity.ps.oidf.platform.profile;

/**
 * A risky but legitimate switch a production deployment may turn on only by naming it in
 * {@value AcceptedRisks#SETTING} (plan decision 4). The ids are stable: an operator writes them into a deployment,
 * so one is never renamed or reused, only retired with a release note. PR-2 (Phase 3) wires each to its switch;
 * until then nothing asks for one, and the start-up audit (F-2) reports what a deployment accepts.
 */
public enum AcceptedRisk {
    /** Federation registration with no superior's metadata policy ({@code OIDF_REQUIRE_METADATA_POLICY=false}). */
    NO_METADATA_POLICY("no-metadata-policy", false,
            "federation registration goes ahead when no superior in the chain sets a metadata policy"),
    /** Attestation without the attester binding ({@code OIDF_ATTESTATION_REQUIRE_ATTESTER_BINDING=false}). */
    ATTESTER_BINDING_OFF("attester-binding-off", false,
            "a client whose bridge-key entry names no attesters is served, so any trusted attester can vouch for it"),
    /** Registration goes ahead when its policy check cannot be answered; PR-2 names the switch. */
    REGISTRATION_FAIL_OPEN("registration-fail-open", false,
            "a registration goes ahead unnarrowed when its policy decision cannot be had"),
    /** Expired registrations logged, not enforced ({@code OIDF_REGISTRATION_EXPIRY_ENFORCEMENT=log}): dated only. */
    EXPIRY_LOG_MODE("expiry-log-mode", true,
            "an expired registration is logged and still served"),
    /** A request goes ahead unnarrowed when the PDP cannot answer ({@code OIDF_PDP_FAIL_OPEN=true} and the plugin's own switch). */
    PDP_FAIL_OPEN("pdp-fail-open", false,
            "a request goes ahead without the PDP's narrowing when the PDP cannot be reached"),
    /** Automatic registration without PKCE ({@code OIDF_AUTO_REGISTRATION_REQUIRE_PKCE=false}). */
    PKCE_OFF("pkce-off", false,
            "front-channel relying parties are registered without requiring PKCE"),
    /** The resolve endpoint answers for any entity ({@code OIDF_FEDERATION_RESOLVE_DISCOVERY=any}). */
    RESOLVE_ANY("resolve-any", false,
            "the federation resolve endpoint resolves any entity for anyone, not only this entity's own"),
    /** Federation audit events kept out of PingFederate's audit log ({@code OIDF_EVENTS_AUDIT=false}). */
    AUDIT_OFF("audit-off", false,
            "security events are kept out of PingFederate's audit log"),
    /** State held in one node's memory while standalone; forbidden outright when clustered (decision 4). */
    IN_MEMORY_STATE("in-memory-state", false,
            "a store keeps its state in this node's memory, lost on restart and invisible to any other node");

    private final String id;
    private final boolean dated;
    private final String description;

    AcceptedRisk(String id, boolean dated, String description) {
        this.id = id;
        this.dated = dated;
        this.description = description;
    }

    /** The id an operator writes in {@value AcceptedRisks#SETTING}. */
    public String id() {
        return this.id;
    }

    /** Whether an acceptance must carry an expiry ({@code id@YYYY-MM-DD}); an undated one is refused. */
    public boolean dated() {
        return this.dated;
    }

    /** What accepting it lets happen, in one line, for a refusal message and the start-up audit. */
    public String description() {
        return this.description;
    }

    /** The risk with this id, exactly as written (ids are lower case), or null for an id nobody registered. */
    public static AcceptedRisk byId(String id) {
        for (AcceptedRisk risk : values()) {
            if (risk.id.equals(id)) {
                return risk;
            }
        }
        return null;
    }
}
