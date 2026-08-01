/*
 * Resolves an instance identifier into the attributes PingFederate maps at issuance.
 */
package com.pingidentity.ps.oidf.registry;

import com.pingidentity.ps.oidf.device.AgentInstance;
import com.pingidentity.ps.oidf.device.ComplianceState;
import com.pingidentity.ps.oidf.device.Device;
import com.pingidentity.ps.oidf.device.InstanceRegistry;
import com.pingidentity.ps.oidf.device.InstanceStatus;
import com.pingidentity.ps.oidf.device.OwnerUser;
import com.pingidentity.ps.oidf.device.RegistryException;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The registry lookup PingFederate performs while issuing a token, kept separate from the
 * {@code CustomDataSourceDriver} shell so it can be tested without the PF SDK.
 *
 * <p>This is where revocation and the time-box actually bite. The attestation the client presented may
 * be perfectly valid and up to fifteen minutes old; between minting and use the instance can have been
 * revoked, the device can have fallen out of compliance, or the user-verification window can have
 * lapsed. None of that is visible in the attestation, so it is read here, at issuance, every time.
 *
 * <h2>What is deliberately not exposed</h2>
 *
 * <p>{@link #AVAILABLE_FIELDS} names everything a mapping may request, and the device identifier,
 * model and OS version are <strong>not</strong> among them. Device data is more sensitive than instance
 * data and must not reach a token or a resource server. Withholding it here means a careless attribute
 * mapping cannot leak it — the field simply does not exist to map.
 *
 * <p>{@link #OWNER_SUBJECT} is the exception that proves the rule: it is the human, and it is exposed
 * precisely because RFC 8693 puts the human in {@code sub} and the instance in {@code act.sub}. This
 * lookup is the only place that resolution happens.
 */
public final class InstanceLookup {

    /** The token's {@code sub}: the human the agent acts for. */
    public static final String OWNER_SUBJECT = "owner_subject";
    /** {@code ACTIVE}, {@code SUSPENDED} or {@code REVOKED}. */
    public static final String INSTANCE_STATUS = "instance_status";
    /** {@code true} only when the instance is ACTIVE — the cheap thing for an issuance criterion. */
    public static final String INSTANCE_ACTIVE = "instance_active";
    /** {@code COMPLIANT}, {@code NOT_COMPLIANT} or {@code UNKNOWN}. */
    public static final String DEVICE_COMPLIANCE = "device_compliance";
    /** {@code true} only when the device is COMPLIANT; an unassessed device is false. */
    public static final String DEVICE_COMPLIANT = "device_compliant";
    /** Seconds since the owner last completed user verification, or -1 if never. */
    public static final String UV_SECONDS_AGO = "uv_seconds_ago";
    /** {@code true} when user verification is within the configured window. The time-box, in one field. */
    public static final String UV_FRESH = "uv_fresh";
    /** The agent platform's federation entity id. */
    public static final String PLATFORM_ENTITY_ID = "platform_entity_id";
    /** The agent build this instance is running. */
    public static final String AGENT_BUILD = "agent_build";
    /** RFC 7638 thumbprint of the bound key, so a mapping can cross-check the attestation's cnf. */
    public static final String CNF_JKT = "cnf_jkt";

    /**
     * Every field a mapping may request. Device identifiers are absent on purpose — see the class
     * javadoc.
     */
    public static final List<String> AVAILABLE_FIELDS = List.of(
            OWNER_SUBJECT, INSTANCE_STATUS, INSTANCE_ACTIVE, DEVICE_COMPLIANCE, DEVICE_COMPLIANT,
            UV_SECONDS_AGO, UV_FRESH, PLATFORM_ENTITY_ID, AGENT_BUILD, CNF_JKT);

    private final InstanceRegistry registry;
    private final Duration userVerificationMaxAge;

    public InstanceLookup(InstanceRegistry registry, Duration userVerificationMaxAge) {
        this.registry = Objects.requireNonNull(registry, "registry");
        this.userVerificationMaxAge = Objects.requireNonNull(userVerificationMaxAge, "userVerificationMaxAge");
    }

    /**
     * Resolves an instance.
     *
     * <p>An unknown instance yields {@link #notFound()} rather than an exception: a revoked instance
     * whose row has been deleted, and an identifier that never existed, should look the same to a
     * mapping — both must fail closed, and neither should be distinguishable by the caller.
     */
    public Map<String, Object> lookup(String instanceId, Instant now) throws RegistryException {
        if (instanceId == null || instanceId.isBlank()) {
            return notFound();
        }
        AgentInstance instance = this.registry.findInstance(instanceId).orElse(null);
        if (instance == null) {
            return notFound();
        }
        Device device = this.registry.findDevice(instance.deviceId()).orElse(null);
        OwnerUser owner = device == null
                ? null
                : this.registry.findOwner(device.ownerUserId()).orElse(null);

        Map<String, Object> values = new LinkedHashMap<>();
        values.put(OWNER_SUBJECT, owner == null ? null : owner.pingOneSubject());
        values.put(INSTANCE_STATUS, instance.status().name());
        values.put(INSTANCE_ACTIVE, instance.status() == InstanceStatus.ACTIVE);

        ComplianceState compliance = device == null ? ComplianceState.UNKNOWN : device.complianceState();
        values.put(DEVICE_COMPLIANCE, compliance.name());
        values.put(DEVICE_COMPLIANT, compliance == ComplianceState.COMPLIANT);

        long secondsAgo = instance.uvLastVerifiedAt() == null
                ? -1L
                : Math.max(0L, Duration.between(instance.uvLastVerifiedAt(), now).toSeconds());
        values.put(UV_SECONDS_AGO, secondsAgo);
        values.put(UV_FRESH, instance.userVerificationFreshAt(now, this.userVerificationMaxAge));

        values.put(PLATFORM_ENTITY_ID, instance.platformEntityId());
        values.put(AGENT_BUILD, instance.agentBuild());
        values.put(CNF_JKT, instance.cnfJkt());
        return values;
    }

    /**
     * The fail-closed result. Every boolean is false and every identifier null, so an issuance
     * criterion written against any of them refuses rather than passing on a missing value.
     */
    public static Map<String, Object> notFound() {
        Map<String, Object> values = new LinkedHashMap<>();
        values.put(OWNER_SUBJECT, null);
        values.put(INSTANCE_STATUS, "UNKNOWN");
        values.put(INSTANCE_ACTIVE, false);
        values.put(DEVICE_COMPLIANCE, ComplianceState.UNKNOWN.name());
        values.put(DEVICE_COMPLIANT, false);
        values.put(UV_SECONDS_AGO, -1L);
        values.put(UV_FRESH, false);
        values.put(PLATFORM_ENTITY_ID, null);
        values.put(AGENT_BUILD, null);
        values.put(CNF_JKT, null);
        return values;
    }

    public Duration userVerificationMaxAge() {
        return this.userVerificationMaxAge;
    }
}
