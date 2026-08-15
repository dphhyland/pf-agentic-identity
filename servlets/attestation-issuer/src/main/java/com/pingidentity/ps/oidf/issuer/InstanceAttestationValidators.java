/*
 * Registry of InstanceAttestationValidators, keyed by evidence-type id and grouped by format family.
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jws.JsonWebSignature;

/**
 * The catalogue of instance-attestation formats the attester supports. Every fact the rest of the attester
 * needs about an evidence type — is it accepted, which validator runs it, does it need a trust domain, what
 * does discovery advertise — is derived from here, so adding a type means registering one plugin rather than
 * editing a scattered set of lists.
 *
 * <p><strong>Selection.</strong> The primary key is the evidence-type {@link InstanceAttestationValidator#id()},
 * because a workload names no client: the issuance endpoint reverse-maps evidence onto a client by trying
 * each attestation client's configured {@code attestation_evidence}. {@link #sniff(String)} is a secondary,
 * best-effort read of the presented token's <em>format family</em>, used to narrow that search and to
 * produce a better error when nothing matches. Sniffing only routes — the chosen validator still fully
 * verifies the attestation.
 *
 * <p>Several ids commonly share one format: all the cloud platform tokens resolve to a SPIFFE identity and
 * so report {@code format() == "spiffe"}, while a wallet WIA reports {@code "wallet"}.
 */
public final class InstanceAttestationValidators {

    private final Map<String, InstanceAttestationValidator> byId;

    public InstanceAttestationValidators(List<InstanceAttestationValidator> validators) {
        Map<String, InstanceAttestationValidator> m = new LinkedHashMap<>();
        for (InstanceAttestationValidator v : validators) {
            InstanceAttestationValidator clash = m.put(v.id(), v);
            if (clash != null) {
                throw new IllegalArgumentException("two validators registered for evidence type '" + v.id()
                        + "': " + clash.getClass().getName() + " and " + v.getClass().getName());
            }
        }
        this.byId = m;
    }

    /** A registry holding only the SPIFFE validator — the minimum any attester supports. */
    public static InstanceAttestationValidators spiffeOnly() {
        return new InstanceAttestationValidators(List.of(new SpiffeInstanceAttestationValidator()));
    }

    /**
     * Every built-in evidence type, independent of deployment wiring. This is the catalogue config validation
     * checks against, so whether {@code attestation_evidence} names a <em>known</em> type never depends on
     * runtime configuration.
     *
     * <p>The wallet entry is registered with an unconfigured key resolver: the id is always recognised, but
     * presenting a WIA without wallet-provider trust configured fails with a clear
     * {@code invalid_instance_attestation}. A deployment that configures wallet trust replaces this entry
     * via {@link #with(InstanceAttestationValidator)}.
     */
    public static InstanceAttestationValidators defaults() {
        return DEFAULTS;
    }

    /** Validators are stateless, so the built-in catalogue is built once and shared. */
    private static final InstanceAttestationValidators DEFAULTS = new InstanceAttestationValidators(List.of(
            new SpiffeInstanceAttestationValidator(),
            new GkeTokenValidator(),
            new GcpSaTokenValidator(),
            new EksTokenValidator(),
            new AwsStsWebIdentityValidator(),
            new AksWorkloadIdentityValidator(),
            new AzureManagedIdentityValidator(),
            new WalletInstanceAttestationValidator(InstanceAttestationValidators::unconfiguredWalletTrust)));

    /**
     * This registry plus {@code validator}, replacing any existing entry with the same id. Used at servlet
     * init to swap the placeholder wallet validator for a wired one.
     */
    public InstanceAttestationValidators with(InstanceAttestationValidator validator) {
        List<InstanceAttestationValidator> merged = new ArrayList<>();
        for (InstanceAttestationValidator existing : this.byId.values()) {
            if (!existing.id().equals(validator.id())) {
                merged.add(existing);
            }
        }
        merged.add(validator);
        return new InstanceAttestationValidators(merged);
    }

    /**
     * Stands in for wallet-provider trust that the deployment has not configured. Registering it keeps the
     * wallet evidence type discoverable and config-validatable while making an actual attempt fail loudly
     * rather than silently accepting an unverifiable provider.
     */
    private static List<JsonWebKey> unconfiguredWalletTrust(String issuer, List<String> trustChain) {
        throw new IllegalStateException("no wallet-provider trust is configured on this attester "
                + "(set a federation trust anchor or OIDF_WALLET_PROVIDER_JWKS)");
    }

    /** Whether an evidence-type id is registered. Replaces the hand-maintained accepted-type whitelist. */
    public boolean supports(String id) {
        return this.byId.containsKey(id);
    }

    public Optional<InstanceAttestationValidator> find(String id) {
        return Optional.ofNullable(this.byId.get(id));
    }

    /**
     * The validator for an evidence-type id.
     *
     * @throws IssuanceException {@code invalid_client} if no validator handles it — a client configured with
     *                           an unknown {@code attestation_evidence} is a configuration fault
     */
    public InstanceAttestationValidator require(String id) throws IssuanceException {
        InstanceAttestationValidator v = this.byId.get(id);
        if (v == null) {
            throw IssuanceException.invalidClient("unsupported instance attestation type: " + id);
        }
        return v;
    }

    /**
     * Whether the given evidence type requires {@code attestation_trust_domain}. Replaces the hardcoded
     * "mapped evidence" boolean; unknown ids report false and are rejected separately by {@link #require}.
     */
    public boolean requiresTrustDomain(String id) {
        InstanceAttestationValidator v = this.byId.get(id);
        return v != null && v.requiresTrustDomain();
    }

    /**
     * Whether the given evidence type needs a SPIFFE trust bundle configured. Unknown ids report true, the
     * conservative answer — they are rejected separately by {@link #require}.
     */
    public boolean requiresTrustBundle(String id) {
        InstanceAttestationValidator v = this.byId.get(id);
        return v == null || v.requiresTrustBundle();
    }

    /** The registered evidence-type ids, in registration order. Drives the discovery document. */
    public List<String> ids() {
        return List.copyOf(this.byId.keySet());
    }

    /** The distinct format families present, in registration order. */
    public List<String> formats() {
        Set<String> out = new LinkedHashSet<>();
        for (InstanceAttestationValidator v : this.byId.values()) {
            out.add(v.format());
        }
        return List.copyOf(out);
    }

    /** The ids belonging to one format family — used to narrow the reverse-mapping search. */
    public List<String> idsForFormat(String format) {
        List<String> out = new ArrayList<>();
        for (InstanceAttestationValidator v : this.byId.values()) {
            if (v.format().equals(format)) {
                out.add(v.id());
            }
        }
        return List.copyOf(out);
    }

    /**
     * Self-describing catalogue for the attester discovery document, as {id, format, title, description}
     * maps — the counterpart of {@link ClientResolverPlugins#supported()} on the client-resolution axis.
     */
    public List<Map<String, Object>> supported() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (InstanceAttestationValidator v : this.byId.values()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", v.id());
            m.put("format", v.format());
            m.put("title", v.title());
            m.put("description", v.description());
            if (v.requiresTrustDomain()) {
                m.put("requires_trust_domain", Boolean.TRUE);
            }
            out.add(m);
        }
        return out;
    }

    /**
     * Best-effort format-family detection from an <em>unverified</em> token; defaults to SPIFFE. A
     * {@code sub} of {@code spiffe://…} is a SPIFFE SVID; a recognised WIA {@code typ}, or a {@code cnf}
     * claim, marks a wallet instance attestation.
     */
    public static String sniff(String presented) {
        if (presented == null || presented.isBlank()) {
            return SpiffeInstanceAttestationValidator.FORMAT;
        }
        try {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(presented);
            JwtClaims claims = JwtClaims.parse(jws.getUnverifiedPayload());
            String sub = claims.getClaimValueAsString("sub");
            if (sub != null && sub.startsWith("spiffe://")) {
                return SpiffeInstanceAttestationValidator.FORMAT;
            }
            String typ = jws.getHeader("typ");
            if (typ != null && WalletInstanceAttestationValidator.WIA_TYPES.contains(typ)) {
                return WalletInstanceAttestationValidator.FORMAT;
            }
            if (claims.hasClaim("cnf")) {
                return WalletInstanceAttestationValidator.FORMAT;
            }
        } catch (Exception ignored) {
            // fall through to the SPIFFE default
        }
        return SpiffeInstanceAttestationValidator.FORMAT;
    }
}
