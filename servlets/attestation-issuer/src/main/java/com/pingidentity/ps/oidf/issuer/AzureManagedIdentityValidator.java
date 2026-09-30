/*
 * EvidenceValidator for Entra-signed Azure managed-identity tokens (Container Apps / VM / Functions).
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jose4j.jwt.JwtClaims;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;

/**
 * The {@code azure-mi-token} evidence type: an Entra-signed access token issued to an Azure managed identity (from the
 * Instance Metadata Service, with this attester as its {@code resource}), verified against the tenant's JWKS and
 * mapped onto {@code spiffe://<attestation_trust_domain>/azure/mi/<oid>}.
 *
 * <p>Microsoft's access token claims reference (read 2026-09-30) defines the claims relied on: {@code tid} "Represents
 * the tenant that the user is signing in to", a GUID; {@code oid} "The immutable identifier for the requestor, which
 * is the verified identity of the user or service principal" - a managed identity is a service principal, so
 * {@code oid} is the managed-identity claim; and {@code iss} "the Microsoft Entra tenant", whose "GUID portion"
 * "can use ... to restrict the set of tenants". {@code xms_mirid} is not in that reference and is not read.
 *
 * <p>Beyond {@link CloudTokenValidator}'s checks: {@code tid} is present and is one of {@code OIDF_ATTESTER_AZURE_TENANTS}
 * when that is set, else the tenant in {@code iss}; {@code oid} is present and is one of
 * {@code OIDF_ATTESTER_AZURE_MANAGED_IDENTITIES} when that is set.
 */
public final class AzureManagedIdentityValidator extends CloudTokenValidator {

    /** The selector names this validator proves. */
    static final List<String> SELECTOR_NAMES = List.of("issuer", "tenant_id", "object_id");

    /** Entra's v1 and v2 issuers; group 1 or 2 is the tenant. Development's default when no issuer is pinned. */
    static final Pattern TENANT_ISSUER = Pattern.compile(
            "https://sts\\.windows\\.net/([0-9a-f-]{36})/|https://login\\.microsoftonline\\.com/([0-9a-f-]{36})/v2\\.0");

    public AzureManagedIdentityValidator() {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS, Policy::process);
    }

    public AzureManagedIdentityValidator(Policy policy) {
        this(ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS, () -> policy);
    }

    AzureManagedIdentityValidator(long allowedClockSkewSeconds, Supplier<Policy> policy) {
        super(allowedClockSkewSeconds, policy);
    }

    @Override
    public String id() {
        return AttestationIssuanceConfig.EVIDENCE_AZURE_MI_TOKEN;
    }

    @Override
    public String title() {
        return "Azure managed-identity token";
    }

    @Override
    public String description() {
        return "An Entra-signed Azure managed-identity token (Container Apps / VM / Functions), verified "
                + "against the tenant's public JWKS and mapped onto a synthetic SPIFFE ID from its object id.";
    }

    @Override
    public List<String> selectorNames() {
        return SELECTOR_NAMES;
    }

    @Override
    protected Pattern developmentIssuer() {
        return TENANT_ISSUER;
    }

    @Override
    protected Mapped map(JwtClaims claims, Policy policy, AttestationIssuanceConfig config) throws IssuanceException {
        String tid = EvidenceSelectors.stringClaim(claims, "tid");
        Set<String> tenants = policy.azureTenants();
        Matcher issuer = TENANT_ISSUER.matcher(claims.getClaimValueAsString("iss"));
        String issuerTenant = issuer.matches() ? (issuer.group(1) != null ? issuer.group(1) : issuer.group(2)) : null;
        String tenant = tid == null ? null : tid.toLowerCase(Locale.ROOT);
        if (tenant == null || (tenants != null ? !tenants.contains(tenant) : !tenant.equals(issuerTenant))) {
            throw refused("tenant", "token's tid is not " + (tenants != null ? "a tenant " + Policy.AZURE_TENANTS + " lists"
                    : "the tenant of its pinned issuer"));
        }
        String oid = EvidenceSelectors.stringClaim(claims, "oid");
        Set<String> identities = policy.azureManagedIdentities();
        if (oid == null || oid.isBlank() || (identities != null && !identities.contains(oid.toLowerCase(Locale.ROOT)))) {
            throw refused("managed_identity", "token has no 'oid' (managed-identity object id) claim, or one "
                    + Policy.AZURE_MANAGED_IDENTITIES + " does not list");
        }
        return new Mapped("/azure/mi/" + oid, this.selectors("issuer", EvidenceSelectors.stringClaim(claims, "iss"),
                "tenant_id", tid, "object_id", oid));
    }
}
