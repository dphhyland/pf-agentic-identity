package au.com.idpartners.gm.servlet;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.sdk.accessgrant.AccessGrant;
import com.pingidentity.sdk.accessgrant.AccessGrantAttributesHolder;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetail;
import com.pingidentity.sdk.authorizationdetails.AuthorizationDetails;
import org.sourceid.saml20.adapter.attribute.AttributeValue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * The parts of a persistent grant the evaluation needs, as plain data.
 *
 * <p>This exists to keep {@link GrantEvaluator} away from {@link AccessGrant}.
 * PingFederate's AccessGrant is not a value object -- constructing one reaches into the
 * server's service locator and throws "No Impl found for AccessGrantService" outside a
 * running PF -- so anything that touches it directly can only be tested inside the
 * server. Every PF-specific assumption lives in {@link #from}, and the decision logic
 * stays ordinary code.
 *
 * <p>It also names the shape the sidecar and this servlet agree on, which is what lets
 * the same rules exist in both.
 */
public record GrantView(
        String guid,
        String subject,
        String clientId,
        List<String> scopes,
        Long expires,
        List<Map<String, Object>> authorizationDetails) {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final java.util.logging.Logger LOG =
            java.util.logging.Logger.getLogger(GrantView.class.getName());

    public GrantView {
        scopes = scopes == null ? List.of() : List.copyOf(scopes);
        authorizationDetails = authorizationDetails == null ? List.of() : List.copyOf(authorizationDetails);
    }

    /**
     * The grant attribute the consent falls back to when PingFederate has no
     * Authorization Detail Processor deployed and it must be injected server-side.
     * Matches the persistent grant contract in the Terraform.
     */
    static final String CONSENT_ATTRIBUTE = "authorization_details";

    /**
     * Reads a PingFederate grant into a plain view, resolving its consent.
     *
     * <p>PingFederate carries the consent two ways, and they are not equal:
     *
     * <ol>
     *   <li>Natively, from {@link AccessGrant#getAuthorizationDetails()}. This is what
     *       the user was shown and approved, and it exists only when an Authorization
     *       Detail Processor is deployed to validate the type.
     *   <li>As an {@code authorization_details} grant attribute holding a JSON array
     *       encoded inside a string -- the fallback for a PF with no processor, where
     *       the consent is injected by configuration rather than requested by the client.
     * </ol>
     *
     * <p>The native form wins whenever it is present: it is the only one that records
     * what a human agreed to. The attribute is whatever the AS configuration put there,
     * which need not be the same thing.
     *
     * <p>The attributes are supplied lazily and only read when the native consent is
     * absent. Once an authorization detail processor is deployed -- the intended end
     * state -- native consent is always present, and fetching the attributes anyway
     * would be a second grant-store round trip on every single request.
     *
     * @param attributes supplies the grant's attributes, consulted only as a fallback.
     *                   May be null to skip the fallback entirely.
     */
    public static GrantView from(AccessGrant grant, Supplier<AccessGrantAttributesHolder> attributes) {
        if (grant == null) {
            return null;
        }
        List<Map<String, Object>> consent = detailsOf(grant);
        if (consent.isEmpty() && attributes != null) {
            consent = consentFromAttributes(attributes.get());
        }
        return new GrantView(
                grant.getGuid(),
                grant.getUniqueUserIdentifer(),
                grant.getClientId(),
                scopesOf(grant),
                grant.getExpires(),
                consent);
    }

    /**
     * Decodes the consent out of the grant's extended attributes.
     *
     * <p>PF stores each attribute value as an opaque string, so the consent arrives as a
     * JSON array inside one. Anything unreadable is treated as no consent and logged:
     * the alternative -- guessing -- would put words in the user's mouth.
     */
    static List<Map<String, Object>> consentFromAttributes(AccessGrantAttributesHolder attributes) {
        if (attributes == null || attributes.getExtendedGrantAttrs() == null) {
            return List.of();
        }
        AttributeValue value = attributes.getExtendedGrantAttrs().get(CONSENT_ATTRIBUTE);
        if (value == null || value.getValue() == null || value.getValue().isBlank()) {
            return List.of();
        }
        try {
            List<Map<String, Object>> parsed = MAPPER.readValue(
                    value.getValue(), new TypeReference<List<Map<String, Object>>>() {
                    });
            return parsed == null ? List.of() : parsed;
        } catch (Exception e) {
            LOG.warning("grant carries an unreadable " + CONSENT_ATTRIBUTE
                    + " attribute; treating it as no consent: " + e.getMessage());
            return List.of();
        }
    }

    /** OAuth renders scope as one space-separated string. */
    static List<String> scopesOf(AccessGrant grant) {
        List<String> out = new ArrayList<>();
        if (grant.getScope() == null) {
            return out;
        }
        String scopeStr = grant.getScope().getScopeStr();
        if (scopeStr == null || scopeStr.isBlank()) {
            return out;
        }
        for (String s : scopeStr.trim().split("\\s+")) {
            if (!s.isEmpty()) {
                out.add(s);
            }
        }
        return out;
    }

    /**
     * The grant's RFC 9396 consent as plain maps.
     *
     * <p>In-process this is already typed, which is the advantage over the sidecar: that
     * has to unpick the same consent from a JSON document encoded inside a string in a
     * grant attribute, and silently gets an empty list if it gets that wrong.
     */
    static List<Map<String, Object>> detailsOf(AccessGrant grant) {
        List<Map<String, Object>> out = new ArrayList<>();
        AuthorizationDetails details = grant.getAuthorizationDetails();
        if (details == null || details.getDetails() == null) {
            return out;
        }
        for (AuthorizationDetail d : details.getDetails()) {
            Map<String, Object> detail = d.getDetail();
            if (detail != null) {
                out.add(new LinkedHashMap<>(detail));
            }
        }
        return out;
    }

    public boolean isExpired(long nowMillis) {
        return expires != null && expires > 0 && expires < nowMillis;
    }
}
