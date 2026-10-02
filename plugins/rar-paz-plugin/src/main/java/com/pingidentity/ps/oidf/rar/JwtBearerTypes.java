/*
 * The processor's "Types allowed on the JWT-bearer grant" field: read, checked on save and at configure.
 */
package com.pingidentity.ps.oidf.rar;

import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.validation.ConfigurationValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;

import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/**
 * Which of this processor's types a JWT-bearer token request (RFC 7523 section 2.1, {@value #GRANT_TYPE}) may carry.
 *
 * <p>PingFederate 13.1.3 calls the processor's {@code validate} on that grant and never {@code enrich}, so the PDP is
 * never asked there (U-0017, driven on the rig on 2026-09-30): on the plain profile {@code validate} sees the request's
 * {@code authorization_details} before the assertion is verified, and the token carries none of them; on the ID-JAG
 * profile ({@code typ} {@code oauth-id-jag+jwt}) it sees the assertion's own {@code authorization_details} after the
 * signature is verified, and the token carries them as they are. A type not listed here is refused by {@code validate}
 * (F-0108); a listed type passes {@code validate}'s model check and is issued without a PDP decision.
 *
 * <p>No principal can be established on that grant from inside the processor, so a type the "Types requiring an
 * authenticated principal" field lists is never allowed here. Like the other checked fields it is checked twice:
 * {@link Validator} on save, where the message reaches the person saving, and {@link #of} at configure, the only
 * check an archive import gets - a refusal there leaves the instance unconfigured, and {@code validate} then refuses
 * every detail bound to it.
 */
final class JwtBearerTypes {

    /** The field's name, as PingFederate stores it. */
    static final String FIELD = "Types allowed on the JWT-bearer grant";

    /** RFC 7523 section 2.1: "The value of the "grant_type" is "urn:ietf:params:oauth:grant-type:jwt-bearer"." */
    static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    /** What {@code validate} answers for a type the field does not list: the same words whatever the type. */
    static final String REFUSAL = "authorization_details of this type are not accepted on the JWT-bearer grant";

    private JwtBearerTypes() {
    }

    /**
     * The field's types, checked against the types requiring an authenticated principal.
     *
     * @throws IllegalStateException naming the field and the types it may not list
     */
    static Set<String> of(Configuration configuration, Set<String> principalTypes) {
        Set<String> types = PdpDecisions.typesOf(configuration.getFieldValue(FIELD));
        String refusal = refusal(types, principalTypes);
        if (refusal != null) {
            throw new IllegalStateException(refusal);
        }
        return Collections.unmodifiableSet(types);
    }

    /** Why these types may not be allowed on the JWT-bearer grant, or {@code null} when they may. */
    static String refusal(Set<String> types, Set<String> principalTypes) {
        Set<String> refused = new TreeSet<>(types);
        refused.retainAll(principalTypes);
        if (refused.isEmpty()) {
            return null;
        }
        return FIELD + " may not list " + String.join(", ", refused) + ": the field "
                + AttestationAwareRarProcessor.AUTHENTICATED_PRINCIPAL_TYPES + " lists "
                + (refused.size() == 1 ? "it" : "them") + ", and no authenticated principal can be established on the "
                + "JWT-bearer grant, where PingFederate never asks this processor to decide";
    }

    /** Whether a {@code grant_type} is the JWT-bearer grant's. */
    static boolean isJwtBearer(String grantType) {
        return GRANT_TYPE.equals(grantType);
    }

    /** The admin-console half: the rule above, on save, with the principal types the form holds. */
    static final class Validator implements ConfigurationValidator {

        @Override
        public void validate(Configuration configuration) throws ValidationException {
            String refusal = refusal(PdpDecisions.typesOf(configuration.getFieldValue(FIELD)),
                    GovernanceEngineConfig.authenticatedPrincipalTypesOf(
                            configuration.getFieldValue(AttestationAwareRarProcessor.AUTHENTICATED_PRINCIPAL_TYPES)));
            if (refusal != null) {
                throw new ValidationException(refusal);
            }
        }
    }
}
