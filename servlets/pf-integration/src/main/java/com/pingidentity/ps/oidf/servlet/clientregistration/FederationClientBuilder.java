/*
 * The PingFederate client a federation registration becomes.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.AutoRegistrationSettings;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ClientAuthenticationType;
import org.sourceid.oauth20.domain.ParamValues;

/**
 * Turns a registration's resolved metadata into the PingFederate {@link Client} it is stored as. Two shapes:
 * {@link #agent} for the token endpoint and explicit registration, as clients have always been built here, and
 * {@link #relyingParty} for an RP registering at the authorization or PAR endpoint (OpenID Federation 1.0
 * §12.1.1), which has redirect URIs, signs its requests and is held to them.
 *
 * <p>Both narrow and never widen: a client may use only the response types and scopes its metadata - which a
 * superior's policy has constrained - declares. Both record where the registration came from, when it ends and
 * the chain it came from, in extended properties every deployment must declare ({@link FederationClientParams}).
 */
final class FederationClientBuilder {

    /** Where a registration came from and when it ends: what every federation client records. */
    record Provenance(String status, List<String> trustChain, long expiresAt, String trustAnchor, String entityType) {
    }

    private FederationClientBuilder() {
    }

    /**
     * An agent, or any client registered at the token endpoint or explicitly. PingFederate has no native
     * {@code attest_jwt_client_auth} type; such a client is {@code PRIVATE_KEY_JWT}, authenticated by its own
     * registered keys through the attestation bridge, and marked so the bridge knows it.
     */
    static Client agent(String clientId, Map<String, Object> metadata, RpKeyMaterial.Keys keys, Provenance provenance) {
        Client client = new Client();
        String tokenEndpointAuthMethod = metadataString(metadata, "token_endpoint_auth_method");
        boolean attestationAuth = isAttestation(tokenEndpointAuthMethod);
        // PingFederate has no native attest_jwt_client_auth type. It used to be mapped to NONE - a
        // PUBLIC client - on the theory that ClientAttestationAuthFilter and the OGNL issuance
        // criterion would authenticate it instead. But the filter passes through when no bridge key is
        // configured, and no environment in this repo sets one, so that composition produced
        // JIT-registered clients PF would accept with no credential at all. Attestation clients are
        // now PRIVATE_KEY_JWT authenticated by their OWN registered keys: the filter mints an assertion
        // under the client's own key (BridgeSigners), so PF's native authenticator makes the decision,
        // and a client with no signing key configured simply cannot authenticate (fail closed) rather
        // than authenticating trivially.
        client.setClientAuthnType(ClientAuthenticationType.PRIVATE_KEY_JWT);
        // The client's own registered keys, unmodified. Nothing is injected here any more: the bridge
        // signs with the key this client is ALREADY registered with, so there is no deployment key whose
        // public half has to be merged in - and no ordering trap where a client registered before that
        // key existed never carried it.
        setKeys(client, keys);
        // String.valueOf(null) is the string "null", not null. Every one of these used to write that
        // literal into PF whenever the leaf omitted the field - a client actually named "null", signing
        // algorithms of "null", and (worst) a client restricted to a scope called "null", which is a
        // scope no token will ever carry. metadataString is the null-safe reader; use it.
        client.setName(metadataString(metadata, "client_name"));
        // An oauth_client doing client_credentials legitimately has no redirect_uris / response_types,
        // but PF's XML client store iterates these lists unguarded at save time — never pass null.
        client.setRedirectUris(strings(metadata.get("redirect_uris")));
        client.setRestrictedResponseTypes(strings(metadata.get("response_types")));
        // The list alone restricts nothing: PingFederate consults restrictedResponseTypes only when
        // restrictResponseTypes is set. Until this flag was set a federation client could use any response
        // type the server allows, whatever its (policy-constrained) metadata said.
        client.setRestrictResponseTypes(true);
        List<String> grantTypes = strings(metadata.get("grant_types"));
        client.setGrantTypes(new HashSet<>(grantTypes));
        client.setTokenEndpointAuthSigningAlgorithm(metadataString(metadata, "token_endpoint_auth_signing_alg"));
        client.setIdTokenSigningAlgorithm(metadataString(metadata, "id_token_signed_response_alg"));
        client.setRequestObjectSigningAlgorithm(metadataString(metadata, "request_object_signing_alg"));
        client.setRestrictedScopes(scopes(metadataString(metadata, "scope")));
        // Likewise for scopes: without the flag PF ignores the list and the client may request any scope the
        // server defines - exactly what a superior's metadata_policy on `scope` exists to prevent. With it, a
        // leaf that declares no scope may request none.
        client.setRestrictScopes(true);
        client.setBypassApprovalPage(bypassApprovalPage(grantTypes));
        client.setExtendedParams(extendedParams(metadata, provenance, attestationAuth ? tokenEndpointAuthMethod : null));
        client.setClientId(clientId);
        return client;
    }

    /**
     * An RP registering at the authorization or PAR endpoint (§12.1.1). It authenticates with its keys (§12.1:
     * "asymmetric cryptography MUST be used"), is registered with the keys it publishes for
     * {@code openid_relying_party}, and is held to what it registered with: signed request objects when it proved
     * itself with one, PAR when it proved itself at PAR, its redirect URIs, and response types and scopes it
     * declared - {@code code} and {@code settings.defaultScopes()} when it declared none.
     *
     * @param proofKind how it proved it holds its keys
     * @param proofAlg  the {@code alg} of that proof, used when its metadata names no request-object algorithm
     * @throws RegistrationRejectedException {@code invalid_client_metadata} for an RP this path cannot register
     */
    static Client relyingParty(String clientId, Map<String, Object> metadata, RpKeyMaterial.Keys keys, Provenance provenance,
                               AutoRegistrationSettings settings, RequestObject.Kind proofKind, String proofAlg)
            throws RegistrationRejectedException {
        String authMethod = metadataString(metadata, "token_endpoint_auth_method");
        if (authMethod != null && !"private_key_jwt".equals(authMethod) && !isAttestation(authMethod)) {
            throw new RegistrationRejectedException(400, "invalid_client_metadata", "token_endpoint_auth_method " + authMethod
                    + " cannot be registered automatically here: it needs private_key_jwt (OpenID Federation 1.0 §12.1)");
        }
        List<String> redirectUris = strings(metadata.get("redirect_uris"));
        if (redirectUris.isEmpty()) {
            throw new RegistrationRejectedException(400, "invalid_client_metadata",
                    "an RP registering at the authorization endpoint needs redirect_uris");
        }
        Client client = new Client();
        client.setClientId(clientId);
        client.setClientAuthnType(ClientAuthenticationType.PRIVATE_KEY_JWT);
        setKeys(client, keys);
        client.setName(metadataString(metadata, "client_name"));
        client.setRedirectUris(redirectUris);
        List<String> responseTypes = strings(metadata.get("response_types"));
        client.setRestrictedResponseTypes(responseTypes.isEmpty() ? new ArrayList<>(List.of("code")) : responseTypes);
        client.setRestrictResponseTypes(true);
        List<String> grantTypes = strings(metadata.get("grant_types"));
        client.setGrantTypes(new HashSet<>(grantTypes.isEmpty() ? List.of("authorization_code") : grantTypes));
        String scope = metadataString(metadata, "scope");
        client.setRestrictedScopes(scopes(scope != null ? scope : settings.defaultScopes()));
        client.setRestrictScopes(true);
        client.setTokenEndpointAuthSigningAlgorithm(metadataString(metadata, "token_endpoint_auth_signing_alg"));
        client.setIdTokenSigningAlgorithm(metadataString(metadata, "id_token_signed_response_alg"));
        String requestObjectAlg = metadataString(metadata, "request_object_signing_alg");
        client.setRequestObjectSigningAlgorithm(requestObjectAlg != null ? requestObjectAlg : proofAlg);
        // §12.1.1: every authentication request "MUST demonstrate" key control. PingFederate can hold a client to
        // signed request objects or to PAR (whose endpoint authenticates it), not to "either"; the RP chose by how
        // it first proved itself.
        boolean byRequestObject = proofKind == RequestObject.Kind.REQUEST_OBJECT;
        client.setRequireSignedRequests(byRequestObject);
        client.setRequirePushedAuthorizationRequests(!byRequestObject || settings.requirePar()
                || Boolean.TRUE.equals(metadata.get("require_pushed_authorization_requests")));
        client.setRequireProofKeyForCodeExchange(settings.requirePkce());
        client.setBypassApprovalPage(false);
        client.setExtendedParams(extendedParams(metadata, provenance, isAttestation(authMethod) ? authMethod : null));
        return client;
    }

    private static boolean isAttestation(String authMethod) {
        return "attest_jwt_client_auth".equals(authMethod) || "attest_jwt_client_auth_dpop".equals(authMethod);
    }

    private static void setKeys(Client client, RpKeyMaterial.Keys keys) {
        if (keys.jwksUri() != null) {
            client.setJwksUrl(keys.jwksUri());
        } else {
            client.setJwks(keys.jwks());
        }
    }

    /**
     * The extended properties every federation client carries. Every name written here must be declared in the
     * deploying PF or it is dropped - see {@link FederationClientParams}, which both this and
     * {@code docs/extended-properties.json} are checked against.
     */
    private static Map<String, ParamValues> extendedParams(Map<String, Object> metadata, Provenance provenance, String attestationMethod) {
        HashMap<String, ParamValues> params = new HashMap<>();
        addParamValue(params, FederationClientParams.STATUS, provenance.status());
        addParamValue(params, metadata, "application_type");
        addParamValue(params, metadata, "subject_type");
        addParamValue(params, metadata, "contacts");
        addParamValues(params, "trust_chain", provenance.trustChain());
        addParamValue(params, FederationClientParams.EXPIRES_AT, Long.toString(provenance.expiresAt()));
        addParamValue(params, FederationClientParams.TRUST_ANCHOR, provenance.trustAnchor());
        addParamValue(params, FederationClientParams.ENTITY_TYPE, provenance.entityType());
        if (attestationMethod != null) {
            addParamValue(params, "token_endpoint_auth_method", attestationMethod);
            addParamValue(params, "attestation_required", "true");
        }
        return params;
    }

    /**
     * Whether to skip the approval page. Previously always true, which silently suppressed consent for
     * every federation-registered client - including one running authorization_code with a real user in
     * front of it.
     *
     * <p>The honest rule is whether there is anyone to ask. A client whose only grant is
     * {@code client_credentials} acts with no resource owner present, so an approval page has no one to
     * show and bypassing is correct. Any user-facing grant gets the page.
     *
     * <p>This is a behaviour change, in the safer direction: some clients that skipped consent will now
     * ask for it. A deployment that genuinely wants consent suppressed for a user-facing client should
     * configure that on the client in PF, where it is visible, rather than inherit it from a default
     * that applied to everything.
     */
    private static boolean bypassApprovalPage(List<String> grantTypes) {
        if (grantTypes.isEmpty()) {
            return false;
        }
        for (String g : grantTypes) {
            if (!"client_credentials".equals(g)) {
                return false;
            }
        }
        return true;
    }

    private static List<String> scopes(String scope) {
        return scope == null ? new ArrayList<>()
                : new ArrayList<>(Arrays.stream(scope.trim().split(" +")).filter(s -> !s.isBlank()).toList());
    }

    /** The strings of a metadata array, in order; anything else is none. A fresh list PingFederate may keep. */
    static List<String> strings(Object raw) {
        List<String> out = new ArrayList<>();
        if (raw instanceof List<?> list) {
            for (Object item : list) {
                if (item instanceof String s) {
                    out.add(s);
                }
            }
        }
        return out;
    }

    private static String metadataString(Map<String, Object> metadata, String key) {
        Object value = metadata.get(key);
        return value == null ? null : String.valueOf(value);
    }

    private static void addParamValue(Map<String, ParamValues> extendedParams, Map<String, Object> metadata, String paramName) {
        if (!metadata.containsKey(paramName)) {
            return;
        }
        Object value = metadata.get(paramName);
        if (value instanceof List<?>) {
            addParamValues(extendedParams, paramName, strings(value));
        } else {
            addParamValue(extendedParams, paramName, String.valueOf(value));
        }
    }

    static void addParamValue(Map<String, ParamValues> extendedParams, String paramName, String paramValue) {
        ParamValues existing = extendedParams.get(paramName);
        if (existing != null) {
            existing.getElements().add(paramValue);
            return;
        }
        ParamValues paramValues = new ParamValues();
        List<String> elements = new ArrayList<>();
        elements.add(paramValue);
        paramValues.setElements(elements);
        extendedParams.put(paramName, paramValues);
    }

    private static void addParamValues(Map<String, ParamValues> extendedParams, String paramName, List<String> values) {
        ParamValues existing = extendedParams.get(paramName);
        if (existing != null) {
            existing.getElements().addAll(values);
            return;
        }
        ParamValues paramValues = new ParamValues();
        paramValues.setElements(new ArrayList<>(values));
        extendedParams.put(paramName, paramValues);
    }

    /** First value of a client's extended param, or null when absent — the read twin of addParamValue. */
    static String extendedParamValue(Client client, String paramName) {
        Map<String, ParamValues> params = client.getExtendedParams();
        ParamValues values = params != null ? params.get(paramName) : null;
        List<String> elements = values != null ? values.getElements() : null;
        return elements != null && !elements.isEmpty() ? elements.get(0) : null;
    }
}
