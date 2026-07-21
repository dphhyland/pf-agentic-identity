/*
 * Runtime IssuanceClientResolver: reads a PingFederate client + its attestation_* extended properties.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import com.pingidentity.ps.oidf.common.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.common.ClientStore;
import com.pingidentity.ps.oidf.common.IssuanceClientResolver;
import com.pingidentity.ps.oidf.common.IssuanceException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ParamValues;

/**
 * The runtime {@link IssuanceClientResolver}: looks a client up in PingFederate's client store, applies
 * the status gate ({@link Client#isEnabled()} — the seam a trust-controller check replaces later), and
 * projects its {@code attestation_*} extended properties into an {@link AttestationIssuanceConfig}. Reads
 * only; the client is provisioned (with its attester key reference, SPIFFE bundle and instance bindings)
 * out of band via registration / admin / Terraform.
 */
public final class PfIssuanceClientResolver implements IssuanceClientResolver {

    private static final String[] PROPERTY_KEYS = {
            AttestationIssuanceConfig.P_ISSUER,
            AttestationIssuanceConfig.P_TTL,
            AttestationIssuanceConfig.P_BUNDLE,
            AttestationIssuanceConfig.P_ENTITLEMENT,
            AttestationIssuanceConfig.P_SIGNING_KEY_REF,
            AttestationIssuanceConfig.P_SIGNING_JWK,
            AttestationIssuanceConfig.P_INSTANCES,
            AttestationIssuanceConfig.P_TRUST_DOMAIN,
    };

    private final ClientStore clientStore;

    public PfIssuanceClientResolver(ClientStore clientStore) {
        this.clientStore = clientStore;
    }

    @Override
    public AttestationIssuanceConfig resolve(String clientId) throws IssuanceException {
        Client client = this.clientStore.get(clientId);
        if (client == null) {
            throw IssuanceException.invalidClient("unknown client: " + clientId);
        }
        if (!client.isEnabled()) {
            throw IssuanceException.invalidClient("client is disabled: " + clientId);
        }
        Map<String, ParamValues> extended = client.getExtendedParams();
        Map<String, String> props = new HashMap<>();
        if (extended != null) {
            for (String key : PROPERTY_KEYS) {
                String value = firstElement(extended.get(key));
                if (value != null) {
                    props.put(key, value);
                }
            }
        }
        return AttestationIssuanceConfig.fromProperties(props);
    }

    private static String firstElement(ParamValues values) {
        if (values == null) {
            return null;
        }
        List<String> elements = values.getElements();
        if (elements == null || elements.isEmpty()) {
            return null;
        }
        return elements.get(0);
    }
}
