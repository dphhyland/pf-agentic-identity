/*
 * Runtime IssuanceClientResolver: reads a PingFederate client + its attestation_* extended properties.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import com.pingidentity.ps.oidf.issuer.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.issuer.AttesterClient;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.issuer.IssuanceClientResolver;
import com.pingidentity.ps.oidf.issuer.IssuanceException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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

    private static final Log LOGGER = LogFactory.getLog(PfIssuanceClientResolver.class);

    private static final String[] PROPERTY_KEYS = {
            AttestationIssuanceConfig.P_ISSUER,
            AttestationIssuanceConfig.P_TTL,
            AttestationIssuanceConfig.P_BUNDLE,
            AttestationIssuanceConfig.P_ENTITLEMENT,
            AttestationIssuanceConfig.P_SIGNING_KEY_REF,
            AttestationIssuanceConfig.P_SIGNING_JWK,
            AttestationIssuanceConfig.P_INSTANCES,
            AttestationIssuanceConfig.P_TRUST_DOMAIN,
            AttestationIssuanceConfig.P_EVIDENCE,
            AttestationIssuanceConfig.P_BUNDLE_URL,
            AttestationIssuanceConfig.P_EVIDENCE_ISSUER,
    };

    private final ClientStore clientStore;

    public PfIssuanceClientResolver(ClientStore clientStore) {
        this.clientStore = clientStore;
    }

    @Override
    public String pluginId() {
        return com.pingidentity.ps.oidf.issuer.ClientResolverPlugins.PF_CLIENT_METADATA;
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
        return AttestationIssuanceConfig.fromProperties(props(client));
    }

    @Override
    public List<AttesterClient> attestationClients() throws IssuanceException {
        Collection<Client> all = this.clientStore.getAll();
        List<AttesterClient> out = new ArrayList<>();
        if (all == null) {
            return out;
        }
        for (Client client : all) {
            if (client == null || !client.isEnabled()) {
                continue;
            }
            Map<String, String> props = props(client);
            // Only clients actually configured for attestation issuance (they carry an attester issuer).
            if (!props.containsKey(AttestationIssuanceConfig.P_ISSUER)) {
                continue;
            }
            try {
                out.add(new AttesterClient(client.getClientId(),
                        AttestationIssuanceConfig.fromProperties(props)));
            } catch (IssuanceException e) {
                // A single misconfigured client must not sink the whole attester — skip it, keep the rest.
                LOGGER.warn((Object) ("Skipping attestation client with invalid config: "
                        + client.getClientId() + " (" + e.error() + ": " + e.getMessage() + ")"));
            }
        }
        return out;
    }

    private static Map<String, String> props(Client client) {
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
        return props;
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
