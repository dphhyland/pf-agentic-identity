/*
 * Runtime IssuanceClientResolver: reads a PingFederate client + its attestation_* extended properties.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import com.pingidentity.ps.oidf.issuer.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.issuer.AttesterClient;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.PfMgmtClientStore;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutors;
import com.pingidentity.ps.oidf.issuer.IssuanceClientResolver;
import com.pingidentity.ps.oidf.issuer.IssuanceException;
import java.time.Clock;
import java.time.Duration;
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
 *
 * <p>{@link #attestationClients()} reads a {@link ClientBindingIndex}, not the store (plan item H-ATT-2, F-0060): over
 * PingFederate's own store one index per webapp, which every resolver made for that store shares - the issuance
 * servlet's and the configuration servlet's - rebuilt every {@code OIDF_ATTESTER_CLIENT_INDEX_REFRESH_SECONDS} on the
 * managed executor {@value #EXECUTOR}, and after a miss at most once every five seconds. {@link #resolve(String)}, one
 * client by id, still asks the store.
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

    /** The managed executor that rebuilds the shared index. */
    static final String EXECUTOR = "attester-client-index";
    /** The rebuild interval for a store other than PingFederate's, which reads no setting: the setting's default. */
    static final Duration DEFAULT_INTERVAL = Duration.ofSeconds(30);

    private final ClientStore clientStore;
    /** This resolver's own index, for a store other than PingFederate's; null for PingFederate's, whose index is shared. */
    private final ClientBindingIndex ownIndex;

    public PfIssuanceClientResolver(ClientStore clientStore) {
        this.clientStore = clientStore;
        this.ownIndex = clientStore instanceof PfMgmtClientStore ? null
                : new ClientBindingIndex(() -> load(clientStore), Clock.systemUTC(), DEFAULT_INTERVAL);
    }

    /** A resolver over {@code clientStore} with an index of its own, on {@code clock}: a test's. */
    PfIssuanceClientResolver(ClientStore clientStore, Clock clock, Duration interval) {
        this.clientStore = clientStore;
        this.ownIndex = new ClientBindingIndex(() -> load(clientStore), clock, interval);
    }

    /** The index this resolver reads: its own, or the webapp's over PingFederate's store, made on first use. */
    ClientBindingIndex index() {
        return this.ownIndex != null ? this.ownIndex : Shared.index();
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

    /** The indexed attestation clients (see the class comment); the index is built on the first call. */
    @Override
    public List<AttesterClient> attestationClients() throws IssuanceException {
        return this.index().clients();
    }

    /** Rebuilds the index after a miss, at most once per {@link ClientBindingIndex#MISS_REFRESH_INTERVAL}. */
    @Override
    public boolean refreshAfterMiss() {
        return this.index().refreshAfterMiss();
    }

    /**
     * Every enabled client of {@code clientStore} that carries an attester issuer, with its configuration: what a
     * rebuild of the index reads. A client whose configuration is refused is skipped with a WARN, and the rest kept.
     */
    static List<AttesterClient> load(ClientStore clientStore) {
        Collection<Client> all = clientStore.getAll();
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

    /** The webapp's index over PingFederate's own store, and its schedule, made once, on first use. */
    static final class Shared {
        private static volatile ClientBindingIndex index;

        private Shared() {
        }

        /** The index, without a lock once it is made. */
        static ClientBindingIndex index() {
            ClientBindingIndex local = index;
            return local != null ? local : create();
        }

        /** Makes the index and starts its schedule, unless a caller that held the lock first already did. */
        static synchronized ClientBindingIndex create() {
            ClientBindingIndex local = index;
            if (local == null) {
                Duration interval = AttestationIssuanceServlet.processSettings()
                        .duration(AttestationIssuanceServlet.CLIENT_INDEX_REFRESH_SETTING);
                PfMgmtClientStore store = new PfMgmtClientStore();
                local = new ClientBindingIndex(() -> load(store), Clock.systemUTC(), interval);
                // Refused (and logged) in a copy that may not start threads; the index then rebuilds on a read that
                // finds it older than twice the interval.
                ManagedExecutors.every(EXECUTOR, interval, local::refresh);
                index = local;
            }
            return local;
        }
    }
}
