/*
 * Whether a stored client was registered through the federation: what the automatic registration filters' gate asks.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.PfMgmtClientStore;
import com.pingidentity.ps.oidf.platform.pf.component.ComponentGate;
import java.util.Objects;
import org.sourceid.oauth20.domain.Client;

/**
 * The {@link ComponentGate.FederationClients} the two automatic registration filters hand their gate (S9b): a client
 * this repository registered carries the extended property {@code status} ({@link FederationClientParams#STATUS}) with
 * {@code registered} or {@code auto_registered}, the same mark {@link RegistrationService} decides by; a client made in
 * the console, by Terraform or by the admin API does not. Asked only for a client id that is an Entity Identifier, and
 * only while automatic registration is disabled or failed.
 */
final class FederationClientLookup implements ComponentGate.FederationClients {

    private static volatile ComponentGate.FederationClients shared = new FederationClientLookup(new PfMgmtClientStore());

    private final ClientStore store;

    FederationClientLookup(ClientStore store) {
        this.store = Objects.requireNonNull(store, "store");
    }

    /** PingFederate's client store, through its management API. */
    static ComponentGate.FederationClients pingFederate() {
        return shared;
    }

    /** Test seam: the lookup the filters' gates use; null puts PingFederate's back. */
    static void useForTests(ComponentGate.FederationClients clients) {
        shared = clients == null ? new FederationClientLookup(new PfMgmtClientStore()) : clients;
    }

    @Override
    public Boolean registeredByFederation(String clientId) {
        Client client = this.store.get(clientId);
        if (client == null) {
            return null;
        }
        String status = RegistrationService.extendedParamValue(client, FederationClientParams.STATUS);
        return RegistrationService.STATUS_AUTO.equals(status) || RegistrationService.STATUS_REGISTERED.equals(status);
    }
}
