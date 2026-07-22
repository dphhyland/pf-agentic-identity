package com.pingidentity.ps.oidf.common;

import org.sourceid.oauth20.domain.Client;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;

/**
 * {@link ClientStore} backed by the PingFederate management API. Delegates add,
 * lookup and disable operations to the runtime {@code ClientManager} obtained
 * from {@link MgmtFactory}.
 */
public final class PfMgmtClientStore
implements ClientStore {
    @Override
    public void add(Client client) {
        MgmtFactory.getClientManager().addClient(client);
    }

    @Override
    public Client get(String clientId) {
        return MgmtFactory.getClientManager().getClient(clientId);
    }

    @Override
    public void disable(Client client) {
        client.setEnabled(false);
        MgmtFactory.getClientManager().updateClient(client);
    }
}

