package com.pingidentity.ps.oidf.pf;

import com.pingidentity.ps.oidf.platform.pf.internals.PfInternals;
import org.sourceid.oauth20.domain.Client;

/**
 * {@link ClientStore} backed by the PingFederate management API. Delegates add,
 * lookup and disable operations to the runtime {@code ClientManager}, through
 * {@link PfInternals}.
 */
public final class PfMgmtClientStore
implements ClientStore {
    @Override
    public void add(Client client) {
        PfInternals.addClient(client);
    }

    @Override
    public void update(Client client) {
        PfInternals.updateClient(client);
    }

    @Override
    public Client get(String clientId) {
        return PfInternals.getClient(clientId);
    }

    @Override
    public java.util.Collection<Client> getAll() {
        return PfInternals.getClients();
    }

    @Override
    public void disable(Client client) {
        client.setEnabled(false);
        PfInternals.updateClient(client);
    }
}
