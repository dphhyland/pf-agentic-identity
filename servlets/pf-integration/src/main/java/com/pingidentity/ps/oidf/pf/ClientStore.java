package com.pingidentity.ps.oidf.pf;

import org.sourceid.oauth20.domain.Client;

/**
 * Abstraction over the PingFederate client registry used by the registration
 * flow: add a newly registered client, disable an existing one, or look one up
 * by client id.
 */
public interface ClientStore {
    public void add(Client client);

    /** Replace an existing client record (same client id) with a freshly derived one. */
    public void update(Client client);

    public void disable(Client client);

    public Client get(String clientId);

    /** All clients in the registry. Used to reverse-map an attested identity onto its client. */
    public java.util.Collection<Client> getAll();
}
