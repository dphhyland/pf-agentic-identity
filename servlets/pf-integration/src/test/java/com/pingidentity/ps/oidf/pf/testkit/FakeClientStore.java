package com.pingidentity.ps.oidf.pf.testkit;

import com.pingidentity.ps.oidf.pf.ClientStore;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.sourceid.oauth20.domain.Client;

/**
 * An in-memory {@link ClientStore} that behaves like PingFederate's for the calls this module makes: what is
 * added or updated is what a later {@code get} returns, and {@code disable} writes the client back disabled.
 * It records every write so a test can say what happened, not just what is left.
 */
public final class FakeClientStore implements ClientStore {
    private final Map<String, Client> clients = new LinkedHashMap<>();
    private final List<String> writes = new ArrayList<>();
    private boolean dropsExtendedParams;

    /**
     * A store that keeps no extended parameters - what PingFederate does with a property it has not been told about
     * (docs/extended-properties.json), silently.
     */
    public FakeClientStore droppingExtendedParams() {
        this.dropsExtendedParams = true;
        return this;
    }

    private Client kept(Client client) {
        if (this.dropsExtendedParams) {
            client.setExtendedParams(new java.util.HashMap<>());
        }
        return client;
    }

    public FakeClientStore with(Client client) {
        this.clients.put(client.getClientId(), client);
        return this;
    }

    @Override
    public synchronized void add(Client client) {
        if (this.clients.containsKey(client.getClientId())) {
            throw new IllegalStateException("client " + client.getClientId() + " already exists");
        }
        this.clients.put(client.getClientId(), this.kept(client));
        this.writes.add("add " + client.getClientId());
    }

    @Override
    public synchronized void update(Client client) {
        if (!this.clients.containsKey(client.getClientId())) {
            throw new IllegalStateException("client " + client.getClientId() + " does not exist");
        }
        this.clients.put(client.getClientId(), this.kept(client));
        this.writes.add("update " + client.getClientId());
    }

    @Override
    public synchronized void disable(Client client) {
        client.setEnabled(false);
        this.clients.put(client.getClientId(), client);
        this.writes.add("disable " + client.getClientId());
    }

    @Override
    public synchronized Client get(String clientId) {
        return this.clients.get(clientId);
    }

    @Override
    public synchronized Collection<Client> getAll() {
        return List.copyOf(this.clients.values());
    }

    /** Every write, in order: {@code add <id>}, {@code update <id>}, {@code disable <id>}. */
    public synchronized List<String> writes() {
        return List.copyOf(this.writes);
    }
}
