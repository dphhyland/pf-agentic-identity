package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.pingidentity.ps.oidf.pf.ClientStore;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ParamValues;

/**
 * The "existing client registered by federation" signal the automatic registration filters' gate asks while the
 * component is disabled or failed (S9b): only this repository's own {@code status} mark counts, so a client made in the
 * console, by Terraform or by the admin API is never treated as a federation client.
 */
class FederationClientLookupTest {

    private static Client client(String id, String status) {
        Client client = new Client();
        client.setClientId(id);
        Map<String, ParamValues> params = new HashMap<>();
        if (status != null) {
            ParamValues values = new ParamValues();
            values.setElements(List.of(status));
            params.put(FederationClientParams.STATUS, values);
        }
        client.setExtendedParams(params);
        return client;
    }

    private static ClientStore store(Client... clients) {
        return new ClientStore() {
            @Override
            public void add(Client client) {
            }

            @Override
            public void update(Client client) {
            }

            @Override
            public Client get(String clientId) {
                for (Client c : clients) {
                    if (c.getClientId().equals(clientId)) {
                        return c;
                    }
                }
                return null;
            }

            @Override
            public Collection<Client> getAll() {
                return List.of(clients);
            }

            @Override
            public void disable(Client client) {
            }
        };
    }

    @Test
    void onlyAClientThisRepositoryRegisteredIsAFederationClient() {
        FederationClientLookup lookup = new FederationClientLookup(store(
                client("https://auto.example", RegistrationService.STATUS_AUTO),
                client("https://explicit.example", RegistrationService.STATUS_REGISTERED),
                client("https://console.example", null),
                client("https://other.example", "something-else")));

        assertNull(lookup.registeredByFederation("https://absent.example"), "no such client: the gate decides by the name");
        assertEquals(Boolean.TRUE, lookup.registeredByFederation("https://auto.example"));
        assertEquals(Boolean.TRUE, lookup.registeredByFederation("https://explicit.example"));
        assertEquals(Boolean.FALSE, lookup.registeredByFederation("https://console.example"));
        assertEquals(Boolean.FALSE, lookup.registeredByFederation("https://other.example"));
    }
}
