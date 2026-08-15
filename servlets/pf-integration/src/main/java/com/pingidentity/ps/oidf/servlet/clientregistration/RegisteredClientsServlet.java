package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.PfMgmtClientStore;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ClientAuthenticationType;
import org.sourceid.oauth20.domain.ParamValues;

/**
 * Read-only listing of the OAuth clients this module registered into PingFederate through OpenID Federation —
 * both explicitly ({@code status=registered}) and automatically ({@code status=auto_registered}). It lets a
 * federation dashboard (e.g. the demo UI) show which clients exist in PingFederate without any PF admin API
 * access or credentials. Only clients carrying our {@code status} extended parameter are listed, so
 * PingFederate's own/system clients are never disclosed.
 *
 * <p>Security note: this reveals client identifiers and their granted scopes. It is intended for a trusted
 * demo/operator surface; in a hardened deployment it should be access-controlled (or disabled).
 */
@WebServlet(urlPatterns={"/federation/registered-clients"})
public final class RegisteredClientsServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Log LOGGER = LogFactory.getLog(RegisteredClientsServlet.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final transient ClientStore clientStore;

    public RegisteredClientsServlet() {
        this(new PfMgmtClientStore());
    }

    RegisteredClientsServlet(ClientStore clientStore) {
        this.clientStore = clientStore;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Collection<Client> all = this.clientStore.getAll();
        ArrayList<Map<String, Object>> clients = new ArrayList<Map<String, Object>>();
        for (Client client : all) {
            String status = RegisteredClientsServlet.firstExtendedParam(client, "status");
            String registration = RegisteredClientsServlet.registrationType(status);
            // Fallback: PingFederate may not persist our custom `status` extended param across reloads, so
            // also recognise a federation client by shape — a private_key_jwt client whose id is an entity
            // URL and which carries an inline jwks. (The demo's own client is a secret client, so excluded.)
            if (registration == null && RegisteredClientsServlet.isFederationShaped(client)) {
                registration = "federation";
            }
            if (registration == null) {
                continue;
            }
            LinkedHashMap<String, Object> entry = new LinkedHashMap<String, Object>();
            entry.put("client_id", client.getClientId());
            entry.put("name", client.getName());
            entry.put("registration", registration);
            entry.put("status", status);
            entry.put("scopes", client.getRestrictedScopes());
            entry.put("grant_types", client.getGrantTypes());
            entry.put("enabled", client.isEnabled());
            clients.add(entry);
        }
        response.setStatus(200);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        LinkedHashMap<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("total_clients", all.size());
        body.put("count", clients.size());
        body.put("clients", clients);
        MAPPER.writeValue(response.getWriter(), body);
    }

    /** A federation client by shape: private_key_jwt auth, an http(s) entity-id, and an inline jwks. */
    private static boolean isFederationShaped(Client client) {
        String id = client.getClientId();
        String jwks = client.getJwks();
        return client.getClientAuthnType() == ClientAuthenticationType.PRIVATE_KEY_JWT
                && id != null && id.startsWith("http")
                && jwks != null && !jwks.isBlank();
    }

    private static String registrationType(String status) {
        if ("auto_registered".equals(status)) {
            return "automatic";
        }
        if ("registered".equals(status)) {
            return "explicit";
        }
        return null;
    }

    private static String firstExtendedParam(Client client, String name) {
        Map<String, ParamValues> extended = client.getExtendedParams();
        if (extended == null) {
            return null;
        }
        ParamValues values = extended.get(name);
        if (values == null || values.getElements() == null || values.getElements().isEmpty()) {
            return null;
        }
        return values.getElements().get(0);
    }
}
