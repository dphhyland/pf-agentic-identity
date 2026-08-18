package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.pf.AdminBearer;
import javax.servlet.ServletException;
import javax.servlet.ServletConfig;
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
import org.sourceid.oauth20.domain.ParamValues;

/**
 * Read-only listing of the OAuth clients this module registered into PingFederate through OpenID Federation —
 * both explicitly ({@code status=registered}) and automatically ({@code status=auto_registered}). It lets a
 * federation dashboard (e.g. the demo UI) show which clients exist in PingFederate without any PF admin API
 * access or credentials. Only clients carrying our {@code status} extended parameter are listed, so
 * PingFederate's own/system clients are never disclosed.
 *
 * <p>This reveals client identifiers and their granted scopes, so it is off unless a deployment turns
 * it on ({@code OIDF_REGISTERED_CLIENTS_ENABLED}) and is gated by the same operator bearer token as
 * the hosted-entity admin surface ({@code OIDF_AUTHORITY_ADMIN_TOKEN}) - no token configured means no
 * access, which is the safe direction to fail. It used to be neither: unauthenticated, always on, and
 * it also returned a count of EVERY client in the instance, disclosing more than the list itself.
 *
 * <p>The {@code status}-shaped fallback is gone too. It listed any PRIVATE_KEY_JWT client with a URL
 * id and an inline JWKS as "federation", which swept in clients Terraform or the console had created -
 * the opposite of the "only clients carrying our marker are disclosed" intent. With `status` now
 * declared in extended-properties.tf the marker is reliable, so the guess is unnecessary.
 */
@WebServlet(urlPatterns={"/federation/registered-clients"})
public final class RegisteredClientsServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Log LOGGER = LogFactory.getLog(RegisteredClientsServlet.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final transient ClientStore clientStore;
    private transient String adminToken;
    private boolean enabled;

    public RegisteredClientsServlet() {
        this(new PfMgmtClientStore());
    }

    RegisteredClientsServlet(ClientStore clientStore) {
        this.clientStore = clientStore;
    }

    /** Test seam: the servlet with an explicit token and enabled state, no container required. */
    RegisteredClientsServlet(ClientStore clientStore, String adminToken, boolean enabled) {
        this.clientStore = clientStore;
        this.adminToken = adminToken;
        this.enabled = enabled;
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        this.adminToken = AdminBearer.resolveToken(config, "adminToken",
                "oidf.authority.admin_token", "OIDF_AUTHORITY_ADMIN_TOKEN");
        String enabledSetting = AdminBearer.resolveToken(config, "registeredClientsEnabled",
                "oidf.registered.clients.enabled", "OIDF_REGISTERED_CLIENTS_ENABLED");
        this.enabled = Boolean.parseBoolean(enabledSetting);
        if (this.enabled && this.adminToken == null) {
            LOGGER.warn((Object) "/federation/registered-clients is enabled but no admin token is configured; "
                    + "every request will be refused (OIDF_AUTHORITY_ADMIN_TOKEN)");
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!this.enabled) {
            // Not "forbidden": a disabled operator surface should not confirm it exists.
            response.sendError(404);
            return;
        }
        if (!AdminBearer.isAuthorized(this.adminToken, request.getHeader("Authorization"))) {
            response.setHeader("WWW-Authenticate", "Bearer");
            response.sendError(401);
            return;
        }
        Collection<Client> all = this.clientStore.getAll();
        ArrayList<Map<String, Object>> clients = new ArrayList<Map<String, Object>>();
        for (Client client : all) {
            String status = RegisteredClientsServlet.firstExtendedParam(client, "status");
            String registration = RegisteredClientsServlet.registrationType(status);
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
        body.put("count", clients.size());
        body.put("clients", clients);
        MAPPER.writeValue(response.getWriter(), body);
    }

    /** A federation client by shape: private_key_jwt auth, an http(s) entity-id, and an inline jwks. */

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
