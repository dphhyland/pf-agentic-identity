package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.pf.OperatorApi;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorAuthenticator;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.PfMgmtClientStore;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
 * it on ({@code OIDF_REGISTERED_CLIENTS_ENABLED}) and is an operator route
 * ({@link OperatorApi#REGISTERED_CLIENTS}): a PingFederate-issued access token with
 * {@code oidf.admin.clients.read}, DPoP-bound in production, through platform-pf's operator authenticator
 * (plan item S8b) - no operator authentication configured means no access, which is the safe direction to
 * fail. It used to be neither: unauthenticated, always on, and it also returned a count of EVERY client in
 * the instance, disclosing more than the list itself.
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
    private transient OperatorAuthenticator authenticator;
    private boolean enabled;

    public RegisteredClientsServlet() {
        this(new PfMgmtClientStore());
    }

    RegisteredClientsServlet(ClientStore clientStore) {
        this.clientStore = clientStore;
    }

    /** Test seam: the servlet with an explicit authenticator and enabled state, no container required. */
    RegisteredClientsServlet(ClientStore clientStore, OperatorAuthenticator authenticator, boolean enabled) {
        this.clientStore = clientStore;
        this.authenticator = authenticator;
        this.enabled = enabled;
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        String enabledSetting = OperatorApi.setting(config, "registeredClientsEnabled",
                "oidf.registered.clients.enabled", "OIDF_REGISTERED_CLIENTS_ENABLED");
        this.configure(OperatorApi.authenticator(config), Boolean.parseBoolean(enabledSetting));
    }

    /**
     * Takes {@code authenticator} - null when it could not be built, on which every request answers 503 - and whether
     * the surface is enabled, warning when it is enabled and nobody can be authenticated.
     */
    void configure(OperatorAuthenticator authenticator, boolean enabled) {
        this.authenticator = authenticator;
        this.enabled = enabled;
        if (this.enabled && (this.authenticator == null || !this.authenticator.usable())) {
            LOGGER.warn((Object) ("/federation/registered-clients is enabled but no operator can be authenticated, so"
                    + " every request will be refused: " + (this.authenticator == null
                            ? "the operator authenticator could not be built (server.log says why)"
                            : this.authenticator.problem())));
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!this.enabled) {
            // Not "forbidden": a disabled operator surface should not confirm it exists.
            response.sendError(404);
            return;
        }
        if (OperatorApi.authorise(this.authenticator, OperatorApi.REGISTERED_CLIENTS, request.getServletPath(), request,
                response, r -> r.sendError(404)).isEmpty()) {
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
