/*
 * The one place this repository calls PingFederate's internal services.
 */
package com.pingidentity.ps.oidf.platform.pf.internals;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Collection;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.issuer.OAuthIssuerUtils;
import org.sourceid.openid.connect.handlers.ProviderConfigurationInfoHandler;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;

/**
 * Every call this repository makes into PingFederate's internal services - classes in {@code pf-protocolengine.jar}
 * that are not part of the SDK and can change in a patch release (plan item F-1, decision 10). Nothing outside
 * platform-pf names {@code org.sourceid.oauth20.issuer}, {@code org.sourceid.saml20.domain.mgmt} or
 * {@code org.sourceid.openid.connect.handlers}; {@code InternalsBoundaryTest} holds that.
 *
 * <p>Each member is one call, made when the member is called and never before: nothing here runs at class load, so
 * loading this class touches no PingFederate class, and each internal is resolved, and fails, where its caller
 * reaches it, as it did when the caller named it. The internals need a booted PingFederate; outside one they
 * throw, a {@link LinkageError} included, and each caller handles that as it did before.
 *
 * <p>The data types stay what PingFederate hands back: {@link Client} is passed and returned as it is, because it
 * is what the client manager takes and returns, and a copy of it here would link the same members and add a
 * translation to keep in step. The members this repository links are listed, and classified, in platform-pf's
 * README.
 */
public final class PfInternals {
    private PfInternals() {
    }

    /**
     * What a discovery document's handler does with a request: writes the document to the response.
     */
    @FunctionalInterface
    public interface DiscoveryHandler {
        void process(HttpServletRequest request, HttpServletResponse response) throws Exception;
    }

    /**
     * The OAuth issuer PingFederate resolves for {@code request}: its base URL, or a virtual host name or issuer it
     * has configured when the request names one ({@code OAuthIssuerUtils.getIssuerValue}).
     */
    public static String issuer(HttpServletRequest request) {
        return OAuthIssuerUtils.getInstance().getIssuerValue(request);
    }

    /**
     * PingFederate's token endpoint base URL (Authorization Server Settings), as its authorization server manager
     * holds it: {@code null} or blank when it is not set.
     */
    public static String tokenEndpointBaseUrl() {
        return MgmtFactory.getAuthzServerManager().getTokenEndpointBaseUrl();
    }

    /** Adds {@code client} to PingFederate's client manager. */
    public static void addClient(Client client) {
        MgmtFactory.getClientManager().addClient(client);
    }

    /** Replaces the client with {@code client}'s id in PingFederate's client manager; answers what it answers. */
    public static Client updateClient(Client client) {
        return MgmtFactory.getClientManager().updateClient(client);
    }

    /** The client with {@code clientId} in PingFederate's client manager, or what it answers for none. */
    public static Client getClient(String clientId) {
        return MgmtFactory.getClientManager().getClient(clientId);
    }

    /** Every client in PingFederate's client manager. */
    public static Collection<Client> getClients() {
        return MgmtFactory.getClientManager().getClients();
    }

    /**
     * Whether PingFederate's client manager keeps its clients in a database rather than in its own configuration
     * files ({@code ClientManager.isBackendDatabase()}, read with javap on 13.1.3's {@code pf-protocolengine.jar} on
     * 2026-09-28). Nothing calls it yet: C-1 (Phase 4) decides from it whether a registration made on one node is
     * seen by the others.
     */
    public static boolean isBackendDatabase() {
        return MgmtFactory.getClientManager().isBackendDatabase();
    }

    /**
     * PingFederate's own handler for its discovery document: {@code /.well-known/openid-configuration} when
     * {@code openIdConnect}, {@code /.well-known/oauth-authorization-server} otherwise. The handler is created now;
     * the returned one runs it.
     */
    public static DiscoveryHandler discoveryHandler(boolean openIdConnect) {
        ProviderConfigurationInfoHandler handler = openIdConnect
                ? ProviderConfigurationInfoHandler.createOpenIDConnectProviderConfigurationInfoHandler()
                : ProviderConfigurationInfoHandler.createOAuthProviderConfigurationInfoHandler();
        return (request, response) -> handler.process(request, response);
    }
}
