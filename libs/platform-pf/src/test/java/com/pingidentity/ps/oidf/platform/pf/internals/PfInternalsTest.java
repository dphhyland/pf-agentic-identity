package com.pingidentity.ps.oidf.platform.pf.internals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.sourceid.oauth20.domain.AuthzServerManager;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ClientManager;
import org.sourceid.openid.connect.handlers.ProviderConfigurationInfoHandler;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;

/**
 * Each member of the facade makes the one PingFederate call it names, with its caller's arguments, and answers
 * what PingFederate answers. PingFederate's statics are replaced, because they need a booted server.
 */
class PfInternalsTest {

    /**
     * {@code OAuthIssuerUtils} is final and cannot be redefined here (Mockito: "class redefinition failed: invalid
     * class", 13.1.3's jar, 2026-09-28), so {@link PfInternals#issuer} is not in the coverage gate. What this shows
     * is the reason every caller has an issuer seam: outside a booted PingFederate the lookup throws a linkage error,
     * PingFederate's registry being absent, and the facade passes it on unchanged.
     */
    @Test
    void theIssuerLookupNeedsABootedPingFederate() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        Throwable thrown = assertThrows(Throwable.class, () -> PfInternals.issuer(request));
        assertTrue(thrown instanceof LinkageError, String.valueOf(thrown));
    }

    @Test
    void theTokenEndpointBaseUrlIsTheAuthorizationServerManagers() {
        AuthzServerManager manager = mock(AuthzServerManager.class);
        when(manager.getTokenEndpointBaseUrl()).thenReturn("https://token.example.com");
        try (MockedStatic<MgmtFactory> statics = mockStatic(MgmtFactory.class)) {
            statics.when(MgmtFactory::getAuthzServerManager).thenReturn(manager);
            assertEquals("https://token.example.com", PfInternals.tokenEndpointBaseUrl());
        }
    }

    @Test
    void eachClientCallGoesToTheClientManagerMethodOfTheSameName() {
        ClientManager manager = mock(ClientManager.class);
        Client client = new Client();
        Client updated = new Client();
        Collection<Client> all = List.of(client);
        when(manager.updateClient(client)).thenReturn(updated);
        when(manager.getClient("rp-1")).thenReturn(client);
        when(manager.getClients()).thenReturn(all);
        when(manager.isBackendDatabase()).thenReturn(true);
        try (MockedStatic<MgmtFactory> statics = mockStatic(MgmtFactory.class)) {
            statics.when(MgmtFactory::getClientManager).thenReturn(manager);

            PfInternals.addClient(client);
            verify(manager).addClient(client);
            verify(manager, never()).updateClient(client);

            assertSame(updated, PfInternals.updateClient(client));
            verify(manager).updateClient(client);

            assertSame(client, PfInternals.getClient("rp-1"));
            assertSame(all, PfInternals.getClients());
            assertTrue(PfInternals.isBackendDatabase());
            when(manager.isBackendDatabase()).thenReturn(false);
            assertFalse(PfInternals.isBackendDatabase());
        }
    }

    @Test
    void theDiscoveryHandlerIsTheOneForTheDocumentAskedFor() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        ProviderConfigurationInfoHandler openId = mock(ProviderConfigurationInfoHandler.class);
        ProviderConfigurationInfoHandler oauth = mock(ProviderConfigurationInfoHandler.class);
        try (MockedStatic<ProviderConfigurationInfoHandler> statics = mockStatic(ProviderConfigurationInfoHandler.class)) {
            statics.when(ProviderConfigurationInfoHandler::createOpenIDConnectProviderConfigurationInfoHandler).thenReturn(openId);
            statics.when(ProviderConfigurationInfoHandler::createOAuthProviderConfigurationInfoHandler).thenReturn(oauth);

            PfInternals.DiscoveryHandler openIdHandler = PfInternals.discoveryHandler(true);
            PfInternals.DiscoveryHandler oauthHandler = PfInternals.discoveryHandler(false);
            // Created when asked for, run only when the returned handler runs.
            statics.verify(ProviderConfigurationInfoHandler::createOpenIDConnectProviderConfigurationInfoHandler);
            statics.verify(ProviderConfigurationInfoHandler::createOAuthProviderConfigurationInfoHandler);
            verify(openId, never()).process(request, response);

            openIdHandler.process(request, response);
            verify(openId).process(request, response);
            verify(oauth, never()).process(request, response);
            oauthHandler.process(request, response);
            verify(oauth).process(request, response);
        }
    }

    @Test
    void whatTheHandlerThrowsReachesTheCaller() throws Exception {
        ProviderConfigurationInfoHandler failing = mock(ProviderConfigurationInfoHandler.class);
        IOException broken = new IOException("broken pipe");
        org.mockito.Mockito.doThrow(broken).when(failing).process(null, null);
        try (MockedStatic<ProviderConfigurationInfoHandler> statics = mockStatic(ProviderConfigurationInfoHandler.class)) {
            statics.when(ProviderConfigurationInfoHandler::createOAuthProviderConfigurationInfoHandler).thenReturn(failing);
            PfInternals.DiscoveryHandler handler = PfInternals.discoveryHandler(false);
            assertSame(broken, assertThrows(IOException.class, () -> handler.process(null, null)));
        }
    }

    @Test
    void loadingTheFacadeTouchesNoPingFederateClass() throws Exception {
        // A fresh loader over the same class path: initialising PfInternals must not initialise what it calls, or
        // a caller that only builds a resolver would reach PingFederate's registry at construction.
        java.net.URL here = PfInternals.class.getProtectionDomain().getCodeSource().getLocation();
        try (java.net.URLClassLoader loader = new java.net.URLClassLoader(new java.net.URL[] {here},
                PfInternalsTest.class.getClassLoader().getParent())) {
            Class<?> facade = Class.forName(PfInternals.class.getName(), true, loader);
            assertEquals(loader, facade.getClassLoader());
        }
    }
}
