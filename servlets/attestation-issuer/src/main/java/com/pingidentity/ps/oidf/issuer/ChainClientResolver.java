/*
 * Combines several resolver plugins: the attester consults each and aggregates their clients.
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.ArrayList;
import java.util.List;

/**
 * A resolver made of several plugins (PF client metadata + CIMD + OpenID Federation, in any combination).
 * {@link #attestationClients()} returns the union across plugins, so evidence-first reverse resolution at
 * mint time considers clients from every configured source; {@link #resolve(String)} returns the first
 * plugin that knows the client. A plugin that fails to produce clients (e.g. a document temporarily
 * unreachable) is skipped rather than sinking the others.
 */
public final class ChainClientResolver implements IssuanceClientResolver {

    private final List<IssuanceClientResolver> plugins;

    public ChainClientResolver(List<IssuanceClientResolver> plugins) {
        this.plugins = List.copyOf(plugins);
    }

    public List<IssuanceClientResolver> plugins() {
        return this.plugins;
    }

    @Override
    public AttestationIssuanceConfig resolve(String clientId) throws IssuanceException {
        IssuanceException last = null;
        for (IssuanceClientResolver plugin : this.plugins) {
            try {
                return plugin.resolve(clientId);
            } catch (IssuanceException e) {
                last = e;
            }
        }
        throw last != null ? last : IssuanceException.invalidClient("unknown client: " + clientId);
    }

    /**
     * The union of every plugin's clients, in plugin order and <strong>de-duplicated by client id</strong>:
     * the first plugin to declare a client wins. Order is precedence — an external mapping source (CIMD,
     * federation) listed before the PF store overrides the same client's locally-configured bindings,
     * rather than colliding with them during evidence-first resolution.
     */
    @Override
    public List<AttesterClient> attestationClients() throws IssuanceException {
        List<AttesterClient> out = new ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        IssuanceException deferred = null;
        for (IssuanceClientResolver plugin : this.plugins) {
            try {
                for (AttesterClient client : plugin.attestationClients()) {
                    if (seen.add(client.clientId())) {
                        out.add(client);
                    }
                }
            } catch (IssuanceException e) {
                deferred = e; // remember, but let the other plugins contribute
            }
        }
        if (out.isEmpty() && deferred != null) {
            throw deferred;
        }
        return out;
    }

    @Override
    public String pluginId() {
        StringBuilder sb = new StringBuilder("chain[");
        for (int i = 0; i < this.plugins.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(this.plugins.get(i).pluginId());
        }
        return sb.append(']').toString();
    }

    /** The distinct plugin ids active in this chain (for the discovery document). */
    public List<String> activePluginIds() {
        List<String> ids = new ArrayList<>();
        for (IssuanceClientResolver plugin : this.plugins) {
            if (!ids.contains(plugin.pluginId())) {
                ids.add(plugin.pluginId());
            }
        }
        return ids;
    }
}
