/*
 * The catalogue of resolver plugins the attester supports for the SPIFFE-ID → OAuth-client mapping.
 */
package com.pingidentity.ps.oidf.common;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The attester resolves a workload's evidence identity onto an OAuth client (and its entitlement ceiling,
 * i.e. downscoping) through a <em>resolver plugin</em>. Three plugins are supported; one or more can be
 * active at once (chained). This registry names them so the discovery document can advertise the full
 * supported set and which are active — the mapping source is an operational fact worth surfacing.
 */
public final class ClientResolverPlugins {

    public static final String PF_CLIENT_METADATA = "pf-client-metadata";
    public static final String CIMD = "cimd";
    public static final String OPENID_FEDERATION = "openid-federation";

    private ClientResolverPlugins() {
    }

    /** All supported plugins, as {id, title, description} maps for the discovery document. */
    public static List<Map<String, Object>> supported() {
        return List.of(
                plugin(PF_CLIENT_METADATA, "PingFederate registered client metadata",
                        "Reverse-maps via each client's attestation_* extended properties in the PF client store."),
                plugin(CIMD, "Client ID Metadata Document",
                        "Fetches a hosted JSON document mapping SPIFFE IDs to OAuth clients, bundles and ceilings."),
                plugin(OPENID_FEDERATION, "OpenID Federation entity metadata",
                        "Resolves the client through an OpenID Federation trust chain / entity statement."));
    }

    private static Map<String, Object> plugin(String id, String title, String description) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("title", title);
        m.put("description", description);
        return m;
    }
}
