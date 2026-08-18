/*
 * WorkloadIntrospector that reads SPIRE registration selectors for a SPIFFE ID.
 */
package com.pingidentity.ps.oidf.issuer;

import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.jose4j.json.JsonUtil;
import com.pingidentity.ps.oidf.jose.HttpGetClient;
import com.pingidentity.ps.oidf.jose.JdkHttpGetClient;

/**
 * Looks up a workload's <strong>SPIRE registration selectors</strong> and returns them as attributes.
 * The attester queries a SPIRE Server Entry endpoint (the Server API {@code Entry.ListEntries}, or a thin
 * JSON proxy in front of the admin socket) for the entry whose SPIFFE ID matches the presented SVID, and
 * projects its selectors — {@code k8s:ns:demo}, {@code k8s:sa:payment-agent}, {@code unix:uid:0},
 * {@code docker:image:…} — into a {@code selectors} attribute plus a flattened {@code spire.<type>} map.
 *
 * <p>Those attributes ride into the attestation's {@code workload.attributes} and are available to the
 * issuance policy for downscoping — e.g. only grant EMEA when {@code k8s:ns:demo} is among the selectors.
 * Selectors are how SPIRE proves <em>how</em> a workload was attested, so they are a stronger basis for
 * policy than anything the workload asserts about itself.
 *
 * <p>Expected proxy response for {@code GET <base>/entries?spiffe_id=<id>} (a minimal projection of the
 * SPIRE Server API): <pre>{ "selectors": [ {"type":"k8s","value":"ns:demo"}, … ] }</pre>
 */
public final class SpireSelectorIntrospector implements WorkloadIntrospector {

    private final String entriesBaseUrl;
    private final HttpGetClient http;

    public SpireSelectorIntrospector(String entriesBaseUrl) {
        // SPIRE's registration API is a loopback/agent endpoint by nature - operator-configured, exempt.
        this(entriesBaseUrl, new JdkHttpGetClient(false, OutboundUrlPolicy.fromEnvironment().trusting(entriesBaseUrl)));
    }

    public SpireSelectorIntrospector(String entriesBaseUrl, HttpGetClient http) {
        this.entriesBaseUrl = entriesBaseUrl.endsWith("/")
                ? entriesBaseUrl.substring(0, entriesBaseUrl.length() - 1) : entriesBaseUrl;
        this.http = http;
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> introspect(InstanceIdentity svid) {
        if (svid == null || svid.subject() == null) {
            return Map.of();
        }
        String url = this.entriesBaseUrl + "/entries?spiffe_id="
                + java.net.URLEncoder.encode(svid.subject(), java.nio.charset.StandardCharsets.UTF_8);
        String body;
        try {
            body = this.http.get(url, "application/json");
        } catch (Exception e) {
            // Introspection is best-effort enrichment: a lookup failure must not block issuance.
            return Map.of();
        }
        Object selectorsRaw;
        try {
            selectorsRaw = JsonUtil.parseJson(body).get("selectors");
        } catch (Exception e) {
            return Map.of();
        }
        if (!(selectorsRaw instanceof List)) {
            return Map.of();
        }

        List<String> flat = new ArrayList<>();
        // selectors grouped by type: {"k8s": ["ns:demo","sa:payment-agent"], "unix": ["uid:0"]}
        Map<String, List<String>> byType = new TreeMap<>();
        for (Object sel : (List<Object>) selectorsRaw) {
            if (!(sel instanceof Map)) {
                continue;
            }
            Map<String, Object> m = (Map<String, Object>) sel;
            Object type = m.get("type");
            Object value = m.get("value");
            if (type == null || value == null) {
                continue;
            }
            String t = String.valueOf(type);
            String v = String.valueOf(value);
            flat.add(t + ":" + v);
            byType.computeIfAbsent(t, k -> new ArrayList<>()).add(v);
        }
        if (flat.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("selectors", flat);
        attributes.put("spire", byType);
        return attributes;
    }
}
