/*
 * MVP AssertedContextResolver: a static, config-driven Entra Agent ID directory.
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;

/**
 * Resolves an asserted Entra Agent ID {@code oid} (a Copilot Studio agent's Microsoft-assigned object id —
 * unverifiable at request time, since Copilot Studio agents share one Microsoft-owned blueprint and cannot
 * present per-agent evidence) against a static, operator-maintained directory: {@code oid → {display_name,
 * groups, ceiling}}.
 *
 * <p>This is deliberately the MVP shape — a live Microsoft Graph {@code checkMemberGroups} lookup (mapping
 * live Entra security-group membership to a ceiling, rather than a pre-baked static map) is real future
 * work once Azure access exists, following this same {@link AssertedContextResolver} contract; the static
 * map lets the whole asserted-context pipeline be built and tested with zero live Azure/Entra dependency.
 *
 * <p>Directory JSON shape ({@code OIDF_ENTRA_AGENT_DIRECTORY}):
 * <pre>{@code
 * {
 *   "<oid>": {
 *     "display_name": "Northwind Copilot (demo)",
 *     "groups": ["copilot-bridge-users", "copilot-payments-allowed"],
 *     "ceiling": [ { "type": "...", "actions": ["initiate"], ... } ]
 *   }
 * }
 * }</pre>
 */
public final class EntraDirectoryAssertedContextResolver implements AssertedContextResolver {

    public static final String ID = "entra-directory";

    private final Map<String, Entry> byOid;

    public EntraDirectoryAssertedContextResolver(Map<String, Entry> byOid) {
        this.byOid = Map.copyOf(byOid);
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public AssertedContext resolve(InstanceIdentity verified, String assertedDiscriminator,
                                   AttestationIssuanceConfig config) throws IssuanceException {
        if (assertedDiscriminator == null || assertedDiscriminator.isBlank()) {
            throw IssuanceException.invalidRequest("asserted_context value (Entra Agent ID oid) is required");
        }
        Entry entry = this.byOid.get(assertedDiscriminator);
        if (entry == null) {
            throw IssuanceException.accessDenied(
                    "Entra Agent ID '" + assertedDiscriminator + "' is not in the directory");
        }
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("type", "entra-copilot-agent-oid");
        claims.put("oid", assertedDiscriminator);
        if (entry.displayName != null) {
            claims.put("display_name", entry.displayName);
        }
        claims.put("groups", entry.groups);
        return new AssertedContext(claims, entry.ceiling);
    }

    /** One directory entry: what an asserted oid maps to. */
    public static final class Entry {
        final String displayName;
        final List<String> groups;
        final List<Map<String, Object>> ceiling;

        public Entry(String displayName, List<String> groups, List<Map<String, Object>> ceiling) {
            this.displayName = displayName;
            this.groups = groups == null ? List.of() : List.copyOf(groups);
            this.ceiling = ceiling == null ? List.of() : List.copyOf(ceiling);
        }
    }

    /**
     * Parses the {@code OIDF_ENTRA_AGENT_DIRECTORY} JSON shape into a resolver. Returns null (not an
     * exception) on absent/unparseable input, mirroring {@code staticWalletValidatorFromEnv}'s
     * fail-open-to-unconfigured convention — a malformed directory disables the feature rather than
     * breaking every attestation on this attester.
     */
    public static EntraDirectoryAssertedContextResolver fromJson(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        Map<String, Entry> byOid = new LinkedHashMap<>();
        try {
            JsonUtil.parseJson(json).forEach((oid, value) -> {
                if (!(value instanceof Map)) {
                    return;
                }
                @SuppressWarnings("unchecked")
                Map<String, Object> obj = (Map<String, Object>) value;
                String displayName = obj.get("display_name") == null ? null : String.valueOf(obj.get("display_name"));
                List<String> groups = stringList(obj.get("groups"));
                List<Map<String, Object>> ceiling = objectList(obj.get("ceiling"));
                byOid.put(oid, new Entry(displayName, groups, ceiling));
            });
        } catch (Exception e) {
            return null;
        }
        return byOid.isEmpty() ? null : new EntraDirectoryAssertedContextResolver(byOid);
    }

    @SuppressWarnings("unchecked")
    private static List<String> stringList(Object value) {
        if (!(value instanceof List)) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (Object item : (List<Object>) value) {
            out.add(String.valueOf(item));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> objectList(Object value) {
        if (!(value instanceof List)) {
            return List.of();
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object item : (List<Object>) value) {
            if (item instanceof Map) {
                out.add((Map<String, Object>) item);
            }
        }
        return out;
    }
}
