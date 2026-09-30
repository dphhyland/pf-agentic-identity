/*
 * The components each of the 0.6.0 catalogues' settings belong to, for a catalogue that does not say.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The components a catalogue's settings belong to when the catalogue has no {@code components} member: the table in
 * docs/development/settings-catalogue.md ("Components"), which {@code DefaultComponentsTest} holds this to and
 * {@code tools/settings-scan.py} holds to the catalogues (every catalogue is in the table or says its own). A
 * violation of the production profile by one of the catalogue's settings refuses these components (plan item PR-5),
 * and an unknown {@code OIDF_*} name under one of its families refuses them too (Phase 3 plan, decision 5).
 *
 * <p>The nine names are S-9's ({@code health.Startup}), and {@code GM_API} is gm-api's own. A plugin or a service
 * that registers no component is named by its catalogue here ({@code CIBA_SIMULATOR}, {@code RAR_PDP_PROCESSOR},
 * {@code INSTANCE_REGISTRY}, {@code DEVICE_ENROLMENT}), so a violation always names what it refuses: the package that
 * converts that reader asks {@code ProfileRefusals} under that name. A catalogue whose owner narrows its components
 * - per catalogue, or per entry - writes them into the catalogue and its line here goes.
 */
final class DefaultComponents {

    /** Every S-9 component. */
    static final List<String> EVERY = List.of("FEDERATION", "AUTO_REGISTRATION", "ATTESTATION_AUTH", "ATTESTATION_ISSUER",
            "HOSTING", "SSF", "SSF_RECEIVER", "OPERATOR_API", "FAPI");

    /** Each catalogue's components, by the catalogue's component name, in the table's order. */
    static final Map<String, List<String>> TABLE;

    static {
        Map<String, List<String>> table = new LinkedHashMap<>();
        table.put("attestation-challenge", List.of("ATTESTATION_AUTH", "ATTESTATION_ISSUER"));
        table.put("attestation-issuer", List.of("ATTESTATION_ISSUER"));
        table.put("attestation-token-endpoint", List.of("ATTESTATION_AUTH"));
        table.put("ciba-simulator", List.of("CIBA_SIMULATOR"));
        table.put("client-properties", List.of("FEDERATION", "AUTO_REGISTRATION", "ATTESTATION_AUTH"));
        table.put("components", List.of());
        table.put("deployment-profile", EVERY);
        table.put("device-enrolment", List.of("DEVICE_ENROLMENT"));
        table.put("evidence-policy", List.of("ATTESTATION_ISSUER"));
        table.put("fapi2-profile", List.of("FAPI"));
        table.put("federation-entity", List.of("FEDERATION", "HOSTING"));
        table.put("federation-resolution", List.of("FEDERATION", "AUTO_REGISTRATION"));
        table.put("federation-runtime", List.of("FEDERATION", "AUTO_REGISTRATION", "ATTESTATION_AUTH"));
        table.put("gm-api", List.of("GM_API"));
        table.put("hosted-entities", List.of("HOSTING", "OPERATOR_API"));
        table.put("hosted-entity-signing", List.of("HOSTING", "ATTESTATION_ISSUER"));
        table.put("instance-registry", List.of("INSTANCE_REGISTRY"));
        table.put("issuance-client-properties", List.of("ATTESTATION_ISSUER"));
        table.put("operator-auth", List.of("OPERATOR_API"));
        table.put("outbound-fetch", List.of("FEDERATION", "AUTO_REGISTRATION", "ATTESTATION_AUTH", "ATTESTATION_ISSUER", "HOSTING"));
        table.put("pf-audit", EVERY);
        table.put("platform-redis", List.of("ATTESTATION_AUTH", "ATTESTATION_ISSUER", "OPERATOR_API"));
        table.put("rar-models", List.of("ATTESTATION_AUTH"));
        table.put("rar-pdp-processor", List.of("RAR_PDP_PROCESSOR"));
        table.put("registration", List.of("FEDERATION", "AUTO_REGISTRATION"));
        table.put("ssf-logout-signal", List.of("SSF"));
        table.put("ssf-transmitter", List.of("SSF", "SSF_RECEIVER"));
        TABLE = Collections.unmodifiableMap(table);
    }

    private DefaultComponents() {
    }

    /** {@code catalogue}'s components from the table; empty for a catalogue the table does not list. */
    static List<String> of(String catalogue) {
        return TABLE.getOrDefault(catalogue, List.of());
    }
}
