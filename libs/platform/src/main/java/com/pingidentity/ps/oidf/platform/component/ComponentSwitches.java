/*
 * The nine components' enable switches, and what each one says about its component.
 */
package com.pingidentity.ps.oidf.platform.component;

import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * S-9's enable switches, {@code OIDF_<COMPONENT>_ENABLED}, catalogued in platform's {@code components.json} and read
 * through {@code Settings.of("components")}. A switch is {@code true}, {@code false} or unset:
 *
 * <ul>
 *   <li>{@code false} disables the component, whatever else is set.</li>
 *   <li>{@code true} enables it; a component switched on without the settings it needs is {@code FAILED_CONFIG}
 *       (the component's own {@code init} says which, through {@code Part.notConfigured}).</li>
 *   <li>Unset, in development: inferred from the component's settings, as before the switches existed.</li>
 *   <li>Unset, in production: inferred only while none of the component's settings ({@link #PRESENCE}) is set.
 *       A component whose settings are present and whose switch is unset is a configuration the operator has not
 *       finished: {@code FAILED_CONFIG}, with a reason naming the switch (Phase 3 plan, decision 1).</li>
 * </ul>
 *
 * <p>{@code OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY} is a superseded name for {@code OIDF_ATTESTATION_AUTH_ENABLED}
 * (a catalogue alias): still read, with a warning, and refused when both are set to different values. A value
 * that is not {@code true} or {@code false}, or a conflict, is {@code FAILED_CONFIG} with the resolver's message.
 */
public final class ComponentSwitches {

    public static final String FEDERATION = "OIDF_FEDERATION_ENABLED";
    public static final String AUTO_REGISTRATION = "OIDF_AUTO_REGISTRATION_ENABLED";
    public static final String ATTESTATION_AUTH = "OIDF_ATTESTATION_AUTH_ENABLED";
    public static final String ATTESTATION_ISSUER = "OIDF_ATTESTATION_ISSUER_ENABLED";
    public static final String HOSTING = "OIDF_HOSTING_ENABLED";
    public static final String SSF = "OIDF_SSF_ENABLED";
    public static final String SSF_RECEIVER = "OIDF_SSF_RECEIVER_ENABLED";
    public static final String OPERATOR_API = "OIDF_OPERATOR_API_ENABLED";
    public static final String FAPI = "OIDF_FAPI_ENABLED";

    /** The catalogue the switches are in. */
    public static final String CATALOGUE = "components";

    /** Each component's switch, by S-9's component name. */
    public static final Map<String, String> SWITCHES;

    /**
     * The settings that make each component "present": when one of them is set, in the environment and not blank,
     * the operator has configured the component, and production wants its switch said out loud. The same lists
     * are in each switch's description in {@code components.json} and in docs/operator/components.md.
     */
    public static final Map<String, List<String>> PRESENCE;

    static {
        Map<String, String> switches = new LinkedHashMap<>();
        Map<String, List<String>> presence = new LinkedHashMap<>();
        add(switches, presence, "FEDERATION", FEDERATION, "OIDF_FEDERATION_TRUST_ANCHORS", "OIDF_FEDERATION_SUBORDINATES",
                "OIDF_FEDERATION_TRUST_ANCHOR_JWKS", "OIDF_FEDERATION_SELF_ANCHOR", "OIDF_FEDERATION_TRUST_MARK_TYPES",
                "OIDF_FEDERATION_ENDPOINT_AUTH");
        add(switches, presence, "AUTO_REGISTRATION", AUTO_REGISTRATION, "OIDF_FEDERATION_TRUST_CONTROLLER_HOST",
                "OIDF_FEDERATION_TRUST_CONTROLLER_BASE_URL", "OIDF_AUTO_REGISTRATION_FAIL_CLOSED", "OIDF_AUTO_REGISTRATION_FRONT_CHANNEL");
        add(switches, presence, "ATTESTATION_AUTH", ATTESTATION_AUTH, "OIDF_BRIDGE_SIGNER_BACKING", "OIDF_BRIDGE_SIGNING_KEYS",
                "OIDF_ATTESTATION_REQUIRE_ATTESTER_BINDING", "OIDF_ATTESTATION_REQUIRE_HOSTED_AGENT");
        add(switches, presence, "ATTESTATION_ISSUER", ATTESTATION_ISSUER, "OIDF_ATTESTER_SIGNING_JWK", "OIDF_ATTESTER_FEDERATION_ENTITY",
                "OIDF_ATTESTER_OP_ISSUER", "OIDF_ATTESTER_CIMD_URL", "OIDF_ATTESTER_SPIRE_ENTRIES_URL");
        add(switches, presence, "HOSTING", HOSTING, "OIDF_AUTHORITY_ENTITY_ID", "OIDF_AUTHORITY_JDBC_URL", "OIDF_AUTHORITY_DATA_STORE_ID",
                "OIDF_OPENBAO_URL");
        add(switches, presence, "SSF", SSF, "OIDF_SSF_ISSUER", "OIDF_SSF_JDBC_URL", "OIDF_SSF_DATA_STORE_ID");
        add(switches, presence, "SSF_RECEIVER", SSF_RECEIVER, "OIDF_SSF_RECEIVER_EXPECTED_ISSUER", "OIDF_SSF_RECEIVER_JWKS_URL",
                "OIDF_SSF_RECEIVER_POLL_URL");
        add(switches, presence, "OPERATOR_API", OPERATOR_API, "OIDF_AUTHORITY_ADMIN_TOKEN");
        add(switches, presence, "FAPI", FAPI, "OIDF_FAPI2_CLIENTS");
        SWITCHES = Map.copyOf(switches);
        PRESENCE = Map.copyOf(presence);
    }

    private static void add(Map<String, String> switches, Map<String, List<String>> presence, String component, String name,
            String... present) {
        switches.put(component, name);
        presence.put(component, List.of(present));
    }

    /** What a switch says. */
    public enum Kind {
        /** Set to {@code true}: the component runs, and must find the settings it needs. */
        ENABLED,
        /** Set to {@code false}: the component does not start and its surfaces keep their disabled behaviour. */
        DISABLED,
        /** Unset, and allowed to be: the component decides from its settings, as it did before the switches. */
        INFERRED,
        /** Unset in production with the component's settings present, a value that does not parse, or a conflict. */
        FAILED_CONFIG
    }

    /**
     * A switch's verdict on its component.
     *
     * @param component S-9's name for it
     * @param name      its switch, or empty for a component that has none
     * @param kind      what the switch says
     * @param note      one line for the start-up banner and the health detail: how the switch was read, or, for
     *                  {@link Kind#FAILED_CONFIG}, why the component is refused
     */
    public record Verdict(String component, String name, Kind kind, String note) {
        public Verdict {
            Objects.requireNonNull(component, "component");
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(note, "note");
        }

        /** Whether the component may start: switched on, or inferred. */
        public boolean mayStart() {
            return this.kind == Kind.ENABLED || this.kind == Kind.INFERRED;
        }
    }

    private final Settings settings;
    /**
     * The environment, asked only whether a presence setting is set - never for its value, which the component's
     * own catalogue declares and its own reader reads.
     */
    private final Function<String, String> presence;
    private final boolean production;

    private ComponentSwitches(Settings settings, Function<String, String> env, boolean production) {
        this.settings = settings;
        this.presence = env;
        this.production = production;
    }

    /** This process's switches: the environment and system properties, and its deployment profile. */
    public static ComponentSwitches process() {
        return of(System::getenv, System::getProperty);
    }

    /** The switches read from these lookups, under the profile the environment names. */
    public static ComponentSwitches of(Function<String, String> env, Function<String, String> systemProperties) {
        Catalogue catalogue = Catalogue.load(ComponentSwitches.class.getClassLoader(), CATALOGUE);
        Settings settings = Settings.of(catalogue, Sources.of(env, systemProperties, null));
        return new ComponentSwitches(settings, env, DeploymentProfile.of(env).isProduction());
    }

    /**
     * {@code component}'s verdict. A component S-9 does not name (gm-api's, say) has no switch and is always
     * {@link Kind#INFERRED}.
     */
    public Verdict verdict(String component) {
        String name = SWITCHES.get(component);
        if (name == null) {
            return new Verdict(component, "", Kind.INFERRED, "");
        }
        String value;
        try {
            value = this.value(component);
        } catch (IllegalStateException e) {
            // A SettingRefused: not true or false, or the superseded name set to something else.
            return new Verdict(component, name, Kind.FAILED_CONFIG, e.getMessage());
        }
        if ("true".equals(value)) {
            return new Verdict(component, name, Kind.ENABLED, name + "=true");
        }
        if ("false".equals(value)) {
            return new Verdict(component, name, Kind.DISABLED, name + "=false");
        }
        List<String> present = present(component);
        if (!this.production) {
            return new Verdict(component, name, Kind.INFERRED, name + " unset: inferred (development profile)");
        }
        if (present.isEmpty()) {
            return new Verdict(component, name, Kind.INFERRED, name + " unset: inferred (none of its settings is set)");
        }
        return new Verdict(component, name, Kind.FAILED_CONFIG, name + " is unset and " + String.join(", ", present)
                + (present.size() == 1 ? " is" : " are") + " set: in production set " + name + " to true or false");
    }

    /**
     * The switch's value, {@code true}, {@code false} or null. One read per switch, each naming its constant, so the
     * settings scan sees every switch read here.
     */
    private String value(String component) {
        switch (component) {
            case "FEDERATION":
                return this.settings.choice(FEDERATION);
            case "AUTO_REGISTRATION":
                return this.settings.choice(AUTO_REGISTRATION);
            case "ATTESTATION_AUTH":
                return this.settings.choice(ATTESTATION_AUTH);
            case "ATTESTATION_ISSUER":
                return this.settings.choice(ATTESTATION_ISSUER);
            case "HOSTING":
                return this.settings.choice(HOSTING);
            case "SSF":
                return this.settings.choice(SSF);
            case "SSF_RECEIVER":
                return this.settings.choice(SSF_RECEIVER);
            case "OPERATOR_API":
                return this.settings.choice(OPERATOR_API);
            default:
                return this.settings.choice(FAPI);
        }
    }

    /** The component's presence settings that are set, in the order {@link #PRESENCE} lists them. */
    List<String> present(String component) {
        List<String> out = new ArrayList<>();
        for (String name : PRESENCE.getOrDefault(component, List.of())) {
            String value = this.presence.apply(name);
            if (value != null && !value.isBlank()) {
                out.add(name);
            }
        }
        return out;
    }
}
