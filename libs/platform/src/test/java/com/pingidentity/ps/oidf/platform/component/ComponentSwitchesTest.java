/*
 * The nine enable switches in both profiles, the inference rule, the superseded bridge-key name and its conflict.
 */
package com.pingidentity.ps.oidf.platform.component;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ComponentSwitchesTest {

    private final Map<String, String> env = new HashMap<>();
    private final Map<String, String> properties = new HashMap<>();

    private ComponentSwitches.Verdict verdict(String component) {
        return ComponentSwitches.of(this.env::get, this.properties::get).verdict(component);
    }

    private void development() {
        this.env.put("OIDF_DEPLOYMENT_PROFILE", "development");
    }

    @Test
    void thereAreNineSwitchesEachCataloguedWithNoDefault() {
        assertEquals(Set.of("FEDERATION", "AUTO_REGISTRATION", "ATTESTATION_AUTH", "ATTESTATION_ISSUER", "HOSTING", "SSF", "SSF_RECEIVER",
                "OPERATOR_API", "FAPI"), ComponentSwitches.SWITCHES.keySet());
        Catalogue catalogue = Catalogue.load(ComponentSwitches.class.getClassLoader(), ComponentSwitches.CATALOGUE);
        for (Map.Entry<String, String> s : ComponentSwitches.SWITCHES.entrySet()) {
            assertEquals("OIDF_" + s.getKey() + "_ENABLED", s.getValue());
            assertEquals(null, catalogue.setting(s.getValue()).defaultValue(), s.getValue() + ": unset means inferred");
            // Every presence setting is named in the switch's description, as docs/operator/components.md names it.
            for (String present : ComponentSwitches.PRESENCE.get(s.getKey())) {
                assertTrue(catalogue.setting(s.getValue()).description().contains(present), s.getValue() + " names " + present);
            }
        }
    }

    @Test
    void trueAndFalseSayTheSameInBothProfiles() {
        for (boolean dev : new boolean[] {false, true}) {
            this.env.clear();
            if (dev) {
                this.development();
            }
            for (Map.Entry<String, String> s : ComponentSwitches.SWITCHES.entrySet()) {
                // Settings present or not, an explicit value decides.
                for (String present : ComponentSwitches.PRESENCE.get(s.getKey())) {
                    this.env.put(present, "set");
                }
                this.env.put(s.getValue(), "true");
                ComponentSwitches.Verdict on = this.verdict(s.getKey());
                assertEquals(ComponentSwitches.Kind.ENABLED, on.kind(), s.getValue());
                assertEquals(s.getValue() + "=true", on.note());
                assertTrue(on.mayStart());
                this.env.put(s.getValue(), "false");
                ComponentSwitches.Verdict off = this.verdict(s.getKey());
                assertEquals(ComponentSwitches.Kind.DISABLED, off.kind(), s.getValue());
                assertFalse(off.mayStart());
            }
        }
    }

    @Test
    void unsetInDevelopmentIsInferredWhateverIsSet() {
        this.development();
        this.env.put("OIDF_FEDERATION_TRUST_CONTROLLER_HOST", "https://anchor.example");
        ComponentSwitches.Verdict v = this.verdict("AUTO_REGISTRATION");
        assertEquals(ComponentSwitches.Kind.INFERRED, v.kind());
        assertTrue(v.mayStart());
        assertEquals("OIDF_AUTO_REGISTRATION_ENABLED unset: inferred (development profile)", v.note());
    }

    @Test
    void unsetInProductionIsInferredOnlyWhileNoneOfItsSettingsIsSet() {
        ComponentSwitches.Verdict none = this.verdict("AUTO_REGISTRATION");
        assertEquals(ComponentSwitches.Kind.INFERRED, none.kind());
        assertEquals("OIDF_AUTO_REGISTRATION_ENABLED unset: inferred (none of its settings is set)", none.note());

        // A blank value is unset.
        this.env.put("OIDF_FEDERATION_TRUST_CONTROLLER_HOST", "  ");
        assertEquals(ComponentSwitches.Kind.INFERRED, this.verdict("AUTO_REGISTRATION").kind());

        this.env.put("OIDF_FEDERATION_TRUST_CONTROLLER_HOST", "https://anchor.example");
        ComponentSwitches.Verdict one = this.verdict("AUTO_REGISTRATION");
        assertEquals(ComponentSwitches.Kind.FAILED_CONFIG, one.kind());
        assertFalse(one.mayStart());
        assertEquals("OIDF_AUTO_REGISTRATION_ENABLED is unset and OIDF_FEDERATION_TRUST_CONTROLLER_HOST is set: in production set"
                + " OIDF_AUTO_REGISTRATION_ENABLED to true or false", one.note());

        this.env.put("OIDF_AUTO_REGISTRATION_FAIL_CLOSED", "true");
        assertTrue(this.verdict("AUTO_REGISTRATION").note().contains(
                "OIDF_FEDERATION_TRUST_CONTROLLER_HOST, OIDF_AUTO_REGISTRATION_FAIL_CLOSED are set"), this.verdict("AUTO_REGISTRATION").note());

        // Only the component's own settings count: federation's are not automatic registration's.
        assertEquals(ComponentSwitches.Kind.INFERRED, this.verdict("FAPI").kind());
    }

    @Test
    void anUnsetProfileIsProduction() {
        this.env.put("OIDF_FAPI2_CLIENTS", "*");
        assertEquals(ComponentSwitches.Kind.FAILED_CONFIG, this.verdict("FAPI").kind());
        this.env.put("OIDF_DEPLOYMENT_PROFILE", "production");
        assertEquals(ComponentSwitches.Kind.FAILED_CONFIG, this.verdict("FAPI").kind());
    }

    @Test
    void aValueThatIsNotTrueOrFalseIsAFailedConfiguration() {
        this.development();
        this.env.put("OIDF_HOSTING_ENABLED", "yes");
        ComponentSwitches.Verdict v = this.verdict("HOSTING");
        assertEquals(ComponentSwitches.Kind.FAILED_CONFIG, v.kind());
        assertTrue(v.note().contains("OIDF_HOSTING_ENABLED"), v.note());
    }

    @Test
    void theSupersededBridgeKeyNameIsReadAsTheAttestationSwitch() {
        this.env.put("OIDF_BRIDGE_SIGNER_BACKING", "openbao");
        this.env.put("OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY", "false");
        assertEquals(ComponentSwitches.Kind.DISABLED, this.verdict("ATTESTATION_AUTH").kind());

        // Its system property too, as the old entry read it.
        this.env.remove("OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY");
        this.properties.put("oidf.attestation.require.bridge.key", "false");
        assertEquals(ComponentSwitches.Kind.DISABLED, this.verdict("ATTESTATION_AUTH").kind());

        // Agreeing with the new name is only redundant.
        this.env.put("OIDF_ATTESTATION_AUTH_ENABLED", "false");
        assertEquals(ComponentSwitches.Kind.DISABLED, this.verdict("ATTESTATION_AUTH").kind());
    }

    @Test
    void theOldAndNewNamesSetToDifferentValuesAreRefused() {
        this.development();
        this.env.put("OIDF_ATTESTATION_AUTH_ENABLED", "true");
        this.env.put("OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY", "false");
        ComponentSwitches.Verdict v = this.verdict("ATTESTATION_AUTH");
        assertEquals(ComponentSwitches.Kind.FAILED_CONFIG, v.kind());
        assertTrue(v.note().contains("OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY"), v.note());
        assertTrue(v.note().contains("OIDF_ATTESTATION_AUTH_ENABLED"), v.note());
    }

    @Test
    void aComponentWithNoSwitchIsInferred() {
        ComponentSwitches.Verdict v = this.verdict("GM_API");
        assertEquals(ComponentSwitches.Kind.INFERRED, v.kind());
        assertEquals("", v.name());
        assertEquals(List.of(), ComponentSwitches.of(this.env::get, this.properties::get).present("GM_API"));
    }

    @Test
    void theProcessSwitchesReadThisProcess() {
        // Whatever this JVM's environment holds, every component gets a verdict.
        ComponentSwitches process = ComponentSwitches.process();
        for (String component : ComponentSwitches.SWITCHES.keySet()) {
            assertEquals(component, process.verdict(component).component());
        }
    }

    @Test
    void aVerdictNeedsEveryField() {
        assertThrows(NullPointerException.class, () -> new ComponentSwitches.Verdict(null, "", ComponentSwitches.Kind.INFERRED, ""));
        assertThrows(NullPointerException.class, () -> new ComponentSwitches.Verdict("X", null, ComponentSwitches.Kind.INFERRED, ""));
        assertThrows(NullPointerException.class, () -> new ComponentSwitches.Verdict("X", "", null, ""));
        assertThrows(NullPointerException.class, () -> new ComponentSwitches.Verdict("X", "", ComponentSwitches.Kind.INFERRED, null));
    }
}
