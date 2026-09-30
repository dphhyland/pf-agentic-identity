package com.pingidentity.ps.oidf.platform.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * PR-5's additions to format 1: every one optional, so a catalogue written before them still loads; the default
 * governed rule and its refusals; the schemes form; upper-case system properties; removed plugin fields; components.
 */
class CatalogueFormatTest {

    /** A catalogue of one entry, {@code entry} being its JSON members after the name. */
    static String catalogue(String top, String entry) {
        return "{\"format\": 1, \"component\": \"fmt\", \"module\": \"libs/platform\","
                + " \"package\": \"com.pingidentity.ps.oidf.platform.settings\", \"families\": [\"OIDF_FMT_\"]" + top + ","
                + " \"settings\": [" + entry + "], \"removed\": []}";
    }

    /** An env entry named OIDF_FMT_X with these members (type, default, profile and anything else). */
    static String env(String members) {
        return "{\"name\": \"OIDF_FMT_X\", \"kind\": \"env\", " + members + ", \"description\": \"d\","
                + " \"when_wrong\": {\"effect\": \"not-checked\", \"detail\": \"d\"}, \"security\": true,"
                + " \"sources\": [{\"from\": \"env\", \"name\": \"OIDF_FMT_X\"}], \"aliases\": [], \"file\": false}";
    }

    static Setting only(String members) {
        return Catalogue.parse(catalogue("", env(members)), "fmt.json").setting("OIDF_FMT_X");
    }

    static String refusal(String members) {
        return assertThrows(IllegalArgumentException.class, () -> only(members)).getMessage();
    }

    @Test
    void aCatalogueWithoutTheNewMembersLoadsAsBefore() {
        Catalogue c = Catalogue.parse(catalogue("", env("\"type\": \"bool\", \"default\": false, \"profile\": \"any\"")), "fmt.json");
        Setting s = c.setting("OIDF_FMT_X");
        assertNull(s.governed(), "any governs nothing");
        assertEquals(List.of(), s.components());
        assertEquals(List.of(), c.components(), "a catalogue the table does not list belongs to no component");
        assertFalse(c.componentsDeclared());
        assertEquals(List.of(), c.componentsOf(s));
    }

    @Test
    void aCatalogueAndAnEntryNameTheirComponents() {
        Catalogue c = Catalogue.parse(catalogue(", \"components\": [\"SSF\", \"GM_API\"]",
                env("\"type\": \"bool\", \"default\": false, \"profile\": \"forbidden-in-production\", \"components\": [\"FAPI\"]")),
                "fmt.json");
        assertEquals(List.of("SSF", "GM_API"), c.components());
        assertTrue(c.componentsDeclared());
        assertEquals(List.of("FAPI"), c.componentsOf(c.setting("OIDF_FMT_X")));
        assertEquals("fmt.json: the document: each component is named as S-9 names one (SSF_RECEIVER), not 'ssf'",
                assertThrows(IllegalArgumentException.class, () -> Catalogue.parse(catalogue(", \"components\": [\"ssf\"]",
                        env("\"type\": \"bool\", \"default\": false, \"profile\": \"any\"")), "fmt.json")).getMessage());
        assertEquals("fmt.json: the document: component SSF is listed twice",
                assertThrows(IllegalArgumentException.class, () -> Catalogue.parse(catalogue(", \"components\": [\"SSF\", \"SSF\"]",
                        env("\"type\": \"bool\", \"default\": false, \"profile\": \"any\"")), "fmt.json")).getMessage());
        assertEquals("fmt.json: the document: components must be a list, not 'SSF'",
                assertThrows(IllegalArgumentException.class, () -> Catalogue.parse(catalogue(", \"components\": \"SSF\"",
                        env("\"type\": \"bool\", \"default\": false, \"profile\": \"any\"")), "fmt.json")).getMessage());
        assertTrue(refusal("\"type\": \"bool\", \"default\": false, \"profile\": \"any\", \"components\": [1]")
                .endsWith("each component is named as S-9 names one (SSF_RECEIVER), not a number"));
        assertTrue(refusal("\"type\": \"bool\", \"default\": false, \"profile\": \"any\", \"components\": []")
                .endsWith("an entry's components names at least one; leave it out to take the catalogue's"));
    }

    @Test
    void theTableGivesTodaysCataloguesTheirComponents() {
        String json = "{\"format\": 1, \"component\": \"ssf-transmitter\", \"module\": \"servlets/ssf\","
                + " \"package\": \"com.pingidentity.ps.oidf.ssf\", \"families\": [], \"settings\": [], \"removed\": []}";
        assertEquals(List.of("SSF", "SSF_RECEIVER"), Catalogue.parse(json, "ssf-transmitter.json").components());
        assertEquals(DefaultComponents.EVERY, DefaultComponents.of("pf-audit"));
        assertEquals(List.of(), DefaultComponents.of("not-a-catalogue"));
    }

    @Test
    void theDefaultRuleGovernsEveryValueButTheDefaultOfASwitch() {
        Setting on = only("\"type\": \"bool\", \"default\": false, \"profile\": \"forbidden-in-production\"");
        assertEquals(Governed.Form.VALUES, on.governed().form());
        assertEquals(List.of("true"), on.governed().values());
        assertFalse(on.governed().explicit());
        assertTrue(on.governed().matches(on, "TRUE"));
        assertFalse(on.governed().matches(on, "false"));
        Setting off = only("\"type\": \"bool\", \"default\": true, \"profile\": \"accepted-risk:pkce-off\"");
        assertEquals(List.of("false"), off.governed().values());
    }

    @Test
    void theDefaultRuleGovernsTheOtherOfTwoChoices() {
        Setting first = only("\"type\": \"choice\", \"default\": \"known\", \"choices\": [\"known\", \"any\"],"
                + " \"profile\": \"accepted-risk:resolve-any\"");
        assertEquals(List.of("any"), first.governed().values());
        Setting second = only("\"type\": \"choice\", \"default\": \"any\", \"choices\": [\"known\", \"any\"],"
                + " \"profile\": \"accepted-risk:resolve-any\"");
        assertEquals(List.of("known"), second.governed().values());
    }

    @Test
    void theDefaultRuleGovernsAnyValueOfATypeWithNoDefault() {
        Setting s = only("\"type\": \"string\", \"default\": null, \"profile\": \"forbidden-in-production\"");
        assertEquals(Governed.Form.ANY_VALUE, s.governed().form());
        assertTrue(s.governed().matches(s, "anything"));
        assertEquals("any value", s.governed().describe());
        Setting choice = only("\"type\": \"choice\", \"default\": null, \"choices\": [\"a\", \"b\", \"c\"],"
                + " \"profile\": \"forbidden-in-production\"");
        assertEquals(Governed.Form.ANY_VALUE, choice.governed().form(), "no default: any value set, however many choices");
    }

    @Test
    void anEntryTheDefaultRuleCannotReadMustSay() {
        assertTrue(refusal("\"type\": \"choice\", \"default\": \"refuse\", \"choices\": [\"refuse\", \"disable\", \"log\"],"
                + " \"profile\": \"accepted-risk:expiry-log-mode\"").endsWith("an entry of type choice with 3 choices and a"
                + " default, classed accepted-risk:expiry-log-mode, says in governed which values the profile acts on"),
                "a choice of more than two");
        assertTrue(refusal("\"type\": \"int\", \"default\": 5, \"min\": 0, \"max\": 9, \"profile\": \"forbidden-in-production\"")
                .endsWith("an entry of type int and a default, classed forbidden-in-production, says in governed which values"
                        + " the profile acts on"));
        Setting said = only("\"type\": \"choice\", \"default\": \"refuse\", \"choices\": [\"refuse\", \"disable\", \"log\"],"
                + " \"profile\": \"accepted-risk:expiry-log-mode\", \"governed\": [\"LOG\", \"disable\"]");
        assertEquals(List.of("log", "disable"), said.governed().values(), "spelt as the choices spell them");
        assertTrue(said.governed().explicit());
        assertEquals("log or disable", said.governed().describe());
        assertTrue(said.governed().matches(said, "Log"));
        assertFalse(said.governed().matches(said, "refuse"));
        assertThrows(SettingRefused.class, () -> said.governed().matches(said, "nope"));
    }

    @Test
    void explicitValuesAreValuesOfTheTypeListedOnceAndNeverTheDefault() {
        Setting bool = only("\"type\": \"bool\", \"default\": false, \"profile\": \"forbidden-in-production\","
                + " \"governed\": [true]");
        assertEquals(List.of("true"), bool.governed().values(), "a JSON boolean is taken as its text");
        assertTrue(refusal("\"type\": \"bool\", \"default\": false, \"profile\": \"forbidden-in-production\","
                + " \"governed\": [\"yes\"]").endsWith("governed value 'yes' is not a value of this bool"));
        assertTrue(refusal("\"type\": \"bool\", \"default\": false, \"profile\": \"forbidden-in-production\","
                + " \"governed\": [1]").endsWith("governed value a number is not a value of this bool"));
        assertTrue(refusal("\"type\": \"bool\", \"default\": false, \"profile\": \"forbidden-in-production\","
                + " \"governed\": [\"true\", \"TRUE\"]").endsWith("governed value true is listed twice"));
        assertTrue(refusal("\"type\": \"bool\", \"default\": false, \"profile\": \"forbidden-in-production\","
                + " \"governed\": [\"false\"]").endsWith("governed value false is the default, so unset would be the case the"
                        + " profile governs and nothing could see it"));
        assertTrue(refusal("\"type\": \"bool\", \"default\": false, \"profile\": \"forbidden-in-production\","
                + " \"governed\": []").endsWith("governed is a list of values or {\"schemes\": [...]}, not a list"));
        assertTrue(refusal("\"type\": \"bool\", \"default\": false, \"profile\": \"forbidden-in-production\","
                + " \"governed\": \"true\"").endsWith("governed is a list of values or {\"schemes\": [...]}, not 'true'"));
        assertTrue(refusal("\"type\": \"string\", \"default\": \"a\", \"profile\": \"forbidden-in-production\","
                + " \"governed\": [\"a\"]").endsWith("governed values go with a bool or a choice, not a string"));
        Setting noDefault = only("\"type\": \"choice\", \"default\": null, \"choices\": [\"a\", \"b\"],"
                + " \"profile\": \"forbidden-in-production\", \"governed\": [\"b\"]");
        assertEquals(List.of("b"), noDefault.governed().values());
    }

    @Test
    void governedGoesOnlyWithAClassThatActsOnValues() {
        assertTrue(refusal("\"type\": \"bool\", \"default\": false, \"profile\": \"any\", \"governed\": [\"true\"]")
                .endsWith("governed goes with forbidden-in-production or accepted-risk:<id>, not any"));
        assertTrue(refusal("\"type\": \"string\", \"default\": null, \"profile\": \"required-in-production\","
                + " \"governed\": [\"x\"]").endsWith("governed goes with forbidden-in-production or accepted-risk:<id>, not"
                        + " required-in-production"));
        assertNull(only("\"type\": \"string\", \"default\": null, \"profile\": \"required-in-production\"").governed());
    }

    @Test
    void theSchemesFormGovernsAUrlByItsScheme() {
        Setting redis = only("\"type\": \"secret\", \"default\": null, \"profile\": \"forbidden-in-production\","
                + " \"governed\": {\"schemes\": [\"redis\"]}");
        assertEquals(Governed.Form.SCHEMES, redis.governed().form());
        assertTrue(redis.governed().matches(redis, "redis://:pw@host:6379"));
        assertTrue(redis.governed().matches(redis, "REDIS://host"), "a scheme in any case");
        assertFalse(redis.governed().matches(redis, "rediss://host"));
        assertFalse(redis.governed().matches(redis, "host:6379"));
        assertFalse(redis.governed().matches(redis, "://host"));
        assertEquals("a redis:// URL", redis.governed().describe());
        assertTrue(refusal("\"type\": \"bool\", \"default\": false, \"profile\": \"forbidden-in-production\","
                + " \"governed\": {\"schemes\": [\"redis\"]}").endsWith("governed schemes go with a string, secret, url or"
                        + " https-url, not a bool"));
        assertTrue(refusal("\"type\": \"url\", \"default\": null, \"profile\": \"forbidden-in-production\","
                + " \"governed\": {\"schemes\": [\"Redis\"]}").endsWith("each governed scheme is a lower-case scheme name, listed"
                        + " once, not 'Redis'"));
        assertTrue(refusal("\"type\": \"url\", \"default\": null, \"profile\": \"forbidden-in-production\","
                + " \"governed\": {\"schemes\": [1]}").endsWith("listed once, not a number"));
        assertTrue(refusal("\"type\": \"https-url\", \"default\": null, \"profile\": \"forbidden-in-production\","
                + " \"governed\": {\"schemes\": [\"a\", \"a\"]}").endsWith("listed once, not 'a'"));
        assertTrue(refusal("\"type\": \"string\", \"default\": null, \"profile\": \"forbidden-in-production\","
                + " \"governed\": {\"schemes\": []}").endsWith("governed schemes lists at least one scheme"));
        assertTrue(refusal("\"type\": \"string\", \"default\": null, \"profile\": \"forbidden-in-production\","
                + " \"governed\": {\"hosts\": []}").contains("unknown member 'hosts'"));
        Setting two = only("\"type\": \"url\", \"default\": null, \"profile\": \"forbidden-in-production\","
                + " \"governed\": {\"schemes\": [\"http\", \"ws\"]}");
        assertEquals("a http:// or ws:// URL", two.governed().describe());
        assertEquals(two.governed(), only("\"type\": \"url\", \"default\": null, \"profile\": \"forbidden-in-production\","
                + " \"governed\": {\"schemes\": [\"http\", \"ws\"]}").governed());
        assertEquals(two.governed().hashCode(), only("\"type\": \"url\", \"default\": null, \"profile\": \"forbidden-in-production\","
                + " \"governed\": {\"schemes\": [\"http\", \"ws\"]}").governed().hashCode());
        assertFalse(two.governed().equals(redis.governed()));
        assertEquals("a http:// or ws:// URL", two.governed().toString());
        assertFalse(two.governed().equals("a http:// or ws:// URL"));
        assertFalse(Governed.values(List.of("true"), true).equals(Governed.values(List.of("true"), false)), "explicit counts");
        assertFalse(Governed.values(List.of("true"), true).equals(Governed.values(List.of("false"), true)));
        assertFalse(Governed.values(List.of("http"), true).equals(Governed.schemes(List.of("http"))));
        assertTrue(Governed.anyValue(true).equals(Governed.anyValue(true)));
    }

    @Test
    void aSystemPropertyNameMayCarryUpperCaseLetters() {
        String json = catalogue("", "{\"name\": \"jdk.internal.httpclient.disableHostnameVerification\", \"kind\": \"system-property\","
                + " \"type\": \"string\", \"default\": null, \"profile\": \"forbidden-in-production\", \"description\": \"d\","
                + " \"when_wrong\": {\"effect\": \"not-checked\", \"detail\": \"d\"}, \"security\": true,"
                + " \"sources\": [{\"from\": \"system-property\", \"name\": \"jdk.internal.httpclient.disableHostnameVerification\"}],"
                + " \"aliases\": [], \"file\": false}");
        Setting flag = Catalogue.parse(json, "fmt.json").setting("jdk.internal.httpclient.disableHostnameVerification");
        assertEquals(EntryKind.SYSTEM_PROPERTY, flag.kind());
        assertEquals(Governed.Form.ANY_VALUE, flag.governed().form());
    }

    @Test
    void aRemovedPluginFieldIsDeclaredAndRefusedWhenAPluginStillSetsIt() {
        String field = "{\"name\": \"Skip TLS\", \"kind\": \"plugin-field\", \"type\": \"bool\", \"default\": false,"
                + " \"profile\": \"any\", \"description\": \"d\", \"when_wrong\": {\"effect\": \"not-checked\", \"detail\": \"d\"},"
                + " \"security\": true, \"sources\": [], \"aliases\": [], \"file\": false}";
        String json = catalogue("", field).replace("\"removed\": []", "\"removed\": [{\"name\": \"Old field\","
                + " \"from\": \"plugin-field\", \"replacement\": \"Skip TLS\", \"release\": \"0.6.0\"},"
                + " {\"name\": \"OIDF_FMT_GONE\", \"from\": \"env\", \"replacement\": null, \"release\": \"0.6.0\"}]");
        Catalogue c = Catalogue.parse(json, "fmt.json");
        Removed gone = c.removed().get(0);
        assertEquals(new Removed("Old field", EntryKind.PLUGIN_FIELD, "Skip TLS", "0.6.0"), gone);
        assertNull(gone.source(), "PingFederate supplies a field");
        assertEquals(Set.of("OIDF_FMT_GONE"), c.declaredEnvironmentNames());
        c.refuseRemoved(Sources.of(Map.of("Old field", "x"), Map.of()));
        c.refuseRemovedFields(Map.of("Skip TLS", "true")::get);
        c.refuseRemovedFields(Map.of("Old field", " ")::get);
        assertEquals("Old field was removed in 0.6.0; set Skip TLS instead",
                assertThrows(SettingRefused.class, () -> c.refuseRemovedFields(Map.of("Old field", "on")::get)).getMessage());
        assertEquals("fmt.json: removed[0]: plugin-field Skip TLS is declared twice in this catalogue",
                assertThrows(IllegalArgumentException.class, () -> Catalogue.parse(json.replace("\"Old field\"", "\"Skip TLS\""),
                        "fmt.json")).getMessage());
        assertEquals("fmt.json: removed[1]: plugin-field Old field is declared twice in this catalogue",
                assertThrows(IllegalArgumentException.class, () -> Catalogue.parse(json.replace("\"OIDF_FMT_GONE\", \"from\": \"env\"",
                        "\"Old field\", \"from\": \"plugin-field\""), "fmt.json")).getMessage());
        assertThrows(IllegalArgumentException.class, () -> new Removed("x", EntryKind.EXTENDED_PROPERTY, null, "0.6.0"));
        assertThrows(IllegalArgumentException.class, () -> EntryKind.of(Source.DEFAULT));
        assertEquals(EntryKind.INIT_PARAM, EntryKind.of(Source.INIT_PARAM));
    }
}
