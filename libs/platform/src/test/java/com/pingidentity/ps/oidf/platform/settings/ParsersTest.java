package com.pingidentity.ps.oidf.platform.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The strict parsers, with the messages they had in FederationRuntimeConfig: each names the setting and the value
 * refused, and each refusal is still an IllegalStateException.
 */
class ParsersTest {

    private static final String NAME = "OIDF_EXAMPLE_X";

    private static SettingRefused refused(Runnable read) {
        SettingRefused e = assertThrows(SettingRefused.class, read::run);
        assertEquals(NAME, e.setting());
        assertTrue(e instanceof IllegalStateException, "a caller that caught IllegalStateException still catches it");
        return e;
    }

    @Test
    void blankIsUnsetAndValuesAreTrimmed() {
        assertNull(Parsers.blankToNull(null));
        assertNull(Parsers.blankToNull(" \t\n"));
        assertEquals("a b", Parsers.blankToNull("  a b\n"));
    }

    @Test
    void theSystemPropertyNameIsLowerCaseWithDots() {
        assertEquals("oidf.pdp.mode", Parsers.systemPropertyName("OIDF_PDP_MODE"));
    }

    @Test
    void aSwitchIsTrueOrFalseInAnyCaseAndNothingElse() {
        assertTrue(Parsers.strictBoolean(NAME, "TRUE"));
        assertTrue(Parsers.strictBoolean(NAME, " true\n"));
        assertFalse(Parsers.strictBoolean(NAME, "False"));
        assertEquals(NAME + " must be true or false, not yes", refused(() -> Parsers.strictBoolean(NAME, "yes")).getMessage());
        assertEquals(NAME + " must be true or false, not  1 ", refused(() -> Parsers.strictBoolean(NAME, " 1 ")).getMessage(),
                "the message shows the value as it was read");
    }

    @Test
    void aSwitchFallsBackOnlyWhenUnset() {
        assertTrue(Parsers.bool(NAME, null, true));
        assertFalse(Parsers.bool(NAME, "  ", false));
        assertTrue(Parsers.bool(NAME, " true ", false));
        assertEquals(NAME + " must be true or false, not on", refused(() -> Parsers.bool(NAME, " on ", true)).getMessage());
    }

    @Test
    void aWholeNumberIsALongWithASign() {
        assertEquals(7L, Parsers.wholeNumber(NAME, null, 7L));
        assertEquals(7L, Parsers.wholeNumber(NAME, " ", 7L));
        assertEquals(-3L, Parsers.wholeNumber(NAME, " -3 ", 7L));
        assertEquals(Long.MAX_VALUE, Parsers.wholeNumber(NAME, "9223372036854775807", 0L));
        assertEquals(NAME + " must be a whole number, not 1.5", refused(() -> Parsers.wholeNumber(NAME, "1.5", 0L)).getMessage());
        assertEquals(NAME + " must be a whole number, not 9223372036854775808",
                refused(() -> Parsers.wholeNumber(NAME, "9223372036854775808", 0L)).getMessage());
    }

    @Test
    void aRangeIsInclusive() {
        assertEquals(1L, Parsers.inRange(NAME, 1L, 1L, 5L));
        assertEquals(5L, Parsers.inRange(NAME, 5L, 1L, 5L));
        assertEquals(NAME + " must be between 1 and 5, not 0", refused(() -> Parsers.inRange(NAME, 0L, 1L, 5L)).getMessage());
        assertEquals(NAME + " must be between 1 and 5, not 6", refused(() -> Parsers.inRange(NAME, 6L, 1L, 5L)).getMessage());
    }

    @Test
    void aChoiceIsReadInAnyCaseAndReturnedAsSpelt() {
        assertEquals("local", Parsers.choice(NAME, null, "local", "off", "local"));
        assertEquals("off", Parsers.choice(NAME, " OFF ", "local", "off", "local"));
        assertEquals(NAME + " must be one of off, local, authzen, not remote",
                refused(() -> Parsers.choice(NAME, "remote", "local", "off", "local", "authzen")).getMessage());
    }

    @Test
    void wordsAreSpaceOrCommaSeparatedAndANullListIsRefused() {
        assertNull(Parsers.words(NAME, null));
        assertNull(Parsers.words(NAME, " "));
        assertEquals(List.of("a", "b", "c"), new ArrayList<>(Parsers.words(NAME, " a, b\tc,,a ")));
        assertEquals(NAME + " lists nothing; leave it unset instead", refused(() -> Parsers.words(NAME, " , ,")).getMessage());
    }

    @Test
    void aJsonObjectIsReadByPlatformJson() {
        assertNull(Parsers.jsonObject(null));
        assertNull(Parsers.jsonObject(" "));
        assertNull(Parsers.jsonObject(" null "), "the JSON literal null reads as unset, as the Jackson read it replaces did");
        Map<String, Object> object = Parsers.jsonObject("{\"b\": 1, \"a\": [true, \"x\"]}");
        assertEquals(List.of("b", "a"), new ArrayList<>(object.keySet()), "members keep their order");
        assertEquals(new BigDecimal("1"), object.get("b"));
        for (String notOne : List.of("[]", "\"text\"", "5", "true", "{", "{\"a\":1,\"a\":2}", "{\"a\":1} x", "{'a':1}")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Parsers.jsonObject(notOne), notOne);
            assertEquals("not a JSON object", e.getMessage(), "the message never repeats the text, which may be a key");
        }
    }

    @Test
    void strictlyNamesTheSettingARefusalCameFrom() {
        assertEquals("ok", Parsers.strictly(NAME, () -> "ok"));
        assertEquals(NAME + ": not a JSON object", refused(() -> Parsers.strictly(NAME, () -> Parsers.jsonObject("[]"))).getMessage());
        assertThrows(UnsupportedOperationException.class, () -> Parsers.strictly(NAME, () -> {
            throw new UnsupportedOperationException("a bug is not a refusal");
        }));
    }

    @Test
    void anHttpsUrlHasAHost() {
        assertNull(Parsers.httpsUrl(NAME, " "));
        assertEquals(URI.create("https://pdp.example/x"), Parsers.httpsUrl(NAME, " https://pdp.example/x "));
        assertEquals(URI.create("HTTPS://pdp.example"), Parsers.httpsUrl(NAME, "HTTPS://pdp.example"));
        for (String bad : List.of("http://pdp.example", "https://", "https:///path", "https://bad host/", "pdp.example", "ftp://pdp.example")) {
            assertEquals(NAME + " must be an https URL with a host, not " + bad, refused(() -> Parsers.httpsUrl(NAME, bad)).getMessage());
        }
    }

    @Test
    void aUrlMayAlsoBeHttp() {
        assertNull(Parsers.httpOrHttpsUrl(NAME, null));
        assertEquals(URI.create("http://pdp.example"), Parsers.httpOrHttpsUrl(NAME, "http://pdp.example"));
        assertEquals(URI.create("https://pdp.example"), Parsers.httpOrHttpsUrl(NAME, "https://pdp.example"));
        assertEquals(NAME + " must be an http or https URL with a host, not ftp://pdp.example",
                refused(() -> Parsers.httpOrHttpsUrl(NAME, "ftp://pdp.example")).getMessage());
    }

    @Test
    void aPathIsOneThePlatformCanName() {
        assertNull(Parsers.path(NAME, null));
        assertEquals(Path.of("/run/secrets/x"), Parsers.path(NAME, " /run/secrets/x "));
        assertEquals(NAME + " is not a path: a\u0000b", refused(() -> Parsers.path(NAME, "a\u0000b")).getMessage());
    }

    @Test
    void anAliasIsUsedWithAWarningOnlyWhenTheCurrentNameIsUnset() {
        List<String> warnings = new ArrayList<>();
        assertEquals("new", Parsers.aliased("NEW", " new ", "OLD", null, warnings));
        assertEquals(List.of(), warnings);
        assertNull(Parsers.aliased("NEW", null, "OLD", " ", warnings));
        assertEquals("old", Parsers.aliased("NEW", null, "OLD", " old ", warnings));
        assertEquals(List.of("OLD is deprecated; set NEW instead (the value was taken from OLD)"), warnings);
        warnings.clear();
        assertEquals("same", Parsers.aliased("NEW", "same", "OLD", " same", warnings));
        assertEquals(List.of("OLD is deprecated and redundant beside NEW; remove it"), warnings);
        SettingRefused e = assertThrows(SettingRefused.class, () -> Parsers.aliased("NEW", "s3cret-a", "OLD", "s3cret-b", new ArrayList<>()));
        assertEquals("NEW and its superseded name OLD are both set, to different values. They name one thing - set only NEW", e.getMessage());
        assertFalse(e.getMessage().contains("s3cret"), "neither value is shown: either may be a secret");
    }
}
