/*
 * What every test of a refusal to a caller that has not authenticated checks about its body.
 */
package com.pingidentity.ps.oidf.servlet.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;

/** The public side of a refusal (plan item H-FED-4): {@code error}, its fixed description and a correlation id. */
public final class PublicErrorsAssert {
    private PublicErrorsAssert() {
    }

    /** {@code description} is {@code error}'s fixed text and a reference, and nothing else. */
    public static void assertGenericDescription(String error, Object description) {
        String text = String.valueOf(description);
        String prefix = PublicErrors.generic(error) + " (reference ";
        assertTrue(text.startsWith(prefix) && text.endsWith(")"), "a generic description for " + error + ": " + text);
        assertTrue(text.substring(prefix.length(), text.length() - 1).matches("[A-Za-z0-9:_-]+"), text);
    }

    /** {@code body} is the JSON refusal {@code error} with its generic description; returns the parsed body. */
    public static Map<String, Object> assertGeneric(String error, String body) {
        Map<String, Object> json;
        try {
            json = JsonUtil.parseJson(body);
        } catch (JoseException e) {
            throw new AssertionError("not JSON: " + body, e);
        }
        assertEquals(error, json.get("error"), body);
        assertGenericDescription(error, json.get("error_description"));
        return json;
    }
}
