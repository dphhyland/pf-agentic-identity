package com.pingidentity.ps.oidf.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AgentIdMinterTest {

    @Test
    void mintsBase64UrlWithNoPadding() {
        String id = AgentIdMinter.mint();
        assertFalse(id.contains("+"), "must be URL-safe, not standard base64");
        assertFalse(id.contains("/"), "must be URL-safe, not standard base64");
        assertFalse(id.contains("="), "must carry no padding");
        // 32 raw bytes, base64url-encoded with no padding, is exactly 43 characters.
        assertEquals(43, id.length());
        Base64.getUrlDecoder().decode(id); // throws IllegalArgumentException if malformed
    }

    @Test
    void successiveMintsAreNotRepeats() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            assertTrue(seen.add(AgentIdMinter.mint()), "a repeat within 1000 mints indicates a broken RNG");
        }
    }
}
