/*
 * Introspection-response parsing: active/scope/client_id, inactive, both scope encodings, transport failure.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PfIntrospectionReceiverAuthenticatorTest {

    @Test
    void activeTokenWithSpaceDelimitedScopes() throws Exception {
        ReceiverAuthenticator auth = new PfIntrospectionReceiverAuthenticator(
                token -> Map.of("active", true, "client_id", "receiver-1", "scope", "openid ssf.manage other"));
        AuthContext ctx = auth.authenticate("tok");
        assertTrue(ctx.isActive());
        assertEquals("receiver-1", ctx.clientId());
        assertTrue(ctx.hasScope("ssf.manage"));
        assertFalse(ctx.hasScope("missing"));
    }

    @Test
    void activeTokenWithArrayScopes() throws Exception {
        ReceiverAuthenticator auth = new PfIntrospectionReceiverAuthenticator(
                token -> Map.of("active", true, "scope", List.of("ssf.manage", "email")));
        assertTrue(auth.authenticate("tok").hasScope("ssf.manage"));
    }

    @Test
    void inactiveTokenIsNotActive() throws Exception {
        ReceiverAuthenticator auth = new PfIntrospectionReceiverAuthenticator(token -> Map.of("active", false));
        AuthContext ctx = auth.authenticate("tok");
        assertFalse(ctx.isActive());
        assertFalse(ctx.hasScope("ssf.manage"));
    }

    @Test
    void missingActiveTreatedAsInactive() throws Exception {
        ReceiverAuthenticator auth = new PfIntrospectionReceiverAuthenticator(token -> Map.of("scope", "ssf.manage"));
        assertFalse(auth.authenticate("tok").isActive());
    }

    @Test
    void transportFailureRaisesReceiverAuthException() {
        ReceiverAuthenticator auth = new PfIntrospectionReceiverAuthenticator(token -> {
            throw new java.io.IOException("connection refused");
        });
        assertThrows(ReceiverAuthException.class, () -> auth.authenticate("tok"));
    }
}
