/*
 * The SSF receiver's and introspection's insecure-TLS switches through InsecureTls: any chain, but still the
 * host dialled.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class InsecureTlsSitesTest {

    private static final String BODY = "{\"keys\":[],\"active\":false,\"sets\":{}}";

    @TempDir
    static Path dir;
    private static SelfSignedTlsServer rightName;
    private static SelfSignedTlsServer wrongName;

    @BeforeAll
    static void start() throws Exception {
        rightName = new SelfSignedTlsServer(dir, "localhost", 200, BODY);
        wrongName = new SelfSignedTlsServer(dir, "wrong.example", 200, BODY);
    }

    @AfterAll
    static void stop() {
        rightName.close();
        wrongName.close();
    }

    @Test
    void theSetVerifiersJwksFetch() throws Exception {
        assertEquals(List.of(), SetVerifier.httpJwksSource(rightName.url("/jwks"), 60, true).keys(true));
        assertTrue(SelfSignedTlsServer.isWrongName(assertThrows(Exception.class,
                () -> SetVerifier.httpJwksSource(wrongName.url("/jwks"), 60, true).keys(true))));
        assertFalse(SelfSignedTlsServer.isWrongName(assertThrows(Exception.class,
                () -> SetVerifier.httpJwksSource(rightName.url("/jwks"), 60, false).keys(true))), "off: the chain is checked");
    }

    @Test
    void thePollReceiversTransport() throws Exception {
        assertEquals(BODY, PollReceiverClient.httpTransport(rightName.url("/poll"), "t", true).poll("{}"));
        assertTrue(SelfSignedTlsServer.isWrongName(assertThrows(Exception.class,
                () -> PollReceiverClient.httpTransport(wrongName.url("/poll"), "t", true).poll("{}"))));
        assertFalse(SelfSignedTlsServer.isWrongName(assertThrows(Exception.class,
                () -> PollReceiverClient.httpTransport(rightName.url("/poll"), "t", false).poll("{}"))));
    }

    @Test
    void theReceiversStreamManagementTransport() throws Exception {
        assertEquals(BODY, ReceiverStreamClient.httpTransport("t", true).call("GET", rightName.url("/ssf/streams"), null));
        assertTrue(SelfSignedTlsServer.isWrongName(assertThrows(Exception.class,
                () -> ReceiverStreamClient.httpTransport("t", true).call("GET", wrongName.url("/ssf/streams"), null))));
        assertFalse(SelfSignedTlsServer.isWrongName(assertThrows(Exception.class,
                () -> ReceiverStreamClient.httpTransport("t", false).call("GET", rightName.url("/ssf/streams"), null))));
    }

    @Test
    void theIntrospectionCall() throws Exception {
        assertFalse(PfIntrospectionReceiverAuthenticator.forEndpoint(rightName.url("/as/introspect.oauth2"), "id", "secret", true)
                .authenticate("token").isActive());
        assertTrue(SelfSignedTlsServer.isWrongName(assertThrows(ReceiverAuthException.class,
                () -> PfIntrospectionReceiverAuthenticator.forEndpoint(wrongName.url("/as/introspect.oauth2"), "id", "secret", true)
                        .authenticate("token"))));
        assertFalse(SelfSignedTlsServer.isWrongName(assertThrows(ReceiverAuthException.class,
                () -> PfIntrospectionReceiverAuthenticator.forEndpoint(rightName.url("/as/introspect.oauth2"), "id", "secret", false)
                        .authenticate("token"))));
    }

    @Test
    void theSettingsAreNamedAsAnOperatorSetsThem() {
        assertEquals("OIDF_SSF_RECEIVER_INSECURE_TLS", PollReceiverClient.RECEIVER_INSECURE_TLS);
        assertEquals("OIDF_SSF_INTROSPECTION_INSECURE_TLS", PfIntrospectionReceiverAuthenticator.INTROSPECTION_INSECURE_TLS);
    }
}
