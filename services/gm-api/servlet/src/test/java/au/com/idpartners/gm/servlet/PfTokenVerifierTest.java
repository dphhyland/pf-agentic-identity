package au.com.idpartners.gm.servlet;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The audience guard is the one thing standing between "a token this PingFederate signed"
 * and "a token this API accepts" — see the class-level Javadoc on {@link PfTokenVerifier}.
 * It used to be a logged warning, which meant a deployment that unset {@code audience} (or
 * never set it) accepted any token this server ever signed, including one minted for a
 * completely different API, and nothing short of reading the log would show it. It is now a
 * construction-time failure instead: a misconfigured deployment does not start.
 *
 * <p>{@link PfTokenVerifier#verify} needs a real {@code JwksEndpointKeyAccessor}, which is a
 * PF SDK final class that reaches into the server's service locator — untestable outside a
 * running PingFederate, and this module carries no mocking library (it is the one vendored,
 * non-BOM module in the repo). What is tested here is everything reachable without one: the
 * constructor's audience guard, and the token-presence check in {@code verify}, which returns
 * before the key accessor is ever touched.
 */
class PfTokenVerifierTest {

    @Test
    void refusesToConstructWithNoAudience() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new PfTokenVerifier((com.pingidentity.access.JwksEndpointKeyAccessor) null, null));
        assertTrue(e.getMessage().contains("audience"), e.getMessage());
    }

    @Test
    void refusesToConstructWithABlankAudience() {
        assertThrows(IllegalArgumentException.class,
                () -> new PfTokenVerifier((com.pingidentity.access.JwksEndpointKeyAccessor) null, "   "));
    }

    @Test
    void refusesToConstructWithAnEmptyAudience() {
        assertThrows(IllegalArgumentException.class,
                () -> new PfTokenVerifier((com.pingidentity.access.JwksEndpointKeyAccessor) null, ""));
    }

    @Test
    void constructsWithAWellFormedAudience() {
        // Nothing beyond the guard is exercised: the key accessor is null, and verify() is
        // not called here, so this only pins that a real audience does not itself throw.
        assertDoesNotThrow(() -> new PfTokenVerifier(
                (com.pingidentity.access.JwksEndpointKeyAccessor) null, "https://gm-api.example.com"));
    }

    @Test
    void aMissingTokenIsRejectedBeforeTheKeyAccessorIsEverTouched() throws Exception {
        // keys is null here; if verify() read it before checking the token is present, this
        // would NPE instead of reporting "no token presented".
        PfTokenVerifier verifier = new PfTokenVerifier(
                (com.pingidentity.access.JwksEndpointKeyAccessor) null, "https://gm-api.example.com");

        PfTokenVerifier.InvalidTokenException e1 = assertThrows(
                PfTokenVerifier.InvalidTokenException.class, () -> verifier.verify(null));
        assertTrue(e1.getMessage().contains("no token presented"), e1.getMessage());

        PfTokenVerifier.InvalidTokenException e2 = assertThrows(
                PfTokenVerifier.InvalidTokenException.class, () -> verifier.verify("  "));
        assertTrue(e2.getMessage().contains("no token presented"), e2.getMessage());
    }
}
