package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import org.junit.jupiter.api.Test;

/** {@link HostedEntityServlet#parseIdSegment(String)} — the routing logic, tested without a servlet container. */
class HostedEntityServletTest {

    @Test
    void wellFormedPathYieldsTheIdSegment() {
        assertEquals(Optional.of("kQ3n7RZ2sK1p"),
                HostedEntityServlet.parseIdSegment("/kQ3n7RZ2sK1p/.well-known/openid-federation"));
    }

    @Test
    void nullPathIsRejected() {
        assertTrue(HostedEntityServlet.parseIdSegment(null).isEmpty());
    }

    @Test
    void pathMissingTheWellKnownSuffixIsRejected() {
        assertTrue(HostedEntityServlet.parseIdSegment("/kQ3n7RZ2sK1p").isEmpty());
        assertTrue(HostedEntityServlet.parseIdSegment("/kQ3n7RZ2sK1p/something-else").isEmpty());
    }

    @Test
    void blankIdIsRejected() {
        assertTrue(HostedEntityServlet.parseIdSegment("/.well-known/openid-federation").isEmpty());
    }

    @Test
    void anIdContainingASlashIsRejected() {
        // Would otherwise let a caller smuggle an unexpected path segment (e.g. path traversal, or a
        // second /.well-known/openid-federation) into what becomes part of the looked-up entity id.
        assertTrue(HostedEntityServlet.parseIdSegment("/a/b/.well-known/openid-federation").isEmpty());
    }

    @Test
    void pathNotStartingWithSlashIsRejected() {
        assertTrue(HostedEntityServlet.parseIdSegment("kQ3n7RZ2sK1p/.well-known/openid-federation").isEmpty());
    }

    // ---- HostedEntityServlet.isAuthorized ----------------------------------------------------------

    @Test
    void correctBearerTokenIsAuthorized() {
        assertTrue(HostedEntityServlet.isAuthorized("secret-token", "Bearer secret-token"));
    }

    @Test
    void bearerSchemeMatchIsCaseInsensitive() {
        assertTrue(HostedEntityServlet.isAuthorized("secret-token", "bearer secret-token"));
    }

    @Test
    void wrongTokenIsRejected() {
        assertFalse(HostedEntityServlet.isAuthorized("secret-token", "Bearer wrong-token"));
    }

    @Test
    void missingHeaderIsRejected() {
        assertFalse(HostedEntityServlet.isAuthorized("secret-token", null));
    }

    @Test
    void nonBearerSchemeIsRejected() {
        assertFalse(HostedEntityServlet.isAuthorized("secret-token", "Basic c2VjcmV0LXRva2Vu"));
    }

    @Test
    void noAdminTokenConfiguredMeansEverythingIsRejected() {
        // Never fail open: an unconfigured admin token must refuse every request, not accept any bearer.
        assertFalse(HostedEntityServlet.isAuthorized(null, "Bearer anything"));
        assertFalse(HostedEntityServlet.isAuthorized(null, null));
    }
}
