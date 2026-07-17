package au.com.idpartners.gm.servlet;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * The servlet is mapped at /grants/*, so the container strips the context path and the
 * servlet path before pathInfo. Getting this wrong returns 404 for every well-formed
 * request, which looks exactly like a deployment problem.
 *
 * <p>Query and revoke take /{id}; evaluate takes /{id}/evaluate. The two must not accept
 * each other's shape, or a DELETE could land on an evaluate path.
 */
class PathTest {

    @Test
    void readsTheGrantIdFromPathInfo() {
        // GET /gm-api/grants/abc123/evaluate  ->  pathInfo "/abc123/evaluate"
        assertEquals("abc123", GrantsServlet.evaluateGrantIdFrom("/abc123/evaluate"));
    }

    @Test
    void readsTheGrantIdForQueryAndRevoke() {
        // GET/DELETE /gm-api/grants/abc123  ->  pathInfo "/abc123"
        assertEquals("abc123", GrantsServlet.grantIdFrom("/abc123"));
    }

    @Test
    void queryAndEvaluatePathsDoNotOverlap() {
        assertNull(GrantsServlet.grantIdFrom("/abc123/evaluate"),
                "an evaluate path must not be read as a bare grant id");
        assertNull(GrantsServlet.evaluateGrantIdFrom("/abc123"),
                "a bare grant id must not be read as an evaluate path");
    }

    @Test
    void rejectsAnythingElse() {
        assertNull(GrantsServlet.evaluateGrantIdFrom(null));
        assertNull(GrantsServlet.evaluateGrantIdFrom("/abc123"), "no action segment");
        assertNull(GrantsServlet.evaluateGrantIdFrom("/abc123/revoke"), "wrong action");
        assertNull(GrantsServlet.evaluateGrantIdFrom("//evaluate"), "no grant id");
        assertNull(GrantsServlet.evaluateGrantIdFrom("/grants/abc123/evaluate"),
                "the servlet path is already consumed; this shape means the mapping changed");
    }
}
