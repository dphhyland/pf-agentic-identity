/*
 * Lets the ssf package's SCIM tests drive the servlet past authentication.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.ssf.AuthContext;
import com.pingidentity.ps.oidf.ssf.ScimSubjectService;
import java.io.IOException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/** {@link SsfScimSubjectServlet#handle}, which is package-private, for a test in another package. */
public final class SsfScimSubjectServletAccess {

    private SsfScimSubjectServletAccess() {
    }

    public static void handle(HttpServletRequest req, HttpServletResponse resp, ScimSubjectService svc, AuthContext auth)
            throws IOException {
        SsfScimSubjectServlet.handle(req, resp, svc, auth);
    }
}
