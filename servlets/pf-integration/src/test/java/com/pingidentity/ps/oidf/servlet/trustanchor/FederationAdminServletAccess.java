/*
 * FederationAdminServlet's package-private init rule, for the tests in other packages.
 */
package com.pingidentity.ps.oidf.servlet.trustanchor;

import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorAuthenticator;

/** Test access to {@link FederationAdminServlet#operatorConfigured}. */
public final class FederationAdminServletAccess {
    private FederationAdminServletAccess() {
    }

    public static boolean operatorConfigured(ComponentParts.Part part, OperatorAuthenticator authenticator) {
        return FederationAdminServlet.operatorConfigured(part, authenticator);
    }
}
