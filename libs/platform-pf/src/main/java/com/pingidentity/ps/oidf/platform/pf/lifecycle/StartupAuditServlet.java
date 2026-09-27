/*
 * A servlet with no mapping, whose init runs the start-up audit after the war's other load-on-startup inits.
 */
package com.pingidentity.ps.oidf.platform.pf.lifecycle;

import jakarta.servlet.GenericServlet;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Added by {@link LifecycleListener} with the highest load-on-startup and no mapping. The container initialises
 * filters before servlets, and load-on-startup servlets in ascending order, so this {@code init} runs once the war's
 * filters and other load-on-startup servlets have registered their components; it runs the audit and does nothing
 * else. Nothing maps a request to it; if something ever did, it answers 404.
 */
final class StartupAuditServlet extends GenericServlet {

    private static final long serialVersionUID = 1L;

    private final transient Runnable audit;

    StartupAuditServlet(Runnable audit) {
        this.audit = audit;
    }

    @Override
    public void init() {
        this.audit.run();
    }

    @Override
    public void service(ServletRequest request, ServletResponse response) throws ServletException, IOException {
        if (response instanceof HttpServletResponse http) {
            http.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
    }
}
