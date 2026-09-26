/*
 * A servlet that serves every request inside a PfRequestScope.
 */
package com.pingidentity.ps.oidf.pf;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * An {@link HttpServlet} that serves every request inside a {@link PfRequestScope}, so the events it raises reach
 * PingFederate's audit log with the caller's address. The scope is entered where {@code doGet}, {@code doPost} and the
 * rest are dispatched from, so no method is left out, and exited in a {@code finally}, so no pooled thread keeps it.
 */
public abstract class RequestScopedServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        PfRequestScope.Context outer = PfRequestScope.enter(req);
        try {
            super.service(req, resp);
        } finally {
            PfRequestScope.exit(outer);
        }
    }
}
