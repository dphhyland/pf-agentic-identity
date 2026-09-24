/*
 * Who is on the other end of the request an event is written for.
 */
package com.pingidentity.ps.oidf.pf;

import jakarta.servlet.http.HttpServletRequest;

/**
 * The host and remote address of the request being handled on this thread, for the {@code host} and
 * {@code ip} columns of PingFederate's security audit log. A servlet or filter calls {@link #enter} as it
 * starts and {@link #exit} in a {@code finally}; events emitted in between carry them. Off a request
 * thread there is nothing, and the columns stay empty.
 */
public final class PfRequestScope {
    /** The request's host (from its {@code Host} header, as PF itself logs it) and the caller's address. */
    public record Context(String host, String remoteAddress) {
    }

    private static final ThreadLocal<Context> CURRENT = new ThreadLocal<>();

    private PfRequestScope() {
    }

    public static void enter(HttpServletRequest request) {
        if (request == null) {
            CURRENT.remove();
            return;
        }
        CURRENT.set(new Context(request.getServerName(), request.getRemoteAddr()));
    }

    public static void exit() {
        CURRENT.remove();
    }

    /** This thread's request context, or {@code null}. */
    public static Context current() {
        return CURRENT.get();
    }
}
