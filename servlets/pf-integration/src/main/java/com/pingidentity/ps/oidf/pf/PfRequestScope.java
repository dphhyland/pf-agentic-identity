/*
 * Who is on the other end of the request an event is written for.
 */
package com.pingidentity.ps.oidf.pf;

import jakarta.servlet.http.HttpServletRequest;

/**
 * The remote address of the request being handled on this thread, for the {@code ip} column of PingFederate's security
 * audit log. Every servlet and filter that emits events {@linkplain #enter enters} a scope as it starts and
 * {@linkplain #exit exits} it in a {@code finally}; events emitted in between carry the address. Off a request thread
 * there is nothing, and the column stays empty.
 *
 * <p>The address is {@code getRemoteAddr()}, which is what PingFederate records for its own events. Its runtime
 * connector has already put the client's address there when PingFederate is set to read it from a forwarded header.
 * The {@code host} column is not taken from the request: PingFederate fills it with this node's name, for its own
 * records and for these.
 *
 * <p>Scopes nest. A filter's scope is set aside while a later filter, the servlet or the OGNL criterion on the same
 * thread has one of its own, and is back when that one exits. The OGNL criterion's copy of this class is the engine
 * classloader's, not the web app's, so it enters its own: the filter's is not visible to it.
 */
public final class PfRequestScope {
    /** The caller's address, as PingFederate's servlet container gives it. */
    public record Context(String remoteAddress) {
    }

    private static final ThreadLocal<Context> CURRENT = new ThreadLocal<>();

    private PfRequestScope() {
    }

    /**
     * Makes {@code request} this thread's request and returns the scope it set aside, for {@link #exit} to put back. A
     * null request, from a caller that has none, keeps whatever scope is already open.
     */
    public static Context enter(HttpServletRequest request) {
        Context outer = CURRENT.get();
        if (request != null) {
            CURRENT.set(new Context(request.getRemoteAddr()));
        }
        return outer;
    }

    /**
     * Leaves the scope {@link #enter} opened, putting back {@code outer} - what that call returned. Call it in a
     * {@code finally}: a pooled thread must not carry one request's address into the next.
     */
    public static void exit(Context outer) {
        if (outer == null) {
            CURRENT.remove();
        } else {
            CURRENT.set(outer);
        }
    }

    /** This thread's request context, or {@code null}. */
    public static Context current() {
        return CURRENT.get();
    }
}
