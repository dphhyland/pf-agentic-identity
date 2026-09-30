/*
 * The seam a per-host bulkhead plugs into.
 */
package com.pingidentity.ps.oidf.platform.http;

/**
 * Limits how many requests to one origin run at once, so one slow peer cannot hold every thread that fetches.
 * {@link OutboundHttp} asks for a permit after the address policy passes and before it connects, and closes the
 * permit when the exchange ends, however it ends. {@link #NONE} lets everything in; plan item S5a's second part
 * (S5AR) supplies the per-host one.
 */
@FunctionalInterface
public interface Bulkhead {

    /** Lets every request in at once. */
    Bulkhead NONE = (origin, deadline) -> Permit.NONE;

    /**
     * A permit for one request to {@code origin} ({@code scheme://host:port}, the port always written).
     *
     * @throws OutboundHttpException with {@link OutboundHttpException.Reason#BULKHEAD_FULL} when none frees up before
     *     {@code deadline}
     */
    Permit enter(String origin, Deadline deadline) throws OutboundHttpException;

    /** A held place, given back by {@link #close}. */
    @FunctionalInterface
    interface Permit extends AutoCloseable {
        /** A permit that holds nothing. */
        Permit NONE = () -> { };

        @Override
        void close();
    }
}
