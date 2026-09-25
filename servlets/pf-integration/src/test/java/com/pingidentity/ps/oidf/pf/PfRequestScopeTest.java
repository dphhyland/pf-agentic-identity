package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Whose request an audit record names: the scope a servlet, filter or OGNL criterion opens holds the caller's address
 * until it is left, an inner scope puts the outer one back, and nothing outlives the request on a pooled thread.
 */
class PfRequestScopeTest {

    @AfterEach
    void leaveNothingBehind() {
        PfRequestScope.exit(null);
    }

    private static HttpServletRequest from(String address) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn(address);
        return request;
    }

    @Test
    void aRequestsAddressIsCurrentUntilItsScopeIsLeft() {
        assertNull(PfRequestScope.current());

        PfRequestScope.Context outer = PfRequestScope.enter(from("203.0.113.9"));

        assertNull(outer, "nothing was open before");
        assertEquals("203.0.113.9", PfRequestScope.current().remoteAddress());
        PfRequestScope.exit(outer);
        assertNull(PfRequestScope.current());
    }

    @Test
    void anInnerScopePutsTheOuterOneBackWhenItIsLeft() {
        PfRequestScope.Context none = PfRequestScope.enter(from("203.0.113.9"));
        PfRequestScope.Context filters = PfRequestScope.current();

        PfRequestScope.Context outer = PfRequestScope.enter(from("198.51.100.4"));
        assertEquals("198.51.100.4", PfRequestScope.current().remoteAddress(), "the inner request's own address, while it runs");
        PfRequestScope.exit(outer);

        assertSame(filters, PfRequestScope.current(), "leaving the inner scope must not leave the filter's events without an address");
        PfRequestScope.exit(none);
        assertNull(PfRequestScope.current());
    }

    @Test
    void aCallerWithNoRequestKeepsTheScopeThatIsOpen() {
        PfRequestScope.Context none = PfRequestScope.enter(from("203.0.113.9"));
        PfRequestScope.Context open = PfRequestScope.current();

        PfRequestScope.Context outer = PfRequestScope.enter(null);
        assertSame(open, outer);
        assertSame(open, PfRequestScope.current());
        PfRequestScope.exit(outer);
        assertSame(open, PfRequestScope.current());

        PfRequestScope.exit(none);
        assertNull(PfRequestScope.enter(null));
        assertNull(PfRequestScope.current(), "no request and nothing open: still nothing");
    }

    @Test
    void aScopeIsThisThreadsAlone() throws Exception {
        PfRequestScope.Context outer = PfRequestScope.enter(from("203.0.113.9"));
        AtomicReference<PfRequestScope.Context> elsewhere = new AtomicReference<>(new PfRequestScope.Context("unset"));

        Thread other = new Thread(() -> elsewhere.set(PfRequestScope.current()));
        other.start();
        other.join();

        assertNull(elsewhere.get());
        PfRequestScope.exit(outer);
    }

    @Test
    void thePooledThreadsNextRequestStartsWithNoAddress() throws Exception {
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            AtomicReference<PfRequestScope.Context> during = new AtomicReference<>();
            pool.submit(() -> {
                PfRequestScope.Context outer = PfRequestScope.enter(from("203.0.113.9"));
                try {
                    during.set(PfRequestScope.current());
                } finally {
                    PfRequestScope.exit(outer);
                }
            }).get();
            AtomicReference<PfRequestScope.Context> next = new AtomicReference<>(new PfRequestScope.Context("unset"));
            pool.submit(() -> next.set(PfRequestScope.current())).get();

            assertEquals("203.0.113.9", during.get().remoteAddress());
            assertNull(next.get(), "the thread's next request must not be put down to the last one's caller");
        } finally {
            pool.shutdown();
            pool.awaitTermination(5, TimeUnit.SECONDS);
        }
    }
}
