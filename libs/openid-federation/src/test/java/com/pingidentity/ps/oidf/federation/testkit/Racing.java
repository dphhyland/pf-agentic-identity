/*
 * Data sources that make two transactions overlap, or count what a caller asks of the database.
 */
package com.pingidentity.ps.oidf.federation.testkit;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;

/**
 * Test data sources over a real one.
 *
 * <p>{@link #meetingAt} holds the first two statements prepared with a given SQL prefix until both are waiting, so two
 * transactions have each read what they are about to change before either writes: the race a conditional update must
 * settle. {@link #counting} counts every statement prepared or created, so a test can hold a read to one query.
 */
public final class Racing {
    private Racing() {
    }

    /** {@code delegate}, but the first two statements whose SQL starts with {@code sqlPrefix} wait for each other. */
    public static DataSource meetingAt(DataSource delegate, String sqlPrefix) {
        CyclicBarrier barrier = new CyclicBarrier(2);
        AtomicInteger arrivals = new AtomicInteger();
        return wrap(delegate, sql -> {
            if (sql.startsWith(sqlPrefix) && arrivals.incrementAndGet() <= 2) {
                barrier.await(20, TimeUnit.SECONDS);
            }
        });
    }

    /** A data source that counts the statements asked of it. */
    public static final class Counting {
        private final AtomicInteger statements = new AtomicInteger();
        private final List<String> sql = new ArrayList<>();
        private final DataSource dataSource;

        private Counting(DataSource delegate) {
            this.dataSource = wrap(delegate, s -> {
                this.statements.incrementAndGet();
                synchronized (this.sql) {
                    this.sql.add(s);
                }
            });
        }

        public DataSource dataSource() {
            return this.dataSource;
        }

        public int statements() {
            return this.statements.get();
        }

        public List<String> sql() {
            synchronized (this.sql) {
                return List.copyOf(this.sql);
            }
        }

        public void reset() {
            this.statements.set(0);
            synchronized (this.sql) {
                this.sql.clear();
            }
        }
    }

    public static Counting counting(DataSource delegate) {
        return new Counting(delegate);
    }

    /**
     * Runs both at once and returns what each did: its result, or the exception it threw.
     */
    public static List<Object> together(Callable<?> first, Callable<?> second) throws InterruptedException {
        List<Object> outcomes = new ArrayList<>(List.of("pending", "pending"));
        Thread a = new Thread(() -> outcomes.set(0, outcome(first)));
        Thread b = new Thread(() -> outcomes.set(1, outcome(second)));
        a.start();
        b.start();
        a.join(30_000);
        b.join(30_000);
        return outcomes;
    }

    private static Object outcome(Callable<?> call) {
        try {
            Object result = call.call();
            return result == null ? "done" : result;
        } catch (Exception e) {
            return e;
        }
    }

    @FunctionalInterface
    private interface OnStatement {
        void seen(String sql) throws Exception;
    }

    private static DataSource wrap(DataSource delegate, OnStatement onStatement) {
        InvocationHandler dataSource = (proxy, method, args) -> {
            Object result = invoke(delegate, method, args);
            return result instanceof Connection c ? connection(c, onStatement) : result;
        };
        return (DataSource) Proxy.newProxyInstance(Racing.class.getClassLoader(), new Class<?>[]{DataSource.class}, dataSource);
    }

    private static Connection connection(Connection delegate, OnStatement onStatement) {
        InvocationHandler handler = (proxy, method, args) -> {
            String name = method.getName();
            if (("prepareStatement".equals(name) || "prepareCall".equals(name)) && args != null && args[0] instanceof String sql) {
                onStatement.seen(sql.trim());
            } else if ("createStatement".equals(name)) {
                onStatement.seen("");
            }
            return invoke(delegate, method, args);
        };
        return (Connection) Proxy.newProxyInstance(Racing.class.getClassLoader(), new Class<?>[]{Connection.class}, handler);
    }

    private static Object invoke(Object target, Method method, Object[] args) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }
}
