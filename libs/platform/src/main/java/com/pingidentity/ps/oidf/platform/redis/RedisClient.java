/*
 * The platform's Redis client: dependency-free RESP over a bounded pool, TLS verified before AUTH, Sentinel optional.
 */
package com.pingidentity.ps.oidf.platform.redis;

import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.profile.ProfileGuard;
import java.io.Closeable;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;

/**
 * A Redis client speaking just enough RESP for the platform's stores, leases and rate limits, with no third-party
 * jar (plan item C-2; 0.4.0's {@code MiniRedisClient} in client-attestation, moved here with its S3a rules):
 *
 * <ul>
 *   <li><b>TLS.</b> {@code rediss://} verifies the server as a browser does - the chain, to the JVM's CAs or the
 *       {@code OIDF_REDIS_CA_FILE}; the name, by the HTTPS endpoint identification algorithm; the host sent as SNI -
 *       and completes the handshake before {@code AUTH} is written.</li>
 *   <li><b>Plaintext.</b> {@code redis://} is refused under the production profile, through
 *       {@link ProfileGuard#forbidInProduction}: the password in {@code AUTH} would cross the network in the clear.</li>
 *   <li><b>Messages.</b> No message quotes a URL's userinfo.</li>
 *   <li><b>Pool.</b> At most {@link RedisConfig#poolSize()} connections are open at once, in use or idle. A command
 *       waits up to {@link RedisConfig#borrowTimeout()} for one, and then has {@link RedisConfig#commandTimeout()}
 *       for everything else: connecting, the handshake, {@code AUTH} and {@code SELECT}, finding the master, the
 *       command, and the one retry.</li>
 *   <li><b>Retry.</b> A command that fails on a reused connection - which may have gone stale on a server-side idle
 *       timeout - is retried once on a fresh one, as 0.4.0 did. Through Sentinel a lost connection, and a
 *       {@code READONLY} reply (the master has become a replica), also send the next connection to wherever the
 *       sentinels now say the master is, and the command is retried once there.</li>
 * </ul>
 *
 * <p>Failures: a transport failure, a timeout, an exhausted pool and a closed client are {@link IOException}; an
 * error reply is {@link RedisErrorReply}, an {@link IllegalStateException}, and not retried. Nothing connects until
 * the first command.
 */
public final class RedisClient implements Closeable {
    private final RedisUrl url;
    private final SSLContext ssl;
    private final MasterLocator locator;
    private final int poolSize;
    private final long borrowTimeoutNanos;
    private final long commandTimeoutNanos;
    private final Semaphore permits;
    private final ArrayDeque<RedisConnection> idle = new ArrayDeque<>();
    private volatile boolean closed;

    /**
     * @throws IllegalArgumentException for a URL this client does not accept, {@code redis://} under the production
     *                                  profile, or a CA file it cannot use; no message quotes the URL's userinfo
     */
    public RedisClient(RedisConfig config) {
        this.url = RedisUrl.parse(config.url());
        String refusal = transportRefusal(this.url.tls, config.profile());
        if (refusal != null) {
            throw new IllegalArgumentException(refusal);
        }
        this.ssl = this.url.tls ? RedisTls.sslContextFor(config.caFile()) : null;
        this.locator = config.sentinelMaster() == null ? MasterLocator.direct(this.url)
                : MasterLocator.sentinel(this.url, config, this.ssl);
        this.poolSize = config.poolSize();
        this.borrowTimeoutNanos = config.borrowTimeout().toNanos();
        this.commandTimeoutNanos = config.commandTimeout().toNanos();
        this.permits = new Semaphore(this.poolSize, true);
    }

    /**
     * Why a URL's transport is refused, or null when it is allowed: the production profile accepts {@code rediss://}
     * only, because the password in {@code AUTH} would otherwise cross the network in the clear. The decision is
     * {@link ProfileGuard}'s; the words are 0.4.0's.
     */
    static String transportRefusal(boolean tls, DeploymentProfile profile) {
        ProfileGuard.Refusal refusal = ProfileGuard.of(profile, AcceptedRisks.none()).forbidInProduction(RedisConfig.URL_SETTING,
                !tls, "a redis:// URL sends the password in AUTH in the clear");
        if (refusal == null) {
            return null;
        }
        return "the Redis URL is redis:// (plaintext); the production profile accepts rediss:// only, because the"
                + " password in AUTH would otherwise cross the network in the clear. Use rediss://, or set "
                + DeploymentProfile.SETTING + "=development on a rig";
    }

    /** Whether the URL is {@code rediss://}. */
    public boolean tls() {
        return this.url.tls;
    }

    /** Whether the master is found through Sentinel. */
    public boolean sentinel() {
        return this.locator.sentinel();
    }

    /** A view that puts {@code prefix} and a {@code :} before every key it is given. */
    public RedisKeyspace keyspace(String prefix) {
        return new RedisKeyspace(this, prefix);
    }

    /** Executes one command and returns its reply: see {@link RedisConnection} for the mapping. */
    public Object call(String... args) throws IOException {
        if (args.length == 0) {
            throw new IllegalArgumentException("a command has a name");
        }
        if (this.closed) {
            throw new IOException("the Redis client is closed");
        }
        this.borrowPermit();
        try {
            long deadline = System.nanoTime() + this.commandTimeoutNanos;
            RedisConnection connection = this.takeIdle();
            boolean reused = connection != null;
            for (int attempt = 0; ; attempt++) {
                try {
                    if (connection == null) {
                        connection = this.open(deadline);
                    }
                    Object reply = connection.roundTrip(deadline, args);
                    this.giveBack(connection);
                    return reply;
                } catch (RedisErrorReply e) {
                    if (connection == null || !failsOver(e, this.locator.sentinel(), attempt)) {
                        if (connection != null) {
                            this.giveBack(connection);
                        }
                        throw e;
                    }
                    this.masterLost(connection);
                } catch (IOException e) {
                    if (connection != null) {
                        this.masterLost(connection);
                    }
                    if (attempt > 0 || !retries(reused, this.locator.sentinel())) {
                        throw e;
                    }
                }
                connection = null;
            }
        } finally {
            this.permits.release();
        }
    }

    /**
     * Whether an error reply sends the command to the master again: {@code READONLY} through Sentinel, on the first
     * attempt - the server has become a replica, so the sentinels are asked where the master went.
     */
    static boolean failsOver(RedisErrorReply reply, boolean sentinel, int attempt) {
        return sentinel && attempt == 0 && "READONLY".equals(reply.code());
    }

    /**
     * Whether a transport failure is retried on a fresh connection: when the connection was reused and may simply
     * have gone stale, or when the master is found through Sentinel and may have moved.
     */
    static boolean retries(boolean reused, boolean sentinel) {
        return reused || sentinel;
    }

    /** {@code PING}: whether Redis answers {@code PONG}. */
    public boolean ping() throws IOException {
        return "PONG".equals(this.call("PING"));
    }

    /** {@code SET key value PX ttl}: always sets. */
    public boolean set(String key, String value, Duration ttl) throws IOException {
        return "OK".equals(this.call("SET", key, value, "PX", millis(ttl)));
    }

    /** {@code SET key value NX PX ttl}: true only for the caller that set it, when the key was absent. */
    public boolean setIfAbsent(String key, String value, Duration ttl) throws IOException {
        return "OK".equals(this.call("SET", key, value, "NX", "PX", millis(ttl)));
    }

    /** {@code GET key}: the value, or null when there is none. */
    public String get(String key) throws IOException {
        Object reply = this.call("GET", key);
        return reply == null ? null : String.valueOf(reply);
    }

    /** {@code DEL key...}: how many of the keys existed. */
    public long del(String... keys) throws IOException {
        String[] args = new String[keys.length + 1];
        args[0] = "DEL";
        System.arraycopy(keys, 0, args, 1, keys.length);
        return (Long) this.call(args);
    }

    /** {@code INCR key}: the value after the increment (1 for a key that did not exist, which then has no TTL). */
    public long incr(String key) throws IOException {
        return (Long) this.call("INCR", key);
    }

    /** {@code PEXPIRE key ttl}: true when the key exists and now expires after {@code ttl}. */
    public boolean pexpire(String key, Duration ttl) throws IOException {
        return Long.valueOf(1L).equals(this.call("PEXPIRE", key, millis(ttl)));
    }

    /**
     * Runs {@code script} by its digest ({@code EVALSHA}), and by its source ({@code EVAL}) when Redis does not hold
     * it ({@code NOSCRIPT}, after a restart or a {@code SCRIPT FLUSH}); {@code EVAL} also loads it for next time.
     */
    public Object eval(RedisScript script, List<String> keys, List<String> args) throws IOException {
        try {
            return this.call(scriptCommand("EVALSHA", script.sha1(), keys, args));
        } catch (RedisErrorReply e) {
            if (!"NOSCRIPT".equals(e.code())) {
                throw e;
            }
            return this.call(scriptCommand("EVAL", script.source(), keys, args));
        }
    }

    static String[] scriptCommand(String command, String script, List<String> keys, List<String> args) {
        List<String> all = new ArrayList<>(3 + keys.size() + args.size());
        all.add(command);
        all.add(script);
        all.add(Integer.toString(keys.size()));
        all.addAll(keys);
        all.addAll(args);
        return all.toArray(new String[0]);
    }

    /** Deletes {@code key} only while it still holds {@code expected}: a lease released by its holder and no other. */
    public boolean compareAndDelete(String key, String expected) throws IOException {
        return Long.valueOf(1L).equals(this.eval(RedisScript.COMPARE_AND_DELETE, List.of(key), List.of(expected)));
    }

    /** Sets {@code key}'s TTL to {@code ttl} only while it still holds {@code expected}: a lease renewed by its holder. */
    public boolean compareAndExtend(String key, String expected, Duration ttl) throws IOException {
        return Long.valueOf(1L).equals(this.eval(RedisScript.COMPARE_AND_EXTEND, List.of(key), List.of(expected, millis(ttl))));
    }

    /**
     * Counts one more hit in {@code key}'s fixed window of {@code window}, which starts at the window's first hit: the
     * count so far, this one included, and how long the window has left. Atomic, so a counter never lives without a
     * TTL, whatever fails between the increment and the expiry.
     */
    public WindowCount countInWindow(String key, Duration window) throws IOException {
        return WindowCount.of(this.eval(RedisScript.FIXED_WINDOW, List.of(key), List.of(millis(window))));
    }

    static String millis(Duration ttl) {
        Objects.requireNonNull(ttl, "ttl");
        long ms = ttl.toMillis();
        if (ms <= 0L) {
            throw new IllegalArgumentException("a TTL is at least a millisecond, not " + ttl);
        }
        return Long.toString(ms);
    }

    private void borrowPermit() throws IOException {
        boolean got;
        try {
            got = this.permits.tryAcquire(this.borrowTimeoutNanos, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted waiting for a Redis connection");
        }
        if (!got) {
            throw new IOException("no Redis connection came free within " + TimeUnit.NANOSECONDS.toMillis(this.borrowTimeoutNanos)
                    + " ms (" + RedisConfig.POOL_SIZE_SETTING + " is " + this.poolSize + ")");
        }
    }

    /** An idle connection to the current master, or null; one to an older master is closed on the way. */
    private RedisConnection takeIdle() {
        synchronized (this.idle) {
            RedisConnection connection;
            while ((connection = this.idle.pollFirst()) != null) {
                if (connection.generation == this.locator.generation()) {
                    return connection;
                }
                connection.close();
            }
            return null;
        }
    }

    private void giveBack(RedisConnection connection) {
        synchronized (this.idle) {
            if (!this.closed && connection.generation == this.locator.generation()) {
                this.idle.addFirst(connection);
                return;
            }
        }
        connection.close();
    }

    /** Closes a connection that failed, and through Sentinel forgets its master and every idle connection to it. */
    private void masterLost(RedisConnection connection) {
        connection.close();
        if (this.locator.sentinel()) {
            this.locator.lost(connection.generation);
            this.closeIdle();
        }
    }

    /** A new connection to the master, authenticated and on its database, by {@code deadline}. */
    private RedisConnection open(long deadline) throws IOException {
        MasterLocator.Endpoint master = this.locator.master(deadline);
        RedisConnection connection;
        try {
            connection = RedisConnection.open(master.host(), master.port(), this.ssl, master.tlsName(), deadline, master.generation());
        } catch (IOException e) {
            this.locator.lost(master.generation());
            throw e;
        }
        try {
            if (this.url.authenticates()) {
                if (this.url.username != null) {
                    connection.roundTrip(deadline, "AUTH", this.url.username, this.url.password);
                } else {
                    connection.roundTrip(deadline, "AUTH", this.url.password);
                }
            }
            if (this.url.db > 0) {
                connection.roundTrip(deadline, "SELECT", Integer.toString(this.url.db));
            }
            if (this.locator.sentinel()) {
                requireMaster(connection.roundTrip(deadline, "ROLE"));
            }
            return connection;
        } catch (IOException | RuntimeException e) {
            connection.close();
            if (e instanceof IOException) {
                this.locator.lost(master.generation());
            }
            throw e;
        }
    }

    /** A {@code ROLE} reply that is not a master's: the sentinels' answer is out of date. */
    static void requireMaster(Object role) throws IOException {
        if (!(role instanceof List<?> list) || list.isEmpty() || !"master".equals(list.get(0))) {
            Object named = role instanceof List<?> list && !list.isEmpty() ? list.get(0) : role;
            throw new IOException("the server the sentinels named is not the master (ROLE says " + named + ")");
        }
    }

    private void closeIdle() {
        synchronized (this.idle) {
            RedisConnection connection;
            while ((connection = this.idle.pollFirst()) != null) {
                connection.close();
            }
        }
    }

    /** Closes the idle connections; one in use is closed when its command ends. Later commands fail. */
    @Override
    public void close() {
        this.closed = true;
        this.closeIdle();
    }
}
