/*
 * Where the master is: the URL's host, or wherever the sentinels say.
 */
package com.pingidentity.ps.oidf.platform.redis;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import javax.net.ssl.SSLContext;

/**
 * Finds the Redis master a client sends its commands to. Directly, it is the URL's host and port, always. Through
 * Sentinel it is what {@code SENTINEL get-master-addr-by-name} answers, asked of each sentinel in turn, each within
 * its share of the command's deadline, until one names it, and remembered until a connection to it is lost or it answers {@code READONLY} - a failover - when the
 * next command asks again.
 *
 * <p>Losing the master starts a new generation, so every connection opened to the old one - idle, or in use and
 * handed back later - is closed rather than reused ({@link RedisClient} compares a connection's generation with the
 * current one).
 */
abstract class MasterLocator {

    /** Where to connect, and the name its TLS certificate must carry. */
    record Endpoint(String host, int port, String tlsName, long generation) {
    }

    /** The master, finding it first if need be, by {@code deadline}. */
    abstract Endpoint master(long deadline) throws IOException;

    /**
     * The master of {@code generation} is gone: when that is the current generation, a new one starts and the next
     * {@link #master} finds the master again; a loss reported for an older generation changes nothing.
     */
    abstract void lost(long generation);

    /** The current generation. */
    abstract long generation();

    /** Whether the master is found through Sentinel, and must say it is a master ({@code ROLE}) when connected. */
    abstract boolean sentinel();

    static MasterLocator direct(RedisUrl url) {
        return new Direct(new Endpoint(url.host, url.port, url.host, 0L));
    }

    static MasterLocator sentinel(RedisUrl url, RedisConfig config, SSLContext ssl) {
        return new Sentinel(url, config.sentinelMaster(), config.sentinels(), config.sentinelPassword(), ssl);
    }

    /** The URL's host, which never moves. */
    static final class Direct extends MasterLocator {
        private final Endpoint endpoint;

        Direct(Endpoint endpoint) {
            this.endpoint = endpoint;
        }

        @Override
        Endpoint master(long deadline) {
            return this.endpoint;
        }

        @Override
        void lost(long generation) {
            // a directly dialled host is the same host next time
        }

        @Override
        long generation() {
            return 0L;
        }

        @Override
        boolean sentinel() {
            return false;
        }
    }

    /**
     * The master the sentinels name. TLS and the CA file apply to the sentinels as to the master, each sentinel
     * verified against its own host. The master is verified against the name a sentinel gave for it, or - when it
     * gave an address, which is what Sentinel reports unless {@code announce-hostnames} is on - against the URL's
     * host, so every master's certificate must then carry that one name.
     *
     * <p>Each sentinel gets its share of what is left of the deadline ({@link #share}), so one that accepts and
     * never answers, or whose host drops packets, leaves time for the next; the sentinel that answered is asked
     * first next time. One thread asks at a time; the others wait for its answer, each only until its own deadline.
     */
    static final class Sentinel extends MasterLocator {
        private final RedisUrl url;
        private final String master;
        /** The order to ask the sentinels in, the last to answer first; under {@link #resolving}. */
        private final List<RedisConfig.HostPort> sentinels;
        private final String password;
        private final SSLContext ssl;
        private final ReentrantLock resolving = new ReentrantLock();
        private volatile Endpoint current;
        private volatile long generation;

        Sentinel(RedisUrl url, String master, List<RedisConfig.HostPort> sentinels, String password, SSLContext ssl) {
            this.url = url;
            this.master = master;
            this.sentinels = new ArrayList<>(sentinels);
            this.password = password;
            this.ssl = ssl;
        }

        @Override
        Endpoint master(long deadline) throws IOException {
            Endpoint known = this.current;
            if (known != null) {
                return known;
            }
            boolean locked;
            try {
                locked = this.resolving.tryLock(deadline - System.nanoTime(), TimeUnit.NANOSECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new InterruptedIOException("interrupted waiting for the sentinels to name the master");
            }
            if (!locked) {
                throw new SocketTimeoutException("Redis command deadline passed while the sentinels were being asked"
                        + " for the master " + this.master);
            }
            try {
                known = this.current;
                return known != null ? known : this.resolve(deadline);
            } finally {
                this.resolving.unlock();
            }
        }

        /** Asks the sentinels in turn, each within its share of the deadline, until one names the master. */
        private Endpoint resolve(long deadline) throws IOException {
            List<RedisConfig.HostPort> asked = new ArrayList<>();
            IOException last = null;
            for (int i = 0; i < this.sentinels.size(); i++) {
                long now = System.nanoTime();
                if (deadline - now <= 0L) {
                    break;
                }
                RedisConfig.HostPort sentinel = this.sentinels.get(i);
                asked.add(sentinel);
                try {
                    List<?> address = this.ask(sentinel, share(now, deadline, this.sentinels.size() - i));
                    if (address == null) {
                        last = new IOException("sentinel " + sentinel + " does not know a master named " + this.master);
                        continue;
                    }
                    String host = String.valueOf(address.get(0));
                    int port = (int) RedisConnection.number(String.valueOf(address.get(1)), 1, 65535);
                    this.sentinels.remove(i);
                    this.sentinels.add(0, sentinel);
                    synchronized (this) {
                        this.current = new Endpoint(host, port, RedisTls.isIpLiteral(host) ? this.url.host : host,
                                this.generation);
                        return this.current;
                    }
                } catch (IOException | RuntimeException e) {
                    last = e instanceof IOException ? (IOException) e : new IOException("sentinel " + sentinel + ": " + e.getMessage(), e);
                }
            }
            if (last == null) {
                throw new SocketTimeoutException("Redis command deadline passed before a sentinel could be asked for the"
                        + " master " + this.master);
            }
            throw new IOException("no sentinel named the master " + this.master + " (asked " + asked + " of "
                    + this.sentinels.size() + "): " + last.getMessage(), last);
        }

        /**
         * The deadline for one sentinel of {@code left} still to ask: an equal share of what remains, so a sentinel
         * that never answers costs the command at most that share, and the last one asked gets all that is left.
         */
        static long share(long now, long deadline, int left) {
            return now + (deadline - now) / Math.max(1, left);
        }

        /** One sentinel's answer: the master's {@code [host, port]}, or null when it knows no master of that name. */
        private List<?> ask(RedisConfig.HostPort sentinel, long deadline) throws IOException {
            RedisConnection connection = RedisConnection.open(sentinel.host(), sentinel.port(), this.ssl, sentinel.host(),
                    deadline, 0L);
            try {
                if (this.password != null) {
                    connection.roundTrip(deadline, "AUTH", this.password);
                }
                Object reply = connection.roundTrip(deadline, "SENTINEL", "get-master-addr-by-name", this.master);
                if (reply == null) {
                    return null;
                }
                if (!(reply instanceof List<?> list) || list.size() != 2) {
                    throw new IOException("sentinel " + sentinel + " answered get-master-addr-by-name with something other"
                            + " than a host and a port");
                }
                return list;
            } finally {
                connection.close();
            }
        }

        @Override
        synchronized void lost(long generation) {
            if (generation == this.generation) {
                this.current = null;
                this.generation = generation + 1;
            }
        }

        @Override
        long generation() {
            return this.generation;
        }

        @Override
        boolean sentinel() {
            return true;
        }
    }
}
