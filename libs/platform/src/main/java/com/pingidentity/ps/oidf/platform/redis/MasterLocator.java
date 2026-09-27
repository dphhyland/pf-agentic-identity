/*
 * Where the master is: the URL's host, or wherever the sentinels say.
 */
package com.pingidentity.ps.oidf.platform.redis;

import java.io.IOException;
import java.util.List;
import javax.net.ssl.SSLContext;

/**
 * Finds the Redis master a client sends its commands to. Directly, it is the URL's host and port, always. Through
 * Sentinel it is what {@code SENTINEL get-master-addr-by-name} answers, asked of each sentinel in order until one
 * names it, and remembered until a connection to it is lost or it answers {@code READONLY} - a failover - when the
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
     */
    static final class Sentinel extends MasterLocator {
        private final RedisUrl url;
        private final String master;
        private final List<RedisConfig.HostPort> sentinels;
        private final String password;
        private final SSLContext ssl;
        private Endpoint current;
        private long generation;

        Sentinel(RedisUrl url, String master, List<RedisConfig.HostPort> sentinels, String password, SSLContext ssl) {
            this.url = url;
            this.master = master;
            this.sentinels = sentinels;
            this.password = password;
            this.ssl = ssl;
        }

        @Override
        synchronized Endpoint master(long deadline) throws IOException {
            if (this.current != null) {
                return this.current;
            }
            IOException last = null;
            for (RedisConfig.HostPort sentinel : this.sentinels) {
                try {
                    List<?> address = this.ask(sentinel, deadline);
                    if (address == null) {
                        last = new IOException("sentinel " + sentinel + " does not know a master named " + this.master);
                        continue;
                    }
                    String host = String.valueOf(address.get(0));
                    int port = (int) RedisConnection.number(String.valueOf(address.get(1)), 1, 65535);
                    this.current = new Endpoint(host, port, RedisTls.isIpLiteral(host) ? this.url.host : host, this.generation);
                    return this.current;
                } catch (IOException | RuntimeException e) {
                    last = e instanceof IOException ? (IOException) e : new IOException("sentinel " + sentinel + ": " + e.getMessage(), e);
                }
            }
            throw new IOException("no sentinel named the master " + this.master + " (asked " + this.sentinels + "): "
                    + last.getMessage(), last);
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
                this.generation++;
            }
        }

        @Override
        synchronized long generation() {
            return this.generation;
        }

        @Override
        boolean sentinel() {
            return true;
        }
    }
}
