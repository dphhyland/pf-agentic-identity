/*
 * What a Redis client is built from: the URL, the CA file, the pool, the deadlines and Sentinel.
 */
package com.pingidentity.ps.oidf.platform.redis;

import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.Secret;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * A {@link RedisClient}'s configuration. {@link #current()} reads it from this process through the
 * {@code platform-redis} catalogue ({@code META-INF/oidf-settings/platform-redis.json}); {@link #builder} makes one
 * in code. Nothing here connects: a URL is judged when the client is built, and the server when a command runs.
 *
 * <p>{@link #toString()} never shows the URL's userinfo or the sentinels' password.
 */
public final class RedisConfig {
    /** The catalogue's component name. */
    public static final String COMPONENT = "platform-redis";
    public static final String URL_SETTING = "OIDF_REDIS_URL";
    /** The URL's fallback, read only when {@value #URL_SETTING} and its property are unset. */
    public static final String FALLBACK_URL_SETTING = "REDIS_URL";
    public static final String CA_FILE_SETTING = RedisTls.CA_FILE_SETTING;
    public static final String POOL_SIZE_SETTING = "OIDF_REDIS_POOL_SIZE";
    public static final String BORROW_TIMEOUT_SETTING = "OIDF_REDIS_BORROW_TIMEOUT_MS";
    public static final String COMMAND_TIMEOUT_SETTING = "OIDF_REDIS_COMMAND_TIMEOUT_MS";
    public static final String SENTINEL_MASTER_SETTING = "OIDF_REDIS_SENTINEL_MASTER";
    public static final String SENTINELS_SETTING = "OIDF_REDIS_SENTINELS";
    public static final String SENTINEL_PASSWORD_SETTING = "OIDF_REDIS_SENTINEL_PASSWORD";

    /** The catalogue's defaults, for a configuration made in code. */
    public static final int DEFAULT_POOL_SIZE = 8;
    public static final int MAX_POOL_SIZE = 256;
    public static final Duration DEFAULT_BORROW_TIMEOUT = Duration.ofMillis(1000);
    public static final Duration DEFAULT_COMMAND_TIMEOUT = Duration.ofMillis(3000);
    public static final int DEFAULT_SENTINEL_PORT = 26379;

    private final String url;
    private final Path caFile;
    private final DeploymentProfile profile;
    private final int poolSize;
    private final Duration borrowTimeout;
    private final Duration commandTimeout;
    private final String sentinelMaster;
    private final List<HostPort> sentinels;
    private final String sentinelPassword;

    private RedisConfig(Builder b) {
        this.url = b.url;
        this.caFile = b.caFile;
        this.profile = b.profile;
        this.poolSize = b.poolSize;
        this.borrowTimeout = b.borrowTimeout;
        this.commandTimeout = b.commandTimeout;
        this.sentinelMaster = b.sentinelMaster;
        this.sentinels = List.copyOf(b.sentinels);
        this.sentinelPassword = b.sentinelPassword;
    }

    /**
     * This process's configuration, from the {@code platform-redis} catalogue on this class's loader, under this
     * process's profile; null when no URL is set ({@code oidf.redis.url}, {@code OIDF_REDIS_URL}, then
     * {@code REDIS_URL}).
     *
     * @throws com.pingidentity.ps.oidf.platform.settings.SettingRefused for a value its setting refuses
     * @throws IllegalArgumentException for Sentinel settings that do not go together
     */
    public static RedisConfig current() {
        return fromSettings(processSettings(), DeploymentProfile.current());
    }

    /** Whether this process names a Redis: a URL is set, whether or not the rest of the settings are good. */
    public static boolean isConfigured() {
        return url(processSettings()) != null;
    }

    /**
     * This process's configuration for {@code url} rather than the one its settings name: the CA file, the pool, the
     * deadlines and Sentinel as the settings say, under this process's profile.
     */
    public static RedisConfig currentFor(String url) {
        return fromSettings(processSettings(), DeploymentProfile.current(), url);
    }

    /** The configuration {@code settings} hold, under {@code profile}; null when no URL is set. */
    public static RedisConfig fromSettings(Settings settings, DeploymentProfile profile) {
        Secret url = url(settings);
        return url == null ? null : fromSettings(settings, profile, url.reveal());
    }

    /** The configuration {@code settings} hold for {@code url}, under {@code profile}. */
    public static RedisConfig fromSettings(Settings settings, DeploymentProfile profile, String url) {
        Builder builder = builder(url)
                .caFile(settings.path(CA_FILE_SETTING))
                .profile(profile)
                .poolSize(settings.integer(POOL_SIZE_SETTING))
                .borrowTimeout(settings.duration(BORROW_TIMEOUT_SETTING))
                .commandTimeout(settings.duration(COMMAND_TIMEOUT_SETTING));
        String master = settings.string(SENTINEL_MASTER_SETTING);
        Set<String> sentinels = settings.words(SENTINELS_SETTING);
        Secret password = settings.secret(SENTINEL_PASSWORD_SETTING);
        if (master != null || sentinels != null) {
            builder.sentinel(master, sentinels == null ? List.of() : List.copyOf(sentinels),
                    password == null ? null : password.reveal());
        }
        return builder.build();
    }

    /** {@value #URL_SETTING} (or its property), else {@value #FALLBACK_URL_SETTING}; null when neither is set. */
    private static Secret url(Settings settings) {
        Secret url = settings.secret(URL_SETTING);
        return url != null ? url : settings.secret(FALLBACK_URL_SETTING);
    }

    /** The catalogue, loaded once per loaded copy of this class, read from this process each time. */
    private static Settings processSettings() {
        return Settings.of(CatalogueHolder.CATALOGUE, Sources.process());
    }

    private static final class CatalogueHolder {
        static final Catalogue CATALOGUE = Catalogue.load(RedisConfig.class.getClassLoader(), COMPONENT);
    }

    /** A configuration in code, starting from the catalogue's defaults and the production profile. */
    public static Builder builder(String url) {
        return new Builder(url);
    }

    /** The URL as it was set, password included: for the client, never for a message. */
    String url() {
        return this.url;
    }

    public Path caFile() {
        return this.caFile;
    }

    public DeploymentProfile profile() {
        return this.profile;
    }

    public int poolSize() {
        return this.poolSize;
    }

    public Duration borrowTimeout() {
        return this.borrowTimeout;
    }

    public Duration commandTimeout() {
        return this.commandTimeout;
    }

    /** The master's name in Sentinel, or null when the URL's host is dialled directly. */
    public String sentinelMaster() {
        return this.sentinelMaster;
    }

    public List<HostPort> sentinels() {
        return this.sentinels;
    }

    String sentinelPassword() {
        return this.sentinelPassword;
    }

    @Override
    public String toString() {
        return "RedisConfig[url=" + RedisUrl.redact(this.url) + ", caFile=" + this.caFile + ", profile=" + this.profile.value()
                + ", poolSize=" + this.poolSize + ", borrowTimeout=" + this.borrowTimeout.toMillis() + "ms, commandTimeout="
                + this.commandTimeout.toMillis() + "ms" + (this.sentinelMaster == null ? ""
                : ", sentinelMaster=" + this.sentinelMaster + ", sentinels=" + this.sentinels
                        + (this.sentinelPassword == null ? "" : ", sentinelPassword=[secret]")) + "]";
    }

    /**
     * A sentinel's {@code host:port}: a name, an IPv4 address or a bracketed IPv6 address, with the port
     * {@value #DEFAULT_SENTINEL_PORT} when left out.
     */
    public record HostPort(String host, int port) {
        public HostPort {
            Objects.requireNonNull(host, "host");
        }

        /**
         * @throws IllegalArgumentException naming the entry, for one that is not {@code host} or {@code host:port}
         */
        static HostPort parse(String entry) {
            String text = entry.trim();
            String host;
            String port = null;
            if (text.startsWith("[")) {
                int close = text.indexOf(']');
                if (close < 0 || (close + 1 < text.length() && text.charAt(close + 1) != ':')) {
                    throw refused(entry);
                }
                host = text.substring(1, close);
                if (close + 1 < text.length()) {
                    port = text.substring(close + 2);
                }
            } else {
                int colon = text.indexOf(':');
                if (colon != text.lastIndexOf(':')) {
                    throw refused(entry);
                }
                host = colon < 0 ? text : text.substring(0, colon);
                port = colon < 0 ? null : text.substring(colon + 1);
            }
            if (host.isEmpty()) {
                throw refused(entry);
            }
            if (port == null) {
                return new HostPort(host, DEFAULT_SENTINEL_PORT);
            }
            try {
                int p = Integer.parseInt(port);
                if (p < 1 || p > 65535) {
                    throw refused(entry);
                }
                return new HostPort(host, p);
            } catch (NumberFormatException e) {
                throw refused(entry);
            }
        }

        private static IllegalArgumentException refused(String entry) {
            return new IllegalArgumentException(SENTINELS_SETTING + " entry " + entry + " is not host or host:port");
        }

        @Override
        public String toString() {
            return (this.host.indexOf(':') >= 0 ? "[" + this.host + "]" : this.host) + ":" + this.port;
        }
    }

    /** Builds a {@link RedisConfig}; each value is checked when set. */
    public static final class Builder {
        private final String url;
        private Path caFile;
        private DeploymentProfile profile = DeploymentProfile.PRODUCTION;
        private int poolSize = DEFAULT_POOL_SIZE;
        private Duration borrowTimeout = DEFAULT_BORROW_TIMEOUT;
        private Duration commandTimeout = DEFAULT_COMMAND_TIMEOUT;
        private String sentinelMaster;
        private final List<HostPort> sentinels = new ArrayList<>();
        private String sentinelPassword;

        private Builder(String url) {
            if (url == null || url.isBlank()) {
                throw new IllegalArgumentException(URL_SETTING + " is required");
            }
            this.url = url.trim();
        }

        /** A PEM file of CA certificates to trust for TLS instead of the JVM's; null for the JVM's. */
        public Builder caFile(Path caFile) {
            this.caFile = caFile;
            return this;
        }

        /** The profile the URL is judged under: production refuses {@code redis://}. */
        public Builder profile(DeploymentProfile profile) {
            this.profile = Objects.requireNonNull(profile, "profile");
            return this;
        }

        /** The most connections open at once, 1 to {@value #MAX_POOL_SIZE}. */
        public Builder poolSize(int poolSize) {
            if (poolSize < 1 || poolSize > MAX_POOL_SIZE) {
                throw new IllegalArgumentException(POOL_SIZE_SETTING + " must be from 1 to " + MAX_POOL_SIZE + ", not " + poolSize);
            }
            this.poolSize = poolSize;
            return this;
        }

        /** How long a command waits for a free connection; positive. */
        public Builder borrowTimeout(Duration borrowTimeout) {
            this.borrowTimeout = positive(BORROW_TIMEOUT_SETTING, borrowTimeout);
            return this;
        }

        /** How long a command may take once it has a connection; positive. */
        public Builder commandTimeout(Duration commandTimeout) {
            this.commandTimeout = positive(COMMAND_TIMEOUT_SETTING, commandTimeout);
            return this;
        }

        /**
         * Finds the master through Sentinel: {@code master} is its name there and {@code sentinels} the
         * {@code host[:port]} of each sentinel, asked in order. Both or neither.
         *
         * @param password what the sentinels ask for in {@code AUTH}, or null when they ask for nothing
         */
        public Builder sentinel(String master, List<String> sentinels, String password) {
            String name = master == null || master.isBlank() ? null : master.trim();
            if (name == null || sentinels.isEmpty()) {
                throw new IllegalArgumentException(SENTINEL_MASTER_SETTING + " and " + SENTINELS_SETTING
                        + " go together: set both to find the master through Sentinel, or neither to dial the URL's host");
            }
            List<HostPort> parsed = new ArrayList<>();
            for (String entry : sentinels) {
                parsed.add(HostPort.parse(entry));
            }
            this.sentinelMaster = name;
            this.sentinels.clear();
            this.sentinels.addAll(parsed);
            this.sentinelPassword = password == null || password.isEmpty() ? null : password;
            return this;
        }

        public RedisConfig build() {
            return new RedisConfig(this);
        }

        private static Duration positive(String setting, Duration value) {
            if (value == null || value.isNegative() || value.isZero()) {
                throw new IllegalArgumentException(setting + " must be positive, not " + value);
            }
            return value;
        }
    }
}
