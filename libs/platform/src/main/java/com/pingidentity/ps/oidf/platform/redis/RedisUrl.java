/*
 * A Redis URL taken apart, and put back together without its password for a message.
 */
package com.pingidentity.ps.oidf.platform.redis;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * {@code redis://[user[:password]@]host[:port][/db]} or {@code rediss://} (TLS), the shape Railway and most managed
 * Redis providers export as {@code REDIS_URL}. A bare userinfo is the password ({@code redis://password@host} is a
 * common shorthand); the port is 6379 when left out and the database 0. No message this class writes quotes the
 * userinfo: {@link #redact} replaces it with {@code ***}.
 */
final class RedisUrl {
    static final int DEFAULT_PORT = 6379;

    final boolean tls;
    final String host;
    final int port;
    final String username;
    final String password;
    final int db;

    private RedisUrl(boolean tls, String host, int port, String username, String password, int db) {
        this.tls = tls;
        this.host = host;
        this.port = port;
        this.username = username;
        this.password = password;
        this.db = db;
    }

    /**
     * @throws IllegalArgumentException for a URL this client does not accept; the message never quotes the userinfo
     */
    static RedisUrl parse(String url) {
        URI uri;
        try {
            uri = URI.create(url.trim());
        } catch (IllegalArgumentException e) {
            // URI's own message quotes the input, password and all; this one does not.
            throw new IllegalArgumentException("Redis URL is not a valid URI: " + redact(url));
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("redis") && !scheme.equals("rediss")) {
            throw new IllegalArgumentException("Unsupported Redis URL scheme: " + uri.getScheme());
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException("Redis URL has no host: " + redact(url));
        }
        String username = null;
        String password = null;
        // 0.4.0's decoding, kept as it was: URI decodes the escapes and URLDecoder decodes the result again, so a
        // '+' is a space and "%2525" is '%' (finding F-0180).
        String userInfo = uri.getUserInfo();
        if (userInfo != null && !userInfo.isEmpty()) {
            int colon = userInfo.indexOf(':');
            if (colon >= 0) {
                String user = decode(userInfo.substring(0, colon));
                username = user.isEmpty() ? null : user;
                password = decode(userInfo.substring(colon + 1));
            } else {
                password = decode(userInfo);
            }
        }
        String path = uri.getPath();
        int db = 0;
        if (path != null && path.length() > 1) {
            try {
                db = Integer.parseInt(path.substring(1));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Redis URL has a non-numeric db path: " + path);
            }
        }
        return new RedisUrl(scheme.equals("rediss"), uri.getHost(), uri.getPort() != -1 ? uri.getPort() : DEFAULT_PORT,
                username, password, db);
    }

    /** Whether AUTH is sent: a password is set and not empty. */
    boolean authenticates() {
        return this.password != null && !this.password.isEmpty();
    }

    /**
     * {@code url} with its userinfo replaced by {@code ***}, for messages that reach a log: everything between the
     * scheme's {@code ://} and the last {@code @}, so a password with an unencoded {@code @} or {@code /} goes too.
     */
    static String redact(String url) {
        if (url == null) {
            return null;
        }
        int authority = url.indexOf("://");
        int at = url.lastIndexOf('@');
        if (authority < 0 || at < authority) {
            return url;
        }
        return url.substring(0, authority + 3) + "***" + url.substring(at);
    }

    /** The second decoding; its own message would quote part of the password, so this one does not. */
    private static String decode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Redis URL's userinfo has a '%' that is not an escape once decoded");
        }
    }
}
