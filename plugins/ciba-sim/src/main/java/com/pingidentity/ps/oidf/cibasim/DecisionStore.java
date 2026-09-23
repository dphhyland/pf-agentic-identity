/*
 * Where an operator's allow/deny for a CIBA request waits for the authenticator to ask.
 */
package com.pingidentity.ps.oidf.cibasim;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Function;

/**
 * A directory of decisions, one file per CIBA transaction. The decision endpoint writes them from
 * inside {@code pf-runtime.war}; the authenticator reads them from a loose plugin jar. Those are two
 * classloaders in PingFederate and they share no statics, so the handoff is the filesystem and nothing
 * cleverer - one process, one directory, files small enough that an atomic rename is the whole protocol.
 *
 * <p>The file is named by {@link #txIdFor}, the SHA-256 of the {@code auth_req_id}, which is also the
 * plugin's transaction identifier: PingFederate hands {@code initiate()} the {@code auth_req_id} but hands
 * {@code check()} only the transaction id (and, in ping mode, an empty parameter map), so the id has to be
 * derivable from what each side has. Naming the file by the hash also keeps the {@code auth_req_id} - a
 * bearer credential at the token endpoint - out of directory listings.
 *
 * <p>A decision is kept for {@code ttl} and then reads as absent: a stale allow must never approve a
 * later request that happened to reuse a transaction id, and PingFederate's own transaction lifetime
 * is shorter than this anyway.
 */
public class DecisionStore {

    /** What the operator decided. PingFederate turns {@code DENY} into {@code access_denied}. */
    public enum Decision {
        ALLOW, DENY;

        /** {@code allow} or {@code deny}, case-insensitively; anything else is null. */
        public static Decision parse(String action) {
            if (action == null) {
                return null;
            }
            switch (action.trim().toLowerCase(Locale.ROOT)) {
                case "allow":
                    return ALLOW;
                case "deny":
                    return DENY;
                default:
                    return null;
            }
        }
    }

    /** Environment variable naming the directory; unset, the JVM's temp dir gets a subdirectory. */
    public static final String DIR_ENV = "OIDF_CIBA_SIM_DIR";
    static final Duration DEFAULT_TTL = Duration.ofMinutes(15);

    private final Path dir;
    private final Duration ttl;
    private final Clock clock;

    public DecisionStore(Path dir, Duration ttl, Clock clock) {
        this.dir = dir;
        this.ttl = ttl;
        this.clock = clock;
    }

    /** The production store: {@code OIDF_CIBA_SIM_DIR}, else {@code ${java.io.tmpdir}/oidf-ciba-sim}. */
    public static DecisionStore fromEnvironment(Function<String, String> env) {
        String configured = env.apply(DIR_ENV);
        Path dir = configured != null && !configured.isBlank()
                ? Path.of(configured.trim())
                : Path.of(System.getProperty("java.io.tmpdir"), "oidf-ciba-sim");
        return new DecisionStore(dir, DEFAULT_TTL, Clock.systemUTC());
    }

    /** The plugin transaction id for an {@code auth_req_id}: its SHA-256, hex. */
    public static String txIdFor(String authReqId) {
        if (authReqId == null || authReqId.isBlank()) {
            throw new IllegalArgumentException("auth_req_id is required");
        }
        return HexFormat.of().formatHex(sha256().digest(authReqId.trim().getBytes(StandardCharsets.UTF_8)));
    }

    /** Every JVM has SHA-256 (it is in the platform's required set); the checked exception is a formality. */
    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Record {@code decision} for {@code authReqId}; a later decision replaces an earlier one. Returns the tx id. */
    public String record(String authReqId, Decision decision) throws IOException {
        if (decision == null) {
            throw new IllegalArgumentException("decision is required");
        }
        String txId = txIdFor(authReqId);
        ensureDir();
        Path target = this.dir.resolve(txId);
        Path temp = this.dir.resolve(txId + ".tmp");
        Files.writeString(temp, decision.name().toLowerCase(Locale.ROOT) + " " + this.clock.instant().getEpochSecond() + "\n",
                StandardCharsets.UTF_8);
        moveInto(temp, target);
        return txId;
    }

    /** An atomic rename where the filesystem has one; a plain replace where it does not. */
    private static void moveInto(Path temp, Path target) throws IOException {
        try {
            Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /** The decision recorded for {@code txId}, or empty when there is none or it is older than the TTL. */
    public Optional<Decision> lookup(String txId) throws IOException {
        if (txId == null || !txId.matches("[0-9a-f]{64}")) {
            return Optional.empty();
        }
        Path file = this.dir.resolve(txId);
        if (!Files.isRegularFile(file)) {
            return Optional.empty();
        }
        String[] parts = Files.readString(file, StandardCharsets.UTF_8).trim().split(" ");
        Decision decision = Decision.parse(parts[0]);
        long recordedAt;
        try {
            recordedAt = parts.length > 1 ? Long.parseLong(parts[1]) : 0L;
        } catch (NumberFormatException e) {
            recordedAt = 0L;
        }
        if (decision == null || this.clock.instant().getEpochSecond() - recordedAt > this.ttl.getSeconds()) {
            Files.deleteIfExists(file);
            return Optional.empty();
        }
        return Optional.of(decision);
    }

    /** Drop the decision for {@code txId}, if any. */
    public void forget(String txId) throws IOException {
        if (txId != null && txId.matches("[0-9a-f]{64}")) {
            Files.deleteIfExists(this.dir.resolve(txId));
        }
    }

    Path dir() {
        return this.dir;
    }

    private void ensureDir() throws IOException {
        if (Files.isDirectory(this.dir)) {
            return;
        }
        Files.createDirectories(this.dir);
        try {
            Files.setPosixFilePermissions(this.dir, PosixFilePermissions.fromString("rwx------"));
        } catch (UnsupportedOperationException e) {
            // not a POSIX filesystem; the directory is still private to the process's user by default
        }
    }
}
