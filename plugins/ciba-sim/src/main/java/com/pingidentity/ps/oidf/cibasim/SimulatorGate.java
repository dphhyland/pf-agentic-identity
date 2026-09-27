/*
 * Whether the CIBA simulator may run here at all: the switch, the deployment profile and the directory.
 */
package com.pingidentity.ps.oidf.cibasim;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;
import java.util.function.Function;

/**
 * The simulator is an approval oracle keyed by nothing but an {@code auth_req_id}: whoever can reach the
 * decision endpoint, or write to the decision directory, can approve a CIBA request. So it runs only where
 * all three of these hold, and both halves - the servlet in {@code pf-runtime.war} and the plugin loose in
 * {@code deploy/} - ask before every request:
 * <ol>
 *   <li>{@code OIDF_CIBA_SIM_ENABLED=true}: off unless a deployment says it is a rig;</li>
 *   <li>{@code OIDF_DEPLOYMENT_PROFILE=development}: never in production, which is what an unset variable
 *       means, and what any value other than {@code development} means too - a typo lands on the safe
 *       side;</li>
 *   <li>{@code OIDF_CIBA_SIM_DIR}: an absolute path to an existing directory that is not a symbolic link,
 *       is owned by the user this process runs as and has no group or other permission bits, on a POSIX
 *       filesystem. The directory is the handoff between the two classloaders, and anyone else who can
 *       write to it can approve a request.</li>
 * </ol>
 *
 * <p>The profile is read from the environment directly, here and in the image's entrypoint. Plan item PR-1
 * (Phase 2) centralises it; until then this is the whole definition.
 */
final class SimulatorGate {

    static final String ENABLED_ENV = "OIDF_CIBA_SIM_ENABLED";
    static final String PROFILE_ENV = "OIDF_DEPLOYMENT_PROFILE";
    static final String DIR_ENV = "OIDF_CIBA_SIM_DIR";

    private static final Set<PosixFilePermission> OWNER_BITS = EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
    private static volatile UserPrincipal processUser;

    private SimulatorGate() {
    }

    /** Why the simulator may not run here, or null when it may. */
    static String refusal(Function<String, String> env) {
        return refusal(env, processUser());
    }

    /** The same, told who this process is; null for {@code processUser} means nobody could say. */
    static String refusal(Function<String, String> env, UserPrincipal processUser) {
        if (!enabled(env)) {
            return ENABLED_ENV + " is not true";
        }
        if (isProduction(env)) {
            String profile = env.apply(PROFILE_ENV);
            return PROFILE_ENV + " is " + (profile == null ? "unset, which is production" : "'" + profile + "', which counts as production")
                    + "; the simulator never runs there";
        }
        String configured = env.apply(DIR_ENV);
        if (configured == null || configured.isBlank()) {
            return DIR_ENV + " is not set";
        }
        if (processUser == null) {
            return "the user this process runs as could not be determined, so the owner of " + DIR_ENV + " cannot be checked";
        }
        Path dir;
        try {
            dir = Path.of(configured.trim());
        } catch (InvalidPathException e) {
            return DIR_ENV + " is not a path: " + e.getMessage();
        }
        return directoryRefusal(dir, processUser);
    }

    /** {@code OIDF_CIBA_SIM_ENABLED} is {@code true}, in any case; nothing else counts. */
    static boolean enabled(Function<String, String> env) {
        String value = env.apply(ENABLED_ENV);
        return value != null && "true".equalsIgnoreCase(value.trim());
    }

    /** Everything but {@code OIDF_DEPLOYMENT_PROFILE=development} is production, an unset variable included. */
    static boolean isProduction(Function<String, String> env) {
        String value = env.apply(PROFILE_ENV);
        return value == null || !"development".equals(value.trim().toLowerCase(Locale.ROOT));
    }

    /** Why {@code dir} may not hold decisions, or null when it may. Every failure to look counts as a refusal. */
    static String directoryRefusal(Path dir, UserPrincipal processUser) {
        String name = DIR_ENV + "=" + dir;
        if (!dir.isAbsolute()) {
            return name + " is not an absolute path";
        }
        // One read, of the link itself: the POSIX view carries the symlink and directory answers as well as
        // the owner and mode, and a filesystem without it has nothing to check and is refused outright.
        PosixFileAttributes posix;
        try {
            posix = Files.readAttributes(dir, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } catch (NoSuchFileException e) {
            return name + " does not exist";
        } catch (UnsupportedOperationException e) {
            return name + " is not on a POSIX filesystem, so its owner and permissions cannot be checked";
        } catch (IOException e) {
            return name + " cannot be read: " + e;
        }
        if (posix.isSymbolicLink()) {
            return name + " is a symbolic link";
        }
        if (!posix.isDirectory()) {
            return name + " is not a directory";
        }
        if (!processUser.equals(posix.owner())) {
            return name + " is owned by " + posix.owner().getName() + ", not by " + processUser.getName()
                    + ", the user this process runs as";
        }
        if (!OWNER_BITS.containsAll(posix.permissions()) || !posix.permissions().containsAll(OWNER_BITS)) {
            return name + " has mode " + PosixFilePermissions.toString(posix.permissions()) + "; it must be rwx------ (0700)";
        }
        return null;
    }

    /** The directory, once {@link #refusal} has passed it. */
    static Path directory(Function<String, String> env) {
        return Path.of(env.apply(DIR_ENV).trim());
    }

    /**
     * The user this JVM runs as: the owner of a file it creates. Read once; null when even that fails, which
     * {@link #refusal} treats as a refusal rather than a guess.
     */
    static UserPrincipal processUser() {
        UserPrincipal known = processUser;
        if (known == null) {
            try {
                Path probe = Files.createTempFile("ciba-sim-", ".owner");
                try {
                    known = Files.getOwner(probe);
                } finally {
                    Files.deleteIfExists(probe);
                }
            } catch (IOException | UnsupportedOperationException e) {
                return null;
            }
            processUser = known;
        }
        return known;
    }
}
