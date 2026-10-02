/*
 * Whether the CIBA simulator may run here at all: the switch, the deployment profile and the directory.
 */
package com.pingidentity.ps.oidf.cibasim;

import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
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
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * The simulator is an approval oracle keyed by nothing but an {@code auth_req_id}: whoever can reach the
 * decision endpoint, or write to the decision directory, can approve a CIBA request. So it runs only where
 * all three of these hold, and both halves - the servlet in {@code pf-runtime.war} and the plugin loose in
 * {@code deploy/} - ask before every request:
 * <ol>
 *   <li>{@code OIDF_DEPLOYMENT_PROFILE=development}: never in production, which is what an unset variable
 *       means, and what any value other than {@code development} means too - a typo lands on the safe
 *       side. It is asked first, so production refuses whatever {@code OIDF_CIBA_SIM_ENABLED} says (plan item
 *       PR-3): the image never stages this jar (R-I1), but a consumer's image can, and the setting being
 *       forbidden in production refuses nothing if the plugin itself does not. The first refusal in production
 *       logs one ERROR; the rest are silent, since each request would say the same;</li>
 *   <li>{@code OIDF_CIBA_SIM_ENABLED=true}: off unless a deployment says it is a rig. Read strictly through
 *       the {@code ciba-simulator} settings catalogue: {@code true} or {@code false}, and a value only the old
 *       reader took ({@code yes}, {@code 1}) is read as false with a warning under development;</li>
 *   <li>{@code OIDF_CIBA_SIM_DIR}: an absolute path to an existing directory that is not a symbolic link,
 *       is owned by the user this process runs as and has no group or other permission bits, on a POSIX
 *       filesystem. The directory is the handoff between the two classloaders, and anyone else who can
 *       write to it can approve a request.</li>
 * </ol>
 *
 * <p>The profile is platform's {@link DeploymentProfile} (plan item PR-1), shaded into this jar under its own
 * package; the image's entrypoint applies the same rule in shell.
 */
final class SimulatorGate {

    static final String ENABLED_ENV = "OIDF_CIBA_SIM_ENABLED";
    static final String PROFILE_ENV = DeploymentProfile.SETTING;
    static final String DIR_ENV = "OIDF_CIBA_SIM_DIR";
    /** The settings catalogue this gate reads its two settings through. */
    static final String CATALOGUE = "ciba-simulator";

    private static final Log LOGGER = LogFactory.getLog(SimulatorGate.class);
    /** How many times this copy has refused for the production profile; the first of them logs the ERROR. */
    private static final AtomicInteger PRODUCTION_REFUSALS = new AtomicInteger();

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
        if (isProduction(env)) {
            String reason = DeploymentProfile.describe(env) + "; the simulator never runs there, whatever "
                    + ENABLED_ENV + " says";
            if (PRODUCTION_REFUSALS.getAndIncrement() == 0) {
                LOGGER.error((Object) ("CIBA simulator refused by the production profile: " + reason + ". Its decision"
                        + " endpoint answers 404 and its authenticator fails every request; remove pf.plugins.ciba-sim.jar"
                        + " from this deployment. Logged once."));
            }
            return reason;
        }
        Settings settings = settings(env);
        Path dir;
        try {
            // Strict: true or false (PR-5's legacy spellings read as false, with a warning, under development only).
            if (!settings.bool(ENABLED_ENV)) {
                return ENABLED_ENV + " is not true";
            }
            dir = settings.path(DIR_ENV);
        } catch (SettingRefused e) {
            return e.getMessage();
        }
        if (dir == null) {
            return DIR_ENV + " is not set";
        }
        if (processUser == null) {
            return "the user this process runs as could not be determined, so the owner of " + DIR_ENV + " cannot be checked";
        }
        return directoryRefusal(dir, processUser);
    }

    /** The two settings, read from {@code env} through this jar's {@code ciba-simulator} catalogue. */
    static Settings settings(Function<String, String> env) {
        return Settings.of(Holder.CATALOGUE, Sources.of(env, name -> null, null));
    }

    /** The catalogue, loaded once from this class's own loader: the jar in {@code deploy/} or in the war. */
    private static final class Holder {
        static final Catalogue CATALOGUE = Catalogue.load(SimulatorGate.class.getClassLoader(), SimulatorGate.CATALOGUE);
    }

    /** Everything but {@code OIDF_DEPLOYMENT_PROFILE=development} is production, an unset variable included. */
    static boolean isProduction(Function<String, String> env) {
        return DeploymentProfile.of(env).isProduction();
    }

    /** How many times this copy has refused for the production profile. */
    static int productionRefusals() {
        return PRODUCTION_REFUSALS.get();
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
        return settings(env).path(DIR_ENV);
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
