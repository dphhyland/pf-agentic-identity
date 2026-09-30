/*
 * Each reason the simulator refuses to run, and the one shape of environment it accepts.
 */
package com.pingidentity.ps.oidf.cibasim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SimulatorGateTest {

    /** A rig's environment: on, development, and a private directory. */
    private static Map<String, String> rig(Path dir) {
        Map<String, String> env = new HashMap<>();
        env.put(SimulatorGate.ENABLED_ENV, "true");
        env.put(SimulatorGate.PROFILE_ENV, "development");
        env.put(SimulatorGate.DIR_ENV, dir.toString());
        return env;
    }

    private static Function<String, String> env(Map<String, String> values) {
        return values::get;
    }

    /** A user that is not the one this test runs as, whichever that is. */
    private static UserPrincipal someoneElse(Path owned) throws IOException {
        UserPrincipal me = Files.getOwner(owned);
        for (String name : new String[] {"nobody", "daemon", "root"}) {
            try {
                UserPrincipal other = owned.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(name);
                if (!other.equals(me)) {
                    return other;
                }
            } catch (UserPrincipalNotFoundException e) {
                // not on this system; try the next
            }
        }
        throw new IllegalStateException("no second user to test with");
    }

    @Test
    void aRigIsAdmitted(@TempDir Path dir) throws IOException {
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        assertNull(SimulatorGate.refusal(env(rig(dir))));
        assertNull(SimulatorGate.refusal(env(rig(dir)), SimulatorGate.processUser()));
        assertEquals(dir, SimulatorGate.directory(env(rig(dir))));

        Map<String, String> spaced = rig(dir);
        spaced.put(SimulatorGate.DIR_ENV, " " + dir + " ");
        assertNull(SimulatorGate.refusal(env(spaced)), "the path is trimmed");
        assertEquals(dir, SimulatorGate.directory(env(spaced)));
    }

    @Test
    void theSwitchIsReadStrictlyWithTheDevelopmentEscapeForLegacySpellings(@TempDir Path dir) {
        Map<String, String> env = rig(dir);
        env.put(SimulatorGate.ENABLED_ENV, " TRUE ");
        assertNull(SimulatorGate.refusal(env(env)), "true in any case, trimmed");
        for (String legacy : new String[] {"yes", "1", "on"}) {
            env.put(SimulatorGate.ENABLED_ENV, legacy);
            assertEquals(SimulatorGate.ENABLED_ENV + " is not true", SimulatorGate.refusal(env(env)),
                    "under development the old reader's spelling '" + legacy + "' is read as false, with a warning");
        }
        env.put(SimulatorGate.ENABLED_ENV, "maybe");
        String refused = SimulatorGate.refusal(env(env));
        assertNotNull(refused);
        assertTrue(refused.contains(SimulatorGate.ENABLED_ENV) && refused.contains("true or false"), refused);
        env.put(SimulatorGate.ENABLED_ENV, "false");
        assertEquals(SimulatorGate.ENABLED_ENV + " is not true", SimulatorGate.refusal(env(env)));
    }

    @Test
    void productionRefusesWhateverTheSwitchSaysWithOneError(@TempDir Path dir) {
        List<LogRecord> errors = new ArrayList<>();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                if (record.getLevel() == Level.SEVERE) {
                    errors.add(record);
                }
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        Logger logger = Logger.getLogger(SimulatorGate.class.getName());
        logger.addHandler(handler);
        try {
            int before = SimulatorGate.productionRefusals();
            for (String value : new String[] {"true", "false", "yes", "maybe", null}) {
                Map<String, String> env = rig(dir);
                env.put(SimulatorGate.PROFILE_ENV, "production");
                env.put(SimulatorGate.ENABLED_ENV, value);
                String refusal = SimulatorGate.refusal(env(env));
                assertNotNull(refusal, String.valueOf(value));
                assertTrue(refusal.contains("never runs there, whatever " + SimulatorGate.ENABLED_ENV + " says"), refusal);
            }
            assertEquals(before + 5, SimulatorGate.productionRefusals());
            assertEquals(before == 0 ? 1 : 0, errors.size(), "one ERROR, at the first refusal this copy makes");
        } finally {
            logger.removeHandler(handler);
        }
    }

    @Test
    void everythingButDevelopmentIsProduction() {
        assertTrue(SimulatorGate.isProduction(k -> null), "unset is production");
        assertTrue(SimulatorGate.isProduction(k -> "production"));
        assertTrue(SimulatorGate.isProduction(k -> "PRODUCTION"));
        assertTrue(SimulatorGate.isProduction(k -> "staging"), "an unknown value lands on the safe side");
        assertTrue(SimulatorGate.isProduction(k -> ""));
        assertFalse(SimulatorGate.isProduction(k -> "development"));
        assertFalse(SimulatorGate.isProduction(k -> " Development "));
    }

    @Test
    void offUnlessSwitchedOnAndNeverInProduction(@TempDir Path dir) {
        Map<String, String> env = rig(dir);
        env.remove(SimulatorGate.ENABLED_ENV);
        assertEquals(SimulatorGate.ENABLED_ENV + " is not true", SimulatorGate.refusal(env(env)));

        env = rig(dir);
        env.remove(SimulatorGate.PROFILE_ENV);
        String unset = SimulatorGate.refusal(env(env));
        assertNotNull(unset);
        assertTrue(unset.contains("unset, which is production"), unset);

        env.put(SimulatorGate.PROFILE_ENV, "production");
        String production = SimulatorGate.refusal(env(env));
        assertNotNull(production);
        assertTrue(production.contains("'production', which counts as production"), production);
    }

    @Test
    void theDirectoryMustBeNamedAndTheProcessUserKnown(@TempDir Path dir) {
        Map<String, String> env = rig(dir);
        env.remove(SimulatorGate.DIR_ENV);
        assertEquals(SimulatorGate.DIR_ENV + " is not set", SimulatorGate.refusal(env(env)));
        env.put(SimulatorGate.DIR_ENV, "  ");
        assertEquals(SimulatorGate.DIR_ENV + " is not set", SimulatorGate.refusal(env(env)));

        String unknownUser = SimulatorGate.refusal(env(rig(dir)), null);
        assertNotNull(unknownUser);
        assertTrue(unknownUser.contains("could not be determined"), unknownUser);

        env = rig(dir);
        env.put(SimulatorGate.DIR_ENV, "/no\0where");
        String notAPath = SimulatorGate.refusal(env(env));
        assertNotNull(notAPath);
        assertTrue(notAPath.contains("is not a path"), notAPath);
    }

    @Test
    void theDirectoryMustBeAnAbsoluteExistingDirectoryAndNotALink(@TempDir Path dir) throws IOException {
        UserPrincipal me = SimulatorGate.processUser();
        assertNotNull(me);

        String relative = SimulatorGate.directoryRefusal(Path.of("ciba-sim"), me);
        assertTrue(relative != null && relative.endsWith("is not an absolute path"), relative);

        String missing = SimulatorGate.directoryRefusal(dir.resolve("absent"), me);
        assertTrue(missing != null && missing.endsWith("does not exist"), missing);

        Path file = Files.writeString(dir.resolve("file"), "x");
        String notADir = SimulatorGate.directoryRefusal(file, me);
        assertTrue(notADir != null && notADir.endsWith("is not a directory"), notADir);

        String unreadable = SimulatorGate.directoryRefusal(file.resolve("below-a-file"), me);
        assertTrue(unreadable != null && unreadable.contains("cannot be read: "), unreadable);

        Path real = Files.createDirectory(dir.resolve("real"));
        Files.setPosixFilePermissions(real, PosixFilePermissions.fromString("rwx------"));
        Path link = Files.createSymbolicLink(dir.resolve("link"), real);
        String symlink = SimulatorGate.directoryRefusal(link, me);
        assertTrue(symlink != null && symlink.endsWith("is a symbolic link"), symlink);
        assertNull(SimulatorGate.directoryRefusal(real, me), "the target itself is fine");
    }

    @Test
    void theDirectoryMustBeOwnedByThisProcessAndPrivateToIt(@TempDir Path dir) throws IOException {
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        UserPrincipal me = SimulatorGate.processUser();
        assertNotNull(me);
        assertEquals(Files.getOwner(dir), me, "the process user is the owner of what it creates");
        assertNull(SimulatorGate.directoryRefusal(dir, me));

        String foreign = SimulatorGate.directoryRefusal(dir, someoneElse(dir));
        assertTrue(foreign != null && foreign.contains("is owned by"), foreign);

        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwxr-x---"));
        String group = SimulatorGate.directoryRefusal(dir, me);
        assertTrue(group != null && group.contains("has mode rwxr-x---"), group);

        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx---rwx"));
        String other = SimulatorGate.directoryRefusal(dir, me);
        assertTrue(other != null && other.contains("has mode rwx---rwx"), other);

        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("r-x------"));
        String readOnly = SimulatorGate.directoryRefusal(dir, me);
        assertTrue(readOnly != null && readOnly.contains("has mode r-x------"), readOnly);
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
    }

    /** A zip filesystem opened without posix attributes has no owner or mode to check; that is a refusal, not a pass. */
    @Test
    void aFilesystemWithoutPosixAttributesIsRefused(@TempDir Path dir) throws IOException {
        UserPrincipal me = SimulatorGate.processUser();
        assertNotNull(me);
        try (FileSystem zip = FileSystems.newFileSystem(dir.resolve("decisions.zip"), Map.of("create", "true"))) {
            Path root = zip.getPath("/");
            assertTrue(Files.isDirectory(root));
            String refusal = SimulatorGate.directoryRefusal(root, me);
            assertTrue(refusal != null && refusal.contains("is not on a POSIX filesystem"), refusal);
        }
    }
}
