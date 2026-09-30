/*
 * The start-up sweep, run on an env file before a deployment.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;

/**
 * The start-up sweep ({@link ProfileAudit}) on an environment file, before it reaches a deployment (plan item ST-7's
 * mechanism; ST7 packages it as {@code oidf-preflight.jar} with every catalogue):
 *
 * <pre>
 * java -cp '&lt;jars&gt;/*' com.pingidentity.ps.oidf.platform.settings.Preflight --env-file FILE [--profile production]
 * </pre>
 *
 * <p>The catalogues are the ones on the class path ({@link Catalogues#onClassPath}): point {@code -cp} at the jars of
 * the release being deployed. The file is {@code NAME=value} lines - blank lines and {@code #} comments skipped, an
 * {@code export } before the name allowed, one pair of matching quotes around the value removed - and a
 * {@code JAVA_OPTS} line's {@code -Dname=value} words are read as system properties. The profile is the file's
 * {@code OIDF_DEPLOYMENT_PROFILE}, read as the server reads it, unless {@code --profile} names one.
 *
 * <p>It prints what the server would log - every violation, then every warning - and exits 0 when nothing would be
 * refused, 1 when the production profile would refuse something (development refuses nothing, so there it exits 0
 * and prints the violations as warnings), and 2 when the arguments or the file cannot be read.
 */
public final class Preflight {

    /** Exit status: nothing would be refused. */
    public static final int CLEAN = 0;
    /** Exit status: the production profile would refuse at least one component. */
    public static final int REFUSED = 1;
    /** Exit status: the arguments or the file could not be read. */
    public static final int USAGE = 2;

    private static final String USAGE_LINE = "usage: Preflight --env-file FILE [--profile production|development]";
    private static final Pattern NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*");

    private Preflight() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err, Preflight.class.getClassLoader(), LocalDate.now(ZoneOffset.UTC)));
    }

    /** What {@link #main} does, with its streams, loader and date given; answers the exit status. */
    static int run(String[] args, PrintStream out, PrintStream err, ClassLoader loader, LocalDate today) {
        String file = null;
        String profileName = null;
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (i + 1 < args.length && "--env-file".equals(arg)) {
                file = args[++i];
            } else if (i + 1 < args.length && "--profile".equals(arg)) {
                profileName = args[++i];
            } else {
                err.println(USAGE_LINE);
                return USAGE;
            }
        }
        if (file == null || (profileName != null && !profileName.equals("production") && !profileName.equals("development"))) {
            err.println(USAGE_LINE);
            return USAGE;
        }
        Map<String, String> env;
        try {
            env = readEnvFile(Files.readAllLines(Path.of(file), StandardCharsets.UTF_8));
        } catch (IOException | InvalidPathException e) {
            err.println("Preflight: " + file + " cannot be read (" + e.getClass().getSimpleName() + ")");
            return USAGE;
        } catch (IllegalArgumentException e) {
            err.println("Preflight: " + file + ": " + e.getMessage());
            return USAGE;
        }
        Map<String, String> properties = systemProperties(env.get("JAVA_OPTS"));
        DeploymentProfile profile = profileName != null ? DeploymentProfile.parse(profileName) : DeploymentProfile.of(env::get);
        ProfileAudit.Result result = ProfileAudit.evaluate(Sources.of(env, properties), Catalogues.onClassPath(loader), profile,
                AcceptedRisks.of(env::get, today));
        return report(result, out);
    }

    /** Prints the result as the server would log it; answers the exit status. */
    static int report(ProfileAudit.Result result, PrintStream out) {
        String profile = result.profile().value();
        for (ProfileAudit.Violation v : result.violations()) {
            out.println((result.refuses() ? "REFUSED: " : "warning: ") + v.line());
        }
        for (String warning : result.warnings()) {
            out.println("warning: " + warning);
        }
        if (result.refuses()) {
            out.println(result.violations().size() + " violation(s) under the " + profile + " profile: the components named"
                    + " would be refused");
            return REFUSED;
        }
        out.println("clean under the " + profile + " profile: nothing would be refused" + (result.violations().isEmpty() ? ""
                : " (" + result.violations().size() + " violation(s) the production profile would refuse)"));
        return CLEAN;
    }

    /**
     * An env file's names and values, in order: blank lines and {@code #} comments skipped, {@code export } allowed
     * before a name, one pair of matching quotes around a value removed; a name set twice keeps the last value, as a
     * shell's would.
     *
     * @throws IllegalArgumentException naming the line, for one that is not {@code NAME=value}
     */
    static Map<String, String> readEnvFile(List<String> lines) {
        Map<String, String> env = new LinkedHashMap<>();
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).strip();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            if (line.startsWith("export ")) {
                line = line.substring("export ".length()).strip();
            }
            int equals = line.indexOf('=');
            String name = equals < 0 ? line : line.substring(0, equals).strip();
            if (equals < 0 || !NAME.matcher(name).matches()) {
                throw new IllegalArgumentException("line " + (i + 1) + " is not NAME=value");
            }
            env.put(name, unquote(line.substring(equals + 1).strip()));
        }
        return env;
    }

    /** A value without one pair of matching quotes around it. */
    static String unquote(String value) {
        if (value.length() >= 2 && (value.charAt(0) == '"' || value.charAt(0) == '\'')
                && value.charAt(value.length() - 1) == value.charAt(0)) {
            return value.substring(1, value.length() - 1);
        }
        return value;
    }

    /**
     * The {@code -Dname=value} (or {@code -Dname}, an empty value) words of a {@code JAVA_OPTS} value, split at
     * whitespace, each word unquoted as a value is.
     */
    static Map<String, String> systemProperties(String javaOpts) {
        Map<String, String> properties = new LinkedHashMap<>();
        if (javaOpts == null) {
            return properties;
        }
        for (String raw : javaOpts.trim().split("\\s+")) {
            String word = unquote(raw);
            if (word.startsWith("-D") && word.length() > 2) {
                String definition = word.substring(2);
                int equals = definition.indexOf('=');
                properties.put(equals < 0 ? definition : definition.substring(0, equals),
                        equals < 0 ? "" : definition.substring(equals + 1));
            }
        }
        return properties;
    }
}
