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
import java.util.TreeSet;
import java.util.regex.Pattern;
import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;

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
 * <p>It judges each violation as the server does ({@link ProfileRefusals#refusedBy}), from the component switches the
 * file sets ({@link ComponentSwitches}): a component switched off is never refused, and a
 * {@code required-in-production} setting left unset refuses only a component switched on. It prints what the server
 * would log - a switch that refuses its component, then every violation labelled as the start-up log labels it
 * ({@link ProfileRefusals#label}), then every warning - and exits 0 when nothing would be refused, 1 when a component
 * would be (under development only a switch that does not parse refuses one; the profile's violations are printed as
 * {@code not refused (development)}), and 2 when the arguments or the file cannot be read.
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
        if (profileName != null) {
            // The switches read the profile from the environment, as the server's do: --profile stands in for the file's.
            env.put(DeploymentProfile.SETTING, profileName);
        }
        Map<String, String> properties = systemProperties(env.get("JAVA_OPTS"));
        DeploymentProfile profile = DeploymentProfile.of(env::get);
        ProfileAudit.Result result = ProfileAudit.evaluate(Sources.of(env, properties), Catalogues.onClassPath(loader), profile,
                AcceptedRisks.of(env::get, today));
        return report(result, ComponentSwitches.of(env::get, properties::get), out);
    }

    /** Prints the result as the server would log it, judged against {@code switches}; answers the exit status. */
    static int report(ProfileAudit.Result result, ComponentSwitches switches, PrintStream out) {
        String profile = result.profile().value();
        int refusing = 0;
        for (String component : new TreeSet<>(ComponentSwitches.SWITCHES.keySet())) {
            ComponentSwitches.Verdict verdict = switches.verdict(component);
            if (verdict.kind() == ComponentSwitches.Kind.FAILED_CONFIG) {
                out.println("REFUSED: " + verdict.note() + " [" + component + "]");
                refusing++;
            }
        }
        int notRefusing = 0;
        for (ProfileAudit.Violation v : result.violations()) {
            boolean refuses = result.refuses() && !ProfileRefusals.refusedBy(v,
                    c -> switches.verdict(c).kind() == ComponentSwitches.Kind.ENABLED,
                    c -> switches.verdict(c).kind() == ComponentSwitches.Kind.DISABLED).isEmpty();
            out.println(ProfileRefusals.label(v, result.profile(), refuses) + v.line());
            if (refuses) {
                refusing++;
            } else {
                notRefusing++;
            }
        }
        for (String warning : result.warnings()) {
            out.println("warning: " + warning);
        }
        if (refusing > 0) {
            out.println(refusing + " line(s) under the " + profile + " profile refuse the components named; each answers 503"
                    + " until it is fixed");
            return REFUSED;
        }
        out.println("clean under the " + profile + " profile: nothing would be refused" + (notRefusing == 0 ? ""
                : " (" + notRefusing + " violation(s) listed that refuse nothing here" + (result.profile().isDevelopment()
                        ? "; the production profile would judge them" : "") + ")"));
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
