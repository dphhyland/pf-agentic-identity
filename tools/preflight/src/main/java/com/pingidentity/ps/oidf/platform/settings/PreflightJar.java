/*
 * The entry point of oidf-preflight.jar.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.CodeSource;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;

/**
 * The entry point of {@code oidf-preflight.jar} (plan item ST-7): {@link Preflight} with every module's settings
 * catalogue beside it in one jar, and two options Preflight does not have.
 *
 * <pre>
 * java -jar oidf-preflight.jar --env-file FILE [--profile production|development] [--accepted-risks IDS]
 * java -jar oidf-preflight.jar --list
 * </pre>
 *
 * <p>Without {@code --accepted-risks} the check is Preflight's own {@link Preflight#run}: the same reading of the file,
 * the same output and the same exit status. {@code --accepted-risks} stands in for the file's
 * {@value AcceptedRisks#SETTING}, as {@code --profile} does for its {@value DeploymentProfile#SETTING}, so an operator
 * can see what accepting a risk would change before editing the file; the check is then Preflight's helpers in
 * Preflight's order, and gives what Preflight gives on the file with that line added. {@code --list} prints every
 * catalogue the jar holds, with its module and its entry counts, and exits 1 when one cannot be loaded.
 *
 * <p>The class sits in platform's package, in a module of its own, because Preflight's {@code run}, {@code report} and
 * file reader are package-private: reusing them keeps the jar's judgement and output Preflight's rather than a copy
 * that could drift from it.
 */
public final class PreflightJar {

    static final String USAGE_LINE = "usage: java -jar oidf-preflight.jar --env-file FILE [--profile production|development]"
            + " [--accepted-risks IDS]" + System.lineSeparator() + "       java -jar oidf-preflight.jar --list";

    private PreflightJar() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err, PreflightJar.class.getClassLoader(), LocalDate.now(ZoneOffset.UTC)));
    }

    /** What {@link #main} does, with its streams, loader and date given; answers the exit status. */
    static int run(String[] args, PrintStream out, PrintStream err, ClassLoader loader, LocalDate today) {
        if (args.length == 1 && "--list".equals(args[0])) {
            return list(Catalogues.onClassPath(loader), about(PreflightJar.class), out);
        }
        String file = null;
        String profile = null;
        String risks = null;
        List<String> preflight = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (i + 1 < args.length && "--accepted-risks".equals(arg)) {
                risks = args[++i];
            } else if (i + 1 < args.length && ("--env-file".equals(arg) || "--profile".equals(arg))) {
                String value = args[++i];
                if ("--env-file".equals(arg)) {
                    file = value;
                } else {
                    profile = value;
                }
                preflight.add(arg);
                preflight.add(value);
            } else {
                err.println(USAGE_LINE);
                return Preflight.USAGE;
            }
        }
        if (file == null || (profile != null && !profile.equals("production") && !profile.equals("development"))) {
            err.println(USAGE_LINE);
            return Preflight.USAGE;
        }
        if (risks == null) {
            return Preflight.run(preflight.toArray(new String[0]), out, err, loader, today);
        }
        return check(file, profile, risks, out, err, loader, today);
    }

    /**
     * Preflight's check of {@code file} with {@code risks} as its {@value AcceptedRisks#SETTING}: its reader, its
     * evaluation and its report, in {@link Preflight#run}'s order and with its messages.
     */
    static int check(String file, String profile, String risks, PrintStream out, PrintStream err, ClassLoader loader,
            LocalDate today) {
        Map<String, String> env;
        try {
            env = Preflight.readEnvFile(Files.readAllLines(Path.of(file), StandardCharsets.UTF_8));
        } catch (IOException | InvalidPathException e) {
            err.println("Preflight: " + file + " cannot be read (" + e.getClass().getSimpleName() + ")");
            return Preflight.USAGE;
        } catch (IllegalArgumentException e) {
            err.println("Preflight: " + file + ": " + e.getMessage());
            return Preflight.USAGE;
        }
        if (profile != null) {
            env.put(DeploymentProfile.SETTING, profile);
        }
        env.put(AcceptedRisks.SETTING, risks);
        Map<String, String> properties = Preflight.systemProperties(env.get("JAVA_OPTS"));
        ProfileAudit.Result result = ProfileAudit.evaluate(Sources.of(env, properties), Catalogues.onClassPath(loader),
                DeploymentProfile.of(env::get), AcceptedRisks.of(env::get, today));
        return Preflight.report(result, ComponentSwitches.of(env::get, properties::get), out);
    }

    /**
     * Prints {@code about}, then one line per catalogue - its name, its module, its settings and removed names - and one
     * per catalogue that could not be loaded; answers 1 when one could not be, 0 otherwise.
     */
    static int list(Catalogues.Loaded loaded, String about, PrintStream out) {
        int settings = 0;
        for (Catalogue catalogue : loaded.catalogues()) {
            settings += catalogue.settings().size();
        }
        out.println(about + ": " + loaded.catalogues().size() + " catalogues, " + settings + " settings");
        for (Catalogue catalogue : loaded.catalogues()) {
            out.println(String.format("  %-28s %-36s %3d settings, %d removed", catalogue.component(), catalogue.module(),
                    catalogue.settings().size(), catalogue.removed().size()));
        }
        for (Catalogues.Problem problem : loaded.problems()) {
            out.println("  cannot load " + problem.component() + ": " + problem.message());
        }
        return loaded.problems().isEmpty() ? Preflight.CLEAN : Preflight.REFUSED;
    }

    /** The version and commit of the jar {@code type} was loaded from, from its manifest. */
    static String about(Class<?> type) {
        CodeSource source = type.getProtectionDomain().getCodeSource();
        URL where = source == null ? null : source.getLocation();
        if (where != null && where.getPath().endsWith(".jar")) {
            try (JarFile jar = new JarFile(Path.of(where.toURI()).toFile())) {
                Manifest manifest = jar.getManifest();
                if (manifest != null) {
                    Attributes main = manifest.getMainAttributes();
                    return "oidf-preflight " + main.getValue("Implementation-Version") + ", commit "
                            + main.getValue("Build-Commit");
                }
            } catch (IOException | URISyntaxException | RuntimeException e) {
                // A jar whose manifest cannot be read says so below; the listing still prints.
            }
        }
        return "oidf-preflight (version unknown: not run from its jar)";
    }
}
