package com.pingidentity.ps.oidf.warassembler;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * pf-runtime.war = the stock PingFederate runtime war + the staged module jars in WEB-INF/lib + the filters
 * and listeners filters.xml declares, registered in its WEB-INF/web.xml. The command line is
 * build/pingfederate/assemble-pf-runtime-war.sh's, with the declaration in front:
 *
 * <pre>
 * java -jar war-assembler.jar --filters FILTERS_XML STOCK_WAR MODULES JOSE4J_JAR OUT_WAR [PROFILE]
 * </pre>
 *
 * <p>Exit 0 with OUT_WAR written; 2 for a usage error (nothing touched); 1 for a refusal, with OUT_WAR
 * deleted - a refusal leaves no war behind, rather than a plausible-looking one with none of this repo's
 * code in it. The war is written to a temporary file beside OUT_WAR, checked there, and moved into place
 * only when every check passed.
 */
final class Assembler {
    static final String USAGE = "usage: war-assembler --filters FILTERS_XML STOCK_WAR MODULES JOSE4J_JAR OUT_WAR [PROFILE]\n"
            + "  MODULES     a directory staged by build/pingfederate/stage-modules.sh (checked against its MANIFEST),\n"
            + "              or a single module jar (the legacy monolith, injected as " + Assembler.MODULE_NAME + ")\n"
            + "  JOSE4J_JAR  a jose4j jar to inject, or - to skip it (PingFederate ships its own; the image skips it)\n"
            + "  PROFILE     production (the default) or conformance; must match the MANIFEST's";
    /** Single-jar mode keeps the WEB-INF/lib entry name the legacy monolith always had. */
    static final String MODULE_NAME = "pf-oidf-modules-0.0.1-SNAPSHOT.jar";
    static final String WEB_XML = "WEB-INF/web.xml";
    static final String LIB = "WEB-INF/lib/";
    static final String CLASSES = "WEB-INF/classes/";

    record Staged(String name, Path path) {
    }

    /** The parts of the stock war the checks need: its descriptor, and the classes it already carries. */
    record Stock(byte[] bytes, byte[] webXml, Set<String> classes) {
    }

    private Assembler() {
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        List<String> a = List.of(args);
        if (a.size() < 6 || a.size() > 7 || !"--filters".equals(a.get(0))) {
            err.println(USAGE);
            return Refusal.USAGE;
        }
        String profile = a.size() == 7 ? a.get(6) : "production";
        if (!"production".equals(profile) && !"conformance".equals(profile)) {
            err.println("ERROR: the profile must be production or conformance, not '" + profile + "'");
            return Refusal.USAGE;
        }
        Path filters = Path.of(a.get(1));
        Path stock = Path.of(a.get(2));
        Path modules = Path.of(a.get(3));
        Path outWar = Path.of(a.get(5)).toAbsolutePath();
        // OUT_WAR is deleted on every way out but success and the same-file refusal - an Error such as
        // OutOfMemoryError included, which propagates after the finally has run.
        boolean keep = false;
        try {
            if (Files.exists(outWar) && Files.isSameFile(stock, outWar)) {
                keep = true;
                err.println("ERROR: STOCK_WAR and OUT_WAR are the same file (" + outWar + "). Write the war somewhere"
                        + " else: a refusal deletes OUT_WAR, and that would be the stock war.");
                return Refusal.USAGE;
            }
            assemble(filters, stock, modules, a.get(4), outWar, profile, out);
            keep = true;
            return 0;
        } catch (Refusal r) {
            err.println(r.getMessage());
            return r.exitCode();
        } catch (IOException | RuntimeException e) {
            err.println("ERROR: " + e);
            return Refusal.REFUSED;
        } finally {
            if (!keep) {
                deleteQuietly(outWar);
            }
        }
    }

    static void assemble(Path filtersXml, Path stockWar, Path modules, String jose4j, Path outWar, String profile,
                         PrintStream out) throws Refusal, IOException {
        out.println("war-assembler " + version() + ", declaration " + filtersXml);
        Declaration declaration = Declaration.parse(Files.readAllBytes(filtersXml), filtersXml.toString());
        List<Staged> staged = stage(modules, jose4j, profile, out);
        Stock stock = readStock(stockWar);
        String what = stockWar.getFileName() + " WEB-INF/web.xml";
        WebXml descriptor = WebXml.parse(stock.webXml(), what);
        guardNamespace(staged, descriptor.namespace(what), stockWar, out);
        Merge.Result merged = Merge.merge(stock.webXml(), descriptor, declaration, what);
        requireClasses(declaration, staged, stock.classes());

        Path temp = Files.createTempFile(outWar.getParent(), "." + outWar.getFileName() + "-", ".tmp");
        try {
            writeWar(stock.bytes(), merged.bytes(), staged, temp);
            copyMode(stockWar, temp);
            WebXml result = verifyWar(temp, staged, declaration, outWar.getFileName().toString());
            merged.notes().forEach(out::println);
            Chains.describe(result, declaration).forEach(out::println);
            moveIntoPlace(temp, outWar);
        } finally {
            Files.deleteIfExists(temp);
        }
        out.println("assembled " + outWar + ":");
        for (Staged s : staged) {
            out.println("  " + LIB + s.name() + " (" + Files.size(s.path()) + " bytes)");
        }
        List<String> names = new ArrayList<>();
        declaration.filters.forEach(f -> names.add(f.name()));
        out.println("verified: " + String.join(" + ", names) + " mapped in " + outWar + " ("
                + declaration.orders.size() + " order rules hold; "
                + (declaration.listeners.isEmpty() ? "no listener declared" : declaration.listeners.size() + " listeners registered")
                + ")");
    }

    /** The jars to inject, each under the name it will have in WEB-INF/lib. */
    static List<Staged> stage(Path modules, String jose4j, String profile, PrintStream out) throws Refusal, IOException {
        List<Staged> staged = new ArrayList<>();
        if (Files.isDirectory(modules)) {
            StagedManifest.Staged checked = StagedManifest.check(modules, profile);
            for (Path p : checked.jars()) {
                staged.add(new Staged(p.getFileName().toString(), p));
            }
            out.println("modules/: " + checked.jars().size() + " jars, matching MANIFEST (" + checked.header() + ")");
        } else if (Files.isRegularFile(modules)) {
            staged.add(new Staged(MODULE_NAME, modules));
        } else {
            throw new Refusal("ERROR: MODULES (" + modules + ") is neither a directory staged by stage-modules.sh nor a jar.");
        }
        if (!"-".equals(jose4j)) {
            Path j = Path.of(jose4j);
            if (!Files.isRegularFile(j)) {
                throw new Refusal("ERROR: JOSE4J_JAR (" + jose4j + ") is not a file; pass - to skip it, as the image build does.");
            }
            staged.add(new Staged(j.getFileName().toString(), j));
        }
        Set<String> names = new HashSet<>();
        for (Staged s : staged) {
            if (!names.add(s.name())) {
                throw new Refusal("ERROR: two jars would both be WEB-INF/lib/" + s.name() + ".");
            }
        }
        staged.sort(Comparator.comparing(Staged::name));
        return staged;
    }

    static Stock readStock(Path stockWar) throws Refusal, IOException {
        byte[] bytes = Files.readAllBytes(stockWar);
        byte[] webXml = null;
        Set<String> classes = new HashSet<>();
        try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            for (ZipEntry e; (e = in.getNextEntry()) != null; ) {
                String name = e.getName();
                if (WEB_XML.equals(name)) {
                    webXml = in.readAllBytes();
                } else if (name.startsWith(CLASSES) && name.endsWith(".class")) {
                    classes.add(name.substring(CLASSES.length(), name.length() - ".class".length()).replace('/', '.'));
                } else if (name.startsWith(LIB) && name.endsWith(".jar")) {
                    Jars.classes(new ByteArrayInputStream(in.readAllBytes()), classes);
                }
            }
        }
        if (webXml == null) {
            throw new Refusal("ERROR: " + stockWar + " has no WEB-INF/web.xml - it is not PingFederate's pf-runtime.war.");
        }
        return new Stock(bytes, webXml, classes);
    }

    /**
     * The stock war's own descriptor decides which servlet namespace this PingFederate speaks (jakartaee 5.0
     * on 13.1.x, javaee 3.1 on 13.0.x), so this needs no flag. A module compiled against the other one
     * assembles into a well-formed war and fails only at boot: a filter named in web.xml kills the whole war
     * (a 503 on every endpoint), and an @WebServlet under the other annotation is never mapped at all (a
     * silent 404). The MANIFEST check cannot see it - it compares the directory with itself, not with the
     * PingFederate it is going into - which is the shape of the accident this guards: a new base image and a
     * git-ignored modules/ still holding jars built for the old one.
     */
    static void guardNamespace(List<Staged> staged, String namespace, Path stockWar, PrintStream out)
            throws Refusal, IOException {
        String other = "jakarta".equals(namespace) ? "javax" : "jakarta";
        List<String> wrong = new ArrayList<>();
        for (Staged s : staged) {
            if (Jars.references(Files.readAllBytes(s.path()), other + "/servlet/", s.name())) {
                wrong.add(s.name());
            }
        }
        if (!wrong.isEmpty()) {
            throw new Refusal("ERROR: " + stockWar.getFileName() + " speaks " + namespace + ".servlet, but these staged jars are compiled\n"
                    + "       against " + other + ".servlet: " + String.join(" ", wrong) + "\n"
                    + "       A war built from them boots to a 503 (filters) or silently 404s (servlets). Rebuild the\n"
                    + "       modules against the matching PingFederate line, or stage a set that was - see\n"
                    + "       docs/pf-13_1-jakarta-migration-plan.md.");
        }
        out.println("namespace: " + namespace + ".servlet (per the stock war); no staged jar references " + other + ".servlet");
    }

    /**
     * Every declared filter's and listener's class is in the war - in a staged jar or one the stock war
     * already carries. A class named in web.xml that is not there fails the whole war at boot.
     */
    static void requireClasses(Declaration declaration, List<Staged> staged, Set<String> stockClasses)
            throws Refusal, IOException {
        Set<String> classes = new HashSet<>(stockClasses);
        for (Staged s : staged) {
            try (var in = Files.newInputStream(s.path())) {
                Jars.classes(in, classes);
            }
        }
        List<String> absent = new ArrayList<>();
        for (Declaration.Filter f : declaration.filters) {
            if (!classes.contains(f.className())) {
                absent.add("the filter " + f.name() + " (" + f.className() + ")");
            }
        }
        for (String l : declaration.listeners) {
            if (!classes.contains(l)) {
                absent.add("the listener " + l);
            }
        }
        if (!absent.isEmpty()) {
            throw new Refusal("ERROR: filters.xml declares classes no jar in the war holds: " + String.join("; ", absent)
                    + ". PingFederate would fail to start the war and answer 503 on every endpoint. Stage the module"
                    + " that has them, or correct the declaration.");
        }
    }

    /**
     * The stock war's entries in their order, with WEB-INF/web.xml replaced and any entry a staged jar
     * replaces left out, then the staged jars in name order. Entry times are kept, so assembling the output
     * again writes the same bytes.
     */
    static void writeWar(byte[] stock, byte[] webXml, List<Staged> staged, Path target) throws IOException {
        Set<String> replaced = new HashSet<>();
        TreeMap<String, Staged> added = new TreeMap<>();
        for (Staged s : staged) {
            replaced.add(LIB + s.name());
            added.put(LIB + s.name(), s);
        }
        try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(stock));
             OutputStream file = Files.newOutputStream(target);
             ZipOutputStream zip = new ZipOutputStream(file)) {
            for (ZipEntry e; (e = in.getNextEntry()) != null; ) {
                if (replaced.contains(e.getName())) {
                    continue;
                }
                byte[] data = WEB_XML.equals(e.getName()) ? webXml : in.readAllBytes();
                put(zip, e.getName(), e.getTime(), e.getMethod(), data);
            }
            for (var entry : added.entrySet()) {
                Path p = entry.getValue().path();
                put(zip, entry.getKey(), Files.getLastModifiedTime(p).toMillis(), ZipEntry.DEFLATED, Files.readAllBytes(p));
            }
        }
    }

    private static void put(ZipOutputStream zip, String name, long time, int method, byte[] data) throws IOException {
        ZipEntry n = new ZipEntry(name);
        n.setTime(time);
        if (method == ZipEntry.STORED) {
            CRC32 crc = new CRC32();
            crc.update(data);
            n.setMethod(ZipEntry.STORED);
            n.setSize(data.length);
            n.setCompressedSize(data.length);
            n.setCrc(crc.getValue());
        } else {
            n.setMethod(ZipEntry.DEFLATED);
        }
        zip.putNextEntry(n);
        zip.write(data);
        zip.closeEntry();
    }

    /** Reads back what was written: every staged jar is in it, and its descriptor passes {@link Merge#verify}. */
    static WebXml verifyWar(Path war, List<Staged> staged, Declaration declaration, String warName)
            throws Refusal, IOException {
        Set<String> entries = new HashSet<>();
        byte[] webXml = null;
        try (ZipInputStream in = new ZipInputStream(Files.newInputStream(war))) {
            for (ZipEntry e; (e = in.getNextEntry()) != null; ) {
                entries.add(e.getName());
                if (WEB_XML.equals(e.getName())) {
                    webXml = in.readAllBytes();
                }
            }
        }
        for (Staged s : staged) {
            if (!entries.contains(LIB + s.name())) {
                throw new Refusal("ERROR: module jar " + s.name() + " not present in " + warName);
            }
        }
        if (webXml == null) {
            throw new Refusal("ERROR: " + warName + " has no WEB-INF/web.xml after assembly");
        }
        WebXml result = WebXml.parse(webXml, warName + " WEB-INF/web.xml");
        Merge.verify(result, declaration, warName + " WEB-INF/web.xml");
        return result;
    }

    static String version() {
        String version = Assembler.class.getPackage().getImplementationVersion();
        return version == null ? "(unpackaged)" : version;
    }

    /** Atomically where the file system can; the temporary file is always in OUT_WAR's own directory. */
    static void moveIntoPlace(Path temp, Path outWar) throws IOException {
        try {
            Files.move(temp, outWar, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(temp, outWar, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /**
     * The stock war's permissions, less group and other write - what the shell assembler's `cp` gave under
     * the usual umask 022 (0640 from the image's 0660), rather than the temporary file's 0600, which a
     * container run under another uid in group 0 could not read.
     */
    static void copyMode(Path from, Path to) throws IOException {
        if (!Files.getFileStore(to).supportsFileAttributeView(PosixFileAttributeView.class)) {
            return;
        }
        Set<PosixFilePermission> mode = new HashSet<>(Files.getPosixFilePermissions(from));
        mode.remove(PosixFilePermission.GROUP_WRITE);
        mode.remove(PosixFilePermission.OTHERS_WRITE);
        Files.setPosixFilePermissions(to, mode);
    }

    private static void deleteQuietly(Path p) {
        try {
            Files.deleteIfExists(p);
        } catch (IOException ignored) {
            // Nothing more can be done; the refusal is already printed.
        }
    }
}
