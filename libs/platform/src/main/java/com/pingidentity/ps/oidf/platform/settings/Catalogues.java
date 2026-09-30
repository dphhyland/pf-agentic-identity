/*
 * Every settings catalogue a class loader can see.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.io.IOException;
import java.net.JarURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The settings catalogues on a class path, for the start-up sweep ({@link ProfileAudit}) and {@link Preflight}.
 *
 * <p>A catalogue is found two ways, and a name either way finds it: by listing {@value Catalogue#RESOURCE_DIRECTORY}
 * in every jar and directory the loader returns for it, and by name, for each catalogue in the components table
 * ({@link DefaultComponents}) - so a jar written without directory entries still has its catalogues found, as long as
 * the table names them. Each name is then loaded with {@link Catalogue#load} on the same loader. A catalogue that
 * cannot be loaded - two copies that differ, a document the loader refuses - is a {@link Problem}, not an exception:
 * the sweep reports it and goes on with the rest.
 */
public final class Catalogues {

    private static final Pattern FILE = Pattern.compile(Pattern.quote(Catalogue.RESOURCE_DIRECTORY) + "([a-z][a-z0-9]*(?:-[a-z0-9]+)*)\\.json");

    /** A catalogue that was found and could not be loaded, and why. */
    public record Problem(String component, String message) {
    }

    /** What was found: the catalogues that loaded, in name order, and the ones that did not. */
    public record Loaded(List<Catalogue> catalogues, List<Problem> problems) {
        public Loaded {
            catalogues = List.copyOf(catalogues);
            problems = List.copyOf(problems);
        }
    }

    private Catalogues() {
    }

    /** Every catalogue {@code loader} can see. Never throws for a catalogue: see {@link Loaded#problems()}. */
    public static Loaded onClassPath(ClassLoader loader) {
        Set<String> names = new TreeSet<>(DefaultComponents.TABLE.keySet());
        names.addAll(listed(loader));
        List<Catalogue> catalogues = new ArrayList<>();
        List<Problem> problems = new ArrayList<>();
        for (String name : names) {
            if (loader.getResource(Catalogue.RESOURCE_DIRECTORY + name + ".json") == null) {
                continue;
            }
            try {
                catalogues.add(Catalogue.load(loader, name));
            } catch (IllegalArgumentException e) {
                problems.add(new Problem(name, e.getMessage()));
            }
        }
        return new Loaded(catalogues, problems);
    }

    /** The catalogue names in every listing of the directory the loader returns; a listing that cannot be read adds none. */
    static Set<String> listed(ClassLoader loader) {
        Set<String> names = new TreeSet<>();
        Enumeration<URL> directories;
        try {
            directories = loader.getResources(Catalogue.RESOURCE_DIRECTORY);
        } catch (IOException e) {
            return names;
        }
        for (URL directory : Collections.list(directories)) {
            try {
                names.addAll(list(directory));
            } catch (IOException | URISyntaxException | RuntimeException e) {
                // A listing that cannot be read: the table's names still find what it holds.
            }
        }
        return names;
    }

    /** The catalogue names in one listing: a {@code jar:} URL's entries, or a {@code file:} directory's files. */
    static List<String> list(URL directory) throws IOException, URISyntaxException {
        List<String> names = new ArrayList<>();
        if ("jar".equals(directory.getProtocol())) {
            URLConnection connection = directory.openConnection();
            // A connection of its own, so closing the jar never closes one a class loader shares.
            connection.setUseCaches(false);
            try (JarFile jar = ((JarURLConnection) connection).getJarFile()) {
                for (JarEntry entry : Collections.list(jar.entries())) {
                    add(names, entry.getName());
                }
            }
        } else if ("file".equals(directory.getProtocol())) {
            try (DirectoryStream<Path> files = Files.newDirectoryStream(Path.of(directory.toURI()), "*.json")) {
                for (Path file : files) {
                    add(names, Catalogue.RESOURCE_DIRECTORY + file.getFileName());
                }
            }
        }
        return names;
    }

    private static void add(List<String> names, String path) {
        Matcher m = FILE.matcher(path);
        if (m.matches()) {
            names.add(m.group(1));
        }
    }
}
