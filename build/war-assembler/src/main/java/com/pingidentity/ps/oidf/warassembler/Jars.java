package com.pingidentity.ps.oidf.warassembler;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** What is inside a jar, read from its bytes. */
final class Jars {
    private Jars() {
    }

    /**
     * Whether any class file in the jar mentions {@code needle} - a constant-pool reference such as
     * {@code javax/servlet/} is stored as those bytes. This is the namespace guard's test: a jar compiled
     * against the other servlet namespace names that namespace's classes.
     */
    static boolean references(byte[] jar, String needle, String what) throws Refusal {
        byte[] n = needle.getBytes(StandardCharsets.US_ASCII);
        try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(jar))) {
            boolean anyEntry = false;
            for (ZipEntry e; (e = in.getNextEntry()) != null; ) {
                anyEntry = true;
                if (e.getName().endsWith(".class") && contains(in.readAllBytes(), n)) {
                    return true;
                }
            }
            if (!anyEntry) {
                throw new Refusal("ERROR: " + what + " is not a jar (no zip entry could be read from it).");
            }
            return false;
        } catch (IOException e) {
            throw new Refusal("ERROR: " + what + " is not a readable jar: " + e.getMessage());
        }
    }

    /** Adds the binary name of every class file in the jar ({@code a.b.C}) to {@code classes}. */
    static void classes(InputStream jar, Set<String> classes) throws IOException {
        ZipInputStream in = new ZipInputStream(jar);
        for (ZipEntry e; (e = in.getNextEntry()) != null; ) {
            String name = e.getName();
            if (name.endsWith(".class")) {
                classes.add(name.substring(0, name.length() - ".class".length()).replace('/', '.'));
            }
        }
    }

    static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}
