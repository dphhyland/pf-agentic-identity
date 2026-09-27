/*
 * The shared vector file, and the library's reading of each case.
 */
package com.pingidentity.ps.oidf.rar.model;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reads {@value #RESOURCE}, the one set of named containment cases, and runs a case through the
 * library. This class ships in the module's test-jar so the other runners the plan names (the
 * authenticator, the issuer, the refresh path) can read the same cases: {@link #load()} gives them the
 * cases, {@link #run} is the library's own answer to one, and {@link #canonical} is how an expectation
 * is compared - as canonical JSON, so member order and number spelling do not matter.
 *
 * <p>A case has an {@code op} ({@code contains}, {@code authorize}, {@code intersect}, {@code validate},
 * {@code details}, {@code fullCeiling}, {@code load}, {@code fingerprint}), the lists that op takes,
 * an optional {@code models} ({@code development} and/or a {@code document}; the default is the
 * built-ins with production semantics) and an {@code expect}: {@code true}/{@code false}, {@code "ok"},
 * {@code {"refused": REASON}}, {@code {"granted": [...]}}, {@code {"intersection": [...]}},
 * {@code {"types": [...]}} (a subset of the model's types) or {@code {"fingerprint": "..."}}.
 */
public final class Vectors {

    public static final String RESOURCE = "/rar-model-vectors.json";

    private Vectors() {
    }

    /** One case, as read from the file. */
    public record Case(String name, String op, List<String> requirements, Map<String, Object> raw) {

        public Object expect() {
            return raw.get("expect");
        }

        public Omission mode() {
            Object m = raw.get("mode");
            return m == null ? null : Omission.valueOf((String) m);
        }

        /** A list the case names, or {@code null} when it does not; entries are whatever the file says. */
        public Object list(String key) {
            return raw.get(key);
        }

        /** The models the case runs against. */
        public RarModels models() throws RarModelException {
            Object spec = raw.get("models");
            if (spec == null) {
                return RarModels.builtIn();
            }
            Map<?, ?> m = (Map<?, ?>) spec;
            boolean development = Boolean.TRUE.equals(m.get("development"));
            Object document = m.get("document");
            return RarModels.load(document == null ? null : Json.write(document), development);
        }

        /** The reason the case expects, or {@code null} when it expects a result. */
        public RarModelException.Reason expectedRefusal() {
            if (expect() instanceof Map<?, ?> m && m.get("refused") instanceof String r) {
                return RarModelException.Reason.valueOf(r);
            }
            return null;
        }
    }

    /** What running a case produced: a value, or a refusal. */
    public record Outcome(Object value, RarModelException.Reason refused) {
        static Outcome of(Object value) {
            return new Outcome(value, null);
        }

        static Outcome refusal(RarModelException e) {
            return new Outcome(null, e.reason());
        }
    }

    /** Every case in the file, in order. */
    public static List<Case> load() {
        String text;
        try (InputStream in = Vectors.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException(RESOURCE + " is not on the classpath");
            }
            text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException(RESOURCE + " could not be read", e);
        }
        Map<?, ?> doc = (Map<?, ?>) Json.parse(text);
        List<Case> out = new ArrayList<>();
        Set<String> names = new java.util.HashSet<>();
        for (Object item : (List<?>) doc.get("cases")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> raw = (Map<String, Object>) item;
            String name = (String) raw.get("name");
            if (!names.add(name)) {
                throw new IllegalStateException("duplicate case name: " + name);
            }
            @SuppressWarnings("unchecked")
            List<String> reqs = raw.get("requirements") == null ? List.of() : (List<String>) raw.get("requirements");
            out.add(new Case(name, (String) raw.get("op"), Collections.unmodifiableList(reqs), raw));
        }
        return out;
    }

    /** The library's answer to a case. */
    public static Outcome run(Case c) {
        try {
            RarModels models = c.models();
            switch (c.op()) {
                case "contains":
                    return Outcome.of(models.contains(details(c.list("ceiling")), details(c.list("candidate"))));
                case "authorize":
                    return Outcome.of(models.authorize(details(c.list("candidate")), details(c.list("ceiling")), c.mode()));
                case "intersect":
                    return Outcome.of(models.intersect(details(c.list("a")), details(c.list("b"))));
                case "validate":
                    models.validate(details(c.list("details")), "details");
                    return Outcome.of("ok");
                case "details":
                    RarModels.details(c.list("details"));
                    return Outcome.of("ok");
                case "fullCeiling":
                    return Outcome.of(models.fullCeiling(details(c.list("ceiling"))));
                case "load":
                    return Outcome.of(new ArrayList<>(models.types()));
                case "fingerprint":
                    return Outcome.of(models.fingerprint());
                default:
                    throw new IllegalStateException("unknown op '" + c.op() + "' in case '" + c.name() + "'");
            }
        } catch (RarModelException e) {
            return Outcome.refusal(e);
        }
    }

    /**
     * Runs a case and explains the first way its outcome differs from its expectation, or returns
     * {@code null} when it matches.
     */
    public static String mismatch(Case c) {
        Outcome actual = run(c);
        RarModelException.Reason expectedRefusal = c.expectedRefusal();
        if (expectedRefusal != null) {
            if (actual.refused() != expectedRefusal) {
                return "expected refusal " + expectedRefusal + " but got "
                        + (actual.refused() == null ? "result " + canonical(actual.value()) : "refusal " + actual.refused());
            }
            return null;
        }
        if (actual.refused() != null) {
            return "expected " + canonical(c.expect()) + " but was refused: " + actual.refused();
        }
        Object expect = c.expect();
        if (expect instanceof Map<?, ?> m) {
            if (m.containsKey("granted") || m.containsKey("intersection")) {
                Object want = m.containsKey("granted") ? m.get("granted") : m.get("intersection");
                return same(want, actual.value());
            }
            if (m.containsKey("types")) {
                List<?> have = (List<?>) actual.value();
                for (Object t : (List<?>) m.get("types")) {
                    if (!have.contains(t)) {
                        return "expected type " + t + " among " + have;
                    }
                }
                return null;
            }
            if (m.containsKey("fingerprint")) {
                return same(m.get("fingerprint"), actual.value());
            }
            return "unrecognised expectation " + canonical(expect);
        }
        return same(expect, actual.value());
    }

    private static String same(Object want, Object have) {
        String w = canonical(want);
        String h = canonical(have);
        return w.equals(h) ? null : "expected " + w + " but got " + h;
    }

    /** A value as canonical JSON, the form expectations are compared in. */
    public static String canonical(Object value) {
        return Json.write(value);
    }

    /** A list as the file gives it, as details. Refusals propagate as the op's own refusal would. */
    private static List<Map<String, Object>> details(Object raw) throws RarModelException {
        return RarModels.details(raw);
    }
}
