/*
 * The production profile's verdict on a process's settings, from the catalogues.
 */
package com.pingidentity.ps.oidf.platform.settings;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisk;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;

/**
 * Plan item PR-5: every governed setting, evaluated from the catalogues at start-up. {@link #evaluate} reads each
 * {@code env} and {@code system-property} entry whose profile class is not {@code any} from a process's sources and
 * gives a {@link Violation} for each of these:
 *
 * <ul>
 *   <li>{@link Kind#FORBIDDEN} - a {@code forbidden-in-production} entry set to a value it governs
 *       ({@link Setting#governed()});</li>
 *   <li>{@link Kind#ACCEPTED_RISK} - an {@code accepted-risk:<id>} entry set to a value it governs, with the risk not
 *       accepted in {@value AcceptedRisks#SETTING};</li>
 *   <li>{@link Kind#REQUIRED} - a {@code required-in-production} entry unset or blank;</li>
 *   <li>{@link Kind#UNREADABLE} - a forbidden or accepted-risk entry set to something that does not parse (a legacy
 *       spelling in production included), or that its resolver refuses: the profile cannot tell whether it asks for
 *       the governed value, so it is refused as if it did;</li>
 *   <li>{@link Kind#UNKNOWN_KEY} - an {@code OIDF_*} environment variable under a catalogue's family that no
 *       catalogue declares ({@link UnknownKeys}; Phase 3 plan, decision 5);</li>
 *   <li>{@link Kind#CATALOGUE} - a catalogue that could not be loaded, so its settings cannot be judged.</li>
 * </ul>
 *
 * <p>Each names the setting, the reason, the fix (the risk id to accept, or the switch to change) and the components
 * it refuses: the entry's, else its catalogue's ({@link Catalogue#componentsOf}). The evaluation is the same in both
 * profiles; the {@link Result} says whether it refuses: under development nothing does, and every violation is a
 * warning. A value a violation quotes is a {@code bool}'s or a {@code choice}'s only: a URL, a path or a secret is
 * never repeated. An {@code OIDF_*} name under no family, and each refused {@value AcceptedRisks#SETTING} entry, is a
 * warning, never a violation: the entry's risk is simply not accepted.
 *
 * <p>{@link #atRead} is the same rule for what the start-up sweep cannot see - an {@code init-param}, a
 * {@code plugin-field}, an {@code extended-property} - which {@link Settings} applies when one is read.
 */
public final class ProfileAudit {

    /** What a violation is. */
    public enum Kind {
        /** A forbidden switch set to a governed value. */
        FORBIDDEN,
        /** A risky switch set to a governed value, the risk not accepted. */
        ACCEPTED_RISK,
        /** A required setting unset or blank. */
        REQUIRED,
        /** A governed setting whose value cannot be read. */
        UNREADABLE,
        /** An {@code OIDF_*} name under a family that nothing declares. */
        UNKNOWN_KEY,
        /** A catalogue that could not be loaded. */
        CATALOGUE,
        /** A condition that is not a setting, refused in code ({@code ProfileRefusals.refuse}). */
        CODE
    }

    /**
     * One violation of the production profile.
     *
     * @param kind       what it is
     * @param setting    the setting, the unknown name, the catalogue, or what code refused
     * @param reason     why, naming the setting
     * @param fix        how to put it right: the risk to accept, or the switch to change
     * @param components the components it refuses, by S-9's names; empty when it refuses none it can name
     */
    public record Violation(Kind kind, String setting, String reason, String fix, List<String> components) {
        public Violation {
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(setting, "setting");
            Objects.requireNonNull(reason, "reason");
            Objects.requireNonNull(fix, "fix");
            components = List.copyOf(components);
        }

        /** The reason and the fix as one sentence. */
        public String message() {
            return this.reason + ". " + this.fix;
        }

        /** The whole line a log and the banner give: the message and what it refuses. */
        public String line() {
            return message() + " [" + (this.components.isEmpty() ? "no component" : String.join(", ", this.components)) + "]";
        }
    }

    /**
     * What the sweep found.
     *
     * @param profile    the profile it judged under
     * @param violations every violation, in catalogue order and then unknown names in name order
     * @param warnings   what is reported and refuses nothing: an {@code OIDF_*} name under no family, a refused
     *                   {@value AcceptedRisks#SETTING} entry, a legacy spelling read in development
     */
    public record Result(DeploymentProfile profile, List<Violation> violations, List<String> warnings) {
        public Result {
            Objects.requireNonNull(profile, "profile");
            violations = List.copyOf(violations);
            warnings = List.copyOf(warnings);
        }

        /** Nothing found, under {@code profile}. */
        public static Result empty(DeploymentProfile profile) {
            return new Result(profile, List.of(), List.of());
        }

        /** Whether it refuses anything: a violation, under the production profile. */
        public boolean refuses() {
            return this.profile.isProduction() && !this.violations.isEmpty();
        }

        /** The violations that name {@code component}. */
        public List<Violation> of(String component) {
            List<Violation> out = new ArrayList<>();
            for (Violation v : this.violations) {
                if (v.components().contains(component)) {
                    out.add(v);
                }
            }
            return out;
        }
    }

    private ProfileAudit() {
    }

    /** {@link #evaluate(Sources, Catalogues.Loaded, DeploymentProfile, AcceptedRisks)} for catalogues that all loaded. */
    public static Result evaluate(Sources sources, Collection<Catalogue> catalogues, DeploymentProfile profile, AcceptedRisks risks) {
        return evaluate(sources, new Catalogues.Loaded(new ArrayList<>(catalogues), List.of()), profile, risks);
    }

    /**
     * Every violation {@code sources} commits against {@code catalogues}, judged under {@code profile} with
     * {@code risks} accepted. Never throws for a setting: what a resolver refuses is an {@link Kind#UNREADABLE}
     * violation of a governed entry, and nothing for an entry that is not.
     */
    public static Result evaluate(Sources sources, Catalogues.Loaded catalogues, DeploymentProfile profile, AcceptedRisks risks) {
        Objects.requireNonNull(sources, "sources");
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(risks, "risks");
        List<Violation> violations = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        for (Catalogues.Problem problem : catalogues.problems()) {
            violations.add(new Violation(Kind.CATALOGUE, problem.component(), "The settings catalogue " + problem.component()
                    + " could not be loaded (" + problem.message() + "), so its settings cannot be checked against the"
                    + " production profile", "Deploy one copy of the module that ships it",
                    DefaultComponents.of(problem.component())));
        }
        for (Catalogue catalogue : catalogues.catalogues()) {
            for (Setting setting : catalogue.settings()) {
                if (setting.profile().kind() == ProfileClass.Kind.ANY
                        || (setting.kind() != EntryKind.ENV && setting.kind() != EntryKind.SYSTEM_PROPERTY)) {
                    continue;
                }
                Violation v = judge(setting, catalogue.componentsOf(setting), sources, profile, risks, warnings);
                if (v != null) {
                    violations.add(v);
                }
            }
        }
        unknown(sources.environmentNames(), catalogues.catalogues(), violations, warnings);
        for (String refusal : risks.refusals()) {
            warnings.add(refusal + " - that risk is not accepted");
        }
        return new Result(profile, violations, warnings);
    }

    /** One classed env or system-property entry, read from {@code sources}; null when it violates nothing. */
    static Violation judge(Setting setting, List<String> components, Sources sources, DeploymentProfile profile,
            AcceptedRisks risks, List<String> warnings) {
        if (presentButBlank(setting, sources)) {
            return governedViolation(setting, "", components, risks);
        }
        Setting.Raw raw;
        try {
            raw = setting.resolveRaw(sources);
        } catch (SettingRefused refused) {
            return setting.governed() == null ? null : unreadable(setting, refused, components);
        }
        boolean set = raw.provenance().source() != Source.DEFAULT;
        if (setting.profile().kind() == ProfileClass.Kind.REQUIRED_IN_PRODUCTION) {
            return set ? null : new Violation(Kind.REQUIRED, setting.name(), setting.name() + " is unset, and the production"
                    + " profile requires it (" + setting.description() + ")", "Set " + name(setting) + developmentEscape(),
                    components);
        }
        if (!set) {
            return null;
        }
        String value = raw.value();
        boolean governed;
        try {
            governed = setting.governed().matches(setting, value);
        } catch (SettingRefused refused) {
            Object old = profile.isDevelopment() ? setting.legacy(value) : null;
            if (old == null) {
                return unreadable(setting, refused, components);
            }
            warnings.add(setting.name() + " is '" + value + "', a legacy spelling read as " + old + " under the development"
                    + " profile; write " + old);
            value = String.valueOf(old);
            governed = setting.governed().matches(setting, value);
        }
        return governed ? governedViolation(setting, value, components, risks) : null;
    }

    /**
     * Whether {@code setting} is a system property governed for any value and set, but blank. A resolver takes blank
     * for unset; the JDK does not - it reads {@code -Djdk.internal.httpclient.disableHostnameVerification} with an
     * empty value as the check turned off - so for a system property whose mere presence the profile forbids, blank
     * is present.
     */
    static boolean presentButBlank(Setting setting, Sources sources) {
        if (setting.kind() != EntryKind.SYSTEM_PROPERTY || setting.governed() == null
                || setting.governed().form() != Governed.Form.ANY_VALUE) {
            return false;
        }
        String value = sources.get(Source.SYSTEM_PROPERTY, setting.name());
        return value != null && value.isBlank();
    }

    /**
     * The read-time rule, for a value the start-up sweep cannot see: an {@code init-param} (an entry of that kind, or
     * any entry whose value came from one), a {@code plugin-field}, an {@code extended-property}. Under the production
     * profile, a value the entry governs without its risk accepted is a violation. Null for anything else -
     * development, an entry classed {@code any} or {@code required-in-production}, a value the entry does not govern,
     * or one that does not parse (its parser refuses it).
     */
    public static Violation atRead(Setting setting, String raw, List<String> components, DeploymentProfile profile,
            AcceptedRisks risks) {
        String value = Parsers.blankToNull(raw);
        if (profile.isDevelopment() || value == null || setting.governed() == null) {
            return null;
        }
        try {
            return setting.governed().matches(setting, value) ? governedViolation(setting, value, components, risks) : null;
        } catch (SettingRefused refused) {
            return null;
        }
    }

    /** A governed value set: forbidden, or needing a risk that is not accepted; null when the risk is accepted. */
    static Violation governedViolation(Setting setting, String value, List<String> components, AcceptedRisks risks) {
        String what = setting.name() + (quotable(setting) ? "=" + setting.parse(value)
                : setting.governed().form() == Governed.Form.SCHEMES ? " is " + setting.governed().describe() : " is set");
        if (setting.profile().kind() == ProfileClass.Kind.FORBIDDEN_IN_PRODUCTION) {
            return new Violation(Kind.FORBIDDEN, setting.name(), what + ", which the production profile forbids ("
                    + setting.description() + ")", undo(setting) + developmentEscape(), components);
        }
        String id = setting.profile().riskId();
        AcceptedRisk risk = AcceptedRisk.byId(id);
        if (risk != null && risks.accepts(risk)) {
            return null;
        }
        String accept = risk == null ? "No release accepts '" + id + "'; " + undo(setting)
                : "Accept the risk by adding " + id + (risk.dated() ? "@YYYY-MM-DD" : "") + " to " + AcceptedRisks.SETTING
                        + ", or " + lowerFirst(undo(setting));
        return new Violation(Kind.ACCEPTED_RISK, setting.name(), what + ", which the production profile allows only with the"
                + " risk '" + id + "' accepted" + (risk == null ? "" : " (" + risk.description() + ")"), accept, components);
    }

    private static Violation unreadable(Setting setting, SettingRefused refused, List<String> components) {
        String because = setting.type() == SettingType.SECRET ? "its value was refused" : refused.getMessage();
        return new Violation(Kind.UNREADABLE, setting.name(), setting.name() + " cannot be read (" + because + "), so the"
                + " production profile cannot tell whether it asks for " + setting.governed().describe() + ", which it"
                + " governs", "Write " + name(setting) + " as its type reads it" + (setting.type() == SettingType.BOOL
                        ? ": true or false" : "") + developmentEscape(), components);
    }

    /** The unknown names under a family, and a warning for each {@code OIDF_*} name under none that nothing declares. */
    static void unknown(Set<String> names, List<Catalogue> catalogues, List<Violation> violations, List<String> warnings) {
        Set<String> declared = new LinkedHashSet<>();
        for (Catalogue catalogue : catalogues) {
            declared.addAll(catalogue.declaredEnvironmentNames());
        }
        Set<String> unknown = new LinkedHashSet<>(UnknownKeys.find(names, catalogues));
        for (String name : unknown) {
            Set<String> components = new LinkedHashSet<>();
            List<String> families = new ArrayList<>();
            for (Catalogue catalogue : catalogues) {
                for (String family : catalogue.families()) {
                    if (name.startsWith(family)) {
                        components.addAll(catalogue.components());
                        if (!families.contains(family)) {
                            families.add(family);
                        }
                    }
                }
            }
            violations.add(new Violation(Kind.UNKNOWN_KEY, name, name + " is set, under the " + String.join(" and ", families)
                    + " famil" + (families.size() == 1 ? "y" : "ies") + ", and no settings catalogue declares it",
                    "Correct the name - a misspelling is the usual cause - or unset it; the configuration reference"
                            + " (docs/configuration) lists every name" + developmentEscape(), new ArrayList<>(components)));
        }
        for (String name : names) {
            if (name.startsWith("OIDF_") && !declared.contains(name) && !unknown.contains(name)) {
                warnings.add(name + " is set and no settings catalogue declares it; it is under no catalogue's family, so"
                        + " nothing refuses it - check the spelling");
            }
        }
    }

    /** Whether a violation may repeat the value: a switch's or a choice's, never text, a URL, a path or a secret. */
    private static boolean quotable(Setting setting) {
        return setting.type() == SettingType.BOOL || setting.type() == SettingType.CHOICE;
    }

    /** How an operator takes the governed value away: back to the default, or unset. */
    static String undo(Setting setting) {
        if (setting.defaultValue() != null && quotable(setting)) {
            return "Set " + name(setting) + " to " + setting.parse(setting.defaultValue()) + ", or unset it";
        }
        if (setting.kind() == EntryKind.SYSTEM_PROPERTY) {
            return "Remove -D" + setting.name() + " from the JVM's options (JAVA_OPTS)";
        }
        return "Unset " + name(setting);
    }

    /** How a message names a setting an operator sets: the entry's name, or a plugin's field by its label. */
    private static String name(Setting setting) {
        return setting.kind() == EntryKind.PLUGIN_FIELD ? "the field \"" + setting.name() + "\"" : setting.name();
    }

    private static String developmentEscape() {
        return " (a rig or a demo sets " + DeploymentProfile.SETTING + "=development instead)";
    }

    private static String lowerFirst(String text) {
        return text.substring(0, 1).toLowerCase(Locale.ROOT) + text.substring(1);
    }
}
