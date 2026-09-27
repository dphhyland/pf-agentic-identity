/*
 * What a war's copy of platform finds at start-up, as one banner.
 */
package com.pingidentity.ps.oidf.platform.pf.lifecycle;

import com.pingidentity.ps.oidf.platform.component.ComponentStatus;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutor;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisk;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.tls.InsecureTls;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * The start-up audit (plan item F-2): this repository's version and commit, PingFederate's version, the deployment
 * profile, the topology, the accepted risks, every insecure TLS use and each component's state, for one war's copy
 * of platform, written as one banner. It reports and refuses nothing: refusing a component for what the audit finds
 * is PR-5 (Phase 3), and until then an {@code OIDF_ACCEPTED_RISKS} entry that does not parse is listed here, and
 * logged at WARN by the listener, and its risk is simply not accepted (Phase 2 plan, decision 7).
 *
 * <p>Every value is written on one line of at most {@value #MAX_VALUE} characters, control, format and separator
 * characters replaced with {@code ?}: the profile and the risk refusals quote what an operator set.
 */
final class StartupAudit {

    /** The longest value written, in characters. */
    static final int MAX_VALUE = 256;

    /** The topology line until C-1 (Phase 4) can tell a cluster from a single node. */
    static final String STANDALONE = "standalone";

    /** What the commit line says while no build records it (finding F-0190). */
    static final String UNKNOWN_COMMIT = "unknown (no build records it yet: finding F-0190)";

    private static final String INDENT = "                  ";

    /**
     * What the audit found.
     *
     * @param war           which war this is, as the log should name it
     * @param versions      {@code BuildInfo.read}'s map: {@code agentic-identity}, {@code commit}, {@code pingfederate}
     *                      and {@code java}, a value null when it cannot be read
     * @param profile       the deployment profile
     * @param profileSaid   how the environment names it ({@link DeploymentProfile#describe})
     * @param topology      {@value #STANDALONE} until C-1
     * @param risks         {@code OIDF_ACCEPTED_RISKS}, parsed
     * @param insecureTls   the settings that asked for insecure TLS in this copy so far
     * @param hostnamesOff  whether the JDK HTTP client's host name check is off for the whole JVM
     * @param components    this copy's components and their states
     * @param executors     this copy's managed executors
     * @param mxBean        the name this copy's metrics MXBean is registered under, if it is
     * @param platformFrom  where this copy of platform was loaded from
     */
    record Facts(String war, Map<String, Object> versions, DeploymentProfile profile, String profileSaid, String topology,
            AcceptedRisks risks, List<InsecureTls.Use> insecureTls, boolean hostnamesOff, List<ComponentStatus> components,
            List<ManagedExecutor.Status> executors, Optional<String> mxBean, String platformFrom) {
    }

    private StartupAudit() {
    }

    /** The profile and the accepted risks, as an environment and a date give them; the rest as passed. */
    static Facts collect(String war, Map<String, Object> versions, Function<String, String> env, LocalDate today,
            List<InsecureTls.Use> insecureTls, boolean hostnamesOff, List<ComponentStatus> components,
            List<ManagedExecutor.Status> executors, Optional<String> mxBean, String platformFrom) {
        return new Facts(war, versions, DeploymentProfile.of(env), DeploymentProfile.describe(env), STANDALONE,
                AcceptedRisks.of(env, today), insecureTls, hostnamesOff, components, executors, mxBean, platformFrom);
    }

    /** The banner: a heading line, then one labelled line per fact, continuation lines indented under the value. */
    static String banner(Facts f) {
        StringBuilder out = new StringBuilder("Start-up audit for ").append(oneLine(f.war())).append(':');
        line(out, "version", or(f.versions().get("agentic-identity"), "unknown"));
        line(out, "commit", or(f.versions().get("commit"), UNKNOWN_COMMIT));
        line(out, "PingFederate", or(f.versions().get("pingfederate"), "unknown"));
        line(out, "Java", or(f.versions().get("java"), "unknown"));
        line(out, "profile", f.profile().value() + " (" + f.profileSaid() + ")");
        line(out, "topology", f.topology());
        lines(out, "accepted risks", accepted(f.risks()));
        line(out, "risk refusals", f.risks().refusals().isEmpty() ? "none"
                : f.risks().refusals().size() + ", each logged at WARN; those risks are not accepted, and nothing"
                        + " refuses a start for them until PR-5");
        lines(out, "insecure TLS", insecure(f.insecureTls()));
        line(out, "JDK host names", f.hostnamesOff()
                ? "NOT checked by any java.net.http client in this JVM (" + InsecureTls.JDK_HOSTNAME_VERIFICATION_PROPERTY + ")"
                : "checked");
        lines(out, "components", components(f.components()));
        line(out, "executors", executors(f.executors()));
        line(out, "metrics MXBean", f.mxBean().orElse("not registered"));
        line(out, "platform", f.platformFrom());
        return out.toString();
    }

    static List<String> accepted(AcceptedRisks risks) {
        List<String> out = new ArrayList<>();
        for (Map.Entry<AcceptedRisk, Optional<LocalDate>> e : risks.accepted().entrySet()) {
            AcceptedRisk risk = e.getKey();
            String until = e.getValue().map(d -> "until " + d).orElse("no expiry");
            out.add(risk.id() + " (" + until + "): " + risk.description());
        }
        return out;
    }

    static List<String> insecure(List<InsecureTls.Use> uses) {
        List<String> out = new ArrayList<>();
        for (InsecureTls.Use use : uses) {
            out.add(use.setting() + ": " + use.kind() + " since " + use.first());
        }
        return out;
    }

    static List<String> components(List<ComponentStatus> components) {
        List<String> out = new ArrayList<>();
        for (ComponentStatus c : components) {
            out.add(c.name() + " " + c.state() + (c.reason().isEmpty() ? "" : ": " + c.reason()));
        }
        return out;
    }

    static String executors(List<ManagedExecutor.Status> executors) {
        List<String> names = new ArrayList<>();
        for (ManagedExecutor.Status s : executors) {
            names.add(s.name() + (s.closed() ? " (closed)" : ""));
        }
        return names.isEmpty() ? "none" : String.join(", ", names);
    }

    private static String or(Object value, String otherwise) {
        return value == null ? otherwise : value.toString();
    }

    private static void line(StringBuilder out, String label, String value) {
        out.append(System.lineSeparator()).append("  ").append(label).append(':')
                .append(" ".repeat(INDENT.length() - label.length() - 3)).append(oneLine(value));
    }

    /** A label with one value per line, or {@code none}. */
    private static void lines(StringBuilder out, String label, List<String> values) {
        if (values.isEmpty()) {
            line(out, label, "none");
            return;
        }
        line(out, label, values.get(0));
        for (String value : values.subList(1, values.size())) {
            out.append(System.lineSeparator()).append(INDENT).append(oneLine(value));
        }
    }

    /** A value as one line an operator can read: separators and control characters become {@code ?}, and it is cut. */
    static String oneLine(String value) {
        String text = value == null ? "" : value.strip();
        int end = Math.min(text.length(), MAX_VALUE);
        if (end < text.length() && Character.isHighSurrogate(text.charAt(end - 1))) {
            end--;
        }
        StringBuilder out = new StringBuilder(end + 3);
        for (int i = 0; i < end; i++) {
            char c = text.charAt(i);
            int type = Character.getType(c);
            boolean hidden = type == Character.CONTROL || type == Character.FORMAT || type == Character.LINE_SEPARATOR
                    || type == Character.PARAGRAPH_SEPARATOR;
            out.append(hidden ? '?' : c);
        }
        return end < text.length() ? out.append("...").toString() : out.toString();
    }
}
