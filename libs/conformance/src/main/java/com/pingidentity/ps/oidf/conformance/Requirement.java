/*
 * Names the specification clause a test pins.
 */
package com.pingidentity.ps.oidf.conformance;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The specification clause (or clauses) a test pins.
 *
 * <p>This repo implements ten standards and documents them in prose matrices. Prose drifts — §5.2 of
 * the architecture doc claimed several coverage gaps were open months after they closed, and claimed a
 * fixed defect was still live. A matrix row nobody can execute is an assertion about the code that the
 * code never has to honour. This annotation is the join: a test carries the clause it pins,
 * {@code tools/coverage-report.py} scans for it, and the dashboard reports pinned-versus-total per
 * specification. What is not pinned shows up as a number rather than as silence.
 *
 * <p>Retention is {@link RetentionPolicy#SOURCE} on purpose. The reporter reads source, not class
 * files, which keeps it independent of whether surefire propagates anything into its XML and adds no
 * runtime cost to any test. Change it to {@code RUNTIME} only if something actually needs it there.
 *
 * <h2>Writing an id</h2>
 *
 * <p>An id is {@code SPEC §clause}. It is an opaque join key, so it only earns its place if it is
 * spelled identically everywhere it appears — the same clause under two spellings shows up in the
 * dashboard as two requirements, each half-covered.
 *
 * <p><b>Repo-published specs.</b> The anchor form differs per document, and getting it wrong produces
 * a citation that resolves to nothing:
 * <ul>
 *   <li>{@code PROFILE §6} — a whole section of {@code docs/ai-agent-attestation-profile-1_0.md}.
 *       Sections 3 to 10 have <em>no subsections</em>; their requirements are numbered list items, so
 *       item 2 of section 6 is {@code PROFILE §6(2)} and never {@code §6.2}. Only §1.1-1.3, §11.1 and
 *       §12.1-12.2 are real subsections.</li>
 *   <li>{@code CAS §7.1} — {@code docs/openid-client-attestation-service-1_0.md} does have real
 *       subsections, so {@code §N.M} is legitimate there. The same notation therefore means different
 *       things under the two prefixes; that is why they are prefixed.</li>
 *   <li>{@code CLAIM-DICT divergence 3} — one of the five numbered deliberate divergences in
 *       {@code docs/claim-dictionary.md}.</li>
 *   <li>{@code UNVERIFIED item 8} — one of the numbered assumptions in {@code docs/unverified.md}.</li>
 * </ul>
 *
 * <p><b>External specs.</b> One prefix and one anchor style per document, chosen once:
 * {@code ABCA-10}, {@code RFC9449}, {@code RFC9396}, {@code RFC8693}, {@code RFC7638}, {@code RFC9493},
 * {@code RFC8417}, {@code OIDFED}, {@code SSF}, {@code CAEP}, {@code AUTHZEN-1.0}, {@code OIDC-CORE},
 * {@code NIST-800-63B}, {@code OID4VCI}, {@code APPLE-APPATTEST}, {@code PF-SDK}.
 *
 * <h2>Three ways to get it wrong</h2>
 *
 * <p><b>Never tag a divergence with the clause it diverges from.</b> This is the one that actively
 * misleads. {@code DeviceAttestationMinterTest#claimingIso18045HighIsRefused} asserts the constructor
 * <em>refuses</em> {@code iso_18045_high}; the EUDI ARF clause requiring that value is precisely what
 * {@code CLAIM-DICT divergence 3} exists to depart from. Tagging the test with that clause tells a
 * reviewer the opposite of the truth. A test asserting divergent behaviour is tagged with the
 * divergence, not the spec.
 *
 * <p><b>Never invent a citation.</b> Use the citation the source itself carries, or verify it verbatim
 * first. {@code SdJwt.java} cites a draft by URL and no RFC number for SD-JWT appears anywhere in this
 * repo — an id asserting one would be fabricated. This repo has been bitten by exactly this: see
 * {@code docs/unverified.md}, whose whole premise is recording what could not be confirmed rather than
 * assuming it.
 *
 * <p><b>Do not tag a repo default as a spec requirement.</b> A 15-minute attestation lifetime is a
 * number this deployment chose ({@code CLAIM-DICT divergence 4}); {@code PROFILE §5} sets an 18-hour
 * ceiling. A test asserting the default is not pinning the ceiling, and tagging it as such makes the
 * ceiling look covered when nothing checks it.
 *
 * <h2>Confidence</h2>
 *
 * <p>{@code PF-SDK} ids name a vendor interface, not a public specification, and
 * {@code docs/unverified.md} item 5 records that no PingFederate 13.x javadoc exists on this machine to
 * check them against. They are legitimate — the SDK contract is real and worth pinning — but they are a
 * different confidence class from an RFC and the dashboard reports them separately.
 */
@Documented
@Retention(RetentionPolicy.SOURCE)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface Requirement {

    /**
     * One or more clause ids, e.g. {@code "ABCA-10 §7.1"} or {@code {"PROFILE §6(2)", "PROFILE §6(3)"}}.
     *
     * <p>Several ids on one test means the test genuinely pins all of them. Prefer splitting a test
     * that pins many clauses: a single test failing tells you less the more requirements it carries.
     */
    String[] value();
}
