package com.pingidentity.ps.oidf.rar;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ModelGate}: how the plugin loads the RAR model set, strips its markers, checks a detail, asks the model's
 * {@code contains}, and compares the attestation context's fingerprint with its own.
 */
class ModelGateTest {

    private static final String EXTRA = "{\"types\":{\"https://scheme.example/files\":{\"fields\":{\"paths\":\"set\"}}}}";

    private final ModelGate builtIn = ModelGate.of(RarModels.builtIn());

    private static Map<String, Object> sales(String... regions) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("type", "sales_agent");
        detail.put("sales_regions", new ArrayList<>(List.of(regions)));
        return detail;
    }

    private static AttestationSubject context(Object fingerprint) {
        Map<String, Object> attr = new HashMap<>();
        attr.put("client_id", "agent-client");
        if (fingerprint != null) {
            attr.put(AttestationSubject.RAR_MODELS_FINGERPRINT_KEY, fingerprint);
        }
        return AttestationSubject.fromAttribute(attr);
    }

    private static List<LogRecord> captured(Runnable action) {
        Logger log = Logger.getLogger(ModelGate.class.getName());
        List<LogRecord> records = new ArrayList<>();
        Handler capture = new Handler() {
            @Override public void publish(LogRecord record) { records.add(record); }
            @Override public void flush() { }
            @Override public void close() { }
        };
        log.addHandler(capture);
        try {
            action.run();
        } finally {
            log.removeHandler(capture);
        }
        return records;
    }

    // ---- loading ------------------------------------------------------------------------------------------

    @Test
    void theEnvironmentsModelsLoadOnceAndSayWhereTheyCameFrom(@TempDir Path dir) throws Exception {
        List<LogRecord> builtInLines = captured(() -> assertTrue(ModelGate.fromEnvironment(Map.of()).loaded()));
        assertTrue(builtInLines.get(0).getMessage().contains("fingerprint=" + RarModels.builtIn().fingerprint()),
                builtInLines.get(0).getMessage());
        assertTrue(builtInLines.get(0).getMessage().endsWith("source=built-in"), builtInLines.get(0).getMessage());

        Path file = dir.resolve("models.json");
        Files.writeString(file, EXTRA, StandardCharsets.UTF_8);
        ModelGate fromFile = ModelGate.fromEnvironment(Map.of(RarModels.ENV_MODELS_FILE, file.toString()));
        ModelGate inline = ModelGate.fromEnvironment(Map.of(RarModels.ENV_MODELS, EXTRA));
        assertEquals(RarModels.load(EXTRA).fingerprint(), fromFile.fingerprint());
        assertEquals(fromFile.fingerprint(), inline.fingerprint(), "one document, one fingerprint, wherever it was read from");
        assertNull(fromFile.loadFailure());
        assertEquals(RarModels.ENV_MODELS_FILE, ModelGate.sourceOf(Map.of(RarModels.ENV_MODELS_FILE, "/x")));
        assertEquals(RarModels.ENV_MODELS, ModelGate.sourceOf(Map.of(RarModels.ENV_MODELS, EXTRA, RarModels.ENV_MODELS_FILE, " ")));
        assertEquals("built-in", ModelGate.sourceOf(Map.of(RarModels.ENV_MODELS, " ")));
        assertSame(ModelGate.process(), ModelGate.process(), "one model set per classloader");
    }

    /** A models document the library refuses leaves the plugin with no model, loudly, and every question refused. */
    @Test
    void aModelsDocumentTheLibraryRefusesLeavesNoModelAndSaysSo() {
        List<ModelGate> gates = new ArrayList<>();
        List<LogRecord> lines = captured(() -> {
            gates.add(ModelGate.fromEnvironment(Map.of(RarModels.ENV_MODELS, "{\"types\":{\"payment_initiation\":{\"fields\":{}}}}")));
            gates.add(ModelGate.fromEnvironment(Map.of(RarModels.ENV_MODELS, EXTRA, RarModels.ENV_MODELS_FILE, "/nowhere")));
        });
        for (ModelGate failed : gates) {
            assertFalse(failed.loaded());
            assertNull(failed.fingerprint());
            assertTrue(failed.loadFailure().startsWith("the RAR models could not be loaded (MODEL_INVALID)"), failed.loadFailure());
            assertEquals(RarModelException.Reason.MODEL_INVALID,
                    assertThrows(RarModelException.class, () -> failed.check(sales("EMEA"))).reason());
            ModelGate.Verdict verdict = failed.within(sales("EMEA"), sales("EMEA"));
            assertFalse(verdict.contained());
            assertTrue(verdict.isRefused());
            assertEquals(RarModelException.Reason.MODEL_INVALID, verdict.reason());
        }
        assertEquals(2, lines.stream().filter(r -> r.getLevel() == Level.SEVERE).count());
        assertTrue(lines.get(0).getMessage().contains("is refused until " + RarModels.ENV_MODELS_FILE), lines.get(0).getMessage());
    }

    // ---- the markers --------------------------------------------------------------------------------------

    /**
     * The library README's rule for the wiring: "_principal_sub" and "_agent_id" are "Markers, not request
     * fields", and "The wiring (S1b, S1c) must strip both before it asks the model: a detail that reaches the
     * model carrying either is MALFORMED". Stripped, the detail is one the model reads; unstripped, it is not.
     */
    @Test
    void theMarkersAreStrippedBeforeTheModelIsAsked() throws Exception {
        Map<String, Object> marked = sales("EMEA");
        marked.put(ModelGate.PRINCIPAL_MARKER, "alice");
        marked.put(ModelGate.AGENT_MARKER, "agent-7");

        assertEquals(RarModelException.Reason.MALFORMED,
                assertThrows(RarModelException.class, () -> builtIn.check(marked)).reason(), "what the model says without the strip");
        Map<String, Object> stripped = ModelGate.strip(marked);
        builtIn.check(stripped);
        assertEquals(sales("EMEA"), stripped);
        assertTrue(marked.containsKey(ModelGate.PRINCIPAL_MARKER), "the caller's map is left alone");
        assertNull(ModelGate.strip(null));
    }

    @Test
    void aDeepCopySharesNoContainerWithItsSource() {
        Map<String, Object> nested = new HashMap<>();
        nested.put("amount", "42.00");
        List<Object> list = new ArrayList<>(List.of(new HashMap<>(Map.of("iban", "DE1"))));
        Map<Object, Object> source = new HashMap<>();
        source.put("instructedAmount", nested);
        source.put("accounts", list);
        source.put(7, "a name that is not a string");

        Map<String, Object> copy = ModelGate.deepCopy(source);
        assertEquals(source, copy);
        assertNotSame(nested, copy.get("instructedAmount"));
        assertNotSame(list, copy.get("accounts"));
        assertNotSame(list.get(0), ((List<?>) copy.get("accounts")).get(0));
        assertTrue(((Map<?, ?>) copy).containsKey(7), "a member name that is not a string is kept for the model to refuse");
    }

    // ---- the questions ------------------------------------------------------------------------------------

    /** RFC 9396 section 5: "The AS MUST refuse to process any unknown authorization details type or authorization
     * details not conforming to the respective type definition." */
    @Test
    @Requirement("RFC9396 §5")
    void aRequestedDetailIsHeldToItsTypesModel() throws Exception {
        builtIn.check(sales("EMEA"));
        Map<String, Object> undeclared = sales("EMEA");
        undeclared.put("tier", "gold");
        assertEquals(RarModelException.Reason.UNDECLARED_FIELD,
                assertThrows(RarModelException.class, () -> builtIn.check(undeclared)).reason());
        assertEquals(RarModelException.Reason.UNMODELLED_TYPE,
                assertThrows(RarModelException.class, () -> builtIn.check(Map.of("type", "https://unknown.example"))).reason());
        assertEquals(RarModelException.Reason.MALFORMED,
                assertThrows(RarModelException.class, () -> builtIn.check(Map.of("type", "sales_agent", "sales_regions", List.of()))).reason());
        assertEquals(RarModelException.Reason.MALFORMED, assertThrows(RarModelException.class, () -> builtIn.check(null)).reason());
    }

    /**
     * CAS section 7 rule 1: "for a candidate to be within the ceiling there must be a ceiling object of the same
     * type whose constraints it does not exceed (arrays: subset; numeric limits: ≤; absent ceiling field:
     * unconstrained)."
     */
    @Test
    @Requirement("CAS §7(1)")
    void withinIsTheModelsStrictContains() {
        assertEquals(ModelGate.Verdict.CONTAINED, builtIn.within(sales("EMEA", "APAC"), sales("APAC")));
        assertEquals(ModelGate.Verdict.NOT_CONTAINED, builtIn.within(sales("EMEA"), sales("EMEA", "APAC")));
        assertEquals(ModelGate.Verdict.NOT_CONTAINED, builtIn.within(sales("EMEA"), Map.of("type", "sales_agent")),
                "a field the ceiling constrains and the candidate omits is not contained");
        assertEquals(ModelGate.Verdict.CONTAINED, builtIn.within(Map.of("type", "sales_agent"), sales("EMEA")),
                "a field the ceiling omits is unconstrained");
        assertEquals(ModelGate.Verdict.NOT_CONTAINED, builtIn.within(sales("EMEA"),
                Map.of("type", "payment_initiation", "amount", "1.00", "currency", "EUR")), "another type is never within");

        ModelGate.Verdict malformed = builtIn.within(sales("EMEA"), Map.of("type", "sales_agent", "max_txn_eur", "lots"));
        assertEquals(RarModelException.Reason.MALFORMED, malformed.reason());
        assertFalse(malformed.contained());
        assertFalse(malformed.refusal().contains("lots"), "the model names the field, never the value: " + malformed.refusal());
        ModelGate.Verdict missing = builtIn.within(null, sales("EMEA"));
        assertEquals(RarModelException.Reason.MALFORMED, missing.reason());
        assertEquals(RarModelException.Reason.MALFORMED, builtIn.within(sales("EMEA"), null).reason());
        assertFalse(ModelGate.Verdict.CONTAINED.isRefused());
    }

    // ---- the fingerprint ----------------------------------------------------------------------------------

    @Test
    void theFingerprintIsComparedWhenAContextIsThereAndOnlyThen() throws Exception {
        String ours = RarModels.builtIn().fingerprint();
        assertNull(builtIn.fingerprintProblem(null));
        assertNull(builtIn.fingerprintProblem(AttestationSubject.empty()), "no context: decided as before the model");
        assertNull(builtIn.fingerprintProblem(AttestationSubject.fromAttribute(null)));
        assertNull(builtIn.fingerprintProblem(context(ours)), "the filter's model is this plugin's");

        String missing = builtIn.fingerprintProblem(context(null));
        assertTrue(missing.contains("carries no " + ModelGate.FINGERPRINT_MEMBER), missing);
        String notAString = builtIn.fingerprintProblem(context(42));
        assertTrue(notAString.contains("carries no"), notAString);

        String other = RarModels.fromEnvironment(Map.of(RarModels.ENV_MODELS, EXTRA)).fingerprint();
        String mismatch = builtIn.fingerprintProblem(context(other));
        assertTrue(mismatch.contains("(" + other.substring(0, 12) + "...) is not this plugin's (" + ours.substring(0, 12) + "...)"), mismatch);
        String junk = builtIn.fingerprintProblem(context("DROP TABLE\nforged log line"));
        assertTrue(junk.contains("(not a lower-case SHA-256 hex value)"), junk);
        assertFalse(junk.contains("forged"), junk);

        String unreadable = builtIn.fingerprintProblem(AttestationSubject.fromAttribute("not a map"));
        assertTrue(unreadable.contains("carries no"), "a context that is there but unreadable is refused: " + unreadable);
    }

    @Test
    void aPluginWithNoModelNamesThatRatherThanAMismatch() {
        ModelGate failed = ModelGate.fromEnvironment(Map.of(RarModels.ENV_MODELS, "not json"));
        assertEquals(failed.loadFailure(), failed.fingerprintProblem(context(RarModels.builtIn().fingerprint())));
        assertNull(failed.fingerprintProblem(AttestationSubject.empty()), "without a context the load failure is reported by within");
    }

    @Test
    void aFingerprintIsShortenedOnlyWhenItIsOne() {
        assertEquals("none", ModelGate.shortForm(null));
        assertEquals("0123456789ab...", ModelGate.shortForm("0123456789abcdef".repeat(4)));
        assertEquals("not a lower-case SHA-256 hex value", ModelGate.shortForm("0123456789ABCDEF".repeat(4)));
    }
}
