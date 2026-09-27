package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.rar.model.RarModelException;
import com.pingidentity.ps.oidf.rar.model.RarModels;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The model set a classloader enforces: read once from {@code OIDF_RAR_MODELS_FILE} or {@code OIDF_RAR_MODELS}
 * through the library, kept, and - when the document cannot be read - refused on every call after, so nothing
 * enforces a model the deployment did not write.
 */
class AttestationRarModelsTest {
    private static final String FILES_TYPE =
            "{\"types\":{\"https://scheme.example.org/files\":{\"fields\":{\"locations\":\"set\"}}}}";

    @AfterEach
    void readTheProcessEnvironmentAgain() {
        AttestationRarModels.resetForTest(null);
    }

    @Test
    void noDocumentIsTheBuiltInsWithProductionSemantics() throws Exception {
        AttestationRarModels.resetForTest(Map.of());

        RarModels models = AttestationRarModels.get();

        assertEquals(RarModels.builtIn().fingerprint(), models.fingerprint());
        assertSame(models, AttestationRarModels.get(), "loaded once and kept");
        assertSame(models, AttestationRarModels.require());
    }

    @Test
    void anInlineDocumentAddsItsTypes() throws Exception {
        AttestationRarModels.resetForTest(Map.of(RarModels.ENV_MODELS, FILES_TYPE));

        RarModels models = AttestationRarModels.get();

        assertTrue(models.types().contains("https://scheme.example.org/files"));
        assertEquals(RarModels.load(FILES_TYPE).fingerprint(), models.fingerprint(),
                "the same document gives the same fingerprint the plugin computes from it");
    }

    @Test
    void aDocumentInAFileIsReadOnce(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("rar-models.json");
        Files.writeString(file, FILES_TYPE);
        AttestationRarModels.resetForTest(Map.of(RarModels.ENV_MODELS_FILE, file.toString()));

        RarModels first = AttestationRarModels.get();
        Files.writeString(file, "{\"types\":{}}");

        assertSame(first, AttestationRarModels.get(), "a change to the file takes a restart");
        assertTrue(first.types().contains("https://scheme.example.org/files"));
    }

    @Test
    void theDevelopmentProfileTurnsTheCommonFieldsFallbackOn() throws Exception {
        Map<String, String> env = new HashMap<>();
        env.put(RarModels.ENV_PROFILE, RarModels.DEVELOPMENT_PROFILE);
        AttestationRarModels.resetForTest(env);

        assertTrue(AttestationRarModels.get().commonFieldsFallback());
    }

    /**
     * A document the library refuses is refused on this call and every one after, with the same reason: a
     * component that asks at start-up refuses to start, and one that asks per request refuses every request.
     */
    @Test
    void aDocumentTheLibraryRefusesIsRefusedEveryTime(@TempDir Path dir) {
        AttestationRarModels.resetForTest(Map.of(RarModels.ENV_MODELS, "{\"types\":{\"x\":{\"fields\":{\"a\":\"nope\"}}}}"));

        RarModelException first = assertThrows(RarModelException.class, AttestationRarModels::get);
        RarModelException second = assertThrows(RarModelException.class, AttestationRarModels::get);

        assertEquals(RarModelException.Reason.MODEL_INVALID, first.reason());
        assertEquals(first.getMessage(), second.getMessage());
        IllegalStateException required = assertThrows(IllegalStateException.class, AttestationRarModels::require);
        assertTrue(required.getMessage().contains(first.getMessage()), required.getMessage());
    }

    @Test
    void aMissingFileAndBothSettingsAtOnceAreRefused(@TempDir Path dir) {
        AttestationRarModels.resetForTest(Map.of(RarModels.ENV_MODELS_FILE, dir.resolve("absent.json").toString()));
        assertThrows(RarModelException.class, AttestationRarModels::get);

        AttestationRarModels.resetForTest(Map.of(RarModels.ENV_MODELS_FILE, "/x.json", RarModels.ENV_MODELS, FILES_TYPE));
        RarModelException both = assertThrows(RarModelException.class, AttestationRarModels::get);
        assertTrue(both.getMessage().contains("both set"), both.getMessage());
    }

    /** A verifier built with the public constructor takes this set, and cannot be built without one. */
    @Test
    void thePublicConstructorTakesThisClassloadersSet() {
        AttestationRarModels.resetForTest(Map.of(RarModels.ENV_MODELS, "not json"));
        ClientAttestationConfig config = ClientAttestationConfig.builder().addAcceptedAudience("https://op.example.com").build();

        assertThrows(IllegalStateException.class, () -> new ClientAttestationVerifier((iss, chain) -> java.util.List.of(),
                config, new InMemoryAttestationReplayCache(), null));
    }
}
