package com.pingidentity.ps.oidf.platform.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** OIDF_* names under a family no catalogue declares: listed, never refused (Phase 2 plan decision 7). */
class UnknownKeysTest {

    private static final Catalogue EXAMPLE = Catalogue.load(UnknownKeysTest.class.getClassLoader(), "example");

    private static final Catalogue OTHER = Catalogue.parse("{\"format\": 1, \"component\": \"other\", \"module\": \"libs/platform\","
            + " \"package\": \"com.example.other\", \"families\": [\"OIDF_OTHER_\", \"OIDF_SHARED_\"], \"settings\": [], \"removed\": []}", "other.json");

    @Test
    void aMisspeltNameUnderAFamilyIsListed() {
        Map<String, String> env = Map.of(
                "OIDF_EXAMPLE_FAIL_CLOSD", "true",
                "OIDF_EXAMPLE_FAIL_CLOSED", "true",
                "OIDF_EXAMPLE_TOKEN_FILE", "/run/x",
                "OIDF_EXAMPLE_REFUSE_ON_FAILURE", "true",
                "OIDF_EXAMPLE_STRICT", "true",
                "OIDF_EXAMPLE_ZZZ", "1",
                "OIDF_ELSEWHERE_X", "1",
                "PATH", "/bin");

        assertEquals(List.of("OIDF_EXAMPLE_FAIL_CLOSD", "OIDF_EXAMPLE_ZZZ"), UnknownKeys.find(env, List.of(EXAMPLE)),
                "declared names, their aliases, file variants and removed names are known; names outside every family are"
                        + " another component's business");
    }

    @Test
    void everyCataloguesFamiliesAndNamesCount() {
        Map<String, String> env = Map.of("OIDF_SHARED_X", "1", "OIDF_OTHER_Y", "1", "OIDF_EXAMPLE_MODE", "local");

        assertEquals(List.of("OIDF_OTHER_Y", "OIDF_SHARED_X"), UnknownKeys.find(env, List.of(EXAMPLE, OTHER)));
        assertEquals(List.of(), UnknownKeys.find(env, List.of()));
    }
}
