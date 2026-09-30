package com.pingidentity.ps.oidf.platform.pf.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;
import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Source;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import org.junit.jupiter.api.Test;

/** A servlet's or filter's init-params, read as the init-param source, with the precedence the catalogue gives. */
class InitParamsTest {

    private static final String CATALOGUE = "{\"format\": 1, \"component\": \"pf-example\", \"module\": \"libs/platform-pf\","
            + " \"package\": \"com.pingidentity.ps.oidf.platform.pf.settings\", \"families\": [\"OIDF_PF_EXAMPLE_\"],"
            + " \"settings\": [{\"name\": \"signingAlgorithm\", \"kind\": \"init-param\", \"type\": \"choice\", \"choices\": [\"RS256\", \"PS256\"],"
            + " \"default\": \"RS256\", \"description\": \"How statements are signed\","
            + " \"when_wrong\": {\"effect\": \"doesnt-start\", \"detail\": \"Anything else\"}, \"profile\": \"any\", \"security\": true,"
            + " \"sources\": [{\"from\": \"init-param\", \"name\": \"signingAlgorithm\"}, {\"from\": \"env\", \"name\": \"OIDF_PF_EXAMPLE_ST12_UNSET_SIGNING_ALG\"}],"
            + " \"aliases\": [], \"file\": false}], \"removed\": []}";

    private static ServletConfig servlet(Map<String, String> params) {
        return new ServletConfig() {
            @Override
            public String getServletName() {
                return "example";
            }

            @Override
            public ServletContext getServletContext() {
                return null;
            }

            @Override
            public String getInitParameter(String name) {
                return params.get(name);
            }

            @Override
            public Enumeration<String> getInitParameterNames() {
                return Collections.enumeration(params.keySet());
            }
        };
    }

    private static FilterConfig filter(Map<String, String> params) {
        return new FilterConfig() {
            @Override
            public String getFilterName() {
                return "example";
            }

            @Override
            public ServletContext getServletContext() {
                return null;
            }

            @Override
            public String getInitParameter(String name) {
                return params.get(name);
            }

            @Override
            public Enumeration<String> getInitParameterNames() {
                return Collections.enumeration(params.keySet());
            }
        };
    }

    @Test
    void aServletsInitParamIsTheInitParamSource() {
        Settings settings = Settings.of(Catalogue.parse(CATALOGUE, "test"), InitParams.sources(servlet(Map.of("signingAlgorithm", "ps256"))));

        assertEquals("PS256", settings.choice("signingAlgorithm"));
        assertEquals(Source.INIT_PARAM, settings.resolve("signingAlgorithm").provenance().source());
    }

    @Test
    void aFiltersInitParamIsTheInitParamSource() {
        Settings settings = Settings.of(Catalogue.parse(CATALOGUE, "test"), InitParams.sources(filter(Map.of("signingAlgorithm", "PS256"))));

        assertEquals("PS256", settings.choice("signingAlgorithm"));
    }

    @Test
    void aMissingConfigHasNoInitParams() {
        assertNull(InitParams.of((ServletConfig) null).apply("signingAlgorithm"));
        assertNull(InitParams.of((FilterConfig) null).apply("signingAlgorithm"));
        Settings settings = Settings.of(Catalogue.parse(CATALOGUE, "test"), InitParams.sources((ServletConfig) null));
        assertEquals("RS256", settings.choice("signingAlgorithm"));
        assertEquals(Source.DEFAULT, settings.resolve("signingAlgorithm").provenance().source());
        assertEquals("RS256", Settings.of(Catalogue.parse(CATALOGUE, "test"), InitParams.sources((FilterConfig) null))
                .choice("signingAlgorithm"));
    }
}
