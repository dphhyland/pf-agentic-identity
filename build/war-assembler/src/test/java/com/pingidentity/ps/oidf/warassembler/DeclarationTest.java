package com.pingidentity.ps.oidf.warassembler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** filters.xml is read strictly: what it does not know, it refuses. */
class DeclarationTest {
    private static Declaration parse(String body) throws Refusal {
        return Declaration.parse(("<war-filters version=\"1\">" + body + "</war-filters>").getBytes(StandardCharsets.UTF_8), "f.xml");
    }

    private static String refusal(String body) {
        return assertThrows(Refusal.class, () -> parse(body)).getMessage();
    }

    private static final String A = "<filter name=\"A\" class=\"x.A\"><url-pattern>/a</url-pattern></filter>";
    private static final String B = "<filter name=\"B\" class=\"x.B\"><url-pattern>/b</url-pattern></filter>";

    @Test
    void theShippedDeclarationIsTheSevenFiltersPathsAndOrder() throws Exception {
        Declaration d = Declaration.parse(Files.readAllBytes(Fixtures.shippedFilters()), "filters.xml");
        assertEquals(List.of(
                new Declaration.Filter("SsfLogoutSignal", Fixtures.SSF_FILTER, List.of("/idp/init_logout.openid")),
                new Declaration.Filter("Fapi2Profile", Fixtures.PFI + "fapi2.Fapi2ProfileFilter", List.of("/as/par.oauth2",
                        "/as/token.oauth2", "/as/introspect.oauth2", "/as/revoke_token.oauth2", "/as/bc-auth.ciba",
                        "/idp/userinfo.openid")),
                new Declaration.Filter("FapiResourceServer", Fixtures.PFI + "fapi1.FapiResourceServerFilter",
                        List.of("/idp/userinfo.openid")),
                new Declaration.Filter("OAuthErrorDescription", Fixtures.PFI + "oauth.OAuthErrorDescriptionFilter",
                        List.of("/as/bc-auth.ciba", "/as/token.oauth2", "/as/par.oauth2")),
                new Declaration.Filter("OidfFrontChannelAutoRegistration",
                        Fixtures.PFI + "clientregistration.FrontChannelAutoRegistrationFilter",
                        List.of("/as/authorization.oauth2", "/as/par.oauth2")),
                new Declaration.Filter("OidfAutoRegistration", Fixtures.PFI + "clientregistration.TokenEndpointAutoRegistrationFilter",
                        List.of("/as/token.oauth2")),
                new Declaration.Filter("IssuedDetailsBelt", Fixtures.PFI + "clientregistration.IssuedDetailsBelt",
                        List.of("/as/token.oauth2")),
                new Declaration.Filter("ClientAttestationAuth", Fixtures.PFI + "clientregistration.ClientAttestationAuthFilter",
                        List.of("/as/token.oauth2", "/as/par.oauth2", "/as/bc-auth.ciba", "/as/device_authz.oauth2",
                                "/as/introspect.oauth2", "/as/revoke_token.oauth2", "/as/authorization.oauth2"))), d.filters);
        // The script's three checks: auto-registration before attestation; Fapi2Profile before auto-registration;
        // and front-channel registration after both Fapi2Profile and the description sanitiser. Then S4d's two:
        // Fapi2Profile, and front-channel registration, before ClientAttestationAuth on every path they share. Then the
        // response belt's, outside ClientAttestationAuth at the token endpoint (S4D3).
        assertEquals(List.of("OidfAutoRegistration<ClientAttestationAuth", "Fapi2Profile<OidfAutoRegistration",
                        "Fapi2Profile<OidfFrontChannelAutoRegistration", "OAuthErrorDescription<OidfFrontChannelAutoRegistration",
                        "Fapi2Profile<ClientAttestationAuth", "OidfFrontChannelAutoRegistration<ClientAttestationAuth",
                        "IssuedDetailsBelt<ClientAttestationAuth"),
                d.orders.stream().map(o -> o.earlier() + "<" + o.later()).toList());
        assertTrue(d.orders.stream().allMatch(o -> !o.reason().isBlank() && !o.reason().contains("\n")));
        assertEquals(List.of(Fixtures.LIFECYCLE_LISTENER), d.listeners, "F-2's lifecycle listener, and no other");
        assertEquals(List.of(), d.pathExceptions);
    }

    @Test
    void everythingItKnowsIsRead() throws Refusal {
        Declaration d = parse(A + B + "<order filter=\"A\" before=\"B\">  because\n  it must </order>"
                + "<path-exception path=\"/b\" reason=\"served by an annotation\"/><listener class=\"x.L\"/>");
        assertEquals("because it must", d.orders.get(0).reason());
        assertTrue(d.isException("/b"));
        assertFalse(d.isException("/a"));
        assertEquals(List.of("x.L"), d.listeners);
        assertEquals("x.B", d.filter("B").className());
        assertNull(d.filter("C"));
    }

    @Test
    void theRootAndVersionAreChecked() {
        assertTrue(assertThrows(Refusal.class, () -> Declaration.parse("<filters version=\"1\"/>".getBytes(StandardCharsets.UTF_8), "f.xml"))
                .getMessage().contains("its root element is <filters>, not <war-filters> in no namespace."));
        assertTrue(assertThrows(Refusal.class, () -> Declaration.parse(
                "<war-filters xmlns=\"urn:x\" version=\"1\"/>".getBytes(StandardCharsets.UTF_8), "f.xml")).getMessage()
                .contains("not <war-filters> in no namespace"));
        assertEquals("ERROR: f.xml declares version '2'; this assembler reads version 1.", assertThrows(Refusal.class,
                () -> Declaration.parse("<war-filters version=\"2\"/>".getBytes(StandardCharsets.UTF_8), "f.xml")).getMessage());
    }

    @Test
    void refusals() {
        assertEquals("ERROR: f.xml declares no filter.", refusal(""));
        assertEquals("ERROR: f.xml declares the filter A twice.", refusal(A + A));
        assertEquals("ERROR: f.xml has an element this assembler does not know: <servlet>.", refusal(A + "<servlet/>"));
        assertEquals("ERROR: f.xml has a <filter> with no name.", refusal("<filter class=\"x.A\"/>"));
        assertEquals("ERROR: f.xml has a <filter> with no class.", refusal("<filter name=\"A\"/>"));
        assertTrue(refusal("<filter name=\"1A\" class=\"x.A\"/>").contains("a filter named '1A'"));
        assertTrue(refusal("<filter name=\"A\" class=\"x.1A\"/>").contains("with class 'x.1A', which is not a Java class name."));
        assertEquals("ERROR: f.xml declares A with a <init-param>; a filter takes url-patterns only.",
                refusal("<filter name=\"A\" class=\"x.A\"><init-param/></filter>"));
        assertEquals("ERROR: f.xml declares A over /a twice.",
                refusal("<filter name=\"A\" class=\"x.A\"><url-pattern>/a</url-pattern><url-pattern> /a </url-pattern></filter>"));
        assertEquals("ERROR: f.xml declares A with no url-pattern.", refusal("<filter name=\"A\" class=\"x.A\"/>"));
        assertEquals("ERROR: f.xml orders A before C, but declares no filter C.", refusal(A + "<order filter=\"A\" before=\"C\">x</order>"));
        assertEquals("ERROR: f.xml orders C before A, but declares no filter C.", refusal(A + "<order filter=\"C\" before=\"A\">x</order>"));
        assertEquals("ERROR: f.xml orders A before itself.", refusal(A + "<order filter=\"A\" before=\"A\">x</order>"));
        assertTrue(refusal(A + B + "<order filter=\"A\" before=\"B\"> </order>").contains("without saying why"));
        assertEquals("ERROR: f.xml has a <path-exception> with no reason.", refusal(A + "<path-exception path=\"/x\"/>"));
        assertTrue(refusal(A + "<path-exception path=\"x\" reason=\"r\"/>").contains("gives path-exception the url-pattern 'x'"));
        assertEquals("ERROR: f.xml has a <listener> with no class.", refusal(A + "<listener/>"));
        assertTrue(refusal(A + "<listener class=\"x..L\"/>").contains("a listener class 'x..L' that is not a Java class name."));
        assertEquals("ERROR: f.xml declares the listener x.L twice.", refusal(A + "<listener class=\"x.L\"/><listener class=\"x.L\"/>"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/a", "/", "/*", "/a/*", "/a/b.c", "*.oauth2"})
    void urlPatternsTheServletSpecificationAllows(String pattern) throws Refusal {
        Declaration.checkPattern(pattern, "A", "f.xml");
    }

    @ParameterizedTest
    @ValueSource(strings = {"a", "/a*", "/*/a", "/a/**", "/a*/*", "*.", "*.a/b", "*.a*", "*a", "/a b", "*.a\tb", ""})
    void urlPatternsItDoesNot(String pattern) {
        assertTrue(assertThrows(Refusal.class, () -> Declaration.checkPattern(pattern, "A", "f.xml")).getMessage()
                .contains("which is not an exact path, a /prefix/* or a *.extension."));
    }
}
