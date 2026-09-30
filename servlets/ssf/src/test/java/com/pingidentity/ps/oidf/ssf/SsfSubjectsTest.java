/*
 * The subject formats the ssf module accepts from outside until H-SSF-1, and the lazy PingFederate signing key.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import com.pingidentity.ps.oidf.signals.SubjectId;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class SsfSubjectsTest {

    @Test
    void theFiveFormatsAreAcceptedAndTheOthersRefusedAsBefore() {
        assertEquals(Set.of("iss_sub", "email", "phone_number", "opaque", "account"), SsfSubjects.FORMATS);
        assertEquals(SubjectId.email("a@b.com"), SsfSubjects.parse(Map.of("format", "email", "email", "a@b.com")));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> SsfSubjects.parse(Map.of(
                "format", "complex", "user", Map.of("format", "email", "email", "a@b.com"))));
        assertEquals("unsupported subject identifier format: complex", e.getMessage());
        assertThrows(IllegalArgumentException.class,
                () -> SsfSubjects.parse(Map.of("format", "did", "url", "did:example:1")));
    }

    @Test
    void aCanonicalKeyInAFormatOutsideTheFiveIsRefused() {
        assertEquals(SubjectId.opaque("abc"), SsfSubjects.fromCanonicalKey("opaque:abc"));
        assertThrows(IllegalArgumentException.class, () -> SsfSubjects.fromCanonicalKey("did:did:example:1"));
        assertThrows(IllegalArgumentException.class, () -> SsfSubjects.fromCanonicalKey(
                SubjectId.aliases(List.of(SubjectId.opaque("abc"))).canonicalKey()));
    }

    @Test
    void pingFederatesKeyIsResolvedOnFirstUseAndKept() {
        TestSigningKeyProvider real = new TestSigningKeyProvider("pf-key");
        AtomicInteger resolutions = new AtomicInteger();
        SigningKeyProvider lazy = new PfSetSigningKeys(() -> {
            resolutions.incrementAndGet();
            return real;
        });
        assertEquals(0, resolutions.get());
        assertEquals("pf-key", lazy.keyId());
        assertSame(real.privateKey(), lazy.privateKey());
        assertSame(real.publicKey(), lazy.publicKey());
        assertEquals(1, resolutions.get());
    }
}
