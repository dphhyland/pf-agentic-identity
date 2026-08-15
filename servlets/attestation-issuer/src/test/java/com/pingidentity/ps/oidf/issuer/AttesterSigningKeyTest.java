package com.pingidentity.ps.oidf.issuer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.Test;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.jose.OpenBaoTransitSigner;
import com.pingidentity.ps.oidf.jose.LocalJwkSigner;

/**
 * {@link AttesterSigningKey} — the per-client choice between {@link OpenBaoTransitSigner} and
 * {@link LocalJwkSigner} — split out from what used to be {@code OpenBaoTransitSignerTest} when
 * {@link OpenBaoTransitSigner}, {@link JwsSigner} and {@link LocalJwkSigner} moved to
 * {@code libs/oidf-jose}: the signers themselves are a JOSE-layer concern with no issuance context;
 * which one a given client's configuration selects is squarely an issuance concern and belongs here.
 */
class AttesterSigningKeyTest {

    private static final String TOKEN = "test-token";

    /** The resolver picks the transit signer when a key ref is set. */
    @Test
    void resolverSelectsTransitByKeyRef() throws Exception {
        try (FakeBaoServer bao = new FakeBaoServer(TOKEN)) {
            AttesterSigningKey resolver = new AttesterSigningKey(bao.url(), TOKEN);
            JwsSigner signer = resolver.signerFor(FakeBaoServer.KEY_NAME, null);
            assertTrue(signer instanceof OpenBaoTransitSigner);
        }
    }

    /** The resolver picks the local signer when an inline JWK is set. */
    @Test
    void resolverSelectsLocalByInlineJwk() throws Exception {
        PublicJsonWebKey attester = TestJwts.ec("att-1");
        AttesterSigningKey resolver = new AttesterSigningKey(null, null);
        JwsSigner signer = resolver.signerFor(null, TestJwts.privateParams(attester));
        assertTrue(signer instanceof LocalJwkSigner);
        assertEquals("ES256", signer.algorithm());
    }

    @Test
    void resolverRejectsNeitherOrBoth() throws Exception {
        AttesterSigningKey resolver = new AttesterSigningKey("http://bao", "t");
        IssuanceException neither = assertThrows(IssuanceException.class, () -> resolver.signerFor(null, null));
        assertEquals("invalid_client", neither.error());
        IssuanceException both = assertThrows(IssuanceException.class,
                () -> resolver.signerFor("k", TestJwts.privateParams(TestJwts.ec("x"))));
        assertEquals("invalid_client", both.error());
    }

    @Test
    void resolverRejectsTransitWithoutVaultConfigured() {
        AttesterSigningKey resolver = new AttesterSigningKey(null, null);
        IssuanceException e = assertThrows(IssuanceException.class, () -> resolver.signerFor("some-key", null));
        assertEquals("server_error", e.error());
    }
}
