/*
 * The configured receiver keeps an inbound sub_id to the five formats this module acts on, until H-SSF-1.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.pingidentity.ps.oidf.signals.SecurityEventToken;
import com.pingidentity.ps.oidf.signals.SetMinter;
import com.pingidentity.ps.oidf.signals.SetVerifier;
import com.pingidentity.ps.oidf.signals.SubjectId;
import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * shared-signals' {@link SetVerifier} accepts every format {@link SubjectId} parses by default, the complex
 * subject among them. Nothing on this receiver matches or acts on those yet, so {@link SsfSupport} builds its
 * verifier with {@link SsfSubjects#FORMATS}; these tests go through {@link SsfSupport#configure}, so a receiver
 * wired with the default fails them.
 */
class ReceiverSubjectFormatsTest {

    private static final String ISS = "https://tx.example.com";
    private static final String AUD = "https://me.example.com";

    private final TestSigningKeyProvider keys = new TestSigningKeyProvider("tx-key");
    private final SetMinter minter = new SetMinter("RS256", keys);
    private HttpServer jwks;

    @BeforeEach
    void serveTheTransmittersKeys() throws Exception {
        SsfSupport.resetForTests();
        RsaJsonWebKey jwk = new RsaJsonWebKey(keys.publicKey());
        jwk.setKeyId(keys.keyId());
        byte[] body = new JsonWebKeySet(List.<JsonWebKey>of(jwk)).toJson().getBytes(StandardCharsets.UTF_8);
        jwks = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        jwks.createContext("/jwks", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        jwks.start();
        SsfSupport.configure(new SsfConfiguration.Builder().issuer("https://op.example.com")
                .receiverExpectedIssuer(ISS).receiverAudience(AUD).receiverEndpointAuthToken("s3cret")
                .receiverJwksUrl("http://127.0.0.1:" + jwks.getAddress().getPort() + "/jwks").build());
    }

    @AfterEach
    void stop() {
        SsfSupport.resetForTests();
        jwks.stop(0);
    }

    private String mint(String jti, SubjectId subject) throws Exception {
        return minter.sign(SecurityEventToken.builder()
                .issuer(ISS).audience(AUD).jti(jti).issuedAt(SetMinter.nowSeconds()).subjectId(subject)
                .event(SsfEventTypes.CAEP_SESSION_REVOKED, Map.of("event_timestamp", 1L)).build());
    }

    @Test
    void aSubjectInOneOfTheFiveFormatsIsAccepted() throws Exception {
        assertEquals(SsfReceiverService.Outcome.ACCEPTED,
                SsfSupport.receiverService().receive(mint("jti-email", SubjectId.email("bob@example.com"))));
    }

    @Test
    void aComplexDidOrAliasesSubjectIsRefusedAsAnInvalidRequest() throws Exception {
        List<SubjectId> outside = List.of(
                SubjectId.complex(Map.of("user", SubjectId.email("bob@example.com"))),
                SubjectId.did("did:example:123"),
                SubjectId.aliases(List.of(SubjectId.email("bob@example.com"), SubjectId.opaque("abc"))));
        int n = 0;
        for (SubjectId subject : outside) {
            String jws = mint("jti-" + n++, subject);
            SetVerifier.SetVerificationException e = assertThrows(SetVerifier.SetVerificationException.class,
                    () -> SsfSupport.receiverService().receive(jws), subject.format());
            assertEquals("invalid_request", e.errorCode(), subject.format());
            assertEquals("unparseable sub_id: unsupported subject identifier format: " + subject.format(),
                    e.getMessage());
        }
    }
}
