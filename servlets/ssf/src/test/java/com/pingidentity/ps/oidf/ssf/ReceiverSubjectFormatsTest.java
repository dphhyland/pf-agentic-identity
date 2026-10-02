/*
 * The configured receiver takes an inbound sub_id in every format it maps (H-SSF-1), and refuses SSF's token and address formats.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.pingidentity.ps.oidf.conformance.Requirement;
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
 * shared-signals' {@link SetVerifier} accepts every format {@link SubjectId} parses by default. {@link SsfSupport} builds
 * the receiver's verifier with {@link SsfSubjects#RECEIVER_FORMATS}; these tests go through {@link SsfSupport#configure},
 * so a receiver wired with the default, or with the transmitter's five, fails them.
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
    @Requirement("RFC9493 §3.2")
    void aSubjectInEveryFormatTheReceiverMapsIsAccepted() throws Exception {
        List<SubjectId> accepted = List.of(SubjectId.email("bob@example.com"), SubjectId.did("did:example:123"),
                SubjectId.uri("https://user.example.com/"),
                SubjectId.aliases(List.of(SubjectId.email("bob@example.com"), SubjectId.opaque("abc"))),
                SubjectId.complex(Map.of("user", SubjectId.email("bob@example.com"))));
        int n = 0;
        for (SubjectId subject : accepted) {
            assertEquals(SsfReceiverService.Outcome.ACCEPTED,
                    SsfSupport.receiverService().receive(mint("jti-ok-" + n++, subject)), subject.format());
        }
    }

    /** SSF 1.0 §3.5's formats name a token or addresses, never a user or device: refused at the top level. */
    @Test
    @Requirement("SSF §3.5")
    void aTokenOrAddressSubjectIsRefusedAsAnInvalidRequest() throws Exception {
        List<SubjectId> outside = List.of(SubjectId.jwtId("https://idp.example.com", "j-1"),
                SubjectId.samlAssertionId("https://idp.example.com", "a-1"),
                SubjectId.ipAddresses(List.of("192.0.2.1")));
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
