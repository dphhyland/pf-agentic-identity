/*
 * Poll client: pulls SETs into the receiver pipeline, acks on the next cycle, contains failures.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PollReceiverClientTest {

    private static final String ISS = "https://transmitter.example.com";

    private final TestSigningKeyProvider keys = new TestSigningKeyProvider("tx-key");
    private final SetMinter minter = new SetMinter("RS256", keys);
    private SsfReceiverService receiver;
    private final List<ReceivedSet> handled = new ArrayList<>();
    private final List<String> pollBodies = new ArrayList<>();

    @BeforeEach
    void setUp() {
        receiver = new SsfReceiverService(new SetVerifier(ISS, null, refresh -> {
            RsaJsonWebKey jwk = new RsaJsonWebKey(keys.publicKey());
            jwk.setKeyId(keys.keyId());
            return List.<JsonWebKey>of(jwk);
        }));
        receiver.addHandler(handled::add);
    }

    private String mint(String jti) throws Exception {
        return minter.sign(SecurityEventToken.builder()
                .issuer(ISS).audience("https://r").jti(jti).issuedAt(SetMinter.nowSeconds())
                .subjectId(SubjectId.opaque("bob"))
                .event(SsfEventTypes.CAEP_SESSION_REVOKED, Map.of()).build());
    }

    @Test
    void pollsReceivesAndAcksNextCycle() throws Exception {
        String jws = mint("jti-1");
        PollReceiverClient client = new PollReceiverClient(receiver, body -> {
            pollBodies.add(body);
            // first poll returns one SET; later polls return none
            return pollBodies.size() == 1
                    ? JsonUtil.toJson(Map.of("sets", Map.of("jti-1", jws), "moreAvailable", false))
                    : JsonUtil.toJson(Map.of("sets", Map.of(), "moreAvailable", false));
        }, 50);

        assertEquals(1, client.runOnce(), "one SET processed");
        assertEquals(1, handled.size());
        assertTrue(!pollBodies.get(0).contains("\"ack\""), "first poll carries no acks");

        client.runOnce();
        assertTrue(pollBodies.get(1).contains("jti-1"), "second poll acks the processed jti");
    }

    @Test
    void unverifiableSetIsAckedNotRetried() throws Exception {
        PollReceiverClient client = new PollReceiverClient(receiver, body -> {
            pollBodies.add(body);
            return pollBodies.size() == 1
                    ? JsonUtil.toJson(Map.of("sets", Map.of("bad-jti", "garbage-not-a-jws")))
                    : JsonUtil.toJson(Map.of("sets", Map.of()));
        }, 50);
        assertEquals(0, client.runOnce(), "nothing processed");
        client.runOnce();
        assertTrue(pollBodies.get(1).contains("bad-jti"), "permanently-bad SET still acked (no redelivery loop)");
        assertTrue(handled.isEmpty());
    }

    @Test
    void transportFailureKeepsPendingAcks() throws Exception {
        String jws = mint("jti-2");
        int[] calls = {0};
        PollReceiverClient client = new PollReceiverClient(receiver, body -> {
            calls[0]++;
            pollBodies.add(body);
            if (calls[0] == 1) {
                return JsonUtil.toJson(Map.of("sets", Map.of("jti-2", jws)));
            }
            if (calls[0] == 2) {
                throw new java.io.IOException("transmitter down");
            }
            return JsonUtil.toJson(Map.of("sets", Map.of()));
        }, 50);
        client.runOnce();               // receives jti-2
        client.runOnce();               // ack attempt fails — acks must be retained
        client.runOnce();               // retried here
        assertTrue(pollBodies.get(2).contains("jti-2"), "ack retried after transport failure");
    }
}
