/*
 * Receiver pipeline: dedup by jti, handler dispatch (failures contained), recent-events buffer.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SsfReceiverServiceTest {

    private static final String ISS = "https://transmitter.example.com";

    private final TestSigningKeyProvider keys = new TestSigningKeyProvider("tx-key");
    private final SetMinter minter = new SetMinter("RS256", keys);
    private SsfReceiverService receiver;
    private final List<ReceivedSet> handled = new ArrayList<>();

    @BeforeEach
    void setUp() {
        SetVerifier verifier = new SetVerifier(ISS, null, refresh -> {
            RsaJsonWebKey jwk = new RsaJsonWebKey(keys.publicKey());
            jwk.setKeyId(keys.keyId());
            return List.<JsonWebKey>of(jwk);
        });
        receiver = new SsfReceiverService(verifier);
        receiver.addHandler(handled::add);
    }

    private String mint(String jti) throws Exception {
        return minter.sign(SecurityEventToken.builder()
                .issuer(ISS).audience("https://r").jti(jti).issuedAt(SetMinter.nowSeconds())
                .subjectId(SubjectId.email("bob@example.com"))
                .event(SsfEventTypes.CAEP_SESSION_REVOKED, Map.of("event_timestamp", 1L)).build());
    }

    @Test
    void acceptsDispatchesAndDedupes() throws Exception {
        String jws = mint("jti-1");
        assertEquals(SsfReceiverService.Outcome.ACCEPTED, receiver.receive(jws));
        assertEquals(SsfReceiverService.Outcome.DUPLICATE, receiver.receive(jws), "redelivery acked, not re-dispatched");
        assertEquals(1, handled.size());
        assertEquals("jti-1", handled.get(0).jti());
    }

    @Test
    void handlerFailureIsContainedAndOtherHandlersStillRun() throws Exception {
        List<String> second = new ArrayList<>();
        SsfReceiverService svc = receiver; // first handler records; add a throwing one BEFORE another recorder
        svc.addHandler(set -> {
            throw new RuntimeException("boom");
        });
        svc.addHandler(set -> second.add(set.jti()));
        assertEquals(SsfReceiverService.Outcome.ACCEPTED, svc.receive(mint("jti-2")));
        assertEquals(1, handled.size());
        assertEquals(List.of("jti-2"), second, "handler after the failing one still ran");
    }

    @Test
    void recentEventsSummarisesNewestFirst() throws Exception {
        receiver.receive(mint("jti-a"));
        receiver.receive(mint("jti-b"));
        List<Map<String, Object>> recent = receiver.recentEvents();
        assertEquals(2, recent.size());
        assertEquals("jti-b", recent.get(0).get("jti"), "newest first");
        assertTrue(((List<?>) recent.get(0).get("event_types")).contains(SsfEventTypes.CAEP_SESSION_REVOKED));
    }
}
