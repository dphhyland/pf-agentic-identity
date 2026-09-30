/*
 * Where a detail's decision comes from: the request's memo, the decision cache, one AuthZEN batch, or one PDP call.
 */
package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/**
 * The PDP step of {@code enrich}, for one processor instance. For each detail PingFederate asks about:
 *
 * <ol>
 *   <li>the request's {@link DecisionMemo}: a question already answered in this HTTP request - by an earlier
 *       {@code enrich}, or by the batch - is answered again, and the PDP is not asked;</li>
 *   <li>the {@link DecisionCache}, for the types an operator listed (never a payment, never a type that needs an
 *       authenticated principal);</li>
 *   <li>with an AuthZEN batch URL, the first question of a request that the memo cannot answer sends every detail
 *       the request carries in one Access Evaluations call ({@link AuthZenPdpClient#decideAll}), and the memo answers
 *       the rest as PingFederate asks for them;</li>
 *   <li>otherwise one call for this detail ({@link PdpClient#decide}).</li>
 * </ol>
 *
 * <p>What is asked is the same whichever route answers: the decision is always the PDP's, for exactly the question
 * this detail makes ({@link #keyOf}), and enforcement after it - deny unless PERMIT, the statements, the narrowing
 * check - is the processor's, unchanged.
 */
final class PdpDecisions {

    /** One question for the PDP: what {@link PdpClient#decide} takes. */
    record Ask(String type, Map<String, Object> detail, AttestationSubject subject, String owner, String clientId,
               String source) { }

    /** Past this many evaluations a batch is not sent; each detail is then asked on its own. */
    static final int MAX_BATCH = 64;

    private static final ObjectMapper CANONICAL = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    private final PdpClient client;
    private final DecisionCache cache;
    private final String cacheScope;
    private final String memoAttribute;

    /**
     * @param cache      the decision cache, or {@code null} for none
     * @param cacheScope what a cached decision is only valid for besides its question: the PDP and the RAR models
     * @param memoAttribute the request attribute this instance keeps its memo under
     */
    PdpDecisions(PdpClient client, DecisionCache cache, String cacheScope, String memoAttribute) {
        this.client = client;
        this.cache = cache;
        this.cacheScope = cacheScope == null ? "" : cacheScope;
        this.memoAttribute = memoAttribute;
    }

    PdpClient client() {
        return client;
    }

    DecisionCache cache() {
        return cache;
    }

    /**
     * The decision for {@code ask}.
     *
     * @param request the servlet request PingFederate passed, which holds the memo; {@code null} means no memo
     * @param others  every other question this request carries, for the batch; asked for at most once per request
     *                and only when a batch URL is configured
     */
    DecisionResponse decide(HttpServletRequest request, Ask ask, Supplier<List<Ask>> others) throws IOException {
        String key = keyOf(ask);
        DecisionMemo memo = key == null ? null : DecisionMemo.of(request, memoAttribute);
        if (memo != null && memo.has(key)) {
            PdpMetrics.answer(PdpMetrics.SOURCE_MEMO);
            return memo.answer(key);
        }
        DecisionResponse cached = cached(ask, key);
        if (cached != null) {
            if (memo != null) {
                memo.remember(key, cached);
            }
            PdpMetrics.answer(PdpMetrics.SOURCE_CACHE);
            return cached;
        }
        if (memo != null && client instanceof AuthZenPdpClient authzen && authzen.batches() && !memo.batched()) {
            memo.markBatched();
            DecisionResponse batched = batch(authzen, memo, ask, key, others);
            if (batched != null) {
                PdpMetrics.answer(PdpMetrics.SOURCE_PDP);
                return batched;
            }
        }
        DecisionResponse decision;
        try {
            decision = client.decide(ask.type(), ask.detail(), ask.subject(), ask.owner(), ask.clientId(), ask.source());
        } catch (IOException e) {
            if (memo != null) {
                memo.rememberFailure(key, e);
            }
            throw e;
        }
        if (memo != null) {
            memo.remember(key, decision);
        }
        store(ask, key, decision);
        PdpMetrics.answer(PdpMetrics.SOURCE_PDP);
        return decision;
    }

    /**
     * Sends {@code ask} and the request's other questions in one Access Evaluations call, and remembers every answer
     * (or the call's failure, for each of them). {@code null} when there is no second question worth batching: the
     * caller then asks for this detail alone, through the single evaluation endpoint.
     */
    private DecisionResponse batch(AuthZenPdpClient authzen, DecisionMemo memo, Ask ask, String key,
                                   Supplier<List<Ask>> others) throws IOException {
        Map<String, Ask> batch = new LinkedHashMap<>();
        batch.put(key, ask);
        List<Ask> more = others == null ? List.of() : others.get();
        for (Ask other : more == null ? List.<Ask>of() : more) {
            String otherKey = keyOf(other);
            if (otherKey != null && !batch.containsKey(otherKey) && !memo.has(otherKey) && cached(other, otherKey) == null) {
                batch.put(otherKey, other);
            }
        }
        if (batch.size() < 2 || batch.size() > MAX_BATCH) {
            return null;
        }
        List<String> keys = new ArrayList<>(batch.keySet());
        List<Ask> asks = new ArrayList<>(batch.values());
        List<DecisionResponse> answers;
        try {
            answers = PdpMetrics.inBatch(() -> authzen.decideAll(asks));
        } catch (IOException e) {
            for (String k : keys) {
                memo.rememberFailure(k, e);
            }
            throw e;
        }
        for (int i = 0; i < keys.size(); i++) {
            memo.remember(keys.get(i), answers.get(i));
            store(asks.get(i), keys.get(i), answers.get(i));
        }
        return answers.get(0);
    }

    private DecisionResponse cached(Ask ask, String key) {
        if (cache == null || key == null || !cache.covers(ask.type())) {
            return null;
        }
        return cache.get(cacheKey(key));
    }

    private void store(Ask ask, String key, DecisionResponse decision) {
        if (cache != null && key != null && cache.covers(ask.type())) {
            cache.put(cacheKey(key), decision);
        }
    }

    private String cacheKey(String key) {
        return digest(cacheScope + "\n" + key);
    }

    /**
     * A digest of everything {@code ask} puts to the PDP: the type, the detail (map keys sorted, so the order a client
     * wrote them in does not matter), the principal and how it was established, the client, and the whole attestation
     * context - its client, subject, agent instance, attester {@code iss}, entitlement, workload, key thumbprint,
     * verified subject-token subject and RAR models fingerprint. {@code null} when the question cannot be written down
     * (a detail value JSON cannot hold): that question is then never remembered or cached, only asked.
     */
    static String keyOf(Ask ask) {
        AttestationSubject s = ask.subject() == null ? AttestationSubject.empty() : ask.subject();
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("subject", s.getSubject());
        subject.put("client_id", s.getClientId());
        subject.put("agent_id", s.getAgentId());
        subject.put("iss", s.getAttesterIssuer());
        subject.put("entitlement", s.getEntitlement());
        subject.put("workload", s.getWorkload());
        subject.put("cnf", s.getCnfThumbprint());
        subject.put("verified_subject", s.getVerifiedSubjectTokenSubject());
        subject.put("rar_models", s.getRarModelsFingerprint());
        subject.put("present", s.isContextPresent());
        Map<String, Object> question = new LinkedHashMap<>();
        question.put("type", ask.type());
        question.put("detail", ask.detail());
        question.put("owner", ask.owner());
        question.put("client_id", ask.clientId());
        question.put("source", ask.source());
        question.put("attestation", subject);
        try {
            return digest(CANONICAL.writeValueAsString(question));
        } catch (JsonProcessingException | RuntimeException e) {
            return null;
        }
    }

    static String digest(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is missing from this JVM", e);
        }
    }

    /** The distinct types in a list field, blanks dropped; blank or a single {@code -} is none. */
    static Set<String> typesOf(String field) {
        Set<String> types = new LinkedHashSet<>();
        if (field != null) {
            for (String type : field.split("[,\\s]+")) {
                if (!type.isBlank() && !"-".equals(type.trim())) {
                    types.add(type.trim());
                }
            }
        }
        return types;
    }
}
