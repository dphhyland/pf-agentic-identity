/*
 * One PDP decision per distinct question within one HTTP request, however many times PingFederate asks.
 */
package com.pingidentity.ps.oidf.rar;

import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The per-request memo, held as an attribute of the servlet request PingFederate hands {@code enrich}, so it lives
 * exactly as long as the HTTP request and is never shared between two.
 *
 * <p>What it rests on, read with {@code javap -c} of pf-protocolengine 13.1.3.0 on 2026-09-29: every caller of
 * {@code AuthorizationDetailsUtil.enrich} - {@code ClientCredentialsGrantProcessor}, {@code RefreshTokenGrantProcessor},
 * {@code TokenExchangeRequest}, {@code CibaAuthenticationRequestHandler}, {@code OIDCRequestParamHandler},
 * {@code UserAuthorizationRequestHandler} and {@code OAuthResumableRequestHandlerBase} - passes the request's whole
 * {@code AuthorizationDetails}; {@code enrich} builds one {@code AuthorizationDetailContext} carrying that request and
 * calls {@code getDetails().forEach(...)}, which calls the processor's {@code enrich} once per detail, in order, on the
 * calling thread. Nothing in it runs in parallel, but the memo is synchronised anyway: it costs nothing uncontended.
 *
 * <p>The key is a digest of everything the PDP is asked ({@link PdpDecisions#keyOf}), so two details that would make
 * the same request get one decision, and two that differ in anything get their own. A failure is remembered too: a
 * batch that failed answers each of its details with the same failure, which fails open or closed as that failure
 * would have. A decision is stored and handed out as a deep copy, because applying a statement can write into the
 * payload it came with.
 */
final class DecisionMemo {

    /** More distinct questions than any request PingFederate accepts would carry; past it, nothing more is remembered. */
    static final int MAX_ENTRIES = 256;

    private final Map<String, Object> outcomes = new LinkedHashMap<>();
    private boolean batched;

    /**
     * The memo on {@code request} under {@code attribute}, made and attached if there is none; {@code null} when there
     * is no request, or it will not hold an attribute (then nothing is remembered and every question is asked).
     */
    static DecisionMemo of(HttpServletRequest request, String attribute) {
        if (request == null) {
            return null;
        }
        try {
            Object existing = request.getAttribute(attribute);
            if (existing instanceof DecisionMemo memo) {
                return memo;
            }
            DecisionMemo memo = new DecisionMemo();
            request.setAttribute(attribute, memo);
            return request.getAttribute(attribute) == memo ? memo : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Whether this request has already sent its batch (or tried to). */
    synchronized boolean batched() {
        return batched;
    }

    synchronized void markBatched() {
        batched = true;
    }

    synchronized boolean has(String key) {
        return outcomes.containsKey(key);
    }

    /**
     * The remembered answer for {@code key}: a copy of the decision, or the remembered failure thrown again.
     *
     * @return {@code null} when nothing is remembered for it
     */
    synchronized DecisionResponse answer(String key) throws IOException {
        Object outcome = outcomes.get(key);
        if (outcome instanceof IOException failure) {
            throw failure;
        }
        return outcome == null ? null : copyOf((DecisionResponse) outcome);
    }

    synchronized void remember(String key, DecisionResponse decision) {
        put(key, copyOf(decision));
    }

    synchronized void rememberFailure(String key, IOException failure) {
        put(key, failure);
    }

    synchronized int size() {
        return outcomes.size();
    }

    private void put(String key, Object outcome) {
        if (outcomes.containsKey(key) || outcomes.size() < MAX_ENTRIES) {
            outcomes.put(key, outcome);
        }
    }

    /** A decision whose statements' payloads are copies: applying one never reaches the remembered one. */
    static DecisionResponse copyOf(DecisionResponse decision) {
        // DecisionResponse holds an empty list for none, never null.
        List<DecisionResponse.Statement> statements = new ArrayList<>();
        for (DecisionResponse.Statement s : decision.getStatements()) {
            statements.add(new DecisionResponse.Statement(s.getName(), copyValue(s.getPayload())));
        }
        return new DecisionResponse(decision.getDecision(), decision.getAuthorised(), statements, decision.getRawBody());
    }

    static Object copyValue(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<Object, Object> copy = new LinkedHashMap<>();
            map.forEach((k, v) -> copy.put(k, copyValue(v)));
            return copy;
        }
        if (value instanceof List<?> list) {
            List<Object> copy = new ArrayList<>(list.size());
            list.forEach(v -> copy.add(copyValue(v)));
            return copy;
        }
        return value;
    }
}
