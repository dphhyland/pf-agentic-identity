package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.sourceid.saml20.adapter.attribute.AttributeValue;

/**
 * Token claims come from the VERIFIED attestation, not from the presented header.
 *
 * <p>{@code attestationClaim} used to base64-decode the {@code OAuth-Client-Attestation} header and put
 * the result straight into an issued access token. Its javadoc justified that by pointing at the
 * sibling {@code validateClientAttestation} issuance criterion: a bad attestation is rejected, so no
 * token is issued, so an unverified read is harmless.
 *
 * <p>That holds only where the criterion is actually configured on the mapping. It is a claim about a
 * deployment's PingFederate configuration, made in Java, that Java cannot check — and the code has to
 * be safe on its own terms. So the value now comes from what the token-endpoint filter published after
 * verifying, and an unverified header contributes nothing to a token no matter how PF is configured.
 */
class AttestationClaimSourceTest {

    private static final String ATTACKER_SPIFFE = "spiffe://banking.demo/workload/treasury-admin";

    /** A syntactically valid attestation the attacker signed with nothing anyone trusts. */
    private static String unverifiedAttestation() {
        String payload = "{\"sub\":\"https://rp.example.com/attacker\",\"agent_id\":\"attacker-agent\","
                + "\"iss\":\"https://attester.attacker.example\","
                + "\"workload\":{\"spiffe_id\":\"" + ATTACKER_SPIFFE + "\",\"trust_domain\":\"banking.demo\"}}";
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString("{\"alg\":\"ES256\"}".getBytes(StandardCharsets.UTF_8))
                + "." + b64.encodeToString(payload.getBytes(StandardCharsets.UTF_8))
                + ".not-a-real-signature";
    }

    private static HttpServletRequest request(Map<String, Object> verifiedContext, String attestationHeader) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        Map<String, Object> attributes = new HashMap<>();
        if (verifiedContext != null) {
            attributes.put(ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE, verifiedContext);
        }
        when(request.getAttribute(anyString())).thenAnswer(i -> attributes.get(i.getArgument(0)));
        when(request.getHeaders(anyString())).thenAnswer(i ->
                "OAuth-Client-Attestation".equals(i.getArgument(0)) && attestationHeader != null
                        ? Collections.enumeration(Collections.singletonList(attestationHeader))
                        : Collections.emptyEnumeration());
        when(request.getHeader(anyString())).thenAnswer(i ->
                "OAuth-Client-Attestation".equals(i.getArgument(0)) ? attestationHeader : null);
        return request;
    }

    private static Map<String, Object> inParams(HttpServletRequest request, String clientId) {
        Map<String, Object> in = new HashMap<>();
        AttributeValue requestValue = mock(AttributeValue.class);
        when(requestValue.getObjectValue()).thenReturn(request);
        in.put("context.HttpRequest", requestValue);
        AttributeValue clientValue = mock(AttributeValue.class);
        when(clientValue.getValue()).thenReturn(clientId);
        in.put("context.ClientId", clientValue);
        return in;
    }

    /** The shape {@code attestationContext} publishes, for a client the attester really did vouch for. */
    private static Map<String, Object> verifiedContext() {
        Map<String, Object> ctx = new LinkedHashMap<>();
        ctx.put("sub", "https://rp.example.com/agent-1");
        ctx.put("client_id", "https://rp.example.com/agent-1");
        ctx.put("agent_id", "agent-1-instance-7");
        ctx.put("iss", "https://attester.example.com");
        ctx.put("entitlement", java.util.List.of(Map.of("type", "sales_agent")));
        Map<String, Object> workload = new LinkedHashMap<>();
        workload.put("spiffe_id", "spiffe://banking.demo/workload/payment-agent");
        workload.put("trust_domain", "banking.demo");
        ctx.put("workload", workload);
        ctx.put("spiffe_id", "spiffe://banking.demo/workload/payment-agent");
        return ctx;
    }

    // ---- the security property ---------------------------------------------------------------------

    /**
     * The case the old javadoc's reasoning depended on a configuration to prevent: a mapping without the
     * issuance criterion, or any path where the filter did not verify. The header is present, well-formed
     * and entirely attacker-chosen. It must not reach the token.
     */
    @Test
    void anUnverifiedHeaderContributesNothing() {
        Map<String, Object> in = inParams(request(null, unverifiedAttestation()), "https://rp.example.com/attacker");

        assertEquals("", ClientAttestationUtils.attestationClaim(in, "spiffe_id"));
        assertEquals("", ClientAttestationUtils.attestationClaim(in, "client_id"));
        assertEquals("", ClientAttestationUtils.attestationClaim(in, "agent_id"));
        assertEquals("", ClientAttestationUtils.attestationClaim(in, "iss"));
        assertEquals("", ClientAttestationUtils.attestationClaim(in, "trust_domain"));
    }

    /**
     * Presence of a header must not override a verification. If both are readable the verified one wins,
     * so a request that smuggles a second, richer attestation past a filter that verified a first one
     * still gets the claims that were actually vouched for.
     */
    @Test
    void theVerifiedContextWinsOverAContradictingHeader() {
        Map<String, Object> in = inParams(request(verifiedContext(), unverifiedAttestation()),
                "https://rp.example.com/agent-1");

        assertEquals("spiffe://banking.demo/workload/payment-agent",
                ClientAttestationUtils.attestationClaim(in, "spiffe_id"));
        assertFalse(ClientAttestationUtils.attestationClaim(in, "spiffe_id").contains("treasury-admin"));
        assertEquals("https://rp.example.com/agent-1", ClientAttestationUtils.attestationClaim(in, "client_id"));
    }

    // ---- it still reads what it is supposed to read -------------------------------------------------

    /** No header at all: if these resolve, they can only have come from the published verification. */
    @Test
    void claimsResolveFromThePublishedContextWithNoHeaderPresent() {
        Map<String, Object> in = inParams(request(verifiedContext(), null), "https://rp.example.com/agent-1");

        assertEquals("https://rp.example.com/agent-1", ClientAttestationUtils.attestationClaim(in, "client_id"));
        assertEquals("agent-1-instance-7", ClientAttestationUtils.attestationClaim(in, "agent_id"));
        assertEquals("https://attester.example.com", ClientAttestationUtils.attestationClaim(in, "iss"));
    }

    /** Nested workload values stay reachable by their bare name, as the OGNL call sites spell them. */
    @Test
    void aNestedWorkloadValueIsFoundByItsBareName() {
        Map<String, Object> in = inParams(request(verifiedContext(), null), "https://rp.example.com/agent-1");

        assertEquals("banking.demo", ClientAttestationUtils.attestationClaim(in, "trust_domain"));
    }

    /** A structured value maps to nothing rather than to a Java toString of a List or Map. */
    @Test
    void structuredContextEntriesDoNotLeakAToString() {
        Map<String, Object> in = inParams(request(verifiedContext(), null), "https://rp.example.com/agent-1");

        assertEquals("", ClientAttestationUtils.attestationClaim(in, "entitlement"));
        assertEquals("", ClientAttestationUtils.attestationClaim(in, "workload"));
    }

    @Test
    void anAbsentClaimIsAnEmptyStringNotAFailure() {
        Map<String, Object> in = inParams(request(verifiedContext(), null), "https://rp.example.com/agent-1");

        assertEquals("", ClientAttestationUtils.attestationClaim(in, "no_such_claim"));
    }

    // ---- the delegation chain inherits the same source ----------------------------------------------

    @Test
    void theDelegationChainNamesTheVerifiedInstanceAndAttester() {
        Map<String, Object> in = inParams(request(verifiedContext(), null), "https://rp.example.com/agent-1");

        String act = ClientAttestationUtils.delegationActChain(in);

        assertTrue(act.contains("\"sub\":\"agent-1-instance-7\""), act);
        assertTrue(act.contains("\"iss\":\"https://attester.example.com\""), act);
    }

    /**
     * With nothing verified, the acting party falls back to the client PF authenticated — never to the
     * attacker-named agent_id or attester in the header.
     */
    @Test
    void anUnverifiedChainFallsBackToTheAuthenticatedClient() {
        Map<String, Object> in = inParams(request(null, unverifiedAttestation()), "https://rp.example.com/agent-1");

        String act = ClientAttestationUtils.delegationActChain(in);

        assertTrue(act.contains("\"sub\":\"https://rp.example.com/agent-1\""), act);
        assertFalse(act.contains("attacker"), act);
    }
}
