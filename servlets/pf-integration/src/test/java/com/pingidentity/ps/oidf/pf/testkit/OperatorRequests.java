/*
 * A mocked request as platform-pf's operator authenticator reads it.
 */
package com.pingidentity.ps.oidf.pf.testkit;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.platform.pf.auth.OperatorTestKit;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Stubs what the operator authenticator reads on a Mockito request: the {@code Authorization} and {@code DPoP}
 * headers as the container enumerates them, the request URI a proof's {@code htu} is checked against, and the
 * attributes it writes the operator to. The test stubs the method, the address and anything its servlet reads.
 */
public final class OperatorRequests {
    private OperatorRequests() {
    }

    /** {@code authorization} and {@code dpop} may each be null: no such header. */
    public static void stub(HttpServletRequest request, String requestUri, String authorization, String dpop) {
        List<String> auth = authorization == null ? List.of() : List.of(authorization);
        List<String> proofs = dpop == null ? List.of() : List.of(dpop);
        when(request.getHeaders("Authorization")).thenAnswer(i -> Collections.enumeration(auth));
        when(request.getHeaders("DPoP")).thenAnswer(i -> Collections.enumeration(proofs));
        when(request.getHeader("Authorization")).thenReturn(authorization);
        when(request.getRequestURI()).thenReturn(requestUri);
        Map<String, Object> attributes = new HashMap<>();
        doAnswer(i -> attributes.put(i.getArgument(0), i.getArgument(1))).when(request).setAttribute(anyString(), any());
        when(request.getAttribute(anyString())).thenAnswer(i -> attributes.get((String) i.getArgument(0)));
    }

    /** A DPoP-bound token from {@code kit} with {@code scopes}, and its proof for {@code method} and {@code requestUri}. */
    public static void dpop(HttpServletRequest request, OperatorTestKit kit, String method, String requestUri,
                            String... scopes) throws Exception {
        String token = kit.token(scopes);
        stub(request, requestUri, "DPoP " + token, kit.proof(token, method, requestUri));
    }
}
