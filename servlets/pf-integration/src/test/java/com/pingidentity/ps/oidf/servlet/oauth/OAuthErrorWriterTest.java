package com.pingidentity.ps.oidf.servlet.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;

class OAuthErrorWriterTest {

    @Test
    @Requirement("RFC6749 §5.2")
    void anErrorIsJsonThatIsNeverCachedAndStaysInsideTheCharacterSet() throws Exception {
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter body = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(body));

        OAuthErrorWriter.write(response, 401, "invalid_client", "renew it by registering again (OpenID Federation 1.0 §12.3), \"now\"");

        verify(response).setStatus(401);
        verify(response).setContentType("application/json");
        verify(response).setHeader("Cache-Control", "no-store");
        verify(response).setHeader("Pragma", "no-cache");
        Map<String, Object> json = JsonUtil.parseJson(body.toString());
        assertEquals("invalid_client", json.get("error"));
        assertEquals("renew it by registering again (OpenID Federation 1.0  12.3),  now ", json.get("error_description"),
                "§ and the double quotes are outside %x20-21 / %x23-5B / %x5D-7E");
    }
}
