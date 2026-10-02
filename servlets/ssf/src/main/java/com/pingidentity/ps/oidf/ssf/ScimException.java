/*
 * A SCIM request refused, as RFC 7644 §3.12 reports it.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A SCIM request the endpoint refuses, carrying what RFC 7644 §3.12 puts in the error body: the HTTP status, the
 * optional {@code scimType} detail keyword (Table 9) and a {@code detail}. {@link #body()} is that body. RFC 7644
 * §3.12: "implementers MUST return the errors in the body of the response in a JSON format, using the attributes
 * described below", identified by the schema {@value #ERROR_SCHEMA}, with {@code status} "The HTTP status code ...
 * expressed as a JSON string. REQUIRED."
 */
public final class ScimException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public static final String ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";

    private final int status;
    private final String scimType;

    public ScimException(int status, String scimType, String detail) {
        super(detail);
        this.status = status;
        this.scimType = scimType;
    }

    /** 400 with a Table 9 {@code scimType}. */
    public static ScimException badRequest(String scimType, String detail) {
        return new ScimException(400, scimType, detail);
    }

    public static ScimException notFound(String detail) {
        return new ScimException(404, null, detail);
    }

    public int status() {
        return this.status;
    }

    /** The Table 9 keyword, or {@code null}. */
    public String scimType() {
        return this.scimType;
    }

    /** The RFC 7644 §3.12 error body. */
    public Map<String, Object> body() {
        return body(this.status, this.scimType, getMessage());
    }

    /** An RFC 7644 §3.12 error body; {@code scimType} and {@code detail} are left out when {@code null}. */
    public static Map<String, Object> body(int status, String scimType, String detail) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        m.put("schemas", List.of(ERROR_SCHEMA));
        if (scimType != null) {
            m.put("scimType", scimType);
        }
        if (detail != null) {
            m.put("detail", detail);
        }
        m.put("status", Integer.toString(status));
        return m;
    }
}
