/*
 * Signing federation JWTs for tests, with every header and claim under the test's control.
 */
package com.pingidentity.ps.oidf.federation.testkit;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

/**
 * Builds signed JWTs of any federation kind. The {@link Spec} starts from the correct statement for its
 * kind and lets a test break exactly one thing: drop the {@code typ}, change the {@code alg}, remove the
 * {@code kid}, back-date the {@code iat}, sign with another key, remove a claim.
 */
public final class Statements {
    public static final String ENTITY_STATEMENT_TYP = "entity-statement+jwt";
    public static final String TRUST_MARK_TYP = "trust-mark+jwt";
    public static final String TRUST_MARK_DELEGATION_TYP = "trust-mark-delegation+jwt";
    public static final String RESOLVE_RESPONSE_TYP = "resolve-response+jwt";
    public static final String JWK_SET_TYP = "jwk-set+jwt";

    private Statements() {
    }

    /** A new spec for a statement of the given {@code typ}, issued now for an hour. */
    public static Spec spec(String typ) {
        return new Spec(typ);
    }

    /** Mutable description of one JWT; {@link #sign} renders it. */
    public static final class Spec {
        private String typ;
        private String alg;
        private String kid;
        private boolean kidExplicit;
        private final Map<String, Object> headers = new LinkedHashMap<>();
        private Long iat;
        private Long exp;
        private boolean omitIat;
        private boolean omitExp;
        private final Map<String, Object> claims = new LinkedHashMap<>();
        private final Set<String> removed = new LinkedHashSet<>();
        private PublicJsonWebKey signWith;
        private boolean unsigned;
        private long lifetimeSeconds = 3600L;
        private long issuedSecondsAgo = 60L;

        private Spec(String typ) {
            this.typ = typ;
        }

        /** The {@code typ} header; {@code null} leaves it off. */
        public Spec typ(String value) {
            this.typ = value;
            return this;
        }

        public Spec alg(String value) {
            this.alg = value;
            return this;
        }

        /** The {@code kid} header; {@code null} leaves it off, an empty string sends it empty. */
        public Spec kid(String value) {
            this.kid = value;
            this.kidExplicit = true;
            return this;
        }

        public Spec header(String name, Object value) {
            this.headers.put(name, value);
            return this;
        }

        public Spec iat(long epochSeconds) {
            this.iat = epochSeconds;
            return this;
        }

        public Spec exp(long epochSeconds) {
            this.exp = epochSeconds;
            return this;
        }

        public Spec withoutIat() {
            this.omitIat = true;
            return this;
        }

        public Spec withoutExp() {
            this.omitExp = true;
            return this;
        }

        public Spec lifetimeSeconds(long seconds) {
            this.lifetimeSeconds = seconds;
            return this;
        }

        public Spec claim(String name, Object value) {
            this.claims.put(name, value);
            this.removed.remove(name);
            return this;
        }

        public Spec claims(Map<String, Object> values) {
            values.forEach(this::claim);
            return this;
        }

        public Spec remove(String name) {
            this.removed.add(name);
            return this;
        }

        /** Sign with this key instead of the statement's rightful one. */
        public Spec signWith(PublicJsonWebKey key) {
            this.signWith = key;
            return this;
        }

        /** Produce an {@code alg: none} token with an empty signature. */
        public Spec unsigned() {
            this.unsigned = true;
            return this;
        }

        boolean hasClaim(String name) {
            return this.claims.containsKey(name) && !this.removed.contains(name);
        }

        Object claimValue(String name) {
            return this.removed.contains(name) ? null : this.claims.get(name);
        }

        /** Renders the JWT with {@code key} (unless {@link #signWith} replaced it), times from {@code clock}. */
        public String sign(PublicJsonWebKey key, Clock clock) {
            long now = clock.instant().getEpochSecond();
            Map<String, Object> payload = new LinkedHashMap<>();
            if (!this.omitIat) {
                payload.put("iat", this.iat != null ? this.iat : now - this.issuedSecondsAgo);
            }
            if (!this.omitExp) {
                payload.put("exp", this.exp != null ? this.exp : now + this.lifetimeSeconds);
            }
            payload.putAll(this.claims);
            for (String name : this.removed) {
                payload.remove(name);
            }
            PublicJsonWebKey signer = this.signWith != null ? this.signWith : key;
            if (this.unsigned) {
                Map<String, Object> header = new LinkedHashMap<>();
                header.put("alg", "none");
                if (this.typ != null) {
                    header.put("typ", this.typ);
                }
                header.putAll(this.headers);
                Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
                return b64.encodeToString(JsonUtil.toJson(header).getBytes(StandardCharsets.UTF_8)) + "."
                        + b64.encodeToString(JsonUtil.toJson(payload).getBytes(StandardCharsets.UTF_8)) + ".";
            }
            try {
                JsonWebSignature jws = new JsonWebSignature();
                jws.setPayload(JsonUtil.toJson(payload));
                jws.setKey(signer.getPrivateKey());
                jws.setAlgorithmHeaderValue(this.alg != null ? this.alg : Keys.defaultAlg(signer));
                if (this.typ != null) {
                    jws.setHeader("typ", this.typ);
                }
                String effectiveKid = this.kidExplicit ? this.kid : signer.getKeyId();
                if (effectiveKid != null) {
                    jws.setKeyIdHeaderValue(effectiveKid);
                }
                for (Map.Entry<String, Object> header : this.headers.entrySet()) {
                    jws.getHeaders().setObjectHeaderValue(header.getKey(), header.getValue());
                }
                return jws.getCompactSerialization();
            } catch (JoseException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
