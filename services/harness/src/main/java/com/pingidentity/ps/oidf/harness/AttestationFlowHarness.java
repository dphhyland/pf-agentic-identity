/*
 * Test harness for the OAuth 2.0 Attestation-Based Client Authentication module
 * (draft-ietf-oauth-attestation-based-client-auth-10) deployed in PingFederate.
 *
 * Ported from pf-oidf-modules (2026-08-18) when that repo was reduced to the demo UI + shell probes.
 * The reflection-based class names below were updated for the unwound package layout
 * (...oidf.common -> ...oidf.clientattestation); nothing else about the harness changed.
 *
 * Two modes:
 *
 *   live <baseUrl> [tokenEndpoint] [clientId]
 *       Talks to a DEPLOYED instance. Fetches a real challenge from
 *       <baseUrl>/federation/attestation-challenge, mints a complete Client
 *       Attestation JWT + PoP JWT (and a DPoP combined-mode proof) that echo the
 *       challenge, and prints the OAuth-Client-Attestation / -PoP (and DPoP)
 *       headers plus a ready-to-run curl against the token endpoint.
 *
 *   selfverify
 *       Runs the module's REAL ClientAttestationVerifier in-process (no network,
 *       no PF) and asserts that a correctly-built request is accepted in both PoP
 *       and DPoP modes, and that a tampered DPoP key is rejected. Proves the
 *       deployed verification logic end-to-end.
 *
 * Classpath: jose4j (always) + client-attestation (for `selfverify`, resolved via reflection so this
 * file compiles even without it on the classpath). See services/harness/README.md.
 */
package com.pingidentity.ps.oidf.harness;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;

public final class AttestationFlowHarness {

    static final String ATTESTATION_TYP = "oauth-client-attestation+jwt";
    static final String POP_TYP = "oauth-client-attestation-pop+jwt";
    static final String DPOP_TYP = "dpop+jwt";

    // Workload identity the attester vouches for (carried as the attestation's "workload" claim).
    static final String SOFTWARE_ID = "pf-oidf-attestation-harness";
    static final String SOFTWARE_VERSION = "0.0.1-SNAPSHOT";
    private static final String INSTANCE_ID = java.util.UUID.randomUUID().toString();
    private static volatile Map<String, Object> WORKLOAD;

    public static void main(String[] args) throws Exception {
        // PingFederate serves a self-signed cert (CN=localhost) behind the TCP proxy;
        // accept it for this dev/test harness (chain + hostname).
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        String mode = args.length > 0 ? args[0] : "selfverify";
        switch (mode) {
            case "live" -> live(args);
            case "selfverify" -> { if (selfVerify() > 0) System.exit(1); }
            default -> {
                System.err.println("usage: AttestationFlowHarness <live|selfverify> [baseUrl] [tokenEndpoint] [clientId]");
                System.exit(2);
            }
        }
    }

    // ---------------------------------------------------------------- live mode

    private static void live(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: AttestationFlowHarness live <baseUrl> [tokenEndpoint] [clientId]");
            System.err.println("  e.g. AttestationFlowHarness live https://<pf-host>            (modules merged into pf-runtime.war)");
            System.err.println("       AttestationFlowHarness live https://<pf-host>/oidf       (loose oidf.war under /oidf)");
            System.exit(2);
        }
        String baseUrl = stripTrailingSlash(args[1]);
        String clientId = args.length > 3 ? args[3] : "https://rp.example.com";
        String tokenEndpoint = args.length > 2 ? args[2] : baseUrl + "/as/token.oauth2";
        String challengeUrl = baseUrl + "/federation/attestation-challenge";

        // Use a fixed attester key when OIDF_ATTESTER_JWK is set (must match the server's
        // mock-attesters trust file); otherwise a random one (which a federation/mock-trusted
        // server will reject).
        PublicJsonWebKey attesterKey = attesterKey();
        PublicJsonWebKey instanceKey = ec("instance-1");

        System.out.println("== Attestation client-auth harness (live) ==");
        System.out.println("challenge endpoint : " + challengeUrl);
        System.out.println("token endpoint     : " + tokenEndpoint);
        System.out.println("client_id          : " + clientId);
        System.out.println();

        // 1) fetch a real challenge from the deployed servlet
        HttpClient http = httpClient();
        HttpResponse<String> chResp = http.send(
                HttpRequest.newBuilder(URI.create(challengeUrl)).POST(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString());
        require(chResp.statusCode() == 200, "challenge endpoint returned HTTP " + chResp.statusCode());
        require("no-store".equalsIgnoreCase(chResp.headers().firstValue("cache-control").orElse("")),
                "challenge response missing Cache-Control: no-store");
        Map<String, Object> chJson = JsonUtil.parseJson(chResp.body());
        String challenge = (String) chJson.get("attestation_challenge");
        require(challenge != null && !challenge.isBlank(), "no attestation_challenge in response");
        System.out.println("[1] fetched challenge: " + challenge + "  (expires_in=" + chJson.get("expires_in") + ")");

        // Optionally omit the challenge (OIDF_NO_CHALLENGE=1) — needed until the challenge
        // servlet and the runtime hook share one challenge store.
        String popChallenge = "1".equals(System.getenv("OIDF_NO_CHALLENGE")) ? null : challenge;
        // 2) Client Attestation JWT (signed by the attester; cnf binds the instance key)
        String attestation = attestationJwt(attesterKey, instanceKey, "https://attester.example.com", clientId);
        // 3a) PoP JWT (signed by the instance key; echoes the challenge)
        String pop = popJwt(instanceKey, clientId, tokenEndpoint, popChallenge);
        // 3b) DPoP combined-mode proof (alternative to the PoP; nonce = challenge)
        String dpop = dpopJwt(instanceKey, tokenEndpoint, popChallenge);

        String requestedRar = toJsonArray(requestedAccess(envOr("OIDF_SALES_REGION", "EMEA"), "create_opportunity"));
        System.out.println("[2] built Client Attestation JWT (typ=" + ATTESTATION_TYP + ")");
        System.out.println("    workload   : " + JsonUtil.toJson(workload()));
        System.out.println("    entitlement: " + toJsonArray(salesAgentEntitlement()));
        System.out.println("    requesting : " + requestedRar);
        System.out.println("[3] built PoP JWT (typ=" + POP_TYP + ") and DPoP proof (typ=" + DPOP_TYP + ")");
        System.out.println();
        System.out.println("---- PoP-mode request headers (attestation_pop_jwt) ----");
        System.out.println("OAuth-Client-Attestation: " + attestation);
        System.out.println("OAuth-Client-Attestation-PoP: " + pop);
        System.out.println();
        System.out.println("---- ready-to-run curl (PoP mode) ----");
        System.out.println(curl(tokenEndpoint, clientId, "OAuth-Client-Attestation-PoP", pop, attestation, requestedRar));
        System.out.println();
        System.out.println("---- DPoP combined-mode (dpop_combined) ----");
        System.out.println(curl(tokenEndpoint, clientId, "DPoP", dpop, attestation, requestedRar));

        // Execute the PoP-mode token request to demonstrate LIVE RFC 9396 enforcement.
        executeToken(http, tokenEndpoint, clientId, attestation, pop, requestedRar);
        System.out.println();
        System.out.println("NOTE: the token endpoint accepts these only once PingFederate is configured with an");
        System.out.println("      OAuth AS, the client registered (public client + attestation_required=true), and an");
        System.out.println("      issuance criterion calling ClientAttestationUtils.validateClientAttestation(#this).");
    }

    /** POSTs the PoP-mode token request (with authorization_details) and prints PF's response. */
    private static void executeToken(HttpClient http, String tokenEndpoint, String clientId,
                                     String attestation, String pop, String authorizationDetailsJson) throws Exception {
        String secret = System.getenv("OIDF_CLIENT_SECRET");
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("OIDF_CLIENT_SECRET is not set - live mode sends it on the wire, so there is no default");
        }
        String form = "grant_type=client_credentials"
                + "&client_id=" + url(clientId)
                + "&client_secret=" + url(secret)
                + "&oidf_requested_access=" + url(authorizationDetailsJson);
        HttpRequest req = HttpRequest.newBuilder(URI.create(tokenEndpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("OAuth-Client-Attestation", attestation)
                .header("OAuth-Client-Attestation-PoP", pop)
                .POST(HttpRequest.BodyPublishers.ofString(form)).build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        System.out.println();
        System.out.println("==== LIVE token response (PoP mode) ====");
        System.out.println("HTTP " + resp.statusCode());
        System.out.println(resp.body());
    }

    static String url(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    // ----------------------------------------------------------- selfverify mode

    /**
     * Runs the module's real verifier in-process. Uses reflection so this file
     * compiles even when client-attestation is absent (live mode only); selfverify
     * requires it on the classpath.
     */
    static int selfVerify() throws Exception {
        final String ATTESTER = "https://attester.example.com";
        final String CLIENT_ID = "https://rp.example.com";
        final String OP_ISSUER = "https://op.example.com";
        final String TOKEN_ENDPOINT = OP_ISSUER + "/as/token.oauth2";

        PublicJsonWebKey attesterKey = ec("attester-1");
        PublicJsonWebKey instanceKey = ec("instance-1");

        Class<?> cfgBuilderHolder = Class.forName("com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig");
        Object builder = cfgBuilderHolder.getMethod("builder").invoke(null);
        Class<?> builderClass = builder.getClass();
        builder = builderClass.getMethod("addAcceptedAudience", String.class).invoke(builder, OP_ISSUER);
        builder = builderClass.getMethod("addAcceptedAudience", String.class).invoke(builder, TOKEN_ENDPOINT);
        builder = builderClass.getMethod("expectedHtu", String.class).invoke(builder, TOKEN_ENDPOINT);
        builder = builderClass.getMethod("challengeRequired", boolean.class).invoke(builder, true);
        Object config = builderClass.getMethod("build").invoke(builder);

        Class<?> resolverIface = Class.forName("com.pingidentity.ps.oidf.clientattestation.AttesterKeyResolver");
        JsonWebKey attesterPublic = JsonWebKey.Factory.newJwk(publicParams(attesterKey));
        Object resolver = java.lang.reflect.Proxy.newProxyInstance(
                resolverIface.getClassLoader(), new Class<?>[]{resolverIface},
                (proxy, method, mArgs) -> "resolve".equals(method.getName()) ? List.of(attesterPublic) : null);

        // AttestationChallengeService / AttestationReplayCache are interfaces now (were concrete classes
        // in the old monolith) — instantiate the in-memory implementations instead.
        Object challengeService = Class.forName("com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationChallengeService")
                .getDeclaredConstructor().newInstance();
        Object replayCache = Class.forName("com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationReplayCache")
                .getDeclaredConstructor().newInstance();

        Class<?> verifierClass = Class.forName("com.pingidentity.ps.oidf.clientattestation.ClientAttestationVerifier");
        Object verifier = verifierClass.getConstructors()[0]
                .newInstance(resolver, config, replayCache, challengeService);
        java.lang.reflect.Method verify = verifierClass.getMethod("verify",
                String.class, String.class, String.class, String.class, String.class, String.class);
        java.lang.reflect.Method issue = challengeService.getClass().getMethod("issue");

        int pass = 0, fail = 0;

        // PoP mode, with a server-issued (in-process) challenge
        String challenge = (String) issue.invoke(challengeService);
        String att = attestationJwt(attesterKey, instanceKey, ATTESTER, CLIENT_ID);
        String pop = popJwt(instanceKey, CLIENT_ID, OP_ISSUER, challenge);
        try {
            Object res = verify.invoke(verifier, att, pop, null, "POST", TOKEN_ENDPOINT, CLIENT_ID);
            String cid = (String) res.getClass().getMethod("clientId").invoke(res);
            require(CLIENT_ID.equals(cid), "PoP mode clientId mismatch: " + cid);
            System.out.println("[PASS] PoP mode accepted (clientId=" + cid + ")"); pass++;
        } catch (Exception e) { System.out.println("[FAIL] PoP mode: " + root(e)); fail++; }

        // DPoP combined mode (no challenge required path: build a fresh verifier-less check via challenge=null)
        String challenge2 = (String) issue.invoke(challengeService);
        String dpop = dpopJwt(instanceKey, TOKEN_ENDPOINT, challenge2);
        try {
            Object res = verify.invoke(verifier, att, null, dpop, "POST", TOKEN_ENDPOINT, CLIENT_ID);
            String modeName = res.getClass().getMethod("mode").invoke(res).toString();
            require(modeName.contains("DPOP"), "expected DPOP mode, got " + modeName);
            System.out.println("[PASS] DPoP combined mode accepted (mode=" + modeName + ")"); pass++;
        } catch (Exception e) { System.out.println("[FAIL] DPoP mode: " + root(e)); fail++; }

        // Negative: DPoP signed by a key that does NOT match the attestation cnf must be rejected
        String challenge3 = (String) issue.invoke(challengeService);
        PublicJsonWebKey otherKey = ec("other-1");
        String badDpop = dpopJwt(otherKey, TOKEN_ENDPOINT, challenge3);
        try {
            verify.invoke(verifier, att, null, badDpop, "POST", TOKEN_ENDPOINT, CLIENT_ID);
            System.out.println("[FAIL] tampered DPoP key was accepted (should be rejected)"); fail++;
        } catch (Exception e) { System.out.println("[PASS] tampered DPoP key rejected (" + root(e) + ")"); pass++; }

        // RFC 9396 entitlement: a request within the attested sales_regions is granted; outside is denied.
        java.lang.reflect.Method verify7 = verifierClass.getMethod("verify",
                String.class, String.class, String.class, String.class, String.class, String.class, String.class);

        String challengeR = (String) issue.invoke(challengeService);
        String popR = popJwt(instanceKey, CLIENT_ID, OP_ISSUER, challengeR);
        String reqEmea = toJsonArray(requestedAccess("EMEA", "create_opportunity"));
        try {
            Object res = verify7.invoke(verifier, att, popR, null, "POST", TOKEN_ENDPOINT, CLIENT_ID, reqEmea);
            Object granted = res.getClass().getMethod("grantedAuthorizationDetails").invoke(res);
            require(granted instanceof List && !((List<?>) granted).isEmpty(), "expected granted authorization_details");
            System.out.println("[PASS] RAR within entitlement granted (EMEA/create_opportunity)"); pass++;
        } catch (Exception e) { System.out.println("[FAIL] RAR within entitlement: " + root(e)); fail++; }

        String challengeR2 = (String) issue.invoke(challengeService);
        String popR2 = popJwt(instanceKey, CLIENT_ID, OP_ISSUER, challengeR2);
        String reqAmer = toJsonArray(requestedAccess("AMER", "create_opportunity"));
        try {
            verify7.invoke(verifier, att, popR2, null, "POST", TOKEN_ENDPOINT, CLIENT_ID, reqAmer);
            System.out.println("[FAIL] RAR outside entitlement (AMER) was accepted"); fail++;
        } catch (Exception e) { System.out.println("[PASS] RAR outside entitlement rejected (" + root(e) + ")"); pass++; }

        System.out.println();
        System.out.println("selfverify: " + pass + " passed, " + fail + " failed");
        return fail;
    }

    // ----------------------------------------------------------------- builders

    static String attestationJwt(PublicJsonWebKey attesterKey, PublicJsonWebKey instanceKey,
                                 String attesterIssuer, String clientId) throws Exception {
        JwtClaims att = new JwtClaims();
        att.setIssuer(attesterIssuer);
        att.setSubject(clientId);
        att.setIssuedAtToNow();
        att.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        att.setClaim("cnf", Map.of("jwk", publicParams(instanceKey)));
        att.setClaim("workload", workload());
        att.setClaim("authorization_details", salesAgentEntitlement());
        return sign(attesterKey, "ES256", ATTESTATION_TYP, att);
    }

    /**
     * The RFC 9396 entitlement the attester asserts: a Microsoft-agentic-style sales agent limited to
     * the EMEA sales region (carried as the attestation's {@code authorization_details}).
     */
    static List<Map<String, Object>> salesAgentEntitlement() {
        return List.of(Map.of(
                "type", "sales_agent",
                "actions", List.of("read_accounts", "create_opportunity", "submit_quote"),
                "locations", List.of("https://crm.contoso.com/api"),
                "sales_regions", List.of("EMEA"),
                "privileges", List.of("quota:standard")));
    }

    /** A token request's {@code authorization_details} asking to act in one region with one action. */
    static List<Map<String, Object>> requestedAccess(String region, String action) {
        return List.of(Map.of(
                "type", "sales_agent",
                "actions", List.of(action),
                "locations", List.of("https://crm.contoso.com/api"),
                "sales_regions", List.of(region)));
    }

    /** Serialize a list of objects to a compact JSON array (jose4j only serializes maps). */
    static String toJsonArray(List<Map<String, Object>> arr) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < arr.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(JsonUtil.toJson(arr.get(i)));
        }
        return sb.append(']').toString();
    }

    /**
     * Attester-asserted attributes describing the workload this attestation vouches for.
     * Computed once per process (the instance_id is stable for the run). Env overrides:
     * {@code OIDF_ENVIRONMENT}, {@code OIDF_GIT_COMMIT}, {@code HOSTNAME}.
     */
    static Map<String, Object> workload() {
        Map<String, Object> w = WORKLOAD;
        if (w == null) {
            java.util.LinkedHashMap<String, Object> m = new java.util.LinkedHashMap<>();
            m.put("software_id", SOFTWARE_ID);
            m.put("software_version", SOFTWARE_VERSION);
            m.put("environment", envOr("OIDF_ENVIRONMENT", "test"));
            m.put("instance_id", INSTANCE_ID);
            m.put("runtime", "java/" + System.getProperty("java.version")
                    + " " + System.getProperty("java.vendor")
                    + "; " + System.getProperty("os.name") + " " + System.getProperty("os.version"));
            m.put("host", hostName());
            m.put("git_commit", gitCommit());
            WORKLOAD = w = java.util.Collections.unmodifiableMap(m);
        }
        return w;
    }

    static String envOr(String key, String dflt) {
        String v = System.getenv(key);
        return v != null && !v.isBlank() ? v : dflt;
    }

    static String hostName() {
        String h = System.getenv("HOSTNAME");
        if (h != null && !h.isBlank()) return h;
        try { return java.net.InetAddress.getLocalHost().getHostName(); }
        catch (Exception e) { return "unknown"; }
    }

    /** Short git commit: {@code $OIDF_GIT_COMMIT}, else {@code git rev-parse --short HEAD}, else "unknown". */
    static String gitCommit() {
        String env = System.getenv("OIDF_GIT_COMMIT");
        if (env != null && !env.isBlank()) return env;
        try {
            Process p = new ProcessBuilder("git", "rev-parse", "--short", "HEAD")
                    .redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            return p.waitFor() == 0 && !out.isBlank() ? out : "unknown";
        } catch (Exception e) { return "unknown"; }
    }

    static String popJwt(PublicJsonWebKey instanceKey, String clientId, String audience, String challenge) throws Exception {
        JwtClaims pop = new JwtClaims();
        pop.setIssuer(clientId);
        pop.setAudience(audience);
        pop.setJwtId(randomId());
        pop.setIssuedAtToNow();
        if (challenge != null) pop.setClaim("challenge", challenge);
        return sign(instanceKey, "ES256", POP_TYP, pop);
    }

    static String dpopJwt(PublicJsonWebKey signingKey, String htu, String nonce) throws Exception {
        JwtClaims d = new JwtClaims();
        d.setClaim("htm", "POST");
        d.setClaim("htu", htu);
        d.setJwtId(randomId());
        d.setIssuedAtToNow();
        if (nonce != null) d.setClaim("nonce", nonce);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(d.toJson());
        jws.setKey(signingKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", DPOP_TYP);
        jws.setJwkHeader((PublicJsonWebKey) JsonWebKey.Factory.newJwk(publicParams(signingKey)));
        return jws.getCompactSerialization();
    }

    // ------------------------------------------------------------------ helpers

    static PublicJsonWebKey ec(String kid) throws Exception {
        PublicJsonWebKey jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        jwk.setKeyId(kid);
        return jwk;
    }

    /** Fixed attester key from $OIDF_ATTESTER_JWK (private JWK JSON), else a fresh random one. */
    static PublicJsonWebKey attesterKey() throws Exception {
        String jwk = System.getenv("OIDF_ATTESTER_JWK");
        if (jwk != null && !jwk.isBlank()) {
            return org.jose4j.jwk.PublicJsonWebKey.Factory.newPublicJwk(jwk);
        }
        return ec("attester-1");
    }

    static Map<String, Object> publicParams(JsonWebKey jwk) {
        return jwk.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
    }

    static String sign(PublicJsonWebKey key, String alg, String typ, JwtClaims claims) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue(alg);
        jws.setHeader("typ", typ);
        if (key.getKeyId() != null) jws.setKeyIdHeaderValue(key.getKeyId());
        return jws.getCompactSerialization();
    }

    static String curl(String tokenEndpoint, String clientId, String proofHeader, String proof,
                       String attestation, String authorizationDetailsJson) {
        String rar = authorizationDetailsJson == null ? ""
                : "  -d 'authorization_details=" + authorizationDetailsJson + "' \\\n";
        return "curl -k -X POST '" + tokenEndpoint + "' \\\n"
                + "  -H 'OAuth-Client-Attestation: " + attestation + "' \\\n"
                + "  -H '" + proofHeader + ": " + proof + "' \\\n"
                + "  -d 'grant_type=client_credentials' \\\n"
                + rar
                + "  -d 'client_id=" + clientId + "'";
    }

    static String randomId() {
        byte[] b = new byte[16];
        new SecureRandom().nextBytes(b);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    static void require(boolean cond, String msg) {
        if (!cond) throw new IllegalStateException(msg);
    }

    static String root(Throwable e) {
        Throwable t = e;
        while (t.getCause() != null) t = t.getCause();
        return t.getClass().getSimpleName() + ": " + t.getMessage();
    }

    static String stripTrailingSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    /**
     * Verifying client by default. {@code OIDF_HARNESS_INSECURE_TLS=true} opts into a trust-all context for
     * a self-signed local PF - loudly, and never by default: live mode's documented use is a real
     * deployment, where a silent MITM would hand an attacker the client secret and the attestation.
     */
    static HttpClient httpClient() throws Exception {
        if (!Boolean.parseBoolean(System.getenv("OIDF_HARNESS_INSECURE_TLS"))) {
            return HttpClient.newHttpClient();
        }
        System.err.println("WARN: OIDF_HARNESS_INSECURE_TLS=true - TLS certificate verification is OFF for this run");
        TrustManager[] trustAll = {new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(null, trustAll, new SecureRandom());
        return HttpClient.newBuilder().sslContext(ssl).build();
    }
}
