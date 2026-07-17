// A single-file client for the Grant Evaluation API.
//
// No dependencies beyond the JDK (java.net.http, JDK 11+) so it drops into any project.
// Copy it, change the package, keep the reason handling.
//
// Run it directly (JDK 11+ single-file source mode):
//
//   java GrantManagementClient.java \
//     --pf https://localhost:9131 \
//     --client acme-budgeting --secret "$(cat .../tpp_secret)" \
//     --grant <agid> --account 222
//
// The question it answers is not "is this token valid" but "does this consent still
// permit this, right now". A grant can be valid, unexpired, and name an account the
// user closed last week.

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GrantManagementClient {

    // ---- reason ids: branch on these, never on the message text ----

    static final String PERMITTED = "consent_covers_request";

    /** The consent does not cover it. The user can fix these by consenting again. */
    static final Set<String> CONSENT_PROBLEMS = Set.of(
            "resource_not_consented", "action_not_consented", "missing_scope",
            "no_consent_for_resource_type", "amount_exceeds_consented_limit");

    /**
     * The subject does not hold the access. Re-consenting cannot help: nobody can
     * consent to what they do not have, so sending the user back through authorization
     * wastes their time and returns the same answer.
     */
    static final Set<String> ENTITLEMENT_PROBLEMS = Set.of(
            "subject_not_entitled", "entitlement_lacks_right");

    private final String base;
    private final HttpClient http;
    private final TokenSource tokens;

    /** Supplies the bearer token. A function, so callers can cache and refresh. */
    interface TokenSource {
        String get() throws Exception;
    }

    GrantManagementClient(String grantManagementBase, TokenSource tokens, HttpClient http) {
        this.base = grantManagementBase.replaceAll("/+$", "");
        this.tokens = tokens;
        this.http = http;
    }

    /** The answer. A denial is a decision, not an error. */
    record Decision(boolean permitted, String reasonId, String message) {
        /**
         * Whether re-consenting could change this answer. False for entitlement
         * denials: the user cannot consent to access they do not have.
         */
        boolean retryable() {
            return !permitted && CONSENT_PROBLEMS.contains(reasonId);
        }
    }

    /** The question could not be asked. Distinct from being told no. */
    static class ApiException extends Exception {
        final int status;

        ApiException(int status, String body) {
            super("grant management API: " + status + ": " + body);
            this.status = status;
        }

        /**
         * The PDP or grant store could not be reached. Must not be read as a denial:
         * "I could not ask" and "no" are different answers.
         */
        boolean unavailable() {
            return status == 503;
        }

        boolean unauthenticated() {
            return status == 401;
        }
    }

    /** POST /grants/{id}/evaluate — needs grant_management_evaluate. */
    Decision evaluate(String grantId, String resourceType, String resourceId, String action)
            throws Exception {
        String body = String.format(
                "{\"action\":{\"name\":\"%s\"},\"resource\":{\"type\":\"%s\",\"id\":\"%s\"}}",
                esc(action), esc(resourceType), esc(resourceId));

        String json = send(HttpRequest.newBuilder()
                .uri(URI.create(base + "/grants/" + enc(grantId) + "/evaluate"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)));

        // Deliberately hand-rolled rather than pulling in a JSON library for one field:
        // the response shape is small and fixed. Use Jackson in a real project.
        return new Decision(
                Boolean.parseBoolean(field(json, "\"decision\"\\s*:\\s*(true|false)")),
                field(json, "\"id\"\\s*:\\s*\"([^\"]*)\""),
                field(json, "\"message\"\\s*:\\s*\"([^\"]*)\""));
    }

    /** GET /grants/{id} — needs grant_management_query. */
    String query(String grantId) throws Exception {
        return send(HttpRequest.newBuilder()
                .uri(URI.create(base + "/grants/" + enc(grantId)))
                .GET());
    }

    /** DELETE /grants/{id} — needs grant_management_revoke. Takes effect immediately. */
    void revoke(String grantId) throws Exception {
        send(HttpRequest.newBuilder()
                .uri(URI.create(base + "/grants/" + enc(grantId)))
                .DELETE());
    }

    private String send(HttpRequest.Builder builder) throws Exception {
        HttpRequest req = builder
                .header("Authorization", "Bearer " + tokens.get())
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(15))
                .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() == 204) {
            return "";
        }
        if (resp.statusCode() != 200) {
            throw new ApiException(resp.statusCode(), resp.body());
        }
        return resp.body();
    }

    private static String field(String json, String regex) {
        Matcher m = Pattern.compile(regex).matcher(json);
        return m.find() ? m.group(1) : "";
    }

    private static String esc(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }

    // ---- worked example ----

    public static void main(String[] args) throws Exception {
        Map<String, String> a = parseArgs(args);
        String pf = a.getOrDefault("pf", "https://localhost:9131");
        String gm = a.getOrDefault("gm", pf + "/gm-api");
        String clientId = a.getOrDefault("client", "acme-budgeting");
        String secret = a.get("secret");
        String grantId = a.get("grant");
        String account = a.getOrDefault("account", "111");
        String action = a.getOrDefault("action", "read_balance");

        if (secret == null || grantId == null) {
            System.err.println("--secret and --grant are required");
            System.exit(2);
        }

        HttpClient http = a.containsKey("secure") ? HttpClient.newHttpClient() : trustAll();

        // A client_credentials token has no subject, and needs none: the subject comes
        // off the grant. This is the Open Banking shape -- no user present.
        GrantManagementClient client = new GrantManagementClient(
                gm, () -> clientCredentials(http, pf, clientId, secret), http);

        System.out.println("consent: " + client.query(grantId));

        Decision d;
        try {
            d = client.evaluate(grantId, "account", account, action);
        } catch (ApiException e) {
            if (e.unavailable()) {
                // Not a denial.
                System.err.println("could not reach the decision service: " + e.getMessage());
                System.err.println("retry -- do not assume denied");
                System.exit(1);
            }
            throw e;
        }

        System.out.printf("%n%s on account %s -> %s%n", action, account,
                d.permitted() ? "PERMIT" : "DENY (" + d.reasonId() + ")");
        System.out.println("  " + d.message());

        if (d.permitted()) {
            System.out.println("\n  Safe to act.");
        } else if (d.retryable()) {
            System.out.println("\n  A consent problem. Send the user through authorization again.");
        } else if (ENTITLEMENT_PROBLEMS.contains(d.reasonId())) {
            System.out.println("\n  Not a consent problem: the user does not hold this access.");
            System.out.println("  Re-consenting cannot fix it. Do not send them through authorization.");
        } else {
            System.out.println("\n  The grant is gone or was never yours. Re-authorize.");
        }
    }

    private static String clientCredentials(HttpClient http, String pf, String id, String secret)
            throws Exception {
        String form = "grant_type=client_credentials&scope="
                + enc("grant_management_query grant_management_evaluate");
        String basic = java.util.Base64.getEncoder()
                .encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));

        HttpResponse<String> resp = http.send(HttpRequest.newBuilder()
                .uri(URI.create(pf.replaceAll("/+$", "") + "/as/token.oauth2"))
                .header("Authorization", "Basic " + basic)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build(), HttpResponse.BodyHandlers.ofString());

        if (resp.statusCode() != 200) {
            throw new ApiException(resp.statusCode(), resp.body());
        }
        String token = field(resp.body(), "\"access_token\"\\s*:\\s*\"([^\"]*)\"");
        if (token.isEmpty()) {
            throw new IllegalStateException("no access_token in: " + resp.body());
        }
        return token;
    }

    /** The demo PingFederate serves a self-signed cert. For the demo, not for you. */
    private static HttpClient trustAll() throws Exception {
        TrustManager[] trustAll = {new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            public void checkClientTrusted(X509Certificate[] c, String a) {
            }

            public void checkServerTrusted(X509Certificate[] c, String a) {
            }
        }};
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(null, trustAll, new java.security.SecureRandom());
        return HttpClient.newBuilder().sslContext(ssl).build();
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> out = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            if (!args[i].startsWith("--")) {
                continue;
            }
            String key = args[i].substring(2);
            String value = i + 1 < args.length && !args[i + 1].startsWith("--") ? args[++i] : "true";
            out.put(key, value);
        }
        return out;
    }
}
