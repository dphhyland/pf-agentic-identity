/*
 * Plan item X-B01: every validator's selectors, their bounds, and what cannot reach them.
 */
package com.pingidentity.ps.oidf.issuer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.clientattestation.StaticAttesterKeyResolver;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EvidenceSelectorsTest {

    private static final String ATTESTER = "https://attester.example.com";
    private static final String GKE_ISSUER =
            "https://container.googleapis.com/v1/projects/demo-project/locations/us-central1-a/clusters/spiffe-demo";
    private static final String EKS_ISSUER = "https://oidc.eks.ap-southeast-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B7";
    private static final String AKS_ISSUER =
            "https://australiaeast.oic.prod-aks.azure.com/11111111-2222-3333-4444-555555555555/"
                    + "66666666-7777-8888-9999-000000000000/";
    private static final String GOOGLE_ISSUER = "https://accounts.google.com";
    private static final String AWS_ISSUER = "https://2f5d1a4e-0c3b-4d8e-9a7f-1b2c3d4e5f60.tokens.sts.global.api.aws";
    private static final String TENANT = "11111111-2222-3333-4444-555555555555";
    private static final String AZURE_ISSUER = "https://login.microsoftonline.com/" + TENANT + "/v2.0";
    private static final String OID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    private static final String WALLET_PROVIDER = "https://wallet.example.com";
    private static final String WALLET_INSTANCE = "urn:wallet:instance:abc123";

    private PublicJsonWebKey key;
    private List<JsonWebKey> bundle;

    @BeforeEach
    void setUp() throws Exception {
        this.key = TestJwts.ec("bundle-1");
        this.bundle = List.of(JsonWebKey.Factory.newJwk(TestJwts.publicParams(this.key)));
    }

    // --- per validator: the selectors from a real-shaped, verified token ---------------------------------------

    @Test
    void spiffeJwtProvesItsIdAndTrustDomain() throws Exception {
        InstanceIdentity id = new SpiffeInstanceAttestationValidator().validate(
                token(claims(null, "spiffe://banking.demo/ns/payments/sa/payment-agent")), this.bundle,
                config(AttestationIssuanceConfig.EVIDENCE_SPIFFE_JWT, null, null));
        assertEquals(map("spiffe-jwt:spiffe_id", "spiffe://banking.demo/ns/payments/sa/payment-agent",
                "spiffe-jwt:trust_domain", "banking.demo"), id.selectors());
    }

    @Test
    void gkeProvesClusterNamespaceAndServiceAccount() throws Exception {
        InstanceIdentity id = new GkeTokenValidator().validate(
                token(claims(GKE_ISSUER, "system:serviceaccount:payments:payment-agent")), this.bundle,
                config(AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN, "demo-project.svc.id.goog", GKE_ISSUER));
        assertEquals(map("gke-sa-token:issuer", GKE_ISSUER, "gke-sa-token:namespace", "payments",
                "gke-sa-token:service_account", "payment-agent"), id.selectors());
    }

    @Test
    void eksProvesClusterNamespaceAndServiceAccount() throws Exception {
        InstanceIdentity id = new EksTokenValidator().validate(
                token(claims(EKS_ISSUER, "system:serviceaccount:payments:payment-agent")), this.bundle,
                config(AttestationIssuanceConfig.EVIDENCE_EKS_SA_TOKEN, "eks.banking.demo", EKS_ISSUER));
        assertEquals(map("eks-sa-token:issuer", EKS_ISSUER, "eks-sa-token:namespace", "payments",
                "eks-sa-token:service_account", "payment-agent"), id.selectors());
    }

    @Test
    void aksProvesClusterNamespaceAndServiceAccount() throws Exception {
        InstanceIdentity id = new AksWorkloadIdentityValidator().validate(
                token(claims(AKS_ISSUER, "system:serviceaccount:payments:gateway-agent")), this.bundle,
                config(AttestationIssuanceConfig.EVIDENCE_AKS_SA_TOKEN, "aks.banking.demo", AKS_ISSUER));
        assertEquals(map("aks-sa-token:issuer", AKS_ISSUER, "aks-sa-token:namespace", "payments",
                "aks-sa-token:service_account", "gateway-agent"), id.selectors());
    }

    @Test
    void gcpProvesIssuerEmailAndTheProjectOfAUserManagedAccount() throws Exception {
        JwtClaims claims = claims(GOOGLE_ISSUER, "104857600000000000001");
        claims.setClaim("email", "payments-agent@demo-project.iam.gserviceaccount.com");
        InstanceIdentity id = new GcpSaTokenValidator().validate(token(claims), this.bundle,
                config(AttestationIssuanceConfig.EVIDENCE_GCP_ID_TOKEN, "demo-project.gcp.example", GOOGLE_ISSUER));
        assertEquals(map("gcp-id-token:email", "payments-agent@demo-project.iam.gserviceaccount.com",
                "gcp-id-token:issuer", GOOGLE_ISSUER, "gcp-id-token:project_id", "demo-project"), id.selectors());
    }

    @Test
    void gcpDefaultServiceAccountGivesNoProject() throws Exception {
        JwtClaims claims = claims(GOOGLE_ISSUER, "104857600000000000002");
        claims.setClaim("email", "123456789012-compute@developer.gserviceaccount.com");
        InstanceIdentity id = new GcpSaTokenValidator().validate(token(claims), this.bundle,
                config(AttestationIssuanceConfig.EVIDENCE_GCP_ID_TOKEN, "demo-project.gcp.example", null));
        assertEquals(map("gcp-id-token:email", "123456789012-compute@developer.gserviceaccount.com",
                "gcp-id-token:issuer", GOOGLE_ISSUER), id.selectors());
    }

    @Test
    void awsProvesIssuerAccountAndRole() throws Exception {
        InstanceIdentity id = new AwsStsWebIdentityValidator().validate(
                token(claims(AWS_ISSUER, "arn:aws:sts::123456789012:assumed-role/payments-agent/session-7")),
                this.bundle,
                config(AttestationIssuanceConfig.EVIDENCE_AWS_STS_WEB_IDENTITY, "aws.banking.demo", AWS_ISSUER));
        assertEquals(map("aws-sts-web-identity:account", "123456789012", "aws-sts-web-identity:issuer", AWS_ISSUER,
                "aws-sts-web-identity:role", "payments-agent"), id.selectors());
    }

    @Test
    void azureProvesIssuerTenantAndObjectId() throws Exception {
        JwtClaims claims = claims(AZURE_ISSUER, "opaque-subject");
        claims.setClaim("tid", TENANT);
        claims.setClaim("oid", OID);
        InstanceIdentity id = new AzureManagedIdentityValidator().validate(token(claims), this.bundle,
                config(AttestationIssuanceConfig.EVIDENCE_AZURE_MI_TOKEN, "azure.banking.demo", AZURE_ISSUER));
        assertEquals(map("azure-mi-token:issuer", AZURE_ISSUER, "azure-mi-token:object_id", OID,
                "azure-mi-token:tenant_id", TENANT), id.selectors());
    }

    @Test
    void walletProvesProviderAndInstance() throws Exception {
        InstanceIdentity id = wallet().validate(wia(WALLET_INSTANCE), List.of(), walletConfig());
        assertEquals(map("wallet-instance-attestation:instance", WALLET_INSTANCE,
                "wallet-instance-attestation:provider", WALLET_PROVIDER), id.selectors());
    }

    // --- extra, unknown, non-string and oversized claims -----------------------------------------------------------

    @Test
    void extraAndUnknownClaimsGiveNoSelectors() throws Exception {
        JwtClaims claims = claims(GKE_ISSUER, "system:serviceaccount:payments:payment-agent");
        // Claims shaped like selectors, like the attestation's own members, and like SPIRE's: none is on the list.
        claims.setClaim("selectors", List.of("k8s:ns:admin", "gke-sa-token:namespace:admin"));
        claims.setClaim("gke-sa-token:namespace", "admin");
        claims.setClaim("namespace", "admin");
        claims.setClaim("service_account", "root");
        claims.setClaim("spiffe_id", "spiffe://evil.example/admin");
        claims.setClaim("kubernetes.io", Map.of("namespace", "admin", "pod", Map.of("name", "p-1")));
        List<String> audiences = new ArrayList<>();
        audiences.add(ATTESTER);
        for (int i = 0; i < 1000; i++) {
            audiences.add("https://rp-" + i + ".example.com");
        }
        claims.setAudience(audiences);
        InstanceIdentity id = new GkeTokenValidator().validate(token(claims), this.bundle,
                config(AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN, "demo-project.svc.id.goog", GKE_ISSUER));
        assertEquals(map("gke-sa-token:issuer", GKE_ISSUER, "gke-sa-token:namespace", "payments",
                "gke-sa-token:service_account", "payment-agent"), id.selectors());
    }

    @Test
    void everySelectorNameIsOnItsValidatorsList() throws Exception {
        List<String> ids = new ArrayList<>();
        for (InstanceAttestationValidator v : validators()) {
            ids.add(v.id());
            assertFalse(v.selectorNames().isEmpty(), v.id() + " declares its names");
            for (String name : v.selectorNames()) {
                assertTrue(name.matches("[a-z][a-z0-9_]*"), v.id() + ":" + name);
            }
        }
        assertEquals(InstanceAttestationValidators.defaults().ids(), ids, "every registered validator is covered here");
        assertEquals(List.of(), new InstanceAttestationValidator() {
            @Override
            public String id() {
                return "plugin";
            }

            @Override
            public String format() {
                return "device";
            }

            @Override
            public String title() {
                return "t";
            }

            @Override
            public String description() {
                return "d";
            }

            @Override
            public InstanceIdentity validate(String presented, List<JsonWebKey> keys, AttestationIssuanceConfig c) {
                return null;
            }
        }.selectorNames(), "a validator that declares nothing proves nothing");
    }

    @Test
    void nonStringClaimsGiveNoSelector() throws Exception {
        JwtClaims claims = claims(AZURE_ISSUER, "opaque-subject");
        claims.setClaim("tid", 12345);
        claims.setClaim("oid", OID);
        InstanceIdentity id = new AzureManagedIdentityValidator().validate(token(claims), this.bundle,
                config(AttestationIssuanceConfig.EVIDENCE_AZURE_MI_TOKEN, "azure.banking.demo", null));
        assertEquals(map("azure-mi-token:issuer", AZURE_ISSUER, "azure-mi-token:object_id", OID), id.selectors());

        // An email that is an array still makes a subject (jose4j reads it as its text) but never a selector.
        JwtClaims gcp = claims(null, "104857600000000000003");
        gcp.setClaim("email", List.of("a@demo-project.iam.gserviceaccount.com"));
        InstanceIdentity g = new GcpSaTokenValidator().validate(token(gcp), this.bundle,
                config(AttestationIssuanceConfig.EVIDENCE_GCP_ID_TOKEN, "demo-project.gcp.example", null));
        assertTrue(g.selectors().isEmpty(), g.selectors().toString());
    }

    @Test
    void anOversizedValueRefusesTheEvidenceRatherThanTruncating() throws Exception {
        String longName = "a".repeat(EvidenceSelectors.MAX_VALUE_BYTES + 1);
        IssuanceException gke = assertThrows(IssuanceException.class, () -> new GkeTokenValidator().validate(
                token(claims(GKE_ISSUER, "system:serviceaccount:payments:" + longName)), this.bundle,
                config(AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN, "demo-project.svc.id.goog", GKE_ISSUER)));
        assertEquals("invalid_svid", gke.error());
        assertTrue(gke.getMessage().contains("gke-sa-token:service_account"), gke.getMessage());

        IssuanceException spiffe = assertThrows(IssuanceException.class,
                () -> new SpiffeInstanceAttestationValidator().validate(
                        token(claims(null, "spiffe://banking.demo/" + longName)), this.bundle,
                        config(AttestationIssuanceConfig.EVIDENCE_SPIFFE_JWT, null, null)));
        assertEquals("invalid_svid", spiffe.error());

        IssuanceException wallet = assertThrows(IssuanceException.class,
                () -> wallet().validate(wia("urn:wallet:" + longName), List.of(), walletConfig()));
        assertEquals("invalid_instance_attestation", wallet.error());

        // Multi-byte characters count as their UTF-8 bytes: 683 three-byte characters are 2049 bytes.
        IssuanceException utf8 = assertThrows(IssuanceException.class, () -> EvidenceSelectors.of("s",
                List.of("n"), IssuanceException::invalidSvid, "n", "€".repeat(683)));
        assertEquals("invalid_svid", utf8.error());
        assertEquals(1, EvidenceSelectors.of("s", List.of("n"), IssuanceException::invalidSvid,
                "n", "a".repeat(EvidenceSelectors.MAX_VALUE_BYTES)).asMap().get("s:n").size());
    }

    @Test
    void aRefusedTokenGivesNoSelectorsAndIsRefusedForItsOwnFaultFirst() throws Exception {
        // Signed by a key outside the bundle, with a value over the bound: refused for the signature, so no selector
        // was built from an unverified claim.
        PublicJsonWebKey stranger = TestJwts.ec("bundle-1");
        String forged = TestJwts.sign(stranger, "ES256", null,
                claims(GKE_ISSUER, "system:serviceaccount:payments:" + "a".repeat(5000)));
        IssuanceException e = assertThrows(IssuanceException.class, () -> new GkeTokenValidator().validate(forged,
                this.bundle, config(AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN, "demo-project.svc.id.goog", null)));
        assertTrue(e.getMessage().contains("signature"), e.getMessage());

        // Expired, with a value over the bound: refused as expired.
        JwtClaims expired = claims(GKE_ISSUER, "system:serviceaccount:payments:" + "a".repeat(5000));
        expired.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() - 3600));
        IssuanceException x = assertThrows(IssuanceException.class, () -> new GkeTokenValidator().validate(
                token(expired), this.bundle,
                config(AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN, "demo-project.svc.id.goog", null)));
        assertTrue(x.getMessage().contains("expired"), x.getMessage());
    }

    // --- EvidenceSelectors itself --------------------------------------------------------------------------------

    @Test
    void theBoundOnCountRefusesAboveItAndCountsDistinctValues() throws Exception {
        String[] pairs = new String[EvidenceSelectors.MAX_SELECTORS * 2];
        for (int i = 0; i < EvidenceSelectors.MAX_SELECTORS; i++) {
            pairs[2 * i] = "k8s";
            pairs[2 * i + 1] = "v" + i;
        }
        EvidenceSelectors full = EvidenceSelectors.of("spire", List.of("k8s"), IssuanceException::invalidSvid, pairs);
        assertEquals(EvidenceSelectors.MAX_SELECTORS, full.asMap().get("spire:k8s").size());

        String[] over = java.util.Arrays.copyOf(pairs, pairs.length + 2);
        over[pairs.length] = "k8s";
        over[pairs.length + 1] = "one-too-many";
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> EvidenceSelectors.of("spire", List.of("k8s"), IssuanceException::invalidSvid, over));
        assertTrue(e.getMessage().contains(String.valueOf(EvidenceSelectors.MAX_SELECTORS)), e.getMessage());

        // A repeated value is one selector, so it does not count twice.
        String[] repeated = java.util.Arrays.copyOf(pairs, pairs.length + 2);
        repeated[pairs.length] = "k8s";
        repeated[pairs.length + 1] = "v0";
        assertEquals(full, EvidenceSelectors.of("spire", List.of("k8s"), IssuanceException::invalidSvid, repeated));
    }

    @Test
    void aNameOffTheListOrAMalformedCallIsAProgrammingError() {
        List<String> names = List.of("issuer");
        assertThrows(IllegalArgumentException.class,
                () -> EvidenceSelectors.of("gke-sa-token", names, IssuanceException::invalidSvid, "namespace", "x"));
        assertThrows(IllegalArgumentException.class, () -> EvidenceSelectors.of("gke-sa-token", List.of("Issuer"),
                IssuanceException::invalidSvid, "Issuer", "x"));
        assertThrows(IllegalArgumentException.class,
                () -> EvidenceSelectors.of("gke-sa-token", names, IssuanceException::invalidSvid, null, "x"));
        assertThrows(IllegalArgumentException.class,
                () -> EvidenceSelectors.of("gke-sa-token", names, IssuanceException::invalidSvid, "issuer"));
        assertThrows(IllegalArgumentException.class,
                () -> EvidenceSelectors.of(null, names, IssuanceException::invalidSvid, "issuer", "x"));
        assertThrows(IllegalArgumentException.class,
                () -> EvidenceSelectors.of(" ", names, IssuanceException::invalidSvid, "issuer", "x"));
        assertThrows(IllegalArgumentException.class,
                () -> EvidenceSelectors.of("a:b", names, IssuanceException::invalidSvid, "issuer", "x"));
    }

    @Test
    void absentAndEmptyValuesGiveNothingAndValuesAreKeptExactly() throws Exception {
        assertSame(EvidenceSelectors.none(), EvidenceSelectors.of("s", List.of("a", "b"),
                IssuanceException::invalidSvid, "a", null, "b", ""));
        assertTrue(EvidenceSelectors.none().isEmpty());
        EvidenceSelectors exact = EvidenceSelectors.of("s", List.of("a"), IssuanceException::invalidSvid,
                "a", " Banking.Demo ", "a", "banking.demo");
        assertFalse(exact.isEmpty());
        assertEquals(new TreeSet<>(List.of(" Banking.Demo ", "banking.demo")), exact.asMap().get("s:a"));
        assertEquals("{s:a=[ Banking.Demo , banking.demo]}", exact.toString());
        assertEquals(exact.hashCode(), EvidenceSelectors.of("s", List.of("a"), IssuanceException::invalidSvid,
                "a", "banking.demo", "a", " Banking.Demo ").hashCode());
        assertNotEquals(exact, EvidenceSelectors.none());
        assertNotEquals(exact, "s:a");
    }

    @Test
    void selectorsCannotBeChangedOnceBuilt() throws Exception {
        InstanceIdentity id = new GkeTokenValidator().validate(
                token(claims(GKE_ISSUER, "system:serviceaccount:payments:payment-agent")), this.bundle,
                config(AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN, "demo-project.svc.id.goog", null));
        SortedMap<String, SortedSet<String>> selectors = id.selectors();
        assertThrows(UnsupportedOperationException.class, () -> selectors.put("x:y", new TreeSet<>()));
        assertThrows(UnsupportedOperationException.class, () -> selectors.remove("gke-sa-token:namespace"));
        assertThrows(UnsupportedOperationException.class,
                () -> selectors.get("gke-sa-token:namespace").add("admin"));
        assertThrows(UnsupportedOperationException.class,
                () -> selectors.get("gke-sa-token:namespace").clear());
        // The identities built outside a validator carry none.
        assertTrue(new InstanceIdentity("device", "d", null, null, Map.of(), 1L).selectors().isEmpty());
        assertTrue(new InstanceIdentity("device", "d", null, null, Map.of(), 1L, "t", null, List.of(), 0L, null)
                .selectors().isEmpty());
        assertTrue(InstanceIdentity.ofSpiffe(new SpiffeSvid("spiffe://a/b", "a", "/b", List.of(), 1L, 0L, "h.p.s"))
                .selectors().isEmpty());
    }

    // --- nothing after the validator reaches the selectors ----------------------------------------------------------

    /**
     * The property: for random binding metadata, random caller-asserted context and random introspected SPIRE
     * attributes - everything the servlet merges into {@code workloadAttributes} at steps 5 and 5a - the selectors of
     * the identity are the ones the validator built from the token, and the minted attestation carries none of them.
     */
    @Test
    void randomBindingMetadataAssertedContextAndIntrospectionNeverChangeSelectors() throws Exception {
        String token = token(claims(GKE_ISSUER, "system:serviceaccount:payments:payment-agent"));
        SortedMap<String, SortedSet<String>> expected = map("gke-sa-token:issuer", GKE_ISSUER,
                "gke-sa-token:namespace", "payments", "gke-sa-token:service_account", "payment-agent");
        String subject = "spiffe://demo-project.svc.id.goog/ns/payments/sa/payment-agent";
        GkeTokenValidator validator = new GkeTokenValidator();
        PublicJsonWebKey attesterKey = TestJwts.ec("attester-1");
        Map<String, Object> instanceJwk = TestJwts.publicParams(TestJwts.ec("instance-1"));

        for (long seed = 1; seed <= 200; seed++) {
            Random random = new Random(seed);
            Map<String, Object> metadata = randomAttributes(random);
            Map<String, String> props = baseProps(AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN,
                    "demo-project.svc.id.goog", GKE_ISSUER);
            Map<String, Object> binding = new LinkedHashMap<>();
            binding.put("spiffe_id", random.nextBoolean() ? subject : "spiffe://demo-project.svc.id.goog/ns/*");
            binding.put("metadata", metadata);
            String wrapped = JsonUtil.toJson(Map.of("x", List.of(binding)));
            props.put(AttestationIssuanceConfig.P_INSTANCES,
                    wrapped.substring("{\"x\":".length(), wrapped.length() - 1));
            props.put(AttestationIssuanceConfig.P_ASSERTED_CONTEXT_RESOLVER, EntraDirectoryAssertedContextResolver.ID);
            AttestationIssuanceConfig config = AttestationIssuanceConfig.fromProperties(props);

            InstanceIdentity instance = validator.validate(token, this.bundle, config);
            assertEquals(expected, instance.selectors(), "seed " + seed);
            SpiffeBinding matched = config.bindingFor(instance.subject()).orElseThrow();

            // Step 5: binding metadata, then the SPIRE introspector's attributes.
            Map<String, Object> workloadAttributes = new LinkedHashMap<>(matched.metadata());
            String spire = randomSpireResponse(random);
            workloadAttributes.putAll(new SpireSelectorIntrospector("https://spire.example/api", (u, a) -> spire)
                    .introspect(instance));
            assertEquals(expected, instance.selectors(), "seed " + seed);

            // Step 5a: the caller-asserted context.
            String oid = "oid-" + random.nextInt(1000);
            Map<String, EntraDirectoryAssertedContextResolver.Entry> directory = new HashMap<>();
            directory.put(oid, new EntraDirectoryAssertedContextResolver.Entry(randomString(random),
                    List.of(randomString(random), "gke-sa-token:namespace=admin"), List.of()));
            AssertedContext asserted = new EntraDirectoryAssertedContextResolver(directory)
                    .resolve(instance, oid, config);
            workloadAttributes.put("asserted", asserted.claims());
            assertEquals(expected, instance.selectors(), "seed " + seed);

            // Step 7: the mint reads the identity, and its workload is the one an identity without selectors gets.
            com.pingidentity.ps.oidf.jose.LocalJwkSigner signer =
                    new com.pingidentity.ps.oidf.jose.LocalJwkSigner(TestJwts.privateParams(attesterKey));
            Map<String, Object> minted = payload(AttestationMinter.mint(ATTESTER, "https://rp.example.com",
                    instanceJwk, instance, workloadAttributes, List.of(), 300L, signer, null));
            assertEquals(expected, instance.selectors(), "seed " + seed);
            Map<String, Object> plain = payload(AttestationMinter.mint(ATTESTER, "https://rp.example.com",
                    instanceJwk, InstanceIdentity.ofSpiffe(validator.validateSvid(token, this.bundle, config),
                            validator.id()), workloadAttributes, List.of(), 300L, signer, null));
            assertEquals(plain.get("workload"), minted.get("workload"), "seed " + seed);
            assertEquals(plain.keySet(), minted.keySet(), "seed " + seed);
        }
    }

    /** Item 5: a minted attestation has the same members, and the same {@code workload}, with or without selectors. */
    @Test
    @SuppressWarnings("unchecked")
    void mintedAttestationIsUnchangedByTheSelectors() throws Exception {
        String token = token(claims(GKE_ISSUER, "system:serviceaccount:payments:payment-agent"));
        AttestationIssuanceConfig config =
                config(AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN, "demo-project.svc.id.goog", GKE_ISSUER);
        GkeTokenValidator validator = new GkeTokenValidator();
        InstanceIdentity with = validator.validate(token, this.bundle, config);
        InstanceIdentity without = InstanceIdentity.ofSpiffe(validator.validateSvid(token, this.bundle, config),
                validator.id());
        assertFalse(with.selectors().isEmpty());
        assertTrue(without.selectors().isEmpty());

        PublicJsonWebKey attesterKey = TestJwts.ec("attester-1");
        Map<String, Object> instanceJwk = TestJwts.publicParams(TestJwts.ec("instance-1"));
        Map<String, Object> a = payload(AttestationMinter.mint(ATTESTER, "https://rp.example.com", instanceJwk, with,
                Map.of("region", "EMEA"), List.of(), 300L,
                new com.pingidentity.ps.oidf.jose.LocalJwkSigner(TestJwts.privateParams(attesterKey)), null));
        Map<String, Object> b = payload(AttestationMinter.mint(ATTESTER, "https://rp.example.com", instanceJwk,
                without, Map.of("region", "EMEA"), List.of(), 300L,
                new com.pingidentity.ps.oidf.jose.LocalJwkSigner(TestJwts.privateParams(attesterKey)), null));
        assertEquals(new TreeSet<>(b.keySet()), new TreeSet<>(a.keySet()));
        assertEquals(b.get("workload"), a.get("workload"));
        assertEquals(List.of("attested_by", "attributes", "instance_attestation_exp", "instance_attestation_sha256",
                "instance_attestation_type", "spiffe_id", "subject"),
                new ArrayList<>(new TreeSet<>(((Map<String, Object>) a.get("workload")).keySet())));
    }

    // --- helpers ------------------------------------------------------------------------------------------------

    private static Map<String, Object> payload(String jwt) throws Exception {
        return JsonUtil.parseJson(new String(java.util.Base64.getUrlDecoder().decode(jwt.split("\\.")[1]),
                java.nio.charset.StandardCharsets.UTF_8));
    }

    private List<InstanceAttestationValidator> validators() {
        return List.of(new SpiffeInstanceAttestationValidator(), new GkeTokenValidator(), new GcpSaTokenValidator(),
                new EksTokenValidator(), new AwsStsWebIdentityValidator(), new AksWorkloadIdentityValidator(),
                new AzureManagedIdentityValidator(), wallet());
    }

    private static SortedMap<String, SortedSet<String>> map(String... keyValues) {
        SortedMap<String, SortedSet<String>> out = new TreeMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            out.computeIfAbsent(keyValues[i], k -> new TreeSet<>()).add(keyValues[i + 1]);
        }
        return out;
    }

    private static JwtClaims claims(String issuer, String subject) {
        JwtClaims claims = new JwtClaims();
        if (issuer != null) {
            claims.setIssuer(issuer);
        }
        claims.setSubject(subject);
        claims.setAudience(ATTESTER);
        claims.setIssuedAtToNow();
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600));
        return claims;
    }

    private String token(JwtClaims claims) throws Exception {
        return TestJwts.sign(this.key, "ES256", null, claims);
    }

    private Map<String, String> baseProps(String evidence, String trustDomain, String evidenceIssuer) {
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ATTESTER);
        props.put(AttestationIssuanceConfig.P_BUNDLE, new JsonWebKeySet(this.bundle).toJson());
        props.put(AttestationIssuanceConfig.P_EVIDENCE, evidence);
        if (trustDomain != null) {
            props.put(AttestationIssuanceConfig.P_TRUST_DOMAIN, trustDomain);
        }
        if (evidenceIssuer != null) {
            props.put(AttestationIssuanceConfig.P_EVIDENCE_ISSUER, evidenceIssuer);
        }
        return props;
    }

    private AttestationIssuanceConfig config(String evidence, String trustDomain, String evidenceIssuer)
            throws Exception {
        return AttestationIssuanceConfig.fromProperties(baseProps(evidence, trustDomain, evidenceIssuer));
    }

    private WalletInstanceAttestationValidator wallet() {
        try {
            return new WalletInstanceAttestationValidator(new StaticAttesterKeyResolver(Map.of(WALLET_PROVIDER,
                    List.of(JsonWebKey.Factory.newJwk(TestJwts.publicParams(this.key))))));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private AttestationIssuanceConfig walletConfig() throws Exception {
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ATTESTER);
        props.put(AttestationIssuanceConfig.P_EVIDENCE, AttestationIssuanceConfig.EVIDENCE_WALLET_INSTANCE_ATTESTATION);
        return AttestationIssuanceConfig.fromProperties(props);
    }

    private String wia(String instance) throws Exception {
        JwtClaims claims = claims(WALLET_PROVIDER, instance);
        claims.setClaim("cnf", Map.of("jwk", TestJwts.publicParams(TestJwts.ec("wallet-instance-1"))));
        claims.setClaim("wallet_name", "Example Wallet");
        return TestJwts.sign(this.key, "ES256", "wallet-instance-attestation+jwt", claims);
    }

    private static String randomString(Random random) {
        String[] pool = {"admin", "payments", "gke-sa-token:namespace", "spiffe-jwt:spiffe_id", "selectors", "",
            "a".repeat(3000), "€", "k8s:ns:admin", "spire:k8s"};
        return random.nextInt(4) == 0 ? pool[random.nextInt(pool.length)] + random.nextInt()
                : pool[random.nextInt(pool.length)];
    }

    private static Map<String, Object> randomAttributes(Random random) {
        Map<String, Object> out = new LinkedHashMap<>();
        int n = random.nextInt(6);
        for (int i = 0; i < n; i++) {
            String key = randomString(random);
            Object value;
            switch (random.nextInt(3)) {
                case 0:
                    value = randomString(random);
                    break;
                case 1:
                    value = List.of(randomString(random), randomString(random));
                    break;
                default:
                    value = Map.of("gke-sa-token:namespace", randomString(random));
                    break;
            }
            out.put(key, value);
        }
        return out;
    }

    private static String randomSpireResponse(Random random) {
        List<Map<String, Object>> selectors = new ArrayList<>();
        int n = random.nextInt(40);
        for (int i = 0; i < n; i++) {
            selectors.add(Map.of("type", random.nextBoolean() ? "k8s" : "gke-sa-token",
                    "value", "ns:" + randomString(random)));
        }
        return JsonUtil.toJson(Map.of("selectors", selectors));
    }
}
