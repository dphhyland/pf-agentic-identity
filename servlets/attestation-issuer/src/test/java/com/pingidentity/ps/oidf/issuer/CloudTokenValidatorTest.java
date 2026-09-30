/*
 * CloudTokenValidator: a table of tokens per cloud evidence type, and each type's own checks (plan item H-ATT-1).
 */
package com.pingidentity.ps.oidf.issuer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Stream;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.OkpJwkGenerator;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class CloudTokenValidatorTest {

    static final String ATTESTER = "https://attester.example.com";
    static final String GKE_ISSUER =
            "https://container.googleapis.com/v1/projects/demo-project/locations/us-central1-a/clusters/spiffe-demo";
    static final String OTHER_GKE_ISSUER =
            "https://container.googleapis.com/v1/projects/other-project/locations/us-central1-a/clusters/spiffe-demo";
    static final String GOOGLE_ISSUER = "https://accounts.google.com";
    static final String EKS_ISSUER = "https://oidc.eks.ap-southeast-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B7";
    static final String AWS_ISSUER = "https://2f5d1a4e-0c3b-4d8e-9a7f-1b2c3d4e5f60.tokens.sts.global.api.aws";
    static final String TENANT = "11111111-2222-3333-4444-555555555555";
    static final String OTHER_TENANT = "99999999-2222-3333-4444-555555555555";
    static final String AKS_ISSUER = "https://australiaeast.oic.prod-aks.azure.com/" + TENANT
            + "/00000000-0000-0000-0000-000000000000/";
    static final String AZURE_ISSUER = "https://login.microsoftonline.com/" + TENANT + "/v2.0";
    static final String AZURE_V1_ISSUER = "https://sts.windows.net/" + TENANT + "/";
    static final String OID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    static final String EMAIL = "agent-runtime@demo-project.iam.gserviceaccount.com";
    static final String KSA = "system:serviceaccount:payments:agent";

    static PublicJsonWebKey key;
    static List<JsonWebKey> bundle;

    @BeforeAll
    static void keys() throws Exception {
        key = TestJwts.ec("cloud-1");
        bundle = List.of(JsonWebKey.Factory.newJwk(TestJwts.publicParams(key)));
    }

    /** One cloud evidence type: how to build its validator, a good token's claims, and where it maps. */
    record Type(String id, Function<CloudTokenValidator.Policy, CloudTokenValidator> validator, String issuer,
                String trustDomain, Consumer<JwtClaims> subject, String path) {
        @Override
        public String toString() {
            return this.id;
        }
    }

    static Stream<Type> types() {
        return Stream.of(
                new Type("gke-sa-token", GkeTokenValidator::new, GKE_ISSUER, "demo-project.svc.id.goog",
                        c -> c.setSubject(KSA), "/ns/payments/sa/agent"),
                new Type("gcp-id-token", GcpSaTokenValidator::new, GOOGLE_ISSUER, "demo-project.gcp.example",
                        c -> {
                            c.setSubject("104857600000000000001");
                            c.setClaim("email", EMAIL);
                        }, "/sa/" + EMAIL),
                new Type("eks-sa-token", EksTokenValidator::new, EKS_ISSUER, "eks.banking.demo",
                        c -> c.setSubject(KSA), "/ns/payments/sa/agent"),
                new Type("aws-sts-web-identity", AwsStsWebIdentityValidator::new, AWS_ISSUER, "aws.banking.demo",
                        c -> c.setSubject("arn:aws:iam::123456789012:role/payments-agent"),
                        "/aws/123456789012/role/payments-agent"),
                new Type("aks-sa-token", AksWorkloadIdentityValidator::new, AKS_ISSUER, "aks.banking.demo",
                        c -> c.setSubject(KSA), "/ns/payments/sa/agent"),
                new Type("azure-mi-token", AzureManagedIdentityValidator::new, AZURE_ISSUER, "azure.banking.demo",
                        c -> {
                            c.setSubject("opaque");
                            c.setClaim("tid", TENANT);
                            c.setClaim("oid", OID);
                        }, "/azure/mi/" + OID));
    }

    // ---- policies, configurations and tokens -------------------------------------------------------------------

    static Map<String, Set<String>> allPinned() {
        Map<String, Set<String>> pins = new HashMap<>();
        types().forEach(t -> pins.put(t.id(), Set.of(t.issuer())));
        return pins;
    }

    /** Production, every type pinned to its issuer, the GCP project listed. */
    static CloudTokenValidator.Policy production() {
        return CloudTokenValidator.Policy.of(allPinned(), 3600L, Set.of("demo-project"), null, null, null, false, true);
    }

    static CloudTokenValidator.Policy policy(Map<String, Set<String>> pins, long max, Set<String> projects,
                                             Set<String> accounts, Set<String> tenants, Set<String> identities,
                                             boolean single, boolean production) {
        return CloudTokenValidator.Policy.of(pins, max, projects, accounts, tenants, identities, single, production);
    }

    static AttestationIssuanceConfig config(Type type, String evidenceIssuer, String... bindings) throws Exception {
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ATTESTER);
        props.put(AttestationIssuanceConfig.P_BUNDLE, new JsonWebKeySet(bundle).toJson());
        props.put(AttestationIssuanceConfig.P_EVIDENCE, type.id());
        props.put(AttestationIssuanceConfig.P_TRUST_DOMAIN, type.trustDomain());
        if (evidenceIssuer != null) {
            props.put(AttestationIssuanceConfig.P_EVIDENCE_ISSUER, evidenceIssuer);
        }
        if (bindings.length > 0) {
            StringBuilder json = new StringBuilder("[");
            for (String b : bindings) {
                json.append(json.length() > 1 ? "," : "").append("{\"spiffe_id\":\"").append(b).append("\"}");
            }
            props.put(AttestationIssuanceConfig.P_INSTANCES, json.append(']').toString());
        }
        return AttestationIssuanceConfig.fromProperties(props);
    }

    /** A good token of the type, then {@code change} applied. */
    static JwtClaims claims(Type type, Consumer<JwtClaims> change) {
        JwtClaims c = new JwtClaims();
        c.setIssuer(type.issuer());
        c.setAudience(ATTESTER);
        long now = NumericDate.now().getValue();
        c.setIssuedAt(NumericDate.fromSeconds(now));
        c.setNotBefore(NumericDate.fromSeconds(now));
        c.setExpirationTime(NumericDate.fromSeconds(now + 600));
        type.subject().accept(c);
        change.accept(c);
        return c;
    }

    static String token(JwtClaims claims) throws Exception {
        return TestJwts.sign(key, "ES256", null, claims);
    }

    static SpiffeSvid validate(Type type, CloudTokenValidator.Policy policy, AttestationIssuanceConfig config,
                               JwtClaims claims) throws Exception {
        return type.validator().apply(policy).validateSvid(token(claims), bundle, config);
    }

    /** Refused with {@code error}, counted under {@code check}, and the message repeats none of {@code secrets}. */
    static IssuanceException refused(Type type, String error, String check, CloudTokenValidator.Policy policy,
                                     AttestationIssuanceConfig config, JwtClaims claims, String... secrets) {
        long before = CloudTokenValidator.refusals(type.id(), check);
        IssuanceException e = assertThrows(IssuanceException.class, () -> validate(type, policy, config, claims),
                type.id() + " " + check);
        assertEquals(error, e.error(), type.id() + " " + check + ": " + e.getMessage());
        assertEquals(before + 1, CloudTokenValidator.refusals(type.id(), check), type.id() + " counted under " + check);
        for (String secret : secrets) {
            assertFalse(e.getMessage().contains(secret), type.id() + " echoed the token: " + e.getMessage());
        }
        return e;
    }

    // ---- the table ------------------------------------------------------------------------------------------------

    @ParameterizedTest
    @MethodSource("types")
    void aGoodTokenMapsOntoItsSpiffeIdUnderProductionPins(Type type) throws Exception {
        SpiffeSvid svid = validate(type, production(), config(type, null), claims(type, c -> { }));
        assertEquals("spiffe://" + type.trustDomain() + type.path(), svid.spiffeId());
        assertEquals(List.of(ATTESTER), svid.audiences());
        InstanceIdentity id = type.validator().apply(production()).validate(token(claims(type, c -> { })), bundle,
                config(type, null));
        assertEquals(type.id(), id.evidenceType());
        assertEquals("spiffe", id.format());
    }

    @ParameterizedTest
    @MethodSource("types")
    void aClientMayNarrowThePinsToOneOfThem(Type type) throws Exception {
        CloudTokenValidator.Policy policy = policy(Map.of(type.id(), Set.of(type.issuer(), "https://other.example")),
                3600L, Set.of("demo-project"), null, null, null, false, true);
        assertNotNull(validate(type, policy, config(type, type.issuer()), claims(type, c -> { })));
        refused(type, "invalid_svid", "iss", policy, config(type, "https://other.example"), claims(type, c -> { }));
    }

    @ParameterizedTest
    @MethodSource("types")
    void aClientMayNotWidenThePins(Type type) throws Exception {
        IssuanceException e = refused(type, "invalid_client", "iss_pin", production(),
                config(type, "https://widened.example"), claims(type, c -> { }));
        assertTrue(e.getMessage().contains(CloudTokenValidator.Policy.issuersSetting(type.id())), e.getMessage());
    }

    @ParameterizedTest
    @MethodSource("types")
    void aWrongIssuerIsRefusedWithoutRepeatingIt(Type type) throws Exception {
        refused(type, "invalid_svid", "iss", production(), config(type, null),
                claims(type, c -> c.setIssuer("https://attacker.example/secret-issuer")), "attacker.example");
        refused(type, "invalid_svid", "iss", production(), config(type, null), claims(type, c -> c.unsetClaim("iss")));
    }

    @ParameterizedTest
    @MethodSource("types")
    void productionRefusesATypeWithNoPinNamingTheSetting(Type type) throws Exception {
        CloudTokenValidator.Policy unpinned = policy(Map.of(), 3600L, Set.of("demo-project"), null, null, null, false, true);
        for (String clientIssuer : new String[] {null, type.issuer()}) {
            IssuanceException e = refused(type, "invalid_client", "iss_pin", unpinned, config(type, clientIssuer),
                    claims(type, c -> { }));
            assertTrue(e.getMessage().contains(CloudTokenValidator.Policy.issuersSetting(type.id())), e.getMessage());
        }
    }

    @ParameterizedTest
    @MethodSource("types")
    void developmentTakesTheProvidersPublishedIssuerForATypeWithNoPin(Type type) throws Exception {
        CloudTokenValidator.Policy dev = CloudPolicies.development();
        assertNotNull(validate(type, dev, config(type, null), claims(type, c -> { })));
        refused(type, "invalid_svid", "iss", dev, config(type, null),
                claims(type, c -> c.setIssuer("https://attacker.example")));
        // A client's own issuer is its pin under development.
        refused(type, "invalid_svid", "iss", dev, config(type, "https://elsewhere.example"), claims(type, c -> { }));
    }

    @ParameterizedTest
    @MethodSource("types")
    void theAudienceMustNameThisAttester(Type type) throws Exception {
        refused(type, "invalid_svid", "aud", production(), config(type, null),
                claims(type, c -> c.setAudience("https://other.example")));
        refused(type, "invalid_svid", "aud", production(), config(type, null), claims(type, c -> c.setClaim("aud", 42)));
        refused(type, "invalid_svid", "aud", production(), config(type, null), claims(type, c -> c.unsetClaim("aud")));
        JwtClaims two = claims(type, c -> c.setAudience(ATTESTER, "https://other.example"));
        assertNotNull(validate(type, production(), config(type, null), two));
        CloudTokenValidator.Policy single = policy(allPinned(), 3600L, Set.of("demo-project"), null, null, null, true, true);
        refused(type, "invalid_svid", "aud", single, config(type, null), two);
        assertNotNull(validate(type, single, config(type, null), claims(type, c -> { })));
    }

    @ParameterizedTest
    @MethodSource("types")
    void theTimesAreHeldWithTheSkew(Type type) throws Exception {
        long now = NumericDate.now().getValue();
        refused(type, "invalid_svid", "exp", production(), config(type, null),
                claims(type, c -> c.setExpirationTime(NumericDate.fromSeconds(now - 120))));
        refused(type, "invalid_svid", "exp", production(), config(type, null), claims(type, c -> c.unsetClaim("exp")));
        refused(type, "invalid_svid", "exp", production(), config(type, null), claims(type, c -> c.setClaim("exp", "soon")));
        refused(type, "invalid_svid", "nbf", production(), config(type, null),
                claims(type, c -> c.setNotBefore(NumericDate.fromSeconds(now + 120))));
        refused(type, "invalid_svid", "iat", production(), config(type, null),
                claims(type, c -> c.setIssuedAt(NumericDate.fromSeconds(now + 120))));
        refused(type, "invalid_svid", "iat", production(), config(type, null), claims(type, c -> c.unsetClaim("iat")));
        // Inside the 60 s skew, and without nbf, is accepted.
        assertNotNull(validate(type, production(), config(type, null), claims(type, c -> {
            c.setExpirationTime(NumericDate.fromSeconds(now - 30));
            c.setIssuedAt(NumericDate.fromSeconds(now - 300));
            c.unsetClaim("nbf");
        })));
        assertNotNull(validate(type, production(), config(type, null), claims(type, c -> {
            c.setNotBefore(NumericDate.fromSeconds(now + 30));
            c.setIssuedAt(NumericDate.fromSeconds(now + 30));
        })));
    }

    @ParameterizedTest
    @MethodSource("types")
    void aTokenIssuedToLiveLongerThanTheMaximumIsRefused(Type type) throws Exception {
        long now = NumericDate.now().getValue();
        IssuanceException e = refused(type, "invalid_svid", "lifetime", production(), config(type, null), claims(type, c -> {
            c.setIssuedAt(NumericDate.fromSeconds(now - 10));
            c.setExpirationTime(NumericDate.fromSeconds(now + 3591));
        }));
        assertTrue(e.getMessage().contains(CloudTokenValidator.Policy.MAX_LIFETIME), e.getMessage());
        assertNotNull(validate(type, production(), config(type, null), claims(type, c -> {
            c.setIssuedAt(NumericDate.fromSeconds(now - 10));
            c.setExpirationTime(NumericDate.fromSeconds(now + 3590));
        })));
    }

    @ParameterizedTest
    @MethodSource("types")
    void onlySigningKeysVerify(Type type) throws Exception {
        CloudTokenValidator validator = type.validator().apply(production());
        String good = token(claims(type, c -> { }));
        Map<String, Object> params = new LinkedHashMap<>(TestJwts.publicParams(key));
        params.put("use", "enc");
        List<JsonWebKey> enc = List.of(JsonWebKey.Factory.newJwk(params));
        long before = CloudTokenValidator.refusals(type.id(), "config");
        assertEquals("invalid_svid", assertThrows(IssuanceException.class,
                () -> validator.validate(good, enc, config(type, null))).error());
        assertEquals(before + 1, CloudTokenValidator.refusals(type.id(), "config"));
        // An encryption key under the same kid beside another signing key: the kid finds no signing key.
        List<JsonWebKey> mixed = List.of(enc.get(0), JsonWebKey.Factory.newJwk(TestJwts.publicParams(TestJwts.ec("other"))));
        long keyBefore = CloudTokenValidator.refusals(type.id(), "key");
        assertEquals("invalid_svid", assertThrows(IssuanceException.class,
                () -> validator.validate(good, mixed, config(type, null))).error());
        assertEquals(keyBefore + 1, CloudTokenValidator.refusals(type.id(), "key"));
        params.put("use", "sig");
        assertNotNull(validator.validate(good, List.of(JsonWebKey.Factory.newJwk(params)), config(type, null)));
    }

    @ParameterizedTest
    @MethodSource("types")
    void theSignatureAndItsKeyAreChecked(Type type) throws Exception {
        CloudTokenValidator validator = type.validator().apply(production());
        AttestationIssuanceConfig config = config(type, null);
        long malformed = CloudTokenValidator.refusals(type.id(), "malformed");
        assertThrows(IssuanceException.class, () -> validator.validate("not-a-jws", bundle, config));
        assertThrows(IssuanceException.class, () -> validator.validate(" ", bundle, config));
        assertThrows(IssuanceException.class, () -> validator.validate(null, bundle, config));
        assertEquals(malformed + 3, CloudTokenValidator.refusals(type.id(), "malformed"));
        // A forged signature, and a stranger's key under the bundle's kid.
        PublicJsonWebKey stranger = TestJwts.ec("cloud-1");
        long signature = CloudTokenValidator.refusals(type.id(), "signature");
        assertThrows(IssuanceException.class, () -> validator.validate(
                TestJwts.sign(stranger, "ES256", null, claims(type, c -> { })), bundle, config));
        assertEquals(signature + 1, CloudTokenValidator.refusals(type.id(), "signature"));
        // No kid: the only key is used; with two keys it is refused.
        PublicJsonWebKey anonymous = TestJwts.ec(null);
        List<JsonWebKey> one = List.of(JsonWebKey.Factory.newJwk(TestJwts.publicParams(anonymous)));
        String noKid = TestJwts.sign(anonymous, "ES256", null, claims(type, c -> { }));
        assertNotNull(validator.validate(noKid, one, config));
        List<JsonWebKey> two = new ArrayList<>(one);
        two.addAll(bundle);
        assertThrows(IssuanceException.class, () -> validator.validate(noKid, two, config));
        // HMAC and none are not asymmetric; nor is an algorithm the header does not name.
        String hs = "eyJhbGciOiJIUzI1NiJ9." + token(claims(type, c -> { })).split("\\.")[1] + ".c2ln";
        String none = "eyJhbGciOiJub25lIn0." + token(claims(type, c -> { })).split("\\.")[1] + ".";
        String noAlg = "eyJraWQiOiJjbG91ZC0xIn0." + token(claims(type, c -> { })).split("\\.")[1] + ".c2ln";
        long alg = CloudTokenValidator.refusals(type.id(), "alg");
        for (String t : List.of(hs, none, noAlg)) {
            assertEquals("invalid_svid", assertThrows(IssuanceException.class, () -> validator.validate(t, bundle, config)).error());
        }
        assertEquals(alg + 3, CloudTokenValidator.refusals(type.id(), "alg"));
        // A signature too short for its algorithm.
        String[] parts = token(claims(type, c -> { })).split("\\.");
        long sig = CloudTokenValidator.refusals(type.id(), "signature");
        assertThrows(IssuanceException.class, () -> validator.validate(parts[0] + "." + parts[1] + ".c2ln", bundle, config));
        assertEquals(sig + 1, CloudTokenValidator.refusals(type.id(), "signature"));
        // A payload that is not JSON claims, under a good signature.
        org.jose4j.jws.JsonWebSignature jws = new org.jose4j.jws.JsonWebSignature();
        jws.setPayload("not json");
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setKeyIdHeaderValue("cloud-1");
        String notClaims = jws.getCompactSerialization();
        assertThrows(IssuanceException.class, () -> validator.validate(notClaims, bundle, config));
    }

    @ParameterizedTest
    @MethodSource("types")
    void theClientsConfigurationIsCheckedFirst(Type type) throws Exception {
        CloudTokenValidator validator = type.validator().apply(production());
        String good = token(claims(type, c -> { }));
        assertEquals("invalid_svid", assertThrows(IssuanceException.class,
                () -> validator.validate(good, List.of(), config(type, null))).error());
        assertEquals("invalid_svid", assertThrows(IssuanceException.class,
                () -> validator.validate(good, null, config(type, null))).error());
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ATTESTER);
        props.put(AttestationIssuanceConfig.P_BUNDLE, new JsonWebKeySet(bundle).toJson());
        props.put(AttestationIssuanceConfig.P_EVIDENCE, AttestationIssuanceConfig.EVIDENCE_SPIFFE_JWT);
        AttestationIssuanceConfig noDomain = AttestationIssuanceConfig.fromProperties(props);
        assertEquals("invalid_client", assertThrows(IssuanceException.class,
                () -> validator.validate(good, bundle, noDomain)).error());
        props.put(AttestationIssuanceConfig.P_TRUST_DOMAIN, " ");
        AttestationIssuanceConfig blankDomain = AttestationIssuanceConfig.fromProperties(props);
        assertEquals("invalid_client", assertThrows(IssuanceException.class,
                () -> validator.validate(good, bundle, blankDomain)).error());
    }

    @ParameterizedTest
    @MethodSource("types")
    void aPolicyThatCannotBeReadIsAServerError(Type type) throws Exception {
        CloudTokenValidator validator = switch (type.id()) {
            case "gke-sa-token" -> new GkeTokenValidator(60, CloudTokenValidatorTest::unreadable);
            case "gcp-id-token" -> new GcpSaTokenValidator(60, CloudTokenValidatorTest::unreadable);
            case "eks-sa-token" -> new EksTokenValidator(60, CloudTokenValidatorTest::unreadable);
            case "aws-sts-web-identity" -> new AwsStsWebIdentityValidator(60, CloudTokenValidatorTest::unreadable);
            case "aks-sa-token" -> new AksWorkloadIdentityValidator(60, CloudTokenValidatorTest::unreadable);
            default -> new AzureManagedIdentityValidator(60, CloudTokenValidatorTest::unreadable);
        };
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> validator.validate(token(claims(type, c -> { })), bundle, config(type, null)));
        assertEquals("server_error", e.error());
        assertTrue(e.getMessage().contains(CloudTokenValidator.Policy.MAX_LIFETIME), e.getMessage());
    }

    static CloudTokenValidator.Policy unreadable() {
        throw new IllegalArgumentException(CloudTokenValidator.Policy.MAX_LIFETIME + " must be between 60 and 86400");
    }

    @ParameterizedTest
    @MethodSource("types")
    void theBuiltInValidatorReadsTheProcessPolicy(Type type) throws Exception {
        CloudTokenValidator builtIn = (CloudTokenValidator) InstanceAttestationValidators.defaults().require(type.id());
        assertEquals(type.id(), builtIn.id());
        assertTrue(builtIn.requiresTrustDomain());
        assertFalse(builtIn.title().isBlank());
        assertFalse(builtIn.description().isBlank());
        assertTrue(builtIn.selectorNames().contains("issuer"));
        // This JVM sets none of the settings, and OIDF_DEPLOYMENT_PROFILE is unset: production with nothing pinned.
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> builtIn.validate(token(claims(type, c -> { })), bundle, config(type, null)));
        assertEquals("invalid_client", e.error());
    }

    @Test
    void theSixSubclassesAreEachShorterThanTheBase() throws Exception {
        Path dir = Path.of("src/main/java/com/pingidentity/ps/oidf/issuer");
        long base = Files.readAllLines(dir.resolve("CloudTokenValidator.java")).size();
        for (String name : List.of("GkeTokenValidator", "GcpSaTokenValidator", "EksTokenValidator",
                "AwsStsWebIdentityValidator", "AksWorkloadIdentityValidator", "AzureManagedIdentityValidator")) {
            long lines = Files.readAllLines(dir.resolve(name + ".java")).size();
            assertTrue(lines < base, name + " has " + lines + " lines, the base " + base);
            assertTrue(CloudTokenValidator.class.isAssignableFrom(Class.forName("com.pingidentity.ps.oidf.issuer." + name)));
        }
    }

    @Test
    void theRegistryWithAPolicyKeepsTheBuiltInOrder() {
        assertEquals(InstanceAttestationValidators.defaults().ids(),
                InstanceAttestationValidators.defaults(production()).ids());
    }

    // ---- GCP: projects, and no wildcard across '@' or the project ------------------------------------------------

    static Type type(String id) {
        return types().filter(t -> t.id().equals(id)).findFirst().orElseThrow();
    }

    @Test
    void gcpBindingsMayNotWildcardAcrossTheAtOrTheProject() throws Exception {
        Type gcp = type("gcp-id-token");
        String prefix = "spiffe://demo-project.gcp.example/sa/";
        assertNotNull(validate(gcp, production(), config(gcp, null, prefix + EMAIL), claims(gcp, c -> { })));
        for (String wildcard : List.of(prefix + "*", prefix + "agent-*", prefix + "agent-runtime@*",
                prefix + "agent-runtime@demo-*", "spiffe://demo-project.gcp.example/*", "spiffe://*")) {
            IssuanceException e = refused(gcp, "invalid_client", "binding_pattern", production(),
                    config(gcp, null, prefix + EMAIL, wildcard), claims(gcp, c -> { }));
            assertTrue(e.getMessage().contains("'*'"), e.getMessage());
            assertFalse(e.getMessage().contains(wildcard), e.getMessage());
        }
        for (String malformed : List.of(prefix + "agent-runtime@demo-project.example.com",
                "spiffe://other.example/sa/" + EMAIL, prefix + "service-1@gcp-sa-aiplatform.iam.gserviceaccount.com",
                prefix + "x@demo-project.iam.gserviceaccount.com")) {
            refused(gcp, "invalid_client", "binding_pattern", production(), config(gcp, null, malformed),
                    claims(gcp, c -> { }));
        }
        refused(gcp, "invalid_client", "binding_pattern", production(),
                config(gcp, null, prefix + "agent-runtime@other-project.iam.gserviceaccount.com"), claims(gcp, c -> { }));
        // Without a project list (development), any user-managed account's project.
        assertNotNull(validate(gcp, CloudPolicies.development(),
                config(gcp, null, prefix + "agent-runtime@other-project.iam.gserviceaccount.com"), claims(gcp, c -> { })));
    }

    @Test
    void gcpEvidenceIsHeldToTheListedProjects() throws Exception {
        Type gcp = type("gcp-id-token");
        refused(gcp, "invalid_svid", "project", production(), config(gcp, null),
                claims(gcp, c -> c.setClaim("email", "agent-runtime@other-project.iam.gserviceaccount.com")), "other-project");
        refused(gcp, "invalid_svid", "project", production(), config(gcp, null),
                claims(gcp, c -> c.setClaim("email", "service-1234567890@gcp-sa-aiplatform-re.iam.gserviceaccount.com")));
        refused(gcp, "invalid_svid", "project", production(), config(gcp, null),
                claims(gcp, c -> c.setClaim("email", "123456789012-compute@developer.gserviceaccount.com")));
        refused(gcp, "invalid_svid", "subject", production(), config(gcp, null), claims(gcp, c -> c.unsetClaim("email")));
        refused(gcp, "invalid_svid", "subject", production(), config(gcp, null), claims(gcp, c -> c.setClaim("email", " ")));
        CloudTokenValidator.Policy noProjects = policy(allPinned(), 3600L, null, null, null, null, false, true);
        IssuanceException e = refused(gcp, "invalid_client", "project", noProjects, config(gcp, null), claims(gcp, c -> { }));
        assertTrue(e.getMessage().contains(CloudTokenValidator.Policy.GCP_PROJECTS), e.getMessage());
        assertEquals("demo-project", GcpSaTokenValidator.projectOf(EMAIL));
    }

    @Test
    void gkeBindingsMayNotWildcardAcrossTheProject() throws Exception {
        Type gke = type("gke-sa-token");
        String prefix = "spiffe://demo-project.svc.id.goog/ns/";
        assertNotNull(validate(gke, production(), config(gke, null, prefix + "payments/sa/agent", prefix + "payments/*",
                prefix + "*"), claims(gke, c -> { })));
        for (String bad : List.of("spiffe://demo-project*", "spiffe://demo-project.svc.id.goog/*", prefix,
                prefix + "pay*ments/sa/agent", "spiffe://other-project.svc.id.goog/ns/payments/sa/agent")) {
            refused(gke, "invalid_client", "binding_pattern", production(), config(gke, null, bad), claims(gke, c -> { }));
        }
        // A workload identity pool of a project not listed.
        Type otherPool = new Type("gke-sa-token", GkeTokenValidator::new, GKE_ISSUER, "other-project.svc.id.goog",
                c -> c.setSubject(KSA), "/ns/payments/sa/agent");
        refused(otherPool, "invalid_client", "binding_pattern", production(), config(otherPool, null), claims(gke, c -> { }));
        assertNotNull(validate(otherPool, CloudPolicies.development(), config(otherPool, null), claims(gke, c -> { })));
        // A trust domain that is not a pool is not held to the list.
        Type plain = new Type("gke-sa-token", GkeTokenValidator::new, GKE_ISSUER, "gke.banking.demo",
                c -> c.setSubject(KSA), "/ns/payments/sa/agent");
        assertNotNull(validate(plain, production(), config(plain, null), claims(gke, c -> { })));
    }

    @Test
    void gkeClustersAreHeldToTheListedProjects() throws Exception {
        Type gke = type("gke-sa-token");
        CloudTokenValidator.Policy two = policy(Map.of("gke-sa-token", Set.of(GKE_ISSUER, OTHER_GKE_ISSUER,
                "https://cluster.example/gke")), 3600L, Set.of("demo-project"), null, null, null, false, true);
        refused(gke, "invalid_svid", "project", two, config(gke, null), claims(gke, c -> c.setIssuer(OTHER_GKE_ISSUER)));
        refused(gke, "invalid_svid", "project", two, config(gke, null),
                claims(gke, c -> c.setIssuer("https://cluster.example/gke")));
        CloudTokenValidator.Policy anyProject = policy(Map.of("gke-sa-token", Set.of(GKE_ISSUER, OTHER_GKE_ISSUER)),
                3600L, null, null, null, null, false, true);
        assertNotNull(validate(gke, anyProject, config(gke, null), claims(gke, c -> c.setIssuer(OTHER_GKE_ISSUER))));
        refused(gke, "invalid_svid", "subject", production(), config(gke, null),
                claims(gke, c -> c.setSubject("spiffe://demo-project.svc.id.goog/ns/payments/sa/agent")));
        refused(gke, "invalid_svid", "subject", production(), config(gke, null), claims(gke, c -> c.unsetClaim("sub")));
    }

    // ---- Azure: the tenant and the managed identity -------------------------------------------------------------

    @Test
    void azureEvidenceIsHeldToItsTenant() throws Exception {
        Type azure = type("azure-mi-token");
        refused(azure, "invalid_svid", "tenant", production(), config(azure, null),
                claims(azure, c -> c.setClaim("tid", OTHER_TENANT)), OTHER_TENANT);
        refused(azure, "invalid_svid", "tenant", production(), config(azure, null), claims(azure, c -> c.unsetClaim("tid")));
        refused(azure, "invalid_svid", "tenant", production(), config(azure, null), claims(azure, c -> c.setClaim("tid", 7)));
        CloudTokenValidator.Policy tenants = policy(allPinned(), 3600L, null, null, Set.of(OTHER_TENANT), null, false, true);
        assertNotNull(validate(azure, tenants, config(azure, null), claims(azure, c -> c.setClaim("tid", OTHER_TENANT.toUpperCase()))));
        refused(azure, "invalid_svid", "tenant", tenants, config(azure, null), claims(azure, c -> { }));
        // The v1 issuer carries the tenant too; an issuer of neither shape holds tid to nothing but the list.
        CloudTokenValidator.Policy v1 = policy(Map.of("azure-mi-token", Set.of(AZURE_V1_ISSUER, "https://entra.example/t")),
                3600L, null, null, null, null, false, true);
        assertNotNull(validate(azure, v1, config(azure, null), claims(azure, c -> c.setIssuer(AZURE_V1_ISSUER))));
        refused(azure, "invalid_svid", "tenant", v1, config(azure, null), claims(azure, c -> c.setIssuer("https://entra.example/t")));
    }

    @Test
    void azureEvidenceNeedsItsManagedIdentityClaim() throws Exception {
        Type azure = type("azure-mi-token");
        refused(azure, "invalid_svid", "managed_identity", production(), config(azure, null),
                claims(azure, c -> c.unsetClaim("oid")));
        refused(azure, "invalid_svid", "managed_identity", production(), config(azure, null),
                claims(azure, c -> c.setClaim("oid", "")));
        CloudTokenValidator.Policy listed = policy(allPinned(), 3600L, null, null, null, Set.of(OID), false, true);
        assertNotNull(validate(azure, listed, config(azure, null), claims(azure, c -> { })));
        refused(azure, "invalid_svid", "managed_identity", listed, config(azure, null),
                claims(azure, c -> c.setClaim("oid", "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee")));
    }

    @Test
    void aksTokensAreHeldToTheListedTenantsWhenTheyCarryOne() throws Exception {
        Type aks = type("aks-sa-token");
        CloudTokenValidator.Policy tenants = policy(allPinned(), 3600L, null, null, Set.of(TENANT), null, false, true);
        assertNotNull(validate(aks, tenants, config(aks, null), claims(aks, c -> { })));
        assertNotNull(validate(aks, tenants, config(aks, null), claims(aks, c -> c.setClaim("tid", TENANT))));
        assertNotNull(validate(aks, production(), config(aks, null), claims(aks, c -> c.setClaim("tid", OTHER_TENANT))));
        refused(aks, "invalid_svid", "tenant", tenants, config(aks, null), claims(aks, c -> c.setClaim("tid", OTHER_TENANT)));
        refused(aks, "invalid_svid", "tenant", tenants, config(aks, null), claims(aks, c -> c.setClaim("tid", 5)));
    }

    // ---- AWS: the account --------------------------------------------------------------------------------------

    @Test
    void awsEvidenceIsHeldToTheListedAccounts() throws Exception {
        Type aws = type("aws-sts-web-identity");
        CloudTokenValidator.Policy accounts = policy(allPinned(), 3600L, null, Set.of("123456789012"), null, null, false, true);
        assertNotNull(validate(aws, accounts, config(aws, null),
                claims(aws, c -> c.setClaim("https://sts.amazonaws.com/", Map.of("aws_account", "123456789012")))));
        SpiffeSvid assumed = validate(aws, accounts, config(aws, null),
                claims(aws, c -> c.setSubject("arn:aws:sts::123456789012:assumed-role/payments-agent/session-7")));
        assertEquals("spiffe://aws.banking.demo/aws/123456789012/role/payments-agent", assumed.spiffeId());
        refused(aws, "invalid_svid", "account", accounts, config(aws, null),
                claims(aws, c -> c.setSubject("arn:aws:iam::210987654321:role/payments-agent")), "210987654321");
        refused(aws, "invalid_svid", "account", production(), config(aws, null),
                claims(aws, c -> c.setClaim("https://sts.amazonaws.com/", Map.of("aws_account", "210987654321"))));
        assertNotNull(validate(aws, production(), config(aws, null),
                claims(aws, c -> c.setClaim("https://sts.amazonaws.com/", "not an object"))));
        refused(aws, "invalid_svid", "subject", production(), config(aws, null),
                claims(aws, c -> c.setSubject("arn:aws:iam::123456789012:user/alice")), "alice");
        refused(aws, "invalid_svid", "subject", production(), config(aws, null), claims(aws, c -> c.unsetClaim("sub")));
    }

    // ---- keys and algorithms -------------------------------------------------------------------------------------

    @Test
    void aKeyFitsOnlyTheAlgorithmOfItsTypeAndCurve() throws Exception {
        JsonWebKey p256 = JsonWebKey.Factory.newJwk(TestJwts.publicParams(TestJwts.ec("a")));
        JsonWebKey p384 = JsonWebKey.Factory.newJwk(TestJwts.publicParams(EcJwkGenerator.generateJwk(EllipticCurves.P384)));
        JsonWebKey p521 = JsonWebKey.Factory.newJwk(TestJwts.publicParams(EcJwkGenerator.generateJwk(EllipticCurves.P521)));
        JsonWebKey rsa = JsonWebKey.Factory.newJwk(TestJwts.publicParams(TestJwts.rsa("r")));
        JsonWebKey okp = JsonWebKey.Factory.newJwk(TestJwts.publicParams(OkpJwkGenerator.generateJwk("Ed25519")));
        assertTrue(CloudTokenValidator.fits(p256, "ES256"));
        assertTrue(CloudTokenValidator.fits(p384, "ES384"));
        assertTrue(CloudTokenValidator.fits(p521, "ES512"));
        assertFalse(CloudTokenValidator.fits(p256, "ES384"));
        assertFalse(CloudTokenValidator.fits(p384, "ES512"));
        assertFalse(CloudTokenValidator.fits(p521, "ES256"));
        assertFalse(CloudTokenValidator.fits(rsa, "ES256"));
        assertTrue(CloudTokenValidator.fits(rsa, "RS256"));
        assertTrue(CloudTokenValidator.fits(rsa, "PS384"));
        assertFalse(CloudTokenValidator.fits(p256, "RS256"));
        assertFalse(CloudTokenValidator.fits(p256, "PS256"));
        assertTrue(CloudTokenValidator.fits(okp, "EdDSA"));
        assertFalse(CloudTokenValidator.fits(rsa, "EdDSA"));
        p256.setAlgorithm("ES256");
        assertTrue(CloudTokenValidator.fits(p256, "ES256"));
        rsa.setAlgorithm("RS256");
        assertFalse(CloudTokenValidator.fits(rsa, "PS256"));
    }

    @Test
    void aKeyThatDoesNotFitTheTokensAlgorithmIsRefused() throws Exception {
        Type gke = type("gke-sa-token");
        CloudTokenValidator validator = gke.validator().apply(production());
        String good = token(claims(gke, c -> { }));
        Map<String, Object> params = new LinkedHashMap<>(TestJwts.publicParams(key));
        params.put("alg", "ES384");
        long before = CloudTokenValidator.refusals(gke.id(), "key");
        assertThrows(IssuanceException.class,
                () -> validator.validate(good, List.of(JsonWebKey.Factory.newJwk(params)), config(gke, null)));
        // A symmetric key under the kid is not a public key.
        JsonWebKey oct = JsonWebKey.Factory.newJwk(Map.of("kty", "oct", "k", "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0", "kid", "cloud-1"));
        assertThrows(IssuanceException.class, () -> validator.validate(good, List.of(oct), config(gke, null)));
        assertEquals(before + 2, CloudTokenValidator.refusals(gke.id(), "key"));
    }

    // ---- the settings --------------------------------------------------------------------------------------------

    static CloudTokenValidator.Policy read(Map<String, String> env) {
        return CloudTokenValidator.Policy.fromEnvironment(name -> null, env::get);
    }

    @Test
    void theSettingsDefaultToNothingPinnedAndAnHour() {
        CloudTokenValidator.Policy p = read(Map.of());
        assertEquals(3600L, p.maxTokenLifetimeSeconds());
        assertTrue(p.production());
        assertFalse(p.requireSingleAudience());
        for (String type : CloudTokenValidator.Policy.TYPES) {
            assertEquals(null, p.issuers(type));
        }
        assertEquals(null, p.gcpProjects());
        assertEquals(null, p.awsAccounts());
        assertEquals(null, p.azureTenants());
        assertEquals(null, p.azureManagedIdentities());
        assertFalse(read(Map.of("OIDF_DEPLOYMENT_PROFILE", "development")).production());
    }

    @Test
    void theSettingsAreReadAsTheirEntriesSay() {
        Map<String, String> env = new HashMap<>();
        env.put("OIDF_ATTESTER_GKE_SA_TOKEN_ISSUERS", GKE_ISSUER + " " + OTHER_GKE_ISSUER);
        env.put("OIDF_ATTESTER_GCP_ID_TOKEN_ISSUERS", GOOGLE_ISSUER);
        env.put("OIDF_ATTESTER_EKS_SA_TOKEN_ISSUERS", EKS_ISSUER);
        env.put("OIDF_ATTESTER_AWS_STS_WEB_IDENTITY_ISSUERS", AWS_ISSUER);
        env.put("OIDF_ATTESTER_AKS_SA_TOKEN_ISSUERS", AKS_ISSUER);
        env.put("OIDF_ATTESTER_AZURE_MI_TOKEN_ISSUERS", AZURE_ISSUER + "," + AZURE_V1_ISSUER);
        env.put("OIDF_ATTESTER_MAX_CLOUD_TOKEN_LIFETIME_SECONDS", "900");
        env.put("OIDF_ATTESTER_GCP_PROJECTS", "demo-project, other-project");
        env.put("OIDF_ATTESTER_AWS_ACCOUNTS", "123456789012");
        env.put("OIDF_ATTESTER_AZURE_TENANTS", TENANT.toUpperCase());
        env.put("OIDF_ATTESTER_AZURE_MANAGED_IDENTITIES", OID);
        env.put("OIDF_ATTESTER_REQUIRE_SINGLE_AUDIENCE_EVIDENCE", "true");
        CloudTokenValidator.Policy p = read(env);
        assertEquals(Set.of(GKE_ISSUER, OTHER_GKE_ISSUER), p.issuers("gke-sa-token"));
        assertEquals(Set.of(AZURE_ISSUER, AZURE_V1_ISSUER), p.issuers("azure-mi-token"));
        assertEquals(Set.of(AKS_ISSUER), p.issuers("aks-sa-token"));
        assertEquals(900L, p.maxTokenLifetimeSeconds());
        assertEquals(Set.of("demo-project", "other-project"), p.gcpProjects());
        assertEquals(Set.of("123456789012"), p.awsAccounts());
        assertEquals(Set.of(TENANT), p.azureTenants());
        assertEquals(Set.of(OID), p.azureManagedIdentities());
        assertTrue(p.requireSingleAudience());
        // A system property wins over the environment.
        CloudTokenValidator.Policy props = CloudTokenValidator.Policy.fromEnvironment(
                name -> "oidf.attester.max.cloud.token.lifetime.seconds".equals(name) ? "120" : null, env::get);
        assertEquals(120L, props.maxTokenLifetimeSeconds());
    }

    @Test
    void theLifetimeIsHeldToItsRange() {
        assertEquals(60L, read(Map.of("OIDF_ATTESTER_MAX_CLOUD_TOKEN_LIFETIME_SECONDS", "60")).maxTokenLifetimeSeconds());
        assertEquals(86400L, read(Map.of("OIDF_ATTESTER_MAX_CLOUD_TOKEN_LIFETIME_SECONDS", "86400")).maxTokenLifetimeSeconds());
        for (String bad : List.of("59", "86401", "0", "-1", "an hour")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> read(Map.of("OIDF_ATTESTER_MAX_CLOUD_TOKEN_LIFETIME_SECONDS", bad)));
            assertTrue(e.getMessage().contains("OIDF_ATTESTER_MAX_CLOUD_TOKEN_LIFETIME_SECONDS"), e.getMessage());
        }
    }

    @Test
    void aValueTheGrammarRefusesNamesItsSetting() {
        Map<String, String> bad = new LinkedHashMap<>();
        bad.put("OIDF_ATTESTER_GKE_SA_TOKEN_ISSUERS", "http://cluster.example");
        bad.put("OIDF_ATTESTER_GCP_ID_TOKEN_ISSUERS", "https://accounts.google.com?x=1");
        bad.put("OIDF_ATTESTER_EKS_SA_TOKEN_ISSUERS", "https:///no-host");
        bad.put("OIDF_ATTESTER_AWS_STS_WEB_IDENTITY_ISSUERS", "https://a.example/#frag");
        bad.put("OIDF_ATTESTER_AKS_SA_TOKEN_ISSUERS", "https://bad^host");
        bad.put("OIDF_ATTESTER_AZURE_MI_TOKEN_ISSUERS", ", ,");
        bad.put("OIDF_ATTESTER_GCP_PROJECTS", "demo-*");
        bad.put("OIDF_ATTESTER_AWS_ACCOUNTS", "12345");
        bad.put("OIDF_ATTESTER_AZURE_TENANTS", "contoso.onmicrosoft.com");
        bad.put("OIDF_ATTESTER_AZURE_MANAGED_IDENTITIES", "not-a-guid");
        bad.put("OIDF_ATTESTER_REQUIRE_SINGLE_AUDIENCE_EVIDENCE", "yes");
        for (Map.Entry<String, String> e : bad.entrySet()) {
            IllegalArgumentException x = assertThrows(IllegalArgumentException.class,
                    () -> read(Map.of(e.getKey(), e.getValue())), e.getKey());
            assertTrue(x.getMessage().contains(e.getKey()), x.getMessage());
        }
        for (String project : List.of("*", "demo-project*", "Demo_Project", "short", "demo-project-")) {
            assertThrows(IllegalArgumentException.class, () -> read(Map.of("OIDF_ATTESTER_GCP_PROJECTS", project)), project);
        }
    }

    @Test
    void theEvidencePolicyReadAtDeployRefusesABadCloudSetting() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> EvidencePolicy.fromEnvironment(
                name -> null, Map.of("OIDF_ATTESTER_GCP_PROJECTS", "*")::get));
        assertTrue(e.getMessage().contains("OIDF_ATTESTER_GCP_PROJECTS"), e.getMessage());
        assertNotNull(EvidencePolicy.fromEnvironment(name -> null, Map.of("OIDF_ATTESTER_GCP_PROJECTS", "demo-project")::get));
    }

    @Test
    void theProcessPolicyIsReadOnce() {
        assertSame(CloudTokenValidator.Policy.process(), CloudTokenValidator.Policy.process());
    }

    @Test
    void theIssuersSettingIsNamedPerType() {
        assertEquals("OIDF_ATTESTER_AKS_SA_TOKEN_ISSUERS", CloudTokenValidator.Policy.issuersSetting("aks-sa-token"));
        assertThrows(IllegalArgumentException.class, () -> CloudTokenValidator.Policy.issuersSetting("spiffe-jwt"));
    }
}
