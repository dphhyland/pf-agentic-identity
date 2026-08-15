/*
 * The digital-wallet implementation of InstanceAttestationValidator (Wallet Instance Attestation / WIA).
 */
package com.pingidentity.ps.oidf.issuer;

import java.security.Key;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jws.JsonWebSignature;
import com.pingidentity.ps.oidf.clientattestation.AttesterKeyResolver;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.jose.Jwks;

/**
 * The digital-wallet implementation of {@link InstanceAttestationValidator}. A wallet has no SPIFFE
 * identity; instead its <em>Wallet Provider</em> issues it a <em>Wallet Instance Attestation</em> (WIA) — a
 * signed JWT that binds the wallet instance's key to a known provider (an OpenID4VC / HAIP requirement, and
 * itself an instance of the same OAuth attestation-based client authentication this endpoint mints). This
 * validator verifies a presented WIA against the wallet provider's trusted keys — resolved via an
 * {@link AttesterKeyResolver} (federation-backed in production via
 * {@code FederationWalletProviderKeyResolver}, {@link StaticAttesterKeyResolver} for dev) — then adapts it
 * to a format-neutral {@link InstanceIdentity}.
 *
 * <p>The WIA is a compact JWS whose {@code iss} is the wallet provider (the trust root, analogous to a
 * SPIFFE trust domain), {@code sub} is the wallet instance identifier (matched against the client's
 * {@code attestation_instances}), and {@code cnf.jwk} binds the instance key. Checks, in order: header
 * {@code typ} is a WIA type (or absent) and {@code alg} is asymmetric; {@code iss}/{@code sub} present; the
 * wallet provider is trusted (resolver) and the signature verifies under the selected key; {@code exp} is
 * not past (small skew allowed); {@code aud} names this attester; if the client pins a wallet provider
 * ({@link AttestationIssuanceConfig#expectedTrustDomain()}) it must equal {@code iss}; and {@code cnf.jwk}
 * is a public key. The bound key rides back as {@link InstanceIdentity#boundKey()} so the endpoint can
 * require it to equal the key being bound. Any failure throws {@code invalid_instance_attestation}.
 */
public final class WalletInstanceAttestationValidator implements InstanceAttestationValidator {

    /** The format label for wallets, used in selection and as {@code workload.attested_by}. */
    public static final String FORMAT = "wallet";

    /** Accepted {@code typ} header values for a Wallet Instance Attestation (a WIA is itself a client attestation). */
    public static final Set<String> WIA_TYPES = Set.of(
            "wallet-instance-attestation+jwt", "wallet-attestation+jwt",
            "wallet-unit-attestation+jwt", "oauth-client-attestation+jwt");

    private static final Set<String> PERMITTED_ALGORITHMS = ClientAttestationConfig.DEFAULT_ASYMMETRIC_ALGORITHMS;

    private final AttesterKeyResolver walletProviderKeys;
    private final long allowedClockSkewSeconds;

    public WalletInstanceAttestationValidator(AttesterKeyResolver walletProviderKeys) {
        this(walletProviderKeys, ClientAttestationConfig.DEFAULT_CLOCK_SKEW_SECONDS);
    }

    public WalletInstanceAttestationValidator(AttesterKeyResolver walletProviderKeys, long allowedClockSkewSeconds) {
        this.walletProviderKeys = Objects.requireNonNull(walletProviderKeys, "walletProviderKeys");
        this.allowedClockSkewSeconds = allowedClockSkewSeconds;
    }

    @Override
    public String id() {
        return AttestationIssuanceConfig.EVIDENCE_WALLET_INSTANCE_ATTESTATION;
    }

    @Override
    public String format() {
        return FORMAT;
    }

    /** A wallet's trust root is its provider, resolved via {@link AttesterKeyResolver} — not a SPIFFE bundle. */
    @Override
    public boolean requiresTrustBundle() {
        return false;
    }

    @Override
    public String title() {
        return "Wallet Instance Attestation";
    }

    @Override
    public String description() {
        return "A Wallet Instance Attestation signed by the wallet provider, whose keys are resolved "
                + "through an OpenID Federation trust chain or a static pin. Binds the instance key via cnf.jwk.";
    }

    /**
     * {@inheritDoc}
     *
     * <p>{@code bundleKeys} is unused: a wallet's trust root is its provider, resolved through the
     * {@link AttesterKeyResolver}, not a SPIFFE trust bundle.
     */
    @Override
    public InstanceIdentity validate(String presented, List<JsonWebKey> bundleKeys,
                                     AttestationIssuanceConfig config) throws IssuanceException {
        if (presented == null || presented.isBlank()) {
            throw IssuanceException.invalidInstanceAttestation("no wallet instance attestation presented");
        }
        if (config.issuer() == null || config.issuer().isBlank()) {
            throw IssuanceException.invalidInstanceAttestation("no expected audience configured");
        }

        JsonWebSignature jws = new JsonWebSignature();
        String typ;
        String alg;
        String kid;
        try {
            jws.setCompactSerialization(presented);
            typ = jws.getHeader("typ");
            alg = jws.getAlgorithmHeaderValue();
            kid = jws.getKeyIdHeaderValue();
        } catch (Exception e) {
            throw IssuanceException.invalidInstanceAttestation("WIA is not a well-formed compact JWS");
        }
        if (typ != null && !WIA_TYPES.contains(typ)) {
            throw IssuanceException.invalidInstanceAttestation("WIA has an unexpected 'typ': " + typ);
        }
        if (alg == null || !PERMITTED_ALGORITHMS.contains(alg)) {
            throw IssuanceException.invalidInstanceAttestation("WIA uses an unsupported signing algorithm: " + alg);
        }

        // Parse (unverified) to learn the wallet provider (iss) before resolving its keys.
        JwtClaims claims;
        try {
            claims = JwtClaims.parse(jws.getUnverifiedPayload());
        } catch (Exception e) {
            throw IssuanceException.invalidInstanceAttestation("WIA payload is not valid JWT claims");
        }
        String provider = claims.getClaimValueAsString("iss");
        if (provider == null || provider.isBlank()) {
            throw IssuanceException.invalidInstanceAttestation("WIA has no 'iss' (wallet provider)");
        }
        String subject = claims.getClaimValueAsString("sub");
        if (subject == null || subject.isBlank()) {
            throw IssuanceException.invalidInstanceAttestation("WIA has no 'sub' (wallet instance id)");
        }

        List<JsonWebKey> providerKeys;
        try {
            providerKeys = this.walletProviderKeys.resolve(provider, headerTrustChain(jws));
        } catch (Exception e) {
            throw IssuanceException.invalidInstanceAttestation(
                    "wallet provider is not trusted or its keys could not be resolved: " + provider);
        }
        if (providerKeys == null || providerKeys.isEmpty()) {
            throw IssuanceException.invalidInstanceAttestation("no trusted keys for wallet provider: " + provider);
        }

        Key verificationKey = selectKey(providerKeys, kid);
        jws.setKey(verificationKey);
        jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, alg));
        try {
            if (!jws.verifySignature()) {
                throw IssuanceException.invalidInstanceAttestation(
                        "WIA signature did not verify against the wallet provider keys");
            }
        } catch (IssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw IssuanceException.invalidInstanceAttestation("WIA signature verification failed");
        }

        long now = NumericDate.now().getValue();
        long exp;
        try {
            if (!claims.hasClaim("exp")) {
                throw IssuanceException.invalidInstanceAttestation("WIA has no 'exp'");
            }
            exp = claims.getExpirationTime().getValue();
        } catch (IssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw IssuanceException.invalidInstanceAttestation("WIA 'exp' is malformed");
        }
        if (exp + this.allowedClockSkewSeconds < now) {
            throw IssuanceException.invalidInstanceAttestation("WIA has expired");
        }

        List<String> aud;
        try {
            aud = claims.getAudience();
        } catch (Exception e) {
            throw IssuanceException.invalidInstanceAttestation("WIA 'aud' is malformed");
        }
        if (aud == null || !aud.contains(config.issuer())) {
            throw IssuanceException.invalidInstanceAttestation(
                    "WIA audience does not include this attester: " + config.issuer());
        }

        // Optional pin: a client may restrict which wallet provider it accepts.
        String pinned = config.expectedTrustDomain();
        if (pinned != null && !pinned.isBlank() && !pinned.equals(provider)) {
            throw IssuanceException.invalidInstanceAttestation(
                    "WIA wallet provider '" + provider + "' does not match the pinned provider '" + pinned + "'");
        }

        Map<String, Object> boundKey = confirmationJwk(claims);
        try {
            Jwks.assertPublicOnly(boundKey);
        } catch (RuntimeException e) {
            throw IssuanceException.invalidInstanceAttestation("WIA cnf.jwk must be a public key: " + e.getMessage());
        }

        LinkedHashMap<String, Object> workload = new LinkedHashMap<>();
        workload.put("wallet_provider", provider);
        workload.put("wallet_instance", subject);
        workload.put("instance_attestation", presented);
        return new InstanceIdentity(FORMAT, subject, provider, boundKey, workload, exp);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> confirmationJwk(JwtClaims claims) throws IssuanceException {
        Object cnf = claims.getClaimValue("cnf");
        if (!(cnf instanceof Map)) {
            throw IssuanceException.invalidInstanceAttestation("WIA has no 'cnf' binding the instance key");
        }
        Object jwk = ((Map<String, Object>) cnf).get("jwk");
        if (!(jwk instanceof Map)) {
            throw IssuanceException.invalidInstanceAttestation("WIA 'cnf' has no embedded 'jwk'");
        }
        return (Map<String, Object>) jwk;
    }

    private static List<String> headerTrustChain(JsonWebSignature jws) {
        Object tc = jws.getHeaders().getObjectHeaderValue("trust_chain");
        if (tc instanceof List) {
            List<String> out = new ArrayList<>();
            for (Object o : (List<?>) tc) {
                out.add(String.valueOf(o));
            }
            return out;
        }
        return List.of();
    }

    private static Key selectKey(List<JsonWebKey> keys, String kid) throws IssuanceException {
        JsonWebKey chosen = null;
        if (kid != null && !kid.isBlank()) {
            for (JsonWebKey k : keys) {
                if (kid.equals(k.getKeyId())) {
                    chosen = k;
                    break;
                }
            }
            if (chosen == null) {
                throw IssuanceException.invalidInstanceAttestation("no wallet-provider key matches WIA kid: " + kid);
            }
        } else if (keys.size() == 1) {
            chosen = keys.get(0);
        } else {
            throw IssuanceException.invalidInstanceAttestation(
                    "WIA has no kid and the provider bundle holds multiple keys");
        }
        if (!(chosen instanceof PublicJsonWebKey)) {
            throw IssuanceException.invalidInstanceAttestation("wallet-provider key is not an asymmetric public key");
        }
        return ((PublicJsonWebKey) chosen).getPublicKey();
    }
}
