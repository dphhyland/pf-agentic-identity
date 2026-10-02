import Foundation

/// The instance-key proof `EnclaveKeyProofValidator` verifies: a compact JWS (RFC 7515 §7.1) the Secure Enclave
/// signs, carrying its own public key in the `jwk` header, which the server thumbprint-matches to the instance's
/// `cnf_jkt` before it trusts the signature.
///
/// The header is written by hand so its bytes are the same every time:
/// `{"alg":"ES256","jwk":{"crv":"P-256","kty":"EC","x":"…","y":"…"},"typ":"oauth-attestation-instance-proof+jwt"}`.
/// The payload is `Claims` with sorted keys. What the key signs is the JWS Signing Input of RFC 7515 §5.1
/// step 5, `ASCII(BASE64URL(header) || "." || BASE64URL(payload))`, and the signature is `R || S`.
public struct KeyProof: Equatable, Sendable {

    /// `EnclaveKeyProofValidator.TYP`: optional to the validator, which refuses any other value; always sent.
    public static let type = "oauth-attestation-instance-proof+jwt"

    /// The proof's own `exp`, as seconds after `iat`. Not read at ab74038; X-A06 will require it, and the
    /// validator's own window is 300 s on `iat`, so this is inside it.
    public static let lifetime = 120

    /// The claims `EnclaveKeyProofValidator.validate` reads: `aud` must contain the service's identifier (its
    /// `ENROLMENT_ISSUER`), `jti` must be present and is replay-checked per instance for 300 s, `iat` must be
    /// at most 300 s old and not 60 s in the future, `challenge` is consumed by `EnrolmentService.reissue`
    /// when present. `exp` is sent for X-A06.
    public struct Claims: Codable, Equatable, Sendable {
        public var aud: String
        public var challenge: String?
        public var exp: Int
        public var iat: Int
        public var jti: String

        public init(aud: String, challenge: String?, exp: Int, iat: Int, jti: String) {
            self.aud = aud
            self.challenge = challenge
            self.exp = exp
            self.iat = iat
            self.jti = jti
        }
    }

    /// The three segments joined with dots: what goes on the wire as `key_proof`, and the bytes an App Attest
    /// assertion commits to.
    public let compact: String
    public let header: Data
    public let payload: Data
    public let signature: Data

    /// The bytes the key signed.
    public var signingInput: Data { Self.signingInput(header: header, payload: payload) }

    public static func signingInput(header: Data, payload: Data) -> Data {
        Data((header.base64URL + "." + payload.base64URL).utf8)
    }

    /// The header for a key. `PublicJWK.thumbprintInput` is the JWK object in its canonical spelling, so the
    /// header's `jwk` is byte for byte the object the thumbprint was taken over.
    public static func header(for jwk: PublicJWK) -> Data {
        Data("{\"alg\":\"ES256\",\"jwk\":\(jwk.thumbprintInput),\"typ\":\"\(type)\"}".utf8)
    }

    /// Builds and signs a proof.
    ///
    /// - Parameters:
    ///   - audience: the service's `ENROLMENT_ISSUER`, the proof's `aud`.
    ///   - challenge: a fresh challenge from `POST /enrol/challenge`, or nil for a proof that names none (the
    ///     server accepts either; the kit always names one).
    ///   - jti: fresh per proof; a repeat within 300 s is `invalid_key_proof`.
    public static func make(key: InstanceKey, audience: String, challenge: String?, jti: String = UUID().uuidString,
                            issuedAt: Date) async throws -> KeyProof {
        let iat = Int(issuedAt.timeIntervalSince1970)
        let claims = Claims(aud: audience, challenge: challenge, exp: iat + lifetime, iat: iat, jti: jti)
        let payload = try WireJSON.encoder().encode(claims)
        let header = header(for: key.publicJWK)
        let input = signingInput(header: header, payload: payload)
        let signature = try await key.sign(input)
        guard signature.count == 64 else {
            throw AgentIdentityError.malformedKey("an ES256 signature is R || S, 64 bytes, not \(signature.count)")
        }
        return KeyProof(compact: String(decoding: input, as: UTF8.self) + "." + signature.base64URL,
                        header: header, payload: payload, signature: signature)
    }
}
