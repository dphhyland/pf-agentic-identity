import CryptoKit
import XCTest
@testable import AgentIdentityKit

/// The proof `EnclaveKeyProofValidator` verifies, byte for byte. That the Java accepts one is shown by the
/// interop run (clients/ios/tools/interop), where every re-mint's proof is the kit's.
final class KeyProofTests: XCTestCase {

    let audience = "https://enrolment.example"
    let issuedAt = Date(timeIntervalSince1970: 1_790_000_000)

    func testTheHeaderIsAlgJwkTyp() async throws {
        let proof = try await KeyProof.make(key: try SoftwareInstanceKey.rfc7515(), audience: audience,
                                            challenge: "c-1", jti: "j-1", issuedAt: issuedAt)
        XCTAssertEqual(String(decoding: proof.header, as: UTF8.self),
                       #"{"alg":"ES256","jwk":{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},"typ":"oauth-attestation-instance-proof+jwt"}"#)
    }

    func testThePayloadCarriesWhatTheValidatorReads() async throws {
        let proof = try await KeyProof.make(key: try SoftwareInstanceKey.rfc7515(), audience: audience,
                                            challenge: "c-1", jti: "j-1", issuedAt: issuedAt)
        XCTAssertEqual(String(decoding: proof.payload, as: UTF8.self),
                       #"{"aud":"https://enrolment.example","challenge":"c-1","exp":1790000120,"iat":1790000000,"jti":"j-1"}"#)
    }

    func testAProofWithoutAChallengeOmitsTheMember() async throws {
        let proof = try await KeyProof.make(key: SoftwareInstanceKey(), audience: audience, challenge: nil,
                                            jti: "j-1", issuedAt: issuedAt)
        XCTAssertNil(try DecodedJWS(proof.compact).payload["challenge"])
    }

    /// RFC 7515 §5.1: what is signed is ASCII(BASE64URL(header) || "." || BASE64URL(payload)), and the compact form
    /// appends the signature, R || S, as a third segment.
    func testTheSignatureIsES256OverTheSigningInput() async throws {
        let key = SoftwareInstanceKey()
        let proof = try await KeyProof.make(key: key, audience: audience, challenge: "c-1", issuedAt: issuedAt)
        let decoded = try DecodedJWS(proof.compact)
        XCTAssertEqual(decoded.signingInput, proof.signingInput)
        XCTAssertEqual(proof.compact,
                       proof.header.base64URL + "." + proof.payload.base64URL + "." + proof.signature.base64URL)
        XCTAssertEqual(proof.signature.count, 64)
        XCTAssertTrue(try decoded.verifiesUnderItsOwnJWK())
    }

    /// RFC 7515 Appendix A.3: the kit's signing input over the RFC's header and payload is the RFC's, and the
    /// RFC's R || S signature verifies over it under the RFC's key. Read at rfc-editor.org on 2026-09-27.
    func testTheRFC7515ExampleVerifies() throws {
        let header = Data(#"{"alg":"ES256"}"#.utf8)
        let payload = try decodeBase64URL(
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")
        let input = KeyProof.signingInput(header: header, payload: payload)
        XCTAssertEqual(String(decoding: input, as: UTF8.self),
                       "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: try decodeBase64URL(
            "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"))
        XCTAssertTrue(try SoftwareInstanceKey.rfc7515().signer.publicKey.isValidSignature(signature, for: input))
    }

    /// `SecKeyCreateSignature` gives DER; the validator reads R || S. A key that hands back DER is refused here,
    /// before the service would refuse it as `invalid_key_proof`.
    func testADERSignatureIsRefused() async throws {
        do {
            _ = try await KeyProof.make(key: DERSigningKey(), audience: audience, challenge: "c-1", issuedAt: issuedAt)
            XCTFail("a DER signature went out")
        } catch AgentIdentityError.malformedKey(let detail) {
            XCTAssertTrue(detail.contains("R || S"), detail)
        }
    }

    func testEveryProofHasItsOwnJti() async throws {
        let key = SoftwareInstanceKey()
        let first = try await KeyProof.make(key: key, audience: audience, challenge: nil, issuedAt: issuedAt)
        let second = try await KeyProof.make(key: key, audience: audience, challenge: nil, issuedAt: issuedAt)
        XCTAssertNotEqual(try DecodedJWS(first.compact).payload["jti"] as? String,
                          try DecodedJWS(second.compact).payload["jti"] as? String)
    }
}
