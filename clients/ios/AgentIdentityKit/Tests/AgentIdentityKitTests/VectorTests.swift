import CryptoKit
import XCTest
@testable import AgentIdentityKit

/// The values the server computes, pinned. Every constant here was printed on 2026-09-27 by
/// clients/ios/tools/vectors/run.sh, which runs the enrolment service's own classes (Jwks.thumbprint,
/// EnrolmentService.clientDataHash and enrolmentNonce, AppAttestVerifier's nonce reader) compiled from this
/// repository at ab74038. When the server's derivations change, run it again and move these with it.
final class VectorTests: XCTestCase {

    /// RFC 7515 Appendix A.3.1's P-256 key, the instance key of every vector.
    static let instanceX = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
    static let instanceY = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    static let instanceJkt = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"
    /// RFC 7517 Appendix A.1's first key, the connector's federation key.
    static let federationX = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"
    static let federationY = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
    static let federationJkt = "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s"
    static let challenge = "Kf8-TzQb1x0yJ3v2wE5tN7oP9aR4sU6dV8gH1jL0mZc"
    static let build = "b4x-3Zq9vP1Ls8Kj7Hn6Md5Fc4Vb3Nx2Za1Qw0Er9Ty"

    static func jwk(_ x: String, _ y: String) throws -> PublicJWK {
        try PublicJWK(p256Raw: try decodeBase64URL(x) + (try decodeBase64URL(y)))
    }

    func testTheThumbprintIsJwksThumbprint() throws {
        XCTAssertEqual(try Self.jwk(Self.instanceX, Self.instanceY).thumbprint, Self.instanceJkt)
        XCTAssertEqual(try Self.jwk(Self.federationX, Self.federationY).thumbprint, Self.federationJkt)
    }

    func testTheAttestationCommitmentIsEnrolmentServiceClientDataHash() {
        XCTAssertEqual(Commitments.attestationClientDataHash(instanceThumbprint: Self.instanceJkt,
                                                             challenge: Self.challenge).hexString,
                       "8fa9fc8a2ab60ed015e58b73a2281f3c1557aca1458ee1b13c3fdf9a8e9fe38c")
    }

    func testTheConnectorCommitmentAppendsTheBuild() {
        XCTAssertEqual(Commitments.attestationClientDataHash(instanceThumbprint: Self.instanceJkt,
                                                             challenge: Self.challenge, build: Self.build).hexString,
                       "a2fb0d3910887863c9f9d2fc7a0cbb4a82a6c1504bc8bf2d155cb7fac744b80e")
    }

    /// The server's own nonce method, three segments: the proof that digest, separator and encoding match.
    func testTheThreeSegmentNonceIsEnrolmentServiceEnrolmentNonce() {
        XCTAssertEqual(Commitments.enrolmentNonce(challenge: Self.challenge, instanceThumbprint: Self.instanceJkt,
                                                  federationThumbprint: Self.federationJkt),
                       "WpH_t8uLcoVBEIrrFg3knPbZADPJUtxusB4E586FTj4")
    }

    /// The iOS nonce: the same digest, separator and encoding over the two segments an iOS enrolment has. Not a
    /// server method (the server checks no nonce on the iOS path; F-0084): the vector is SHA-256 in Java over
    /// the same string, so what this pins is the kit's proposal for X-A05, not a server behaviour.
    func testTheTwoSegmentNonceIsTheKitsProposal() {
        XCTAssertEqual(Commitments.enrolmentNonce(challenge: Self.challenge, instanceThumbprint: Self.instanceJkt),
                       "DmMGWbB6TJpfTCoLrMXtcM7xaSsk_7SKy0iBkZLig6k")
    }

    /// A made-up proof: header `{"alg":"ES256"}`, payload `{"aud":"https://enrol"}`, the word "sig".
    func testTheAssertionCommitmentIsSha256OfTheProofAsSent() {
        let madeUp = "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL2Vucm9sIn0.c2ln"
        XCTAssertEqual(Commitments.assertionClientDataHash(keyProof: madeUp).hexString,
                       "a10dcc630c8d8f271e0b7cc707f1e7971d6377af857859e2bb1eaaeaf1c412f4")
    }

    // ---- a real device: the macOS 27.2 objects in libs/app-attest/src/test/resources/fixtures ----------------

    /// The attestation SecureEnclaveSigner.app made on macOS 27.2 (26 Sep 2026): Apple wrote SHA-256(authData ||
    /// clientDataHash) into the credential certificate, and the kit's commitment over the fixture's jkt and
    /// challenge reproduces it. So the commitment is what a real App Attest attestation signed, not only what the
    /// Java computes.
    func testTheAttestationCommitmentIsWhatARealAttestationSigned() throws {
        let authData = try XCTUnwrap(Data(hex: "ec44fd6a26b073c736a7a9adacf67ab7305935f829c082d0832d9fd9285800b8c00000000061707061747465737400000000000000002023869d0e6c82e2ee1c791466c7cf24a6817294de81bcd48dd2deee50c24f339aa5010203262001215820437820444bb86dc1bb32d8c7e9e6d33b0635426b4a22ba62aba7b69ecc1ea82c2258202367350fc05d826eba9fc985a5f5e64a8e10b93be80c5afa9bad19a355b8ed23a1781c6170706c655f76616c69646174696f6e5f63617465676f72795f30314403000000"))
        let clientDataHash = Commitments.attestationClientDataHash(
            instanceThumbprint: "tSb7JBw7RPCSyeGgH9LnxgZjaaim3KsQws_7yl8kZT8", challenge: "spike-challenge-001")
        XCTAssertEqual(Data(SHA256.hash(data: authData + clientDataHash)).hexString,
                       "28484b8f51a5e870e7e3695c67732fc0e8dcadb525cabeae652b6d751db928a8")
    }

    /// The two assertions from the same app: each signature verifies under the attested key over the nonce
    /// SHA-256(authenticatorData || clientDataHash), with the kit's assertion commitment as clientDataHash, and
    /// the counter in the authenticator data rises from 1 to 2. The authenticator data is 73 bytes, not 37: an
    /// extensions map follows the counter.
    func testTheAssertionCommitmentIsWhatRealAssertionsSigned() throws {
        let key = try P256.Signing.PublicKey(derRepresentation: try decodeBase64URL(
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5QDBGQUsMFxm6mD1MybRhzPWz7pE9wiLaXFfJh2UKCjydrphXxip1w-3zKgmYi3bCGK3aIUdgrnHRfvpv_G9dA"))
        let clientDataHash = Commitments.assertionClientDataHash(keyProof: "renewal key proof")
        let assertions: [(authData: String, signature: String, counter: UInt32)] = [
            ("ec44fd6a26b073c736a7a9adacf67ab7305935f829c082d0832d9fd9285800b8c000000001a1781c6170706c655f76616c69646174696f6e5f63617465676f72795f30314403000000",
             "3045022100fa51676bd54950789170194179706d185284ea2496dd75cb27965ce236df275302207a3ba4c751e0b817085751ad3c4927c7454e96f4ef97f3ba5caf7f49dd113512",
             1),
            ("ec44fd6a26b073c736a7a9adacf67ab7305935f829c082d0832d9fd9285800b8c000000002a1781c6170706c655f76616c69646174696f6e5f63617465676f72795f30314403000000",
             "304602210096757fcc103e646bf897afe0e02fec177b972331fd505c84915c0297a591d937022100f4f41c66696e255791826c77b373ae6d2decc3492268dedfd41e5df9f6d43d14",
             2),
        ]
        for assertion in assertions {
            let authData = try XCTUnwrap(Data(hex: assertion.authData))
            XCTAssertEqual(authData.count, 73)
            XCTAssertEqual(authData[33..<37].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }, assertion.counter)
            let nonce = Data(SHA256.hash(data: authData + clientDataHash))
            let signature = try P256.Signing.ECDSASignature(derRepresentation: try XCTUnwrap(Data(hex: assertion.signature)))
            XCTAssertTrue(key.isValidSignature(signature, for: nonce))
            XCTAssertFalse(key.isValidSignature(signature, for: Data(SHA256.hash(
                data: authData + Commitments.assertionClientDataHash(keyProof: "another proof")))))
        }
    }
}
