import CryptoKit
import XCTest
@testable import AgentIdentityKit

final class JWKTests: XCTestCase {

    func testTheX963PointGivesTheRFCsCoordinates() throws {
        let key = try SoftwareInstanceKey.rfc7515()
        let jwk = try PublicJWK(p256X963: key.signer.publicKey.x963Representation)
        XCTAssertEqual(jwk.x, VectorTests.instanceX)
        XCTAssertEqual(jwk.y, VectorTests.instanceY)
        XCTAssertEqual(jwk, key.publicJWK)
    }

    /// RFC 7638 §3.2: the required members, lexicographic, no whitespace. jose4j hashes exactly this.
    func testTheThumbprintInputIsTheRequiredMembersInOrder() throws {
        let jwk = try VectorTests.jwk(VectorTests.instanceX, VectorTests.instanceY)
        XCTAssertEqual(jwk.thumbprintInput,
                       #"{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#)
    }

    /// `enclave_public_jwk` is echoed into every attestation's `cnf.jwk`, so it carries the four members and no
    /// more; with sorted keys the wire form is the thumbprint input itself.
    func testTheWireFormIsFourMembers() throws {
        let jwk = try VectorTests.jwk(VectorTests.instanceX, VectorTests.instanceY)
        let data = try WireJSON.encoder().encode(jwk)
        XCTAssertEqual(String(decoding: data, as: UTF8.self), jwk.thumbprintInput)
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: String])
        XCTAssertEqual(Set(object.keys), ["kty", "crv", "x", "y"])
    }

    /// jose4j re-encodes each coordinate to 32 bytes before hashing, so a coordinate whose first byte is zero has
    /// to go out as 43 characters, not 42, or the thumbprints part company.
    func testALeadingZeroCoordinateStaysThirtyTwoBytes() throws {
        var raw = Data(repeating: 0x11, count: 64)
        raw[0] = 0x00
        raw[32] = 0x00
        let jwk = try PublicJWK(p256Raw: raw)
        XCTAssertEqual(jwk.x.count, 43)
        XCTAssertEqual(try decodeBase64URL(jwk.x).count, 32)
        XCTAssertEqual(try decodeBase64URL(jwk.y).first, 0x00)
    }

    func testTheWrongLengthsAreRefused() {
        XCTAssertThrowsError(try PublicJWK(p256Raw: Data(count: 63)))
        XCTAssertThrowsError(try PublicJWK(p256X963: Data(count: 64)))
        XCTAssertThrowsError(try PublicJWK(p256X963: Data([0x02]) + Data(count: 64)))
    }

    func testTheJWKReadsBackAsTheSameKey() throws {
        let key = P256.Signing.PrivateKey()
        XCTAssertEqual(try PublicJWK(key.publicKey).p256Key().rawRepresentation, key.publicKey.rawRepresentation)
    }
}

final class Base64URLTests: XCTestCase {

    func testRoundTrip() throws {
        for length in 0..<70 {
            let bytes = Data((0..<length).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ 11) })
            XCTAssertEqual(Data(base64URL: bytes.base64URL), bytes)
            XCTAssertFalse(bytes.base64URL.contains("="))
        }
    }

    /// The server decodes with `Base64.getUrlDecoder`, which refuses `+` and `/`; the kit refuses them too, and
    /// padding, and a second spelling of the same bytes.
    func testOnlyTheURLAlphabetWithoutPaddingInOneSpelling() {
        XCTAssertNil(Data(base64URL: "ab+/"))
        XCTAssertNil(Data(base64URL: "YQ=="))
        XCTAssertNil(Data(base64URL: "YR"))
        XCTAssertEqual(Data(base64URL: "YQ"), Data("a".utf8))
    }
}
