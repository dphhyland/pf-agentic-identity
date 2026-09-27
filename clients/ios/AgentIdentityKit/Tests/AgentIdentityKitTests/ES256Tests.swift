import CryptoKit
import XCTest
@testable import AgentIdentityKit

/// The Secure Enclave signs in DER; the key proof carries R || S. What `SecureEnclaveInstanceKey.sign` does to
/// every signature, tested on signatures from a software key and on real App Attest ones.
final class ES256Tests: XCTestCase {

    /// Two hundred signatures: about one R or S in 128 has its high bit set (DER adds a zero octet) and one in 256
    /// starts with a zero octet (DER drops it). Each converts to the raw form CryptoKit gives, and verifies.
    func testDERBecomesTheSixtyFourOctetsTheValidatorReads() throws {
        let key = P256.Signing.PrivateKey()
        for index in 0..<200 {
            let message = Data("signing input \(index)".utf8)
            let signature = try key.signature(for: message)
            let raw = try ES256.rawSignature(fromDER: signature.derRepresentation)
            XCTAssertEqual(raw, signature.rawRepresentation)
            XCTAssertTrue(key.publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: raw), for: message))
        }
    }

    /// A DER signature from a real device (the first macOS 27.2 assertion, whose R needs the extra zero octet)
    /// converts to 64 octets.
    func testARealDeviceSignatureConverts() throws {
        let der = try XCTUnwrap(Data(hex: "3045022100fa51676bd54950789170194179706d185284ea2496dd75cb27965ce236df275302207a3ba4c751e0b817085751ad3c4927c7454e96f4ef97f3ba5caf7f49dd113512"))
        let raw = try ES256.rawSignature(fromDER: der)
        XCTAssertEqual(raw.hexString, "fa51676bd54950789170194179706d185284ea2496dd75cb27965ce236df2753"
                                      + "7a3ba4c751e0b817085751ad3c4927c7454e96f4ef97f3ba5caf7f49dd113512")
    }

    func testAnythingElseIsRefused() {
        XCTAssertThrowsError(try ES256.rawSignature(fromDER: Data()))
        XCTAssertThrowsError(try ES256.rawSignature(fromDER: Data(count: 64)))
        XCTAssertThrowsError(try ES256.rawSignature(fromDER: Data([0x30, 0x03, 0x02, 0x01, 0x01])))
    }
}
