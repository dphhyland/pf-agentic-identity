import XCTest
@testable import AgentIdentityKit

/// The wire names are the contract: `EnrolmentHttpServer` reads each field with `body.get(name)`, so a misspelt key
/// is a missing field on the server. Each request is encoded and its keys compared with the Java's.
final class MessagesTests: XCTestCase {

    private func keys<T: Encodable>(_ value: T) throws -> Set<String> {
        let object = try JSONSerialization.jsonObject(with: try WireJSON.encoder().encode(value))
        return Set(try XCTUnwrap(object as? [String: Any]).keys)
    }

    /// `EnrolmentHttpServer.enrol`, the iOS shape: no federation_public_jwk, key_proofs or evidence.
    func testTheEnrolmentRequestUsesTheServersNames() throws {
        let jwk = try VectorTests.jwk(VectorTests.instanceX, VectorTests.instanceY)
        let request = EnrolRequest(appattestObject: "o", appattestKeyId: "k", enclavePublicJwk: jwk, challenge: "c",
                                   userAuthentication: "t", platform: "ios", model: "iPhone16,2", osVersion: "18.5",
                                   agentBuild: "agent/1.0")
        XCTAssertEqual(try keys(request), ["appattest_object", "appattest_key_id", "enclave_public_jwk", "challenge",
                                           "user_authentication", "platform", "model", "os_version", "agent_build"])
        let bare = EnrolRequest(appattestObject: "o", appattestKeyId: "k", enclavePublicJwk: jwk, challenge: "c",
                                userAuthentication: "t", platform: "ios", model: nil, osVersion: nil, agentBuild: nil)
        XCTAssertEqual(try keys(bare), ["appattest_object", "appattest_key_id", "enclave_public_jwk", "challenge",
                                        "user_authentication", "platform"])
    }

    /// `EnrolmentHttpServer.attestation`: `app_attest_assertion` has the underscore `appattest_object` lacks.
    func testTheReissueRequestUsesTheServersNames() throws {
        XCTAssertEqual(try keys(ReissueRequest(instanceId: "i", keyProof: "p", appAttestAssertion: "a")),
                       ["instance_id", "key_proof", "app_attest_assertion"])
        XCTAssertEqual(try keys(ReissueRequest(instanceId: "i", keyProof: "p", appAttestAssertion: nil)),
                       ["instance_id", "key_proof"])
    }

    func testTheUserVerificationRequestUsesTheServersNames() throws {
        XCTAssertEqual(try keys(UserVerificationRequest(instanceId: "i", userAuthentication: "t")),
                       ["instance_id", "user_authentication"])
    }

    /// The replies as `EnrolmentHttpServer` writes them (Jackson, `LinkedHashMap` order).
    func testTheRepliesDecode() throws {
        let decoder = WireJSON.decoder()
        XCTAssertEqual(try decoder.decode(ChallengeResponse.self,
                                          from: Data(#"{"challenge":"abc","expires_in":300}"#.utf8)).expiresIn, 300)
        let enrolled = try decoder.decode(EnrolResponse.self, from: Data(
            #"{"instance_id":"i-1","attestation":"a.b.c","expires_in":900,"appattest_key_id":"k"}"#.utf8))
        XCTAssertEqual(enrolled, EnrolResponse(instanceId: "i-1", attestation: "a.b.c", expiresIn: 900, appattestKeyId: "k"))
        XCTAssertEqual(try decoder.decode(ReissueResponse.self, from: Data(#"{"attestation":"a.b.c","expires_in":900}"#.utf8)),
                       ReissueResponse(attestation: "a.b.c", expiresIn: 900))
        XCTAssertEqual(try decoder.decode(StatusResponse.self, from: Data(#"{"status":"ok"}"#.utf8)).status, "ok")
        XCTAssertEqual(try decoder.decode(ErrorResponse.self, from: Data(
            #"{"error":"user_verification_required","error_description":"older than PT5M"}"#.utf8)).error,
                       "user_verification_required")
    }

    func testSlashesAreNotEscaped() throws {
        let body = try WireJSON.encoder().encode(UserVerificationRequest(instanceId: "a/b", userAuthentication: "t"))
        XCTAssertTrue(String(decoding: body, as: UTF8.self).contains(#""a/b""#))
    }
}
