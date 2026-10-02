import CryptoKit
import XCTest
@testable import AgentIdentityKit

/// The kit against the real Java service over HTTP. clients/ios/tools/interop/run.sh starts the service's own
/// classes beside an oracle for Apple and PingOne and sets the three variables below; anywhere else, CI included,
/// this skips. What it shows that the unit tests cannot: that `EnrolmentHttpServer` reads what the kit sends -
/// every field name and encoding, the commitment, the key proof, the assertion - and that the kit reads what the
/// service answers, including the two refusals a re-mint recovers from.
final class InteropTests: XCTestCase {

    struct Endpoints {
        let service: URL
        let oracle: URL
        let audience: String
    }

    private var endpoints: Endpoints?

    override func setUpWithError() throws {
        let environment = ProcessInfo.processInfo.environment
        guard let service = environment["AGENTIDENTITYKIT_INTEROP_SERVICE"].flatMap(URL.init(string:)),
              let oracle = environment["AGENTIDENTITYKIT_INTEROP_ORACLE"].flatMap(URL.init(string:)),
              let audience = environment["AGENTIDENTITYKIT_INTEROP_AUDIENCE"] else {
            throw XCTSkip("run clients/ios/tools/interop/run.sh to drive the kit against the Java service")
        }
        endpoints = Endpoints(service: service, oracle: oracle, audience: audience)
    }

    func testTheKitAndTheJavaServiceAgree() async throws {
        let endpoints = try XCTUnwrap(endpoints)
        let oracle = Oracle(base: endpoints.oracle)
        let key = SoftwareInstanceKey()
        let appAttest = OracleAppAttest(oracle: oracle)
        let authenticator = OracleAuthenticator(oracle: oracle)
        let agent = DeviceAgent(client: EnrolmentClient(baseURL: endpoints.service), audience: endpoints.audience,
                                instanceKey: key, appAttest: appAttest, authenticator: authenticator,
                                device: DeviceDescription(platform: "ios", model: "iPhone16,2", osVersion: "18.5",
                                                          agentBuild: "interop/1"))

        // Enrolment: App Attest over SHA-256(jkt | challenge), the ID token, the four-member JWK.
        let enrolment = try await agent.enrol()
        let attestation = try DecodedJWS(enrolment.attestation)
        XCTAssertEqual(attestation.header["typ"] as? String, "oauth-client-attestation+jwt")
        XCTAssertEqual(attestation.payload["iss"] as? String, endpoints.audience)
        XCTAssertEqual(attestation.payload["agent_id"] as? String, enrolment.instanceID)
        XCTAssertEqual(attestation.payload["agent_build"] as? String, "interop/1")
        let cnf = try XCTUnwrap((attestation.payload["cnf"] as? [String: Any])?["jwk"] as? [String: String])
        XCTAssertEqual(cnf, ["kty": "EC", "crv": "P-256", "x": key.publicJWK.x, "y": key.publicJWK.y])
        var device = try await oracle.call("registry/device", ["instance_id": enrolment.instanceID])
        XCTAssertEqual(device["cnf_jkt"] as? String, key.publicJWK.thumbprint)
        XCTAssertEqual(device["app_attest_key_id"] as? String, enrolment.appAttestKeyID.wire)
        XCTAssertEqual(device["platform"] as? String, "ios")
        XCTAssertEqual(device["model"] as? String, "iPhone16,2")
        XCTAssertEqual(device["os_version"] as? String, "18.5")
        XCTAssertEqual(device["app_attest_sign_count"] as? Int, 0)

        // A re-mint: the key proof passes EnclaveKeyProofValidator, the assertion passes verifyRenewalAssertion,
        // and the registry's counter moves to the assertion's.
        var reminted = try await agent.remint()
        XCTAssertNotEqual(reminted.attestation, enrolment.attestation)
        device = try await oracle.call("registry/device", ["instance_id": enrolment.instanceID])
        XCTAssertEqual(device["app_attest_sign_count"] as? Int, 1)

        // The time-box: the service refuses with user_verification_required; the kit signs the owner in again,
        // POST /user-verification takes the new token, and the re-mint goes through.
        _ = try await oracle.call("registry/age-user-verification", ["instance_id": enrolment.instanceID])
        XCTAssertEqual(authenticator.count, 1)
        reminted = try await agent.remint()
        XCTAssertEqual(authenticator.count, 2, "the owner signed in again")
        XCTAssertEqual(appAttest.counter, 3, "assertion 2 went with the refused request, 3 with the one that minted")
        device = try await oracle.call("registry/device", ["instance_id": enrolment.instanceID])
        XCTAssertEqual(device["app_attest_sign_count"] as? Int, 3)

        // A lost race: another renewal of this device recorded the counter the kit's next assertion will carry.
        // The service refuses it as counter_not_advanced; the kit re-mints once more with a higher counter.
        _ = try await oracle.call("registry/advance-counter", ["instance_id": enrolment.instanceID, "counter": 4])
        reminted = try await agent.remint()
        XCTAssertEqual(appAttest.counter, 5, "assertion 4 lost to the other renewal's 4, and 5 minted")
        device = try await oracle.call("registry/device", ["instance_id": enrolment.instanceID])
        XCTAssertEqual(device["app_attest_sign_count"] as? Int, 5)

        // Another key cannot re-mint this instance: the proof's jwk is thumbprint-matched to cnf_jkt.
        let impostor = DeviceAgent(client: EnrolmentClient(baseURL: endpoints.service), audience: endpoints.audience,
                                   instanceKey: SoftwareInstanceKey(), appAttest: appAttest, authenticator: authenticator,
                                   device: .current(agentBuild: nil), state: .enrolled(reminted))
        do {
            _ = try await impostor.remint()
            XCTFail("another key re-minted the instance")
        } catch AgentIdentityError.refused(let refusal) {
            XCTAssertEqual(refusal.code, ServerCode.invalidKeyProof)
        }
    }
}

/// The harness's oracle: Apple's and PingOne's parts, and two levers on the registry.
struct Oracle: Sendable {
    let base: URL

    func call(_ path: String, _ body: [String: Any]) async throws -> [String: Any] {
        var request = URLRequest(url: base.appending(path: path))
        request.httpMethod = "POST"
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await URLSession.shared.data(for: request)
        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw AgentIdentityError.unexpectedResponse(status: (response as? HTTPURLResponse)?.statusCode ?? 0,
                                                        body: String(describing: object))
        }
        return object
    }
}

/// App Attest by way of the oracle: `generateKey` returns the identifier in standard base64, as macOS 27.2's did,
/// and the counter is kept here, as the device keeps it.
final class OracleAppAttest: AttestationProvider, @unchecked Sendable {
    let oracle: Oracle
    private let lock = NSLock()
    private var _counter = 0

    init(oracle: Oracle) {
        self.oracle = oracle
    }

    var isSupported: Bool { true }
    var counter: Int { lock.withLock { _counter } }

    func generateKey() async throws -> AppAttestKeyID {
        try AppAttestKeyID(apple: try await oracle.call("app-attest/key", [:])["key_id"] as? String ?? "")
    }

    func attest(_ key: AppAttestKeyID, clientDataHash: Data) async throws -> Data {
        try decodeBase64URL(try await oracle.call("app-attest/attest", [
            "key_id": key.apple, "client_data_hash": clientDataHash.base64URL,
        ])["attestation_object"] as? String ?? "")
    }

    func generateAssertion(_ key: AppAttestKeyID, clientDataHash: Data) async throws -> Data {
        let counter = lock.withLock { () -> Int in
            _counter += 1
            return _counter
        }
        return try decodeBase64URL(try await oracle.call("app-attest/assert", [
            "key_id": key.apple, "client_data_hash": clientDataHash.base64URL, "counter": counter,
        ])["assertion"] as? String ?? "")
    }
}

/// PingOne by way of the oracle: an RS256 ID token for one owner, with the nonce asked for.
final class OracleAuthenticator: Authenticator, @unchecked Sendable {
    let oracle: Oracle
    private let lock = NSLock()
    private var _count = 0

    init(oracle: Oracle) {
        self.oracle = oracle
    }

    var count: Int { lock.withLock { _count } }

    func authenticate(nonce: String) async throws -> String {
        lock.withLock { _count += 1 }
        return try await oracle.call("idp/id-token", ["nonce": nonce, "sub": "interop-owner"])["id_token"] as? String ?? ""
    }
}
