import AgentIdentityKit
import CryptoKit
import Foundation

/// App Attest objects for docs/findings/U-0063.yaml and plan item X-A07: one key, its attestation over the kit's
/// commitment to a fixed thumbprint and challenge, and three assertions over fixed client data, in the fields of
/// libs/app-attest's macOS 27.2 fixtures. Run it once in a development build and once in a production one (the
/// entitlement decides); the aaguid in the attestation's authenticator data says which it was.
enum VectorCapture {

    /// RFC 7515 Appendix A.3.1's key's thumbprint, the kit's vector: the attestation commits to it, not to a key
    /// this device holds, so the capture needs no enrolment.
    static let jkt = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"
    static let clientData = "renewal key proof"

    static func run(appAttest: AttestationProvider) async throws -> String {
        guard appAttest.isSupported else { throw AgentIdentityError.appAttestUnsupported }
        let capturedAt = Date()
        let challenge = "capture-" + String(Int(capturedAt.timeIntervalSince1970))
        let key = try await appAttest.generateKey()
        let attestation = try await appAttest.attest(
            key, clientDataHash: Commitments.attestationClientDataHash(instanceThumbprint: jkt, challenge: challenge))
        let clientDataHash = Data(SHA256.hash(data: Data(clientData.utf8)))
        var assertions: [String] = []
        for _ in 0..<3 {
            assertions.append(try await appAttest.generateAssertion(key, clientDataHash: clientDataHash).base64URL)
        }
        let device = DeviceDescription.current(agentBuild: nil)
        let capture: [String: Any] = [
            "captured_at": ISO8601DateFormatter().string(from: capturedAt),
            "device": "\(device.model ?? "unknown") \(device.platform) \(device.osVersion ?? "")",
            "bundle_id": Bundle.main.bundleIdentifier ?? "unknown",
            "attestation": [
                "jkt": jkt,
                "challenge": challenge,
                "key_id_as_returned": key.apple,
                "key_id": key.wire,
                "attestation_object": attestation.base64URL,
            ],
            "assertions": [
                "client_data": clientData,
                "assertions": assertions,
            ],
        ]
        let data = try JSONSerialization.data(withJSONObject: capture, options: [.prettyPrinted, .sortedKeys,
                                                                                  .withoutEscapingSlashes])
        return String(decoding: data, as: UTF8.self)
    }
}
