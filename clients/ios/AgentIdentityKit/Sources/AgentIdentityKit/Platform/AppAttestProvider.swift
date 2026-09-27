#if canImport(DeviceCheck)
import DeviceCheck
import Foundation

/// App Attest through `DCAppAttestService`. Cannot run under test: `isSupported` is false on a simulator and on
/// a CI runner. A run on a physical iPhone is docs/findings/U-0063.yaml.
public struct AppAttestProvider: AttestationProvider {

    public init() {}

    public var isSupported: Bool { DCAppAttestService.shared.isSupported }

    public func generateKey() async throws -> AppAttestKeyID {
        try AppAttestKeyID(apple: try await DCAppAttestService.shared.generateKey())
    }

    public func attest(_ key: AppAttestKeyID, clientDataHash: Data) async throws -> Data {
        do {
            return try await DCAppAttestService.shared.attestKey(key.apple, clientDataHash: clientDataHash)
        } catch where Self.isServerUnavailable(error) {
            // Apple, attestKey(_:clientDataHash:completionHandler:), read 2026-09-27: on serverUnavailable "retry
            // attestation again using the same key and client data hash later to avoid unnecessarily generating
            // new keys". Once, after a pause, inside the challenge's 300 s; a second failure is the caller's.
            try await Task.sleep(nanoseconds: 2_000_000_000)
            return try await DCAppAttestService.shared.attestKey(key.apple, clientDataHash: clientDataHash)
        }
    }

    public func generateAssertion(_ key: AppAttestKeyID, clientDataHash: Data) async throws -> Data {
        try await DCAppAttestService.shared.generateAssertion(key.apple, clientDataHash: clientDataHash)
    }

    private static func isServerUnavailable(_ error: Error) -> Bool {
        let nsError = error as NSError
        return nsError.domain == DCErrorDomain && nsError.code == DCError.serverUnavailable.rawValue
    }
}
#endif
