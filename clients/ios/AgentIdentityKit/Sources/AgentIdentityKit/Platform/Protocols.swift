import Foundation

// The four platform seams and the transport. The protocol layer speaks to these and nothing else, so the unit
// tests run with fakes on a Mac and the real implementations (App Attest, the Secure Enclave, PingOne) are
// exercised only on a device.

/// The instance key: the Secure Enclave P-256 key whose thumbprint is the instance's identity and which signs
/// every key proof. `SecureEnclaveInstanceKey` is the real one.
public protocol InstanceKey: Sendable {
    var publicJWK: PublicJWK { get }
    /// ES256 over the JWS Signing Input (RFC 7515 §5.1 step 5): SHA-256 inside, and the signature returned as
    /// `R || S`, 64 bytes (RFC 7518 §3.4), never DER.
    func sign(_ signingInput: Data) async throws -> Data
}

/// Apple's key identifier as `generateKey` returned it, and the 32 bytes it names.
///
/// Apple's documentation says only "An identifier that you use to refer to the key" and nothing
/// about its encoding (read 2026-09-27). On macOS 27.2 it decoded as standard base64, and the server's check
/// that the bytes are SHA-256 of the attested key passed, so that is tried first, with base64url second
/// (docs/findings/U-0063.yaml). The service wants the bytes as base64url (`EnrolmentHttpServer.binary`), which
/// `wire` gives.
public struct AppAttestKeyID: Equatable, Hashable, Sendable, Codable {
    /// Exactly what `generateKey` returned: what `attestKey` and `generateAssertion` take.
    public let apple: String
    /// The credential id: SHA-256 of the attested public key's X9.62 uncompressed point.
    public let bytes: Data

    public init(apple: String) throws {
        if let standard = Data(base64Encoded: apple), standard.count == 32 {
            self.bytes = standard
        } else if let url = Data(base64URL: apple), url.count == 32 {
            self.bytes = url
        } else {
            throw AgentIdentityError.keyIdentifierNotDecodable(
                "App Attest returned a key identifier that is not base64 of 32 bytes")
        }
        self.apple = apple
    }

    /// `appattest_key_id`.
    public var wire: String { bytes.base64URL }
}

/// App Attest through `DCAppAttestService`. `AppAttestProvider` is the real one.
public protocol AttestationProvider: Sendable {
    /// `DCAppAttestService.isSupported`. When false the kit refuses to enrol: the server requires the attestation.
    var isSupported: Bool { get }
    /// `generateKey()`.
    func generateKey() async throws -> AppAttestKeyID
    /// `attestKey(_:clientDataHash:)`: the CBOR attestation object.
    func attest(_ key: AppAttestKeyID, clientDataHash: Data) async throws -> Data
    /// `generateAssertion(_:clientDataHash:)`: the CBOR assertion object.
    func generateAssertion(_ key: AppAttestKeyID, clientDataHash: Data) async throws -> Data
}

/// A fresh sign-in of the owner at PingOne. `PingOneAuthenticator` is the real one.
public protocol Authenticator: Sendable {
    /// Returns the ID token as PingOne issued it, compact JWS, from an authentication request that carried this
    /// `nonce` and asked for a fresh authentication (`max_age=0`), because the server measures the time-box from
    /// the token's `auth_time`. `DeviceAgent` checks the nonce and `auth_time` in what comes back.
    func authenticate(nonce: String) async throws -> String
}

/// The Entra device token from the MSAL broker. No request carries it at ab74038; the seam exists for X-A17,
/// and `UnavailableDeviceTokenProvider` is what ships (docs/findings/U-0064.yaml, U-0065.yaml).
public protocol DeviceTokenProvider: Sendable {
    func deviceToken() async throws -> String
}

/// One HTTP round trip. `URLSessionTransport` is the real one; the tests script replies.
public struct HTTPReply: Equatable, Sendable {
    public let status: Int
    public let body: Data

    public init(status: Int, body: Data) {
        self.status = status
        self.body = body
    }
}

public protocol HTTPTransport: Sendable {
    /// `POST` with `Content-Type: application/json`; returns whatever came back, any status.
    func post(_ url: URL, body: Data) async throws -> HTTPReply
}
