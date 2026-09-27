import CryptoKit
import Foundation

/// The instance key's public half as the service reads it (`enclave_public_jwk`) and as the key proof carries
/// it (the `jwk` header): four members and nothing else, because `DeviceAttestationMinter.mint` echoes the
/// object into every attestation's `cnf.jwk`.
///
/// The thumbprint is RFC 7638's, over exactly `{"crv":"P-256","kty":"EC","x":"…","y":"…"}`. That is what the
/// server computes: jose4j re-encodes `x` and `y` from the parsed point to the curve's 32 bytes before hashing
/// (`EllipticCurveJsonWebKey.produceThumbprintHashInput`, 0.9.6), so a coordinate with a leading zero byte has
/// to be sent padded to 32 bytes, which the initialisers below guarantee. A `kid` would be ignored by the
/// thumbprint and is never sent.
public struct PublicJWK: Codable, Equatable, Hashable, Sendable {
    public let kty: String
    public let crv: String
    public let x: String
    public let y: String

    /// One P-256 coordinate, big-endian.
    public static let coordinateLength = 32

    /// From CryptoKit's `rawRepresentation`, `X || Y`, 64 bytes.
    public init(p256Raw raw: Data) throws {
        guard raw.count == 2 * Self.coordinateLength else {
            throw AgentIdentityError.malformedKey("a P-256 raw public key is 64 bytes, not \(raw.count)")
        }
        self.init(x: Data(raw.prefix(Self.coordinateLength)), y: Data(raw.suffix(Self.coordinateLength)))
    }

    /// From the X9.62 uncompressed point, `0x04 || X || Y`, 65 bytes: CryptoKit's `x963Representation` and what
    /// `SecKeyCopyExternalRepresentation` returns for an EC public key.
    public init(p256X963 point: Data) throws {
        guard point.count == 1 + 2 * Self.coordinateLength, point.first == 0x04 else {
            throw AgentIdentityError.malformedKey("a P-256 X9.62 uncompressed point is 65 bytes starting 0x04")
        }
        try self.init(p256Raw: Data(point.dropFirst()))
    }

    public init(_ key: P256.Signing.PublicKey) {
        self.init(x: Data(key.rawRepresentation.prefix(Self.coordinateLength)),
                  y: Data(key.rawRepresentation.suffix(Self.coordinateLength)))
    }

    private init(x: Data, y: Data) {
        self.kty = "EC"
        self.crv = "P-256"
        self.x = x.base64URL
        self.y = y.base64URL
    }

    /// The RFC 7638 §3.2 hash input: the required members, lexicographic, no whitespace.
    public var thumbprintInput: String {
        "{\"crv\":\"\(crv)\",\"kty\":\"\(kty)\",\"x\":\"\(x)\",\"y\":\"\(y)\"}"
    }

    /// `jkt`: base64url of SHA-256 over `thumbprintInput`. The instance's identity in the App Attest
    /// commitment, the nonce and the registry's `cnf_jkt`.
    public var thumbprint: String {
        Data(SHA256.hash(data: Data(thumbprintInput.utf8))).base64URL
    }

    /// The key as CryptoKit sees it, for verifying a proof in a test.
    public func p256Key() throws -> P256.Signing.PublicKey {
        guard let xBytes = Data(base64URL: x), let yBytes = Data(base64URL: y) else {
            throw AgentIdentityError.malformedKey("x and y are not base64url")
        }
        return try P256.Signing.PublicKey(rawRepresentation: xBytes + yBytes)
    }
}
