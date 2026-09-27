import CryptoKit
import Foundation

/// ES256 as a JWS carries it. RFC 7518 §3.4: R and S "in big-endian order, with each array being be 32 octets
/// long", concatenated, and "The JWS Signature value MUST be a 64-octet sequence" (read 2026-09-27). The Security
/// framework's `SecKeyCreateSignature` returns the DER `SEQUENCE { INTEGER r, INTEGER s }` instead, whose integers
/// drop leading zero octets and gain one when the high bit is set; `EnclaveKeyProofValidator` (jose4j) refuses
/// that shape, so the instance key converts before a signature goes anywhere.
public enum ES256 {

    /// DER to R || S. Refuses anything that is not a P-256 ECDSA signature.
    public static func rawSignature(fromDER der: Data) throws -> Data {
        let raw: Data
        do {
            raw = try P256.Signing.ECDSASignature(derRepresentation: der).rawRepresentation
        } catch {
            throw AgentIdentityError.malformedKey("not a DER ECDSA P-256 signature (\(der.count) bytes)")
        }
        guard raw.count == 64 else {
            throw AgentIdentityError.malformedKey("an ES256 signature is R || S, 64 bytes, not \(raw.count)")
        }
        return raw
    }
}
