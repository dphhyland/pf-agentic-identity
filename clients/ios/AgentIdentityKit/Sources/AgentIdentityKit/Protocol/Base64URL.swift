import Foundation

/// base64url without padding (RFC 4648 §5): the encoding of every binary value on the wire. The enrolment
/// service reads it with Java's `Base64.getUrlDecoder`, which takes padding but refuses `+` and `/`, and writes
/// it without padding (`EnrolmentHttpServer.binary`, `InstanceIdentifiers`).
extension Data {
    /// Strict: the URL-safe alphabet only, no padding, and one spelling of the bytes (re-encoding must give
    /// the input back). The same rule the connector helper's Jose.swift applies.
    public init?(base64URL: String) {
        guard base64URL.utf8.allSatisfy({
            ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39)
                || $0 == 0x2D || $0 == 0x5F
        }) else { return nil }
        var padded = base64URL.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while padded.count % 4 != 0 { padded += "=" }
        guard let decoded = Data(base64Encoded: padded), decoded.base64URL == base64URL else { return nil }
        self = decoded
    }

    public var base64URL: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Lower-case hexadecimal, the form the contract's vector table uses for hashes.
    public var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
