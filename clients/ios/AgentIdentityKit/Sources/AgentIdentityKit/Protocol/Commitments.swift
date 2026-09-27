import CryptoKit
import Foundation
import Security

/// The values the client commits to and the server recomputes, byte for byte as the Java does them. Each is
/// pinned in the tests against a value printed by the server's own classes (clients/ios/tools/vectors).
public enum Commitments {

    /// `EnrolmentService.clientDataHash`: `SHA-256(UTF-8(jkt + "|" + challenge))`, and with a third segment
    /// `"|" + build` for a connector running inside the attested app. What `attestKey` signs over, and the
    /// only thing tying App Attest to the instance key: the server recomputes it from the JWK and challenge in
    /// the request, so committing to any other key fails as `invalid_attestation`.
    public static func attestationClientDataHash(instanceThumbprint jkt: String, challenge: String,
                                                 build: String? = nil) -> Data {
        let committed = build.map { jkt + "|" + challenge + "|" + $0 } ?? (jkt + "|" + challenge)
        return sha256(committed)
    }

    /// `EnrolmentService.verifyRenewalAssertion`: `SHA-256(UTF-8(key_proof))` over the compact serialisation
    /// exactly as it is sent, all three segments and both dots. What `generateAssertion` signs over.
    public static func assertionClientDataHash(keyProof: String) -> Data {
        sha256(keyProof)
    }

    /// `EnrolmentService.enrolmentNonce`: `base64url(SHA-256(UTF-8(challenge + "|" + instanceJkt + "|" +
    /// federationJkt)))`. With a federation thumbprint this is the server's own method, the connector path's
    /// nonce. Without one it is the two-segment value an iOS enrolment has: the same digest, separator and
    /// encoding, but not a method the server has, because the server checks no nonce on the iOS path (plan
    /// item X-A05 adds the check; docs/findings/F-0084.yaml).
    public static func enrolmentNonce(challenge: String, instanceThumbprint: String,
                                      federationThumbprint: String? = nil) -> String {
        var segments = [challenge, instanceThumbprint]
        if let federationThumbprint { segments.append(federationThumbprint) }
        return sha256(segments.joined(separator: "|")).base64URL
    }

    /// 32 bytes from the system's cryptographic generator as base64url: the nonce of a sign-in the server
    /// does not bind (the user-verification refresh), a PKCE verifier and an OAuth `state`.
    public static func randomNonce() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            // Nothing sensible can be sent without randomness, and a predictable value would be worse than none.
            preconditionFailure("SecRandomCopyBytes failed")
        }
        return Data(bytes).base64URL
    }

    private static func sha256(_ text: String) -> Data {
        Data(SHA256.hash(data: Data(text.utf8)))
    }
}
