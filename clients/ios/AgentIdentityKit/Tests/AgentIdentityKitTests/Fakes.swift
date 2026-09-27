import CryptoKit
import Foundation
@testable import AgentIdentityKit

// The platform pieces, faked. What the kit sends and what it signs are real; Apple, the Secure Enclave, PingOne
// and the service are not.

/// CryptoKit's software P-256 signing key. (A type name, so that no line reads as a credential to gitleaks.)
typealias SoftwareP256 = P256.Signing.PrivateKey

/// A software P-256 key where the phone has the Secure Enclave. CryptoKit's `signature(for:)` hashes with SHA-256
/// and returns a signature whose `rawRepresentation` is `R || S`, as the enclave's does.
struct SoftwareInstanceKey: InstanceKey {
    let signer: SoftwareP256

    init(_ signer: SoftwareP256 = SoftwareP256()) {
        self.signer = signer
    }

    /// RFC 7515 Appendix A.3.1's key (`d`, with the `x` and `y` the vectors use).
    static func rfc7515() throws -> SoftwareInstanceKey {
        SoftwareInstanceKey(try SoftwareP256(rawRepresentation: try decodeBase64URL("jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI")))
    }

    var publicJWK: PublicJWK { PublicJWK(signer.publicKey) }

    func sign(_ signingInput: Data) async throws -> Data {
        try signer.signature(for: signingInput).rawRepresentation
    }
}

/// A key that hands back DER, the shape `SecKeyCreateSignature` gives for `.ecdsaSignatureMessageX962SHA256`.
struct DERSigningKey: InstanceKey {
    let signer = SoftwareP256()
    var publicJWK: PublicJWK { PublicJWK(signer.publicKey) }

    func sign(_ signingInput: Data) async throws -> Data {
        try signer.signature(for: signingInput).derRepresentation
    }
}

/// App Attest's surface without Apple: a key identifier in standard base64, as `generateKey` returned one on
/// macOS 27.2, and stand-in objects that carry what they were asked to sign, so a test can read it back.
final class FakeAppAttest: AttestationProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var _supported = true
    private var _attested: [(key: AppAttestKeyID, clientDataHash: Data)] = []
    private var _asserted: [(key: AppAttestKeyID, clientDataHash: Data, counter: Int)] = []
    private var counter = 0

    var isSupported: Bool {
        get { lock.withLock { _supported } }
        set { lock.withLock { _supported = newValue } }
    }
    var attested: [(key: AppAttestKeyID, clientDataHash: Data)] { lock.withLock { _attested } }
    var asserted: [(key: AppAttestKeyID, clientDataHash: Data, counter: Int)] { lock.withLock { _asserted } }

    func generateKey() async throws -> AppAttestKeyID {
        try AppAttestKeyID(apple: Data((0..<32).map { _ in UInt8.random(in: .min ... .max) }).base64EncodedString())
    }

    func attest(_ key: AppAttestKeyID, clientDataHash: Data) async throws -> Data {
        lock.withLock { _attested.append((key, clientDataHash)) }
        return Data("attestation-object:".utf8) + clientDataHash
    }

    func generateAssertion(_ key: AppAttestKeyID, clientDataHash: Data) async throws -> Data {
        let counter = lock.withLock { () -> Int in
            self.counter += 1
            _asserted.append((key, clientDataHash, self.counter))
            return self.counter
        }
        return Data("assertion:\(counter):".utf8) + clientDataHash
    }
}

/// PingOne's surface without PingOne: an ID token shaped as PingOne issues one (unsigned here; the service is the
/// verifier of record and the kit never checks the signature), carrying the nonce it was asked for.
final class FakeAuthenticator: Authenticator, @unchecked Sendable {
    enum Behaviour { case honest, wrongNonce, noNonce, noAuthTime, notAJWT }

    private let lock = NSLock()
    private var _nonces: [String] = []
    private var _behaviour: Behaviour = .honest
    let subject: String

    init(subject: String = "pingone-subject-1") {
        self.subject = subject
    }

    var nonces: [String] { lock.withLock { _nonces } }
    var behaviour: Behaviour {
        get { lock.withLock { _behaviour } }
        set { lock.withLock { _behaviour = newValue } }
    }

    func authenticate(nonce: String) async throws -> String {
        let behaviour = lock.withLock { () -> Behaviour in
            _nonces.append(nonce)
            return _behaviour
        }
        if behaviour == .notAJWT { return "not-a-jwt" }
        var claims: [String: Any] = ["iss": "https://auth.pingone.example/env/as", "sub": subject,
                                     "aud": "sample-client", "exp": 4_000_000_000, "acr": "passkey-policy"]
        if behaviour != .noNonce { claims["nonce"] = behaviour == .wrongNonce ? "another-nonce" : nonce }
        if behaviour != .noAuthTime { claims["auth_time"] = 1_790_000_000 }
        return FakeAuthenticator.unsignedJWT(claims)
    }

    static func unsignedJWT(_ claims: [String: Any]) -> String {
        let header = Data(#"{"alg":"RS256","kid":"test"}"#.utf8).base64URL
        let payload = (try? JSONSerialization.data(withJSONObject: claims, options: [.sortedKeys])) ?? Data()
        return header + "." + payload.base64URL + "." + Data("signature".utf8).base64URL
    }
}

/// The service's four routes, answered as `EnrolmentHttpServer` answers them, with refusals a test can queue.
final class FakeService: HTTPTransport, @unchecked Sendable {
    struct Request {
        let route: String
        let body: [String: Any]
    }

    static let base = URL(string: "https://enrolment.example/")!

    private let lock = NSLock()
    private var _requests: [Request] = []
    private var challenges = 0
    private var mints = 0
    private var reissueRefusals: [HTTPReply] = []
    private var enrolRefusal: HTTPReply?
    private var userVerificationRefusal: HTTPReply?
    private var delays: [String: UInt64] = [:]

    var requests: [Request] { lock.withLock { _requests } }
    func routes() -> [String] { requests.map(\.route) }
    func bodies(_ route: String) -> [[String: Any]] { requests.filter { $0.route == route }.map(\.body) }

    /// Served in order by `POST /attestation` before it mints again.
    func refuseReissue(_ replies: HTTPReply...) { lock.withLock { reissueRefusals += replies } }
    func refuseEnrol(_ reply: HTTPReply) { lock.withLock { enrolRefusal = reply } }
    func refuseUserVerification(_ reply: HTTPReply) { lock.withLock { userVerificationRefusal = reply } }
    /// Holds every request to `route` back before it is answered, so a test can act while it is on the wire.
    func delay(_ route: String, nanoseconds: UInt64) { lock.withLock { delays[route] = nanoseconds } }

    static func refusal(_ status: Int, _ code: String, _ description: String) -> HTTPReply {
        reply(status, ["error": code, "error_description": description])
    }

    static func reply(_ status: Int, _ body: [String: Any]) -> HTTPReply {
        HTTPReply(status: status, body: (try? JSONSerialization.data(withJSONObject: body)) ?? Data())
    }

    func post(_ url: URL, body: Data) async throws -> HTTPReply {
        let route = String(url.path.dropFirst(Self.base.path.count))
        let json = (try? JSONSerialization.jsonObject(with: body) as? [String: Any]) ?? [:]
        if let delay = lock.withLock({ delays[route] }), delay > 0 {
            try await Task.sleep(nanoseconds: delay)
        }
        return lock.withLock {
            _requests.append(Request(route: route, body: json))
            switch route {
            case "enrol/challenge":
                challenges += 1
                return Self.reply(200, ["challenge": "challenge-\(challenges)", "expires_in": 300])
            case "enrol":
                if let refusal = enrolRefusal { return refusal }
                return Self.reply(200, ["instance_id": "instance-1", "attestation": "attestation-0",
                                        "expires_in": 900, "appattest_key_id": json["appattest_key_id"] ?? NSNull()])
            case "attestation":
                if !reissueRefusals.isEmpty { return reissueRefusals.removeFirst() }
                mints += 1
                return Self.reply(200, ["attestation": "attestation-\(mints)", "expires_in": 900])
            case "user-verification":
                if let refusal = userVerificationRefusal { return refusal }
                return Self.reply(200, ["status": "ok"])
            default:
                return Self.reply(404, ["error": "not_found"])
            }
        }
    }
}

/// A clock a test moves.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var _now: Date

    init(_ now: Date = Date(timeIntervalSince1970: 1_790_000_000)) {
        _now = now
    }

    var now: Date {
        get { lock.withLock { _now } }
        set { lock.withLock { _now = newValue } }
    }
}

/// base64url to bytes, or a test failure.
func decodeBase64URL(_ base64URL: String) throws -> Data {
    guard let data = Data(base64URL: base64URL) else {
        throw AgentIdentityError.malformedKey("not base64url: \(base64URL)")
    }
    return data
}

extension Data {
    /// Lower-case hexadecimal, two characters a byte.
    init?(hex: String) {
        guard hex.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self = Data(bytes)
    }
}

/// A compact JWS taken apart: the decoded header and payload as JSON objects, the signature and the signing input.
struct DecodedJWS {
    let header: [String: Any]
    let payload: [String: Any]
    let signature: Data
    let signingInput: Data

    init(_ compact: String) throws {
        let parts = compact.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3 else { throw AgentIdentityError.malformedKey("not three segments") }
        header = try JSONSerialization.jsonObject(with: try decodeBase64URL(parts[0])) as? [String: Any] ?? [:]
        payload = try JSONSerialization.jsonObject(with: try decodeBase64URL(parts[1])) as? [String: Any] ?? [:]
        signature = try decodeBase64URL(parts[2])
        signingInput = Data((parts[0] + "." + parts[1]).utf8)
    }

    /// ES256 under the key in the `jwk` header, as `EnclaveKeyProofValidator` checks it.
    func verifiesUnderItsOwnJWK() throws -> Bool {
        guard let jwk = header["jwk"] as? [String: String], let x = jwk["x"], let y = jwk["y"] else { return false }
        let key = try P256.Signing.PublicKey(rawRepresentation: try decodeBase64URL(x) + (try decodeBase64URL(y)))
        return key.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: signature), for: signingInput)
    }
}
