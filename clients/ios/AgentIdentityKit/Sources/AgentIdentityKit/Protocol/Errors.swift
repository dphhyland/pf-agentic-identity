import Foundation

/// The service's refusal codes: `EnrolmentException`'s constants. `error` is the contract; the description is
/// prose for a log, read in one place only (`ServerRefusal.isCounterRace`).
public enum ServerCode {
    public static let invalidRequest = "invalid_request"
    public static let invalidChallenge = "invalid_challenge"
    public static let invalidAttestation = "invalid_attestation"
    public static let userAuthenticationFailed = "user_authentication_failed"
    public static let insufficientAssurance = "insufficient_assurance"
    public static let invalidKeyProof = "invalid_key_proof"
    public static let unknownInstance = "unknown_instance"
    public static let instanceNotActive = "instance_not_active"
    public static let deviceNotCompliant = "device_not_compliant"
    public static let userVerificationRequired = "user_verification_required"
    public static let serverError = "server_error"
}

/// A refusal in the shape `EnrolmentHttpServer.route` writes: the status, `error` and `error_description`.
public struct ServerRefusal: Error, Equatable, Sendable {
    public let status: Int
    public let code: String
    public let description: String

    public init(status: Int, code: String, description: String) {
        self.status = status
        self.code = code
        self.description = description
    }

    /// The time-box firing: the one refusal the client recovers from by putting the owner back in front of
    /// the phone (`EnrolmentException.USER_VERIFICATION_REQUIRED`).
    public var isUserVerificationRequired: Bool { code == ServerCode.userVerificationRequired }

    /// A lost App Attest counter race. `EnrolmentService.verifyRenewalAssertion` answers it with
    /// `invalid_attestation`, the code every assertion failure shares, and one of two descriptions: "App Attest
    /// assertion counter did not advance: …" when the registry's compare-and-set refused, and "App Attest
    /// assertion failed (counter_not_advanced): …" when the verifier saw a counter at or below the stored one
    /// (`AppAttestException.COUNTER_NOT_ADVANCED`, a reason libs/app-attest calls contract). Those two
    /// fragments are the only signal until X-A08 gives the race a code of its own.
    public var isCounterRace: Bool {
        code == ServerCode.invalidAttestation
            && (description.contains("counter did not advance") || description.contains("(counter_not_advanced)"))
    }

    /// A challenge the service no longer knows: expired, already spent, or issued by another node.
    public var isInvalidChallenge: Bool { code == ServerCode.invalidChallenge }
}

/// Everything the kit can fail with. `refused` is the server's answer; the rest is the client's own.
public enum AgentIdentityError: Error, Equatable {
    /// The service refused, with a code from `ServerCode`.
    case refused(ServerRefusal)
    /// A reply that is not a refusal and not the route's answer: a non-200 whose body is not the error shape, or a
    /// 200 that does not decode as the route's reply. A non-200 in the error shape is `refused`, whatever its
    /// status.
    case unexpectedResponse(status: Int, body: String)
    /// The request never got an HTTP answer.
    case transport(String)
    /// A re-mint or a refresh with nothing enrolled.
    case notEnrolled
    /// An enrolment while one is held. A new enrolment is a new `DeviceAgent` over a new instance key, after
    /// `forget()` on this one.
    case alreadyEnrolled
    /// An enrolment after `forget()`. This agent's key was enrolled, or was about to be, and a key reused across
    /// instances would link them, so a new enrolment is a new `DeviceAgent` over a new key.
    case forgotten
    /// `DCAppAttestService.isSupported` is false: the server requires the attestation, so there is no
    /// enrolment to attempt.
    case appAttestUnsupported
    /// `generateKey` returned something that is neither standard base64 nor base64url of 32 bytes.
    case keyIdentifierNotDecodable(String)
    /// A public key or a signature in a shape the kit does not read.
    case malformedKey(String)
    /// The Secure Enclave or the keychain refused: no key, a key that could not be made, a signature not given.
    case secureEnclave(String)
    /// The ID token PingOne returned is not usable: no compact JWS, the wrong nonce, no `auth_time`.
    case idToken(String)
    /// The authorization response or the token response was not what the flow asked for.
    case authorization(String)
    /// A seam whose real implementation is a later plan item (`UnavailableDeviceTokenProvider`).
    case notImplemented(String)

    /// One line for a log or a screen.
    public var message: String {
        switch self {
        case .refused(let refusal):
            return "\(refusal.status) \(refusal.code): \(refusal.description)"
        case .unexpectedResponse(let status, let body):
            return "unexpected response \(status): \(body)"
        case .transport(let detail):
            return "transport: \(detail)"
        case .notEnrolled:
            return "not enrolled"
        case .alreadyEnrolled:
            return "already enrolled: forget this agent, then enrol a new one with a new key"
        case .forgotten:
            return "this agent was forgotten: enrol a new one with a new key"
        case .appAttestUnsupported:
            return "App Attest is not supported on this device"
        case .keyIdentifierNotDecodable(let detail), .malformedKey(let detail), .secureEnclave(let detail),
             .idToken(let detail), .authorization(let detail), .notImplemented(let detail):
            return detail
        }
    }
}
