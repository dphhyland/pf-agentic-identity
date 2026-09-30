import Foundation

// The request and reply shapes, named as EnrolmentHttpServer reads and writes them. Every key is spelled here
// rather than derived, because the wire names are the contract: `appattest_object` has no underscore where
// `app_attest_assertion` has one, and the server reads each with `body.get(name)`.

/// `POST /enrol/challenge`: `{"challenge": "<43 characters>", "expires_in": 300}`.
public struct ChallengeResponse: Decodable, Equatable, Sendable {
    public let challenge: String
    public let expiresIn: Int64

    enum CodingKeys: String, CodingKey {
        case challenge
        case expiresIn = "expires_in"
    }
}

/// `POST /enrol`, the iOS shape: App Attest over one instance key, no federation key.
public struct EnrolRequest: Encodable, Equatable, Sendable {
    /// base64url of the CBOR attestation object from `attestKey`.
    public var appattestObject: String
    /// base64url of the 32 raw bytes of Apple's key identifier.
    public var appattestKeyId: String
    public var enclavePublicJwk: PublicJWK
    /// The challenge from `POST /enrol/challenge`, verbatim.
    public var challenge: String
    /// The PingOne ID token, compact JWS, verbatim.
    public var userAuthentication: String
    /// `ios`, or `macos` on a Mac.
    public var platform: String
    public var model: String?
    public var osVersion: String?
    public var agentBuild: String?

    public init(appattestObject: String, appattestKeyId: String, enclavePublicJwk: PublicJWK, challenge: String,
                userAuthentication: String, platform: String, model: String?, osVersion: String?,
                agentBuild: String?) {
        self.appattestObject = appattestObject
        self.appattestKeyId = appattestKeyId
        self.enclavePublicJwk = enclavePublicJwk
        self.challenge = challenge
        self.userAuthentication = userAuthentication
        self.platform = platform
        self.model = model
        self.osVersion = osVersion
        self.agentBuild = agentBuild
    }

    enum CodingKeys: String, CodingKey {
        case appattestObject = "appattest_object"
        case appattestKeyId = "appattest_key_id"
        case enclavePublicJwk = "enclave_public_jwk"
        case challenge
        case userAuthentication = "user_authentication"
        case platform
        case model
        case osVersion = "os_version"
        case agentBuild = "agent_build"
    }
}

/// `POST /enrol`'s reply.
public struct EnrolResponse: Decodable, Equatable, Sendable {
    public let instanceId: String
    public let attestation: String
    public let expiresIn: Int64
    /// The verified key identifier as the server encodes it: the bytes the client sent.
    public let appattestKeyId: String?

    enum CodingKeys: String, CodingKey {
        case instanceId = "instance_id"
        case attestation
        case expiresIn = "expires_in"
        case appattestKeyId = "appattest_key_id"
    }
}

/// `POST /attestation`: the re-mint.
public struct ReissueRequest: Encodable, Equatable, Sendable {
    public var instanceId: String
    /// The compact key proof (`KeyProof`).
    public var keyProof: String
    /// base64url of the CBOR assertion over `Commitments.assertionClientDataHash(keyProof:)`.
    public var appAttestAssertion: String?

    public init(instanceId: String, keyProof: String, appAttestAssertion: String?) {
        self.instanceId = instanceId
        self.keyProof = keyProof
        self.appAttestAssertion = appAttestAssertion
    }

    enum CodingKeys: String, CodingKey {
        case instanceId = "instance_id"
        case keyProof = "key_proof"
        case appAttestAssertion = "app_attest_assertion"
    }
}

/// `POST /attestation`'s reply.
public struct ReissueResponse: Decodable, Equatable, Sendable {
    public let attestation: String
    public let expiresIn: Int64

    enum CodingKeys: String, CodingKey {
        case attestation
        case expiresIn = "expires_in"
    }
}

/// `POST /user-verification`: a fresh ID token for the instance's owner.
public struct UserVerificationRequest: Encodable, Equatable, Sendable {
    public var instanceId: String
    public var userAuthentication: String

    public init(instanceId: String, userAuthentication: String) {
        self.instanceId = instanceId
        self.userAuthentication = userAuthentication
    }

    enum CodingKeys: String, CodingKey {
        case instanceId = "instance_id"
        case userAuthentication = "user_authentication"
    }
}

/// `{"status": "ok"}`.
public struct StatusResponse: Decodable, Equatable, Sendable {
    public let status: String
}

/// The refusal body `EnrolmentHttpServer.error` writes.
public struct ErrorResponse: Decodable, Equatable, Sendable {
    public let error: String
    public let errorDescription: String?

    enum CodingKeys: String, CodingKey {
        case error
        case errorDescription = "error_description"
    }
}

/// How the kit encodes a request body: keys sorted so a body is the same bytes every time, and `/` left
/// alone (the default escapes it as `\/`, which the server reads but nobody wants to diff).
enum WireJSON {
    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    static func decoder() -> JSONDecoder { JSONDecoder() }
}
