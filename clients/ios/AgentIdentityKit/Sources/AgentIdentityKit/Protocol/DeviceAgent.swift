import Foundation

/// What the app keeps between launches: the instance and the App Attest key that attested it. Apple's key
/// identifier is here because every re-mint asserts with it and there is no way to recover it. Nothing here is a
/// secret: the attestation is presented to PingFederate on every token request anyway, and the instance id is
/// pseudonymous by construction. The instance key itself is the Secure Enclave's and is kept by the app
/// through `SecureEnclaveInstanceKey`.
public struct Enrolment: Codable, Equatable, Sendable {
    public var instanceID: String
    public var appAttestKeyID: AppAttestKeyID
    public var attestation: String
    public var attestationExpiresAt: Date

    public init(instanceID: String, appAttestKeyID: AppAttestKeyID, attestation: String, attestationExpiresAt: Date) {
        self.instanceID = instanceID
        self.appAttestKeyID = appAttestKeyID
        self.attestation = attestation
        self.attestationExpiresAt = attestationExpiresAt
    }
}

/// The four descriptive fields of `POST /enrol`. Recorded on the device row and, for `agent_build`, minted into
/// the attestation; none of them is verified by the server, and on a Mac `platform` is compared with the OS
/// Apple wrote into the credential certificate.
public struct DeviceDescription: Equatable, Sendable {
    public var platform: String
    public var model: String?
    public var osVersion: String?
    public var agentBuild: String?

    public init(platform: String, model: String?, osVersion: String?, agentBuild: String?) {
        self.platform = platform
        self.model = model
        self.osVersion = osVersion
        self.agentBuild = agentBuild
    }

    /// This device: `ios` or `macos`, the hardware model from `uname` (`iPhone16,2` on a phone, the
    /// architecture on a simulator) and the OS version.
    public static func current(agentBuild: String?) -> DeviceDescription {
        #if os(iOS)
        let platform = "ios"
        #elseif os(macOS)
        let platform = "macos"
        #else
        let platform = "unknown"
        #endif
        var system = utsname()
        uname(&system)
        let model = withUnsafeBytes(of: &system.machine) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
        let version = ProcessInfo.processInfo.operatingSystemVersion
        let osVersion = "\(version.majorVersion).\(version.minorVersion)"
            + (version.patchVersion > 0 ? ".\(version.patchVersion)" : "")
        return DeviceDescription(platform: platform, model: model, osVersion: osVersion, agentBuild: agentBuild)
    }
}

/// What a re-mint does after a refusal: the table in the contract's "Errors and what the client does". Each
/// recovery happens at most once per re-mint and none of them is a resend. By the time the service refuses, the
/// request's challenge and its proof's `jti` are spent, so every retry is built new: a new challenge, a new proof
/// and a new assertion, whose App Attest counter is higher.
public struct RemintRecovery: Equatable, Sendable {

    public enum Step: Equatable, Sendable {
        /// `user_verification_required`: sign the owner in again, refresh the verification, then re-mint.
        case refreshUserVerificationThenRetry
        /// A lost counter race, or a challenge the service no longer knows: re-mint with new values.
        case retry
        /// Anything else, or a recovery already spent: the refusal goes to the app.
        case fail
    }

    public private(set) var refreshedUserVerification = false
    public private(set) var retriedCounterRace = false
    public private(set) var retriedChallenge = false

    public init() {}

    public mutating func step(after refusal: ServerRefusal) -> Step {
        if refusal.isUserVerificationRequired && !refreshedUserVerification {
            refreshedUserVerification = true
            return .refreshUserVerificationThenRetry
        }
        if refusal.isCounterRace && !retriedCounterRace {
            retriedCounterRace = true
            return .retry
        }
        if refusal.isInvalidChallenge && !retriedChallenge {
            retriedChallenge = true
            return .retry
        }
        return .fail
    }
}

/// The device side of the protocol as one state machine: enrol, re-mint, refresh user verification. Pure: it
/// speaks to the platform through `InstanceKey`, `AttestationProvider` and `Authenticator`, and to the service
/// through `EnrolmentClient`, so every path runs under test with fakes. The order of each ceremony and every
/// retry is the contract's (docs/device/ios-client-contract.md).
///
/// One agent holds one instance key and enrols it once. `forget()` ends the agent, and a new enrolment is a new
/// agent over a new key: the key's thumbprint is the attestation's `cnf`, which every resource server sees, so
/// reusing a key across instances would link them.
///
/// Concurrent calls share one ceremony. Two re-mints racing each other would race the App Attest counter too,
/// and the loser would be refused, so a call that arrives while a re-mint (or an enrolment) is under way waits
/// for that one's result instead of starting another.
public actor DeviceAgent {

    public enum State: Equatable, Sendable {
        case unenrolled
        case enrolled(Enrolment)
    }

    public private(set) var state: State

    private let client: EnrolmentClient
    private let audience: String
    private let instanceKey: InstanceKey
    private let appAttest: AttestationProvider
    private let authenticator: Authenticator
    private let device: DeviceDescription
    private let remintLeeway: TimeInterval
    private let clock: @Sendable () -> Date
    private var enrolling: Task<Enrolment, Error>?
    private var reminting: Task<Enrolment, Error>?
    private var forgotten = false

    /// - Parameters:
    ///   - audience: the service's `ENROLMENT_ISSUER`, which every key proof names as `aud`. Not the base URL
    ///     unless the deployment made them the same.
    ///   - state: an `Enrolment` the app kept, or `.unenrolled`.
    ///   - remintLeeway: how long before an attestation's expiry `currentAttestation()` re-mints.
    ///   - clock: the time source; the tests move it.
    public init(client: EnrolmentClient, audience: String, instanceKey: InstanceKey, appAttest: AttestationProvider,
                authenticator: Authenticator, device: DeviceDescription, state: State = .unenrolled,
                remintLeeway: TimeInterval = 60, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.client = client
        self.audience = audience
        self.instanceKey = instanceKey
        self.appAttest = appAttest
        self.authenticator = authenticator
        self.device = device
        self.state = state
        self.remintLeeway = remintLeeway
        self.clock = clock
    }

    /// The ceremony: a challenge; the owner's sign-in with the nonce derived from it; a fresh App Attest key,
    /// attested over the commitment to the instance key and the challenge; `POST /enrol`.
    ///
    /// The sign-in comes before the attestation so that a slow human does not leave a finished attestation
    /// waiting on the 300 s challenge; the attestation itself is a network round trip to Apple and no prompt.
    /// Nothing is retried here: a refusal leaves the agent unenrolled, and calling `enrol()` again starts over
    /// with a new challenge, a new sign-in and a new App Attest key, because the old key committed to the old
    /// challenge and Apple says to discard a key whose attestation the server did not verify. After `forget()`
    /// it throws `forgotten`.
    public func enrol() async throws -> Enrolment {
        guard !forgotten else { throw AgentIdentityError.forgotten }
        if let enrolling { return try await enrolling.value }
        guard case .unenrolled = state else { throw AgentIdentityError.alreadyEnrolled }
        let task = Task { try await self.runEnrolment() }
        enrolling = task
        defer { enrolling = nil }
        return try await task.value
    }

    /// The attestation to present, re-minted first when it is within `remintLeeway` of its expiry.
    public func currentAttestation() async throws -> String {
        guard case .enrolled(let enrolment) = state else { throw AgentIdentityError.notEnrolled }
        if enrolment.attestationExpiresAt.timeIntervalSince(clock()) > remintLeeway {
            return enrolment.attestation
        }
        return try await remint().attestation
    }

    /// The hot path, `POST /attestation`: a fresh challenge, a key proof naming it, an App Attest assertion over
    /// the proof. A refusal is handled as `RemintRecovery` says; what it does not recover is thrown.
    public func remint() async throws -> Enrolment {
        if let reminting { return try await reminting.value }
        guard case .enrolled = state else { throw AgentIdentityError.notEnrolled }
        let task = Task { try await self.runRemint() }
        reminting = task
        defer { reminting = nil }
        return try await task.value
    }

    /// `POST /user-verification`: a fresh sign-in of the owner, bound to a random nonce the kit checks itself
    /// (the server checks none here), sent as the instance's new verification. The server records the token's
    /// `auth_time`, so only a fresh authentication moves the time-box.
    public func refreshUserVerification() async throws {
        guard case .enrolled(let enrolment) = state else { throw AgentIdentityError.notEnrolled }
        try await refreshUserVerification(instanceID: enrolment.instanceID)
    }

    /// Ends the agent: after `unknown_instance` or `instance_not_active`, or when the app decides to enrol again.
    /// The enrolment is dropped and `enrol()` throws `forgotten` from then on, so this agent never enrols its key
    /// twice. A new enrolment is a new `DeviceAgent` over a new key; the Secure Enclave key is the app's to
    /// delete. An enrolment or a re-mint already under way is returned to its caller and not kept.
    public func forget() {
        forgotten = true
        state = .unenrolled
    }

    private func runEnrolment() async throws -> Enrolment {
        guard appAttest.isSupported else { throw AgentIdentityError.appAttestUnsupported }
        let challenge = try await client.issueChallenge().challenge
        let jwk = instanceKey.publicJWK
        let idToken = try await signIn(
            nonce: Commitments.enrolmentNonce(challenge: challenge, instanceThumbprint: jwk.thumbprint))
        let keyID = try await appAttest.generateKey()
        let object = try await appAttest.attest(keyID, clientDataHash: Commitments.attestationClientDataHash(
            instanceThumbprint: jwk.thumbprint, challenge: challenge))
        let response = try await client.enrol(EnrolRequest(
            appattestObject: object.base64URL, appattestKeyId: keyID.wire, enclavePublicJwk: jwk,
            challenge: challenge, userAuthentication: idToken, platform: device.platform, model: device.model,
            osVersion: device.osVersion, agentBuild: device.agentBuild))
        let enrolment = Enrolment(instanceID: response.instanceId, appAttestKeyID: keyID,
                                  attestation: response.attestation,
                                  attestationExpiresAt: clock().addingTimeInterval(TimeInterval(response.expiresIn)))
        // A forget() that arrived while the enrolment was out stands: the enrolment is returned, not kept.
        if !forgotten {
            state = .enrolled(enrolment)
        }
        return enrolment
    }

    private func runRemint() async throws -> Enrolment {
        guard case .enrolled(var enrolment) = state else { throw AgentIdentityError.notEnrolled }
        var recovery = RemintRecovery()
        while true {
            let request = try await reissueRequest(for: enrolment)
            do {
                let response = try await client.reissue(request)
                enrolment.attestation = response.attestation
                enrolment.attestationExpiresAt = clock().addingTimeInterval(TimeInterval(response.expiresIn))
                // A forget() that arrived while the request was out stands: the attestation is returned, not kept.
                if case .enrolled(let current) = state, current.instanceID == enrolment.instanceID {
                    state = .enrolled(enrolment)
                }
                return enrolment
            } catch AgentIdentityError.refused(let refusal) {
                switch recovery.step(after: refusal) {
                case .refreshUserVerificationThenRetry:
                    try await refreshUserVerification(instanceID: enrolment.instanceID)
                case .retry:
                    continue
                case .fail:
                    throw AgentIdentityError.refused(refusal)
                }
            }
        }
    }

    private func refreshUserVerification(instanceID: String) async throws {
        let idToken = try await signIn(nonce: Commitments.randomNonce())
        try await client.refreshUserVerification(
            UserVerificationRequest(instanceId: instanceID, userAuthentication: idToken))
    }

    /// The owner's sign-in, and the two checks the kit makes before the token goes anywhere.
    private func signIn(nonce: String) async throws -> String {
        let idToken = try await authenticator.authenticate(nonce: nonce)
        try IDTokenClaims.parse(idToken).check(nonce: nonce)
        return idToken
    }

    private func reissueRequest(for enrolment: Enrolment) async throws -> ReissueRequest {
        let challenge = try await client.issueChallenge().challenge
        let proof = try await KeyProof.make(key: instanceKey, audience: audience, challenge: challenge, issuedAt: clock())
        let assertion = try await appAttest.generateAssertion(
            enrolment.appAttestKeyID, clientDataHash: Commitments.assertionClientDataHash(keyProof: proof.compact))
        return ReissueRequest(instanceId: enrolment.instanceID, keyProof: proof.compact,
                              appAttestAssertion: assertion.base64URL)
    }
}
