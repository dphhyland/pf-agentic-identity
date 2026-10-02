import AgentIdentityKit
import Foundation

/// The sample's state: the settings, the enrolment it keeps between launches, a log of what happened.
@MainActor
final class SampleModel: ObservableObject {

    @Published var settings = SampleSettings.load() {
        didSet { settings.save() }
    }
    @Published private(set) var enrolment: Enrolment?
    @Published private(set) var busy = false
    @Published private(set) var log: [String] = []
    @Published private(set) var capturedVectors: String?

    /// The instance key's keychain tag. One enrolment at a time, so one tag.
    private static let keyTag = "com.example.agentidentity.sample.instance-key"
    private static let enrolmentKey = "SampleEnrolment"

    private var agent: DeviceAgent?

    init() {
        if let data = UserDefaults.standard.data(forKey: Self.enrolmentKey) {
            enrolment = try? JSONDecoder().decode(Enrolment.self, from: data)
        }
    }

    func enrol() async {
        await run("enrol") {
            // A new enrolment takes a new instance key: its thumbprint is the attestation's cnf, which every
            // resource server sees, so a key shared between two instances would link them.
            let key = try SecureEnclaveInstanceKey.create(tag: Self.keyTag, gate: .userPresence)
            let agent = try self.makeAgent(key: key, state: .unenrolled)
            let enrolment = try await agent.enrol()
            self.keep(enrolment, agent: agent)
            return "enrolled as instance \(enrolment.instanceID)"
        }
    }

    func remint() async {
        await run("re-mint") {
            let enrolment = try await self.currentAgent().remint()
            self.keep(enrolment, agent: self.agent)
            return "re-minted; the attestation expires at \(enrolment.attestationExpiresAt.formatted(date: .omitted, time: .standard))"
        }
    }

    func refreshUserVerification() async {
        await run("refresh user verification") {
            try await self.currentAgent().refreshUserVerification()
            return "user verification refreshed"
        }
    }

    /// Drops the enrolment and deletes its key. The service keeps the instance until it is revoked there.
    func forget() async {
        await run("forget") {
            await self.agent?.forget()
            try SecureEnclaveInstanceKey.delete(tag: Self.keyTag)
            self.agent = nil
            self.enrolment = nil
            UserDefaults.standard.removeObject(forKey: Self.enrolmentKey)
            return "enrolment and instance key removed"
        }
    }

    func captureVectors() async {
        await run("capture App Attest vectors") {
            let json = try await VectorCapture.run(appAttest: AppAttestProvider())
            self.capturedVectors = json
            return "captured one attestation and three assertions; share the JSON"
        }
    }

    private func currentAgent() throws -> DeviceAgent {
        if let agent { return agent }
        guard let enrolment else { throw AgentIdentityError.notEnrolled }
        guard let key = try SecureEnclaveInstanceKey.load(tag: Self.keyTag) else {
            throw AgentIdentityError.secureEnclave("the instance key is gone: forget the enrolment and enrol again")
        }
        let agent = try makeAgent(key: key, state: .enrolled(enrolment))
        self.agent = agent
        return agent
    }

    private func makeAgent(key: InstanceKey, state: DeviceAgent.State) throws -> DeviceAgent {
        guard let base = URL(string: settings.baseURL), let issuer = URL(string: settings.issuer),
              let redirect = URL(string: settings.redirectURI) else {
            throw AgentIdentityError.authorization("the base URL, the issuer and the redirect URI must be URLs")
        }
        let authenticator = PingOneAuthenticator(configuration: .init(
            issuer: issuer, clientID: settings.clientID, redirectURI: redirect,
            acrValues: settings.acrValues.isEmpty ? nil : settings.acrValues))
        return DeviceAgent(client: EnrolmentClient(baseURL: base), audience: settings.audience, instanceKey: key,
                           appAttest: AppAttestProvider(), authenticator: authenticator,
                           device: .current(agentBuild: settings.agentBuild), state: state)
    }

    private func keep(_ enrolment: Enrolment, agent: DeviceAgent?) {
        self.enrolment = enrolment
        self.agent = agent
        if let data = try? JSONEncoder().encode(enrolment) {
            UserDefaults.standard.set(data, forKey: Self.enrolmentKey)
        }
    }

    private func run(_ action: String, _ work: @escaping () async throws -> String) async {
        busy = true
        defer { busy = false }
        do {
            record("\(action): \(try await work())")
        } catch let error as AgentIdentityError {
            record("\(action) failed: \(error.message)")
        } catch {
            record("\(action) failed: \(error.localizedDescription)")
        }
    }

    private func record(_ line: String) {
        log.insert("\(Date().formatted(date: .omitted, time: .standard))  \(line)", at: 0)
    }
}
