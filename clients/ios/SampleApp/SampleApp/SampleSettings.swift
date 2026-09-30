import Foundation

/// Where the sample sends its requests. Placeholders only: nothing here names a real tenant, and nothing here is a
/// secret, because the PingOne application is a public client and the service takes no credential.
struct SampleSettings: Codable, Equatable {
    /// The enrolment service; with X-A11's `/v1`, include the prefix.
    var baseURL = "https://enrolment.example.com"
    /// The service's `ENROLMENT_ISSUER`: the key proofs' `aud`.
    var audience = "https://enrolment.example.com"
    /// The service's `PINGONE_ISSUER`: `https://auth.pingone.<region>/<environment id>/as`.
    var issuer = "https://auth.pingone.com/00000000-0000-0000-0000-000000000000/as"
    /// The service's `PINGONE_CLIENT_ID`.
    var clientID = "00000000-0000-0000-0000-000000000000"
    /// A redirect URI registered on that application.
    var redirectURI = "com.example.agentidentity.sample:/callback"
    /// A sign-on policy the service's `PINGONE_ACR_AAL2` lists, or empty for the application's default.
    var acrValues = ""
    /// Minted into the attestation as `agent_build`.
    var agentBuild = "sample/0.1"

    private static let storageKey = "SampleSettings"

    static func load() -> SampleSettings {
        guard let data = UserDefaults.standard.data(forKey: storageKey),
              let settings = try? JSONDecoder().decode(SampleSettings.self, from: data) else {
            return SampleSettings()
        }
        return settings
    }

    func save() {
        if let data = try? JSONEncoder().encode(self) {
            UserDefaults.standard.set(data, forKey: Self.storageKey)
        }
    }
}
