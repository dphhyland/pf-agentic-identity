import SwiftUI

/// A minimal app that drives AgentIdentityKit against an enrolment service you name, with the real App Attest,
/// Secure Enclave and PingOne implementations. It exists to be run on a physical iPhone (the README says what to
/// supply), and to capture App Attest vectors for docs/findings/U-0063.yaml.
@main
struct SampleApp: App {
    @StateObject private var model = SampleModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
        }
    }
}
