import AgentIdentityKit
import SwiftUI

struct ContentView: View {
    @ObservedObject var model: SampleModel

    var body: some View {
        NavigationStack {
            Form {
                Section("Enrolment service") {
                    field("Base URL", text: $model.settings.baseURL)
                    field("Audience (ENROLMENT_ISSUER)", text: $model.settings.audience)
                    field("Agent build", text: $model.settings.agentBuild)
                }
                Section("PingOne") {
                    field("Issuer", text: $model.settings.issuer)
                    field("Client id", text: $model.settings.clientID)
                    field("Redirect URI", text: $model.settings.redirectURI)
                    field("acr_values (optional)", text: $model.settings.acrValues)
                }
                Section("Instance") {
                    if let enrolment = model.enrolment {
                        LabeledContent("Instance", value: enrolment.instanceID)
                        LabeledContent("App Attest key", value: enrolment.appAttestKeyID.wire)
                        LabeledContent("Attestation expires",
                                       value: enrolment.attestationExpiresAt.formatted(date: .omitted, time: .standard))
                        Button("Re-mint") { Task { await model.remint() } }
                        Button("Refresh user verification") { Task { await model.refreshUserVerification() } }
                        Button("Forget", role: .destructive) { Task { await model.forget() } }
                    } else {
                        Text("Not enrolled")
                        Button("Enrol") { Task { await model.enrol() } }
                    }
                }
                .disabled(model.busy)
                Section("App Attest vectors (U-0063)") {
                    Button("Capture App Attest vectors") { Task { await model.captureVectors() } }
                        .disabled(model.busy)
                    if let json = model.capturedVectors {
                        ShareLink("Share the captured JSON", item: json)
                    }
                }
                Section("Log") {
                    ForEach(Array(model.log.enumerated()), id: \.offset) { _, line in
                        Text(line).font(.caption.monospaced())
                    }
                }
            }
            .navigationTitle("Agent identity")
        }
    }

    /// A labelled field: the placeholder alone disappears once there is a value, and two URLs look alike.
    private func field(_ title: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            TextField(title, text: text)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.URL)
        }
    }
}
