// swift-tools-version: 5.9
// The device side of the enrolment protocol (docs/device/ios-client-contract.md). iOS 17 is the floor the
// sample app targets; macOS 14 is there so `swift test` runs on a Mac, where the unit tests use fakes for App
// Attest, the Secure Enclave and PingOne. No dependencies: CryptoKit, DeviceCheck, AuthenticationServices and
// Security are the platform's. MSAL is deliberately absent (docs/findings/U-0065.yaml).
import PackageDescription

let package = Package(
    name: "AgentIdentityKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "AgentIdentityKit", targets: ["AgentIdentityKit"]),
    ],
    targets: [
        .target(name: "AgentIdentityKit"),
        .testTarget(name: "AgentIdentityKitTests", dependencies: ["AgentIdentityKit"]),
    ]
)
