import Foundation

/// The `DeviceTokenProvider` that ships at X-I01a: it throws.
///
/// The programme's device-correlation design wants an Entra access token carrying `deviceid`, obtained with
/// MSAL through the Microsoft Authenticator broker on an Intune-managed iPhone. Two things stand in front of a
/// real implementation: David's spike on such a phone, which decides whether Entra emits the claim at all
/// (docs/findings/U-0042.yaml, U-0064.yaml), and plan item X-A17, which gives the enrolment request a field for
/// the token; at ab74038 there is none. MSAL is not a dependency of this package (U-0065).
public struct UnavailableDeviceTokenProvider: DeviceTokenProvider {

    public init() {}

    public func deviceToken() async throws -> String {
        throw AgentIdentityError.notImplemented(
            "the Entra device token needs MSAL and the Microsoft Authenticator broker (X-I01b, after the deviceid "
                + "spike), and no request to the enrolment service carries one yet (X-A17)")
    }
}
