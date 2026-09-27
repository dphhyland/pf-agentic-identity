#if canImport(AuthenticationServices)
import AuthenticationServices
import Foundation
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

/// PingOne through `ASWebAuthenticationSession`: discovery, the authorization code flow with PKCE, the token
/// request. Cannot run under test: it opens a browser sheet. Its pure parts are in `OpenIDConnect.swift` and are
/// tested there; what this adds is the sheet, the two HTTP calls and the presentation anchor.
public final class PingOneAuthenticator: NSObject, Authenticator, ASWebAuthenticationPresentationContextProviding,
                                         @unchecked Sendable {

    public struct Configuration: Sendable {
        /// `https://auth.pingone.<region>/<environment id>/as`: the service's `PINGONE_ISSUER`.
        public var issuer: URL
        /// The application's id: the service's `PINGONE_CLIENT_ID`. A public native app with PKCE.
        public var clientID: String
        /// A custom-scheme URI registered on the application at PingOne. "The browser detects the redirect,
        /// dismisses itself, and passes the complete URL to your app by calling the closure you specified during
        /// initialization" (Apple, "Authenticating a user through a web service", read 2026-09-27); that page names
        /// no scheme for the app to declare, and the sample app declares none.
        public var redirectURI: URL
        /// The sign-on policy the service's `PINGONE_ACR_AAL2` lists, or nil for PingOne's default policy.
        public var acrValues: String?
        /// True keeps the browser's cookies out of the sheet. With `max_age=0` the owner authenticates either
        /// way; the difference is whether PingOne's own session cookie is offered.
        public var ephemeralSession: Bool

        public init(issuer: URL, clientID: String, redirectURI: URL, acrValues: String? = nil,
                    ephemeralSession: Bool = false) {
            self.issuer = issuer
            self.clientID = clientID
            self.redirectURI = redirectURI
            self.acrValues = acrValues
            self.ephemeralSession = ephemeralSession
        }
    }

    private let configuration: Configuration
    private let session: URLSession
    /// Held for as long as the sheet is up: nothing else keeps the session alive once `start()` returns.
    @MainActor private var webSession: ASWebAuthenticationSession?

    public init(configuration: Configuration, session: URLSession = .shared) {
        self.configuration = configuration
        self.session = session
    }

    public func authenticate(nonce: String) async throws -> String {
        let discovery = try await discover()
        let pkce = PKCE.generate()
        let state = Commitments.randomNonce()
        let url = AuthorizationRequest.url(
            authorizationEndpoint: discovery.authorizationEndpoint, clientID: configuration.clientID,
            redirectURI: configuration.redirectURI, nonce: nonce, state: state, pkce: pkce,
            acrValues: configuration.acrValues)
        let callback = try await present(url)
        let code = try AuthorizationCallback.code(from: callback, expectedState: state)
        return try await exchange(code: code, at: discovery.tokenEndpoint, pkce: pkce)
    }

    private func discover() async throws -> OpenIDConfiguration {
        let url = configuration.issuer.appending(path: ".well-known/openid-configuration")
        let (data, response) = try await session.data(from: url)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw AgentIdentityError.authorization("discovery at \(url.absoluteString) did not answer 200")
        }
        let discovery: OpenIDConfiguration
        do {
            discovery = try JSONDecoder().decode(OpenIDConfiguration.self, from: data)
        } catch {
            throw AgentIdentityError.authorization("the discovery document is not readable: \(error)")
        }
        // The service compares the token's iss with PINGONE_ISSUER exactly, so a document naming another issuer
        // would only produce tokens the service refuses.
        guard discovery.issuer == configuration.issuer.absoluteString else {
            throw AgentIdentityError.authorization(
                "the discovery document names issuer \(discovery.issuer), not \(configuration.issuer.absoluteString)")
        }
        return discovery
    }

    @MainActor
    private func present(_ url: URL) async throws -> URL {
        defer { webSession = nil }
        return try await withCheckedThrowingContinuation { continuation in
            let sheet = ASWebAuthenticationSession(url: url, callbackURLScheme: configuration.redirectURI.scheme) {
                callback, error in
                if let callback {
                    continuation.resume(returning: callback)
                } else if let error = error as? ASWebAuthenticationSessionError, error.code == .canceledLogin {
                    continuation.resume(throwing: AgentIdentityError.authorization("the owner cancelled the sign-in"))
                } else {
                    continuation.resume(throwing: AgentIdentityError.authorization(
                        error?.localizedDescription ?? "the sign-in returned no callback"))
                }
            }
            sheet.presentationContextProvider = self
            sheet.prefersEphemeralWebBrowserSession = configuration.ephemeralSession
            webSession = sheet
            if !sheet.start() {
                continuation.resume(throwing: AgentIdentityError.authorization("the sign-in sheet could not start"))
            }
        }
    }

    private func exchange(code: String, at tokenEndpoint: URL, pkce: PKCE) async throws -> String {
        var request = URLRequest(url: tokenEndpoint)
        request.httpMethod = "POST"
        request.setValue(TokenRequest.contentType, forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = TokenRequest.body(code: code, redirectURI: configuration.redirectURI,
                                             clientID: configuration.clientID, pkce: pkce)
        let (data, response) = try await session.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        let decoded = try? JSONDecoder().decode(TokenResponse.self, from: data)
        guard status == 200, let idToken = decoded?.idToken else {
            throw AgentIdentityError.authorization(
                "the token endpoint answered \(status): \(decoded?.error ?? "no error code") "
                    + (decoded?.errorDescription ?? ""))
        }
        return idToken
    }

    @MainActor
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        #if canImport(UIKit)
        let windows = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.flatMap(\.windows)
        return windows.first { $0.isKeyWindow } ?? windows.first ?? UIWindow()
        #else
        return NSApplication.shared.keyWindow ?? NSWindow()
        #endif
    }
}
#endif
