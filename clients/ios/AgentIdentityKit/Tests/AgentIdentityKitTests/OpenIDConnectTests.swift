import XCTest
@testable import AgentIdentityKit

/// The pure parts of the PingOne sign-in. The sheet itself runs only in an app.
final class OpenIDConnectTests: XCTestCase {

    let endpoint = URL(string: "https://auth.pingone.example/env-1/as/authorize")!
    let redirect = URL(string: "com.example.agentidentity.sample:/callback")!

    private func items(_ url: URL) -> [String: String] {
        Dictionary(uniqueKeysWithValues: (URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? [])
            .map { ($0.name, $0.value ?? "") })
    }

    /// `max_age=0`: the service measures the time-box from `auth_time`, which OpenID Connect Core 1.0 §3.1.2.1
    /// makes required in the ID token whenever `max_age` is sent.
    func testTheAuthenticationRequest() {
        let pkce = PKCE(verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        let url = AuthorizationRequest.url(authorizationEndpoint: endpoint, clientID: "client-1", redirectURI: redirect,
                                           nonce: "n-1", state: "s-1", pkce: pkce, acrValues: "Passkey_AAL2")
        XCTAssertEqual(items(url), [
            "response_type": "code", "client_id": "client-1", "redirect_uri": redirect.absoluteString,
            "scope": "openid", "state": "s-1", "nonce": "n-1", "code_challenge": pkce.challenge,
            "code_challenge_method": "S256", "max_age": "0", "acr_values": "Passkey_AAL2",
        ])
        XCTAssertNil(items(AuthorizationRequest.url(authorizationEndpoint: endpoint, clientID: "c", redirectURI: redirect,
                                                    nonce: "n", state: "s", pkce: pkce, acrValues: nil))["acr_values"])
    }

    /// `+`, `&` and `=` in a value are percent-encoded, so a server that form-decodes the query reads the value
    /// sent, and the redirect URI is encoded exactly as the token request encodes it.
    func testTheAuthenticationRequestEncodesEveryValueAsTheTokenRequestDoes() throws {
        let redirect = URL(string: "com.example.app+dev:/callback")!
        let url = AuthorizationRequest.url(authorizationEndpoint: endpoint, clientID: "client-1", redirectURI: redirect,
                                           nonce: "n-1", state: "s-1", pkce: PKCE(verifier: "v-1"),
                                           acrValues: "Passkey+AAL2 policy&x=y")
        let query = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false)?.percentEncodedQuery)
        XCTAssertFalse(query.contains("+"), query)
        XCTAssertTrue(query.contains("&acr_values=Passkey%2BAAL2%20policy%26x%3Dy"), query)
        XCTAssertTrue(query.contains("&redirect_uri=" + TokenRequest.formEncode(redirect.absoluteString) + "&"), query)
        XCTAssertEqual(items(url)["acr_values"], "Passkey+AAL2 policy&x=y")
        XCTAssertEqual(items(url)["redirect_uri"], redirect.absoluteString)
    }

    /// RFC 7636 Appendix B's example verifier and challenge (read at rfc-editor.org on 2026-09-27).
    func testPKCEIsS256() {
        XCTAssertEqual(PKCE(verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").challenge,
                       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        let generated = PKCE.generate()
        XCTAssertEqual(generated.verifier.count, 43)
        XCTAssertNotEqual(generated.verifier, PKCE.generate().verifier)
    }

    func testTheCallbackGivesTheCodeOnlyForTheStateSent() throws {
        XCTAssertEqual(try AuthorizationCallback.code(
            from: URL(string: "com.example.agentidentity.sample:/callback?code=abc&state=s-1")!, expectedState: "s-1"), "abc")
        XCTAssertThrowsError(try AuthorizationCallback.code(
            from: URL(string: "com.example.agentidentity.sample:/callback?code=abc&state=other")!, expectedState: "s-1"))
        XCTAssertThrowsError(try AuthorizationCallback.code(
            from: URL(string: "com.example.agentidentity.sample:/callback?state=s-1")!, expectedState: "s-1"))
        do {
            _ = try AuthorizationCallback.code(from: URL(string:
                "com.example.agentidentity.sample:/callback?error=access_denied&error_description=no&state=s-1")!,
                                               expectedState: "s-1")
            XCTFail("an error callback gave a code")
        } catch AgentIdentityError.authorization(let detail) {
            XCTAssertTrue(detail.hasPrefix("access_denied"))
        }
    }

    /// A public client: no secret, the verifier instead, every value form-encoded with RFC 3986's unreserved set.
    func testTheTokenRequest() {
        let body = String(decoding: TokenRequest.body(code: "a+b/c", redirectURI: redirect, clientID: "client-1",
                                                      pkce: PKCE(verifier: "v-1")), as: UTF8.self)
        XCTAssertEqual(body, "grant_type=authorization_code&code=a%2Bb%2Fc"
                             + "&redirect_uri=com.example.agentidentity.sample%3A%2Fcallback&client_id=client-1&code_verifier=v-1")
    }

    func testTheIDTokenClaimsAndTheClientsTwoChecks() throws {
        let token = FakeAuthenticator.unsignedJWT(["iss": "https://auth.pingone.example/env-1/as", "sub": "s",
                                                   "aud": ["client-1"], "nonce": "n-1", "auth_time": 1_790_000_000, "acr": "p"])
        let claims = try IDTokenClaims.parse(token)
        XCTAssertEqual(claims.audience, ["client-1"])
        XCTAssertEqual(claims.authTime, 1_790_000_000)
        XCTAssertNoThrow(try claims.check(nonce: "n-1"))
        XCTAssertThrowsError(try claims.check(nonce: "n-2"))
        XCTAssertThrowsError(try IDTokenClaims.parse(FakeAuthenticator.unsignedJWT(["nonce": "n-1"])).check(nonce: "n-1"))
        XCTAssertThrowsError(try IDTokenClaims.parse("a.b"))
    }

    func testTheDiscoveryDocumentIsRead() throws {
        let document = try JSONDecoder().decode(OpenIDConfiguration.self, from: Data("""
            {"issuer":"https://auth.pingone.example/env-1/as",
             "authorization_endpoint":"https://auth.pingone.example/env-1/as/authorize",
             "token_endpoint":"https://auth.pingone.example/env-1/as/token",
             "jwks_uri":"https://auth.pingone.example/env-1/as/jwks",
             "claims_parameter_supported":false}
            """.utf8))
        XCTAssertEqual(document.tokenEndpoint.absoluteString, "https://auth.pingone.example/env-1/as/token")
    }
}
