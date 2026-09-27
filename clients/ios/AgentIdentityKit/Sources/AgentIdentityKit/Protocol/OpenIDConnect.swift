import CryptoKit
import Foundation

// The pure parts of the PingOne sign-in: the discovery document, PKCE, the authorization request, the callback,
// the token request and the ID token's claims. `PingOneAuthenticator` drives them through
// `ASWebAuthenticationSession`; the tests drive them directly.

/// What the kit reads from `<issuer>/.well-known/openid-configuration`.
public struct OpenIDConfiguration: Decodable, Equatable, Sendable {
    public let issuer: String
    public let authorizationEndpoint: URL
    public let tokenEndpoint: URL
    public let jwksUri: URL?

    enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case jwksUri = "jwks_uri"
    }
}

/// RFC 7636 with `S256`: the environment advertises `plain` and `S256`, and the client is registered
/// `S256_REQUIRED` (the service README).
public struct PKCE: Equatable, Sendable {
    public let verifier: String
    public let challenge: String

    /// `challenge = base64url(SHA-256(ASCII(verifier)))`, RFC 7636 §4.2.
    public init(verifier: String) {
        self.verifier = verifier
        self.challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64URL
    }

    /// 32 random bytes as base64url: 43 characters of the unreserved alphabet, inside §4.1's 43 to 128.
    public static func generate() -> PKCE {
        PKCE(verifier: Commitments.randomNonce())
    }
}

/// The authentication request (OpenID Connect Core 1.0 §3.1.2.1) as the kit sends it.
public enum AuthorizationRequest {
    /// `response_type=code`, `scope=openid`, PKCE, a `state`, the `nonce`, and `max_age=0`, which makes
    /// `auth_time` REQUIRED in the ID token and is "equivalent to prompt=login" (§3.1.2.1): the server measures
    /// the time-box from `auth_time`, so a stale session is no use. `acr_values` names the sign-on policy the
    /// service's `PINGONE_ACR_AAL2` lists, when the app knows it.
    public static func url(authorizationEndpoint: URL, clientID: String, redirectURI: URL, nonce: String,
                           state: String, pkce: PKCE, acrValues: String?) -> URL {
        var components = URLComponents(url: authorizationEndpoint, resolvingAgainstBaseURL: false)!
        var items = (components.queryItems ?? []) + [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "redirect_uri", value: redirectURI.absoluteString),
            URLQueryItem(name: "scope", value: "openid"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "code_challenge", value: pkce.challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "max_age", value: "0"),
        ]
        if let acrValues, !acrValues.isEmpty {
            items.append(URLQueryItem(name: "acr_values", value: acrValues))
        }
        components.queryItems = items
        return components.url!
    }
}

/// The redirect back into the app.
public enum AuthorizationCallback {
    /// The `code`, once `state` is the one sent; an `error` parameter is thrown with its description.
    public static func code(from callback: URL, expectedState: String) throws -> String {
        let items = URLComponents(url: callback, resolvingAgainstBaseURL: false)?.queryItems ?? []
        func value(_ name: String) -> String? { items.first { $0.name == name }?.value }
        if let error = value("error") {
            throw AgentIdentityError.authorization("\(error): \(value("error_description") ?? "no description")")
        }
        guard value("state") == expectedState else {
            throw AgentIdentityError.authorization("the callback's state is not the one sent")
        }
        guard let code = value("code"), !code.isEmpty else {
            throw AgentIdentityError.authorization("the callback carries no code")
        }
        return code
    }
}

/// The token request of a public client: no secret, the PKCE verifier instead (RFC 7636 §4.5).
public enum TokenRequest {
    public static let contentType = "application/x-www-form-urlencoded"

    public static func body(code: String, redirectURI: URL, clientID: String, pkce: PKCE) -> Data {
        let fields = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirectURI.absoluteString),
            ("client_id", clientID),
            ("code_verifier", pkce.verifier),
        ]
        return Data(fields.map { "\(formEncode($0.0))=\(formEncode($0.1))" }.joined(separator: "&").utf8)
    }

    /// Percent-encoding with RFC 3986's unreserved set only, so `:`, `/` and `+` in a redirect URI or a code
    /// survive the form decoding on the other side.
    static func formEncode(_ value: String) -> String {
        var allowed = CharacterSet()
        allowed.insert(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }
}

/// What the kit reads from the token endpoint's reply.
public struct TokenResponse: Decodable, Equatable, Sendable {
    public let idToken: String?
    public let error: String?
    public let errorDescription: String?

    enum CodingKeys: String, CodingKey {
        case idToken = "id_token"
        case error
        case errorDescription = "error_description"
    }
}

/// The ID token's claims, read without verifying the signature: the enrolment service is the verifier of
/// record (`PingOneIdTokenVerifier`, offline against the JWKS). The kit reads them for the two things a client
/// must or should check before spending a sign-in: the nonce it sent came back (OpenID Connect Core 1.0
/// §3.1.3.7), and `auth_time` is there, since the server refuses a token without it.
public struct IDTokenClaims: Equatable, Sendable {
    public let issuer: String?
    public let subject: String?
    public let audience: [String]
    public let nonce: String?
    public let authTime: Int?
    public let acr: String?

    public static func parse(_ compact: String) throws -> IDTokenClaims {
        let segments = compact.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3, let payload = Data(base64URL: String(segments[1])) else {
            throw AgentIdentityError.idToken("the ID token is not a compact JWS")
        }
        guard let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
            throw AgentIdentityError.idToken("the ID token's payload is not a JSON object")
        }
        let audience: [String]
        if let one = object["aud"] as? String {
            audience = [one]
        } else {
            audience = object["aud"] as? [String] ?? []
        }
        return IDTokenClaims(issuer: object["iss"] as? String, subject: object["sub"] as? String, audience: audience,
                             nonce: object["nonce"] as? String, authTime: (object["auth_time"] as? NSNumber)?.intValue,
                             acr: object["acr"] as? String)
    }

    /// The two client-side checks. A token that fails them is not sent to the service.
    public func check(nonce expected: String) throws {
        guard let nonce else {
            throw AgentIdentityError.idToken("the ID token carries no nonce; the request sent one")
        }
        guard nonce == expected else {
            throw AgentIdentityError.idToken("the ID token's nonce is not the one sent")
        }
        guard authTime != nil else {
            throw AgentIdentityError.idToken(
                "the ID token carries no auth_time; the service measures the time-box from it (max_age was sent)")
        }
    }
}
