import Foundation

/// The four requests, one method each, over an `HTTPTransport`. The paths are the service's own
/// (`EnrolmentHttpServer`'s constructor) under whatever base URL the app gives. The service has no version
/// prefix today; when X-A11 moves it under `/v1`, the base URL carries the prefix and nothing here changes.
///
/// A 200 is decoded as the reply the route documents. Anything else is decoded as the refusal shape and
/// thrown as `AgentIdentityError.refused`, or, when the body is not that shape, as `unexpectedResponse`.
public struct EnrolmentClient: Sendable {

    public enum Route: String, CaseIterable, Sendable {
        case challenge = "enrol/challenge"
        case enrol = "enrol"
        case attestation = "attestation"
        case userVerification = "user-verification"
    }

    public let baseURL: URL
    private let transport: HTTPTransport

    public init(baseURL: URL, transport: HTTPTransport = URLSessionTransport()) {
        self.baseURL = baseURL
        self.transport = transport
    }

    /// `POST /enrol/challenge`. The handler never reads the body; `{}` is sent.
    public func issueChallenge() async throws -> ChallengeResponse {
        try await post(.challenge, EmptyBody())
    }

    /// `POST /enrol`.
    public func enrol(_ request: EnrolRequest) async throws -> EnrolResponse {
        try await post(.enrol, request)
    }

    /// `POST /attestation`.
    public func reissue(_ request: ReissueRequest) async throws -> ReissueResponse {
        try await post(.attestation, request)
    }

    /// `POST /user-verification`.
    public func refreshUserVerification(_ request: UserVerificationRequest) async throws {
        let reply: StatusResponse = try await post(.userVerification, request)
        guard reply.status == "ok" else {
            throw AgentIdentityError.unexpectedResponse(status: 200, body: "status \(reply.status)")
        }
    }

    /// The URL a route is posted to: the base URL with the route's segments appended.
    public func url(for route: Route) -> URL {
        baseURL.appending(path: route.rawValue)
    }

    private func post<Request: Encodable, Reply: Decodable>(_ route: Route, _ request: Request) async throws -> Reply {
        let body = try WireJSON.encoder().encode(request)
        let reply: HTTPReply
        do {
            reply = try await transport.post(url(for: route), body: body)
        } catch let error as AgentIdentityError {
            throw error
        } catch {
            throw AgentIdentityError.transport(String(describing: error))
        }
        if reply.status == 200 {
            do {
                return try WireJSON.decoder().decode(Reply.self, from: reply.body)
            } catch {
                throw Self.unexpected(reply)
            }
        }
        if let refusal = try? WireJSON.decoder().decode(ErrorResponse.self, from: reply.body) {
            throw AgentIdentityError.refused(ServerRefusal(status: reply.status, code: refusal.error,
                                                           description: refusal.errorDescription ?? ""))
        }
        throw Self.unexpected(reply)
    }

    private static func unexpected(_ reply: HTTPReply) -> AgentIdentityError {
        .unexpectedResponse(status: reply.status, body: String(decoding: reply.body.prefix(512), as: UTF8.self))
    }

    private struct EmptyBody: Encodable {}
}
