import Foundation

/// `HTTPTransport` over `URLSession`: one `POST` with a JSON body and the reply as it came, whatever the status.
public struct URLSessionTransport: HTTPTransport {
    private let session: URLSession
    private let timeout: TimeInterval

    /// - Parameter timeout: per request. A challenge lives 300 s, so a request that hangs longer than this
    ///   one has cost the ceremony less than the challenge's life.
    public init(session: URLSession = .shared, timeout: TimeInterval = 30) {
        self.session = session
        self.timeout = timeout
    }

    public func post(_ url: URL, body: Data) async throws -> HTTPReply {
        var request = URLRequest(url: url, timeoutInterval: timeout)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = body
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw AgentIdentityError.transport(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else {
            throw AgentIdentityError.transport("no HTTP response from \(url.absoluteString)")
        }
        return HTTPReply(status: http.statusCode, body: data)
    }
}
