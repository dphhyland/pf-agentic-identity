import XCTest
@testable import AgentIdentityKit

final class EnrolmentClientTests: XCTestCase {

    /// One scripted reply, whatever the request.
    struct OneReply: HTTPTransport {
        let reply: HTTPReply?
        var error: Error?

        func post(_ url: URL, body: Data) async throws -> HTTPReply {
            if let error { throw error }
            return reply!
        }
    }

    func testTheRoutesAreTheServersUnderTheBaseURL() throws {
        let plain = EnrolmentClient(baseURL: URL(string: "https://enrolment.example")!, transport: OneReply(reply: nil))
        XCTAssertEqual(plain.url(for: .challenge).absoluteString, "https://enrolment.example/enrol/challenge")
        XCTAssertEqual(plain.url(for: .enrol).absoluteString, "https://enrolment.example/enrol")
        XCTAssertEqual(plain.url(for: .attestation).absoluteString, "https://enrolment.example/attestation")
        XCTAssertEqual(plain.url(for: .userVerification).absoluteString, "https://enrolment.example/user-verification")
        // X-A11's /v1, or a gateway's prefix, is the base URL's business.
        let prefixed = EnrolmentClient(baseURL: URL(string: "https://gateway.example/v1/")!, transport: OneReply(reply: nil))
        XCTAssertEqual(prefixed.url(for: .attestation).absoluteString, "https://gateway.example/v1/attestation")
    }

    func testARefusalIsThrownWithItsStatusCodeAndDescription() async throws {
        let client = EnrolmentClient(baseURL: FakeService.base, transport: OneReply(reply: FakeService.refusal(
            401, "user_verification_required", "user verification is older than PT5M; re-authenticate the owner and retry")))
        do {
            _ = try await client.reissue(ReissueRequest(instanceId: "i", keyProof: "p", appAttestAssertion: nil))
            XCTFail("a refusal was taken as a reply")
        } catch AgentIdentityError.refused(let refusal) {
            XCTAssertEqual(refusal.status, 401)
            XCTAssertEqual(refusal.code, ServerCode.userVerificationRequired)
            XCTAssertTrue(refusal.isUserVerificationRequired)
        }
    }

    /// A proxy's HTML page, or a 200 that is not the route's reply, is reported with its status and the start of
    /// its body, and nothing is retried.
    func testAnythingElseIsAnUnexpectedResponse() async throws {
        let gateway = EnrolmentClient(baseURL: FakeService.base, transport: OneReply(
            reply: HTTPReply(status: 502, body: Data("<html>Bad Gateway</html>".utf8))))
        do {
            _ = try await gateway.issueChallenge()
            XCTFail("a 502 was taken as a challenge")
        } catch AgentIdentityError.unexpectedResponse(let status, let body) {
            XCTAssertEqual(status, 502)
            XCTAssertTrue(body.contains("Bad Gateway"))
        }
        let wrongShape = EnrolmentClient(baseURL: FakeService.base, transport: OneReply(
            reply: FakeService.reply(200, ["status": "ok"])))
        do {
            _ = try await wrongShape.issueChallenge()
            XCTFail("a reply without a challenge was taken as one")
        } catch AgentIdentityError.unexpectedResponse(let status, _) {
            XCTAssertEqual(status, 200)
        }
    }

    func testAUserVerificationReplyOtherThanOkIsUnexpected() async throws {
        let client = EnrolmentClient(baseURL: FakeService.base, transport: OneReply(
            reply: FakeService.reply(200, ["status": "pending"])))
        do {
            try await client.refreshUserVerification(UserVerificationRequest(instanceId: "i", userAuthentication: "t"))
            XCTFail("a pending status was taken as ok")
        } catch AgentIdentityError.unexpectedResponse(let status, _) {
            XCTAssertEqual(status, 200)
        }
    }

    func testATransportFailureIsReportedAsOne() async throws {
        let client = EnrolmentClient(baseURL: FakeService.base, transport: OneReply(
            reply: nil, error: URLError(.notConnectedToInternet)))
        do {
            _ = try await client.issueChallenge()
            XCTFail("no transport failure")
        } catch AgentIdentityError.transport {
        }
    }
}
