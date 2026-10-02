import CryptoKit
import XCTest
@testable import AgentIdentityKit

/// The state machine against a service that answers as `EnrolmentHttpServer` does, with App Attest, the Secure
/// Enclave and PingOne faked. Each test reads back what went on the wire.
final class DeviceAgentTests: XCTestCase {

    let audience = "https://enrolment.example"
    let device = DeviceDescription(platform: "ios", model: "iPhone16,2", osVersion: "18.5", agentBuild: "agent/1.0")

    struct Rig {
        let agent: DeviceAgent
        let service: FakeService
        let appAttest: FakeAppAttest
        let authenticator: FakeAuthenticator
        let key: SoftwareInstanceKey
        let clock: TestClock
    }

    func rig(state: DeviceAgent.State = .unenrolled) -> Rig {
        let service = FakeService()
        let appAttest = FakeAppAttest()
        let authenticator = FakeAuthenticator()
        let key = SoftwareInstanceKey()
        let clock = TestClock()
        let agent = DeviceAgent(client: EnrolmentClient(baseURL: FakeService.base, transport: service),
                                audience: audience, instanceKey: key, appAttest: appAttest,
                                authenticator: authenticator, device: device, state: state,
                                clock: { clock.now })
        return Rig(agent: agent, service: service, appAttest: appAttest, authenticator: authenticator, key: key,
                   clock: clock)
    }

    func enrolled() async throws -> Rig {
        let rig = rig()
        _ = try await rig.agent.enrol()
        return rig
    }

    // ---- enrolment -------------------------------------------------------------------------------------------

    func testEnrolmentIsAChallengeASignInAnAttestationAndOnePost() async throws {
        let rig = rig()
        let enrolment = try await rig.agent.enrol()

        XCTAssertEqual(rig.service.routes(), ["enrol/challenge", "enrol"])
        let jkt = rig.key.publicJWK.thumbprint
        // The sign-in carried the nonce over this challenge and this key.
        XCTAssertEqual(rig.authenticator.nonces,
                       [Commitments.enrolmentNonce(challenge: "challenge-1", instanceThumbprint: jkt)])
        // App Attest committed to SHA-256(jkt | challenge), which the server recomputes.
        XCTAssertEqual(rig.appAttest.attested.map(\.clientDataHash),
                       [Commitments.attestationClientDataHash(instanceThumbprint: jkt, challenge: "challenge-1")])

        let body = try XCTUnwrap(rig.service.bodies("enrol").first)
        let attested = try XCTUnwrap(rig.appAttest.attested.first)
        XCTAssertEqual(body["appattest_object"] as? String,
                       (Data("attestation-object:".utf8) + attested.clientDataHash).base64URL)
        XCTAssertEqual(body["appattest_key_id"] as? String, attested.key.wire)
        XCTAssertEqual(try decodeBase64URL(body["appattest_key_id"] as? String ?? "").count, 32)
        XCTAssertEqual(body["enclave_public_jwk"] as? [String: String],
                       ["kty": "EC", "crv": "P-256", "x": rig.key.publicJWK.x, "y": rig.key.publicJWK.y])
        XCTAssertEqual(body["challenge"] as? String, "challenge-1")
        let token = try XCTUnwrap(body["user_authentication"] as? String)
        XCTAssertEqual(try IDTokenClaims.parse(token).nonce, rig.authenticator.nonces.first)
        XCTAssertEqual(body["platform"] as? String, "ios")
        XCTAssertEqual(body["model"] as? String, "iPhone16,2")
        XCTAssertEqual(body["os_version"] as? String, "18.5")
        XCTAssertEqual(body["agent_build"] as? String, "agent/1.0")

        XCTAssertEqual(enrolment.instanceID, "instance-1")
        XCTAssertEqual(enrolment.appAttestKeyID, attested.key)
        XCTAssertEqual(enrolment.attestationExpiresAt, rig.clock.now.addingTimeInterval(900))
        let state = await rig.agent.state
        XCTAssertEqual(state, .enrolled(enrolment))
    }

    func testNoEnrolmentIsAttemptedWithoutAppAttest() async throws {
        let rig = rig()
        rig.appAttest.isSupported = false
        do {
            _ = try await rig.agent.enrol()
            XCTFail("enrolled without App Attest")
        } catch AgentIdentityError.appAttestUnsupported {
        }
        XCTAssertEqual(rig.service.routes(), [])
    }

    /// OpenID Connect Core 1.0 §3.1.3.7: the client checks the nonce it sent. A token that fails the kit's two
    /// checks never reaches the service, and nothing is attested for it.
    func testATokenWithTheWrongNonceOrNoAuthTimeGoesNowhere() async throws {
        for behaviour in [FakeAuthenticator.Behaviour.wrongNonce, .noNonce, .noAuthTime, .notAJWT] {
            let rig = rig()
            rig.authenticator.behaviour = behaviour
            do {
                _ = try await rig.agent.enrol()
                XCTFail("enrolled with \(behaviour)")
            } catch AgentIdentityError.idToken {
            }
            XCTAssertEqual(rig.service.routes(), ["enrol/challenge"], "\(behaviour)")
            XCTAssertTrue(rig.appAttest.attested.isEmpty, "\(behaviour)")
        }
    }

    func testARefusedEnrolmentLeavesNothingEnrolledAndIsNotRetried() async throws {
        let rig = rig()
        rig.service.refuseEnrol(FakeService.refusal(401, ServerCode.invalidAttestation,
                                                    "App Attest verification failed (nonce_mismatch): x"))
        do {
            _ = try await rig.agent.enrol()
            XCTFail("a refused enrolment was taken")
        } catch AgentIdentityError.refused(let refusal) {
            XCTAssertEqual(refusal.code, ServerCode.invalidAttestation)
        }
        XCTAssertEqual(rig.service.routes(), ["enrol/challenge", "enrol"])
        let state = await rig.agent.state
        XCTAssertEqual(state, .unenrolled)
    }

    func testASecondEnrolmentIsRefusedWhileOneIsHeld() async throws {
        let rig = try await enrolled()
        do {
            _ = try await rig.agent.enrol()
            XCTFail("enrolled twice")
        } catch AgentIdentityError.alreadyEnrolled {
        }
        XCTAssertEqual(rig.service.bodies("enrol").count, 1)
    }

    /// forget() ends the agent. Enrolling again on it would send the same instance key for a second instance,
    /// and the key's thumbprint in both attestations' cnf would link them; a new enrolment is a new agent.
    func testAForgottenAgentNeverEnrolsItsKeyAgain() async throws {
        let rig = try await enrolled()
        await rig.agent.forget()
        let state = await rig.agent.state
        XCTAssertEqual(state, .unenrolled)
        do {
            _ = try await rig.agent.enrol()
            XCTFail("a forgotten agent enrolled its key again")
        } catch AgentIdentityError.forgotten {
        }
        XCTAssertEqual(rig.service.routes(), ["enrol/challenge", "enrol"])
        XCTAssertEqual(rig.authenticator.nonces.count, 1)
        XCTAssertEqual(rig.appAttest.attested.count, 1)

        // The same holds for an agent forgotten before it ever enrolled, and for one that resumed a kept enrolment.
        let kept = Enrolment(instanceID: "instance-9", appAttestKeyID: try AppAttestKeyID(apple: Data(count: 32).base64EncodedString()),
                             attestation: "old", attestationExpiresAt: Date(timeIntervalSince1970: 0))
        for other in [self.rig(), self.rig(state: .enrolled(kept))] {
            await other.agent.forget()
            do {
                _ = try await other.agent.enrol()
                XCTFail("a forgotten agent enrolled")
            } catch AgentIdentityError.forgotten {
            }
            XCTAssertEqual(other.service.routes(), [])
        }
    }

    /// Two callers at once share one enrolment: two would bind one instance key to two instances.
    func testConcurrentEnrolmentsShareOneCeremony() async throws {
        let rig = rig()
        // The service takes its time, so the second caller arrives while the first enrolment is on the wire.
        rig.service.delay("enrol", nanoseconds: 500_000_000)
        async let first = rig.agent.enrol()
        async let second = rig.agent.enrol()
        let (a, b) = try await (first, second)
        XCTAssertEqual(a, b)
        XCTAssertEqual(rig.service.routes(), ["enrol/challenge", "enrol"])
        XCTAssertEqual(rig.authenticator.nonces.count, 1)
        XCTAssertEqual(rig.appAttest.attested.count, 1)
    }

    /// The app forgot the agent while its enrolment was on the wire: the answer is returned to the caller that
    /// asked, and not kept, so the agent stays unenrolled and cannot enrol again.
    func testAForgetDuringAnEnrolmentStands() async throws {
        let rig = rig()
        rig.service.delay("enrol", nanoseconds: 300_000_000)
        async let enrolled = rig.agent.enrol()
        try await Task.sleep(nanoseconds: 100_000_000)
        await rig.agent.forget()
        let enrolment = try await enrolled
        XCTAssertEqual(enrolment.instanceID, "instance-1")
        let state = await rig.agent.state
        XCTAssertEqual(state, .unenrolled)
        do {
            _ = try await rig.agent.currentAttestation()
            XCTFail("a forgotten enrolment was used")
        } catch AgentIdentityError.notEnrolled {
        }
        do {
            _ = try await rig.agent.enrol()
            XCTFail("a forgotten agent enrolled its key again")
        } catch AgentIdentityError.forgotten {
        }
        XCTAssertEqual(rig.service.bodies("enrol").count, 1)
    }

    // ---- re-mint ---------------------------------------------------------------------------------------------

    /// A fresh challenge, a proof naming it signed by the instance key, and an assertion over the proof exactly as
    /// sent.
    func testARemintIsAChallengeAProofAndAnAssertionOverTheProof() async throws {
        let rig = try await enrolled()
        let enrolment = try await rig.agent.remint()

        XCTAssertEqual(rig.service.routes(), ["enrol/challenge", "enrol", "enrol/challenge", "attestation"])
        let body = try XCTUnwrap(rig.service.bodies("attestation").first)
        XCTAssertEqual(body["instance_id"] as? String, "instance-1")
        let compact = try XCTUnwrap(body["key_proof"] as? String)
        let proof = try DecodedJWS(compact)
        XCTAssertTrue(try proof.verifiesUnderItsOwnJWK())
        XCTAssertEqual(proof.header["alg"] as? String, "ES256")
        XCTAssertEqual(proof.header["typ"] as? String, KeyProof.type)
        XCTAssertEqual(proof.header["jwk"] as? [String: String],
                       ["kty": "EC", "crv": "P-256", "x": rig.key.publicJWK.x, "y": rig.key.publicJWK.y])
        XCTAssertEqual(proof.payload["aud"] as? String, audience)
        XCTAssertEqual(proof.payload["challenge"] as? String, "challenge-2")
        XCTAssertEqual(proof.payload["iat"] as? Int, Int(rig.clock.now.timeIntervalSince1970))
        XCTAssertNotNil(proof.payload["jti"] as? String)

        let assertion = try XCTUnwrap(rig.appAttest.asserted.first)
        XCTAssertEqual(assertion.key, enrolment.appAttestKeyID)
        XCTAssertEqual(assertion.clientDataHash, Data(SHA256.hash(data: Data(compact.utf8))))
        XCTAssertEqual(body["app_attest_assertion"] as? String,
                       (Data("assertion:1:".utf8) + assertion.clientDataHash).base64URL)
        XCTAssertEqual(enrolment.attestation, "attestation-1")
    }

    /// The time-box: the owner signs in again with a random nonce, the verification is refreshed, and the re-mint
    /// goes again with a new challenge and proof. Once.
    func testUserVerificationRequiredRefreshesAndRemintsOnce() async throws {
        let rig = try await enrolled()
        rig.service.refuseReissue(FakeService.refusal(401, ServerCode.userVerificationRequired,
                                                      "user verification is older than PT5M; re-authenticate the owner and retry"))
        let enrolment = try await rig.agent.remint()

        XCTAssertEqual(rig.service.routes().dropFirst(2),
                       ["enrol/challenge", "attestation", "user-verification", "enrol/challenge", "attestation"])
        let refresh = try XCTUnwrap(rig.service.bodies("user-verification").first)
        XCTAssertEqual(refresh["instance_id"] as? String, "instance-1")
        XCTAssertEqual(rig.authenticator.nonces.count, 2)
        XCTAssertEqual(try IDTokenClaims.parse(refresh["user_authentication"] as? String ?? "").nonce,
                       rig.authenticator.nonces.last)
        XCTAssertNotEqual(rig.authenticator.nonces.last, rig.authenticator.nonces.first)
        let proofs = try rig.service.bodies("attestation").map { try DecodedJWS($0["key_proof"] as? String ?? "") }
        XCTAssertEqual(proofs.map { $0.payload["challenge"] as? String }, ["challenge-2", "challenge-3"])
        XCTAssertNotEqual(proofs[0].payload["jti"] as? String, proofs[1].payload["jti"] as? String)
        XCTAssertEqual(enrolment.attestation, "attestation-1")
    }

    /// A refused refresh is reported, and nothing more is sent: not another sign-in, not another re-mint.
    func testARefusedRefreshGoesToTheApp() async throws {
        let rig = try await enrolled()
        rig.service.refuseUserVerification(FakeService.refusal(401, ServerCode.userAuthenticationFailed,
                                                               "the authenticated user does not own this instance"))
        do {
            try await rig.agent.refreshUserVerification()
            XCTFail("a refused refresh was taken")
        } catch AgentIdentityError.refused(let refusal) {
            XCTAssertEqual(refusal.code, ServerCode.userAuthenticationFailed)
        }
        XCTAssertEqual(rig.service.routes().dropFirst(2), ["user-verification"])
        XCTAssertEqual(rig.authenticator.nonces.count, 2)
        let state = await rig.agent.state
        XCTAssertNotEqual(state, .unenrolled, "a refusal does not forget the enrolment by itself")
    }

    /// The time-box fired and the refresh the re-mint made for it was refused: that refusal is the re-mint's
    /// answer, and the re-mint is not tried again.
    func testARefusedRefreshInsideARemintGoesToTheApp() async throws {
        let rig = try await enrolled()
        rig.service.refuseReissue(FakeService.refusal(401, ServerCode.userVerificationRequired, "older"))
        rig.service.refuseUserVerification(FakeService.refusal(401, ServerCode.userAuthenticationFailed,
                                                               "the authenticated user does not own this instance"))
        do {
            _ = try await rig.agent.remint()
            XCTFail("re-minted through a refused refresh")
        } catch AgentIdentityError.refused(let refusal) {
            XCTAssertEqual(refusal.code, ServerCode.userAuthenticationFailed)
        }
        XCTAssertEqual(rig.service.routes().dropFirst(2), ["enrol/challenge", "attestation", "user-verification"])
    }

    func testASecondTimeBoxRefusalGoesToTheApp() async throws {
        let rig = try await enrolled()
        let refusal = FakeService.refusal(401, ServerCode.userVerificationRequired, "older")
        rig.service.refuseReissue(refusal, refusal)
        do {
            _ = try await rig.agent.remint()
            XCTFail("re-minted through two time-box refusals")
        } catch AgentIdentityError.refused(let refused) {
            XCTAssertTrue(refused.isUserVerificationRequired)
        }
        XCTAssertEqual(rig.service.bodies("user-verification").count, 1)
    }

    /// A lost counter race: a new challenge, a new proof and a new assertion, whose counter is higher. Never the
    /// same request again: its challenge and jti are spent, and its counter is not above the winner's.
    func testALostCounterRaceIsRetriedOnceWithNewValues() async throws {
        let rig = try await enrolled()
        rig.service.refuseReissue(FakeService.refusal(401, ServerCode.invalidAttestation,
            "App Attest assertion counter did not advance: App Attest counter did not advance for device d: 1"))
        let enrolment = try await rig.agent.remint()

        XCTAssertEqual(rig.service.routes().dropFirst(2),
                       ["enrol/challenge", "attestation", "enrol/challenge", "attestation"])
        let bodies = rig.service.bodies("attestation")
        XCTAssertNotEqual(bodies[0]["key_proof"] as? String, bodies[1]["key_proof"] as? String)
        XCTAssertNotEqual(bodies[0]["app_attest_assertion"] as? String, bodies[1]["app_attest_assertion"] as? String)
        XCTAssertEqual(rig.appAttest.asserted.map(\.counter), [1, 2])
        XCTAssertEqual(rig.appAttest.asserted.map(\.clientDataHash), try bodies.map {
            Commitments.assertionClientDataHash(keyProof: try XCTUnwrap($0["key_proof"] as? String))
        })
        XCTAssertEqual(enrolment.attestation, "attestation-1")
    }

    func testASecondLostRaceGoesToTheApp() async throws {
        let rig = try await enrolled()
        let race = FakeService.refusal(401, ServerCode.invalidAttestation,
                                       "App Attest assertion failed (counter_not_advanced): assertion signCount 2 did not advance beyond 3 — replay")
        rig.service.refuseReissue(race, race)
        do {
            _ = try await rig.agent.remint()
            XCTFail("re-minted through two lost races")
        } catch AgentIdentityError.refused(let refusal) {
            XCTAssertTrue(refusal.isCounterRace)
        }
        XCTAssertEqual(rig.service.bodies("attestation").count, 2)
    }

    func testAChallengeTheServiceNoLongerKnowsIsReplacedOnce() async throws {
        let rig = try await enrolled()
        rig.service.refuseReissue(FakeService.refusal(400, ServerCode.invalidChallenge,
                                                      "challenge is unknown, expired, or already used"))
        _ = try await rig.agent.remint()
        XCTAssertEqual(rig.service.bodies("attestation").count, 2)
    }

    /// The recoveries compose, each once: here the time-box, then a lost race, then a mint.
    func testTheRecoveriesComposeEachOnce() async throws {
        let rig = try await enrolled()
        rig.service.refuseReissue(
            FakeService.refusal(401, ServerCode.userVerificationRequired, "older"),
            FakeService.refusal(401, ServerCode.invalidAttestation, "App Attest assertion counter did not advance: x"))
        _ = try await rig.agent.remint()
        XCTAssertEqual(rig.service.bodies("attestation").count, 3)
        XCTAssertEqual(rig.service.bodies("user-verification").count, 1)
    }

    func testEveryOtherRefusalGoesToTheAppAtOnce() async throws {
        for (status, code) in [(403, ServerCode.deviceNotCompliant), (403, ServerCode.instanceNotActive),
                               (404, ServerCode.unknownInstance), (401, ServerCode.invalidKeyProof),
                               (500, ServerCode.serverError)] {
            let rig = try await enrolled()
            rig.service.refuseReissue(FakeService.refusal(status, code, "refused"))
            do {
                _ = try await rig.agent.remint()
                XCTFail("re-minted through \(code)")
            } catch AgentIdentityError.refused(let refusal) {
                XCTAssertEqual(refusal.code, code)
            }
            XCTAssertEqual(rig.service.bodies("attestation").count, 1, code)
            let state = await rig.agent.state
            XCTAssertNotEqual(state, .unenrolled, "a refusal does not forget the enrolment by itself")
        }
    }

    /// Two callers at once share one re-mint: two would race the App Attest counter against each other.
    func testConcurrentRemintsShareOneCeremony() async throws {
        let rig = try await enrolled()
        // The service takes its time, so the second caller arrives while the first re-mint is on the wire.
        rig.service.delay("attestation", nanoseconds: 500_000_000)
        async let first = rig.agent.remint()
        async let second = rig.agent.remint()
        let (a, b) = try await (first, second)
        XCTAssertEqual(a, b)
        XCTAssertEqual(rig.service.bodies("attestation").count, 1)
        XCTAssertEqual(rig.appAttest.asserted.count, 1)
    }

    /// The app forgot the enrolment while a re-mint was on the wire: the re-mint's answer does not bring it back.
    func testAForgetDuringARemintStands() async throws {
        let rig = try await enrolled()
        rig.service.delay("attestation", nanoseconds: 300_000_000)
        async let reminted = rig.agent.remint()
        try await Task.sleep(nanoseconds: 100_000_000)
        await rig.agent.forget()
        _ = try await reminted
        let state = await rig.agent.state
        XCTAssertEqual(state, .unenrolled)
    }

    func testTheCurrentAttestationIsReusedUntilItNearsExpiry() async throws {
        let rig = try await enrolled()
        var attestation = try await rig.agent.currentAttestation()
        XCTAssertEqual(attestation, "attestation-0")
        XCTAssertTrue(rig.service.bodies("attestation").isEmpty)

        rig.clock.now = rig.clock.now.addingTimeInterval(900 - 30)
        attestation = try await rig.agent.currentAttestation()
        XCTAssertEqual(attestation, "attestation-1")
        XCTAssertEqual(rig.service.bodies("attestation").count, 1)
    }

    func testNothingIsSentWithoutAnEnrolment() async throws {
        let rig = rig()
        for call in [{ _ = try await rig.agent.remint() }, { _ = try await rig.agent.currentAttestation() },
                     { try await rig.agent.refreshUserVerification() }] as [() async throws -> Void] {
            do {
                try await call()
                XCTFail("a call went out unenrolled")
            } catch AgentIdentityError.notEnrolled {
            }
        }
        XCTAssertEqual(rig.service.routes(), [])
    }

    /// An enrolment the app kept is picked up where it left off.
    func testAKeptEnrolmentRemints() async throws {
        let kept = Enrolment(instanceID: "instance-9", appAttestKeyID: try AppAttestKeyID(apple: Data(count: 32).base64EncodedString()),
                             attestation: "old", attestationExpiresAt: Date(timeIntervalSince1970: 0))
        let rig = rig(state: .enrolled(kept))
        let attestation = try await rig.agent.currentAttestation()
        XCTAssertEqual(attestation, "attestation-1")
        XCTAssertEqual(rig.service.bodies("attestation").first?["instance_id"] as? String, "instance-9")
        XCTAssertEqual(rig.appAttest.asserted.first?.key, kept.appAttestKeyID)
    }

    func testTheEnrolmentSurvivesCoding() throws {
        let enrolment = Enrolment(instanceID: "i", appAttestKeyID: try AppAttestKeyID(apple: Data(count: 32).base64EncodedString()),
                                  attestation: "a", attestationExpiresAt: Date(timeIntervalSince1970: 1_790_000_000))
        XCTAssertEqual(try JSONDecoder().decode(Enrolment.self, from: try JSONEncoder().encode(enrolment)), enrolment)
    }
}

final class AppAttestKeyIDTests: XCTestCase {

    /// Standard base64 first, as macOS 27.2's generateKey gave it; base64url second; the wire is base64url.
    func testTheKeyIdentifierIsReadInEitherAlphabetAndSentAsBase64URL() throws {
        let bytes = Data((0..<32).map { UInt8(truncatingIfNeeded: $0 * 7 + 250) })
        let standard = try AppAttestKeyID(apple: bytes.base64EncodedString())
        XCTAssertEqual(standard.bytes, bytes)
        XCTAssertEqual(standard.wire, bytes.base64URL)
        XCTAssertEqual(standard.apple, bytes.base64EncodedString())
        XCTAssertEqual(try AppAttestKeyID(apple: bytes.base64URL).bytes, bytes)
    }

    func testAnythingButThirtyTwoBytesIsRefused() {
        XCTAssertThrowsError(try AppAttestKeyID(apple: Data(count: 31).base64EncodedString()))
        XCTAssertThrowsError(try AppAttestKeyID(apple: "not base64 at all!"))
    }
}
