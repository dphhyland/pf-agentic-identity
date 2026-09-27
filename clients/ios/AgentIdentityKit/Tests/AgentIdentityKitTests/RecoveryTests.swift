import XCTest
@testable import AgentIdentityKit

/// What the kit reads out of a refusal, and what a re-mint does with it.
final class RecoveryTests: XCTestCase {

    /// The two descriptions a lost race gets, as the Java builds them: EnrolmentService.verifyRenewalAssertion's
    /// prefix around the registry's message (IomInstanceRegistry's, and InMemoryInstanceRegistry's), and around
    /// AppAttestVerifier's COUNTER_NOT_ADVANCED.
    func testALostCounterRaceIsRecognisedInEitherPhrasing() {
        for description in [
            "App Attest assertion counter did not advance: App Attest counter did not advance for device d-1: 5",
            "App Attest assertion counter did not advance: App Attest counter 5 did not advance beyond 5 — replay",
            "App Attest assertion failed (counter_not_advanced): assertion signCount 4 did not advance beyond 5 — replay",
        ] {
            XCTAssertTrue(ServerRefusal(status: 401, code: ServerCode.invalidAttestation, description: description).isCounterRace,
                          description)
        }
    }

    /// Every other assertion failure shares the code and is not a race; `bad_counter` is an enrolment refusal
    /// that happens to contain the word.
    func testOtherAttestationRefusalsAreNotARace() {
        for description in [
            "App Attest assertion failed (bad_signature): assertion signature did not verify under the attested key",
            "App Attest assertion failed (app_id_mismatch): assertion rpIdHash does not match the configured App ID",
            "App Attest verification failed (bad_counter): attestation signCount is 3, expected 0",
            "app_attest_assertion is required: this agent enrolled with App Attest, so each renewal carries a fresh assertion from the same app",
        ] {
            XCTAssertFalse(ServerRefusal(status: 401, code: ServerCode.invalidAttestation, description: description).isCounterRace,
                           description)
        }
        XCTAssertFalse(ServerRefusal(status: 401, code: ServerCode.invalidKeyProof,
                                     description: "App Attest assertion counter did not advance").isCounterRace)
    }

    func testEachRecoveryHappensOnceAndNothingElseIsRecovered() {
        let verification = ServerRefusal(status: 401, code: ServerCode.userVerificationRequired, description: "")
        let race = ServerRefusal(status: 401, code: ServerCode.invalidAttestation,
                                 description: "App Attest assertion counter did not advance: x")
        let challenge = ServerRefusal(status: 400, code: ServerCode.invalidChallenge,
                                      description: "challenge is unknown, expired, or already used")
        var recovery = RemintRecovery()
        XCTAssertEqual(recovery.step(after: race), .retry)
        XCTAssertEqual(recovery.step(after: verification), .refreshUserVerificationThenRetry)
        XCTAssertEqual(recovery.step(after: challenge), .retry)
        XCTAssertEqual(recovery.step(after: race), .fail)
        XCTAssertEqual(recovery.step(after: verification), .fail)
        XCTAssertEqual(recovery.step(after: challenge), .fail)

        for code in [ServerCode.invalidRequest, ServerCode.userAuthenticationFailed, ServerCode.insufficientAssurance,
                     ServerCode.invalidKeyProof, ServerCode.unknownInstance, ServerCode.instanceNotActive,
                     ServerCode.deviceNotCompliant, ServerCode.serverError] {
            var fresh = RemintRecovery()
            XCTAssertEqual(fresh.step(after: ServerRefusal(status: 400, code: code, description: "")), .fail, code)
        }
    }
}
