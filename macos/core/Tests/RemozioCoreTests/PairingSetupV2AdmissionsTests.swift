import Foundation
import XCTest
@testable import RemozioCore

final class PairingSetupV2AdmissionsTests: XCTestCase {
    func testNewArrivalsEvictOnlyUnprovedSlotsDuringVerification() {
        var admission = PairingSetupV2Admissions()
        let accepted = ContinuousClock.now
        let deadline = accepted.advanced(by: PairingSetupV2Admissions.proofTimeout)
        let protected = UUID()
        XCTAssertEqual(admission.admit(protected, deadline: deadline, draining: 0), .admitted(evicting: nil))
        XCTAssertTrue(admission.beginVerification(protected, at: accepted))

        var waiting = (0..<3).map { _ in UUID() }
        for id in waiting {
            XCTAssertEqual(admission.admit(id, deadline: deadline, draining: 0), .admitted(evicting: nil))
        }
        for _ in 0..<9 {
            let arrival = UUID()
            XCTAssertEqual(admission.admit(arrival, deadline: deadline, draining: 0),
                           .admitted(evicting: waiting.removeFirst()))
            waiting.append(arrival)
        }

        XCTAssertTrue(admission.completeVerification(protected, at: accepted.advanced(by: .seconds(2))))
        XCTAssertFalse(admission.expire(protected, at: deadline))
    }

    func testFourVerifyingSlotsRejectTheNextArrivalWithoutEviction() {
        var admission = PairingSetupV2Admissions()
        let accepted = ContinuousClock.now
        let deadline = accepted.advanced(by: PairingSetupV2Admissions.proofTimeout)
        let verifying = (0..<4).map { _ in UUID() }
        for id in verifying {
            XCTAssertEqual(admission.admit(id, deadline: deadline, draining: 0), .admitted(evicting: nil))
            XCTAssertTrue(admission.beginVerification(id, at: accepted))
        }

        XCTAssertEqual(admission.admit(UUID(), deadline: deadline, draining: 0), .rejected)
        for id in verifying {
            XCTAssertTrue(admission.completeVerification(id, at: accepted))
        }
    }

    func testVerifyingSlotExpiresAtTheDeadlineFromAccept() {
        var admission = PairingSetupV2Admissions()
        let accepted = ContinuousClock.now
        let deadline = accepted.advanced(by: PairingSetupV2Admissions.proofTimeout)
        let candidate = UUID()
        XCTAssertEqual(admission.admit(candidate, deadline: deadline, draining: 0), .admitted(evicting: nil))
        XCTAssertTrue(admission.beginVerification(candidate, at: deadline.advanced(by: .milliseconds(-1))))

        XCTAssertFalse(admission.expire(candidate, at: deadline.advanced(by: .milliseconds(-1))))
        XCTAssertFalse(admission.completeVerification(candidate, at: deadline))
        XCTAssertTrue(admission.expire(candidate, at: deadline))
        XCTAssertFalse(admission.expire(candidate, at: deadline))
        XCTAssertFalse(admission.completeVerification(candidate, at: deadline))
        XCTAssertEqual(admission.admit(UUID(), deadline: deadline.advanced(by: .seconds(1)), draining: 1),
                       .admitted(evicting: nil))
    }

    func testRejectedVerificationReleasesItsPendingSlot() {
        var admission = PairingSetupV2Admissions()
        let accepted = ContinuousClock.now
        let deadline = accepted.advanced(by: PairingSetupV2Admissions.proofTimeout)
        let rejected = UUID()
        for id in [rejected, UUID(), UUID(), UUID()] {
            XCTAssertEqual(admission.admit(id, deadline: deadline, draining: 0), .admitted(evicting: nil))
            XCTAssertTrue(admission.beginVerification(id, at: accepted))
        }

        XCTAssertTrue(admission.remove(rejected))
        XCTAssertFalse(admission.remove(rejected))
        XCTAssertFalse(admission.completeVerification(rejected, at: accepted))
        XCTAssertEqual(admission.admit(UUID(), deadline: deadline, draining: 1), .admitted(evicting: nil))
    }

    func testExpiredVerificationsStillCountUntilTheirWorkDrains() {
        var admission = PairingSetupV2Admissions()
        let accepted = ContinuousClock.now
        let deadline = accepted.advanced(by: PairingSetupV2Admissions.proofTimeout)
        let verifying = (0..<4).map { _ in UUID() }
        for id in verifying {
            XCTAssertEqual(admission.admit(id, deadline: deadline, draining: 4), .admitted(evicting: nil))
            XCTAssertTrue(admission.beginVerification(id, at: accepted))
        }
        for id in verifying {
            XCTAssertTrue(admission.expire(id, at: deadline))
        }

        let nextDeadline = deadline.advanced(by: PairingSetupV2Admissions.proofTimeout)
        XCTAssertEqual(admission.admit(UUID(), deadline: nextDeadline, draining: 8), .rejected)
        XCTAssertEqual(admission.admit(UUID(), deadline: nextDeadline, draining: 7), .admitted(evicting: nil))
    }
}
