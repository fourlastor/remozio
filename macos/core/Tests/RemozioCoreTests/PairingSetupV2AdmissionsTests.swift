import Foundation
import XCTest
@testable import RemozioCore

final class PairingSetupV2AdmissionsTests: XCTestCase {
    private struct Fixture {
        let started = ContinuousClock.now
        let epoch = UUID()
        var admission = PairingSetupV2Admissions()

        mutating func admit(_ id: UUID = UUID(), source: String? = nil, offset: UInt64 = 0,
                            draining: Int = 0, drainingSources: [String] = []) -> PairingSetupV2Admissions.Admission {
            admission.admit(id, source: source ?? id.uuidString, accepted: started.advanced(by: .milliseconds(Int64(offset))),
                clock: .init(epoch: epoch, milliseconds: offset),
                draining: drainingSources + (0..<draining).map { "draining-\($0)" })
        }
    }

    func testSameSourceReplacesOnlyItsOwnUnprovedSlot() {
        var fixture = Fixture()
        let busy = UUID(), peer = UUID()
        XCTAssertEqual(fixture.admit(busy, source: "busy"), .admitted(evicting: nil))
        XCTAssertEqual(fixture.admit(peer, source: "peer"), .admitted(evicting: nil))
        let replacement = UUID()
        XCTAssertEqual(fixture.admit(replacement, source: "busy"), .admitted(evicting: busy))
        XCTAssertTrue(fixture.admission.beginVerification(peer, at: fixture.started))
        XCTAssertTrue(fixture.admission.beginVerification(replacement, at: fixture.started))
        XCTAssertEqual(fixture.admit(source: "busy"), .rejected)
    }

    func testSourceRefillsAndLeavesCapacityForAnotherSource() {
        var fixture = Fixture()
        let first = UUID(), second = UUID()
        XCTAssertEqual(fixture.admit(first, source: "busy"), .admitted(evicting: nil))
        XCTAssertEqual(fixture.admit(second, source: "busy"), .admitted(evicting: first))
        for _ in 0..<9 {
            XCTAssertEqual(fixture.admit(source: "busy", offset: 999), .rejected)
        }
        XCTAssertEqual(fixture.admit(source: "new", offset: 999), .admitted(evicting: nil))
        XCTAssertEqual(fixture.admit(source: "busy", offset: 1_000), .admitted(evicting: second))
    }

    func testSourceCanRetryWhileOneSlotDrainsAndCannotAccumulateMore() {
        var fixture = Fixture()
        XCTAssertEqual(fixture.admit(source: "busy", drainingSources: ["busy", "busy"]), .rejected)
        XCTAssertEqual(fixture.admit(source: "busy", drainingSources: ["busy"]), .admitted(evicting: nil))
        XCTAssertEqual(fixture.admit(source: "new", drainingSources: ["busy"]), .admitted(evicting: nil))
    }

    func testGlobalBudgetStillAppliesAcrossDifferentSources() {
        var fixture = Fixture()
        for _ in 0..<PairingRegistrationBudget.burst {
            let id = UUID()
            XCTAssertEqual(fixture.admit(id), .admitted(evicting: nil))
            XCTAssertTrue(fixture.admission.remove(id))
        }
        let refill = (1_000 + PairingRegistrationBudget.registrationsPerSecond - 1) / PairingRegistrationBudget.registrationsPerSecond
        XCTAssertEqual(fixture.admit(offset: refill - 1), .rejected)
        XCTAssertEqual(fixture.admit(offset: refill), .admitted(evicting: nil))
    }

    func testDistinctSourceCanAdvanceDuringLogicalBackgroundActivity() {
        let offsets: [UInt64] = [0, 124, 125, 250, 500, 999, 1_000]
        var admitted = 0
        for offset in offsets {
            var fixture = Fixture()
            _ = fixture.admit(source: "background")
            _ = fixture.admit(source: "background", offset: offset / 2)
            let phone = UUID()
            if fixture.admit(phone, source: "test-phone", offset: offset) == .admitted(evicting: nil) {
                let now = fixture.started.advanced(by: .milliseconds(Int64(offset)))
                XCTAssertTrue(fixture.admission.beginVerification(phone, at: now))
                admitted += 1
            }
        }
        XCTAssertEqual(admitted, offsets.count)
    }

    func testNewArrivalsEvictOnlyUnprovedSlotsDuringVerification() {
        var fixture = Fixture()
        let accepted = fixture.started
        let deadline = accepted.advanced(by: PairingSetupV2Admissions.proofTimeout)
        let protected = UUID()
        XCTAssertEqual(fixture.admit(protected), .admitted(evicting: nil))
        XCTAssertTrue(fixture.admission.beginVerification(protected, at: accepted))

        var waiting = (0..<3).map { _ in UUID() }
        for id in waiting {
            XCTAssertEqual(fixture.admit(id), .admitted(evicting: nil))
        }
        for index in 1...9 {
            let arrival = UUID()
            XCTAssertEqual(fixture.admit(arrival, offset: UInt64(index) * 125),
                           .admitted(evicting: waiting.removeFirst()))
            waiting.append(arrival)
        }

        XCTAssertTrue(fixture.admission.completeVerification(protected, at: accepted.advanced(by: .seconds(2))))
        XCTAssertFalse(fixture.admission.expire(protected, at: deadline))
    }

    func testFourVerifyingSlotsRejectTheNextArrivalWithoutEviction() {
        var fixture = Fixture()
        let accepted = fixture.started
        let verifying = (0..<4).map { _ in UUID() }
        for id in verifying {
            XCTAssertEqual(fixture.admit(id), .admitted(evicting: nil))
            XCTAssertTrue(fixture.admission.beginVerification(id, at: accepted))
        }

        XCTAssertEqual(fixture.admit(), .rejected)
        for id in verifying {
            XCTAssertTrue(fixture.admission.completeVerification(id, at: accepted))
        }
    }

    func testVerifyingSlotExpiresAtTheDeadlineFromAccept() {
        var fixture = Fixture()
        let accepted = fixture.started
        let deadline = accepted.advanced(by: PairingSetupV2Admissions.proofTimeout)
        let candidate = UUID()
        XCTAssertEqual(fixture.admit(candidate), .admitted(evicting: nil))
        XCTAssertTrue(fixture.admission.beginVerification(candidate, at: deadline.advanced(by: .milliseconds(-1))))

        XCTAssertTrue(fixture.admission.isVerifying(candidate, at: deadline.advanced(by: .milliseconds(-1))))
        XCTAssertFalse(fixture.admission.expire(candidate, at: deadline.advanced(by: .milliseconds(-1))))
        XCTAssertFalse(fixture.admission.isVerifying(candidate, at: deadline))
        XCTAssertFalse(fixture.admission.completeVerification(candidate, at: deadline))
        XCTAssertTrue(fixture.admission.expire(candidate, at: deadline))
        XCTAssertFalse(fixture.admission.expire(candidate, at: deadline))
        XCTAssertFalse(fixture.admission.completeVerification(candidate, at: deadline))
        XCTAssertEqual(fixture.admit(offset: 1_000, draining: 1),
                       .admitted(evicting: nil))
    }

    func testRejectedVerificationReleasesItsPendingSlot() {
        var fixture = Fixture()
        let accepted = fixture.started
        let rejected = UUID()
        for id in [rejected, UUID(), UUID(), UUID()] {
            XCTAssertEqual(fixture.admit(id), .admitted(evicting: nil))
            XCTAssertTrue(fixture.admission.beginVerification(id, at: accepted))
        }

        XCTAssertTrue(fixture.admission.remove(rejected))
        XCTAssertFalse(fixture.admission.isVerifying(rejected, at: accepted))
        XCTAssertFalse(fixture.admission.remove(rejected))
        XCTAssertFalse(fixture.admission.completeVerification(rejected, at: accepted))
        XCTAssertEqual(fixture.admit(draining: 1), .admitted(evicting: nil))
    }

    func testExpiredVerificationsStillCountUntilTheirWorkDrains() {
        var fixture = Fixture()
        let accepted = fixture.started
        let deadline = accepted.advanced(by: PairingSetupV2Admissions.proofTimeout)
        let verifying = (0..<4).map { _ in UUID() }
        for id in verifying {
            XCTAssertEqual(fixture.admit(id, draining: 4), .admitted(evicting: nil))
            XCTAssertTrue(fixture.admission.beginVerification(id, at: accepted))
        }
        for id in verifying {
            XCTAssertTrue(fixture.admission.expire(id, at: deadline))
        }

        XCTAssertEqual(fixture.admit(offset: 3_000, draining: 8), .rejected)
        XCTAssertEqual(fixture.admit(offset: 3_000, draining: 7), .admitted(evicting: nil))
    }
}
