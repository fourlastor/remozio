import Foundation
import Network
import XCTest
@testable import RemozioCore

final class PairingSetupV2AdmissionsTests: XCTestCase {
    private struct Fixture {
        let started = ContinuousClock.now
        let epoch = UUID()
        var admission = PairingSetupV2Admissions()
        private var sources: [String: PairingSetupV2Source] = [:]

        mutating func admit(_ id: UUID = UUID(), source: String? = nil, offset: UInt64 = 0, draining: Int = 0,
                            drainingSources: [String] = []) -> PairingSetupV2Admissions.Admission {
            let key = sourceKey(source ?? id.uuidString)
            let drainingKeys = (drainingSources + (0..<draining).map { "draining-\($0)" }).map { sourceKey($0) }
            return admit(id, key: key, offset: offset, draining: drainingKeys)
        }

        mutating func admit(_ id: UUID = UUID(), key: PairingSetupV2Source, offset: UInt64 = 0,
                            draining: [PairingSetupV2Source] = []) -> PairingSetupV2Admissions.Admission {
            admission.admit(id, source: key, accepted: started.advanced(by: .milliseconds(Int64(offset))),
                clock: .init(epoch: epoch, milliseconds: offset), draining: draining)
        }

        private mutating func sourceKey(_ label: String) -> PairingSetupV2Source {
            if let key = sources[label] { return key }
            let key = PairingSetupV2Source.ipv4(UInt32(sources.count))
            sources[label] = key
            return key
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

    func testRejectedAttemptsDoNotCreateSourceEntriesOrConsumeSourceCredits() {
        var fixture = Fixture()
        for _ in 0..<PairingRegistrationBudget.burst {
            let id = UUID()
            XCTAssertEqual(fixture.admit(id), .admitted(evicting: nil))
            XCTAssertTrue(fixture.admission.remove(id))
        }
        for _ in 0..<64 {
            XCTAssertEqual(fixture.admit(), .rejected)
        }
        for _ in 0..<2 {
            XCTAssertEqual(fixture.admit(source: "retry"), .rejected)
        }

        XCTAssertEqual(fixture.admit(offset: 375), .admitted(evicting: nil))
        let first = UUID()
        XCTAssertEqual(fixture.admit(first, source: "retry", offset: 375), .admitted(evicting: nil))
        XCTAssertEqual(fixture.admit(source: "retry", offset: 375), .admitted(evicting: first))
    }

    func testSourceKeyNormalizesMappedIPv4AndIgnoresPorts() throws {
        let native = try source("192.0.2.17")
        XCTAssertEqual(native, .ipv4(0xc0000211))
        XCTAssertEqual(try source("::ffff:192.0.2.17", port: 2), native)
        XCTAssertNotEqual(try source("192.0.2.18"), native)
        XCTAssertNil(PairingSetupV2Source(.hostPort(host: .name("localhost", nil), port: 1)))
        XCTAssertNil(PairingSetupV2Source(.unix(path: "/fixture")))
    }

    func testIPv6SourceKeyIgnoresScopeAndSharesQuotaWithinPrefix() throws {
        XCTAssertEqual(try source("fe80::1234%lo0"), try source("fe80::1234"))
        let original = try source("2001:db8:0:1::1")
        let rotation = try source("2001:db8:0:1:abcd::2")
        let other = try source("2001:db8:0:2::1")
        XCTAssertEqual(original, .ipv6Prefix(0x20010db800000001))
        XCTAssertEqual(rotation, original)
        XCTAssertNotEqual(other, original)

        var fixture = Fixture()
        let id = UUID()
        XCTAssertEqual(fixture.admit(id, key: original), .admitted(evicting: nil))
        XCTAssertEqual(fixture.admit(key: rotation), .admitted(evicting: id))
        XCTAssertEqual(fixture.admit(key: rotation), .rejected)
        XCTAssertEqual(fixture.admit(key: other), .admitted(evicting: nil))
    }

    private func source(_ host: String, port: NWEndpoint.Port = 1) throws -> PairingSetupV2Source {
        try XCTUnwrap(PairingSetupV2Source(.hostPort(host: NWEndpoint.Host(host), port: port)))
    }

    func testUnrelatedSourceWaitsForReleasedSlotWithoutEvictingPendingPeers() {
        var fixture = Fixture()
        let waiting = (0..<PairingSetupV2Admissions.maximumPending).map { _ in UUID() }
        for id in waiting {
            XCTAssertEqual(fixture.admit(id), .admitted(evicting: nil))
        }
        XCTAssertTrue(fixture.admission.beginVerification(waiting[0], at: fixture.started))
        let arrival = UUID()
        XCTAssertEqual(fixture.admit(arrival, offset: 125), .rejected)

        let now = fixture.started.advanced(by: .milliseconds(250))
        XCTAssertTrue(fixture.admission.completeVerification(waiting[0], at: now))
        XCTAssertEqual(fixture.admit(arrival, offset: 250), .admitted(evicting: nil))
        for id in waiting.dropFirst() {
            XCTAssertTrue(fixture.admission.beginVerification(id, at: now))
        }
        XCTAssertTrue(fixture.admission.beginVerification(arrival, at: now))
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
