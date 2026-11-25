import Foundation
import Network
import XCTest
@testable import RemozioCore

final class PairingSetupV2AdmissionsTests: XCTestCase {
    private static let pendingCapacity = PairingSetupV2Admissions.maximumPending
    private static let rate = PairingRegistrationBudget.registrationsPerSecond

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

        mutating func fillPending(draining: Int = 0) -> [UUID] {
            (0..<PairingSetupV2AdmissionsTests.pendingCapacity).map { index in
                let id = UUID()
                let afterBurst = UInt64(max(0, index + 1 - Int(PairingRegistrationBudget.ingressBurst)))
                let rate = PairingSetupV2AdmissionsTests.rate
                let offset = (1_000 * afterBurst + rate - 1) / rate
                XCTAssertEqual(admit(id, offset: offset, draining: draining), .admitted(evicting: nil))
                return id
            }
        }

        private mutating func sourceKey(_ label: String) -> PairingSetupV2Source {
            if let key = sources[label] { return key }
            let key = PairingSetupV2Source.ipv4(UInt32(sources.count))
            sources[label] = key
            return key
        }
    }

    func testCompletingScopedProofRejectsNewConnectionsBeforeBonjourWithdrawal() {
        var fixture = Fixture()
        let winner = UUID()
        XCTAssertEqual(fixture.admit(winner, source: "winner"), .admitted(evicting: nil))
        XCTAssertFalse(fixture.admission.completeVerification(winner, at: fixture.started, closeAdmission: true))
        XCTAssertEqual(fixture.admit(source: "other"), .admitted(evicting: nil))
        XCTAssertTrue(fixture.admission.beginVerification(winner, at: fixture.started))
        XCTAssertTrue(fixture.admission.completeVerification(winner, at: fixture.started, closeAdmission: true))
        XCTAssertFalse(fixture.admission.remove(winner))
        XCTAssertEqual(fixture.admit(source: "new", offset: 500), .rejected)
        XCTAssertEqual(fixture.admit(source: "winner", offset: 1_000), .rejected)
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
        for _ in 0..<PairingRegistrationBudget.ingressBurst {
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
        for _ in 0..<PairingRegistrationBudget.ingressBurst {
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

        let threeCredits = (3_000 + Self.rate - 1) / Self.rate
        XCTAssertEqual(fixture.admit(offset: threeCredits), .admitted(evicting: nil))
        let first = UUID()
        XCTAssertEqual(fixture.admit(first, source: "retry", offset: threeCredits), .admitted(evicting: nil))
        XCTAssertEqual(fixture.admit(source: "retry", offset: threeCredits), .admitted(evicting: first))
    }

    func testSourceKeyNormalizesMappedIPv4AndIgnoresPorts() throws {
        let native = try source("192.0.2.17")
        XCTAssertEqual(native, .ipv4(0xc0000211))
        XCTAssertEqual(try source("::ffff:192.0.2.17", port: 2), native)
        XCTAssertNotEqual(try source("192.0.2.18"), native)
        XCTAssertNil(PairingSetupV2Source(.hostPort(host: .name("localhost", nil), port: 1)))
        XCTAssertNil(PairingSetupV2Source(.unix(path: "/fixture")))
    }

    func testIPv6AddressesInSamePrefixKeepSeparateSlotsAndQuotas() throws {
        let scoped = try source("fe80::1234%lo0")
        XCTAssertEqual(scoped, try source("fe80::1234"))
        XCTAssertNotEqual(scoped, try source("fe80::5678%lo0"))
        let phone = try source("2001:db8:0:1::1")
        let peer = try source("2001:db8:0:1:abcd::2")
        XCTAssertEqual(phone, .ipv6(high: 0x20010db800000001, low: 1))
        XCTAssertNotEqual(phone, peer)

        var fixture = Fixture()
        let phoneFirst = UUID(), peerFirst = UUID()
        XCTAssertEqual(fixture.admit(phoneFirst, key: phone), .admitted(evicting: nil))
        XCTAssertEqual(fixture.admit(peerFirst, key: peer), .admitted(evicting: nil))
        let phoneRetry = UUID(), peerRetry = UUID()
        XCTAssertEqual(fixture.admit(phoneRetry, key: phone), .admitted(evicting: phoneFirst))
        XCTAssertEqual(fixture.admit(peerRetry, key: peer), .admitted(evicting: peerFirst))
        XCTAssertEqual(fixture.admit(key: phone), .rejected)
        XCTAssertEqual(fixture.admit(key: peer), .rejected)
        XCTAssertTrue(fixture.admission.beginVerification(phoneRetry, at: fixture.started))
        XCTAssertTrue(fixture.admission.beginVerification(peerRetry, at: fixture.started))
    }

    private func source(_ host: String, port: NWEndpoint.Port = 1) throws -> PairingSetupV2Source {
        try XCTUnwrap(PairingSetupV2Source(.hostPort(host: NWEndpoint.Host(host), port: port)))
    }

    func testUnrelatedSourceWaitsForReleasedSlotWithoutEvictingPendingPeers() {
        var fixture = Fixture()
        let waiting = fixture.fillPending()
        let now = fixture.started.advanced(by: .milliseconds(500))
        XCTAssertTrue(fixture.admission.beginVerification(waiting[0], at: now))
        let arrival = UUID()
        XCTAssertEqual(fixture.admit(arrival, offset: 500), .rejected)

        XCTAssertTrue(fixture.admission.completeVerification(waiting[0], at: now))
        XCTAssertEqual(fixture.admit(arrival, offset: 500), .admitted(evicting: nil))
        for id in waiting.dropFirst() {
            XCTAssertTrue(fixture.admission.beginVerification(id, at: now))
        }
        XCTAssertTrue(fixture.admission.beginVerification(arrival, at: now))
    }

    func testFullVerifyingSlotsRejectTheNextArrivalWithoutEviction() {
        var fixture = Fixture()
        let verifying = fixture.fillPending()
        XCTAssertEqual(verifying.count, 16)
        let now = fixture.started.advanced(by: .milliseconds(500))
        for id in verifying {
            XCTAssertTrue(fixture.admission.beginVerification(id, at: now))
        }

        XCTAssertEqual(fixture.admit(offset: 500), .rejected)
        for id in verifying {
            XCTAssertTrue(fixture.admission.completeVerification(id, at: now))
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
        let verifying = fixture.fillPending()
        let rejected = verifying[0]
        let now = fixture.started.advanced(by: .milliseconds(500))
        for id in verifying {
            XCTAssertTrue(fixture.admission.beginVerification(id, at: now))
        }

        XCTAssertTrue(fixture.admission.remove(rejected))
        XCTAssertFalse(fixture.admission.isVerifying(rejected, at: now))
        XCTAssertFalse(fixture.admission.remove(rejected))
        XCTAssertFalse(fixture.admission.completeVerification(rejected, at: now))
        XCTAssertEqual(fixture.admit(offset: 500, draining: 1), .admitted(evicting: nil))
    }

    func testExpiredVerificationsStillCountUntilTheirWorkDrains() {
        var fixture = Fixture()
        let verifying = fixture.fillPending(draining: 4)
        let now = fixture.started.advanced(by: .milliseconds(500))
        let expiredAt = fixture.started.advanced(by: .seconds(4))
        for id in verifying {
            XCTAssertTrue(fixture.admission.beginVerification(id, at: now))
            XCTAssertTrue(fixture.admission.expire(id, at: expiredAt))
        }

        let allDraining = verifying.count + 4
        XCTAssertEqual(fixture.admit(offset: 4_000, draining: allDraining), .rejected)
        XCTAssertEqual(fixture.admit(offset: 4_000, draining: allDraining - 1), .admitted(evicting: nil))
    }
}
