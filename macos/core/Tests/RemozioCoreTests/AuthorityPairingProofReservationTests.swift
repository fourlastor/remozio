import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityPairingProofReservationTests: XCTestCase {
    private final class Clock: Sendable {
        let epoch = UUID()
        let milliseconds = Mutex<UInt64>(100)
        func now() -> AuthorityMoment { .init(epoch: epoch, milliseconds: milliseconds.withLock { $0 }) }
        func advance(to value: UInt64) { milliseconds.withLock { $0 = value } }
    }

    private struct Fixture {
        let clock = Clock()
        let invitation: PairingInvitationV2
        let window: AuthorityPairingV2Window
        let proposal: PairingPhoneProposal
        let authorityOwner = UUID()
        let link: AuthorityPairingProofLink

        init(lifetime: UInt64 = 10_000, verifyPolicy: @escaping @Sendable () throws -> Void = {}) throws {
            link = .init(verifyPolicy: verifyPolicy, validatePolicy: { _ in })

            let scope = try ChannelScope(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
                phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16))
            let publicInvitation = try PairingInvitation(macID: scope.macID, accountID: scope.accountID, label: "Fixture",
                authorityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                transportPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation, minimumEnvelopeVersion: 1)
            invitation = try PairingInvitationV2(invitation: publicInvitation, windowID: Data(repeating: 5, count: 16),
                secret: Data(repeating: 6, count: 32), lifetimeMilliseconds: lifetime)
            window = try AuthorityPairingV2Window(invitation: invitation, predecessor: nil, started: clock.now(),
                                                  authorityOwner: authorityOwner)
            let offer = try ChannelOffer(role: .phone, scope: scope, nonce: Data(repeating: 7, count: 32),
                envelopeVersions: [1], requests: [], auditVersions: [])
            func key(_ id: UInt8) throws -> PairingKey {
                try .init(keyID: Data(repeating: id, count: 16), publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
            }
            proposal = try .init(phone: offer, transportKey: key(10), decisionKey: key(11), biometricKey: key(12))
        }

        func reservations(makeChallenge: @escaping @Sendable () throws -> Data = { Data(repeating: 13, count: 32) })
            throws -> AuthorityPairingProofReservations {
            try .init(window: window, authorityOwner: authorityOwner, link: link, now: clock.now,
                      makeChallenge: makeChallenge, verifyWindow: {})
        }

        func register(_ reservations: AuthorityPairingProofReservations, connection: UUID = UUID(),
                      acceptedAt: UInt64 = 100, peerPoint: Data? = nil, exporter: Data = Data(repeating: 20, count: 32))
            throws -> AuthorityPairingProofReservations.Candidate {
            try reservations.register(connection: connection, acceptedAt: acceptedAt,
                peerPoint: peerPoint ?? proposal.transportKey.publicKey, exporter: exporter)
        }

        func verify(_ reservations: AuthorityPairingProofReservations, _ candidate: AuthorityPairingProofReservations.Candidate,
                    exporter: Data = Data(repeating: 20, count: 32), challenge: Data? = nil) throws {
            let tag = try invitation.proof(proposal: proposal, challenge: challenge ?? candidate.challenge, exporter: exporter)
            try reservations.verify(candidate: candidate.id, proposalBytes: proposal.encode(), tag: tag)
        }
    }

    func testProofRequiresConfirmationAndStagesOnlyExactProposalOnce() throws {
        let fixture = try Fixture(), reservations = try fixture.reservations()
        let candidate = try fixture.register(reservations), proposal = try fixture.proposal.encode()
        try fixture.verify(reservations, candidate)

        XCTAssertThrowsError(try fixture.window.export(at: fixture.clock.now()))
        XCTAssertThrowsError(try fixture.window.takeProposal(connection: candidate.id, matching: proposal, at: fixture.clock.now()))
        XCTAssertThrowsError(try reservations.confirm(candidate: UUID()))
        try reservations.confirm(candidate: candidate.id)
        XCTAssertThrowsError(try reservations.confirm(candidate: candidate.id))
        XCTAssertThrowsError(try fixture.window.takeProposal(connection: UUID(), matching: proposal, at: fixture.clock.now()))
        XCTAssertThrowsError(try fixture.window.takeProposal(connection: candidate.id, matching: proposal + Data([0]), at: fixture.clock.now()))
        XCTAssertEqual(try fixture.window.takeProposal(connection: candidate.id, matching: proposal, at: fixture.clock.now()).encode(), proposal)
        XCTAssertThrowsError(try fixture.window.takeProposal(connection: candidate.id, matching: proposal, at: fixture.clock.now()))
    }

    func testExhaustedXPCBudgetRejectsBeforeConsumingOrDecodingProposal() throws {
        let fixture = try Fixture(), reservations = try fixture.reservations()
        let candidate = try fixture.register(reservations)
        let invalidProposal = Data([0xff])
        let tag = Data(repeating: 0, count: 32)

        try reservations.withXPCWork {
            XCTAssertThrowsError(try reservations.withXPCWork {
                try reservations.verify(candidate: candidate.id, proposalBytes: invalidProposal, tag: tag)
            }) {
                guard case AuthorityXPCEndpointError.unavailable = $0 else {
                    return XCTFail("Expected proof work admission to fail")
                }
            }
            XCTAssertEqual(reservations.pendingCount, 1)
        }
        try reservations.withXPCWork { try fixture.verify(reservations, candidate) }
        try reservations.withXPCWork { try reservations.confirm(candidate: candidate.id) }
    }

    func testRegistrationRetainsReplayChecksAfterCandidateRetirement() throws {
        let fixture = try Fixture(), reservations = try fixture.reservations()
        let connection = UUID(), exporter = Data(repeating: 21, count: 32)
        let candidate = try fixture.register(reservations, connection: connection, exporter: exporter)
        reservations.retire(candidate: candidate.id)

        XCTAssertThrowsError(try fixture.register(reservations, connection: connection))
        XCTAssertThrowsError(try fixture.register(reservations, exporter: exporter))
        XCTAssertNoThrow(try fixture.register(reservations))
    }

    func testMismatchedTLSBindingDoesNotSpendInvitation() throws {
        for mismatch in 0..<3 {
            let fixture = try Fixture(), reservations = try fixture.reservations()
            let otherKey = P256.Signing.PrivateKey().publicKey.x963Representation
            let candidate = try fixture.register(reservations, peerPoint: mismatch == 0 ? otherKey : nil)
            let exporter = Data(repeating: mismatch == 1 ? 21 : 20, count: 32)
            let wrongChallenge = mismatch == 2 ? Data(repeating: 14, count: 32) : nil
            XCTAssertThrowsError(try fixture.verify(reservations, candidate, exporter: exporter, challenge: wrongChallenge))
            XCTAssertThrowsError(try fixture.verify(reservations, candidate))
            XCTAssertThrowsError(try reservations.confirm(candidate: candidate.id))
            let nextExporter = Data(repeating: 22, count: 32)
            let next = try fixture.register(reservations, exporter: nextExporter)
            try fixture.verify(reservations, next, exporter: nextExporter)
            try reservations.confirm(candidate: next.id)
        }
    }

    func testFutureAcceptSampleAndExpiryDuringRegistrationAreRejected() throws {
        let fixture = try Fixture()
        let clock = fixture.clock
        let reservations = try fixture.reservations {
            clock.advance(to: 3_100)
            return Data(repeating: 13, count: 32)
        }
        XCTAssertThrowsError(try fixture.register(reservations, acceptedAt: 101))
        XCTAssertEqual(clock.now().milliseconds, 100)
        XCTAssertThrowsError(try fixture.register(reservations)) { XCTAssertEqual($0 as? PairingEnrollmentError, .expired) }
        XCTAssertEqual(clock.now().milliseconds, 3_100)
    }

    func testRegistrationRejectsAnAcceptThatAlreadyExpired() throws {
        let fixture = try Fixture(), reservations = try fixture.reservations()
        fixture.clock.advance(to: 3_100)
        XCTAssertThrowsError(try fixture.register(reservations, acceptedAt: 100)) {
            XCTAssertEqual($0 as? PairingEnrollmentError, .expired)
        }
        XCTAssertNoThrow(try fixture.register(reservations, acceptedAt: 101))
    }

    func testSecondValidProofCannotClaimAnAlreadySpentWindow() throws {
        let fixture = try Fixture(), reservations = try fixture.reservations()
        let first = try fixture.register(reservations)
        let exporter = Data(repeating: 22, count: 32)
        let second = try fixture.register(reservations, exporter: exporter)
        try fixture.verify(reservations, first)
        XCTAssertThrowsError(try fixture.verify(reservations, second, exporter: exporter))
        XCTAssertThrowsError(try reservations.confirm(candidate: second.id))
        try reservations.confirm(candidate: first.id)
    }

    func testVerifyPolicyFailureBlocksEveryProofOperation() throws {
        let allowed = MutexBox()
        let fixture = try Fixture { if !allowed.value.withLock({ $0 }) { throw AuthorityPairingSetupError.policyChanged } }
        let reservations = try fixture.reservations()
        allowed.value.withLock { $0 = false }
        XCTAssertThrowsError(try fixture.register(reservations)) {
            XCTAssertEqual($0 as? AuthorityPairingSetupError, .policyChanged)
        }

        allowed.value.withLock { $0 = true }
        let candidate = try fixture.register(reservations)
        allowed.value.withLock { $0 = false }
        XCTAssertThrowsError(try fixture.verify(reservations, candidate)) {
            XCTAssertEqual($0 as? AuthorityPairingSetupError, .policyChanged)
        }
        allowed.value.withLock { $0 = true }
        try fixture.verify(reservations, candidate)
        allowed.value.withLock { $0 = false }
        XCTAssertThrowsError(try reservations.confirm(candidate: candidate.id)) {
            XCTAssertEqual($0 as? AuthorityPairingSetupError, .policyChanged)
        }
    }

    private final class MutexBox: Sendable {
        let value = Mutex(true)
    }

    func testExpiredConfirmCannotReopenOrStageTheWindow() throws {
        let fixture = try Fixture(), reservations = try fixture.reservations()
        let candidate = try fixture.register(reservations)
        fixture.clock.advance(to: 3_099)
        try fixture.verify(reservations, candidate)
        fixture.clock.advance(to: 3_100)

        XCTAssertThrowsError(try reservations.confirm(candidate: candidate.id)) { XCTAssertEqual($0 as? PairingEnrollmentError, .expired) }
        XCTAssertThrowsError(try fixture.window.takeProposal(connection: candidate.id,
            matching: fixture.proposal.encode(), at: fixture.clock.now()))
        XCTAssertThrowsError(try fixture.register(reservations, acceptedAt: 3_100, exporter: Data(repeating: 25, count: 32)))
    }

    func testProofDeadlineIsCappedByTheAuthorityWindow() throws {
        let fixture = try Fixture(lifetime: 1_000), reservations = try fixture.reservations()
        fixture.clock.advance(to: 1_000)
        let deadline = try fixture.window.proofDeadline(for: fixture.link, acceptedAt: 990, at: fixture.clock.now())
        XCTAssertEqual(deadline.milliseconds, 1_100)
        let candidate = try fixture.register(reservations, acceptedAt: 990)
        fixture.clock.advance(to: 1_099)
        try fixture.verify(reservations, candidate)
        fixture.clock.advance(to: 1_100)
        XCTAssertThrowsError(try reservations.confirm(candidate: candidate.id)) { XCTAssertEqual($0 as? PairingEnrollmentError, .expired) }
    }

    func testExpiredPendingCandidatesFreeCapacityWithoutClearingReplayChecks() throws {
        let fixture = try Fixture(), reservations = try fixture.reservations()
        let capacity = AuthorityPairingProofReservations.maximumPending
        for index in 0..<capacity {
            _ = try fixture.register(reservations, exporter: Data(repeating: UInt8(index), count: 32))
        }
        XCTAssertThrowsError(try fixture.register(reservations))
        XCTAssertEqual(reservations.pendingCount, capacity)
        fixture.clock.advance(to: 3_100)
        XCTAssertThrowsError(try fixture.register(reservations, acceptedAt: 3_100, exporter: Data(repeating: 0, count: 32)))
        XCTAssertEqual(reservations.pendingCount, 0)
        XCTAssertNoThrow(try fixture.register(reservations, acceptedAt: 3_100))
        XCTAssertEqual(reservations.pendingCount, 1)
    }

    func testReplayCapacityExceedsAllRegistrationsTheBudgetCanAdmitDuringAWindow() {
        let duration = AuthorityPairingSetupConfiguration.maximumLifetimeMilliseconds
        let rate = PairingRegistrationBudget.registrationsPerSecond
        let required = PairingRegistrationBudget.burst + (duration * rate + 999) / 1_000
        XCTAssertLessThan(required, UInt64(AuthorityPairingProofReservations.maximumRegistrations))
    }

    func testRegistrationRecoversAfterMoreThan256RetirementsInOneWindow() throws {
        let fixture = try Fixture(lifetime: AuthorityPairingSetupConfiguration.maximumLifetimeMilliseconds)
        let reservations = try fixture.reservations()
        let interval = (1_000 + PairingRegistrationBudget.registrationsPerSecond - 1) / PairingRegistrationBudget.registrationsPerSecond
        for index in 0...256 {
            let accepted = 100 + UInt64(index) * interval
            fixture.clock.advance(to: accepted)
            var exporter = Data(repeating: 0, count: 32)
            exporter[0] = UInt8(truncatingIfNeeded: index)
            exporter[1] = UInt8(truncatingIfNeeded: index >> 8)
            let candidate = try fixture.register(reservations, acceptedAt: accepted, exporter: exporter)
            reservations.retire(candidate: candidate.id)
        }
        let accepted = fixture.clock.now().milliseconds + interval
        fixture.clock.advance(to: accepted)
        let exporter = Data(repeating: 20, count: 32)
        let candidate = try fixture.register(reservations, acceptedAt: accepted, exporter: exporter)
        try fixture.verify(reservations, candidate, exporter: exporter)
        try reservations.confirm(candidate: candidate.id)
        XCTAssertNoThrow(try fixture.window.takeProposal(connection: candidate.id, matching: fixture.proposal.encode(), at: fixture.clock.now()))
    }

    func testRejectedRegistrationsSpendBudgetUntilRefill() throws {
        let fixture = try Fixture(), reservations = try fixture.reservations()
        let duplicate = UUID()
        let candidate = try fixture.register(reservations, connection: duplicate)
        reservations.retire(candidate: candidate.id)
        for _ in 1..<PairingRegistrationBudget.burst {
            XCTAssertThrowsError(try fixture.register(reservations, connection: duplicate))
        }
        let refill = (1_000 + PairingRegistrationBudget.registrationsPerSecond - 1) / PairingRegistrationBudget.registrationsPerSecond
        fixture.clock.advance(to: 100 + refill - 1)
        XCTAssertThrowsError(try fixture.register(reservations, acceptedAt: 100 + refill - 1, exporter: Data(repeating: 21, count: 32)))
        fixture.clock.advance(to: 100 + refill)
        XCTAssertNoThrow(try fixture.register(reservations, acceptedAt: 100 + refill, exporter: Data(repeating: 21, count: 32)))
    }

    func testRegistrationBudgetRejectsARegressedOrChangedClock() {
        let epoch = UUID()
        for invalid in [AuthorityMoment(epoch: epoch, milliseconds: 99), .init(epoch: UUID(), milliseconds: 101)] {
            var budget = PairingRegistrationBudget()
            XCTAssertTrue(budget.spend(at: .init(epoch: epoch, milliseconds: 100)))
            XCTAssertFalse(budget.spend(at: invalid))
            XCTAssertFalse(budget.spend(at: .init(epoch: epoch, milliseconds: 1_100)))
        }
    }

    func testRegistrationBudgetRefillSaturatesAfterALargeClockAdvance() {
        let epoch = UUID()
        var budget = PairingRegistrationBudget()
        for _ in 0..<PairingRegistrationBudget.burst {
            XCTAssertTrue(budget.spend(at: .init(epoch: epoch, milliseconds: 100)))
        }
        XCTAssertFalse(budget.spend(at: .init(epoch: epoch, milliseconds: 100)))
        for _ in 0..<PairingRegistrationBudget.burst {
            XCTAssertTrue(budget.spend(at: .init(epoch: epoch, milliseconds: UInt64.max)))
        }
        XCTAssertFalse(budget.spend(at: .init(epoch: epoch, milliseconds: UInt64.max)))
    }

    func testDuplicateLinkAttachmentDoesNotRetireTheLiveReservation() throws {
        let fixture = try Fixture(), reservations = try fixture.reservations()
        let other = try Fixture()
        XCTAssertThrowsError(try fixture.reservations())
        XCTAssertThrowsError(try AuthorityPairingProofReservations(window: other.window, authorityOwner: other.authorityOwner,
            link: fixture.link, now: other.clock.now, makeChallenge: { Data(repeating: 13, count: 32) }, verifyWindow: {}))
        let candidate = try fixture.register(reservations)
        try fixture.verify(reservations, candidate)
        try reservations.confirm(candidate: candidate.id)
    }

    func testRetiredLinkCannotStage() throws {
        let fixture = try Fixture(), reservations = try fixture.reservations()
        let candidate = try fixture.register(reservations)
        try fixture.verify(reservations, candidate)
        try reservations.confirm(candidate: candidate.id)
        reservations.retire()
        XCTAssertThrowsError(try fixture.window.takeProposal(connection: candidate.id,
            matching: fixture.proposal.encode(), at: fixture.clock.now()))
        XCTAssertThrowsError(try fixture.register(reservations))

    }
}
