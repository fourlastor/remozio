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
        let link = AuthorityPairingProofLink(verifyPolicy: {}, validatePolicy: { _ in })

        init(lifetime: UInt64 = 10_000) throws {
            let scope = try ChannelScope(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
                phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16))
            let publicInvitation = try PairingInvitation(macID: scope.macID, accountID: scope.accountID, label: "Fixture",
                authorityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                transportPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation, minimumEnvelopeVersion: 1)
            invitation = try PairingInvitationV2(invitation: publicInvitation, windowID: Data(repeating: 5, count: 16),
                secret: Data(repeating: 6, count: 32), lifetimeMilliseconds: lifetime)
            window = try AuthorityPairingV2Window(invitation: invitation, predecessor: nil, started: clock.now())
            let offer = try ChannelOffer(role: .phone, scope: scope, nonce: Data(repeating: 7, count: 32),
                envelopeVersions: [1], requests: [], auditVersions: [])
            func key(_ id: UInt8) throws -> PairingKey {
                try .init(keyID: Data(repeating: id, count: 16), publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
            }
            proposal = try .init(phone: offer, transportKey: key(10), decisionKey: key(11), biometricKey: key(12))
        }

        func reservations(makeChallenge: @escaping @Sendable () throws -> Data = { Data(repeating: 13, count: 32) })
            throws -> AuthorityPairingProofReservations {
            try .init(window: window, link: link, now: clock.now, makeChallenge: makeChallenge, verifyWindow: {})
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
        fixture.clock.advance(to: 3_100)
        XCTAssertThrowsError(try fixture.register(reservations, acceptedAt: 3_100, exporter: Data(repeating: 0, count: 32)))
        XCTAssertNoThrow(try fixture.register(reservations, acceptedAt: 3_100))
    }

    func testReplayLedgerCannotGrowPastTheLifetimeRegistrationLimit() throws {
        let fixture = try Fixture(), reservations = try fixture.reservations()
        let limit = AuthorityPairingProofReservations.maximumRegistrations
        for index in 0..<limit {
            var exporter = Data(repeating: 0, count: 32)
            exporter[0] = UInt8(truncatingIfNeeded: index)
            exporter[1] = UInt8(truncatingIfNeeded: index >> 8)
            let candidate = try fixture.register(reservations, exporter: exporter)
            reservations.retire(candidate: candidate.id)
        }
        XCTAssertThrowsError(try fixture.register(reservations))
    }

    func testDuplicateLinkAttachmentDoesNotRetireTheLiveReservation() throws {
        let fixture = try Fixture(), reservations = try fixture.reservations()
        let other = try Fixture()
        XCTAssertThrowsError(try fixture.reservations())
        XCTAssertThrowsError(try AuthorityPairingProofReservations(window: other.window, link: fixture.link, now: other.clock.now,
            makeChallenge: { Data(repeating: 13, count: 32) }, verifyWindow: {}))
        let candidate = try fixture.register(reservations)
        try fixture.verify(reservations, candidate)
        try reservations.confirm(candidate: candidate.id)
    }

    func testRetiredLinkCannotStageOrAffectAnotherWindow() throws {
        let fixture = try Fixture(), reservations = try fixture.reservations()
        let candidate = try fixture.register(reservations)
        try fixture.verify(reservations, candidate)
        try reservations.confirm(candidate: candidate.id)
        reservations.retire()
        XCTAssertThrowsError(try fixture.window.takeProposal(connection: candidate.id,
            matching: fixture.proposal.encode(), at: fixture.clock.now()))
        XCTAssertThrowsError(try fixture.register(reservations))

        let next = try Fixture(), replacement = try next.reservations()
        let newCandidate = try next.register(replacement)
        reservations.retire(candidate: candidate.id)
        try next.verify(replacement, newCandidate)
        try replacement.confirm(candidate: newCandidate.id)
    }
}
