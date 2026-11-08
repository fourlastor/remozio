import CryptoKit
import Foundation
import Security
import Synchronization
import XCTest
@testable import RemozioCore

final class MachineUpdateTransportHealthKeyTests: XCTestCase {
    private final class State<Value: Sendable>: Sendable {
        let value: Mutex<Value>
        init(_ value: Value) { self.value = Mutex(value) }
    }
    private enum Failure: Error { case changed }
    private func material() throws -> TransportFileIdentity.Created {
        try TransportFileIdentity.create(notValidBefore: Date().addingTimeInterval(-60), notValidAfter: Date().addingTimeInterval(300))
    }
    private func requirement(_ material: TransportFileIdentity.Created) throws -> MachineUpdateRestartHealthPlan.Requirement {
        try MachineUpdateRoleChallengeTests.Fixture().requirement(role: .transport, uid: 20000, publicKey: material.publicKeyX963)
    }
    private func identity(_ material: TransportFileIdentity.Created) throws -> SecIdentity {
        try TransportFileIdentity.load(bytes: material.encoded, publicKeyInfo: material.subjectPublicKeyInfo)
    }
    private final class LiveProofChecks: Sendable { let value = Mutex(0) }
    private func liveRequest(_ material: TransportFileIdentity.Created,
        expected: MachineUpdateRestartHealthPlan.Requirement? = nil
    ) throws -> (MachineUpdateConsumerHealthPeer,MachineUpdateConsumerHealthChallengeSession,MachineUpdateConsumerHealthRequest) {
        let selected = try expected ?? requirement(material), epoch = UUID()
        let session = try MachineUpdateConsumerHealthChallengeSession(requirement: selected,registration: nil,
            clock: { .init(epoch: epoch,milliseconds: 100) },verifyCurrent: {})
        let peer = MachineUpdateConsumerHealthPeer.owned(expected: selected,authenticateInvocation: {},verifyPeer: {},verifyCurrent: {})
        try peer.greet()
        return (peer,session,try peer.accept(session.makeRequest()))
    }
    func testLiveIdentityAnswersOneAuthenticatedRequestAndTheBorrowCannotBeReused() throws {
        let material = try material(), live = try MachineUpdateTransportHealthKey.LiveIdentity(identity(material))
        let (peer,session,request) = try liveRequest(material); defer { peer.close() }
        let reply = try live.answer(request,expected: request.requirement,publicKeyInfo: material.subjectPublicKeyInfo,verifyCurrent: {})
        XCTAssertEqual(try session.accept(reply,authenticatePeer: { _ in }).role.requirement,request.requirement)
        XCTAssertThrowsError(try live.answer(request,expected: request.requirement,publicKeyInfo: material.subjectPublicKeyInfo,verifyCurrent: {}))
        let (nextPeer,nextSession,next) = try liveRequest(material); defer { nextPeer.close() }
        let nextReply = try live.answer(next,expected: next.requirement,publicKeyInfo: material.subjectPublicKeyInfo,verifyCurrent: {})
        _ = try nextSession.accept(nextReply,authenticatePeer: { _ in })
    }
    func testLiveIdentityRejectsWrongPinsWithoutReplacingOrRetiringTheOrdinaryIdentity() throws {
        let first = try material(),other = try material(),live = try MachineUpdateTransportHealthKey.LiveIdentity(identity(first))
        let (peer,_,request) = try liveRequest(first); defer { peer.close() }
        XCTAssertThrowsError(try live.answer(request,expected: request.requirement,publicKeyInfo: other.subjectPublicKeyInfo,verifyCurrent: {}))
        let (nextPeer,session,next) = try liveRequest(first); defer { nextPeer.close() }
        let reply = try live.answer(next,expected: next.requirement,publicKeyInfo: first.subjectPublicKeyInfo,verifyCurrent: {})
        _ = try session.accept(reply,authenticatePeer: { _ in })
    }
    func testRevokedLiveIdentityRequestCannotReachTheBorrowedIdentityChecks() throws {
        let material = try material(),live = try MachineUpdateTransportHealthKey.LiveIdentity(identity(material)),checks = LiveProofChecks()
        let (peer,_,request) = try liveRequest(material); peer.close()
        XCTAssertThrowsError(try live.answer(request,expected: request.requirement,publicKeyInfo: material.subjectPublicKeyInfo,
            verifyCurrent: { checks.value.withLock { $0 += 1 } }))
        XCTAssertEqual(checks.value.withLock { $0 },0)
    }
    func testRevocationDuringLiveIdentityValidationCannotReturnAProof() throws {
        let material = try material(),live = try MachineUpdateTransportHealthKey.LiveIdentity(identity(material)),checks = LiveProofChecks()
        let (peer,_,request) = try liveRequest(material); defer { peer.close() }
        XCTAssertThrowsError(try live.answer(request,expected: request.requirement,publicKeyInfo: material.subjectPublicKeyInfo,
            verifyCurrent: {
                let value = checks.value.withLock { n in n += 1; return n }
                if value == 2 { request.close() }
            }))
    }

    func testExistingTLSIdentityAnswersTheExactRoleChallengeWithoutExportingItsKey() throws {
        let material = try material(), requirement = try requirement(material)
        let session = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        let key = try MachineUpdateTransportHealthKey.openOwned(identity: identity(material), publicKeyInfo: material.subjectPublicKeyInfo,
            requirement: requirement, expectedRequest: session.request, verifyCurrent: {})
        defer { key.close() }
        let reply = try key.answer(session.request)
        XCTAssertEqual(try session.accept(reply, authenticatePeer: { XCTAssertEqual($0, requirement) }).requirement, requirement)
    }
    func testBoundRequestRejectsAnotherNonceAndRetiresTheIdentity() throws {
        let material = try material(), requirement = try requirement(material)
        let first = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        let other = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        let key = try MachineUpdateTransportHealthKey.openOwned(identity: identity(material), publicKeyInfo: material.subjectPublicKeyInfo,
            requirement: requirement, expectedRequest: first.request, verifyCurrent: {})
        defer { key.close() }
        XCTAssertThrowsError(try key.answer(other.request))
        XCTAssertThrowsError(try key.answer(first.request))
    }
    func testWrongExpectedPublicKeyIsRejectedAndReleasesTheOwner() throws {
        let first = try material(), other = try material(), released = State(0)
        XCTAssertThrowsError(try MachineUpdateTransportHealthKey.openOwned(identity: identity(first), publicKeyInfo: first.subjectPublicKeyInfo,
            requirement: requirement(other), verifyCurrent: {}, release: { released.value.withLock { $0 += 1 } }))
        XCTAssertEqual(released.value.withLock { $0 }, 1)
    }
    func testWrongCertificatePinCannotReachTheSigningOperation() throws {
        let first = try material(), other = try material()
        XCTAssertThrowsError(try MachineUpdateTransportHealthKey.openOwned(identity: identity(first), publicKeyInfo: other.subjectPublicKeyInfo,
            requirement: requirement(other), verifyCurrent: {})) { XCTAssertEqual($0 as? ApprovalTransportStartupError, .invalidIdentity) }
    }
    func testClosedIdentityCannotAnswerAndReleasesOnlyOnce() throws {
        let material = try material(), requirement = try requirement(material), released = State(0)
        let key = try MachineUpdateTransportHealthKey.openOwned(identity: identity(material), publicKeyInfo: material.subjectPublicKeyInfo,
            requirement: requirement, verifyCurrent: {}, release: { released.value.withLock { $0 += 1 } })
        let session = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        key.close(); key.close(); XCTAssertThrowsError(try key.answer(session.request))
        XCTAssertEqual(released.value.withLock { $0 }, 1)
    }
    func testChangedOwnerCannotBeRevivedByRestoringTheFlag() throws {
        let material = try material(), requirement = try requirement(material), valid = State(true)
        let key = try MachineUpdateTransportHealthKey.openOwned(identity: identity(material), publicKeyInfo: material.subjectPublicKeyInfo,
            requirement: requirement, verifyCurrent: { guard valid.value.withLock({ $0 }) else { throw Failure.changed } })
        defer { key.close() }
        let session = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {}), request = try session.request
        valid.value.withLock { $0 = false }; XCTAssertThrowsError(try key.answer(request))
        valid.value.withLock { $0 = true }; XCTAssertThrowsError(try key.answer(request))
    }
    func testClosureDuringValidationCannotReturnAReply() throws {
        let material = try material(), requirement = try requirement(material), reference = State<MachineUpdateTransportHealthKey?>(nil)
        let key = try MachineUpdateTransportHealthKey.openOwned(identity: identity(material), publicKeyInfo: material.subjectPublicKeyInfo,
            requirement: requirement, verifyCurrent: { reference.value.withLock { $0 }?.close() })
        reference.value.withLock { $0 = key }
        defer { reference.value.withLock { $0 = nil }; key.close() }
        let session = try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {})
        XCTAssertThrowsError(try key.answer(session.request))
    }
    func testTransportIdentityCannotAnswerForAnotherRole() throws {
        let material = try material()
        let wrong = try MachineUpdateRoleChallengeTests.Fixture().requirement(publicKey: material.publicKeyX963)
        XCTAssertThrowsError(try MachineUpdateTransportHealthKey.openOwned(identity: identity(material), publicKeyInfo: material.subjectPublicKeyInfo,
            requirement: wrong, verifyCurrent: {}))
    }
}
