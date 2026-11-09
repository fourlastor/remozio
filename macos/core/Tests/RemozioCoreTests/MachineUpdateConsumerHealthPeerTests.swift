import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class MachineUpdateConsumerHealthPeerTests: XCTestCase {
    private final class State<Value: Sendable>: Sendable {
        let value: Mutex<Value>
        init(_ value: Value) { self.value = Mutex(value) }
    }
    private enum Failure: Error, Equatable { case denied, changed }
    private typealias Requirement = MachineUpdateRestartHealthPlan.Requirement
    private func requirement() throws -> Requirement {
        try MachineUpdateRoleChallengeTests.Fixture().requirement(role: .transport, uid: 20000)
    }
    private func peer(_ requirement: Requirement) -> MachineUpdateConsumerHealthPeer {
        .owned(expected: requirement, authenticateInvocation: {}, verifyPeer: {}, verifyCurrent: {})
    }
    private func request(_ requirement: Requirement) throws -> Data {
        try MachineUpdateRoleChallengeSession(requirement: requirement, verifyCurrent: {}).request
    }
    private func changingScope(_ bytes: Data, _ change: (inout [UInt64: CBORValue]) throws -> Void) throws -> Data {
        let limits = try CBORLimits(maxBytes: 20000, maxDepth: 2, maxItems: 64)
        guard case .map(var outer) = try DeterministicCBOR.decode(bytes, limits: limits),
              case .bytes(let scope) = outer[3], case .map(var fields) = try DeterministicCBOR.decode(scope, limits: limits) else {
            throw Failure.changed
        }
        try change(&fields); outer[3] = .bytes(try DeterministicCBOR.encode(.map(fields), limits: limits))
        return try DeterministicCBOR.encode(.map(outer), limits: limits)
    }
    func testUntrustedRequestDecoderPreservesEveryRoleAndEpochValue() throws {
        let fixture = MachineUpdateRoleChallengeTests.Fixture()
        for (role, uid) in [(AuthorityCodeRole.authority, UInt32(0)), (.transport, 20000), (.notificationGateway, 20001)] {
            let requirement = try fixture.requirement(role: role, uid: uid)
            XCTAssertEqual(try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(request(requirement)), requirement)
        }
    }
    func testRequestDecoderRejectsUnknownFieldsBoundsAndTrailingBytes() throws {
        let bytes = try request(requirement())
        XCTAssertThrowsError(try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(bytes + Data([0])))
        XCTAssertThrowsError(try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(Data(repeating: 0, count: 16481)))
        XCTAssertThrowsError(try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(changingScope(bytes) { $0[9] = .unsigned(1) }))
        XCTAssertThrowsError(try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(changingScope(bytes) { $0[1] = .bytes(Data(count: 15)) }))
        XCTAssertThrowsError(try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(changingScope(bytes) { $0[6] = .unsigned(UInt64(UInt32.max) + 1) }))
    }
    func testRequestDecoderRejectsForeignRoleCodeAndInvalidPublicKey() throws {
        let bytes = try request(requirement())
        XCTAssertThrowsError(try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(changingScope(bytes) { $0[5] = .unsigned(AuthorityCodeRole.app.rawValue) }))
        XCTAssertThrowsError(try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(changingScope(bytes) { $0[5] = .unsigned(AuthorityCodeRole.notificationGateway.rawValue) }))
        XCTAssertThrowsError(try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(changingScope(bytes) { $0[8] = .bytes(Data(count: 65)) }))
        XCTAssertThrowsError(try MachineUpdateRoleChallengeSession.decodeRequestedRequirement(changingScope(bytes) { $0[6] = .unsigned(0) }))
    }
    func testRootAuthenticationRunsBeforeParsingMalformedBytes() throws {
        let count = State(0), requirement = try requirement()
        let peer = MachineUpdateConsumerHealthPeer.owned(expected: requirement, authenticateInvocation: {
            count.value.withLock { $0 += 1 }; throw Failure.denied
        }, verifyPeer: { XCTFail("Reached peer verification after failed authentication") }, verifyCurrent: {})
        XCTAssertThrowsError(try peer.accept(Data([0]))) { XCTAssertEqual($0 as? Failure, .denied) }
        XCTAssertEqual(count.value.withLock { $0 }, 1)
        XCTAssertThrowsError(try peer.accept(request(requirement)))
        XCTAssertEqual(count.value.withLock { $0 }, 1)
    }
    func testAcceptedInvocationIssuesOnlyOneOwnerOpening() throws {
        let requirement = try requirement(), peer = peer(requirement), bytes = try request(requirement)
        let accepted = try peer.accept(bytes)
        XCTAssertEqual(accepted.requirement, requirement); XCTAssertEqual(accepted.bytes, bytes)
        try accepted.claim(); try accepted.validate()
        XCTAssertThrowsError(try accepted.claim())
        XCTAssertThrowsError(try peer.accept(bytes))
        try accepted.validate()
    }
    func testWrongLocalScopeConsumesTheConnection() throws {
        let first = try requirement(), second = try requirement(), peer = peer(first)
        XCTAssertThrowsError(try peer.accept(request(second)))
        XCTAssertThrowsError(try peer.accept(request(first)))
    }
    func testPeerClosureInvalidatesAnAlreadyClaimedRequest() throws {
        let requirement = try requirement(), peer = peer(requirement)
        let accepted = try peer.accept(request(requirement)); try accepted.claim()
        peer.close(); XCTAssertThrowsError(try accepted.validate())
        XCTAssertThrowsError(try accepted.claim())
    }
    func testChangedPeerCannotBeRevivedByRestoringItsFlag() throws {
        let requirement = try requirement(), valid = State(true)
        let peer = MachineUpdateConsumerHealthPeer.owned(expected: requirement, authenticateInvocation: {}, verifyPeer: {
            guard valid.value.withLock({ $0 }) else { throw Failure.changed }
        }, verifyCurrent: {})
        let accepted = try peer.accept(request(requirement))
        valid.value.withLock { $0 = false }; XCTAssertThrowsError(try accepted.claim())
        valid.value.withLock { $0 = true }; XCTAssertThrowsError(try accepted.validate())
    }
    func testClosureDuringScopeValidationCannotIssueARequest() throws {
        let requirement = try requirement(), reference = State<MachineUpdateConsumerHealthPeer?>(nil)
        let peer = MachineUpdateConsumerHealthPeer.owned(expected: requirement, authenticateInvocation: {}, verifyPeer: {},
            verifyCurrent: { reference.value.withLock { $0 }?.close() })
        reference.value.withLock { $0 = peer }; defer { reference.value.withLock { $0 = nil } }
        XCTAssertThrowsError(try peer.accept(request(requirement)))
    }

    func testGreetingAuthenticatesWithoutIssuingARequest() throws {
        let requirement = try requirement()
        let attempts = State(0)
        let peer = MachineUpdateConsumerHealthPeer.owned(expected: requirement, authenticateInvocation: {
            attempts.value.withLock { $0 += 1 }
        }, verifyPeer: {}, verifyCurrent: {})

        try peer.greet()
        XCTAssertEqual(attempts.value.withLock { $0 }, 1)
        XCTAssertThrowsError(try peer.greet())
        let accepted = try peer.accept(request(requirement))
        try accepted.claim()
        XCTAssertEqual(attempts.value.withLock { $0 }, 2)
    }

    func testFailedGreetingClosesThePeerBeforeAnotherInvocation() throws {
        let requirement = try requirement()
        let peer = MachineUpdateConsumerHealthPeer.owned(expected: requirement, authenticateInvocation: {
            throw Failure.denied
        }, verifyPeer: { XCTFail("Reached peer verification after failed authentication") }, verifyCurrent: {})

        XCTAssertThrowsError(try peer.greet()) { XCTAssertEqual($0 as? Failure, .denied) }
        XCTAssertThrowsError(try peer.accept(request(requirement))) {
            XCTAssertEqual($0 as? MachineUpdateRoleChallengeError, .unavailable)
        }
    }
}
