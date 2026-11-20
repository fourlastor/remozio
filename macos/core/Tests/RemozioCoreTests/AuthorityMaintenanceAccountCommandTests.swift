import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityMaintenanceAccountCommandTests: XCTestCase, @unchecked Sendable {
    private actor CaptureGate {
        var entered = false
        private var continuation: CheckedContinuation<Void, Never>?
        func hold() async { await withCheckedContinuation { entered = true; continuation = $0 } }
        func release() { continuation?.resume(); continuation = nil }
    }
    private func waitUntil(_ condition: () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !(await condition()) {
            guard ContinuousClock.now < deadline else { throw GatewayRootChannelError.timedOut }
            try await Task.sleep(for: .milliseconds(5))
        }
    }
    private func work() throws -> AuthorityMaintenanceChannelWork {
        try .init(journal: .init(requests: .init(liveRequests: 0, commandCaptures: 0, activityOwners: 0),
            exchanges: .init(active: 0, stopped: false), nativeExecutions: 0, executionActivityOwners: 0),
            execution: .init(started: true, stopping: false, failed: false, queuedTurns: 0, rejectedTurns: 0),
            pairing: .init(ready: true, stagedAttempts: 0, activityOwners: 0, operationActive: false))
    }
    private func request() throws -> AuthorityMaintenanceChannelRequest {
        try .init(action: .open, accountID: unboundAuthorityBytes(3), attemptID: unboundAuthorityBytes(16),
            revision: unboundAuthorityBytes(17), installationID: unboundAuthorityBytes(2),
            gate: .init(device: 1, inode: 2), binding: nil, challenge: unboundAuthorityBytes(42, 32))
    }
    private func exchange(_ endpoint: AuthorityMaintenanceXPCEndpoint,
        _ request: AuthorityMaintenanceChannelRequest) async throws -> AuthorityMaintenanceChannelResponse {
        let payload = try request.encoded
        let bytes: Data? = await withCheckedContinuation { continuation in
            endpoint.exchange(payload) { continuation.resume(returning: $0) }
        }
        return try .decode(XCTUnwrap(bytes), expected: request)
    }
    func testTwoConnectionsShareTheAccountGuardBeforeTheirFirstStateCheck() async throws {
        let commands = AuthorityMaintenanceCommandExclusion(), gate = CaptureGate(), checks = Mutex(0)
        let pairing = try AuthorityMaintenancePairingAdmission(accountID: unboundAuthorityBytes(3), incarnation: unboundAuthorityBytes(41))
        let actualWork = try work()
        let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: pairing, commandExclusion: commands,
            check: { _ in checks.withLock { $0 += 1 } }, observe: { _ in if !(await gate.entered) { await gate.hold() }; return actualWork })
        let first = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access, budget: .init(maximum: 2))
        let second = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access, budget: .init(maximum: 2))
        defer { first.close(); second.close() }
        let request = try request(), running = Task { try await exchange(first, request) }
        try await waitUntil { await gate.entered }; let before = checks.withLock { $0 }
        let waiting = Task { try await exchange(second, request) }
        try await waitUntil { commands.waitingCommands == 1 }
        XCTAssertEqual(checks.withLock { $0 }, before); XCTAssertEqual(try pairing.connectionReservations(), 0)
        await gate.release(); let applied = try await running.value, next = try await waiting.value
        XCTAssertEqual(applied.outcome, .applied); XCTAssertEqual(next.outcome, .applied)
        XCTAssertEqual(try pairing.connectionReservations(), 2)
    }
    func testACommandAfterStopStartsDoesNotReachTheStateReader() async throws {
        let commands = AuthorityMaintenanceCommandExclusion(), checks = Mutex(0)
        let pairing = try AuthorityMaintenancePairingAdmission(accountID: unboundAuthorityBytes(3), incarnation: unboundAuthorityBytes(41))
        let actualWork = try work()
        let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: pairing, commandExclusion: commands,
            check: { _ in checks.withLock { $0 += 1 } }, observe: { _ in return actualWork })
        let endpoint = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access, budget: .init(maximum: 1)); defer { endpoint.close() }
        let stop = try await commands.beginStop(); try stop.validate()
        let refused = try await exchange(endpoint, request())
        XCTAssertEqual(refused.outcome, .refused)
        XCTAssertEqual(checks.withLock { $0 }, 0); XCTAssertEqual(try pairing.connectionReservations(), 0)
    }
    func testClosingAWaitingConnectionRepliesNothingAndTouchesNoState() async throws {
        let commands = AuthorityMaintenanceCommandExclusion(), checks = Mutex(0), replies = Mutex(0)
        let pairing = try AuthorityMaintenancePairingAdmission(accountID: unboundAuthorityBytes(3), incarnation: unboundAuthorityBytes(41))
        let actualWork = try work(), command = try commands.acquire(); defer { command.close() }
        let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: pairing, commandExclusion: commands,
            check: { _ in checks.withLock { $0 += 1 } }, observe: { _ in actualWork })
        let endpoint = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access, budget: .init(maximum: 1))
        endpoint.exchange(try request().encoded) { _ in replies.withLock { $0 += 1 } }
        try await waitUntil { commands.waitingCommands == 1 }; await endpoint.closeAndWait()
        XCTAssertEqual(commands.waitingCommands, 0); XCTAssertEqual(endpoint.pendingOperations(), 0)
        XCTAssertEqual(checks.withLock { $0 }, 0); XCTAssertEqual(replies.withLock { $0 }, 0)
        XCTAssertEqual(try pairing.connectionReservations(), 0); try command.validate()
    }
    func testBusyGateReadKeepsTheConnectionOpenAndDoesNotReadStorage() async throws {
        let commands = AuthorityMaintenanceCommandExclusion(), reads = Mutex(0)
        let pairing = try AuthorityMaintenancePairingAdmission(accountID: unboundAuthorityBytes(3), incarnation: unboundAuthorityBytes(41))
        let actualWork = try work(), records = try UnboundAuthorityRecords(), q = try request()
        let target = try pairing.refusalBinding(accountID: q.accountID, attemptID: q.attemptID, revision: q.revision)
        let hold = AuthorityMaintenanceAdmissionHold(projection: try records.projection(records.authorized))
        let pending = try RuntimeMaintenanceWindowRecord(id: records.authorized.id, revision: unboundAuthorityBytes(90),
            purpose: .retainedRuntime, scope: records.authorized.scope, phase: .reopenPending,
            service: .notStopped, shutdownBinding: target)
        try hold.reopen(pending, binding: target, incarnation: unboundAuthorityBytes(41), releaseBinding: {})
        let command = try commands.acquire(); defer { command.close() }
        let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: pairing, commandExclusion: commands,
            check: { _ in XCTFail("A busy gate read checked storage") }, observe: { _ in actualWork },
            readGate: { _ in reads.withLock { $0 += 1 }; throw RuntimePreparationError.changedScope },
            readBusyGateHold: { try hold.gateHold(attemptID: $0.attemptID) })
        let endpoint = try AuthorityMaintenanceXPCEndpoint.openOwned(access: access, budget: .init(maximum: 1)); defer { endpoint.close() }
        endpoint.hello { XCTAssertEqual($0, AuthorityMaintenanceChannelScope.protocolVersion) }
        let gate = try AuthorityMaintenanceGateRequest(accountID: q.accountID, attemptID: q.attemptID, revision: pending.revision,
            installationID: q.installationID, gate: q.gate, target: target, challenge: unboundAuthorityBytes(42))
        let payload = try gate.encoded
        let bytes: Data? = await withCheckedContinuation { continuation in endpoint.readGate(payload) { continuation.resume(returning: $0) } }
        let response = try AuthorityMaintenanceGateResponse.decode(XCTUnwrap(bytes), expected: gate)
        XCTAssertEqual(response.hold, .released); XCTAssertEqual(response.admission, .busy)
        let readback = try response.readback(expectedIncarnation: unboundAuthorityBytes(41))
        XCTAssertEqual(readback.hold, .released); XCTAssertEqual(readback.admission, .busy)
        XCTAssertEqual(reads.withLock { $0 }, 0)
        endpoint.hello { XCTAssertEqual($0, AuthorityMaintenanceChannelScope.protocolVersion) }
    }

}
