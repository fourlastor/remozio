import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class SetupRetainedOrphanClaimTests: XCTestCase, @unchecked Sendable {
    private typealias Invocation = SetupRetainedInvocation
    private typealias Claim = SetupRetainedOrphanClaim
    private typealias Authorization = SetupRetainedRecoveryAuthorization
    private enum Failure: Error { case expected, timeout }
    private final class InvocationCell: @unchecked Sendable { var value: Invocation? }
    private final class ClaimCell: @unchecked Sendable { weak var value: Claim? }
    private struct ClaimFailure: Error { let retained: Claim }
    private final class Gate: @unchecked Sendable {
        private let state = Mutex<(Bool, CheckedContinuation<Void, Never>?)>((false, nil))
        let parked = DispatchSemaphore(value: 0)
        func worker() -> Task<Void, Never> {
            Task {
                await withCheckedContinuation { continuation in
                    let ready = state.withLock { state in
                        if state.0 { return true }; state.1 = continuation; return false
                    }
                    if ready { continuation.resume() }
                    parked.signal()
                }
            }
        }
        func finish() {
            let continuation = state.withLock { state in
                state.0 = true; let old = state.1; state.1 = nil; return old
            }
            continuation?.resume()
        }
        deinit { finish() }
    }
    private final class JoinProbe: @unchecked Sendable {
        let done = DispatchSemaphore(value: 0), finished = Mutex(false), failed = Mutex(false)
        let result = Mutex<Claim.Joined?>(nil)
        init(_ claim: Claim) {
            let work = Task {
                do { let joined = try await claim.join(); result.withLock { $0 = joined } }
                catch { failed.withLock { $0 = true } }
            }
            Task { await work.value; finished.withLock { $0 = true }; done.signal() }
        }
        func wait() throws -> Claim.Joined {
            guard done.wait(timeout: .now() + 3) == .success else { throw Failure.timeout }
            if failed.withLock({ $0 }) { throw Failure.expected }
            return try XCTUnwrap(result.withLock { $0 })
        }
        func waitForFailure() throws {
            guard done.wait(timeout: .now() + 3) == .success else { throw Failure.timeout }
            XCTAssertTrue(failed.withLock { $0 }); XCTAssertNil(result.withLock { $0 })
        }
    }
    private final class VoidProbe: @unchecked Sendable {
        let done = DispatchSemaphore(value: 0), failed = Mutex(false)
        init(_ body: @escaping @Sendable () async throws -> Void) {
            let work = Task { do { try await body() } catch { failed.withLock { $0 = true } } }
            Task { await work.value; done.signal() }
        }
        func wait() throws {
            guard done.wait(timeout: .now() + 3) == .success else { throw Failure.timeout }
            XCTAssertFalse(failed.withLock { $0 })
        }
    }
    private final class Frame: @unchecked Sendable {
        let fixture: RetainedMaterialWriterFixture
        let owner: SetupAccountOwner, installer: ReleaseActivityBarrier
        let binding: SetupRetainedCallerBinding, policy: XPCPeerPolicy
        let connection: NSXPCConnection, guardValue: XPCInvocationGuard
        let capture: SetupAccountOwner.RetainedMaintenanceCapture
        init(_ f: RetainedMaterialWriterFixture, activity: ReleaseActivityFixture) throws {
            let machine = try f.machine(), state = try machine.retainedSetupCallerState(candidate: f.candidate)
            let entry = try machine.retainedSetupInitialRuntimeEntry(owner: f.owner, candidate: f.candidate)
            let member = try XCTUnwrap(state.source.actual.inventory.accounts.first)
            let (_, host) = try MachineUpdateRetainedSetupPolicyNativeEntry.publishedAuthority(runtime: entry.runtime, accountID: member.accountID)
            let app = try XCTUnwrap(host.codePolicy.entries.first { $0.role == .app && $0.active })
            let peer = XPCPeerCredentials(processID: getpid(), userID: member.ownerUID, auditSessionID: 1)
            let accepted = try XPCPeerPolicy(teamID: app.teamID, componentIdentifier: app.identifier,
                approvedCodeDirectoryHashes: [app.codeDirectoryHash], expectedUserID: peer.userID)
            let actualConnection = NSXPCConnection(machServiceName: AdministrativeSetupConfiguration.serviceName)
            let exported = XPCInvocationGuard(connection: actualConnection, policy: accepted)
            let captured = try SetupRetainedCallerBinding.resolve(state: state, peer: peer, incarnation: exported.incarnation,
                accepted: accepted, entry: entry, lookup: { uid in
                    let account = try XCTUnwrap(state.source.preparations.first { $0.ownerUID == uid })
                    return .init(uid: uid, primaryGroupID: getgid(), directoryID: account.directoryID)
                })
            let inputs = try MachineUpdateRetainedSetupRuntimeInputs.capture(expected: entry.runtime, journal: nil,
                verifyCurrent: {}, readRelay: { _ in throw SharedSetupImportError.wrongScope })
            fixture = f; installer = try activity.open(); policy = accepted; connection = actualConnection; guardValue = exported
            binding = captured; capture = try .openOwned(binding: captured, inputs: inputs)
            owner = try .init(machine: machine, expectedReleaseDigest: InstallationInventory.digest(f.candidate),
                resume: { _, value in value }, releaseActivity: activity.open())
        }
        func invocation(captured: Bool = true, closeRights: @escaping () -> Void = {}) throws -> Invocation {
            let binding = self.binding, capture = self.capture
            let value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {}, closeRights: closeRights,
                ownedCapture: .init(invocation: guardValue, verifyPeer: { binding.peer }, binding: { binding }, maintenance: { capture }))
            if captured { try value.captureOwnedBinding(binding) }
            return value
        }
        func authorize(peer: XPCPeerCredentials? = nil, identity: LocalAccountIdentity? = nil, incarnation: UUID = UUID(),
            verify: @escaping () throws -> Void = {}, close: @escaping () -> Void = {}) throws -> Authorization {
            try .openOwned(peer: peer ?? binding.peer, currentOwner: identity ?? binding.authorityOwner,
                incarnation: incarnation, verifyRights: verify, closeRights: close)
        }
        func claim(_ authorization: Authorization? = nil, target: Claim.Target? = nil) throws -> Claim {
            let rights: Authorization
            if let authorization { rights = authorization } else { rights = try authorize() }
            let exact = try target ?? Claim.Target.capture(owner: owner, authorization: rights)
            return try .open(owner: owner, target: exact, authorization: rights)
        }
        func window(_ value: Invocation) throws {
            let actual = try value.maintenanceCapture(invocation: guardValue, candidate: fixture.candidate, purpose: .retainedRuntime)
            _ = try value.authorizedMaintenanceWindow(invocation: guardValue, expected: actual, purpose: .retainedRuntime,
                candidate: fixture.candidate, id: Data(repeating: 0xa1, count: 16), revision: Data(repeating: 0xa2, count: 16))
        }
        func lose(_ value: inout Invocation?) throws {
            weak var old = value; value = nil; XCTAssertNil(old)
            XCTAssertEqual(try owner.retainedInvocationState(), .orphan)
        }
        var status: SetupRetainedInvocationStatus {
            owner.retainedInvocationStatus(authenticatedPeer: binding.peer, currentOwner: binding.authorityOwner)
        }
        func assertHeld() {
            XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
            XCTAssertThrowsError(try installer.acquireExclusive())
        }
        func assertReleased() throws {
            XCTAssertEqual(try owner.retainedInvocationState(), .settled)
            let exclusive = try installer.acquireExclusive(); exclusive.close()
            try owner.verifyCurrent(); let reply = try owner.acquireSetupReplyAdmission(); reply.close()
        }
        deinit { connection.invalidate(); try? owner.close() }
    }
    private func withFrame(_ body: (Frame) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let activity = try ReleaseActivityFixture(); try body(Frame(f, activity: activity))
        }
    }
    private func joined(_ claim: Claim) throws -> Claim.Joined { try JoinProbe(claim).wait() }

    func testUnboundOrphanReleasesAfterActualCleanupWhileOwnerClosesAdmission() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation(captured: false)
            let stack = Mutex<Int>(0), calls = Mutex(0)
            try value?.retainCleanup { stack.withLock { $0 = pthread_get_stacksize_np(pthread_self()) }; calls.withLock { $0 += 1 } }
            try f.lose(&value); XCTAssertEqual(f.status.identity, .unavailable); f.assertHeld()
            XCTAssertThrowsError(try f.owner.close())
            let closing = VoidProbe { try await f.owner.closeWhenIdle() }
            let claim = try f.claim(), actual = try joined(claim)
            XCTAssertTrue(actual.evidence.windowWriteNeverPossible); XCTAssertTrue(actual.evidence.invocationCleanupReturned)
            XCTAssertGreaterThanOrEqual(stack.withLock { $0 }, SetupAuditUpgradeWorkExecutor.stackBytes)
            XCTAssertEqual(calls.withLock { $0 }, 1); XCTAssertTrue(try actual.releaseIfWindowFree())
            try closing.wait(); let exclusive = try f.installer.acquireExclusive(); exclusive.close()
        }
    }
    func testCapturedOrphanWithoutBodyOrWindowReleasesOnlyAfterJoin() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation(); try f.lose(&value)
            let claim = try f.claim(); f.assertHeld()
            let actual = try joined(claim)
            XCTAssertTrue(actual.evidence.neverEntered); XCTAssertTrue(actual.evidence.stopNeverPossible)
            XCTAssertTrue(try actual.releaseIfWindowFree()); try f.assertReleased()
        }
    }
    func testEnteredBodyWithCapturedBindingButNoWindowCanReleaseAfterCleanup() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation()
            try value?.run(work: {}, reply: { _, _ in }); try f.lose(&value)
            let actual = try joined(f.claim())
            XCTAssertFalse(actual.evidence.neverEntered); XCTAssertFalse(actual.evidence.stopNeverPossible)
            XCTAssertTrue(actual.evidence.windowWriteNeverPossible); XCTAssertTrue(try actual.releaseIfWindowFree())
            XCTAssertEqual(f.status.operation, .unavailable); try f.assertReleased()
        }
    }
    func testRegisteredWorkerWithoutWindowNeedsItsActualReturnDespiteCancellation() throws {
        try withFrame { f in
            let gate = Gate(); defer { gate.finish() }
            var value: Invocation? = try f.invocation(); let worker = gate.worker()
            try value?.retainWorker(worker); XCTAssertEqual(gate.parked.wait(timeout: .now() + 3), .success)
            XCTAssertEqual(f.status.worker, .observed(.registered)); XCTAssertEqual(f.status.cleanup, .observed(.noneRegistered))
            try f.lose(&value); let claim = try f.claim(), pending = JoinProbe(claim)
            XCTAssertFalse(pending.finished.withLock { $0 }); f.assertHeld(); worker.cancel()
            XCTAssertFalse(pending.finished.withLock { $0 }); gate.finish()
            let actual = try pending.wait()
            XCTAssertEqual(actual.evidence.workersRegistered, 1); XCTAssertEqual(actual.evidence.workersJoined, 1)
            XCTAssertFalse(actual.evidence.neverEntered); XCTAssertTrue(try actual.releaseIfWindowFree()); try f.assertReleased()
        }
    }
    func testAuthorizedMetadataKeepsTokensEvenWhenNoDurableWriteWasObserved() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation(); try f.window(XCTUnwrap(value)); try f.lose(&value)
            let actual = try joined(f.claim())
            XCTAssertTrue(actual.evidence.neverEntered); XCTAssertFalse(actual.evidence.windowWriteNeverPossible)
            XCTAssertFalse(try actual.releaseIfWindowFree()); f.assertHeld()
            XCTAssertEqual(f.status.reservation, .observed(.recovering)); XCTAssertEqual(f.status.operation, .unavailable)
        }
    }
    func testLiveReservedAndSettledRecordsCannotBeClaimed() throws {
        try withFrame { f in
            let authorization = try f.authorize(); defer { authorization.close() }
            let reservation = try f.owner.reserveRetainedInvocation(authenticatedPeer: f.binding.peer, incarnation: f.binding.incarnation,
                authenticatedOwner: f.binding.authorityOwner)
            XCTAssertThrowsError(try Claim.Target.capture(owner: f.owner, authorization: authorization)); reservation.record.abortConstruction()
            let value = try f.invocation(); XCTAssertThrowsError(try Claim.Target.capture(owner: f.owner, authorization: authorization))
            try value.close(); XCTAssertThrowsError(try Claim.Target.capture(owner: f.owner, authorization: authorization))
        }
    }
    func testWrongOwnerTargetOwnerRecycledDirectoryAndOldIncarnationRefuse() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation(); try f.lose(&value)
            let target = XPCPeerCredentials(processID: getpid(), userID: f.binding.targetOwner.uid, auditSessionID: 1)
            let recycled = LocalAccountIdentity(uid: f.binding.authorityOwner.uid, primaryGroupID: getgid(), directoryID: UUID())
            let wrong = [try f.authorize(peer: target, identity: f.binding.targetOwner), try f.authorize(identity: recycled),
                try f.authorize(incarnation: f.binding.incarnation)]
            for rights in wrong { defer { rights.close() }; XCTAssertThrowsError(try Claim.Target.capture(owner: f.owner, authorization: rights)) }
            XCTAssertEqual(f.owner.retainedInvocationStatus(authenticatedPeer: f.binding.peer, currentOwner: recycled), .unavailable)
            f.assertHeld(); XCTAssertTrue(try joined(f.claim()).releaseIfWindowFree())
        }
    }
    func testExactTargetCannotSelectAnotherOwnerRecord() throws {
        try withFrame { first in
            var a: Invocation? = try first.invocation(); try first.lose(&a)
            let rights = try first.authorize(), target = try Claim.Target.capture(owner: first.owner, authorization: rights)
            try withFrame { second in
                var b: Invocation? = try second.invocation(); try second.lose(&b)
                XCTAssertThrowsError(try Claim.open(owner: second.owner, target: target, authorization: rights))
                first.assertHeld(); second.assertHeld(); XCTAssertTrue(try joined(second.claim()).releaseIfWindowFree())
            }
            XCTAssertTrue(try joined(first.claim()).releaseIfWindowFree())
        }
    }
    func testAnAuthorizationCanBeConsumedOnlyOnceAndCannotStealAnotherAdmission() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation(); try f.lose(&value)
            let rights = try f.authorize(), target = try Claim.Target.capture(owner: f.owner, authorization: rights)
            try rights.takeForClaim()
            XCTAssertThrowsError(try Claim.open(owner: f.owner, target: target, authorization: rights)); f.assertHeld()
            XCTAssertThrowsError(try f.owner.reserveRetainedInvocation(authenticatedPeer: f.binding.peer, incarnation: UUID()))
            XCTAssertTrue(try joined(f.claim()).releaseIfWindowFree()); try f.assertReleased()
        }
    }
    func testOnlyOneLiveClaimExistsAndFreshClaimCanFollowExplicitAbandon() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation(); try f.lose(&value)
            let first = try f.claim(); XCTAssertThrowsError(try f.claim()); first.abandon()
            let second = try f.claim(), actual = try joined(second)
            XCTAssertThrowsError(try JoinProbe(first).wait()); XCTAssertTrue(try actual.releaseIfWindowFree()); try f.assertReleased()
        }
    }
    func testDeinitRightsReturnIsRequiredAfterStatusAlreadyShowsOrphan() throws {
        try withFrame { f in
            let cell = InvocationCell(), entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0)
            let dropped = DispatchSemaphore(value: 0)
            defer { resume.signal(); _ = dropped.wait(timeout: .now() + 3) }
            cell.value = try f.invocation(closeRights: { entered.signal(); _ = resume.wait(timeout: .now() + 3) })
            DispatchQueue.global().async { cell.value = nil; dropped.signal() }
            XCTAssertEqual(entered.wait(timeout: .now() + 3), .success); XCTAssertEqual(f.status.reservation, .observed(.orphan))
            let pending = JoinProbe(try f.claim()); XCTAssertFalse(pending.finished.withLock { $0 }); f.assertHeld()
            resume.signal(); let actual = try pending.wait()
            XCTAssertTrue(actual.evidence.invocationCleanupReturned); XCTAssertTrue(try actual.releaseIfWindowFree())
        }
    }
    func testRightsExpiryDoesNotStopCleanupAndFreshClaimReusesTheCompletedJoin() throws {
        try withFrame { f in
            let valid = Mutex(true), entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0), calls = Mutex(0)
            defer { resume.signal() }
            var value: Invocation? = try f.invocation()
            try value?.retainCleanup { calls.withLock { $0 += 1 }; entered.signal(); _ = resume.wait(timeout: .now() + 3) }
            try f.lose(&value)
            let rights = try f.authorize(verify: { if !valid.withLock({ $0 }) { throw Failure.expected } })
            let first = try f.claim(rights), pending = JoinProbe(first)
            XCTAssertEqual(entered.wait(timeout: .now() + 3), .success); valid.withLock { $0 = false }; resume.signal()
            let actual = try pending.wait(); XCTAssertThrowsError(try actual.releaseIfWindowFree()); f.assertHeld(); first.abandon()
            let renewed = try joined(f.claim()); XCTAssertEqual(calls.withLock { $0 }, 1)
            XCTAssertTrue(try renewed.releaseIfWindowFree()); try f.assertReleased()
        }
    }
    func testAbandonDuringBlockedJoinKeepsActualCleanupAndInvalidatesOldWaiter() throws {
        try withFrame { f in
            let entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0), calls = Mutex(0)
            defer { resume.signal() }
            var value: Invocation? = try f.invocation()
            try value?.retainCleanup { calls.withLock { $0 += 1 }; entered.signal(); _ = resume.wait(timeout: .now() + 3) }
            try f.lose(&value)
            let first = try f.claim(), oldWaiter = JoinProbe(first)
            XCTAssertEqual(entered.wait(timeout: .now() + 3), .success); first.abandon()
            let current = try f.claim(), newWaiter = JoinProbe(current)
            XCTAssertFalse(newWaiter.finished.withLock { $0 }); f.assertHeld(); resume.signal()
            try oldWaiter.waitForFailure(); let actual = try newWaiter.wait()
            XCTAssertEqual(calls.withLock { $0 }, 1); XCTAssertTrue(try actual.releaseIfWindowFree()); try f.assertReleased()
        }
    }
    func testFailedTaskCanReleaseAnErrorOwnedClaimOutsideTheOwnerAndRecordLocks() throws {
        try withFrame { f in
            let cell = ClaimCell(), calls = Mutex(0)
            var value: Invocation? = try f.invocation()
            try value?.retainCleanup {
                let attempt = calls.withLock { $0 += 1; return $0 }
                if attempt == 1 { throw ClaimFailure(retained: try XCTUnwrap(cell.value)) }
            }
            try f.lose(&value)
            var first: Claim? = try f.claim(); cell.value = first; weak var old = first
            try JoinProbe(XCTUnwrap(first)).waitForFailure(); first?.abandon(); first = nil
            XCTAssertNotNil(old); f.assertHeld()
            let current = try f.claim(), actual = try joined(current)
            XCTAssertNil(old); XCTAssertEqual(calls.withLock { $0 }, 2)
            XCTAssertTrue(try actual.releaseIfWindowFree()); try f.assertReleased()
        }
    }
    func testSuccessfulCleanupIsNotRepeatedWhenAnExplicitRetryClosesAFailedOwner() throws {
        try withFrame { f in
            let succeeded = Mutex(0), failing = Mutex(0)
            var value: Invocation? = try f.invocation()
            try value?.retainCleanup { let n = failing.withLock { $0 += 1; return $0 }; if n == 1 { throw Failure.expected } }
            try value?.retainCleanup { succeeded.withLock { $0 += 1 } }
            try f.lose(&value); let first = try f.claim(); try JoinProbe(first).waitForFailure()
            XCTAssertEqual(succeeded.withLock { $0 }, 1); f.assertHeld(); first.abandon()
            let actual = try joined(f.claim()); XCTAssertEqual(succeeded.withLock { $0 }, 1); XCTAssertEqual(failing.withLock { $0 }, 2)
            XCTAssertTrue(try actual.releaseIfWindowFree())
        }
    }
    func testRealContextLoanReturnsWithoutResettingTheBodyAndStopMarkers() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation()
            let rights = try f.authorize(); defer { rights.close() }
            do {
                let actual = try XCTUnwrap(value)
                try actual.installOwnedContext(connection: f.connection, readPeer: { _ in f.binding.peer })
                try actual.run(work: {
                    try actual.withWorkerContext { scope in
                        try scope.verify(); XCTAssertThrowsError(try Claim.Target.capture(owner: f.owner, authorization: rights))
                    }
                }, reply: { _, _ in })
            }
            try f.lose(&value)
            let actual = try joined(f.claim(rights))
            XCTAssertEqual(actual.evidence.contextLoansStarted, 1); XCTAssertEqual(actual.evidence.contextLoansReturned, 1)
            XCTAssertFalse(actual.evidence.neverEntered); XCTAssertFalse(actual.evidence.stopNeverPossible)
            XCTAssertTrue(try actual.releaseIfWindowFree()); try f.assertReleased()
        }
    }
    func testNormalCloseRefusesRegisteredWorkersUntilTheirActualJoin() throws {
        try withFrame { f in
            let gate = Gate(); defer { gate.finish() }
            let value = try f.invocation(), worker = gate.worker(); try value.retainWorker(worker)
            XCTAssertThrowsError(try value.close()); f.assertHeld()
            let pending = VoidProbe { try await value.joinRegisteredWorkers() }
            gate.finish(); try pending.wait(); try value.close(); try f.assertReleased()
        }
    }
    func testUnknownExecutorAndZeroCountersDoNotCreateJoinedEvidence() throws {
        let ledger = SetupRetainedRecoveryLedger(executor: nil); ledger.invocationCleanupReturned()
        let retired = try ledger.sealForClaim(); withExtendedLifetime(retired) {}
        let task = try ledger.joinSealed(), done = DispatchSemaphore(value: 0), failed = Mutex(false)
        Task { do { try await task.value } catch { failed.withLock { $0 = true } }; done.signal() }
        XCTAssertEqual(done.wait(timeout: .now() + 3), .success); XCTAssertTrue(failed.withLock { $0 })
        XCTAssertThrowsError(try ledger.requireJoined()); XCTAssertThrowsError(try ledger.beginWorker())
        XCTAssertThrowsError(try ledger.retainCleanup {})
    }
    func testEnteredMarkersSurviveAbandonAndASecondFreshClaim() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation()
            XCTAssertThrowsError(try value?.run(work: { throw Failure.expected }, reply: { _, _ in XCTFail("Unexpected reply") }))
            try f.lose(&value); let first = try f.claim(), old = try joined(first)
            XCTAssertFalse(old.evidence.neverEntered); XCTAssertFalse(old.evidence.stopNeverPossible); first.abandon()
            let current = try joined(f.claim()); XCTAssertEqual(current.evidence, old.evidence)
            XCTAssertThrowsError(try old.releaseIfWindowFree()); XCTAssertTrue(try current.releaseIfWindowFree())
            XCTAssertEqual(f.status.operation, .unavailable)
        }
    }
    func testRecoveryObjectsRedactIdentityAndRefuseForkedAuthorization() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation(); try f.lose(&value)
            let rights = try f.authorize(), target = try Claim.Target.capture(owner: f.owner, authorization: rights)
            let child = Self.forkProcess(); XCTAssertGreaterThanOrEqual(child, 0)
            if child == 0 { do { try rights.requireCurrent(); _exit(11) } catch { _exit(0) } }
            if child > 0 {
                var status: Int32 = 0; let deadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000; var reaped = false
                while DispatchTime.now().uptimeNanoseconds < deadline {
                    if waitpid(child, &status, WNOHANG) == child { reaped = true; break }; usleep(10_000)
                }
                if !reaped { _ = kill(child, SIGKILL); while waitpid(child, &status, 0) < 0 && errno == EINTR {} }
                XCTAssertTrue(reaped); XCTAssertEqual(status, 0)
            }
            let claim = try Claim.open(owner: f.owner, target: target, authorization: rights), actual = try joined(claim)
            for object in [rights as Any, target as Any, claim as Any, actual as Any] {
                XCTAssertTrue(Mirror(reflecting: object).children.isEmpty)
                var output = ""; dump(object, to: &output); XCTAssertFalse(output.contains(f.binding.incarnation.uuidString))
            }
            XCTAssertTrue(try actual.releaseIfWindowFree())
        }
    }
    private static let forkProcess: @convention(c) () -> pid_t = {
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "fork") else { preconditionFailure("fork unavailable") }
        return unsafeBitCast(symbol, to: (@convention(c) () -> pid_t).self)
    }()
}
