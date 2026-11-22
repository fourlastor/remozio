import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class SetupRetainedOrphanClaimTests: XCTestCase, @unchecked Sendable {
    typealias Invocation = SetupRetainedInvocation
    typealias Claim = SetupRetainedOrphanClaim
    typealias Authorization = SetupRetainedRecoveryAuthorization
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
        private var work: Task<Void, Never>?
        init(_ claim: Claim) {
            let work = Task {
                do { let joined = try await claim.join(); result.withLock { $0 = joined } }
                catch { failed.withLock { $0 = true } }
            }
            self.work = work
            Task { await work.value; finished.withLock { $0 = true }; done.signal() }
        }
        func cancel() { work?.cancel() }
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
    private final class RestorationProbe: @unchecked Sendable {
        typealias Work = SetupRetainedInvocationReservation.RestorationWork
        let done = DispatchSemaphore(value: 0), failed = Mutex(false), result = Mutex<Work?>(nil)
        init(_ joined: Claim.Joined,
            body: @escaping @Sendable (UUID) async throws -> RuntimeMaintenanceStartupRecovery.ExplicitCompletion) {
            let starting = Task {
                do { let work = try await joined.startRestoration(body); result.withLock { $0 = work } }
                catch { failed.withLock { $0 = true } }
            }
            Task { await starting.value; done.signal() }
        }
        func wait() throws -> Work {
            guard done.wait(timeout: .now() + 3) == .success else { throw Failure.timeout }
            XCTAssertFalse(failed.withLock { $0 }); return try XCTUnwrap(result.withLock { $0 })
        }
        func waitForRefusal() throws {
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
    final class Frame: @unchecked Sendable {
        let candidate: SignedReleaseEvidence
        let owner: SetupAccountOwner, installer: ReleaseActivityBarrier
        let binding: SetupRetainedCallerBinding, policy: XPCPeerPolicy
        let connection: NSXPCConnection, guardValue: XPCInvocationGuard
        let capture: SetupAccountOwner.RetainedMaintenanceCapture
        convenience init(_ f: RetainedMaterialWriterFixture, activity: ReleaseActivityFixture) throws {
            try self.init(machine: f.machine(), candidate: f.candidate, targetOwner: f.owner, activity: activity)
        }
        init(machine: PreparationIntentStore, candidate: SignedReleaseEvidence,
            targetOwner: LocalAccountIdentity, activity: ReleaseActivityFixture) throws {
            let state = try machine.retainedSetupCallerState(candidate: candidate)
            let entry = try machine.retainedSetupInitialRuntimeEntry(owner: targetOwner, candidate: candidate)
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
            self.candidate = candidate; installer = try activity.open(); policy = accepted; connection = actualConnection; guardValue = exported
            binding = captured; capture = try .openOwned(binding: captured, inputs: inputs)
            owner = try .init(machine: machine, expectedReleaseDigest: InstallationInventory.digest(candidate),
                resume: { _, value in value }, lookupAccount: { uid in
                    if uid == captured.authorityOwner.uid { return captured.authorityOwner }
                    if uid == captured.targetOwner.uid { return captured.targetOwner }
                    return try LocalAccountDirectory.lookup(uid: uid)
                }, releaseActivity: activity.open())
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
        func claim(_ authorization: Authorization? = nil, target: Claim.Target? = nil,
            shutdownSession: AdministrativeSetupShutdown.RecoverySessionWork? = nil) throws -> Claim {
            let rights: Authorization
            if let authorization { rights = authorization } else { rights = try authorize() }
            let exact = try target ?? Claim.Target.capture(owner: owner, authorization: rights)
            return try .open(owner: owner, target: exact, authorization: rights, shutdownSession: shutdownSession)
        }
        func window(_ value: Invocation, id: Data = Data(repeating: 0xa1, count: 16),
            revision: Data = Data(repeating: 0xa2, count: 16)) throws {
            let actual = try value.maintenanceCapture(invocation: guardValue, candidate: candidate, purpose: .retainedRuntime)
            _ = try value.authorizedMaintenanceWindow(invocation: guardValue, expected: actual, purpose: .retainedRuntime,
                candidate: candidate, id: id, revision: revision)
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
    func testJoinedRefusesAForeignRealTokenWithoutReleasingEitherReservation() throws {
        try withFrame { first in
            var a: Invocation? = try first.invocation(); try first.lose(&a)
            let rights = try first.authorize()
            defer { rights.close() }
            let target = try Claim.Target.capture(owner: first.owner, authorization: rights)
            let token = try first.owner.claimRetainedOrphan(target: target, authorization: rights)
            let joining = VoidProbe { try await token.joinTask().value }
            try joining.wait()
            try withFrame { second in
                var b: Invocation? = try second.invocation(); try second.lose(&b)
                let claim = try second.claim(), other = try joined(claim)
                XCTAssertThrowsError(try other.requireCurrentAuthorization(for: token)) {
                    XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
                }
                try other.requireCurrentAuthorization()
                first.assertHeld(); second.assertHeld()
                XCTAssertTrue(try other.releaseIfWindowFree()); try second.assertReleased()
                first.assertHeld()
            }
            XCTAssertTrue(try token.releaseWindowFree()); try first.assertReleased()
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
            XCTAssertThrowsError(try f.owner.reserveRetainedInvocation(authenticatedPeer: f.binding.peer, incarnation: UUID(), authenticatedOwner: f.binding.authorityOwner))
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
            let ledger = SetupRetainedRecoveryLedger(executor: nil)
            for object in [rights as Any, target as Any, target.record as Any, ledger as Any, claim as Any, actual as Any] {
                XCTAssertTrue(Mirror(reflecting: object).children.isEmpty)
                var output = ""; dump(object, to: &output)
                XCTAssertTrue(output.contains("redacted")); XCTAssertFalse(output.contains(f.binding.incarnation.uuidString))
                XCTAssertFalse(output.contains(f.binding.authorityOwner.directoryID.uuidString))
            }
            XCTAssertTrue(try actual.releaseIfWindowFree())
        }
    }
    func testMaintenanceCaptureWithoutWindowKeepsTheOrphanTokensAfterJoin() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation()
            _ = try value?.maintenanceCapture(invocation: f.guardValue, candidate: f.candidate, purpose: .retainedRuntime)
            try f.lose(&value)
            let actual = try joined(f.claim())
            XCTAssertTrue(actual.evidence.neverEntered)
            XCTAssertFalse(actual.evidence.windowWriteNeverPossible)
            XCTAssertFalse(try actual.releaseIfWindowFree()); f.assertHeld()
            XCTAssertEqual(f.status.window, .unavailable)
        }
    }
    func testRefusedRecaptureKeepsTheOrphanTokensWithoutInventingAWindow() async throws {
        let stop = try MaintenanceStopTestFixture(), client = try stop.client()
        let capture = try await stop.capture(client)
        try withFrame { f in
            var value: Invocation? = try f.invocation()
            do {
                let invocation = try XCTUnwrap(value)
                try invocation.installOwnedContext(connection: f.connection, readPeer: { _ in f.binding.peer })
                let stores = try MaintenanceBodyStores(mac: stop.window.scope.macID,
                    account: stop.cohort.accountID, policy: stop.runtime.plan.host.codePolicy)
                let pair = try stores.pair(policy: stop.runtime.plan.host.codePolicy); defer { try? pair.close() }
                try invocation.run(work: {
                    XCTAssertThrowsError(try invocation.recaptureMaintenance(expected: f.capture, transitions: [],
                        capture: capture, pair: pair, candidate: f.candidate)) {
                        XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
                    }
                }, reply: { _, _ in })
            }
            try f.lose(&value)
            let actual = try joined(f.claim())
            XCTAssertFalse(actual.evidence.windowWriteNeverPossible)
            XCTAssertEqual(actual.evidence.contextLoansStarted, 1); XCTAssertEqual(actual.evidence.contextLoansReturned, 1)
            XCTAssertFalse(try actual.releaseIfWindowFree()); f.assertHeld()
        }
        await client.close()
    }
    func testCancelledWaiterStillWaitsForTheActualWorkerReturn() throws {
        try withFrame { f in
            let gate = Gate(); defer { gate.finish() }
            var value: Invocation? = try f.invocation(); let worker = gate.worker()
            try value?.retainWorker(worker); XCTAssertEqual(gate.parked.wait(timeout: .now() + 3), .success)
            try f.lose(&value)
            let pending = JoinProbe(try f.claim()); pending.cancel()
            XCTAssertEqual(pending.done.wait(timeout: .now() + 0.05), .timedOut); f.assertHeld()
            gate.finish(); let actual = try pending.wait()
            XCTAssertEqual(actual.evidence.workersJoined, 1)
            XCTAssertTrue(try actual.releaseIfWindowFree()); try f.assertReleased()
        }
    }
    func testConcurrentClaimantsProduceOneLiveClaimForTheSameActualRecord() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation(); try f.lose(&value)
            let first = try f.authorize(), second = try f.authorize()
            let target = try Claim.Target.capture(owner: f.owner, authorization: first)
            let ready = DispatchSemaphore(value: 0), go = DispatchSemaphore(value: 0), group = DispatchGroup()
            let accepted = Mutex<[Claim]>([]), refused = Mutex(0)
            for rights in [first, second] {
                group.enter()
                DispatchQueue.global().async {
                    defer { group.leave() }; ready.signal()
                    guard go.wait(timeout: .now() + 3) == .success else { return }
                    do { let claim = try Claim.open(owner: f.owner, target: target, authorization: rights); accepted.withLock { $0.append(claim) } }
                    catch { refused.withLock { $0 += 1 } }
                }
            }
            XCTAssertEqual(ready.wait(timeout: .now() + 3), .success)
            XCTAssertEqual(ready.wait(timeout: .now() + 3), .success); go.signal(); go.signal()
            XCTAssertEqual(group.wait(timeout: .now() + 3), .success)
            XCTAssertEqual(accepted.withLock { $0.count }, 1); XCTAssertEqual(refused.withLock { $0 }, 1); f.assertHeld()
            let actual = try joined(XCTUnwrap(accepted.withLock { $0.first }))
            XCTAssertTrue(try actual.releaseIfWindowFree()); try f.assertReleased()
        }
    }
    func testTransientExecutorWorkRefusesANewRetainedReservationBeforeItsBody() throws {
        try withFrame { f in
            let entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0)
            defer { resume.signal() }
            let busy = VoidProbe {
                try await f.owner.occupyExecutorOwned {
                    entered.signal()
                    guard resume.wait(timeout: .now() + 5) == .success else { throw Failure.timeout }
                }
            }
            XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
            XCTAssertThrowsError(try f.invocation()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
            resume.signal(); try busy.wait()
            let value = try f.invocation(); try value.close(); try f.assertReleased()
        }
    }
    func testRepeatedJoinOnTheSameFailedClaimDoesNotRepeatCleanup() throws {
        try withFrame { f in
            let calls = Mutex(0)
            var value: Invocation? = try f.invocation()
            try value?.retainCleanup { calls.withLock { $0 += 1 }; throw Failure.expected }
            try f.lose(&value); let claim = try f.claim()
            try JoinProbe(claim).waitForFailure(); try JoinProbe(claim).waitForFailure()
            XCTAssertEqual(calls.withLock { $0 }, 1)
            XCTAssertEqual(f.status.cleanup, .observed(.joinFailed)); f.assertHeld()
        }
    }
    func testRestorationSlotIsRetainedBeforeTheFirstCallbackAndAClaimJoinsActualReturn() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation(); try f.window(XCTUnwrap(value)); try f.lose(&value)
            let first = try f.claim(), original = try joined(first), gate = Gate()
            let entered = DispatchSemaphore(value: 0); defer { gate.finish() }
            let starting = RestorationProbe(original) { _ in
                XCTAssertEqual(f.status.cleanup, .observed(.joining)); XCTAssertEqual(f.status.worker, .observed(.registered))
                entered.signal(); await gate.worker().value; throw Failure.expected
            }
            let work = try starting.wait(); XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
            f.assertHeld(); first.abandon()
            let pending = JoinProbe(try f.claim())
            XCTAssertEqual(pending.done.wait(timeout: .now() + 0.05), .timedOut); f.assertHeld()
            gate.finish(); let fresh = try pending.wait()
            XCTAssertEqual(fresh.evidence.workersRegistered, 0)
            XCTAssertEqual(f.status.cleanup, .observed(.joined)); XCTAssertFalse(try fresh.releaseIfWindowFree()); f.assertHeld()
            withExtendedLifetime(work) {}
        }
    }
    func testCancelledFreshClaimWaiterStillJoinsTheRestorationTask() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation(); try f.window(XCTUnwrap(value)); try f.lose(&value)
            let first = try f.claim(), gate = Gate(), entered = DispatchSemaphore(value: 0); defer { gate.finish() }
            let starting = RestorationProbe(try joined(first)) { _ in
                entered.signal(); await gate.worker().value; throw Failure.expected
            }
            let work = try starting.wait(); XCTAssertEqual(entered.wait(timeout: .now() + 3), .success); first.abandon()
            let pending = JoinProbe(try f.claim()); pending.cancel()
            XCTAssertEqual(pending.done.wait(timeout: .now() + 0.05), .timedOut); f.assertHeld()
            gate.finish(); let fresh = try pending.wait()
            XCTAssertFalse(try fresh.releaseIfWindowFree()); f.assertHeld(); withExtendedLifetime(work) {}
        }
    }
    func testFailedRestorationNeedsAFreshClaimBeforeAnotherSlotAttempt() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation(); try f.window(XCTUnwrap(value)); try f.lose(&value)
            let calls = Mutex(0), first = try f.claim()
            let starting = RestorationProbe(try joined(first)) { _ in calls.withLock { $0 += 1 }; throw Failure.expected }
            let work = try starting.wait()
            let returned = VoidProbe { do { _ = try await work.value(); XCTFail("Unexpected completion") } catch {} }; try returned.wait()
            let repeated = RestorationProbe(try joined(first)) { _ in calls.withLock { $0 += 1 }; throw Failure.expected }
            try repeated.waitForRefusal(); XCTAssertEqual(calls.withLock { $0 }, 1); f.assertHeld(); first.abandon()
            let retry = RestorationProbe(try joined(f.claim())) { _ in calls.withLock { $0 += 1 }; throw Failure.expected }
            let renewed = try retry.wait()
            let retryReturned = VoidProbe { do { _ = try await renewed.value(); XCTFail("Unexpected completion") } catch {} }
            try retryReturned.wait(); XCTAssertEqual(calls.withLock { $0 }, 2); f.assertHeld()
        }
    }
    func testRestorationPhasesUseTheOriginalExecutorAndCloseOnlyAfterItReturns() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation(); try f.window(XCTUnwrap(value)); try f.lose(&value)
            let original = try joined(f.claim()), phases = try original.restorationPhases()
            let entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0), closed = Mutex(0), stack = Mutex(0)
            defer { resume.signal() }
            let busy = VoidProbe {
                try await phases.cleanup {
                    entered.signal(); guard resume.wait(timeout: .now() + 3) == .success else { throw Failure.timeout }
                }
            }
            XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
            let refusal = VoidProbe {
                do {
                    let bounded = try phases.forAttempt(until: .now.advanced(by: .milliseconds(50)))
                    try await bounded.run { XCTFail("The original executor was busy") }; XCTFail("Unexpected second worker")
                } catch is CancellationError {}
            }
            try refusal.wait()
            let closing = VoidProbe {
                try await phases.closeActual {
                    stack.withLock { $0 = pthread_get_stacksize_np(pthread_self()) }; closed.withLock { $0 += 1 }
                }
            }
            XCTAssertEqual(closing.done.wait(timeout: .now() + 0.05), .timedOut); XCTAssertEqual(closed.withLock { $0 }, 0)
            resume.signal(); try busy.wait(); try closing.wait()
            XCTAssertEqual(closed.withLock { $0 }, 1)
            XCTAssertGreaterThanOrEqual(stack.withLock { $0 }, SetupAuditUpgradeWorkExecutor.stackBytes); f.assertHeld()
        }
    }
    func testRestorationPhaseRetriesBusyOnlyUntilTheOriginalExecutorReturns() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation(); try f.window(XCTUnwrap(value)); try f.lose(&value)
            let phases = try joined(f.claim()).restorationPhases()
            let entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0), calls = Mutex(0)
            defer { resume.signal() }
            let busy = VoidProbe {
                try await phases.cleanup {
                    entered.signal(); guard resume.wait(timeout: .now() + 3) == .success else { throw Failure.timeout }
                }
            }
            XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
            let waiting = VoidProbe {
                try await phases.run {
                    XCTAssertGreaterThanOrEqual(pthread_get_stacksize_np(pthread_self()), SetupAuditUpgradeWorkExecutor.stackBytes)
                    calls.withLock { $0 += 1 }
                }
            }
            XCTAssertEqual(waiting.done.wait(timeout: .now() + 0.05), .timedOut)
            XCTAssertEqual(calls.withLock { $0 }, 0); resume.signal(); try busy.wait(); try waiting.wait()
            XCTAssertEqual(calls.withLock { $0 }, 1); f.assertHeld()
        }
    }
    func testRestorationPhaseDoesNotRetryUnavailableFromAStartedBody() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation(); try f.window(XCTUnwrap(value)); try f.lose(&value)
            let phases = try joined(f.claim()).restorationPhases(), calls = Mutex(0)
            let failed = VoidProbe {
                do {
                    try await phases.run { calls.withLock { $0 += 1 }; throw AdministrativeSetupError.unavailable }
                    XCTFail("Unexpected phase success")
                } catch AdministrativeSetupError.unavailable {}
            }
            try failed.wait(); XCTAssertEqual(calls.withLock { $0 }, 1); f.assertHeld()
        }
    }
    private static let forkProcess: @convention(c) () -> pid_t = {
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "fork") else { preconditionFailure("fork unavailable") }
        return unsafeBitCast(symbol, to: (@convention(c) () -> pid_t).self)
    }()

    func testOrphanSignalsCanReenterStatusAndNeverSettleAdmission() async throws {
        try await SetupExecutorAdmissionTestFixture.make {
            try self.withFrame { f in
                let signals = Mutex(0), peer = f.binding.peer, identity = f.binding.authorityOwner
                try f.owner.installMaintenanceRecoverySignal { [weak owner = f.owner] in
                    signals.withLock { $0 += 1 }
                    guard let owner else { XCTFail("The record must retain its owner during this fixture"); return }
                    XCTAssertEqual(try? owner.retainedInvocationState(), .orphan)
                    _ = owner.retainedInvocationStatus(authenticatedPeer: peer, currentOwner: identity)
                }
                var invocation: Invocation? = try f.invocation(captured: false)
                try f.lose(&invocation)
                XCTAssertEqual(signals.withLock { $0 }, 2); f.assertHeld()
                let completed = try self.joined(f.claim()); XCTAssertTrue(try completed.releaseIfWindowFree())
                try f.assertReleased(); XCTAssertEqual(signals.withLock { $0 }, 2)
            }
        }
    }
    func testCleanupSignalFollowsTheActualInvocationCleanupReturn() async throws {
        try await SetupExecutorAdmissionTestFixture.make {
            try self.withFrame { f in
                let signals = Mutex(0), closing = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), returned = DispatchSemaphore(value: 0)
                let deadline = DispatchTime.now() + Double(120) / 4
                try f.owner.installMaintenanceRecoverySignal { signals.withLock { $0 += 1 } }
                let cell = InvocationCell()
                cell.value = try f.invocation(captured: false, closeRights: {
                    closing.signal(); XCTAssertEqual(release.wait(timeout: deadline), .success)
                })
                let thread = Thread { cell.value = nil; returned.signal() }
                thread.stackSize = SetupAuditUpgradeWorkExecutor.stackBytes; thread.start()
                XCTAssertEqual(closing.wait(timeout: deadline), .success)
                XCTAssertEqual(signals.withLock { $0 }, 1); f.assertHeld()
                release.signal(); XCTAssertEqual(returned.wait(timeout: deadline), .success)
                XCTAssertEqual(signals.withLock { $0 }, 2); f.assertHeld()
                let completed = try self.joined(f.claim()); XCTAssertTrue(try completed.releaseIfWindowFree())
                try f.assertReleased()
            }
        }
    }

    func testAbandonWithoutShutdownDoesNotCancelTheActualRestorationTask() throws {
        try withFrame { f in
            var value: Invocation? = try f.invocation(); try f.window(XCTUnwrap(value)); try f.lose(&value)
            let first = try f.claim(), gate = Gate(), entered = DispatchSemaphore(value: 0)
            let cancelled = Mutex(true); defer { gate.finish() }
            let starting = RestorationProbe(try joined(first)) { _ in
                entered.signal(); await gate.worker().value
                cancelled.withLock { $0 = Task.isCancelled }; throw Failure.expected
            }
            let actual = try starting.wait(); XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
            first.abandon(); let fresh = JoinProbe(try f.claim())
            XCTAssertEqual(fresh.done.wait(timeout: .now() + 0.05), .timedOut); f.assertHeld()
            gate.finish(); _ = try fresh.wait()
            let resultJoined = VoidProbe { do { _ = try await actual.value(); XCTFail("Expected the actual failure") } catch {} }
            try resultJoined.wait(); XCTAssertFalse(cancelled.withLock { $0 }); f.assertHeld()
        }
    }

    private func withShutdownFrame(_ body: (Frame, AdministrativeSetupShutdown, SetupProcessLease, ReleaseDestinationLease) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { fixture in
            let activity = try ReleaseActivityFixture(), f = try Frame(fixture, activity: activity)
            let placement = try ReleaseDestinationLease(anchor: activity.root.path, relativeDirectory: "Machine", owner: getuid())
            let process = try SetupProcessLease.openOwned(directory: .init(anchor: activity.root.path, relativeDirectory: "Machine", owner: getuid()))
            let shutdown = AdministrativeSetupShutdown(owner: f.owner, placement: placement, processLease: process)
            defer { placement.close(); process.close() }
            try body(f, shutdown, process, placement)
        }
    }
    func testShutdownKeepsBothLeasesWhileTheOriginalClaimWorkerHasNotReturned() throws {
        try withShutdownFrame { f, shutdown, process, placement in
            let gate = Gate(); defer { gate.finish() }
            var invocation: Invocation? = try f.invocation(), original = gate.worker()
            try invocation?.retainWorker(original)
            XCTAssertEqual(gate.parked.wait(timeout: .now() + 3), .success); try f.lose(&invocation)
            let session = try shutdown.registerRecoverySession(owner: f.owner)
            XCTAssertTrue(session.reservePublication())
            let claim = try f.claim(shutdownSession: session), cancelled = Mutex(false)
            session.bindEndpointClose { claim.abandon() }
            let actual = Task {
                do { _ = try await claim.join() } catch {}
                cancelled.withLock { $0 = Task.isCancelled }
            }
            session.publish(actual)
            let finalizer = VoidProbe { await shutdown.joinRecoverySessions() }
            XCTAssertEqual(finalizer.done.wait(timeout: .now() + 0.05), .timedOut)
            XCTAssertNoThrow(try process.validate()); XCTAssertNoThrow(try placement.validate()); f.assertHeld()
            gate.finish(); try finalizer.wait()
            XCTAssertTrue(cancelled.withLock { $0 }); XCTAssertNoThrow(try process.validate())
        }
    }
    func testShutdownCancelsTheRealRestorationTaskAndStillAwaitsItsActualReturn() throws {
        try withShutdownFrame { f, shutdown, process, placement in
            var invocation: Invocation? = try f.invocation(); try f.window(XCTUnwrap(invocation)); try f.lose(&invocation)
            let session = try shutdown.registerRecoverySession(owner: f.owner)
            XCTAssertTrue(session.reservePublication())
            let claim = try f.claim(shutdownSession: session), gate = Gate()
            let entered = DispatchSemaphore(value: 0), cancelled = DispatchSemaphore(value: 0), returned = Mutex(false)
            defer { gate.finish() }
            let starting = RestorationProbe(try joined(claim)) { _ in
                try await withTaskCancellationHandler {
                    entered.signal(); await gate.worker().value
                    returned.withLock { $0 = true }; throw Failure.expected
                } onCancel: { cancelled.signal() }
            }
            let work = try starting.wait()
            XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
            session.publish(Task { do { _ = try await work.value() } catch {} })
            let finalizer = VoidProbe { await shutdown.joinRecoverySessions() }
            XCTAssertEqual(cancelled.wait(timeout: .now() + 3), .success)
            XCTAssertEqual(finalizer.done.wait(timeout: .now() + 0.05), .timedOut)
            XCTAssertFalse(returned.withLock { $0 }); f.assertHeld()
            XCTAssertNoThrow(try process.validate()); XCTAssertNoThrow(try placement.validate())
            gate.finish(); try finalizer.wait(); XCTAssertTrue(returned.withLock { $0 })
            XCTAssertNoThrow(try process.validate()); f.assertHeld()
        }
    }

    func testShutdownRequestCancelsAnActualRestorationHandleRetainedAfterTheSnapshot() throws {
        try withShutdownFrame { f, shutdown, process, placement in
            var invocation: Invocation? = try f.invocation(); try f.window(XCTUnwrap(invocation)); try f.lose(&invocation)
            let claim = try f.claim(), gate = Gate(), entered = DispatchSemaphore(value: 0), cancelled = DispatchSemaphore(value: 0)
            defer { gate.finish() }
            let starting = RestorationProbe(try joined(claim)) { _ in
                try await withTaskCancellationHandler {
                    entered.signal(); await gate.worker().value; throw Failure.expected
                } onCancel: { cancelled.signal() }
            }
            let work = try starting.wait(); XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
            let session = try shutdown.registerRecoverySession(owner: f.owner), closing = DispatchSemaphore(value: 0)
            XCTAssertTrue(session.reservePublication()); session.bindEndpointClose { closing.signal() }
            session.publish(Task { do { _ = try await work.value() } catch {} })
            let finalizer = VoidProbe { await shutdown.joinRecoverySessions() }
            XCTAssertEqual(closing.wait(timeout: .now() + 3), .success)
            XCTAssertEqual(cancelled.wait(timeout: .now() + 0.05), .timedOut)
            session.retainRestoration(work)
            XCTAssertEqual(cancelled.wait(timeout: .now() + 3), .success)
            XCTAssertEqual(finalizer.done.wait(timeout: .now() + 0.05), .timedOut)
            XCTAssertNoThrow(try process.validate()); XCTAssertNoThrow(try placement.validate())
            gate.finish(); try finalizer.wait(); f.assertHeld()
        }
    }
    func testWatchdogExitSeventyFiveDoesNotReleaseLeasesDuringTheActualOriginalJoin() throws {
        try withShutdownFrame { f, shutdown, process, placement in
            let gate = Gate(); defer { gate.finish() }
            var invocation: Invocation? = try f.invocation(), original = gate.worker()
            try invocation?.retainWorker(original)
            XCTAssertEqual(gate.parked.wait(timeout: .now() + 3), .success); try f.lose(&invocation)
            let session = try shutdown.registerRecoverySession(owner: f.owner)
            XCTAssertTrue(session.reservePublication())
            let claim = try f.claim(shutdownSession: session)
            session.publish(Task { do { _ = try await claim.join() } catch {} })
            let closing = VoidProbe { await shutdown.joinRecoverySessions() }
            XCTAssertEqual(closing.done.wait(timeout: .now() + 0.05), .timedOut)
            let epoch = ContinuousClock.now, now = Mutex(epoch), codes = Mutex<[Int32]>([])
            let fire = Mutex<(@Sendable () -> Void)?>(nil)
            let timer = try AdministrativeSetupLifecycle.RetirementWatchdog.TimerDriver.owned(arm: { _, callback in
                fire.withLock { $0 = callback }
            }, cancel: { fire.withLock { $0 = nil } })
            let watchdog = AdministrativeSetupLifecycle.RetirementWatchdog(timing: .init(now: { now.withLock { $0 } },
                sleep: { _ in XCTFail("The independent watchdog must not use a cooperative sleep") }), timer: timer,
                terminate: { code in codes.withLock { $0.append(code) } })
            let deadline = watchdog.start(); XCTAssertEqual(deadline, epoch.advanced(by: .seconds(300)))
            now.withLock { $0 = deadline }
            let callback = try XCTUnwrap(fire.withLock { $0 }); callback()
            XCTAssertEqual(codes.withLock { $0 }, [75])
            XCTAssertEqual(closing.done.wait(timeout: .now() + 0.05), .timedOut)
            XCTAssertNoThrow(try process.validate()); XCTAssertNoThrow(try placement.validate()); f.assertHeld()
            XCTAssertEqual(f.status.cleanup, .observed(.joining)); XCTAssertEqual(f.status.window, .unavailable)
            gate.finish(); try closing.wait(); watchdog.didClose()
        }
    }

    func testShutdownBeforeRestorationPublicationCancelsTheTaskBeforeItsFirstForwardEffect() throws {
        try withShutdownFrame { f, shutdown, process, placement in
            var invocation: Invocation? = try f.invocation(); try f.window(XCTUnwrap(invocation)); try f.lose(&invocation)
            let publishing = DispatchSemaphore(value: 0), publish = DispatchSemaphore(value: 0)
            let shutdownRequested = DispatchSemaphore(value: 0), forwardCalls = Mutex(0), sawCancellation = Mutex(false)
            defer { publish.signal() }
            let control = try AdministrativeSetupShutdown.RecoverySessionWork.OwnedPublicationControl(beforeRetaining: {
                publishing.signal()
                XCTAssertEqual(publish.wait(timeout: .now() + 3), .success)
            })
            let session = try shutdown.registerRecoverySessionOwned(owner: f.owner, publicationControl: control)
            XCTAssertTrue(session.reservePublication()); session.bindEndpointClose { shutdownRequested.signal() }
            let claim = try f.claim(shutdownSession: session), original = try joined(claim)
            let actual = Task {
                do {
                    let work = try await original.startRestoration { _ in
                        sawCancellation.withLock { $0 = Task.isCancelled }
                        try Task.checkCancellation()
                        forwardCalls.withLock { $0 += 1 }
                        throw Failure.expected
                    }
                    _ = try await work.value()
                } catch {}
            }
            session.publish(actual)
            XCTAssertEqual(publishing.wait(timeout: .now() + 3), .success)
            XCTAssertFalse(sawCancellation.withLock { $0 }); XCTAssertEqual(forwardCalls.withLock { $0 }, 0)
            let finalizer = VoidProbe { await shutdown.joinRecoverySessions() }
            XCTAssertEqual(shutdownRequested.wait(timeout: .now() + 3), .success)
            XCTAssertEqual(finalizer.done.wait(timeout: .now() + 0.05), .timedOut)
            XCTAssertNoThrow(try process.validate()); XCTAssertNoThrow(try placement.validate())
            publish.signal(); try finalizer.wait()
            XCTAssertTrue(sawCancellation.withLock { $0 }); XCTAssertEqual(forwardCalls.withLock { $0 }, 0)
            XCTAssertNoThrow(try process.validate()); f.assertHeld()
        }
    }

    func testFinalizationWaitsForTheActualWrapperAfterItsOriginalClaimHasJoined() throws {
        try withShutdownFrame { f, shutdown, process, placement in
            var invocation: Invocation? = try f.invocation(); try f.window(XCTUnwrap(invocation)); try f.lose(&invocation)
            let session = try shutdown.registerRecoverySession(owner: f.owner)
            XCTAssertTrue(session.reservePublication())
            let claim = try f.claim(shutdownSession: session), gate = Gate()
            let originalJoined = DispatchSemaphore(value: 0); defer { gate.finish() }
            session.bindEndpointClose { claim.abandon() }
            let actual = Task {
                do { _ = try await claim.join(); originalJoined.signal(); await gate.worker().value } catch {}
            }
            session.publish(actual)
            XCTAssertEqual(originalJoined.wait(timeout: .now() + 3), .success)
            let finalizer = VoidProbe { await shutdown.joinRecoverySessions() }
            XCTAssertEqual(finalizer.done.wait(timeout: .now() + 0.05), .timedOut)
            XCTAssertNoThrow(try process.validate()); XCTAssertNoThrow(try placement.validate()); f.assertHeld()
            gate.finish(); try finalizer.wait()
            XCTAssertNoThrow(try process.validate()); f.assertHeld()
        }
    }


}
