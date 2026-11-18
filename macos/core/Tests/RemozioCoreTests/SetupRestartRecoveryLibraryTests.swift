import Darwin
import Foundation
import Synchronization
import XCTest
import RemozioProtocol
@testable import RemozioCore

struct RestartRecoveryTestTiming {
    static func deadline(restorations: Int = 1) -> ContinuousClock.Instant {
        .now.advanced(by: .seconds(30) + restorationTestForwardDeadline * restorations + .seconds(20))
    }
    static func remaining(_ deadline: ContinuousClock.Instant) -> TimeInterval {
        let value = ContinuousClock.now.duration(to: deadline).components
        return max(0, Double(value.seconds) + Double(value.attoseconds) / 1e18)
    }
}

/// One waiter with a finite deadline; no cooperative thread waits on a semaphore.
final class RestartRecoveryTestSignal: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Bool?
    private var waiter: CheckedContinuation<Bool, Never>?
    private var timer: Task<Void, Never>?
    func signal() { finish(true) }
    private func finish(_ value: Bool) {
        let pending = lock.withLock { () -> (CheckedContinuation<Bool, Never>?, Task<Void, Never>?) in
            guard result == nil else { return (nil, nil) }
            result = value
            let pending = (waiter, timer); waiter = nil; timer = nil
            return pending
        }
        pending.1?.cancel(); pending.0?.resume(returning: value)
    }
    func wait(until deadline: ContinuousClock.Instant) async -> Bool {
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                lock.lock()
                if let result { lock.unlock(); continuation.resume(returning: result); return }
                precondition(waiter == nil)
                waiter = continuation
                timer = Task { [weak self] in
                    do { try await ContinuousClock().sleep(until: deadline) } catch { return }
                    self?.finish(false)
                }
                lock.unlock()
            }
        } onCancel: { self.finish(false) }
    }
}

final class SetupRestartRecoveryLibraryTests: XCTestCase, @unchecked Sendable {
    private typealias Fixture = ExplicitStartupFixture
    private typealias Claim = SetupRestartRecovery.Claim
    private enum Failure: Error { case expected }
    private func withFixture(restorations: Int = 1, _ body: @escaping @Sendable (Fixture) async throws -> Void) throws {
        let harness = RuntimeMaintenanceRestartRestorationTests(selector: NSSelectorFromString("testRightsCheckedExitBeforeStartingReleasesTheIdleSlot"))
        try harness.withFixture(outerDeadline: RestartRecoveryTestTiming.deadline(restorations: restorations), body)
    }
    private static func claim(_ f: Fixture, policy: SetupAccountOwner.RestartClaimPolicy = .freshOrReclaim,
        authorization: SetupRetainedRecoveryAuthorization? = nil) async throws -> Claim {
        try await .openOwned(owner: f.retained.owner, authorization: authorization ?? f.retained.authorize(),
            processLease: f.processLease, policy: policy, until: .now.advanced(by: .seconds(5)))
    }
    private static func projection(_ f: Fixture) -> SetupRetainedStatusProjection {
        f.retained.owner.retainedInvocationStatusV2(authenticatedPeer: f.retained.binding.peer, currentOwner: f.retained.binding.authorityOwner)
    }
    private static func available(_ f: Fixture) throws {
        try f.retained.owner.verifyCurrent()
        let reply = try f.retained.owner.acquireSetupReplyAdmission(); reply.close()
        let activity = try f.retained.installer.acquireExclusive(); activity.close()
    }
    private static func refuses<T>(_ body: () async throws -> T) async {
        do { _ = try await body(); XCTFail("Expected refusal") } catch {}
    }
    private static func statusRequest() throws -> SetupRetainedStatusV2Wire.Request { try .init(requestID: Data(repeating: 7, count: 16)) }

    func testPeerDerivedClaimUsesTheActualPreparedAccount() throws {
        try withFixture { f in
            let claim = try await Self.claim(f); defer { claim.abandon() }
            XCTAssertEqual(try claim.restorationAccountID(), f.h.initial.scope.authority.accountID)
            XCTAssertEqual(Self.projection(f).restart?.slot, .held)
            XCTAssertEqual(Self.projection(f).restart?.claim, .present)
            XCTAssertEqual(Self.projection(f).restart?.task, .notStarted)
            f.retained.assertHeld()
        }
    }
    func testReclaimOnlyCannotCreateARecordOrTakeFreshAdmissions() throws {
        try withFixture { f in
            await Self.refuses { try await Self.claim(f, policy: .reclaimOnly) }
            XCTAssertNil(Self.projection(f).restart); try Self.available(f)
        }
    }
    func testReclaimOnlyUsesTheExistingRecordAfterAbandon() throws {
        try withFixture { f in
            try f.seed(.stopped)
            let rights = f.rightsLive
            let authorization = try f.retained.authorize(verify: { guard rights.value.withLock({ $0 }) else { throw Failure.expected } })
            let first = try await Self.claim(f, authorization: authorization)
            f.h.afterWrite = { row in if row.phase == .restored { f.rightsLive.value.withLock { $0 = false } } }
            await Self.refuses { try await RuntimeMaintenanceRestartRestorationTests.restore(f, first) }
            let firstRow = try XCTUnwrap(Self.projection(f).restart?.row)
            first.abandon(); f.h.afterWrite = nil; f.rightsLive.value.withLock { $0 = true }
            let adopter = try await Self.claim(f, policy: .reclaimOnly); defer { adopter.abandon() }
            XCTAssertEqual(Self.projection(f).restart?.task, .completionPending)
            XCTAssertEqual(Self.projection(f).restart?.row, firstRow)
            let actions = f.driver.metrics.actions.withLock { $0 }
            let restored = try await adopter.finishRecordedRestoration()
            XCTAssertEqual(restored.phase, .restored)
            XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, actions)
            XCTAssertEqual(Self.projection(f).restart?.task, .completionAdopted)
            try Self.available(f)
        }
    }
    func testMissingPreparedAccountCannotTakeTheSlot() throws {
        try withFixture { f in
            let peer = XPCPeerCredentials(processID: getpid(), userID: f.retained.binding.peer.userID + 100, auditSessionID: 1)
            let identity = LocalAccountIdentity(uid: peer.userID, primaryGroupID: getgid(), directoryID: UUID())
            let auth = try f.retained.authorize(peer: peer, identity: identity)
            await Self.refuses { try await Self.claim(f, authorization: auth) }
            XCTAssertNil(Self.projection(f).restart); try Self.available(f)
        }
    }
    func testRecycledDirectoryRefusesWithoutPublishingRestart() throws {
        try withFixture { f in
            let identity = LocalAccountIdentity(uid: f.retained.binding.peer.userID, primaryGroupID: getgid(), directoryID: UUID())
            let auth = try f.retained.authorize(identity: identity)
            await Self.refuses { try await Self.claim(f, authorization: auth) }
            XCTAssertNil(Self.projection(f).restart); try Self.available(f)
        }
    }
    func testOldSettledInvocationStaysUnavailableAfterRestartInstallAndIdleRelease() throws {
        try withFixture { f in
            let original = try f.retained.invocation(); try original.close()
            XCTAssertEqual(f.retained.status.reservation, .observed(.settled))
            let claim = try await Self.claim(f); defer { claim.abandon() }
            for _ in 0..<20 { XCTAssertEqual(f.retained.status, .unavailable) }
            let releasedIdle = try await claim.releaseIdleAfterRequest(); XCTAssertTrue(releasedIdle)
            for _ in 0..<20 { XCTAssertEqual(f.retained.status, .unavailable) }
            XCTAssertEqual(Self.projection(f).restart?.slot, .released)
            XCTAssertEqual(Self.projection(f).restart?.task, .idleReleased)
            XCTAssertNil(Self.projection(f).restart?.row)
            try Self.available(f)
        }
    }
    func testIdleReleaseDoesNotInventARestoredWindow() throws {
        try withFixture { f in
            try f.seed(.stopped); let before = try f.h.frame().window
            let claim = try await Self.claim(f); defer { claim.abandon() }
            let releasedIdle = try await claim.releaseIdleAfterRequest(); XCTAssertTrue(releasedIdle)
            XCTAssertEqual(try f.h.frame().window, before)
            XCTAssertEqual(before?.phase, .needsOwnerRecovery)
            XCTAssertNil(Self.projection(f).restart?.row)
            XCTAssertEqual(Self.projection(f).restart?.custody, .notOpened)
        }
    }
    func testActualRestoreSeparatesRowCompletionAndSlotDisposition() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f); defer { claim.abandon() }
            let row = try await RuntimeMaintenanceRestartRestorationTests.restore(f, claim)
            XCTAssertTrue(claim.hasCheckedRestorationResult(row))
            let snapshot = try XCTUnwrap(Self.projection(f).restart)
            XCTAssertEqual(snapshot.slot, .released); XCTAssertEqual(snapshot.task, .completionAdopted)
            XCTAssertEqual(snapshot.custody, .closed); XCTAssertEqual(snapshot.row?.restoration.phase, .restored)
            XCTAssertEqual(snapshot.row?.operation, row.operation)
            XCTAssertEqual(f.retained.status, .unavailable); try Self.available(f)
        }
    }
    func testAnUnstartedClaimCannotManufactureACheckedRestorationResult() throws {
        try withFixture { f in
            let claim = try await Self.claim(f); defer { claim.abandon() }
            XCTAssertFalse(claim.hasCheckedRestorationResult(f.h.initial))
            XCTAssertEqual(Self.projection(f).restart?.task, .notStarted)
        }
    }
    func testOpenCustodyMasksWriterFactsAndActualWorkPinsBothAdmissions() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f); defer { claim.abandon() }
            let seen = Mutex<SetupRestartStatus.Snapshot?>(nil)
            f.h.beforeRegistration = {
                seen.withLock { $0 = Self.projection(f).restart }
                f.retained.assertHeld()
            }
            defer { f.h.beforeRegistration = nil }
            _ = try await RuntimeMaintenanceRestartRestorationTests.restore(f, claim)
            let snapshot = try XCTUnwrap(seen.withLock { $0 })
            XCTAssertEqual(snapshot.slot, .held); XCTAssertEqual(snapshot.task, .running)
            XCTAssertEqual(snapshot.custody, .open); XCTAssertNil(snapshot.writer)
        }
    }
    func testWriterRefusalMasksOpenFactsAndPublishesUncertaintyAfterClose() throws {
        try withFixture { f in
            try f.seed(.stopped); let claim = try await Self.claim(f); defer { claim.abandon() }
            let open = Mutex<SetupRestartStatus.Snapshot?>(nil)
            f.h.beforeWrite = { row in
                if row.phase == .restoring {
                    let snapshot = Self.projection(f).restart
                    open.withLock { $0 = snapshot }
                    XCTAssertEqual(snapshot?.custody, .open); XCTAssertNil(snapshot?.writer)
                    throw Failure.expected
                }
            }
            await Self.refuses { try await RuntimeMaintenanceRestartRestorationTests.restore(f, claim) }
            let snapshot = try XCTUnwrap(Self.projection(f).restart)
            XCTAssertNotNil(open.withLock { $0 })
            XCTAssertEqual(snapshot.custody, .closed); XCTAssertEqual(snapshot.writer, .uncertain)
            XCTAssertEqual(snapshot.slot, .held); XCTAssertNotEqual(snapshot.task, .completionAdopted)
            f.retained.assertHeld()
        }
    }
    func testLostRightsCannotReleaseAnIdleClaimThroughTheSessionExit() throws {
        try withFixture { f in
            let live = Mutex(true)
            let auth = try f.retained.authorize(verify: { guard live.withLock({ $0 }) else { throw Failure.expected } })
            let claim = try await Self.claim(f, authorization: auth)
            live.withLock { $0 = false }
            await Self.refuses { try await claim.releaseIdleAfterRequest() }
            f.retained.assertHeld(); claim.abandon(); try Self.available(f)
        }
    }
    func testRecycledDirectoryCannotObserveTheRestartOrigin() throws {
        try withFixture { f in
            let claim = try await Self.claim(f); defer { claim.abandon() }
            let recycled = LocalAccountIdentity(uid: f.retained.binding.peer.userID, primaryGroupID: getgid(), directoryID: UUID())
            let value = f.retained.owner.retainedInvocationStatusV2(authenticatedPeer: f.retained.binding.peer, currentOwner: recycled)
            XCTAssertEqual(value, .unavailable)
        }
    }
    func testStatusNeverBorrowsEitherAdmissionOrStartsWork() throws {
        try withFixture { f in
            let claim = try await Self.claim(f); defer { claim.abandon() }
            let before = try f.h.frame().window, actions = f.driver.metrics.actions.withLock { $0 }
            for _ in 0..<25 {
                XCTAssertEqual(Self.projection(f).restart?.task, .notStarted)
                XCTAssertEqual(f.retained.status, .unavailable)
            }
            XCTAssertEqual(try f.h.frame().window, before)
            XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, actions)
            f.retained.assertHeld()
        }
    }
    func testSupervisorCacheCannotReappearAfterAnotherOwnersSuccessor() throws {
        try withFixture { f in
            try f.seed(.stopped); let old = try XCTUnwrap(f.h.frame().window)
            f.retained.owner.publishMaintenanceRecovery(old)
            let claim = try await Self.claim(f)
            let restored = try await RuntimeMaintenanceRestartRestorationTests.restore(f, claim); claim.abandon()
            let binding = f.retained.binding
            let b = XPCPeerCredentials(processID: getpid(), userID: binding.targetOwner.uid, auditSessionID: 1)
            let successor = try f.retained.owner.reserveRetainedInvocation(authenticatedPeer: b, incarnation: UUID(), authenticatedOwner: binding.targetOwner)
            defer { successor.record.abortConstruction() }
            XCTAssertEqual(f.retained.status, .unavailable); XCTAssertEqual(Self.projection(f).retained, .unavailable)
            let before = Self.projection(f)
            XCTAssertEqual(before.restart?.slot, .released)
            XCTAssertEqual(before.restart?.row?.restoration.phase, .restored)
            XCTAssertEqual(before.restart?.row?.window.id, restored.id)
            let request = try Self.statusRequest()
            let bytes = try SetupRetainedStatusV2Wire.reply(request, before)
            let fields = try SetupRetainedStatusV2Wire.decodeReply(bytes)
            XCTAssertEqual(fields[11], .null)
            XCTAssertEqual(fields[6], .array([.bytes(restored.id), .bytes(restored.revision), .unsigned(restored.purpose.rawValue)]))
            XCTAssertEqual(fields[7], .unsigned(restored.operation.rawValue))
            XCTAssertEqual(fields[8], .array([.unsigned(9), .unsigned(restored.service.rawValue), .null]))
            f.retained.owner.publishMaintenanceRecovery(old)
            f.retained.owner.publishMaintenanceRecovery(request: try .init(accountID: old.scope.authority.accountID, windowID: old.id, revision: old.revision), observation: .busy)
            XCTAssertEqual(f.retained.status, .unavailable); XCTAssertEqual(Self.projection(f).retained, .unavailable)
            XCTAssertEqual(try SetupRetainedStatusV2Wire.reply(request, Self.projection(f)), bytes)
        }
    }
    func testRestartWireNeverCombinesSupervisorFactsWithItsOwnRow() throws {
        try withFixture { f in
            try f.seed(.stopped); f.retained.owner.publishMaintenanceRecovery(try XCTUnwrap(f.h.frame().window))
            let claim = try await Self.claim(f); defer { claim.abandon() }
            _ = try await RuntimeMaintenanceRestartRestorationTests.restore(f, claim)
            let fields = try SetupRetainedStatusV2Wire.decodeReply(SetupRetainedStatusV2Wire.reply(Self.statusRequest(), Self.projection(f)))
            XCTAssertEqual(fields[3], .unsigned(2)); XCTAssertEqual(fields[11], .null)
            XCTAssertNotEqual(fields[6], .null); XCTAssertNotEqual(fields[8], .null)
            for key in [UInt64(4), 5, 9, 10] { XCTAssertEqual(fields[key], .null) }
        }
    }
    func testAnotherOwnersStableBytesDoNotChangeAcrossRestartInstallCaptureReleaseAndReplacement() throws {
        try withFixture { f in
            try f.seed(.stopped)
            let actual = try XCTUnwrap(f.h.frame().window)
            let source = f.h.initial.scope
            let scope = try RuntimeMaintenanceWindowRecord.Scope(macID: source.macID, installationID: source.installationID,
                authority: source.target, target: source.authority, releaseDigest: source.releaseDigest,
                candidateDigest: source.candidateDigest, authorityPolicyDigest: source.authorityPolicyDigest,
                operationDigest: source.operationDigest, restorationDigest: source.restorationDigest,
                mutationFootprintDigest: source.mutationFootprintDigest, authorityGrantDigest: source.authorityGrantDigest,
                targetConsentDigest: source.targetConsentDigest, administratorIntentDigest: source.administratorIntentDigest)
            let row = try RuntimeMaintenanceWindowRecord(id: Data(repeating: 9, count: 16), revision: Data(repeating: 8, count: 16),
                purpose: .retainedRuntime, scope: scope, phase: .needsOwnerRecovery, service: .unknown, failure: .cleanupPending)
            f.retained.owner.publishMaintenanceRecovery(row)
            let binding = f.retained.binding
            let peer = XPCPeerCredentials(processID: getpid(), userID: binding.targetOwner.uid, auditSessionID: 1)
            func bytes() throws -> (Data, Data) {
                let snapshot = f.retained.owner.retainedInvocationStatusV2(authenticatedPeer: peer, currentOwner: binding.targetOwner)
                return (try SetupRetainedStatusWire.reply(.init(requestID: Data(repeating: 7, count: 16)), snapshot.v1),
                    try SetupRetainedStatusV2Wire.reply(Self.statusRequest(), snapshot))
            }
            let before = try bytes()
            for _ in 0..<2 {
                let claim = try await Self.claim(f)
                let held = try bytes(); XCTAssertEqual(held.0, before.0); XCTAssertEqual(held.1, before.1)
                try await claim.restorationPhases().run { try claim.capture(actual) }
                let captured = try bytes(); XCTAssertEqual(captured.0, before.0); XCTAssertEqual(captured.1, before.1)
                let releasedIdle = try await claim.releaseIdleAfterRequest(); XCTAssertTrue(releasedIdle)
                let released = try bytes(); XCTAssertEqual(released.0, before.0); XCTAssertEqual(released.1, before.1)
                claim.abandon()
            }
        }
    }
    func testConfirmedRowSurvivesReplacementOfTheActualAttempt() throws {
        try withFixture(restorations: 2) { f in
            try f.seed(.stopped)
            let first = try await Self.claim(f); f.h.rejectCode = true
            await Self.refuses { try await RuntimeMaintenanceRestartRestorationTests.restore(f, first) }
            let before = try XCTUnwrap(Self.projection(f).restart?.row)
            XCTAssertEqual(before.restoration.phase, .needsOwnerRecovery)
            first.abandon(); f.h.rejectCode = false
            let next = try await Self.claim(f, policy: .reclaimOnly); defer { next.abandon() }
            let seen = Mutex<SetupRestartStatus.Row?>(nil)
            _ = try await RuntimeMaintenanceRestartRestorationTests.restore(f, next, beforeCustody: {
                seen.withLock { $0 = Self.projection(f).restart?.row }
            })
            XCTAssertEqual(seen.withLock { $0 }, before)
            XCTAssertEqual(Self.projection(f).restart?.row?.restoration.phase, .restored)
        }
    }
    func testReaderCloseDuringTheOwnedSnapshotReturnsUnavailable() throws {
        try withFixture { f in
            let peer = f.retained.binding.peer, owner = f.retained.binding.authorityOwner
            let reader = SetupRetainedInvocationStatus.Reader()
            reader.publishRecovery(f.h.initial)
            let value = try reader.readV2Owned(authenticatedPeer: peer, currentOwner: owner, afterSnapshot: { reader.close() })
            XCTAssertEqual(value, .unavailable)
        }
    }
    func testContendedV2ReaderReturnsWithoutWaitingForItsLock() throws {
        let lock = NSLock(), reader = try SetupRetainedInvocationStatus.Reader.openOwned(statusLock: lock)
        let peer = XPCPeerCredentials(processID: getpid(), userID: getuid(), auditSessionID: 1)
        let owner = LocalAccountIdentity(uid: getuid(), primaryGroupID: getgid(), directoryID: UUID())
        lock.lock()
        let start = ContinuousClock.now
        XCTAssertEqual(reader.readV2(authenticatedPeer: peer, currentOwner: owner), .unavailable)
        let duration = start.duration(to: .now); lock.unlock()
        XCTAssertLessThan(duration, .seconds(1)); reader.close()
    }
    func testStatusHandleDescriptionsRedactTheAccountAndDirectory() {
        let identity = LocalAccountIdentity(uid: getuid(), primaryGroupID: getgid(), directoryID: UUID())
        let handle = SetupRestartStatus.Handle(accountID: Data(repeating: 0xab, count: 16), owner: identity)
        XCTAssertEqual(handle.description, "SetupRestartStatusHandle(redacted)")
        XCTAssertEqual(handle.customMirror.children.count, 0)
        XCTAssertFalse(String(reflecting: handle).contains(identity.directoryID.uuidString))
    }
    func testReleasedOriginSurvivesAnotherOwnersFreshRestartAndSuccessor() throws {
        try withFixture { f in
            let initial = try f.retained.invocation(); try initial.close()
            let a = try await Self.claim(f)
            let releasedA = try await a.releaseIdleAfterRequest(); XCTAssertTrue(releasedA); a.abandon()
            let beforeA = Self.projection(f)
            let request = try Self.statusRequest()
            let bytesA = try SetupRetainedStatusV2Wire.reply(request, beforeA)
            let binding = f.retained.binding
            let peerB = XPCPeerCredentials(processID: getpid(), userID: binding.targetOwner.uid, auditSessionID: 1)
            let rightsB = try f.retained.authorize(peer: peerB, identity: binding.targetOwner)
            let b = try await Self.claim(f, authorization: rightsB); defer { b.abandon() }
            XCTAssertEqual(f.retained.status, .unavailable)
            XCTAssertEqual(try SetupRetainedStatusV2Wire.reply(request, Self.projection(f)), bytesA)
            let releasedB = try await b.releaseIdleAfterRequest(); XCTAssertTrue(releasedB)
            XCTAssertEqual(f.retained.status, .unavailable)
            XCTAssertEqual(try SetupRetainedStatusV2Wire.reply(request, Self.projection(f)), bytesA)
            let beforeB = f.retained.owner.retainedInvocationStatusV2(authenticatedPeer: peerB, currentOwner: binding.targetOwner)
            let bytesB = try SetupRetainedStatusV2Wire.reply(request, beforeB)
            let successor = try f.retained.owner.reserveRetainedInvocation(authenticatedPeer: binding.peer,
                incarnation: UUID(), authenticatedOwner: binding.authorityOwner)
            defer { successor.record.abortConstruction() }
            XCTAssertNil(Self.projection(f).restart)
            XCTAssertEqual(f.retained.status.reservation, .observed(.reserved))
            let afterB = f.retained.owner.retainedInvocationStatusV2(authenticatedPeer: peerB, currentOwner: binding.targetOwner)
            XCTAssertEqual(afterB.v1, .unavailable)
            XCTAssertEqual(try SetupRetainedStatusV2Wire.reply(request, afterB), bytesB)
        }
    }
    func testRestartMapNeverEvictsAndRefusesANewOwnerAtCapacity() throws {
        let reader = SetupRetainedInvocationStatus.Reader(); defer { reader.close() }
        var owners: [LocalAccountIdentity] = []
        for offset in 0..<64 {
            let owner = LocalAccountIdentity(uid: getuid() + UInt32(offset) + 100, primaryGroupID: getgid(), directoryID: UUID())
            owners.append(owner)
            XCTAssertTrue(try reader.publishRestartOwned(.init(accountID: Data(repeating: UInt8(offset), count: 16), owner: owner)))
        }
        let peer = XPCPeerCredentials(processID: getpid(), userID: getuid(), auditSessionID: 1)
        let owner = LocalAccountIdentity(uid: getuid(), primaryGroupID: getgid(), directoryID: UUID())
        let work = try SetupOwnerAsyncWork.fixtureOwned(), replies = try SetupOwnerAsyncWork.fixtureOwned()
        let old = try SetupRetainedInvocationReservation(authenticatedPeer: peer, incarnation: UUID(),
            admission: work.admit(), reply: replies.admit(), activity: nil, authenticatedOwner: owner)
        old.abortConstruction(); reader.publish(old, owner: owner)
        XCTAssertEqual(reader.read(authenticatedPeer: peer, currentOwner: owner).reservation, .observed(.settled))
        XCTAssertFalse(try reader.publishRestartOwned(.init(accountID: Data(repeating: 99, count: 16), owner: owner)))
        XCTAssertEqual(reader.readV2(authenticatedPeer: peer, currentOwner: owner), .unavailable)
        for account in owners {
            let peer = XPCPeerCredentials(processID: getpid(), userID: account.uid, auditSessionID: 1)
            XCTAssertNotNil(reader.readV2(authenticatedPeer: peer, currentOwner: account).restart)
        }
        XCTAssertTrue(try reader.publishRestartOwned(.init(accountID: Data(repeating: 0, count: 16), owner: owners[0])))
    }
    func testOwnerRefusesAFreshClaimAtStatusCapacityWithoutTakingAdmissions() throws {
        try withFixture { f in
            let original = try f.retained.invocation(); try original.close()
            XCTAssertEqual(f.retained.status.reservation, .observed(.settled))
            let owners = (0..<64).map { offset in
                LocalAccountIdentity(uid: getuid() + UInt32(offset) + 100, primaryGroupID: getgid(), directoryID: UUID())
            }
            try f.retained.owner.fillRestartStatusCapacityOwned(owners)
            await Self.refuses { try await Self.claim(f) }
            XCTAssertEqual(f.retained.status, .unavailable)
            XCTAssertEqual(Self.projection(f), .unavailable)
            try Self.available(f)
            for owner in owners {
                let peer = XPCPeerCredentials(processID: getpid(), userID: owner.uid, auditSessionID: 1)
                let snapshot = f.retained.owner.retainedInvocationStatusV2(authenticatedPeer: peer, currentOwner: owner)
                XCTAssertEqual(snapshot.restart?.slot, .held)
                XCTAssertEqual(snapshot.restart?.claim, .abandoned)
            }
        }
    }
    func testActualInstallOverlappingAStatusReadCannotReturnOldSettled() throws {
        try withFixture { f in
            let old = try f.retained.invocation(); try old.close()
            let entered = RestartRecoveryTestSignal(), done = RestartRecoveryTestSignal()
            let resume = DispatchSemaphore(value: 0)
            let result = Mutex<Result<SetupRetainedStatusProjection, Error>?>(nil)
            let deadline = RestartRecoveryTestTiming.deadline(restorations: 0)
            defer { resume.signal() }
            let thread = Thread {
                do {
                    let value = try f.retained.owner.retainedInvocationStatusV2Owned(authenticatedPeer: f.retained.binding.peer,
                        currentOwner: f.retained.binding.authorityOwner, afterSnapshot: {
                            entered.signal()
                            XCTAssertEqual(resume.wait(timeout: .now() + RestartRecoveryTestTiming.remaining(deadline)), .success)
                        })
                    result.withLock { $0 = .success(value) }
                } catch { result.withLock { $0 = .failure(error) } }
                done.signal()
            }
            thread.start()
            guard await entered.wait(until: deadline) else { return XCTFail("Status snapshot did not start") }
            let claim = try await Self.claim(f); defer { claim.abandon() }
            resume.signal()
            guard await done.wait(until: deadline) else { return XCTFail("Status read did not return") }
            let observed = try XCTUnwrap(result.withLock { $0 }).get()
            XCTAssertEqual(observed, .unavailable); XCTAssertEqual(observed.v1, .unavailable)
            XCTAssertNotNil(Self.projection(f).restart)
        }
    }
    func testActualCaptureOverlappingAStatusReadCannotMixOrigins() throws {
        try withFixture { f in
            try f.seed(.stopped); let row = try XCTUnwrap(f.h.frame().window)
            f.retained.owner.publishMaintenanceRecovery(row)
            let claim = try await Self.claim(f); defer { claim.abandon() }
            let entered = RestartRecoveryTestSignal(), done = RestartRecoveryTestSignal()
            let resume = DispatchSemaphore(value: 0)
            let result = Mutex<Result<SetupRetainedStatusProjection, Error>?>(nil)
            let deadline = RestartRecoveryTestTiming.deadline(restorations: 0)
            defer { resume.signal() }
            let thread = Thread {
                do {
                    let value = try f.retained.owner.retainedInvocationStatusV2Owned(authenticatedPeer: f.retained.binding.peer,
                        currentOwner: f.retained.binding.authorityOwner, afterSnapshot: {
                            entered.signal()
                            XCTAssertEqual(resume.wait(timeout: .now() + RestartRecoveryTestTiming.remaining(deadline)), .success)
                        })
                    result.withLock { $0 = .success(value) }
                } catch { result.withLock { $0 = .failure(error) } }
                done.signal()
            }
            thread.start()
            guard await entered.wait(until: deadline) else { return XCTFail("Status snapshot did not start") }
            try await claim.restorationPhases().run { try claim.capture(row) }
            resume.signal()
            guard await done.wait(until: deadline) else { return XCTFail("Status read did not return") }
            let value = try XCTUnwrap(result.withLock { $0 }).get()
            XCTAssertEqual(value, .unavailable); XCTAssertEqual(value.v1, .unavailable)
            XCTAssertEqual(Self.projection(f).restart?.row?.window.id, row.id)
        }
    }
    func testSupersedeWithoutAHandleChangeInvalidatesTheSnapshotGeneration() throws {
        try withFixture { f in
            try f.seed(.stopped); let row = try XCTUnwrap(f.h.frame().window)
            let reader = SetupRetainedInvocationStatus.Reader(); defer { reader.close() }
            reader.publishRecovery(row)
            XCTAssertNotEqual(reader.readV2(authenticatedPeer: f.retained.binding.peer, currentOwner: f.retained.binding.authorityOwner), .unavailable)
            let value = try reader.readV2Owned(authenticatedPeer: f.retained.binding.peer,
                currentOwner: f.retained.binding.authorityOwner, afterSnapshot: { reader.supersedeRecovery(row) })
            XCTAssertEqual(value, .unavailable); XCTAssertEqual(value.v1, .unavailable)
        }
    }
    func testCustodyIsNotPublishedOpenUntilAcquisitionReturns() throws {
        try withFixture { f in
            try f.seed(.stopped)
            let enabled = Mutex(false), observations = Mutex<[SetupRestartStatus.Custody?]>([])
            let authorization = try f.retained.authorize(verify: { [weak f] in
                if enabled.withLock({ $0 }), let f {
                    observations.withLock { $0.append(Self.projection(f).restart?.custody) }
                }
            })
            let claim = try await Self.claim(f, authorization: authorization); defer { claim.abandon() }
            f.h.verifyOverride = { [weak f] in
                if let f { observations.withLock { $0.append(Self.projection(f).restart?.custody) } }
            }
            defer { f.h.verifyOverride = nil }
            _ = try await RuntimeMaintenanceRestartRestorationTests.restore(f, claim, beforeCustody: {
                observations.withLock { $0.append(Self.projection(f).restart?.custody) }
                enabled.withLock { $0 = true }
            })
            let values = observations.withLock { $0 }
            guard !values.isEmpty else { return XCTFail("No custody observations") }
            XCTAssertEqual(values[0], .notOpened)
            let acquisition = try XCTUnwrap(values.firstIndex { $0 == nil })
            let opened = try XCTUnwrap(values.firstIndex { $0 == .open })
            XCTAssertLessThan(acquisition, opened)
            XCTAssertEqual(Self.projection(f).restart?.custody, .closed)
        }
    }
}
