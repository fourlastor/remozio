import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class SetupRetainedInvocationStatusTests: XCTestCase, @unchecked Sendable {
    private typealias Status = SetupRetainedInvocationStatus
    private typealias Invocation = SetupRetainedInvocation
    private typealias Fixture = RetainedMaterialWriterFixture
    private enum Failure: Error { case work, cleanup }
    private final class Input: @unchecked Sendable {
        let peer: XPCPeerCredentials, owner: LocalAccountIdentity
        init(_ peer: XPCPeerCredentials, _ owner: LocalAccountIdentity) { self.peer = peer; self.owner = owner }
    }
    private final class Cell: @unchecked Sendable { var value: Invocation? }
    private func values(_ f: Fixture, incarnation: UUID = UUID()) throws -> (SetupRetainedCallerBinding, XPCPeerPolicy) {
        let machine = try f.machine(), state = try machine.retainedSetupCallerState(candidate: f.candidate)
        let entry = try machine.retainedSetupInitialRuntimeEntry(owner: f.owner, candidate: f.candidate)
        let member = try XCTUnwrap(state.source.actual.inventory.accounts.first)
        let (_, host) = try MachineUpdateRetainedSetupPolicyNativeEntry.publishedAuthority(runtime: entry.runtime, accountID: member.accountID)
        let app = try XCTUnwrap(host.codePolicy.entries.first { $0.role == .app && $0.active })
        let peer = XPCPeerCredentials(processID: getpid(), userID: member.ownerUID, auditSessionID: 1)
        let policy = try XPCPeerPolicy(teamID: app.teamID, componentIdentifier: app.identifier,
            approvedCodeDirectoryHashes: [app.codeDirectoryHash], expectedUserID: peer.userID)
        let binding = try SetupRetainedCallerBinding.resolve(state: state, peer: peer, incarnation: incarnation,
            accepted: policy, entry: entry, lookup: { uid in
                let account = try XCTUnwrap(state.source.preparations.first { $0.ownerUID == uid })
                return .init(uid: uid, primaryGroupID: getgid(), directoryID: account.directoryID)
            })
        return (binding, policy)
    }
    private func owner(_ f: Fixture, activity: ReleaseActivityBarrier? = nil,
        verifyHost: @escaping (InstallationInventory) throws -> Void = { _ in }) throws -> SetupAccountOwner {
        try .init(machine: f.machine(), expectedReleaseDigest: InstallationInventory.digest(f.candidate),
            resume: { _, value in value }, verifyHost: verifyHost, releaseActivity: activity)
    }
    private func read(_ owner: SetupAccountOwner, _ binding: SetupRetainedCallerBinding) -> Status {
        owner.retainedInvocationStatus(authenticatedPeer: binding.peer, currentOwner: binding.authorityOwner)
    }
    private func row(_ binding: Status.Binding, foreign: Bool = false) throws -> RuntimeMaintenanceWindowRecord {
        let digest = Data(repeating: 9, count: 32)
        let authority = foreign ? try RuntimeMaintenanceWindowRecord.Account(accountID: binding.authority.accountID,
            ownerUID: binding.authority.ownerUID, directoryID: Data(repeating: 0xe1, count: 16)) : binding.authority
        let scope = try RuntimeMaintenanceWindowRecord.Scope(macID: binding.macID, installationID: binding.installationID,
            authority: authority, target: binding.target, releaseDigest: binding.releaseDigest, candidateDigest: digest,
            authorityPolicyDigest: digest, operationDigest: digest, restorationDigest: digest, mutationFootprintDigest: digest,
            authorityGrantDigest: digest, targetConsentDigest: digest, administratorIntentDigest: digest)
        return try .init(id: Data(repeating: 0xab, count: 16), revision: Data(repeating: 0xcd, count: 16),
            purpose: .retainedRuntime, scope: scope, phase: .needsOwnerRecovery, operation: .committed,
            service: .unknown, failure: .cleanupPending)
    }
    private func captured(_ status: Status) throws -> Status.Binding {
        guard case .observed(let binding) = status.binding else { throw Failure.work }; return binding
    }
    func testReservedRecordStoresOnlyTheAuthenticatedOwnerUntilCapture() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, _) = try values(f)
            let reservation = try owner.reserveRetainedInvocation(authenticatedPeer: binding.peer, incarnation: binding.incarnation)
            defer { reservation.record.abortConstruction() }
            let before = read(owner, binding)
            XCTAssertEqual(before.reservation, .observed(.reserved)); XCTAssertEqual(before.binding, .unavailable)
            XCTAssertEqual(before.cleanup, .observed(.noneRegistered)); XCTAssertEqual(before.operation, .unavailable)
            XCTAssertEqual(before.restoration, .unavailable); XCTAssertEqual(before.supervisor, .unavailable)
            for _ in 0..<20 { XCTAssertEqual(read(owner, binding), before) }
            XCTAssertEqual(try reservation.record.state(), .reserved)
            XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
        }
    }
    func testValidatedCaptureAddsTheDistinctProtectedAuthorityAndTarget() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            defer { try? value.close() }
            XCTAssertEqual(read(owner, binding).binding, .unavailable)
            try value.captureOwnedBinding(binding)
            let snapshot = read(owner, binding), actual = try captured(snapshot)
            XCTAssertEqual(actual.authority.ownerUID, binding.peer.userID)
            XCTAssertEqual(actual.target.ownerUID, binding.targetOwner.uid)
            XCTAssertNotEqual(actual.authority.ownerUID, actual.target.ownerUID)
            XCTAssertEqual(actual.authority.accountID, binding.authorityAccountID)
            XCTAssertEqual(actual.target.accountID, binding.entry.runtime.preparation.accountID)
            XCTAssertEqual(snapshot.reservation, .observed(.attached))
        }
    }
    func testWrongUIDAloneAndTargetUIDCannotDiscloseTheRecord() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            defer { try? value.close() }; try value.captureOwnedBinding(binding)
            let wrong = XPCPeerCredentials(processID: binding.peer.processID, userID: binding.peer.userID + 20,
                auditSessionID: binding.peer.auditSessionID)
            XCTAssertEqual(owner.retainedInvocationStatus(authenticatedPeer: wrong, currentOwner: binding.authorityOwner), .unavailable)
            let target = XPCPeerCredentials(processID: binding.peer.processID, userID: binding.targetOwner.uid,
                auditSessionID: binding.peer.auditSessionID)
            XCTAssertEqual(owner.retainedInvocationStatus(authenticatedPeer: target, currentOwner: binding.targetOwner), .unavailable)
            XCTAssertEqual(read(owner, binding).reservation, .observed(.attached))
        }
    }
    func testRecycledOwnerDirectoryCannotDiscloseCapturedScope() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            defer { try? value.close() }; try value.captureOwnedBinding(binding)
            let recycled = LocalAccountIdentity(uid: binding.authorityOwner.uid,
                primaryGroupID: binding.authorityOwner.primaryGroupID, directoryID: UUID())
            XCTAssertEqual(owner.retainedInvocationStatus(authenticatedPeer: binding.peer, currentOwner: recycled), .unavailable)
        }
    }
    func testDifferentValidatedBindingRefusesWithoutReplacingTheCapturedScope() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            defer { try? value.close() }; try value.captureOwnedBinding(binding); let before = read(owner, binding)
            try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { other in
                let (changed, _) = try values(other, incarnation: binding.incarnation)
                XCTAssertEqual(changed.peer, binding.peer)
                XCTAssertThrowsError(try value.captureOwnedBinding(changed)) {
                    XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
                }
            }
            XCTAssertEqual(read(owner, binding), before)
        }
    }
    func testOrphanStatusDoesNotInferAnOutcomeOrReleaseEitherAdmission() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let activity = try ReleaseActivityFixture(), installer = try activity.open()
            let owner = try owner(f, activity: activity.open()); let (binding, policy) = try values(f)
            var value: Invocation? = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            try value?.captureOwnedBinding(binding); weak var lost = value; value = nil; XCTAssertNil(lost)
            let status = read(owner, binding); XCTAssertEqual(status.reservation, .observed(.orphan))
            XCTAssertEqual(status.operation, .unavailable); XCTAssertEqual(status.restoration, .unavailable)
            XCTAssertEqual(status.cleanup, .observed(.noneRegistered)); XCTAssertEqual(status.supervisor, .unavailable)
            XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
            XCTAssertThrowsError(try installer.acquireExclusive()); XCTAssertThrowsError(try owner.close())
            XCTAssertEqual(try owner.retainedInvocationState(), .orphan)
        }
    }
    func testStatusCompletesWhileDeinitRightsCleanupIsStillBlocked() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); let (binding, policy) = try values(f), cell = Cell()
            let entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
            defer { resume.signal(); _ = done.wait(timeout: .now() + 3) }
            cell.value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {}, closeRights: {
                entered.signal(); _ = resume.wait(timeout: .now() + 3)
            })
            DispatchQueue.global().async { cell.value = nil; done.signal() }
            XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
            XCTAssertEqual(read(owner, binding).reservation, .observed(.orphan))
            XCTAssertEqual(done.wait(timeout: .now()), .timedOut)
        }
    }
    func testStrongCleanupCaptureAndCallerDropDuringSettleDoNotDeadlock() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f), cell = Cell()
            let done = DispatchSemaphore(value: 0), failed = Mutex(false), closes = Mutex(0)
            cell.value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {},
                closeRights: { closes.withLock { $0 += 1 } })
            weak var lost = cell.value
            try cell.value?.retainCleanup { [held = try XCTUnwrap(cell.value)] in
                cell.value = nil; _ = held.incarnation
            }
            DispatchQueue.global().async {
                do { try cell.value?.close() } catch { failed.withLock { $0 = true } }; done.signal()
            }
            XCTAssertEqual(done.wait(timeout: .now() + 3), .success); XCTAssertFalse(failed.withLock { $0 })
            XCTAssertNil(lost); XCTAssertEqual(closes.withLock { $0 }, 1)
            XCTAssertEqual(read(owner, binding).reservation, .observed(.settled))
            try owner.verifyCurrent()
        }
    }
    func testCleanupFailureAndActualJoinRemainSeparateFromTheOperationOutcome() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            var calls = 0
            try value.retainCleanup {
                XCTAssertEqual(self.read(owner, binding).cleanup, .observed(.joining))
                calls += 1; if calls == 1 { throw Failure.cleanup }
            }
            XCTAssertEqual(read(owner, binding).cleanup, .observed(.pending))
            XCTAssertThrowsError(try value.close()); XCTAssertEqual(read(owner, binding).cleanup, .observed(.pending))
            XCTAssertEqual(read(owner, binding).operation, .unavailable)
            try value.close(); XCTAssertEqual(read(owner, binding).cleanup, .observed(.settled))
            XCTAssertEqual(read(owner, binding).operation, .unavailable)
        }
    }
    func testBodyFailureIsNotInventedAsADurableOperationFailure() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            XCTAssertThrowsError(try value.run(work: { throw Failure.work }, reply: { _, _ in XCTFail("Unexpected reply") }))
            XCTAssertEqual(read(owner, binding).operation, .unavailable)
            XCTAssertEqual(read(owner, binding).restoration, .unavailable)
            try value.close(); XCTAssertEqual(read(owner, binding).operation, .unavailable)
        }
    }
    func testMatchingDurableFactsAndBusySupervisorKeepTheCommittedOutcomeSeparate() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            defer { try? value.close() }; try value.captureOwnedBinding(binding)
            let initial = read(owner, binding), observedRow = try row(captured(initial))
            let status = initial.observing(observedRow).observing(supervisor: .busy)
            XCTAssertEqual(status.operation, .observed(.committed)); XCTAssertEqual(status.supervisor, .observed(.busy))
            XCTAssertEqual(status.restoration, .observed(.init(phase: .needsOwnerRecovery, service: .unknown, failure: .cleanupPending)))
            guard case .observed(let window) = status.window else { return XCTFail("Missing observed row identity") }
            XCTAssertEqual(window.id, observedRow.id); XCTAssertEqual(window.revision, observedRow.revision)
            XCTAssertEqual(read(owner, binding), initial)
        }
    }
    func testDifferentRowScopeClearsAllDurableFactsInsteadOfKeepingAnEarlierObservation() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            defer { try? value.close() }; try value.captureOwnedBinding(binding)
            let initial = read(owner, binding), protectedBinding = try captured(initial)
            let observed = initial.observing(try row(protectedBinding)), foreign = try row(protectedBinding, foreign: true)
            let refused = observed.observing(foreign)
            XCTAssertEqual(refused.window, .unavailable); XCTAssertEqual(refused.operation, .unavailable)
            XCTAssertEqual(refused.restoration, .unavailable); XCTAssertEqual(refused.reservation, initial.reservation)
        }
    }
    func testReaderAndRecordContentionReturnUnavailableWithoutWaiting() throws {
        let peer = XPCPeerCredentials(processID: getpid(), userID: getuid(), auditSessionID: 1)
        let input = Input(peer, .init(uid: getuid(), primaryGroupID: getgid(), directoryID: UUID()))
        let readerLock = NSLock(), recordLock = NSLock(), work = SetupOwnerAsyncWork(), replies = SetupOwnerAsyncWork()
        let record = try SetupRetainedInvocationReservation(authenticatedPeer: peer, incarnation: UUID(),
            admission: work.admit(), reply: replies.admit(), activity: nil, ownedStatusLock: recordLock)
        defer { record.abortConstruction() }
        let reader = try Status.Reader.openOwned(statusLock: readerLock); reader.publish(record)
        for lock in [readerLock, recordLock] {
            let done = DispatchSemaphore(value: 0), result = Mutex<Status?>(nil)
            lock.lock()
            DispatchQueue.global().async {
                result.withLock { $0 = reader.read(authenticatedPeer: input.peer, currentOwner: input.owner) }; done.signal()
            }
            let completed = done.wait(timeout: .now() + 1); lock.unlock()
            if completed != .success { _ = done.wait(timeout: .now() + 3) }
            XCTAssertEqual(completed, .success); XCTAssertEqual(result.withLock { $0 }, .unavailable)
        }
        XCTAssertEqual(try record.state(), .reserved)
    }
    func testStatusDoesNotWaitForTheOwnerLockOrWriteTheMachine() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let blocked = Mutex(false), entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0)
            let done = DispatchSemaphore(value: 0), statusDone = DispatchSemaphore(value: 0), commits = Mutex(0)
            try f.reopen { commits.withLock { $0 += 1 } }
            let owner = try owner(f, verifyHost: { _ in
                if blocked.withLock({ $0 }) { entered.signal(); _ = resume.wait(timeout: .now() + 3) }
            })
            defer { resume.signal(); _ = done.wait(timeout: .now() + 3); try? owner.close() }
            let (binding, _) = try values(f), input = Input(binding.peer, binding.authorityOwner)
            blocked.withLock { $0 = true }
            DispatchQueue.global().async { try? owner.verifyCurrent(); done.signal() }
            XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
            let result = Mutex<Status?>(nil)
            DispatchQueue.global().async {
                result.withLock { $0 = owner.retainedInvocationStatus(authenticatedPeer: input.peer, currentOwner: input.owner) }
                statusDone.signal()
            }
            let completed = statusDone.wait(timeout: .now() + 1); XCTAssertEqual(completed, .success)
            resume.signal()
            if completed != .success { _ = statusDone.wait(timeout: .now() + 3) }
            XCTAssertEqual(result.withLock { $0?.reservation }, .observed(.absent)); XCTAssertEqual(commits.withLock { $0 }, 0)
            blocked.withLock { $0 = false }
        }
    }
    func testClosedReaderAndInvalidPeerReturnUnavailable() throws {
        let reader = Status.Reader(), peer = XPCPeerCredentials(processID: getpid(), userID: getuid(), auditSessionID: 1)
        let owner = LocalAccountIdentity(uid: getuid(), primaryGroupID: getgid(), directoryID: UUID())
        XCTAssertEqual(reader.read(authenticatedPeer: peer, currentOwner: owner).reservation, .observed(.absent))
        let invalid = XPCPeerCredentials(processID: 0, userID: peer.userID, auditSessionID: peer.auditSessionID)
        XCTAssertEqual(reader.read(authenticatedPeer: invalid, currentOwner: owner), .unavailable)
        reader.close(); XCTAssertEqual(reader.read(authenticatedPeer: peer, currentOwner: owner), .unavailable)
    }
    func testTwoReservationsOnOneConnectionHaveDistinctRedactedIdentities() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let first = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            let old = read(owner, binding); try first.close()
            let second = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            defer { try? second.close() }; let new = read(owner, binding)
            guard case .observed(let a) = old.identity, case .observed(let b) = new.identity else { return XCTFail("Missing identity") }
            XCTAssertEqual(a.incarnation, b.incarnation); XCTAssertNotEqual(a.reservationID, b.reservationID)
            XCTAssertEqual(new.reservation, .observed(.attached))
        }
    }
    func testStatusBindingWindowAndIdentityRedactDescriptionsDumpsAndMirrors() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            defer { try? value.close() }; try value.captureOwnedBinding(binding)
            let initial = read(owner, binding), protectedBinding = try captured(initial)
            let status = initial.observing(try row(protectedBinding))
            var output = ""; dump(status, to: &output)
            XCTAssertEqual(String(describing: status), "SetupRetainedInvocationStatus(redacted)")
            XCTAssertEqual(String(reflecting: status), "SetupRetainedInvocationStatus(redacted)")
            XCTAssertTrue(Mirror(reflecting: status).children.isEmpty); XCTAssertTrue(Mirror(reflecting: protectedBinding).children.isEmpty)
            XCTAssertFalse(output.contains("accountID")); XCTAssertFalse(output.contains(binding.incarnation.uuidString))
            if case .observed(let window) = status.window { XCTAssertTrue(Mirror(reflecting: window).children.isEmpty) }
            if case .observed(let identity) = status.identity { XCTAssertTrue(Mirror(reflecting: identity).children.isEmpty) }
        }
    }
}
