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
    private func withCapturePath(verifyRights: @escaping () throws -> Void = {}, afterCapture: @escaping () throws -> Void = {},
        _ body: (Fixture, SetupAccountOwner, SetupRetainedCallerBinding, Invocation, XPCInvocationGuard) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (_, policy) = try values(f)
            let connection = NSXPCConnection(machServiceName: AdministrativeSetupConfiguration.serviceName)
            defer { connection.invalidate() }
            let guardValue = XPCInvocationGuard(connection: connection, policy: policy)
            let (binding, _) = try values(f, incarnation: guardValue.incarnation)
            let inputs = try MachineUpdateRetainedSetupRuntimeInputs.capture(expected: binding.entry.runtime, journal: nil,
                verifyCurrent: {}, readRelay: { _ in throw SharedSetupImportError.wrongScope })
            let capture = try SetupAccountOwner.RetainedMaintenanceCapture.openOwned(binding: binding, inputs: inputs)
            let value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: verifyRights,
                ownedCapture: .init(invocation: guardValue, verifyPeer: { binding.peer }, binding: {
                    try afterCapture(); return binding
                }, maintenance: { try afterCapture(); return capture }))
            defer { try? value.close() }
            try body(f, owner, binding, value, guardValue)
        }
    }
    private func window(_ f: Fixture, _ value: Invocation, _ guardValue: XPCInvocationGuard) throws -> RuntimeMaintenanceWindowRecord {
        let expected = try value.maintenanceCapture(invocation: guardValue, candidate: f.candidate, purpose: .retainedRuntime)
        let authorized = try value.authorizedMaintenanceWindow(invocation: guardValue, expected: expected,
            purpose: .retainedRuntime, candidate: f.candidate, id: Data(repeating: 0xab, count: 16), revision: Data(repeating: 0xcd, count: 16))
        return try .init(id: authorized.id, revision: authorized.revision, purpose: authorized.purpose, scope: authorized.scope,
            phase: .needsOwnerRecovery, operation: .committed, service: .unknown, failure: .cleanupPending)
    }
    func testReservedRecordStoresOnlyTheAuthenticatedOwnerUntilCapture() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, _) = try values(f)
            let reservation = try owner.reserveRetainedInvocation(authenticatedPeer: binding.peer, incarnation: binding.incarnation, authenticatedOwner: binding.authorityOwner)
            defer { reservation.record.abortConstruction() }
            let before = read(owner, binding)
            XCTAssertEqual(before.reservation, .observed(.reserved)); XCTAssertEqual(before.binding, .unavailable)
            XCTAssertEqual(before.identity, .unavailable)
            let recycled = LocalAccountIdentity(uid: binding.authorityOwner.uid, primaryGroupID: getgid(), directoryID: UUID())
            XCTAssertEqual(owner.retainedInvocationStatus(authenticatedPeer: binding.peer, currentOwner: recycled).identity, .unavailable)
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
            XCTAssertEqual(read(owner, binding).identity, .unavailable)
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
        try withCapturePath { f, owner, binding, value, guardValue in
            let observedRow = try window(f, value, guardValue), initial = read(owner, binding)
            XCTAssertEqual(initial.window, .unavailable); XCTAssertEqual(initial.operation, .unavailable)
            let status = initial.observing(observedRow).observing(supervisor: .busy)
            XCTAssertEqual(status.operation, .observed(.committed)); XCTAssertEqual(status.supervisor, .observed(.busy))
            XCTAssertEqual(status.restoration, .observed(.init(phase: .needsOwnerRecovery, service: .unknown, failure: .cleanupPending)))
            guard case .observed(let actual) = status.window else { return XCTFail("Missing observed row identity") }
            XCTAssertEqual(actual.id, observedRow.id); XCTAssertEqual(actual.revision, observedRow.revision)
            XCTAssertEqual(read(owner, binding), initial)
        }
    }
    func testDifferentRowScopeClearsAllDurableFactsInsteadOfKeepingAnEarlierObservation() throws {
        try withCapturePath { f, owner, binding, value, guardValue in
            let actual = try window(f, value, guardValue), initial = read(owner, binding), protectedBinding = try captured(initial)
            let observed = initial.observing(actual), foreign = try row(protectedBinding, foreign: true)
            let refused = observed.observing(foreign)
            XCTAssertEqual(refused.window, .unavailable); XCTAssertEqual(refused.operation, .unavailable)
            XCTAssertEqual(refused.restoration, .unavailable); XCTAssertEqual(refused.reservation, initial.reservation)
        }
    }
    func testCallerBindingPathPublishesOnlyAfterItsFinalRightsCheck() throws {
        try withCapturePath { f, owner, binding, value, guardValue in
            XCTAssertEqual(read(owner, binding).identity, .unavailable)
            let actual = try value.callerBinding(invocation: guardValue, candidate: f.candidate)
            XCTAssertEqual(actual.peer, binding.peer); XCTAssertEqual(actual.incarnation, binding.incarnation)
            let status = read(owner, binding)
            XCTAssertEqual(try captured(status), try Status.capturedBinding(binding))
            guard case .observed = status.identity else { return XCTFail("Missing captured identity") }
            let stale = try row(captured(status)), refused = status.observing(stale)
            XCTAssertEqual(refused.window, .unavailable); XCTAssertEqual(refused.operation, .unavailable)
            XCTAssertEqual(refused.restoration, .unavailable)
        }
    }
    func testMaintenanceCapturePathBindsBeforeTheExactAuthorizedWindowIsObserved() throws {
        try withCapturePath { f, owner, binding, value, guardValue in
            let capture = try value.maintenanceCapture(invocation: guardValue, candidate: f.candidate, purpose: .retainedRuntime)
            XCTAssertEqual(capture.binding.incarnation, binding.incarnation)
            let before = read(owner, binding)
            XCTAssertEqual(try captured(before), try Status.capturedBinding(binding))
            XCTAssertEqual(before.observing(try row(captured(before))).operation, .unavailable)
            let actual = try window(f, value, guardValue)
            XCTAssertEqual(read(owner, binding).observing(actual).operation, .observed(.committed))
        }
    }
    func testFailedFinalRightsCheckNeverPublishesEitherCapturePath() throws {
        for maintenance in [false, true] {
            var valid = true
            try withCapturePath(verifyRights: { if !valid { throw Failure.work } }, afterCapture: { valid = false }) {
                f, owner, binding, value, guardValue in
                if maintenance {
                    XCTAssertThrowsError(try value.maintenanceCapture(invocation: guardValue, candidate: f.candidate, purpose: .retainedRuntime))
                } else { XCTAssertThrowsError(try value.callerBinding(invocation: guardValue, candidate: f.candidate)) }
                XCTAssertEqual(read(owner, binding).binding, .unavailable)
                XCTAssertEqual(read(owner, binding).identity, .unavailable)
                XCTAssertEqual(read(owner, binding).operation, .unavailable)
            }
        }
    }
    func testAnotherWindowForTheSameAccountsCannotSupplyAnOutcome() throws {
        try withCapturePath { f, owner, binding, value, guardValue in
            let actual = try window(f, value, guardValue), initial = read(owner, binding), scope = actual.scope
            let otherCandidate = try RuntimeMaintenanceWindowRecord.Scope(macID: scope.macID, installationID: scope.installationID,
                authority: scope.authority, target: scope.target, releaseDigest: scope.releaseDigest, candidateDigest: Data(repeating: 0xe1, count: 32),
                authorityPolicyDigest: scope.authorityPolicyDigest, operationDigest: scope.operationDigest, restorationDigest: scope.restorationDigest,
                mutationFootprintDigest: scope.mutationFootprintDigest, authorityGrantDigest: scope.authorityGrantDigest,
                targetConsentDigest: scope.targetConsentDigest, administratorIntentDigest: scope.administratorIntentDigest)
            let rows = try [
                RuntimeMaintenanceWindowRecord(id: Data(repeating: 0xe2, count: 16), revision: actual.revision, purpose: actual.purpose, scope: scope),
                RuntimeMaintenanceWindowRecord(id: actual.id, revision: actual.revision, purpose: .retainedPolicy, scope: scope),
                RuntimeMaintenanceWindowRecord(id: actual.id, revision: actual.revision, purpose: actual.purpose, scope: otherCandidate)]
            for row in rows {
                let refused = initial.observing(actual).observing(row)
                XCTAssertEqual(refused.window, .unavailable); XCTAssertEqual(refused.operation, .unavailable)
                XCTAssertEqual(refused.restoration, .unavailable)
            }
            XCTAssertEqual(initial.observing(actual).operation, .observed(.committed))
        }
    }
    func testSameWindowWithALaterRevisionExposesTheActualRowOutcome() throws {
        try withCapturePath { f, owner, binding, value, guardValue in
            let actual = try window(f, value, guardValue), initial = read(owner, binding)
            let later = try RuntimeMaintenanceWindowRecord(id: actual.id, revision: Data(repeating: 0xe3, count: 16),
                purpose: actual.purpose, scope: actual.scope, phase: .needsOwnerRecovery,
                operation: .failed, service: .unknown, failure: .operationUncertain)
            let observed = initial.observing(later)
            XCTAssertEqual(observed.operation, .observed(.failed))
            XCTAssertEqual(observed.restoration, .observed(.init(phase: .needsOwnerRecovery, service: .unknown, failure: .operationUncertain)))
            guard case .observed(let window) = observed.window else { return XCTFail("Missing observed window") }
            XCTAssertEqual(window.id, actual.id); XCTAssertEqual(window.revision, later.revision)
            XCTAssertNotEqual(window.revision, actual.revision)
        }
    }
    func testRunningWorkerDoesNotInventRegisteredCleanup() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            defer { try? value.close() }
            XCTAssertEqual(read(owner, binding).worker, .observed(.idle))
            try value.run(work: {
                let status = read(owner, binding)
                XCTAssertEqual(status.worker, .observed(.running)); XCTAssertEqual(status.cleanup, .observed(.noneRegistered))
                XCTAssertEqual(status.operation, .unavailable)
            }, reply: { _, _ in })
            XCTAssertEqual(read(owner, binding).worker, .observed(.idle))
            XCTAssertEqual(read(owner, binding).cleanup, .observed(.noneRegistered))
        }
    }
    func testRecordReplacementDuringAReadReturnsUnavailable() throws {
        let peer = XPCPeerCredentials(processID: getpid(), userID: getuid(), auditSessionID: 1)
        let account = LocalAccountIdentity(uid: getuid(), primaryGroupID: getgid(), directoryID: UUID())
        let work = SetupOwnerAsyncWork(), replies = SetupOwnerAsyncWork(), reader = Status.Reader()
        let first = try SetupRetainedInvocationReservation(authenticatedPeer: peer, incarnation: UUID(),
            admission: work.admit(), reply: replies.admit(), activity: nil, authenticatedOwner: account)
        let second = try SetupRetainedInvocationReservation(authenticatedPeer: peer, incarnation: UUID(),
            admission: SetupOwnerAsyncWork().admit(), reply: SetupOwnerAsyncWork().admit(), activity: nil, authenticatedOwner: account)
        defer { first.abortConstruction(); second.abortConstruction() }
        reader.publish(first)
        XCTAssertEqual(try reader.readOwned(authenticatedPeer: peer, currentOwner: account, afterSnapshot: { reader.publish(second) }), .unavailable)
        XCTAssertEqual(reader.read(authenticatedPeer: peer, currentOwner: account).reservation, .observed(.reserved))
    }
    func testReaderAndRecordContentionReturnUnavailableWithoutWaiting() throws {
        let peer = XPCPeerCredentials(processID: getpid(), userID: getuid(), auditSessionID: 1)
        let input = Input(peer, .init(uid: getuid(), primaryGroupID: getgid(), directoryID: UUID()))
        let readerLock = NSLock(), recordLock = NSLock(), work = SetupOwnerAsyncWork(), replies = SetupOwnerAsyncWork()
        let record = try SetupRetainedInvocationReservation(authenticatedPeer: peer, incarnation: UUID(),
            admission: work.admit(), reply: replies.admit(), activity: nil, ownedStatusLock: recordLock, authenticatedOwner: input.owner)
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
            // A settled record stays published and releases both admissions, so the owner lock can be held below.
            let reservation = try owner.reserveRetainedInvocation(authenticatedPeer: binding.peer, incarnation: binding.incarnation)
            reservation.record.abortConstruction()
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
            // Real facts while the owner lock is held: status reads the published projection, never the owner lock.
            XCTAssertEqual(result.withLock { $0?.reservation }, .observed(.settled)); XCTAssertEqual(commits.withLock { $0 }, 0)
            blocked.withLock { $0 = false }
        }
    }
    func testClosedReaderAndInvalidPeerReturnUnavailable() throws {
        let reader = Status.Reader(), peer = XPCPeerCredentials(processID: getpid(), userID: getuid(), auditSessionID: 1)
        let owner = LocalAccountIdentity(uid: getuid(), primaryGroupID: getgid(), directoryID: UUID())
        // An empty slot has no owner, so even a valid peer cannot learn that no reservation exists.
        XCTAssertEqual(reader.read(authenticatedPeer: peer, currentOwner: owner), .unavailable)
        let invalid = XPCPeerCredentials(processID: 0, userID: peer.userID, auditSessionID: peer.auditSessionID)
        XCTAssertEqual(reader.read(authenticatedPeer: invalid, currentOwner: owner), .unavailable)
        reader.close(); XCTAssertEqual(reader.read(authenticatedPeer: peer, currentOwner: owner), .unavailable)
    }
    func testStatusLaneCheckNeverWaitsAndNeverBorrowsTheReservationAdmission() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let blocked = Mutex(false), drift = Mutex(false), leaseBusy = Mutex(false), entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0)
            let done = DispatchSemaphore(value: 0)
            let owner = try owner(f, verifyHost: { _ in
                if drift.withLock({ $0 }) { throw AdministrativeSetupError.changedInstallation }
                if leaseBusy.withLock({ $0 }) { throw JournalLeaseError.busy }
                if blocked.withLock({ $0 }) { entered.signal(); _ = resume.wait(timeout: .now() + 3) }
            })
            defer { resume.signal(); _ = done.wait(timeout: .now() + 3); try? owner.close() }
            XCTAssertEqual(owner.statusLaneCheck(), .verified)
            drift.withLock { $0 = true }; XCTAssertEqual(owner.statusLaneCheck(), .refused); drift.withLock { $0 = false }
            // A busy writer lease is not drift: it only leaves the store-derived facts unavailable.
            leaseBusy.withLock { $0 = true }; XCTAssertEqual(owner.statusLaneCheck(), .busy); leaseBusy.withLock { $0 = false }
            XCTAssertEqual(owner.statusLaneCheck(), .verified)
            let (binding, _) = try values(f)
            let reservation = try owner.reserveRetainedInvocation(authenticatedPeer: binding.peer, incarnation: binding.incarnation)
            // The reservation holds the admission: the store is not read, so even drift cannot be observed here.
            drift.withLock { $0 = true }; XCTAssertEqual(owner.statusLaneCheck(), .pinned); drift.withLock { $0 = false }
            XCTAssertEqual(try reservation.record.state(), .reserved)
            reservation.record.abortConstruction()
            blocked.withLock { $0 = true }
            DispatchQueue.global().async { try? owner.verifyCurrent(); done.signal() }
            XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
            let started = DispatchTime.now()
            XCTAssertEqual(owner.statusLaneCheck(), .busy)
            XCTAssertLessThan(DispatchTime.now().uptimeNanoseconds - started.uptimeNanoseconds, 1_000_000_000)
            blocked.withLock { $0 = false }; resume.signal()
            XCTAssertEqual(done.wait(timeout: .now() + 3), .success)
            try owner.close(); XCTAssertEqual(owner.statusLaneCheck(), .refused)
        }
    }
    func testOwnerStatusEntryLooksUpTheDirectoryIdentityFromTheAuthenticatedUID() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let (binding, _) = try values(f), lookups = Mutex<[uid_t]>([]), unknown = Mutex(false)
            let owner = try SetupAccountOwner(machine: f.machine(), expectedReleaseDigest: InstallationInventory.digest(f.candidate),
                resume: { _, value in value }, lookupAccount: { uid in
                    lookups.withLock { $0.append(uid) }
                    if unknown.withLock({ $0 }) { throw AdministrativeSetupError.wrongAccount }
                    return binding.authorityOwner
                })
            defer { try? owner.close() }
            let reservation = try owner.reserveRetainedInvocation(authenticatedPeer: binding.peer, incarnation: binding.incarnation)
            defer { reservation.record.abortConstruction() }
            XCTAssertEqual(owner.retainedInvocationStatus(authenticatedPeer: binding.peer), read(owner, binding))
            XCTAssertEqual(owner.retainedInvocationStatus(authenticatedPeer: binding.peer).reservation, .observed(.reserved))
            XCTAssertEqual(lookups.withLock { $0 }, [binding.peer.userID, binding.peer.userID])
            unknown.withLock { $0 = true }
            XCTAssertEqual(owner.retainedInvocationStatus(authenticatedPeer: binding.peer), .unavailable)
        }
    }
    /// The Setup owner is machine-wide and records no single account owner before a reservation exists, so an empty
    /// slot has no owner to match: every UID, including the caller's own, reads unavailable rather than absent.
    func testEmptySlotAnswersUnavailableForEveryUID() throws {
        let reader = Status.Reader()
        for uid in [getuid(), getuid() + 1, 501, 502] {
            let peer = XPCPeerCredentials(processID: getpid(), userID: uid, auditSessionID: 1)
            let owner = LocalAccountIdentity(uid: uid, primaryGroupID: getgid(), directoryID: UUID())
            XCTAssertEqual(reader.read(authenticatedPeer: peer, currentOwner: owner), .unavailable, "\(uid)")
        }
    }
    func testTwoReservationsOnOneConnectionHaveDistinctRedactedIdentities() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let first = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            try first.captureOwnedBinding(binding)
            let old = read(owner, binding); try first.close()
            let second = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            defer { try? second.close() }; try second.captureOwnedBinding(binding); let new = read(owner, binding)
            guard case .observed(let a) = old.identity, case .observed(let b) = new.identity else { return XCTFail("Missing identity") }
            XCTAssertEqual(a.incarnation, b.incarnation); XCTAssertNotEqual(a.reservationID, b.reservationID)
            XCTAssertEqual(new.reservation, .observed(.attached))
        }
    }
    func testStatusBindingWindowAndIdentityRedactDescriptionsDumpsAndMirrors() throws {
        try withCapturePath { f, owner, binding, value, guardValue in
            let actual = try window(f, value, guardValue), initial = read(owner, binding), protectedBinding = try captured(initial)
            let status = initial.observing(actual)
            var output = ""; dump(status, to: &output)
            XCTAssertEqual(String(describing: status), "SetupRetainedInvocationStatus(redacted)")
            XCTAssertEqual(String(reflecting: status), "SetupRetainedInvocationStatus(redacted)")
            XCTAssertTrue(Mirror(reflecting: status).children.isEmpty); XCTAssertTrue(Mirror(reflecting: protectedBinding).children.isEmpty)
            XCTAssertFalse(output.contains("accountID")); XCTAssertFalse(output.contains(binding.incarnation.uuidString))
            guard case .observed(let window) = status.window, case .observed(let identity) = status.identity else { return XCTFail("Missing captured identities") }
            XCTAssertTrue(Mirror(reflecting: window).children.isEmpty); XCTAssertTrue(Mirror(reflecting: identity).children.isEmpty)
        }
    }
}
