import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class SetupRetainedInvocationTests: XCTestCase {
    private enum Failure: Error { case rights, work, reply, cleanup }
    private typealias Invocation = SetupRetainedInvocation
    private typealias Fixture = RetainedMaterialWriterFixture
    private func values(_ f: Fixture) throws -> (SetupRetainedCallerBinding, XPCPeerPolicy) {
        let machine = try f.machine(), state = try machine.retainedSetupCallerState(candidate: f.candidate)
        let entry = try machine.retainedSetupInitialRuntimeEntry(owner: f.owner, candidate: f.candidate)
        let member = try XCTUnwrap(state.source.actual.inventory.accounts.first)
        let (_, host) = try MachineUpdateRetainedSetupPolicyNativeEntry.publishedAuthority(runtime: entry.runtime, accountID: member.accountID)
        let app = try XCTUnwrap(host.codePolicy.entries.first { $0.role == .app && $0.active })
        let peer = XPCPeerCredentials(processID: getpid(), userID: member.ownerUID, auditSessionID: 1)
        let policy = try XPCPeerPolicy(teamID: app.teamID, componentIdentifier: app.identifier,
            approvedCodeDirectoryHashes: [app.codeDirectoryHash], expectedUserID: peer.userID)
        let binding = try SetupRetainedCallerBinding.resolve(state: state, peer: peer, incarnation: UUID(),
            accepted: policy, entry: entry, lookup: { uid in
                let account = try XCTUnwrap(state.source.preparations.first { $0.ownerUID == uid })
                return .init(uid: uid, primaryGroupID: getgid(), directoryID: account.directoryID)
            })
        return (binding, policy)
    }
    private func owner(_ f: Fixture, activity: ReleaseActivityBarrier? = nil) throws -> SetupAccountOwner {
        try .init(machine: f.machine(), expectedReleaseDigest: InstallationInventory.digest(f.candidate),
            resume: { _, value in value }, releaseActivity: activity)
    }
    func testReservationAndSharedActivitySurviveWorkAndReplyUntilClose() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let activity = try ReleaseActivityFixture(), barrier = try activity.open(), installer = try activity.open()
            let owner = try owner(f, activity: barrier); defer { try? owner.close() }
            let (binding, policy) = try values(f)
            var checks = 0, closes = 0, replies = 0
            let invocation = try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                verifyRights: { checks += 1 }, closeRights: {
                    closes += 1
                    do {
                        XCTAssertEqual(try owner.retainedInvocationState(), .attached)
                        XCTAssertThrowsError(try owner.verifyCurrent())
                        XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
                        XCTAssertThrowsError(try installer.acquireExclusive())
                    } catch { XCTFail("Rights cleanup observation failed: \(error)") }
                })
            XCTAssertEqual(invocation.incarnation, binding.incarnation)
            XCTAssertEqual(invocation.acceptedPolicy.requirement, policy.requirement)
            XCTAssertEqual(invocation.peer, binding.peer)
            XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
            XCTAssertThrowsError(try installer.acquireExclusive())
            try invocation.run(work: {
                XCTAssertThrowsError(try invocation.run(work: {}, reply: { _, _ in XCTFail("Reentry") }))
                XCTAssertThrowsError(try invocation.close())
                return 17
            }, reply: { value, state in
                XCTAssertEqual(value, 17); XCTAssertEqual(state, .init(cancelled: false, expired: false)); replies += 1
                XCTAssertThrowsError(try invocation.close()); XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
                XCTAssertThrowsError(try installer.acquireExclusive())
            })
            XCTAssertEqual(replies, 1); XCTAssertGreaterThan(checks, 2); XCTAssertEqual(closes, 0)
            XCTAssertThrowsError(try invocation.run(work: {}, reply: { _, _ in XCTFail("Replay") }))
            XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try installer.acquireExclusive())
            try invocation.close(); try invocation.close(); XCTAssertEqual(closes, 1)
            let update = try installer.acquireExclusive(); update.close()
            let reply = try owner.acquireSetupReplyAdmission(); reply.close(); try owner.verifyCurrent()
            XCTAssertThrowsError(try invocation.validateLifetime())
        }
    }
    func testExpiryAndConnectionCancellationStopStagesWithoutReleasingAdmission() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            var valid = true, closes = 0
            let expired = try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                verifyRights: { if !valid { throw Failure.rights } }, closeRights: { closes += 1 })
            valid = false
            XCTAssertThrowsError(try expired.run(work: { XCTFail("Expired work") }, reply: { _, _ in XCTFail("Expired reply") }))
            XCTAssertThrowsError(try owner.verifyCurrent()); try expired.close(); XCTAssertEqual(closes, 1)
            let cancelled = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            cancelled.cancel(incarnation: UUID()); try cancelled.validateLifetime()
            var replies = 0
            try cancelled.run(work: {
                cancelled.cancel(incarnation: binding.incarnation); return "committed"
            }, reply: { value, state in
                XCTAssertEqual(value, "committed"); XCTAssertEqual(state, .init(cancelled: true, expired: false)); replies += 1
            })
            XCTAssertEqual(replies, 1)
            XCTAssertThrowsError(try cancelled.run(work: {}, reply: { _, _ in XCTFail("Cancelled replay") }))
            XCTAssertThrowsError(try owner.acquireSetupReplyAdmission()); try cancelled.close(); try owner.verifyCurrent()
        }
    }
    func testConstructionFailureDoesNotStealAnotherReservationOrLeakRights() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            var closes = 0
            XCTAssertThrowsError(try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                verifyRights: { throw Failure.rights }, closeRights: { closes += 1 }))
            XCTAssertEqual(closes, 1); try owner.verifyCurrent()
            let first = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            XCTAssertThrowsError(try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                verifyRights: {}, closeRights: { closes += 1 }))
            XCTAssertEqual(closes, 2); try first.validateLifetime(); try first.close(); try owner.verifyCurrent()
            var checks = 0
            XCTAssertThrowsError(try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                verifyRights: { checks += 1; if checks == 2 { throw Failure.rights } }, closeRights: { closes += 1 }))
            XCTAssertEqual(closes, 3); try owner.verifyCurrent()
        }
    }
    func testWorkReplyAndCleanupFailuresKeepOwnershipUntilExplicitSettlement() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            for failReply in [false, true] {
                var closes = 0
                let invocation = try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                    verifyRights: {}, closeRights: { closes += 1 })
                XCTAssertThrowsError(try invocation.run(work: {
                    if !failReply { throw Failure.work }; return 1
                }, reply: { _, _ in throw Failure.reply }))
                func cleanup(_ fail: Bool) throws { if fail { throw Failure.cleanup }; try invocation.close() }
                XCTAssertThrowsError(try cleanup(true)); XCTAssertEqual(closes, 0)
                XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
                XCTAssertThrowsError(try invocation.run(work: {}, reply: { _, _ in XCTFail("Failed work replay") }))
                try cleanup(false); XCTAssertEqual(closes, 1); try owner.verifyCurrent()
            }
            let shutdown = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            XCTAssertThrowsError(try owner.close()); XCTAssertThrowsError(try shutdown.validateLifetime())
            try shutdown.close(); try owner.close()
        }
    }
    func testNativeFactoryRefusesOrdinaryIdentityAndExplicitCloseReleasesOnce() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let connection = NSXPCConnection(machServiceName: AdministrativeSetupConfiguration.serviceName)
            defer { connection.invalidate() }; let guardValue = XPCInvocationGuard(connection: connection, policy: policy)
            XCTAssertThrowsError(try Invocation.open(owner: owner, invocation: guardValue, externalForm: Data())) {
                XCTAssertEqual($0 as? SetupAdministratorAuthorizationError, .wrongProcess)
            }
            var closes = 0
            do {
                let value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                    verifyRights: {}, closeRights: { closes += 1 })
                XCTAssertThrowsError(try value.callerBinding(invocation: guardValue, candidate: f.candidate)) {
                    if case XPCPeerPolicyError.wrongConnection = $0 {} else { XCTFail("Unexpected failure: \($0)") }
                }
                XCTAssertThrowsError(try owner.verifyCurrent())
                XCTAssertEqual(value.description, "SetupRetainedInvocation(redacted)")
                XCTAssertTrue(value.customMirror.children.isEmpty)
                try value.close(); try value.close(); XCTAssertEqual(closes, 1)
            }
            XCTAssertEqual(closes, 1); try owner.verifyCurrent()
        }
    }
    func testLostInvocationClosesRightsButKeepsAdmissionsAndSharedActivity() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let activity = try ReleaseActivityFixture(), installer = try activity.open()
            var setup: SetupAccountOwner? = try owner(f, activity: activity.open())
            let (binding, policy) = try values(f); var closes = 0
            var dropped: Invocation? = try Invocation.openOwned(owner: XCTUnwrap(setup), binding: binding, policy: policy,
                verifyRights: {}, closeRights: { closes += 1 })
            weak var weakInvocation = dropped; weak var weakOwner = setup
            XCTAssertNotNil(weakInvocation); dropped = nil
            XCTAssertNil(weakInvocation); XCTAssertEqual(closes, 1)
            XCTAssertThrowsError(try XCTUnwrap(setup).verifyCurrent())
            XCTAssertThrowsError(try XCTUnwrap(setup).acquireSetupReplyAdmission())
            XCTAssertThrowsError(try installer.acquireExclusive())
            XCTAssertThrowsError(try Invocation.openOwned(owner: XCTUnwrap(setup), binding: binding, policy: policy,
                verifyRights: {}, closeRights: { closes += 1 }))
            XCTAssertEqual(closes, 2); XCTAssertThrowsError(try XCTUnwrap(setup).close())
            setup = nil; XCTAssertNil(weakOwner)
            let released = try installer.acquireExclusive(); released.close()
        }
    }
    func testLateRightsChangesPreserveTheValueAndNeverPermitReplay() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let changesToCheck: [(cancelled: Bool, expired: Bool)] = [(false, true), (true, true), (false, false)]
            for changes in changesToCheck {
                var valid = true, replies = 0, works = 0
                let invocation = try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                    verifyRights: { if !valid { throw Failure.rights } })
                try invocation.run(work: {
                    works += 1
                    if changes.cancelled { invocation.cancel(incarnation: binding.incarnation) }
                    valid = !changes.expired
                    return "committed"
                }, reply: { value, state in
                    XCTAssertEqual(value, "committed")
                    XCTAssertEqual(state, .init(cancelled: changes.cancelled, expired: changes.expired)); replies += 1
                    XCTAssertThrowsError(try invocation.close())
                    XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
                })
                XCTAssertEqual(works, 1); XCTAssertEqual(replies, 1)
                XCTAssertThrowsError(try invocation.run(work: { works += 1 }, reply: { _, _ in XCTFail("Replay") }))
                XCTAssertEqual(works, 1); try invocation.close(); try owner.verifyCurrent()
            }
            let shutdown = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            var replies = 0
            try shutdown.run(work: { XCTAssertThrowsError(try owner.close()); return "committed" }, reply: { value, state in
                XCTAssertEqual(value, "committed"); XCTAssertEqual(state, .init(cancelled: false, expired: false)); replies += 1
            })
            XCTAssertEqual(replies, 1); try shutdown.close(); try owner.close()
        }
    }
    func testConstructionGapIsReservedUntilTheExactInvocationAttaches() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            var checks = 0
            let value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {
                checks += 1
                if checks == 2 {
                    XCTAssertEqual(try owner.retainedInvocationState(), .reserved)
                    XCTAssertThrowsError(try owner.verifyCurrent())
                    XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
                }
            })
            XCTAssertEqual(try owner.retainedInvocationState(), .attached)
            try value.close(); XCTAssertEqual(try owner.retainedInvocationState(), .settled)
            try owner.verifyCurrent()
        }
    }
    func testConstructionFailureSettlesOnlyItsReservedRecord() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            var checks = 0
            XCTAssertThrowsError(try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {
                checks += 1
                if checks == 2 {
                    XCTAssertEqual(try owner.retainedInvocationState(), .reserved); throw Failure.rights
                }
            }))
            XCTAssertEqual(try owner.retainedInvocationState(), .settled); try owner.verifyCurrent()
            let current = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            XCTAssertEqual(try owner.retainedInvocationState(), .attached)
            try current.close()
        }
    }
    func testForeignInvocationCannotAttachEvenWithTheSameIncarnation() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let first = try owner(f), second = try owner(f)
            defer { try? first.close(); try? second.close() }; let (binding, policy) = try values(f)
            let reserved = try first.reserveRetainedInvocation(incarnation: binding.incarnation)
            defer { reserved.record.abortConstruction() }
            let foreign = try Invocation.openOwned(owner: second, binding: binding, policy: policy, verifyRights: {})
            defer { try? foreign.close() }
            XCTAssertThrowsError(try reserved.record.attach(foreign))
            XCTAssertEqual(try first.retainedInvocationState(), .reserved)
            XCTAssertThrowsError(try reserved.record.settle(foreign))
            XCTAssertThrowsError(try first.verifyCurrent()); try foreign.validateLifetime()
        }
    }
    func testOrphanKeepsBothAdmissionsAndSharedActivityAfterCancellationAndConnectionLoss() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let activity = try ReleaseActivityFixture(), installer = try activity.open()
            let owner = try owner(f, activity: activity.open()); let (binding, policy) = try values(f)
            let connection = NSXPCConnection(machServiceName: AdministrativeSetupConfiguration.serviceName)
            var value: Invocation? = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            try value?.installOwnedContext(connection: connection, readPeer: { _ in binding.peer })
            value?.cancel(incarnation: UUID()); XCTAssertEqual(try owner.retainedInvocationState(), .attached)
            value?.cancel(incarnation: binding.incarnation); connection.invalidate()
            weak var lost = value; value = nil
            XCTAssertNil(lost); XCTAssertEqual(try owner.retainedInvocationState(), .orphan)
            XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
            XCTAssertThrowsError(try installer.acquireExclusive()); XCTAssertThrowsError(try owner.close())
            XCTAssertEqual(try owner.retainedInvocationState(), .orphan)
        }
    }
    private final class WorkerRetention: @unchecked Sendable {
        let entered = DispatchSemaphore(value: 0), resume = DispatchSemaphore(value: 0), joined = DispatchSemaphore(value: 0)
        let failure = Mutex(false)
        func execute(_ invocation: Invocation) {
            defer { joined.signal() }
            do {
                try invocation.run(work: {
                    try invocation.withWorkerContext { scope in
                        try scope.verify(); XCTAssertThrowsError(try invocation.close())
                        entered.signal()
                        guard resume.wait(timeout: .now() + 3) == .success else { throw Failure.work }
                        try scope.verify()
                    }
                }, reply: { _, _ in })
            } catch { failure.withLock { $0 = true } }
        }
    }
    func testDroppingTheCallerReferenceCannotSettleAnActiveWorker() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); let (binding, policy) = try values(f)
            var value: Invocation? = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            let connection = NSXPCConnection(machServiceName: AdministrativeSetupConfiguration.serviceName)
            defer { connection.invalidate() }
            try value?.installOwnedContext(connection: connection, readPeer: { _ in binding.peer })
            weak var actual = value; let worker = WorkerRetention()
            func dispatch(_ invocation: Invocation) {
                DispatchQueue.global().async { [invocation] in worker.execute(invocation) }
            }
            try dispatch(XCTUnwrap(value))
            XCTAssertEqual(worker.entered.wait(timeout: .now() + 3), .success)
            value = nil
            XCTAssertNotNil(actual); XCTAssertEqual(try owner.retainedInvocationState(), .attached)
            XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
            worker.resume.signal(); XCTAssertEqual(worker.joined.wait(timeout: .now() + 3), .success)
            let deadline = DispatchTime.now().uptimeNanoseconds + 3_000_000_000
            while actual != nil, DispatchTime.now().uptimeNanoseconds < deadline { usleep(1_000) }
            XCTAssertNil(actual); XCTAssertFalse(worker.failure.withLock { $0 })
            XCTAssertEqual(try owner.retainedInvocationState(), .orphan)
            XCTAssertThrowsError(try owner.close())
        }
    }
    func testFailedCleanupRemainsRetainedAndPreventsSettlementOrReplay() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let activity = try ReleaseActivityFixture(), installer = try activity.open()
            let owner = try owner(f, activity: activity.open()); defer { try? owner.close() }
            let (binding, policy) = try values(f)
            let value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            var attempts = 0, completed = 0
            try value.retainCleanup { completed += 1 }
            try value.retainCleanup { attempts += 1; if attempts == 1 { throw Failure.cleanup } }
            try value.run(work: {}, reply: { _, _ in })
            XCTAssertThrowsError(try value.close()); XCTAssertEqual(attempts, 1); XCTAssertEqual(completed, 0)
            XCTAssertEqual(try owner.retainedInvocationState(), .attached)
            XCTAssertThrowsError(try value.run(work: { XCTFail("Replay") }, reply: { _, _ in }))
            XCTAssertThrowsError(try value.retainCleanup { XCTFail("Late cleanup") })
            XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
            XCTAssertThrowsError(try installer.acquireExclusive())
            try value.close(); try value.close()
            XCTAssertEqual(attempts, 2); XCTAssertEqual(completed, 1)
            XCTAssertEqual(try owner.retainedInvocationState(), .settled)
            let released = try installer.acquireExclusive(); released.close(); try owner.verifyCurrent()
        }
    }
    func testCleanupReentryCannotReleaseTheReservationOrJoinTwice() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let value = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            var calls = 0
            try value.retainCleanup { [weak value] in
                calls += 1; XCTAssertThrowsError(try value?.close())
                XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
                XCTAssertEqual(try owner.retainedInvocationState(), .attached)
            }
            try value.close(); XCTAssertEqual(calls, 1)
            XCTAssertEqual(try owner.retainedInvocationState(), .settled)
        }
    }
    func testSecondReservationIsRefusedWhileReservedAttachedAndOrphaned() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); let (binding, policy) = try values(f)
            var checks = 0
            var value: Invocation? = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {
                checks += 1
                if checks == 2 {
                    XCTAssertEqual(try owner.retainedInvocationState(), .reserved)
                    XCTAssertThrowsError(try owner.reserveRetainedInvocation(incarnation: UUID()))
                    XCTAssertEqual(try owner.retainedInvocationState(), .reserved)
                }
            })
            XCTAssertNotNil(value); XCTAssertEqual(try owner.retainedInvocationState(), .attached)
            XCTAssertThrowsError(try owner.reserveRetainedInvocation(incarnation: binding.incarnation))
            weak var weakValue = value; value = nil
            XCTAssertNil(weakValue); XCTAssertEqual(try owner.retainedInvocationState(), .orphan)
            XCTAssertThrowsError(try owner.reserveRetainedInvocation(incarnation: binding.incarnation))
            XCTAssertEqual(try owner.retainedInvocationState(), .orphan)
        }
    }
    func testForeignConstructedIncarnationRefusesItsOwnRecordAndClosesRightsOnce() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let activity = try ReleaseActivityFixture(), installer = try activity.open()
            let owner = try owner(f, activity: activity.open()); defer { try? owner.close() }
            let (binding, policy) = try values(f); var closes = 0
            XCTAssertThrowsError(try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                verifyRights: {}, closeRights: {
                    closes += 1
                    do {
                        XCTAssertEqual(try owner.retainedInvocationState(), .reserved)
                        XCTAssertThrowsError(try owner.verifyCurrent())
                        XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
                        XCTAssertThrowsError(try installer.acquireExclusive())
                    } catch { XCTFail("Attachment cleanup observation failed: \(error)") }
                }, rejectedIncarnation: UUID())) {
                if case XPCPeerPolicyError.wrongConnection = $0 {} else { XCTFail("Unexpected attachment failure: \($0)") }
            }
            XCTAssertEqual(closes, 1); XCTAssertEqual(try owner.retainedInvocationState(), .settled)
            try owner.verifyCurrent(); let reply = try owner.acquireSetupReplyAdmission(); reply.close()
            let exclusive = try installer.acquireExclusive(); exclusive.close()
        }
    }
    func testFailedConstructionClosesRightsBeforeReleasingAdmissions() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let activity = try ReleaseActivityFixture(), installer = try activity.open()
            let owner = try owner(f, activity: activity.open()); defer { try? owner.close() }
            let (binding, policy) = try values(f); var checks = 0, closes = 0
            XCTAssertThrowsError(try Invocation.openOwned(owner: owner, binding: binding, policy: policy,
                verifyRights: { checks += 1; if checks == 2 { throw Failure.rights } }, closeRights: {
                    closes += 1
                    do {
                        XCTAssertEqual(try owner.retainedInvocationState(), .reserved)
                        XCTAssertThrowsError(try owner.verifyCurrent())
                        XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
                        XCTAssertThrowsError(try installer.acquireExclusive())
                    } catch { XCTFail("Construction cleanup observation failed: \(error)") }
                }))
            XCTAssertEqual(closes, 1); XCTAssertEqual(try owner.retainedInvocationState(), .settled)
            try owner.verifyCurrent(); let reply = try owner.acquireSetupReplyAdmission(); reply.close()
            let exclusive = try installer.acquireExclusive(); exclusive.close()
        }
    }
    private final class ContextProbe: @unchecked Sendable {
        let live = Mutex(true), reads = Mutex(0)
        func read(_ connection: NSXPCConnection, peer: XPCPeerCredentials) throws -> XPCPeerCredentials {
            guard live.withLock({ $0 }) else { throw XPCPeerPolicyError.wrongConnection }
            reads.withLock { $0 += 1 }; return peer
        }
    }
    private func withContext(_ body: (Invocation, SetupAccountOwner, NSXPCConnection, ContextProbe) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let connection = NSXPCConnection(machServiceName: AdministrativeSetupConfiguration.serviceName), probe = ContextProbe()
            defer { connection.invalidate() }
            let invocation = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            defer { try? invocation.close() }
            try invocation.installOwnedContext(connection: connection, readPeer: { try probe.read($0, peer: binding.peer) })
            try body(invocation, owner, connection, probe)
        }
    }
    func testWorkerContextIsConfinedToOneActualOwnerRunAndExpiresWithItsLoan() throws {
        try withContext { invocation, _, connection, _ in
            XCTAssertThrowsError(try invocation.withWorkerContext { _ in XCTFail("Outside the owner worker") })
            var escaped: SetupRetainedInvocationContext.Scope?
            try invocation.run(work: {
                try invocation.withWorkerContext { scope in
                    escaped = scope; try scope.verify(); try scope.requireConnection(connection); return 17
                }
            }, reply: { result, _ in XCTAssertEqual(result, 17) })
            XCTAssertThrowsError(try XCTUnwrap(escaped).verify())
            XCTAssertThrowsError(try invocation.withWorkerContext { _ in XCTFail("Replay") })
            try invocation.close()
        }
    }
    func testFailedOwnedConnectionReadRetiresTheContextWithoutAutomaticRevalidation() throws {
        try withContext { invocation, _, _, probe in
            XCTAssertThrowsError(try invocation.run(work: {
                try invocation.withWorkerContext { scope in
                    try scope.verify(); probe.live.withLock { $0 = false }
                    XCTAssertThrowsError(try scope.verify())
                    probe.live.withLock { $0 = true }; XCTAssertThrowsError(try scope.verify())
                }
            }, reply: { _, _ in XCTFail("An invalidated peer returned success") }))
        }
    }
    func testAnotherConnectionWithTheSamePeerCannotUseTheContext() throws {
        try withContext { invocation, _, connection, _ in
            let other = NSXPCConnection(machServiceName: AdministrativeSetupConfiguration.serviceName)
            defer { other.invalidate() }; XCTAssertFalse(connection === other)
            XCTAssertThrowsError(try invocation.run(work: {
                try invocation.withWorkerContext { scope in
                    try scope.requireConnection(connection); XCTAssertThrowsError(try scope.requireConnection(other))
                }
            }, reply: { _, _ in XCTFail("A foreign connection returned success") }))
        }
    }
    func testOwnerClosureBeforeWorkPreventsContextEntry() throws {
        try withContext { invocation, _, _, _ in
            try invocation.close()
            XCTAssertThrowsError(try invocation.run(work: {
                try invocation.withWorkerContext { _ in XCTFail("Closed owner") }
            }, reply: { _, _ in XCTFail() }))
        }
    }
    func testClosingTheReservationOwnerRetiresTheWorkerContext() throws {
        try withContext { invocation, owner, _, _ in
            XCTAssertThrowsError(try invocation.run(work: {
                try invocation.withWorkerContext { scope in
                    try scope.verify(); XCTAssertThrowsError(try owner.close())
                    XCTAssertThrowsError(try scope.verify())
                }
            }, reply: { _, _ in XCTFail("Lost reservation") }))
        }
    }
    private final class ContextTransfer: @unchecked Sendable {
        let invocation: Invocation
        let done = DispatchSemaphore(value: 0), refused = Mutex(false)
        var scope: SetupRetainedInvocationContext.Scope?
        init(_ invocation: Invocation) { self.invocation = invocation }
    }
    func testAnotherThreadCannotClaimTheFirstWorkerContextThread() throws {
        try withContext { invocation, _, _, _ in
            let transfer = ContextTransfer(invocation)
            try invocation.run(work: {
                DispatchQueue.global().async {
                    do { try transfer.invocation.withWorkerContext { _ in } }
                    catch { transfer.refused.withLock { $0 = true } }
                    transfer.done.signal()
                }
                XCTAssertEqual(transfer.done.wait(timeout: .now() + 3), .success)
                XCTAssertTrue(transfer.refused.withLock { $0 })
                try invocation.withWorkerContext { try $0.verify() }
            }, reply: { _, _ in })
        }
    }
    func testAnotherThreadCannotUseAnAlreadyBorrowedContext() throws {
        try withContext { invocation, _, _, probe in
            let transfer = ContextTransfer(invocation)
            XCTAssertThrowsError(try invocation.run(work: {
                try invocation.withWorkerContext { scope in
                    transfer.scope = scope; let before = probe.reads.withLock { $0 }
                    DispatchQueue.global().async {
                        do { try transfer.scope?.verify() } catch { transfer.refused.withLock { $0 = true } }
                        transfer.done.signal()
                    }
                    XCTAssertEqual(transfer.done.wait(timeout: .now() + 3), .success)
                    XCTAssertTrue(transfer.refused.withLock { $0 }); XCTAssertEqual(probe.reads.withLock { $0 }, before)
                }
            }, reply: { _, _ in XCTFail("Foreign-thread use") }))
        }
    }
    func testCaughtContextReentryPoisonsTheOuterLoan() throws {
        try withContext { invocation, _, _, _ in
            XCTAssertThrowsError(try invocation.run(work: {
                try invocation.withWorkerContext { scope in
                    XCTAssertThrowsError(try invocation.withWorkerContext { _ in XCTFail("Reentry") })
                    XCTAssertThrowsError(try scope.verify())
                }
            }, reply: { _, _ in XCTFail("Caught reentry") }))
        }
    }
    func testCaughtMintReentryCannotInstallAnOuterContext() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let connection = NSXPCConnection(machServiceName: AdministrativeSetupConfiguration.serviceName)
            defer { connection.invalidate() }
            let invocation = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            defer { try? invocation.close() }
            XCTAssertThrowsError(try invocation.installOwnedContext(connection: connection, readPeer: { _ in
                XCTAssertThrowsError(try invocation.installOwnedContext(connection: connection, readPeer: { _ in binding.peer }))
                return binding.peer
            }))
            try invocation.run(work: {
                XCTAssertThrowsError(try invocation.withWorkerContext { _ in XCTFail("Reentrant mint") })
            }, reply: { _, _ in })
        }
    }
    func testOwnedContextCannotSelectTheNativeFactoryWithoutAnExportedInvocation() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            let connection = NSXPCConnection(machServiceName: AdministrativeSetupConfiguration.serviceName)
            defer { connection.invalidate() }
            let invocation = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
            defer { try? invocation.close() }
            let guardValue = XPCInvocationGuard(connection: connection, policy: policy)
            XCTAssertThrowsError(try SetupRetainedInvocationContext.open(owner: invocation, invocation: guardValue)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertThrowsError(try guardValue.withRetainedConnection { _, _, _ in XCTFail("Not an exported invocation") })
        }
    }
    func testForkedContextRefusesBeforeAnyInheritedLockAndKeepsTheParentLoanValid() throws {
        try withContext { invocation, _, _, _ in
            try invocation.run(work: {
                try invocation.withWorkerContext { scope in
                    let child = Self.contextFork(); XCTAssertGreaterThanOrEqual(child, 0)
                    if child == 0 { do { try scope.verify(); _exit(11) } catch { _exit(0) } }
                    guard child > 0 else { throw Failure.work }
                    let deadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
                    var reaped = false, status: Int32 = 0
                    while DispatchTime.now().uptimeNanoseconds < deadline {
                        if waitpid(child, &status, WNOHANG) == child { reaped = true; break }; usleep(10_000)
                    }
                    if !reaped { _ = kill(child, SIGKILL); while waitpid(child, &status, 0) < 0 && errno == EINTR {} }
                    XCTAssertTrue(reaped); XCTAssertEqual(status, 0); try scope.verify()
                }
            }, reply: { _, _ in })
        }
    }
    private static let contextFork: @convention(c) () -> pid_t = {
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "fork") else { preconditionFailure("fork is unavailable") }
        return unsafeBitCast(symbol, to: (@convention(c) () -> pid_t).self)
    }()
    private final class ContextExportedProbe: NSObject, AuthorityMaintenanceXPCProtocol {
        func hello(reply: @escaping @Sendable (UInt64) -> Void) { reply(AuthorityMaintenanceChannelScope.protocolVersion) }
        func exchange(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void) { reply(nil) }
        func readGate(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void) { reply(nil) }
        func observeIncarnation(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void) { reply(nil) }
    }
    func testContextGuardAndExportedObjectReleaseAfterTheInvalidationHandler() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let owner = try owner(f); defer { try? owner.close() }; let (binding, policy) = try values(f)
            weak var weakContext: SetupRetainedInvocationContext?, weakGuard: XPCInvocationGuard?, weakObject: ContextExportedProbe?
            let handled = expectation(description: "The invalidation handler completed")
            try autoreleasepool {
                let connection = NSXPCConnection(machServiceName: "dev.sebastiano.remozio.test-" + UUID().uuidString)
                let invocation = try Invocation.openOwned(owner: owner, binding: binding, policy: policy, verifyRights: {})
                let guardValue = XPCInvocationGuard(connection: connection, policy: policy), object = ContextExportedProbe()
                weakGuard = guardValue; weakObject = object
                connection.exportedInterface = NSXPCInterface(with: AuthorityMaintenanceXPCProtocol.self)
                connection.exportedObject = object
                weakContext = try invocation.installOwnedContext(connection: connection, readPeer: { [guardValue] _ in
                    _ = guardValue.incarnation; return binding.peer
                })
                connection.invalidationHandler = { [weak invocation] in
                    try? invocation?.close(); handled.fulfill()
                }
                try guardValue.observeConnectionLifetime()
                connection.resume(); connection.invalidate()
                wait(for: [handled], timeout: 3); try invocation.close()
            }
            XCTAssertNil(weakContext); XCTAssertNil(weakGuard); XCTAssertNil(weakObject)
            try owner.verifyCurrent()
        }
    }

}
