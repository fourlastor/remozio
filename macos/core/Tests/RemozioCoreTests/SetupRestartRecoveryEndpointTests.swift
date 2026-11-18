import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class SetupRestartRecoveryEndpointTests: XCTestCase, @unchecked Sendable {
    private typealias W = SetupRestartRecoveryWire
    private typealias Fixture = ExplicitStartupFixture
    private enum Failure: Error { case expected }
    private final class Context: @unchecked Sendable {
        let f: Fixture
        let route = Mutex(AdministrativeSetupLifecycle.State.serving), clock = Mutex(ContinuousClock.now)
        let live = Mutex(true), replied = Mutex(false), imports = Mutex(0), restores = Mutex(0), rightsChecks = Mutex(0)
        let peer: Mutex<SetupRestartRecoveryOperations.Peer>
        var failImport = false, hasHost = true, fakeRestore = false
        var rightsFailure: any Error = Failure.expected
        var operationFailure: (any Error)?
        var onHost: (@Sendable () -> Void)?, onRights: (@Sendable (Int) -> Void)?
        init(_ f: Fixture) {
            self.f = f
            peer = .init(.init(credentials: f.retained.binding.peer, owner: f.retained.binding.authorityOwner))
        }
        func endpoint() throws -> SetupRestartRecoveryEndpoint {
            let host: (@Sendable () throws -> Void)?
            if hasHost {
                host = { [self] in
                    XCTAssertGreaterThanOrEqual(pthread_get_stacksize_np(pthread_self()), SetupAuditUpgradeWorkExecutor.stackBytes)
                    onHost?(); try f.processLease.validate()
                }
            } else { host = nil }
            let effects = SetupRestartRecoveryOperations.Effects(verifyPeer: { [self] in peer.withLock { $0 } },
                routing: { [self] in route.withLock { $0 } }, checkHost: host, importAuthorization: { [self] _ in
                    XCTAssertTrue(replied.withLock { $0 }); imports.withLock { $0 += 1 }
                    guard !failImport else { throw Failure.expected }
                    let actual = peer.withLock { $0 }
                    return try f.retained.authorize(peer: actual.credentials, identity: actual.owner, verify: { [self] in
                        let count = rightsChecks.withLock { $0 += 1; return $0 }
                        onRights?(count); guard live.withLock({ $0 }) else { throw rightsFailure }
                    })
                }, restore: { [self] claim, deadline in
                    restores.withLock { $0 += 1 }
                    if let operationFailure { throw operationFailure }
                    if fakeRestore { return f.h.initial }
                    return try await RuntimeMaintenanceRestartRestorationTests.restore(f, claim,
                        deadline: min(deadline, ContinuousClock.now.advanced(by: restorationTestForwardDeadline)))
                }, now: { [self] in clock.withLock { $0 } })
            let ops = try SetupRestartRecoveryOperations.owned(owner: f.retained.owner, processLease: f.processLease, effects: effects)
            return try .openOwned(operations: ops)
        }
        func start(_ endpoint: SetupRestartRecoveryEndpoint, _ action: W.Action = .restore, id: UInt8 = 7) throws -> Data? {
            let reply = Mutex<Data?>(nil)
            endpoint.start(try W.Request(requestID: Data(repeating: id, count: 16), action: action).bytes,
                authorization: Data(repeating: 9, count: 32), reply: { [self] bytes in
                    replied.withLock { $0 = true }; reply.withLock { $0 = bytes }
                })
            return reply.withLock { $0 }
        }
        func progress(_ endpoint: SetupRestartRecoveryEndpoint, id: UInt8 = 7) throws -> W.Code {
            try W.Reply.decode(XCTUnwrap(endpoint.progress(W.Progress(requestID: Data(repeating: id, count: 16)).bytes))).code
        }
    }
    private func withFixture(restorations: Int = 1, _ body: @escaping @Sendable (Fixture) async throws -> Void) throws {
        let harness = RuntimeMaintenanceRestartRestorationTests(selector: NSSelectorFromString("testRightsCheckedExitBeforeStartingReleasesTheIdleSlot"))
        try harness.withFixture(outerDeadline: RestartRecoveryTestTiming.deadline(restorations: restorations), body)
    }
    private static func available(_ f: Fixture) throws {
        try f.retained.owner.verifyCurrent()
        let reply = try f.retained.owner.acquireSetupReplyAdmission(); reply.close()
        let activity = try f.retained.installer.acquireExclusive(); activity.close()
    }
    private static func refuses<T>(_ body: () async throws -> T) async {
        do { _ = try await body(); XCTFail("Expected refusal") } catch {}
    }
    func testActualRestoreImportsAfterRecordingAndReturnsCheckedCompletion() throws {
        try withFixture { f in
            try f.seed(.stopped)
            let c = Context(f), endpoint = try c.endpoint(); defer { endpoint.close() }
            XCTAssertEqual(try W.Reply.decode(XCTUnwrap(c.start(endpoint))).code, .requestRecorded)
            await endpoint.waitForWork()
            XCTAssertEqual(try c.progress(endpoint), .restored)
            XCTAssertEqual(c.imports.withLock { $0 }, 1); XCTAssertEqual(c.restores.withLock { $0 }, 1)
            XCTAssertEqual(try f.h.frame().window?.phase, .restored); try Self.available(f)
        }
    }
    func testDuplicateRequestKeepsTheRecordedReplyAndDoesNotReplay() throws {
        try withFixture { f in
            let c = Context(f); c.fakeRestore = true
            let endpoint = try c.endpoint(); defer { endpoint.close() }
            let original = try XCTUnwrap(c.start(endpoint)); await endpoint.waitForWork()
            for _ in 0..<5 { XCTAssertEqual(try c.start(endpoint), original) }
            XCTAssertEqual(c.imports.withLock { $0 }, 1); XCTAssertEqual(c.restores.withLock { $0 }, 1)
            XCTAssertEqual(try c.progress(endpoint), .failedOperation); try Self.available(f)
        }
    }
    func testSamePeerPayloadMismatchAndOtherSelectorRefuseOnlyThatCall() throws {
        try withFixture { f in
            let c = Context(f); c.fakeRestore = true
            let endpoint = try c.endpoint(); defer { endpoint.close() }
            _ = try c.start(endpoint); await endpoint.waitForWork()
            XCTAssertEqual(try c.progress(endpoint), .failedOperation)
            let mismatch = try XCTUnwrap(c.start(endpoint, .restore, id: 8))
            XCTAssertEqual(try W.Reply.decode(mismatch).code, .refusedUnavailable)
            XCTAssertNotNil(endpoint.refuseForeignSelector())
            XCTAssertEqual(try c.progress(endpoint), .failedOperation)
            XCTAssertEqual(c.imports.withLock { $0 }, 1); try Self.available(f)
        }
    }
    func testAdoptAndReleaseCannotMintAFreshSlot() throws {
        try withFixture { f in
            for action in [W.Action.adoptRecordedCompletion, .releaseIdleSlot] {
                let c = Context(f), endpoint = try c.endpoint(); defer { endpoint.close() }
                _ = try c.start(endpoint, action); await endpoint.waitForWork()
                XCTAssertEqual(try c.progress(endpoint), .refusedUnavailable)
                XCTAssertNil(f.retained.owner.retainedInvocationStatusV2(authenticatedPeer: f.retained.binding.peer,
                    currentOwner: f.retained.binding.authorityOwner).restart)
                XCTAssertEqual(c.restores.withLock { $0 }, 0); try Self.available(f)
            }
        }
    }
    func testNoWindowHasACheckedIdleExitAndReportsNotApplicable() throws {
        try withFixture { f in
            let c = Context(f), endpoint = try c.endpoint(); defer { endpoint.close() }
            _ = try c.start(endpoint); await endpoint.waitForWork()
            XCTAssertEqual(try c.progress(endpoint), .notApplicable)
            XCTAssertNil(try f.h.frame().window); try Self.available(f)
        }
    }
    func testRoutingRefusalAfterClaimIsNotApplicableAndDoesNotHoldIdleAdmissions() throws {
        try withFixture { f in
            let c = Context(f); c.onHost = { c.route.withLock { $0 = .retiring } }
            defer { c.onHost = nil }
            let endpoint = try c.endpoint(); defer { endpoint.close() }
            _ = try c.start(endpoint); await endpoint.waitForWork()
            XCTAssertEqual(try c.progress(endpoint), .notApplicable)
            XCTAssertEqual(c.restores.withLock { $0 }, 0); try Self.available(f)
        }
    }
    func testDeadlineAfterClaimReleasesWithoutStartingRestoration() throws {
        try withFixture { f in
            let c = Context(f); c.onHost = { c.clock.withLock { $0 = .now.advanced(by: .seconds(121)) } }
            defer { c.onHost = nil }
            let endpoint = try c.endpoint(); defer { endpoint.close() }
            _ = try c.start(endpoint); await endpoint.waitForWork()
            XCTAssertEqual(try c.progress(endpoint), .failedDeadline)
            XCTAssertEqual(c.restores.withLock { $0 }, 0); try Self.available(f)
        }
    }
    func testConnectionCloseDuringClaimCreationAbandonsTheLateClaim() throws {
        try withFixture { f in
            let c = Context(f), cell = Mutex<SetupRestartRecoveryEndpoint?>(nil)
            c.onRights = { count in if count == 2 { cell.withLock { $0 }?.close() } }
            let endpoint = try c.endpoint(); cell.withLock { $0 = endpoint }
            defer { cell.withLock { $0 = nil }; endpoint.close() }
            _ = try c.start(endpoint); await endpoint.waitForWork()
            XCTAssertEqual(c.restores.withLock { $0 }, 0)
            XCTAssertNil(try endpoint.progress(W.Progress(requestID: Data(repeating: 7, count: 16)).bytes))
            try Self.available(f)
        }
    }
    func testLostRightsAfterClaimCannotStartWorkOrLeaveAnIdleLease() throws {
        try withFixture { f in
            let c = Context(f); c.onHost = { c.live.withLock { $0 = false } }
            defer { c.onHost = nil }
            let endpoint = try c.endpoint(); defer { endpoint.close() }
            _ = try c.start(endpoint); await endpoint.waitForWork()
            XCTAssertEqual(try c.progress(endpoint), .failedAuthorization)
            XCTAssertEqual(c.restores.withLock { $0 }, 0); try Self.available(f)
        }
    }
    func testAChangedPublicCallerClosesTheSession() throws {
        try withFixture { f in
            let c = Context(f); c.fakeRestore = true
            let endpoint = try c.endpoint(); defer { endpoint.close() }
            _ = try c.start(endpoint); await endpoint.waitForWork()
            c.peer.withLock { old in
                old = .init(credentials: .init(processID: getpid(), userID: old.credentials.userID + 1, auditSessionID: 1), owner: old.owner)
            }
            XCTAssertNil(try endpoint.progress(W.Progress(requestID: Data(repeating: 7, count: 16)).bytes))
            XCTAssertEqual(c.imports.withLock { $0 }, 1); try Self.available(f)
        }
    }
    func testEveryPreclaimRefusalHasTheSameReplyBytes() throws {
        try withFixture { f in
            let failing = Context(f); failing.failImport = true
            let first = try failing.endpoint(); defer { first.close() }
            _ = try failing.start(first); await first.waitForWork()
            let expected = try XCTUnwrap(first.progress(W.Progress(requestID: Data(repeating: 7, count: 16)).bytes))
            let idle = Context(f), second = try idle.endpoint(); defer { second.close() }
            _ = try idle.start(second, .releaseIdleSlot); await second.waitForWork()
            XCTAssertEqual(try second.progress(W.Progress(requestID: Data(repeating: 7, count: 16)).bytes), expected)
            let refusals: [(String, (Context) -> Void)] = [
                ("missing account", { c in
                    let uid = f.retained.binding.peer.userID + 100
                    c.peer.withLock { $0 = .init(credentials: .init(processID: getpid(), userID: uid, auditSessionID: 1),
                        owner: .init(uid: uid, primaryGroupID: getgid(), directoryID: UUID())) }
                }),
                ("recycled directory", { c in c.peer.withLock { $0 = .init(credentials: $0.credentials,
                    owner: .init(uid: $0.owner.uid, primaryGroupID: getgid(), directoryID: UUID())) } }),
                ("routing", { c in c.route.withLock { $0 = .starting } }),
                ("no host", { c in c.hasHost = false }),
                ("deadline before claim", { c in c.onRights = { count in
                    if count == 1 { c.clock.withLock { $0 = .now.advanced(by: .seconds(121)) } }
                } }),
            ]
            for (name, configure) in refusals {
                let context = Context(f); configure(context)
                let endpoint = try context.endpoint()
                defer { endpoint.close(); context.onRights = nil }
                _ = try context.start(endpoint); await endpoint.waitForWork()
                XCTAssertEqual(try endpoint.progress(W.Progress(requestID: Data(repeating: 7, count: 16)).bytes), expected, name)
                try Self.available(f)
            }
            let held = try await SetupRestartRecovery.Claim.openOwned(owner: f.retained.owner, authorization: f.retained.authorize(),
                processLease: f.processLease, policy: .freshOrReclaim, until: .now.advanced(by: .seconds(5)))
            defer { held.abandon() }
            let busy = Context(f), busyEndpoint = try busy.endpoint(); defer { busyEndpoint.close() }
            _ = try busy.start(busyEndpoint); await busyEndpoint.waitForWork()
            XCTAssertEqual(try busyEndpoint.progress(W.Progress(requestID: Data(repeating: 7, count: 16)).bytes), expected)
            f.retained.assertHeld()
            let foreign = Context(f), b = f.retained.binding
            foreign.peer.withLock { $0 = .init(credentials: .init(processID: getpid(), userID: b.targetOwner.uid, auditSessionID: 1), owner: b.targetOwner) }
            let third = try foreign.endpoint(); defer { third.close() }
            _ = try foreign.start(third); await third.waitForWork()
            XCTAssertEqual(try third.progress(W.Progress(requestID: Data(repeating: 7, count: 16)).bytes), expected)
        }
    }
    func testRetiringSessionAdoptsAnActualCompletionWithoutReplay() throws {
        try withFixture { f in
            try f.seed(.stopped)
            let live = Mutex(true)
            let rights = try f.retained.authorize(verify: { guard live.withLock({ $0 }) else { throw Failure.expected } })
            let first = try await SetupRestartRecovery.Claim.openOwned(owner: f.retained.owner, authorization: rights,
                processLease: f.processLease, policy: .freshOrReclaim, until: .now.advanced(by: .seconds(5)))
            f.h.afterWrite = { row in if row.phase == .restored { live.withLock { $0 = false } } }
            await Self.refuses { try await RuntimeMaintenanceRestartRestorationTests.restore(f, first) }
            first.abandon(); f.h.afterWrite = nil
            let actions = f.driver.metrics.actions.withLock { $0 }
            let c = Context(f); c.route.withLock { $0 = .retiring }
            let endpoint = try c.endpoint(); defer { endpoint.close() }
            _ = try c.start(endpoint, .adoptRecordedCompletion); await endpoint.waitForWork()
            XCTAssertEqual(try c.progress(endpoint), .restored)
            XCTAssertEqual(c.restores.withLock { $0 }, 0)
            XCTAssertEqual(f.driver.metrics.actions.withLock { $0 }, actions); try Self.available(f)
        }
    }
    func testReleaseRemainsPendingUntilTheActualTaskReturns() throws {
        try withFixture { f in
            try f.seed(.stopped)
            let first = try await SetupRestartRecovery.Claim.openOwned(owner: f.retained.owner, authorization: f.retained.authorize(),
                processLease: f.processLease, policy: .freshOrReclaim, until: .now.advanced(by: .seconds(5)))
            let gate = AsyncStream<Void>.makeStream()
            let entered = RestartRecoveryTestSignal(), checked = RestartRecoveryTestSignal()
            let deadline = RestartRecoveryTestTiming.deadline()
            defer { gate.continuation.finish(); first.abandon() }
            let original = Task {
                try await RuntimeMaintenanceRestartRestorationTests.restore(f, first, beforeCustody: {
                    entered.signal()
                    for await _ in gate.stream { break }
                })
            }
            guard await entered.wait(until: deadline) else { return XCTFail("Actual restoration did not start") }
            first.abandon()
            let c = Context(f); c.onHost = { checked.signal() }
            defer { c.onHost = nil }
            let endpoint = try c.endpoint(); defer { endpoint.close() }
            _ = try c.start(endpoint, .releaseIdleSlot)
            guard await checked.wait(until: deadline) else { return XCTFail("Release did not claim the record") }
            XCTAssertEqual(try c.progress(endpoint), .pending)
            XCTAssertEqual(f.retained.owner.retainedInvocationStatusV2(authenticatedPeer: f.retained.binding.peer,
                currentOwner: f.retained.binding.authorityOwner).restart?.task, .running)
            f.retained.assertHeld()
            gate.continuation.yield(()); gate.continuation.finish()
            await endpoint.waitForWork(); _ = await original.result
            XCTAssertEqual(try c.progress(endpoint), .released)
            XCTAssertTrue(f.driver.metrics.actions.withLock { $0.isEmpty }); try Self.available(f)
        }
    }
    func testActualRestorationRightsLossAlwaysMapsToAuthorizationFailure() throws {
        for secondError in [false, true] {
            try withFixture { f in
                try f.seed(.stopped)
                let c = Context(f)
                if secondError { c.rightsFailure = NSError(domain: "remozio.owned-rights", code: 2) }
                f.h.afterWrite = { row in if row.phase == .restored { c.live.withLock { $0 = false } } }
                let endpoint = try c.endpoint(); defer { endpoint.close() }
                _ = try c.start(endpoint); await endpoint.waitForWork()
                XCTAssertEqual(try c.progress(endpoint), .failedAuthorization)
                XCTAssertEqual(try f.h.frame().window?.phase, .restored); f.retained.assertHeld()
                f.h.afterWrite = nil
                let adopter = try await SetupRestartRecovery.Claim.openOwned(owner: f.retained.owner, authorization: f.retained.authorize(),
                    processLease: f.processLease, policy: .reclaimOnly, until: .now.advanced(by: .seconds(5)))
                defer { adopter.abandon() }
                _ = try await adopter.finishRecordedRestoration(); try Self.available(f)
            }
        }
    }
    func testForwardOnlyReleaseRequiresRestorationWithoutReportingRepair() throws {
        try withFixture(restorations: 2) { f in
            try f.seed(.stopped)
            let first = try await SetupRestartRecovery.Claim.openOwned(owner: f.retained.owner, authorization: f.retained.authorize(),
                processLease: f.processLease, policy: .freshOrReclaim, until: .now.advanced(by: .seconds(5)))
            f.h.rejectCode = true
            await Self.refuses { try await RuntimeMaintenanceRestartRestorationTests.restore(f, first) }
            let before = f.retained.owner.retainedInvocationStatusV2(authenticatedPeer: f.retained.binding.peer,
                currentOwner: f.retained.binding.authorityOwner)
            XCTAssertEqual(before.restart?.custody, .closed)
            XCTAssertEqual(before.restart?.writer, .noUncertaintyObserved)
            XCTAssertEqual(before.restart?.row?.restoration.phase, .needsOwnerRecovery)
            first.abandon()
            let c = Context(f), endpoint = try c.endpoint(); defer { endpoint.close() }
            _ = try c.start(endpoint, .releaseIdleSlot); await endpoint.waitForWork()
            XCTAssertEqual(try c.progress(endpoint), .notApplicable)
            XCTAssertEqual(c.restores.withLock { $0 }, 0); f.retained.assertHeld()
            f.h.rejectCode = false
            let next = try await SetupRestartRecovery.Claim.openOwned(owner: f.retained.owner, authorization: f.retained.authorize(),
                processLease: f.processLease, policy: .reclaimOnly, until: .now.advanced(by: .seconds(5)))
            defer { next.abandon() }
            _ = try await RuntimeMaintenanceRestartRestorationTests.restore(f, next); try Self.available(f)
        }
    }
    func testUnsafeWriterAndUnsettledWindowRefusalsRequireRepair() throws {
        try withFixture { f in
            for failure in [SetupRestartRecoveryError.uncertainWriter, .unsettledWindow] {
                let c = Context(f); c.operationFailure = failure
                let endpoint = try c.endpoint(); defer { endpoint.close() }
                _ = try c.start(endpoint); await endpoint.waitForWork()
                XCTAssertEqual(try c.progress(endpoint), .repairRequired)
                try Self.available(f)
            }
        }
    }
}
