import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class SetupOrphanRecoveryOperationsTests: XCTestCase, @unchecked Sendable {
    private typealias W = SetupOrphanRecoveryWire
    private typealias E = SetupOrphanRecoveryEndpointTests
    private enum Failure: Error { case expected }
    private final class WorkerGate: Sendable {
        let stream: AsyncStream<Void>, continuation: AsyncStream<Void>.Continuation
        init() { let pair = AsyncStream<Void>.makeStream(); stream = pair.stream; continuation = pair.continuation }
        func task() -> Task<Void, Never> { Task { for await _ in stream { break } } }
        func finish() { continuation.yield(()); continuation.finish() }
        deinit { finish() }
    }
    private final class Context: @unchecked Sendable {
        let f: ExplicitStartupFixture
        let rights = Mutex(true), imports = Mutex(0), effects = Mutex<[String]>([]), hostChecks = Mutex(0)
        let route = Mutex(AdministrativeSetupLifecycle.State.serving), clock = Mutex(ContinuousClock.now)
        var foreign = false, recycledDirectory = false, failImport = false
        var onHost: (@Sendable () -> Void)?, onRights: (@Sendable () -> Void)?
        init(_ f: ExplicitStartupFixture) { self.f = f }
        var peer: SetupOrphanRecoveryOperations.Peer {
            if recycledDirectory {
                return .init(credentials: f.retained.binding.peer,
                    owner: .init(uid: f.retained.binding.authorityOwner.uid, primaryGroupID: getgid(), directoryID: UUID()))
            }
            if foreign {
                return .init(credentials: .init(processID: getpid(), userID: getuid() + 1, auditSessionID: 1),
                    owner: .init(uid: getuid() + 1, primaryGroupID: getgid(), directoryID: UUID(uuidString: "00000000-0000-0000-0000-000000000009")!))
            }
            return .init(credentials: f.retained.binding.peer, owner: f.retained.binding.authorityOwner)
        }
        func session(maximum: Int = 8,
            validateContext: @escaping @Sendable (SetupOrphanRecoveryOperations.Validation) throws -> Void = { _ in }
        ) throws -> SetupOrphanRecoveryEndpoint {
            let peer = self.peer
            let ops = try SetupOrphanRecoveryOperations.owned(owner: f.retained.owner, effects: .init(
                verifyPeer: { peer }, routing: { [self] in route.withLock { $0 } }, checkHost: { [self] in
                    XCTAssertGreaterThanOrEqual(pthread_get_stacksize_np(pthread_self()), SetupAuditUpgradeWorkExecutor.stackBytes)
                    hostChecks.withLock { $0 += 1 }; onHost?(); try f.processLease.validate()
                }, importAuthorization: { [self] _ in
                    imports.withLock { $0 += 1 }
                    guard !failImport else { throw Failure.expected }
                    return try f.retained.authorize(peer: peer.credentials, identity: peer.owner, verify: { [self] in
                        onRights?(); guard rights.withLock({ $0 }) else { throw Failure.expected }
                    })
                }, restore: { [self] joined, _, deadline in
                    effects.withLock { $0.append("restore") }
                    return try await f.restore(joined, until: deadline)
                }, adopt: { [self] joined, _ in
                    effects.withLock { $0.append("adopt") }
                    return try await joined.finishRecordedRestorationOwned(processLease: f.processLease)
                }, now: { [self] in clock.withLock { $0 } }, validateContext: validateContext))
            return try .openOwned(operations: ops, maximumConnections: maximum)
        }
        func request(_ action: W.Action) throws -> W.Request {
            let identity: SetupRetainedInvocationStatus.Identity?
            if case .observed(let value) = f.retained.status.identity { identity = value } else { identity = nil }
            return try E.request(action, identity: identity)
        }
    }
    private static let sessionAttempt: Duration = .seconds(120)
    private static let replyAndCleanupMargin: Duration = .seconds(20)
    private static let fixtureSetupMargin: Duration = .seconds(30)
    private static func remaining(_ deadline: ContinuousClock.Instant) -> TimeInterval {
        let parts = ContinuousClock.now.duration(to: deadline).components
        return max(0, Double(parts.seconds) + Double(parts.attoseconds) / 1e18)
    }
    private func withFixture(window: Bool = true, binding: Bool = true,
        seed: RuntimeMaintenanceWindowRecord.Phase? = nil, helperRestorations: Int = 0,
        prepare: @escaping @Sendable (ExplicitStartupFixture) throws -> Void = { _ in },
        _ body: @escaping @Sendable (ExplicitStartupFixture) async throws -> Void) throws {
        let bound = Self.sessionAttempt + restorationTestForwardDeadline * helperRestorations + Self.replyAndCleanupMargin
        let outerDeadline = ContinuousClock.now.advanced(by: bound + Self.fixtureSetupMargin)
        let finished = DispatchSemaphore(value: 0), outcome = Mutex<Result<Void, Error>?>(nil)
        let thread = Thread {
            do {
                try MachineUpdateReplacementTests.withMaintenanceWriterFixture { writer in
                    XCTAssertGreaterThanOrEqual(pthread_get_stacksize_np(pthread_self()), SetupAuditUpgradeWorkExecutor.stackBytes)
                    let f = try ExplicitStartupFixture(writer, reserveInProcess: window)
                    if !window { f.invocation = try f.retained.invocation(captured: binding) }
                    if let seed { try f.seed(seed) }
                    try prepare(f)
                    try f.retained.lose(&f.invocation)
                    defer {
                        f.h.beforeWrite = nil; f.h.afterWrite = nil; f.h.verifyOverride = nil
                        f.driver.onExchange.withLock { $0 = nil }; f.claim?.abandon()
                    }
                    let done = DispatchSemaphore(value: 0), result = Mutex<Result<Void, Error>?>(nil)
                    let deadline = ContinuousClock.now.advanced(by: bound)
                    Task {
                        do { try await body(f); result.withLock { $0 = .success(()) } }
                        catch { result.withLock { $0 = .failure(error) } }
                        done.signal()
                    }
                    guard done.wait(timeout: .now() + Self.remaining(deadline)) == .success else {
                        return XCTFail("Recovery did not return within its operation deadlines")
                    }
                    try XCTUnwrap(result.withLock { $0 }).get()
                }
                outcome.withLock { $0 = .success(()) }
            } catch { outcome.withLock { $0 = .failure(error) } }
            finished.signal()
        }
        thread.stackSize = SetupAuditUpgradeWorkExecutor.stackBytes
        thread.name = "Remozio orphan recovery fixture"; thread.start()
        guard finished.wait(timeout: .now() + Self.remaining(outerDeadline)) == .success else {
            return XCTFail("Fixture did not return within its operation and setup deadlines")
        }
        try XCTUnwrap(outcome.withLock { $0 }).get()
    }
    private static func unsettled(_ f: ExplicitStartupFixture) async throws {
        let joined = try await f.join()
        f.h.afterWrite = { row in if row.phase == .restored { f.rightsLive.value.withLock { $0 = false } } }
        do { _ = try await f.restore(joined); XCTFail("Expected lost completion authorization") } catch {}
        f.h.afterWrite = nil
        XCTAssertEqual(try f.h.frame().window?.phase, .restored)
        f.claim?.abandon()
    }
    func testWindowFreeOrphanReleasesOnlyAfterItsRealJoin() throws {
        try withFixture(window: false, binding: false) { f in
            let h = Context(f), s = try h.session(), r = try h.request(.releaseWindowFree); defer { s.close() }
            try E.start(s, r); await s.waitForWork()
            XCTAssertEqual(try E.code(s, r), .released); try f.retained.assertReleased()
            XCTAssertTrue(h.effects.withLock { $0.isEmpty }); XCTAssertEqual(h.imports.withLock { $0 }, 1)
        }
    }
    func testBindingWithoutWindowRequiresIdentityBeforeItCanRelease() throws {
        try withFixture(window: false) { f in
            let h = Context(f), first = try h.session(), missing = try E.request(.releaseWindowFree)
            try E.start(first, missing); await first.waitForWork()
            XCTAssertEqual(try E.code(first, missing), .refusedUnavailable)
            XCTAssertEqual(try f.retained.owner.retainedInvocationState(), .orphan); first.close()
            let s = try h.session(), r = try h.request(.releaseWindowFree); defer { s.close() }
            try E.start(s, r); await s.waitForWork(); XCTAssertEqual(try E.code(s, r), .released)
        }
    }
    func testCapturedTargetsAtTotalsOneAndTwoRefuseWithoutClaim() throws {
        try withFixture { f in
            for total in [1, 2] {
                let h = Context(f), s = try h.session(maximum: total), r = try h.request(.restore); defer { s.close() }
                try E.start(s, r); await s.waitForWork()
                XCTAssertEqual(try E.code(s, r), .refusedUnavailable)
                XCTAssertEqual(try f.retained.owner.retainedInvocationState(), .orphan)
                XCTAssertTrue(h.effects.withLock { $0.isEmpty }); f.retained.assertHeld()
            }
        }
    }
    func testFirstBoundOrphanOffersRestoreWithoutAClaimAndRunsOnlyTheRequestedAction() throws {
        let cleanup = Mutex(0)
        try withFixture(seed: .stopped, prepare: { f in
            try f.retained.owner.installRetainedApplicabilityRelease(f.retained.candidate)
            try XCTUnwrap(f.invocation).retainCleanup { cleanup.withLock { $0 += 1 } }
        }) { f in
            let h = Context(f)
            let owner = f.retained.owner
            let peer = h.peer
            try await owner.waitForRetainedQuiescenceOwned()
            XCTAssertEqual(cleanup.withLock { $0 }, 1)
            XCTAssertEqual(try owner.retainedInvocationState(), .orphan)
            let routing = AdministrativeSetupLifecycle.Routing(validateStartup: {})
            try routing.install(owner)
            routing.move(to: .serving)
            let checkCount = Mutex(0)
            let attempts = try owner.observeMaintenanceRecoveryExecutorOwned()
            let executorBefore = try attempts.countOwned()
            let accessBefore = try owner.statusAccessCountsOwned()
            let facade = AdministrativeSetupConnectionFacade(verify: { peer.credentials }, select: { $0 == .statusOnly },
                openNormal: { _ in throw Failure.expected }, status: { routing.status($0) },
                statusV3: AdministrativeSetupXPCListener.statusApplicabilityReader(available: true, routing: routing),
                check: {
                    checkCount.withLock { $0 += 1 }
                    let result = routing.checkStatus()
                    XCTAssertEqual(result, .pinned)
                    return result
                }, invalidate: {})
            defer { facade.close() }
            let request = try SetupRetainedStatusV3Wire.Request(legacy: .init(requestID: Data(repeating: 2, count: 16)))
            let replies = Mutex<[Data?]>([])
            facade.retainedInvocationStatus(try request.bytes) { bytes in replies.withLock { $0.append(bytes) } }
            XCTAssertEqual(replies.withLock { $0.count }, 1)
            let bytes = try XCTUnwrap(replies.withLock { $0.first ?? nil })
            let observation = try SetupRetainedStatusV3Wire.decodeReply(bytes, matching: request)
            XCTAssertEqual(observation.applicability, .restore)
            XCTAssertEqual(observation.window?.revision, try f.h.frame().window?.revision)
            XCTAssertEqual(checkCount.withLock { $0 }, 1)
            XCTAssertEqual(try attempts.countOwned(), executorBefore)
            XCTAssertEqual(try owner.statusAccessCountsOwned(), accessBefore)
            XCTAssertEqual(h.imports.withLock { $0 }, 0)
            XCTAssertTrue(h.effects.withLock { $0.isEmpty })
            XCTAssertEqual(try owner.retainedInvocationState(), .orphan)

            let session = try h.session(maximum: 3)
            defer { session.close() }
            let restore = try E.request(.restore, identity: XCTUnwrap(observation.identity))
            try E.start(session, restore)
            XCTAssertNil(owner.retainedStatusApplicability(authenticatedPeer: peer.credentials, currentOwner: peer.owner).applicability)
            await session.waitForWork()
            XCTAssertEqual(try E.code(session, restore), .restored)
            XCTAssertEqual(h.effects.withLock { $0 }, ["restore"])
            XCTAssertEqual(cleanup.withLock { $0 }, 1)
            try f.retained.assertReleased()
        }
    }

    func testChangedProtectedRowInvalidatesFirstOrphanRestore() throws {
        try withFixture(seed: .stopped, prepare: { f in
            try f.retained.owner.installRetainedApplicabilityRelease(f.retained.candidate)
        }) { f in
            let owner = f.retained.owner, binding = f.retained.binding
            try await owner.waitForRetainedQuiescenceOwned()
            let first = owner.retainedStatusApplicability(authenticatedPeer: binding.peer, currentOwner: binding.authorityOwner)
            XCTAssertEqual(first.applicability, .restore)
            let old = try XCTUnwrap(f.h.frame().window)
            let other = try RuntimeMaintenanceStartupPolicy.row(old, phase: .needsOwnerRecovery,
                service: old.service, failure: .healthFailed)
            XCTAssertNotEqual(other.revision, old.revision)
            owner.publishMaintenanceRecovery(other)
            let next = owner.retainedStatusApplicability(authenticatedPeer: binding.peer, currentOwner: binding.authorityOwner)
            XCTAssertNil(next.applicability)
            try await owner.waitForRetainedQuiescenceOwned()
            XCTAssertNil(owner.retainedStatusApplicability(authenticatedPeer: binding.peer, currentOwner: binding.authorityOwner).applicability)
            owner.publishMaintenanceRecovery(old)
            try await owner.waitForRetainedQuiescenceOwned()
            XCTAssertEqual(owner.retainedStatusApplicability(authenticatedPeer: binding.peer, currentOwner: binding.authorityOwner).applicability, .restore)
            XCTAssertEqual(try owner.retainedInvocationState(), .orphan)
        }
    }

    func testActualClaimInvalidatesFirstOrphanRestore() throws {
        try withFixture(seed: .stopped, prepare: { f in
            try f.retained.owner.installRetainedApplicabilityRelease(f.retained.candidate)
        }) { f in
            let owner = f.retained.owner, binding = f.retained.binding
            try await owner.waitForRetainedQuiescenceOwned()
            let refuse = Mutex(false)
            let rights = try f.retained.authorize(verify: { if refuse.withLock({ $0 }) { throw Failure.expected } })
            let target = try SetupRetainedOrphanClaim.Target.capture(owner: owner, authorization: rights)
            let read = { owner.retainedStatusApplicability(authenticatedPeer: binding.peer, currentOwner: binding.authorityOwner).applicability }
            XCTAssertEqual(read(), .restore)
            // The retained record still owns both admissions. A refused request cannot consume its observation.
            XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
            XCTAssertEqual(read(), .restore)
            refuse.withLock { $0 = true }
            XCTAssertThrowsError(try f.retained.claim(rights, target: target))
            XCTAssertEqual(read(), .restore)

            let claim = try f.retained.claim()
            XCTAssertNil(read())
            XCTAssertEqual(try owner.retainedInvocationState(), .recovering)
            claim.abandon()
            try await owner.waitForRetainedQuiescenceOwned()
            XCTAssertEqual(read(), .restore)
        }
    }

    func testSuccessfulMutationAdmissionInvalidatesAPublishedRestoreHint() throws {
        try withFixture(seed: .stopped, prepare: { f in
            try f.retained.owner.installRetainedApplicabilityRelease(f.retained.candidate)
        }) { f in
            let owner = f.retained.owner, binding = f.retained.binding
            try await owner.waitForRetainedQuiescenceOwned()
            let read = { owner.retainedStatusApplicability(authenticatedPeer: binding.peer, currentOwner: binding.authorityOwner).applicability }
            XCTAssertEqual(read(), .restore)
            let token = try owner.admitMutationAfterReleasingRetainedHoldOwned()
            defer { token.close() }
            XCTAssertNil(read())
        }
    }

    func testRestartStatusPublicationInvalidatesAPublishedRestoreHint() throws {
        try withFixture(seed: .stopped, prepare: { f in
            try f.retained.owner.installRetainedApplicabilityRelease(f.retained.candidate)
        }) { f in
            let owner = f.retained.owner, binding = f.retained.binding
            try await owner.waitForRetainedQuiescenceOwned()
            XCTAssertEqual(owner.retainedStatusApplicability(authenticatedPeer: binding.peer,
                currentOwner: binding.authorityOwner).applicability, .restore)
            try owner.republishRestartStatusOwned(accountID: binding.authorityAccountID, owner: binding.authorityOwner)
            XCTAssertNil(owner.retainedStatusApplicability(authenticatedPeer: binding.peer,
                currentOwner: binding.authorityOwner).applicability)
        }
    }

    func testUnrelatedAccountRowDoesNotInvalidateRestore() throws {
        try withFixture(seed: .stopped, prepare: { f in
            try f.retained.owner.installRetainedApplicabilityRelease(f.retained.candidate)
        }) { f in
            let owner = f.retained.owner, binding = f.retained.binding
            try await owner.waitForRetainedQuiescenceOwned()
            let read = { owner.retainedStatusApplicability(authenticatedPeer: binding.peer, currentOwner: binding.authorityOwner).applicability }
            XCTAssertEqual(read(), .restore)
            let row = try XCTUnwrap(f.h.frame().window), scope = row.scope
            let other = try RuntimeMaintenanceWindowRecord.Account(accountID: Data(repeating: 0xee, count: 16),
                ownerUID: scope.authority.ownerUID, directoryID: scope.authority.directoryID)
            let foreign = try RuntimeMaintenanceWindowRecord.Scope(macID: scope.macID, installationID: scope.installationID,
                authority: other, target: scope.target, releaseDigest: scope.releaseDigest, candidateDigest: scope.candidateDigest,
                authorityPolicyDigest: scope.authorityPolicyDigest, operationDigest: scope.operationDigest,
                restorationDigest: scope.restorationDigest, mutationFootprintDigest: scope.mutationFootprintDigest,
                authorityGrantDigest: scope.authorityGrantDigest, targetConsentDigest: scope.targetConsentDigest,
                administratorIntentDigest: scope.administratorIntentDigest)
            owner.publishMaintenanceRecovery(try .init(id: row.id, revision: row.revision, purpose: row.purpose, scope: foreign))
            XCTAssertEqual(read(), .restore)
        }
    }

    func testOwnerQuiescenceBackoffCapsBusyAndCountsOnlyConsecutiveFailedJoins() {
        var backoff = SetupAccountOwner.QuiescenceBackoff()
        let busy: [Duration] = [25, 50, 100, 200, 400, 800, 1600, 2000, 2000].map { .milliseconds($0) }
        for expected in busy {
            XCTAssertEqual(backoff.delay(for: .retryBusy(joinCompleted: false)), expected)
        }
        let joins: [Duration] = [1, 2, 4, 8].map { .seconds($0) }
        for expected in joins {
            XCTAssertEqual(backoff.delay(for: .retryJoin), expected)
        }
        XCTAssertEqual(backoff.delay(for: .retryBusy(joinCompleted: false)), .milliseconds(25))
        XCTAssertNil(backoff.delay(for: .retryJoin))
        XCTAssertEqual(backoff.delay(for: .retryBusy(joinCompleted: true)), .milliseconds(25))
        XCTAssertEqual(backoff.delay(for: .retryJoin), .seconds(1))
    }

    func testFiveOwnerCleanupFailuresWaitForANewQuiescenceEvent() throws {
        let failures = Mutex(0), allow = Mutex(false)
        try withFixture(seed: .stopped, prepare: { f in
            try f.retained.owner.installRetainedApplicabilityRelease(f.retained.candidate)
            try XCTUnwrap(f.invocation).retainCleanup {
                if !allow.withLock({ $0 }) {
                    failures.withLock { $0 += 1 }
                    throw Failure.expected
                }
            }
        }) { f in
            let owner = f.retained.owner, binding = f.retained.binding
            try await owner.waitForRetainedQuiescenceOwned()
            XCTAssertEqual(failures.withLock { $0 }, 5)
            XCTAssertNil(try owner.retainedQuiescenceTaskOwned())
            XCTAssertNil(owner.retainedStatusApplicability(authenticatedPeer: binding.peer,
                currentOwner: binding.authorityOwner).applicability)

            allow.withLock { $0 = true }
            owner.publishMaintenanceRecovery(try XCTUnwrap(f.h.frame().window))
            try await owner.waitForRetainedQuiescenceOwned()
            XCTAssertEqual(owner.retainedStatusApplicability(authenticatedPeer: binding.peer,
                currentOwner: binding.authorityOwner).applicability, .restore)
            XCTAssertEqual(failures.withLock { $0 }, 5)
        }
    }

    func testQuiescenceRefreshDuringFifthFailedJoinPublishesRestore() throws {
        let joins = Mutex(0)
        let finishFifthJoin = DispatchSemaphore(value: 0)
        let window = Mutex<RuntimeMaintenanceWindowRecord?>(nil)
        defer { finishFifthJoin.signal() }

        try withFixture(seed: .stopped, prepare: { f in
            try window.withLock { $0 = try XCTUnwrap(f.h.frame().window) }
            try f.retained.owner.installRetainedApplicabilityRelease(f.retained.candidate)
            try XCTUnwrap(f.invocation).retainCleanup {
                let join = joins.withLock { $0 += 1; return $0 }
                if join == 5 {
                    guard finishFifthJoin.wait(timeout: .now() + 15) == .success else {
                        XCTFail("The refresh did not arrive during the fifth join")
                        throw Failure.expected
                    }
                }
                if join <= 5 { throw Failure.expected }
            }
        }) { f in
            let owner = f.retained.owner, binding = f.retained.binding
            let task = try XCTUnwrap(owner.retainedQuiescenceTaskOwned())
            let deadline = ContinuousClock.now.advanced(by: .seconds(45))
            while joins.withLock({ $0 }) < 5 {
                guard ContinuousClock.now < deadline else {
                    finishFifthJoin.signal()
                    throw Failure.expected
                }
                try await Task.sleep(for: .milliseconds(5))
            }
            let row = try XCTUnwrap(window.withLock { $0 })
            owner.publishMaintenanceRecovery(row)
            finishFifthJoin.signal()

            await task.value
            XCTAssertEqual(joins.withLock { $0 }, 6)
            XCTAssertNil(try owner.retainedQuiescenceTaskOwned())
            XCTAssertEqual(owner.retainedStatusApplicability(authenticatedPeer: binding.peer,
                currentOwner: binding.authorityOwner).applicability, .restore)
        }
    }

    func testOwnerCloseAndAdmissionClosingCancelTheRetainedQuiescenceTask() throws {
        for closeImmediately in [true, false] {
            let cleanupEntered = Mutex(false), finishCleanup = DispatchSemaphore(value: 0)
            defer { finishCleanup.signal() }
            try withFixture(seed: .stopped, prepare: { f in
                try f.retained.owner.installRetainedApplicabilityRelease(f.retained.candidate)
                try XCTUnwrap(f.invocation).retainCleanup {
                    cleanupEntered.withLock { $0 = true }
                    _ = finishCleanup.wait(timeout: .now() + 5)
                    throw Failure.expected
                }
            }) { f in
                let owner = f.retained.owner
                let task = try XCTUnwrap(owner.retainedQuiescenceTaskOwned())
                let deadline = ContinuousClock.now.advanced(by: .seconds(5))
                while !cleanupEntered.withLock({ $0 }) {
                    guard ContinuousClock.now < deadline else {
                        finishCleanup.signal()
                        throw Failure.expected
                    }
                    try await Task.sleep(for: .milliseconds(5))
                }
                if closeImmediately { XCTAssertThrowsError(try owner.close()) }
                else { owner.closeMaintenanceRecoveryAdmission() }
                XCTAssertTrue(task.isCancelled)
                finishCleanup.signal()
                await task.value
                XCTAssertNil(try owner.retainedQuiescenceTaskOwned())
            }
        }
    }

    func testOwnerRepublishesAfterBusyExecutorAndFailedCleanup() throws {
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let cleanup = Mutex(0), probe = Mutex<SetupAuditUpgradeWorkExecutor.OwnedAttempts?>(nil)
        defer { release.signal() }
        try withFixture(seed: .stopped, prepare: { f in
            let owner = f.retained.owner
            try owner.installRetainedApplicabilityRelease(f.retained.candidate)
            try probe.withLock { $0 = try owner.observeMaintenanceRecoveryExecutorOwned() }
            try XCTUnwrap(f.invocation).retainCleanup {
                let attempt = cleanup.withLock { $0 += 1; return $0 }
                if attempt == 1 { throw Failure.expected }
            }
            Task {
                try await owner.occupyRetainedExecutorOwned {
                    entered.signal()
                    guard release.wait(timeout: .now() + 10) == .success else { throw Failure.expected }
                }
            }
            guard entered.wait(timeout: .now() + 5) == .success else { throw Failure.expected }
        }) { f in
            let owner = f.retained.owner, binding = f.retained.binding
            let attempts = try XCTUnwrap(probe.withLock { $0 })
            let deadline = ContinuousClock.now.advanced(by: .seconds(5))
            while try attempts.countOwned() < 2 {
                guard ContinuousClock.now < deadline else { throw Failure.expected }
                try await Task.sleep(for: .milliseconds(10))
            }
            XCTAssertNil(owner.retainedStatusApplicability(authenticatedPeer: binding.peer,
                currentOwner: binding.authorityOwner).applicability)
            release.signal()
            try await owner.waitForRetainedQuiescenceOwned()
            XCTAssertEqual(cleanup.withLock { $0 }, 2)
            XCTAssertEqual(owner.retainedStatusApplicability(authenticatedPeer: binding.peer,
                currentOwner: binding.authorityOwner).applicability, .restore)
        }
    }

    func testTotalThreeRestoresThroughTheExistingEntryAndOriginalHold() throws {
        try withFixture(seed: .stopped) { f in
            let h = Context(f), s = try h.session(maximum: 3), r = try h.request(.restore); defer { s.close() }
            try E.start(s, r); await s.waitForWork()
            XCTAssertEqual(try E.code(s, r), .restored); try f.retained.assertReleased()
            XCTAssertEqual(h.effects.withLock { $0 }, ["restore"])
            XCTAssertEqual(try f.h.frame().window?.phase, .restored)
        }
    }
    func testForeignAndAbsentTargetsHaveIdenticalStartAndProgressBytes() throws {
        try withFixture(window: false, binding: false) { f in
            let h = Context(f); h.foreign = true
            let s = try h.session(), r = try E.request(.releaseWindowFree)
            let foreignStart = try E.start(s, r); await s.waitForWork()
            let foreignProgress = s.progress(try W.Progress(requestID: r.requestID).bytes)
            XCTAssertEqual(try E.code(s, r), .refusedUnavailable)
            XCTAssertEqual(try f.retained.owner.retainedInvocationState(), .orphan)
            s.close()
            let legitimate = try f.retained.claim()
            let joined = try await legitimate.join()
            XCTAssertTrue(try joined.releaseIfWindowFree()); legitimate.abandon()
            XCTAssertEqual(try f.retained.owner.retainedInvocationState(), .settled)
            let empty = try h.session(); defer { empty.close() }
            XCTAssertEqual(try E.start(empty, r), foreignStart)
            XCTAssertEqual(empty.progress(try W.Progress(requestID: r.requestID).bytes), foreignProgress)
            XCTAssertEqual(try E.code(empty, r), .refusedUnavailable)
            XCTAssertEqual(try f.retained.owner.retainedInvocationState(), .settled)
        }
    }
    func testRefusedSelectorsAndDuplicatesKeepTheActualClaimLiveDuringJoin() throws {
        let gate = WorkerGate(); defer { gate.finish() }
        try withFixture(window: false, binding: false, prepare: { f in try f.invocation?.retainWorker(gate.task()) }) { f in
            let h = Context(f), s = try h.session(), r = try h.request(.releaseWindowFree); defer { s.close() }
            let first = try E.start(s, r, form: Data([1]))
            for _ in 0..<2 {
                XCTAssertNotNil(s.refuseForeignSelector())
                XCTAssertThrowsError(try f.retained.claim())
            }
            XCTAssertEqual(try W.Reply.decode(E.start(s, E.request(.restore, id: 2))).code, .refusedUnavailable)
            XCTAssertThrowsError(try f.retained.claim())
            XCTAssertEqual(try E.start(s, r, form: Data([2])), first)
            XCTAssertEqual(h.imports.withLock { $0 }, 1)
            XCTAssertEqual(try E.code(s, r), .pending)
            gate.finish(); await s.waitForWork(); XCTAssertEqual(try E.code(s, r), .released)
        }
    }
    func testStartAndHundredProgressReadsRun103SynchronousFullChecks() throws {
        let cleanupEntered = Mutex(false), finishCleanup = DispatchSemaphore(value: 0)
        defer { finishCleanup.signal() }
        try withFixture(window: false, binding: false, prepare: { f in
            try XCTUnwrap(f.invocation).retainCleanup {
                cleanupEntered.withLock { $0 = true }
                guard finishCleanup.wait(timeout: .now() + 45) == .success else {
                    XCTFail("The progress reads did not release the retained cleanup")
                    throw Failure.expected
                }
            }
        }) { f in
            let h = Context(f), checks = Mutex(0), r = try h.request(.releaseWindowFree)
            let s = try h.session { validation in
                if case .full = validation { checks.withLock { $0 += 1 } }
            }
            let facade = AdministrativeSetupConnectionFacade(verify: { h.peer.credentials },
                select: { $0 == .recoveryOnly }, openNormal: { _ in throw Failure.expected }, status: { _ in .unavailable },
                openRecovery: { _ in s }, recoveryAllowed: { true }, invalidate: {})
            defer { facade.close(); finishCleanup.signal() }

            let hello = Mutex<UInt64?>(nil)
            facade.recoveryHello { value in hello.withLock { $0 = value } }
            XCTAssertEqual(hello.withLock { $0 }, AdministrativeSetupInterface.orphanRecoveryVersion)
            let started = Mutex<Data?>(nil)
            facade.startRecovery(try r.bytes, authorization: Data()) { value in started.withLock { $0 = value } }
            XCTAssertEqual(try W.Reply.decode(XCTUnwrap(started.withLock { $0 })).code, .requestRecorded)
            XCTAssertEqual(try f.retained.owner.retainedInvocationState(), .recovering)
            XCTAssertEqual(h.imports.withLock { $0 }, 1)
            let deadline = ContinuousClock.now.advanced(by: .seconds(15))
            while !cleanupEntered.withLock({ $0 }) {
                guard ContinuousClock.now < deadline else {
                    return XCTFail("The retained cleanup did not reach the barrier")
                }
                try await Task.sleep(for: .milliseconds(5))
            }

            let progress = try W.Progress(requestID: r.requestID).bytes
            for _ in 0..<100 {
                let reply = Mutex<Data?>(nil)
                facade.recoveryProgress(progress) { value in reply.withLock { $0 = value } }
                XCTAssertEqual(try W.Reply.decode(XCTUnwrap(reply.withLock { $0 })).code, .pending)
            }
            XCTAssertEqual(checks.withLock { $0 }, 103)
            XCTAssertEqual(h.hostChecks.withLock { $0 }, 0)
            finishCleanup.signal()
            await s.waitForWork()
            XCTAssertEqual(try E.code(s, r), .released)
        }
    }
    func testFullValidationAfterRightsImportRefusesBeforeClaiming() throws {
        try withFixture(window: false, binding: false) { f in
            let h = Context(f), fullChecks = Mutex(0)
            let s = try h.session { validation in
                guard case .full = validation else { return }
                fullChecks.withLock { $0 += 1 }
                if h.imports.withLock({ $0 }) > 0 { throw Failure.expected }
            }
            defer { s.close() }
            let r = try h.request(.releaseWindowFree)
            XCTAssertEqual(try W.Reply.decode(E.start(s, r)).code, .requestRecorded)
            XCTAssertEqual(fullChecks.withLock { $0 }, 3)
            XCTAssertEqual(h.imports.withLock { $0 }, 1)
            XCTAssertEqual(try f.retained.owner.retainedInvocationState(), .orphan)
            XCTAssertEqual(h.hostChecks.withLock { $0 }, 0)
            f.retained.assertHeld()
        }
    }
    func testDeadlineDuringJoinPreventsRestorationButDoesNotAbandon() throws {
        let gate = WorkerGate(); defer { gate.finish() }
        try withFixture(seed: .stopped, prepare: { f in try f.invocation?.retainWorker(gate.task()) }) { f in
            let h = Context(f), s = try h.session(), r = try h.request(.restore); defer { s.close() }
            try E.start(s, r, onReply: { h.clock.withLock { $0 = $0.advanced(by: .seconds(121)) } })
            XCTAssertEqual(try E.code(s, r), .pending)
            gate.finish(); await s.waitForWork()
            XCTAssertEqual(try E.code(s, r), .failedDeadline)
            XCTAssertTrue(h.effects.withLock { $0.isEmpty }); XCTAssertTrue(f.h.writes.isEmpty)
            XCTAssertThrowsError(try f.retained.claim()); f.retained.assertHeld()
        }
    }
    private func retryAfterRetiringHello(_ f: ExplicitStartupFixture, action: W.Action) async throws {
        let h = Context(f), request = try h.request(action), opened = Mutex<SetupOrphanRecoveryEndpoint?>(nil)
        let invalidated = Mutex(0)
        func facade(_ routing: AdministrativeSetupLifecycle.Routing) -> AdministrativeSetupConnectionFacade {
            .init(verify: { h.peer.credentials }, select: { _ in true }, openNormal: { _ in throw Failure.expected },
                status: { _ in .unavailable }, normalAllowed: { false }, openRecovery: { _ in
                    let session = try h.session(); opened.withLock { $0 = session }; return session
                }, recoveryAllowed: { (try? routing.recoveryOwner()) != nil },
                invalidate: { invalidated.withLock { $0 += 1 } })
        }
        let retiring = AdministrativeSetupLifecycle.Routing(validateStartup: {})
        try retiring.install(f.retained.owner); retiring.move(to: .serving); retiring.move(to: .retiring)
        let old = facade(retiring), refused = Mutex<UInt64?>(nil), refusedStart = Mutex<Data?>(nil)
        old.recoveryHello { value in refused.withLock { $0 = value } }
        old.startRecovery(try request.bytes, authorization: Data()) { value in refusedStart.withLock { $0 = value } }
        XCTAssertEqual(refused.withLock { $0 }, 0); XCTAssertEqual(old.state, .closed)
        XCTAssertEqual(invalidated.withLock { $0 }, 1); XCTAssertNil(opened.withLock { $0 })
        XCTAssertNil(refusedStart.withLock { $0 }); XCTAssertEqual(h.imports.withLock { $0 }, 0)
        f.retained.assertHeld()
        let next = AdministrativeSetupLifecycle.Routing(validateStartup: {})
        try next.install(f.retained.owner); next.move(to: .serving)
        let replacement = facade(next), accepted = Mutex<UInt64?>(nil), reply = Mutex<Data?>(nil)
        defer { replacement.close() }
        replacement.recoveryHello { value in accepted.withLock { $0 = value } }
        XCTAssertEqual(accepted.withLock { $0 }, 13)
        replacement.startRecovery(try request.bytes, authorization: Data()) { value in reply.withLock { $0 = value } }
        let session = try XCTUnwrap(opened.withLock { $0 }); await session.waitForWork()
        XCTAssertEqual(try W.Reply.decode(XCTUnwrap(reply.withLock { $0 })).code, .requestRecorded)
        XCTAssertEqual(try E.code(session, request), action == .releaseWindowFree ? .released : .restored)
        XCTAssertEqual(h.imports.withLock { $0 }, 1); try f.retained.assertReleased()
    }
    func testRetiringHelloLeavesTheSameWindowFreeReleaseForTheNextDaemon() throws {
        try withFixture(window: false, binding: false) { f in
            try await self.retryAfterRetiringHello(f, action: .releaseWindowFree)
        }
    }
    func testRetiringHelloLeavesTheSameRecordedAdoptionForTheNextDaemon() throws {
        try withFixture(seed: .stopped, helperRestorations: 1) { f in
            try await Self.unsettled(f)
            let writes = f.h.writes
            try await self.retryAfterRetiringHello(f, action: .adoptRecordedCompletion)
            XCTAssertEqual(f.h.writes, writes)
        }
    }
    func testWindowFreeReleaseRemainsAllowedAfterDeadlineAndDuringRetirement() throws {
        try withFixture(window: false, binding: false) { f in
            let h = Context(f), s = try h.session(), r = try h.request(.releaseWindowFree); defer { s.close() }
            h.route.withLock { $0 = .retiring }
            try E.start(s, r, onReply: { h.clock.withLock { $0 = $0.advanced(by: .seconds(121)) } })
            await s.waitForWork(); XCTAssertEqual(try E.code(s, r), .released)
            try f.retained.assertReleased()
        }
    }
    func testRetirementBetweenJoinAndEffectStartsNoRestoration() throws {
        try withFixture(seed: .stopped) { f in
            let h = Context(f), s = try h.session(), r = try h.request(.restore); defer { s.close() }
            h.onHost = { [weak h] in guard let h else { return }; h.route.withLock { $0 = .retiring } }
            try E.start(s, r); await s.waitForWork()
            XCTAssertEqual(try E.code(s, r), .refusedUnavailable)
            XCTAssertTrue(h.effects.withLock { $0.isEmpty }); XCTAssertTrue(f.h.writes.isEmpty)
            f.retained.assertHeld(); h.onHost = nil
        }
    }
    func testAdoptionAfterDeadlineAndDuringRetirementDoesNotReplayRestoration() throws {
        try withFixture(seed: .stopped, helperRestorations: 1) { f in
            try await Self.unsettled(f)
            let writes = f.h.writes, h = Context(f), s = try h.session(), r = try h.request(.adoptRecordedCompletion)
            defer { s.close() }; h.route.withLock { $0 = .retiring }
            try E.start(s, r, onReply: { h.clock.withLock { $0 = $0.advanced(by: .seconds(121)) } })
            await s.waitForWork(); XCTAssertEqual(try E.code(s, r), .restored)
            XCTAssertEqual(f.h.writes, writes); XCTAssertEqual(h.effects.withLock { $0 }, ["adopt"])
            try f.retained.assertReleased()
        }
    }
    func testNoCompletionIsNotApplicableToAdoptionAfterSuccessfulClaim() throws {
        try withFixture(seed: .stopped) { f in
            let h = Context(f), s = try h.session(), r = try h.request(.adoptRecordedCompletion); defer { s.close() }
            try E.start(s, r); await s.waitForWork()
            XCTAssertEqual(try E.code(s, r), .notApplicable)
            XCTAssertEqual(try f.retained.owner.retainedInvocationState(), .recovering)
            XCTAssertTrue(h.effects.withLock { $0.isEmpty }); XCTAssertTrue(f.h.writes.isEmpty)
        }
    }
    func testUnsettledCompletionIsNotApplicableToANewRestore() throws {
        try withFixture(seed: .stopped, helperRestorations: 1) { f in
            try await Self.unsettled(f)
            let writes = f.h.writes, h = Context(f), s = try h.session(), r = try h.request(.restore); defer { s.close() }
            try E.start(s, r); await s.waitForWork()
            XCTAssertEqual(try E.code(s, r), .notApplicable)
            XCTAssertTrue(h.effects.withLock { $0.isEmpty }); XCTAssertEqual(f.h.writes, writes)
            f.retained.assertHeld()
        }
    }
    func testApplicabilityReadsAllThreeStatesAndRejectsExpiredRightsWithoutEffects() throws {
        try withFixture(window: false, binding: false) { f in
            let joined = try await f.join(), writes = f.h.writes
            XCTAssertEqual(try joined.recoveryApplicability(), .windowFree)
            f.rightsLive.value.withLock { $0 = false }
            XCTAssertThrowsError(try joined.recoveryApplicability()); XCTAssertEqual(f.h.writes, writes)
        }
        try withFixture(seed: .stopped) { f in
            let joined = try await f.join(), writes = f.h.writes
            XCTAssertEqual(try joined.recoveryApplicability(), .noCompletion)
            f.rightsLive.value.withLock { $0 = false }
            XCTAssertThrowsError(try joined.recoveryApplicability()); XCTAssertEqual(f.h.writes, writes)
        }
        try withFixture(seed: .stopped, helperRestorations: 1) { f in
            try await Self.unsettled(f)
            let joined = try await f.freshJoined(), writes = f.h.writes
            XCTAssertEqual(try joined.recoveryApplicability(), .unsettledCompletion)
            f.rightsLive.value.withLock { $0 = false }
            XCTAssertThrowsError(try joined.recoveryApplicability()); XCTAssertEqual(f.h.writes, writes)
        }
    }
    func testConnectionLossDuringJoinKeepsActualWorkerAndAllowsASuccessor() throws {
        let gate = WorkerGate(); defer { gate.finish() }
        try withFixture(window: false, binding: false, prepare: { f in try f.invocation?.retainWorker(gate.task()) }) { f in
            let h = Context(f), s = try h.session(), r = try h.request(.releaseWindowFree)
            try E.start(s, r); s.close(); s.close(); f.retained.assertHeld()
            let next = try h.session(); defer { next.close() }
            try E.start(next, r); XCTAssertEqual(try E.code(next, r), .pending)
            gate.finish(); await s.waitForWork(); await next.waitForWork()
            XCTAssertEqual(try E.code(next, r), .released); try f.retained.assertReleased()
        }
    }
    func testCloseAfterClaimCreationCannotInstallTheLateClaim() throws {
        try withFixture(window: false, binding: false) { f in
            let h = Context(f), s = try h.session(), r = try h.request(.releaseWindowFree)
            h.onRights = { [weak s] in
                if (try? f.retained.owner.retainedInvocationState()) == .recovering { s?.close() }
            }
            defer { h.onRights = nil }; try E.start(s, r); await s.waitForWork()
            XCTAssertNil(s.progress(try W.Progress(requestID: r.requestID).bytes))
            let claim = try f.retained.claim(); defer { claim.abandon() }
            let joined = try await claim.join(); XCTAssertTrue(try joined.releaseIfWindowFree())
        }
    }
    func testWritableCaptureWithoutADurableRowStaysHeld() throws {
        try withFixture { f in
            let h = Context(f), s = try h.session(), r = try h.request(.releaseWindowFree); defer { s.close() }
            try E.start(s, r); await s.waitForWork()
            XCTAssertEqual(try E.code(s, r), .notApplicable)
            XCTAssertTrue(h.effects.withLock { $0.isEmpty }); f.retained.assertHeld()
        }
    }
    func testLossDuringTheRestoredWriterLeavesARealSuccessorPathWithoutBodyReplay() throws {
        try withFixture(seed: .stopped, helperRestorations: 1) { f in
            let h = Context(f), s = try h.session(), r = try h.request(.restore)
            f.h.afterWrite = { [weak s] row in if row.phase == .restored { s?.close() } }
            try E.start(s, r); await s.waitForWork(); f.h.afterWrite = nil
            XCTAssertNil(s.progress(try W.Progress(requestID: r.requestID).bytes))
            XCTAssertEqual(h.effects.withLock { $0 }, ["restore"])
            let row = try XCTUnwrap(f.h.frame().window)
            XCTAssertTrue([RuntimeMaintenanceWindowRecord.Phase.restored, .needsOwnerRecovery, .restoring, .reopenPending].contains(row.phase))
            XCTAssertTrue(f.h.attemptedRows.allSatisfy { $0.scope == f.h.initial.scope })
            let successor = try f.retained.claim(); defer { successor.abandon() }
            let joined = try await successor.join()
            if try joined.recoveryApplicability() == .unsettledCompletion {
                let writes = f.h.writes
                let completed = try await joined.finishRecordedRestorationOwned(processLease: f.processLease)
                XCTAssertEqual(completed.phase, .restored); XCTAssertEqual(f.h.writes, writes)
            } else {
                let completed = try await f.restore(joined)
                XCTAssertEqual(completed.phase, .restored)
            }
            try f.retained.assertReleased()
        }
    }
    func testRecycledDirectoryIdentityCannotClaimTheExistingOwnerRecord() throws {
        try withFixture { f in
            let h = Context(f); h.recycledDirectory = true
            let s = try h.session(), r = try h.request(.restore); defer { s.close() }
            try E.start(s, r); await s.waitForWork()
            XCTAssertEqual(try E.code(s, r), .refusedUnavailable)
            XCTAssertEqual(try f.retained.owner.retainedInvocationState(), .orphan)
            XCTAssertTrue(h.effects.withLock { $0.isEmpty }); f.retained.assertHeld()
        }
    }
    func testFailedRightsImportLeavesTheActualOrphanUnchanged() throws {
        try withFixture { f in
            let before = f.retained.status, h = Context(f); h.failImport = true
            let s = try h.session(), r = try h.request(.restore); defer { s.close() }
            try E.start(s, r, onReply: { XCTAssertEqual(h.imports.withLock { $0 }, 0) })
            await s.waitForWork(); XCTAssertEqual(try E.code(s, r), .failedAuthorization)
            XCTAssertEqual(f.retained.status, before); XCTAssertTrue(h.effects.withLock { $0.isEmpty })
        }
    }
    func testAnUnboundAuthorizedRowCannotUseTheBoundRestorationEntry() throws {
        try withFixture(prepare: { try $0.h.seed(.authorized) }) { f in
            let before = try XCTUnwrap(f.h.frame().window)
            XCTAssertEqual(before.phase, .authorized); XCTAssertNil(before.shutdownBinding)
            let process = getpid(), user = getuid()
            try f.processLease.validate()
            let h = Context(f), s = try h.session(), r = try h.request(.restore); defer { s.close() }
            try E.start(s, r); await s.waitForWork()
            XCTAssertEqual(try E.code(s, r), .failedOperation)
            XCTAssertEqual(try f.h.frame().window, before)
            XCTAssertEqual(getpid(), process); XCTAssertEqual(getuid(), user); XCTAssertEqual(geteuid(), user)
            try f.processLease.validate()
            XCTAssertEqual(h.effects.withLock { $0 }, ["restore"])
            XCTAssertTrue(f.h.writes.isEmpty); f.retained.assertHeld()
        }
    }
    func testUncertainRestoredCommitDoesNotReplayTheEffectForADuplicate() throws {
        try withFixture(seed: .stopped) { f in
            f.h.failPhase = .restored; f.h.commitBeforeFailure = true
            let h = Context(f), s = try h.session(), r = try h.request(.restore); defer { s.close() }
            let first = try E.start(s, r); await s.waitForWork()
            let writes = f.h.writes
            XCTAssertNotEqual(try E.code(s, r), .restored)
            XCTAssertEqual(try E.start(s, r), first)
            XCTAssertEqual(f.h.writes, writes); XCTAssertEqual(h.effects.withLock { $0 }, ["restore"])
            f.retained.assertHeld()
        }
    }
    func testConcurrentDuplicateStartsImportOnceAndKeepOneActualClaim() throws {
        let gate = WorkerGate(); defer { gate.finish() }
        try withFixture(window: false, binding: false, prepare: { f in try f.invocation?.retainWorker(gate.task()) }) { f in
            let h = Context(f), s = try h.session(), r = try h.request(.releaseWindowFree); defer { s.close() }
            let bytes = try r.bytes, replies = Mutex<[Data?]>([])
            DispatchQueue.concurrentPerform(iterations: 2) { index in
                s.start(bytes, authorization: Data([UInt8(index)])) { value in replies.withLock { $0.append(value) } }
            }
            let values = replies.withLock { $0 }
            XCTAssertEqual(values.count, 2); XCTAssertTrue(values.allSatisfy { $0 != nil })
            XCTAssertEqual(Set(values.compactMap { $0 }).count, 1)
            XCTAssertEqual(h.imports.withLock { $0 }, 1)
            XCTAssertEqual(try f.retained.owner.retainedInvocationState(), .recovering)
            XCTAssertThrowsError(try f.retained.claim())
            XCTAssertEqual(try E.code(s, r), .pending)
            gate.finish(); await s.waitForWork(); XCTAssertEqual(try E.code(s, r), .released)
            try f.retained.assertReleased()
        }
    }
    func testUnboundTargetRefusesEveryProvidedIdentityBeforeClaim() throws {
        try withFixture(window: false, binding: false) { f in
            XCTAssertEqual(f.retained.status.identity, .unavailable)
            let authorization = try f.retained.authorize()
            let privateTarget = try SetupRetainedOrphanClaim.Target.capture(owner: f.retained.owner, authorization: authorization)
            authorization.close()
            let h = Context(f)
            for action in W.Action.allCases {
                let s = try h.session(), r = try E.request(action, identity: privateTarget.identity); defer { s.close() }
                try E.start(s, r); await s.waitForWork()
                XCTAssertEqual(try E.code(s, r), .refusedUnavailable)
                XCTAssertEqual(try f.retained.owner.retainedInvocationState(), .orphan)
            }
            for action in [W.Action.restore, .adoptRecordedCompletion] {
                let s = try h.session(), r = try E.request(action); defer { s.close() }
                try E.start(s, r); await s.waitForWork()
                XCTAssertEqual(try E.code(s, r), .refusedUnavailable)
                XCTAssertEqual(try f.retained.owner.retainedInvocationState(), .orphan)
            }
            XCTAssertTrue(h.effects.withLock { $0.isEmpty })
            let s = try h.session(), r = try E.request(.releaseWindowFree); defer { s.close() }
            try E.start(s, r); await s.waitForWork(); XCTAssertEqual(try E.code(s, r), .released)
        }
    }
    func testAbortWriterUsesTheFixedSetupProcessLeaseAfterCallerLoss() throws {
        for validSetupLease in [true, false] {
            try withFixture(seed: .stopped) { f in
                let setupProcess = getpid(), setupUser = getuid(), h = Context(f)
                let s = try h.session(), r = try h.request(.restore), lost = Mutex(false), abortWrites = Mutex(0)
                defer { s.close() }
                f.h.beforeWrite = { row in
                    if row.phase == .needsOwnerRecovery {
                        XCTAssertTrue(lost.withLock { $0 }); XCTAssertFalse(h.rights.withLock { $0 })
                        XCTAssertEqual(getpid(), setupProcess); XCTAssertEqual(getuid(), setupUser); XCTAssertEqual(geteuid(), setupUser)
                        try f.processLease.validate(); abortWrites.withLock { $0 += 1 }
                    }
                }
                f.h.afterWrite = { [weak s] row in
                    if row.phase == .reopenPending {
                        lost.withLock { $0 = true }; h.rights.withLock { $0 = false }; s?.close()
                        if !validSetupLease { f.processLease.close() }
                    }
                }
                try E.start(s, r); await s.waitForWork()
                XCTAssertTrue(lost.withLock { $0 })
                if validSetupLease {
                    XCTAssertEqual(abortWrites.withLock { $0 }, 1)
                    XCTAssertEqual(try f.h.frame().window?.phase, .needsOwnerRecovery)
                } else {
                    XCTAssertEqual(abortWrites.withLock { $0 }, 0)
                    XCTAssertEqual(try f.h.frame().window?.phase, .reopenPending)
                }
                XCTAssertEqual(h.effects.withLock { $0 }, ["restore"]); f.retained.assertHeld()
            }
        }
    }
}
