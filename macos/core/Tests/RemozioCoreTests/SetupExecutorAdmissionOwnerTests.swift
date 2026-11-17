import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

// Large fixture construction must finish before the test resumes on the cooperative pool.
enum SetupExecutorAdmissionTestFixture {
    private enum Failure: Error { case insufficientStack }
    static func make<Value: Sendable>(_ body: @escaping @Sendable () throws -> Value) async throws -> Value {
        try await withCheckedThrowingContinuation { continuation in
            let thread = Thread {
                continuation.resume(with: Result {
                    guard pthread_get_stacksize_np(pthread_self()) >= SetupAuditUpgradeWorkExecutor.stackBytes else {
                        throw Failure.insufficientStack
                    }
                    return try body()
                })
            }
            thread.name = "remozio.test.fixture"
            thread.stackSize = SetupAuditUpgradeWorkExecutor.stackBytes
            thread.start()
        }
    }
}

final class SetupExecutorAdmissionOwnerTests: XCTestCase {
    private typealias Claim = SetupRestartRecovery.Claim
    private enum Failure: Error { case expected, timeout }
    private final class Gate: @unchecked Sendable {
        let entered = Mutex(false)
        private let resume = DispatchSemaphore(value: 0)
        func wait() throws {
            entered.withLock { $0 = true }
            guard resume.wait(timeout: .now() + 15) == .success else { throw Failure.timeout }
        }
        func open() { resume.signal() }
    }
    private final class Probe<Value: Sendable>: @unchecked Sendable {
        let task: Task<Value, any Error>, finished = Mutex(false)
        init(_ operation: @escaping @Sendable () async throws -> Value) {
            let actual = Task { try await operation() }; task = actual
            Task { [self] in _ = await actual.result; finished.withLock { $0 = true } }
        }
        func value() async throws -> Value { try await task.value }
    }
    private final class Fixture: @unchecked Sendable {
        let h: RuntimeAuditUpgradeOperationTests.Harness
        let owner: SetupAccountOwner, process: SetupProcessLease
        var accountID: Data { h.base.runtime.account.accountID }
        var identity: LocalAccountIdentity { h.base.runtime.f.identity }
        var peer: XPCPeerCredentials { .init(processID: getpid(), userID: identity.uid, auditSessionID: 1) }
        init() throws {
            h = try .init(); owner = try h.owner()
            process = try .openOwned(directory: .init(anchor: h.activity.root.path, relativeDirectory: "Machine", owner: getuid()))
        }
        static func make() async throws -> Fixture {
            try await SetupExecutorAdmissionTestFixture.make { try Fixture() }
        }
        func authorize(verify: @escaping () throws -> Void = {}) throws -> SetupRetainedRecoveryAuthorization {
            try .openOwned(peer: peer, currentOwner: identity, incarnation: UUID(), verifyRights: verify)
        }
        func claim(_ rights: SetupRetainedRecoveryAuthorization? = nil,
            account: Data? = nil, until deadline: ContinuousClock.Instant = .now.advanced(by: .seconds(5))) async throws -> Claim {
            let grant = try rights ?? authorize()
            return try await .openOwned(owner: owner, authorization: grant, processLease: process,
                accountID: account ?? accountID, until: deadline)
        }
        func assertBlocked() {
            XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try owner.acquireSetupReplyAdmission())
        }
        func assertPinned() {
            // A concurrent abandon can hold the owner lock. Require pinned once that lock becomes available.
            let deadline = ContinuousClock.now.advanced(by: .seconds(5))
            var status = owner.statusLaneCheck()
            while status == .busy, ContinuousClock.now < deadline {
                Thread.sleep(forTimeInterval: 0.001)
                status = owner.statusLaneCheck()
            }
            XCTAssertEqual(status, .pinned)
            assertBlocked()
        }
        func assertAvailable() throws {
            try owner.verifyCurrent(); let reply = try owner.acquireSetupReplyAdmission(); reply.close()
            let exclusive = try h.installer.acquireExclusive(); exclusive.close()
        }
        deinit { try? owner.close(); process.close() }
    }
    private static func eventually(_ predicate: () -> Bool, within duration: Duration = .seconds(5)) async throws {
        let deadline = ContinuousClock.now.advanced(by: duration)
        while !predicate() {
            guard ContinuousClock.now < deadline else { throw Failure.timeout }
            try await ContinuousClock().sleep(for: .milliseconds(1))
        }
    }
    private static func unavailable<Value>(_ operation: () async throws -> Value) async {
        do { _ = try await operation(); XCTFail("Busy admission was accepted") }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
    }
    private func auditClaimGroup() async throws {
        let f = try await Fixture.make(), gate = Gate(), calls = Mutex(0), opened = Mutex(false)
        let grant = try SetupAuditUpgradeAuthorization.openOwned(verifyRights: {})
        let audit = Probe {
            try await f.owner.performAuditUpgradeWork(authorization: grant) { _, admission in
                try gate.wait()
                let scope = try f.owner.acquireAuditUpgradeScope(authorization: grant, admission: admission)
                opened.withLock { $0 = true }; try scope.close()
            }
        }
        defer { gate.open() }
        try await Self.eventually { gate.entered.withLock { $0 } }
        for _ in 0..<200 {
            let rights = try f.authorize { calls.withLock { $0 += 1 } }
            let baseline = calls.withLock { $0 }
            do {
                _ = try await f.claim(rights, until: .now.advanced(by: .milliseconds(50)))
                XCTFail("Claim stole an audit admission")
            } catch { XCTAssertTrue(error is CancellationError) }
            XCTAssertEqual(calls.withLock { $0 }, baseline)
            f.assertPinned()
        }
        gate.open(); try await audit.value()
        XCTAssertTrue(opened.withLock { $0 }); try f.assertAvailable()
    }

    // DESIGN3.
    func testAuditAndFreshClaimArePinnedInsideTheirActualExecutorBodies() async throws {
        let f = try await Fixture.make(), grant = try SetupAuditUpgradeAuthorization.openOwned(verifyRights: {})
        try await f.owner.performAuditUpgradeWork(authorization: grant) { _, admission in
            f.assertPinned()
            let scope = try f.owner.acquireAuditUpgradeScope(authorization: grant, admission: admission); try scope.close()
        }
        let enabled = Mutex(false), checks = Mutex(0)
        let rights = try f.authorize {
            if enabled.withLock({ $0 }) { f.assertPinned(); checks.withLock { $0 += 1 } }
        }
        enabled.withLock { $0 = true }
        let claim = try await f.claim(rights); XCTAssertGreaterThan(checks.withLock { $0 }, 0)
        claim.abandon(); try f.assertAvailable()
    }
    // DESIGN4 and9.
    func testTransientRunRefusesAuditAndReservationButClaimWaitsForReturn() async throws {
        let f = try await Fixture.make(), gate = Gate(), checks = Mutex(0)
        let worker = Probe { try await f.owner.occupyExecutorOwned { try gate.wait() } }
        defer { gate.open() }
        try await Self.eventually { gate.entered.withLock { $0 } }
        let grant = try SetupAuditUpgradeAuthorization.openOwned(verifyRights: {})
        await Self.unavailable {
            try await f.owner.performAuditUpgradeWork(authorization: grant) { _, _ in XCTFail("Busy audit body") }
        }
        XCTAssertThrowsError(try f.owner.reserveRetainedInvocation(authenticatedPeer: f.peer,
            incarnation: UUID(), authenticatedOwner: f.identity))
        let rights = try f.authorize { checks.withLock { $0 += 1 } }, baseline = checks.withLock { $0 }
        let claim = Probe { try await f.claim(rights) }
        try await ContinuousClock().sleep(for: .milliseconds(200))
        XCTAssertFalse(claim.finished.withLock { $0 }); XCTAssertEqual(checks.withLock { $0 }, baseline); f.assertPinned()
        gate.open(); try await worker.value()
        let actual = try await claim.value(); actual.abandon(); try f.assertAvailable()
    }
    // DESIGN6.
    func testAuditAdmissionAllowsOneScopeOnlyWhileItsWorkerRuns() async throws {
        let f = try await Fixture.make(), grant = try SetupAuditUpgradeAuthorization.openOwned(verifyRights: {})
        let saved = Mutex<SetupAccountOwner.ExecutorAdmission?>(nil)
        try await f.owner.performAuditUpgradeWork(authorization: grant) { _, admission in
            saved.withLock { $0 = admission }
            let first = try f.owner.acquireAuditUpgradeScope(authorization: grant, admission: admission)
            XCTAssertThrowsError(try f.owner.acquireAuditUpgradeScope(authorization: grant, admission: admission))
            try first.close()
            XCTAssertThrowsError(try f.owner.acquireAuditUpgradeScope(authorization: grant, admission: admission))
            f.assertPinned()
        }
        let admission = try XCTUnwrap(saved.withLock { $0 })
        XCTAssertThrowsError(try f.owner.acquireAuditUpgradeScope(authorization: grant, admission: admission))
        try f.assertAvailable()
    }
    // DESIGN7.
    func testFailedFreshClaimReleasesBothTokensAfterItsBodyReturns() async throws {
        let f = try await Fixture.make(), checks = Mutex(0), enabled = Mutex(false)
        let rights = try f.authorize { if enabled.withLock({ $0 }) { f.assertPinned(); checks.withLock { $0 += 1 } } }
        enabled.withLock { $0 = true }
        do { _ = try await f.claim(rights, account: Data(repeating: 0x33, count: 16)); XCTFail("Wrong account accepted") }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .wrongAccount) }
        XCTAssertGreaterThan(checks.withLock { $0 }, 0); try f.assertAvailable()
    }
    // DESIGN8.
    func testCloseWhenIdleWaitsForTheActualAuditBody() async throws {
        let f = try await Fixture.make(), gate = Gate(), grant = try SetupAuditUpgradeAuthorization.openOwned(verifyRights: {})
        let audit = Probe { try await f.owner.performAuditUpgradeWork(authorization: grant) { _, _ in try gate.wait() } }
        defer { gate.open() }
        try await Self.eventually { gate.entered.withLock { $0 } }
        let close = Probe { try await f.owner.closeWhenIdle() }
        try await ContinuousClock().sleep(for: .milliseconds(200))
        XCTAssertFalse(close.finished.withLock { $0 }); f.assertBlocked()
        gate.open(); try await audit.value(); try await close.value()
        XCTAssertThrowsError(try f.owner.verifyCurrent())
    }
    // DESIGN10(a),(c): neither durable holder permits rights verification on the executor.
    func testDurableReservationAndReplyOnlyWorkRefuseAClaimBeforeRights() async throws {
        let f = try await Fixture.make(), checks = Mutex(0)
        let record = try f.owner.reserveRetainedInvocation(authenticatedPeer: f.peer,
            incarnation: UUID(), authenticatedOwner: f.identity).record
        let first = try f.authorize { checks.withLock { $0 += 1 } }, baseline = checks.withLock { $0 }
        let start = ContinuousClock.now
        await Self.unavailable { try await f.claim(first) }
        XCTAssertLessThan(start.duration(to: .now), .milliseconds(100)); XCTAssertEqual(checks.withLock { $0 }, baseline)
        record.abortConstruction(); try f.assertAvailable()
        let reply = try f.owner.acquireSetupReplyAdmission(); defer { reply.close() }
        let second = try f.authorize { checks.withLock { $0 += 1 } }, next = checks.withLock { $0 }
        let again = ContinuousClock.now
        await Self.unavailable { try await f.claim(second) }
        XCTAssertLessThan(again.duration(to: .now), .milliseconds(100)); XCTAssertEqual(checks.withLock { $0 }, next)
    }
    func testFixtureHoldsAndOwnedPhasesCannotWrapRealReservationTokens() async throws {
        let f = try await Fixture.make()
        let record = try f.owner.reserveRetainedInvocation(authenticatedPeer: f.peer,
            incarnation: UUID(), authenticatedOwner: f.identity).record
        defer { record.abortConstruction() }
        let hold = record.hold
        XCTAssertThrowsError(try SetupAccountOwner.ExecutorAdmission.durableOwned(admission: hold.admission,
            reply: hold.reply, activity: nil))
        XCTAssertThrowsError(try SetupRetainedInvocationReservation.RestorationPhases.owned(executor: .init(), hold: hold))
        f.assertPinned(); record.abortConstruction(); try f.assertAvailable()
    }
    // DESIGN12.
    func testClaimWaitsWhileLastWorkerHasMarkedReleaseButNotClosedTokens() async throws {
        let f = try await Fixture.make(), ending = Gate(), observed = Mutex(false)
        try f.owner.observeHoldEndOwned {
            let first = observed.withLock { value in if value { return false }; value = true; return true }
            if first { do { try ending.wait() } catch { XCTFail("End observer timed out") } }
        }
        let worker = Probe { try await f.owner.occupyExecutorOwned {} }
        defer { ending.open() }
        try await Self.eventually { ending.entered.withLock { $0 } }
        let claim = Probe { try await f.claim() }
        try await ContinuousClock().sleep(for: .milliseconds(100))
        XCTAssertFalse(claim.finished.withLock { $0 }); f.assertPinned()
        ending.open(); try await worker.value()
        let actual = try await claim.value(); actual.abandon(); try f.assertAvailable()
    }
    // DESIGN13, including a waiting claim whose deadline expires without taking rights.
    func testClaimWaitsForReleasedRecordsLastPhaseAndDeadlineTakesNothing() async throws {
        let f = try await Fixture.make(), gate = Gate(), checks = Mutex(0), a = try await f.claim()
        let phases = a.restorationPhases()
        let phase = Probe { try await phases.cleanup { a.abandon(); try gate.wait() } }
        defer { gate.open() }
        try await Self.eventually { gate.entered.withLock { $0 } }
        let rights = try f.authorize { checks.withLock { $0 += 1 } }, baseline = checks.withLock { $0 }
        do { _ = try await f.claim(rights, until: .now.advanced(by: .milliseconds(100))); XCTFail("Expired wait claimed") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(checks.withLock { $0 }, baseline)
        let next = Probe { try await f.claim() }
        try await ContinuousClock().sleep(for: .milliseconds(100)); XCTAssertFalse(next.finished.withLock { $0 })
        gate.open(); try await phase.value()
        let actual = try await next.value(); actual.abandon(); try f.assertAvailable()
    }
    // DESIGN22.
    func testCloseWhenIdleWaitsForAReleasedRecordsRunningPhase() async throws {
        let f = try await Fixture.make(), a = try await f.claim(), gate = Gate(), phases = a.restorationPhases()
        let phase = Probe { try await phases.cleanup { a.abandon(); try gate.wait() } }
        defer { gate.open() }
        try await Self.eventually { gate.entered.withLock { $0 } }
        let close = Probe { try await f.owner.closeWhenIdle() }
        try await ContinuousClock().sleep(for: .milliseconds(200))
        XCTAssertFalse(close.finished.withLock { $0 }); f.assertBlocked()
        gate.open(); try await phase.value(); try await close.value()
        let exclusive = try f.h.installer.acquireExclusive(); exclusive.close()
    }
    // DESIGN23 integration and24: refused phases wait for the real end observer.
    private func refusedPhaseWait(cancelled: Bool) async throws {
        let f = try await Fixture.make(), ending = Gate(), observed = Mutex(false), writes = Mutex(0)
        try f.owner.observeHoldEndOwned {
            let first = observed.withLock { value in if value { return false }; value = true; return true }
            if first { do { try ending.wait() } catch { XCTFail("End observer timed out") } }
        }
        let a = try await f.claim(), phases = a.restorationPhases()
        let phase = Probe { try await phases.cleanup { a.abandon() } }
        defer { ending.open() }
        try await Self.eventually { ending.entered.withLock { $0 } }
        if cancelled {
            let refused = Probe { try await phases.cleanup { writes.withLock { $0 += 1 } } }
            refused.task.cancel()
            try await Self.eventually({ refused.finished.withLock { $0 } }, within: .milliseconds(100))
            do { try await refused.value(); XCTFail("Released phase accepted") }
            catch { XCTAssertEqual(error as? JournalLeaseError, .invalidated) }
            f.assertPinned(); XCTAssertEqual(writes.withLock { $0 }, 0)
        } else {
            let refused = Probe { await a.releaseRefusedAttemptIfSafe() }
            try await ContinuousClock().sleep(for: .milliseconds(200))
            XCTAssertFalse(refused.finished.withLock { $0 }); f.assertPinned()
            ending.open(); try await refused.value()
            try f.assertAvailable()
        }
        ending.open(); try await phase.value(); try f.assertAvailable()
    }
    func testCancelledRefusedPhaseReturnsWithoutReleasingPendingRealClose() async throws {
        try await refusedPhaseWait(cancelled: true)
    }
    func testRefusedClaimCleanupWaitsUntilTheRealReleaseHasFinished() async throws {
        try await refusedPhaseWait(cancelled: false)
    }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup00() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup01() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup02() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup03() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup04() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup05() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup06() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup07() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup08() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup09() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup10() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup11() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup12() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup13() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup14() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup15() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup16() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup17() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup18() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup19() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup20() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup21() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup22() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup23() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup24() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup25() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup26() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup27() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup28() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup29() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup30() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup31() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup32() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup33() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup34() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup35() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup36() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup37() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup38() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup39() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup40() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup41() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup42() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup43() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup44() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup45() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup46() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup47() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup48() async throws { try await auditClaimGroup() }
    func testAuditScopeSurvivesTwoHundredTimedClaimsGroup49() async throws { try await auditClaimGroup() }
    // DESIGN11.
    func testTwoFreshClaimsWaitThenRefuseTheStillLiveWinner() async throws {
        let f = try await Fixture.make(), gate = Gate(), firstVerification = Mutex(false), checks = Mutex(0)
        let a = try f.authorize {
            let shouldBlock = firstVerification.withLock { value in
                if !value { return false }; value = false; return true
            }
            if shouldBlock { try gate.wait() }
        }
        firstVerification.withLock { $0 = true }
        let first = Probe { try await f.claim(a) }; defer { gate.open() }
        try await Self.eventually { gate.entered.withLock { $0 } }
        let b = try f.authorize { checks.withLock { $0 += 1 } }, baseline = checks.withLock { $0 }
        let second = Probe { try await f.claim(b) }
        try await ContinuousClock().sleep(for: .milliseconds(100))
        XCTAssertFalse(second.finished.withLock { $0 }); XCTAssertEqual(checks.withLock { $0 }, baseline)
        gate.open(); let winner = try await first.value()
        await Self.unavailable { try await second.value() }
        f.assertPinned(); winner.abandon(); try f.assertAvailable()
    }
    // DESIGN18. Each verification that reaches the executor must still see a real admission.
    func testFiveHundredReclaimsRacingAbandonNeverRunWithoutAdmission() async throws {
        let f = try await Fixture.make(), checked = Mutex(0)
        for round in 0..<500 {
            let a = try await f.claim(), enabled = Mutex(false)
            let b = try f.authorize {
                if enabled.withLock({ $0 }) { f.assertPinned(); checked.withLock { $0 += 1 } }
            }
            enabled.withLock { $0 = true }
            let next = Probe { try await f.claim(b) }
            let abandoning = Task.detached {
                try? await ContinuousClock().sleep(for: .milliseconds(Int64(round % 3)))
                a.abandon()
            }
            var winner: Claim?
            do { winner = try await next.value() }
            catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
            await abandoning.value; winner?.abandon(); try f.assertAvailable()
        }
        XCTAssertGreaterThan(checked.withLock { $0 }, 0)
    }
    // DESIGN15, restart half. No body or lease/rights verification runs after a full release.
    func testReleasedRestartPhasesNeverEnterTheExecutorEvenWithInvalidRights() async throws {
        let f = try await Fixture.make(), writes = Mutex(0), rights = try f.authorize(), a = try await f.claim(rights)
        let phases = a.restorationPhases(), attempts = try f.owner.observeMaintenanceRecoveryExecutorOwned()
        let released = try await a.releaseWithoutRestoration(); XCTAssertTrue(released)
        let baseline = try attempts.countOwned()
        for operation in 0..<3 {
            do {
                if operation == 0 { try await phases.run { writes.withLock { $0 += 1 } } }
                else if operation == 1 { try await phases.cleanup { writes.withLock { $0 += 1 } } }
                else { try await phases.closeActual { writes.withLock { $0 += 1 } } }
                XCTFail("Released phase body was accepted")
            } catch { XCTAssertEqual(error as? JournalLeaseError, .invalidated) }
        }
        rights.close(); f.process.close()
        let again = try await a.releaseWithoutRestoration(); XCTAssertFalse(again)
        XCTAssertEqual(writes.withLock { $0 }, 0); XCTAssertEqual(try attempts.countOwned(), baseline)
        try f.assertAvailable()
    }
    // DESIGN1, free-running variant. There is no retry of an audit that entered its body.
    func testFreeRunningClaimsDoNotFailAnAuditThatEnteredItsBody() async throws {
        let f = try await Fixture.make(), stop = Mutex(false), entered = Mutex(0)
        let claims = Probe {
            while !stop.withLock({ $0 }) {
                do {
                    let claim = try await f.claim(until: .now.advanced(by: .milliseconds(200)))
                    claim.abandon()
                } catch is CancellationError {} catch {
                    XCTAssertEqual(error as? AdministrativeSetupError, .unavailable)
                }
                try? await ContinuousClock().sleep(for: .milliseconds(1))
            }
        }
        defer { stop.withLock { $0 = true } }
        for _ in 0..<200 {
            let began = Mutex(false), grant = try SetupAuditUpgradeAuthorization.openOwned(verifyRights: {})
            do {
                try await f.owner.performAuditUpgradeWork(authorization: grant) { _, admission in
                    began.withLock { $0 = true }; entered.withLock { $0 += 1 }
                    let scope = try f.owner.acquireAuditUpgradeScope(authorization: grant, admission: admission)
                    try scope.close()
                }
            } catch {
                XCTAssertFalse(began.withLock { $0 }, "An admitted audit failed")
                XCTAssertEqual(error as? AdministrativeSetupError, .unavailable)
            }
        }
        stop.withLock { $0 = true }; try await claims.value()
        XCTAssertGreaterThan(entered.withLock { $0 }, 0); try f.assertAvailable()
    }

    private func withRetainedFrame(_ body: @escaping @Sendable (SetupRetainedOrphanClaimTests.Frame) async throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { source in
            let activity = try ReleaseActivityFixture(), frame = try SetupRetainedOrphanClaimTests.Frame(source, activity: activity)
            let done = DispatchSemaphore(value: 0), result = Mutex<Result<Void, any Error>?>(nil)
            Task {
                do { try await body(frame); result.withLock { $0 = .success(()) } }
                catch { result.withLock { $0 = .failure(error) } }
                done.signal()
            }
            guard done.wait(timeout: .now() + 45) == .success else { throw Failure.timeout }
            try XCTUnwrap(result.withLock { $0 }).get()
        }
    }
    // DESIGN15, retained half. Capture the real phase capability before releasing its reservation.
    func testReleasedRetainedPhasesNeverEnterTheirOriginalExecutor() throws {
        try withRetainedFrame { frame in
            var invocation: SetupRetainedInvocation? = try frame.invocation(); try frame.lose(&invocation)
            let joined = try await frame.claim().join(), phases = try joined.restorationPhases(), writes = Mutex(0)
            let released = try joined.releaseIfWindowFree(); XCTAssertTrue(released)
            for operation in 0..<3 {
                do {
                    if operation == 0 { try await phases.run { writes.withLock { $0 += 1 } } }
                    else if operation == 1 { try await phases.cleanup { writes.withLock { $0 += 1 } } }
                    else { try await phases.closeActual { writes.withLock { $0 += 1 } } }
                    XCTFail("Released retained phase body was accepted")
                } catch { XCTAssertEqual(error as? JournalLeaseError, .invalidated) }
            }
            XCTAssertEqual(writes.withLock { $0 }, 0); try frame.assertReleased()
        }
    }
    // DESIGN20.
    func testLedgerCleanupSeesTheReservationsAdmissionOnTheWorker() throws {
        try withRetainedFrame { frame in
            let observed = Mutex(0)
            var invocation: SetupRetainedInvocation? = try frame.invocation()
            try invocation?.retainCleanup {
                XCTAssertEqual(frame.owner.statusLaneCheck(), .pinned)
                XCTAssertGreaterThanOrEqual(pthread_get_stacksize_np(pthread_self()), SetupAuditUpgradeWorkExecutor.stackBytes)
                observed.withLock { $0 += 1 }
            }
            try frame.lose(&invocation)
            let joined = try await frame.claim().join()
            XCTAssertEqual(observed.withLock { $0 }, 1)
            let released = try joined.releaseIfWindowFree(); XCTAssertTrue(released); try frame.assertReleased()
        }
    }

}
