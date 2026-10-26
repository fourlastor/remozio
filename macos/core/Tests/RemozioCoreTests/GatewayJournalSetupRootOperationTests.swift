import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewayJournalSetupRootOperationTests: XCTestCase, @unchecked Sendable {
    private struct Interrupted: Error {}
    private final class Harness: @unchecked Sendable {
        struct State {
            var job = GatewayJournalSetupJobRegistration.Observation.absent
            var events: [String] = []
            var dropReport = false
            var keepActive = false
            var forbidJournal = false
            var invalidateAfterReport = false
            var invalidHost = false
            var created: Bool?
        }
        let value = Mutex(State())
        let fixture: GatewayJournalSetupExchangeTests.Fixture
        let configuration: GatewayJournalSetupServiceConfiguration
        let job: GatewayJournalSetupJobManifest
        let jobs: ProtectedSetupDirectory
        init() throws {
            fixture = try .init()
            configuration = try .init(intent: fixture.intent, bundlePath: fixture.runtime.plan.bundlePath, codePolicy: fixture.runtime.plan.host.codePolicy)
            job = try .init(configuration: configuration)
            jobs = try .init(anchor: fixture.root.path, relativePath: "Jobs", owner: getuid(), visibility: .sharedMetadata)
        }
        deinit { jobs.close() }
        func scope() throws -> GatewayJournalSetupRootScope {
            try .init(machine: fixture.runtime.machine, account: fixture.runtime.account, foreground: fixture.runtime.plan,
                inventory: XCTUnwrap(fixture.runtime.machine.inventory()), configuration: configuration, expected: fixture.state(),
                verifyHost: { [self] _ in
                    guard value.withLock({ !$0.invalidHost }) else { throw GatewayPreparationError.changedScope }
                })
        }
        func event(_ name: String) { value.withLock { $0.events.append(name) } }
        func publish(_ scope: GatewayJournalSetupRootScope, retained: Bool) throws {
            try scope.verifyPending()
            _ = try GatewayJournalSetupJobArtifacts.publish(configuration: configuration, service: fixture.parent, jobs: jobs,
                owner: getuid(), mode: retained ? .validateRetained : .preparePending, verifyCurrent: { try scope.verifyPending() })
        }
        func operations(_ scope: GatewayJournalSetupRootScope,
                        exchange: (@Sendable () async throws -> GatewayJournalSetupReport)? = nil) -> GatewayJournalSetupRootOperations {
            .init(inspectFiles: { [self] in
                event("inspect")
                guard value.withLock({ !$0.forbidJournal }) else { XCTFail("Completed retries must not inspect the journal"); throw Interrupted() }
                try scope.withCurrent { try fixture.validateFiles() }
            }, publish: { [self] in event("publish"); try publish(scope, retained: false) },
                verifyPublished: { [self] in event("validate artifacts"); try publish(scope, retained: true) },
                register: { [self] in
                    event("register")
                    try GatewayJournalSetupJobRegistration.reconcileRegistration(verifyCurrent: { try scope.verifyPending() },
                        inspect: { self.value.withLock { $0.job } }, bootstrap: { self.value.withLock { $0.job = .matchingStopped } })
                }, exchange: exchange ?? { [self] in
                    event("exchange"); value.withLock { $0.job = .matchingActive }
                    let driver = try GatewayJournalSetupExchangeTests.Driver(fixture: fixture, dropResponse: value.withLock { $0.dropReport })
                    let channel = try GatewayJournalSetupChannel(driver: driver, intentID: fixture.intent.id, scopeDigest: fixture.intent.digest,
                        verifyPending: { try self.publish(scope, retained: true) },
                        challenge: { AccountPreparationIntent.randomID() + AccountPreparationIntent.randomID() })
                    do {
                        let report = try await channel.prepare()
                        value.withLock { $0.created = report.created; $0.job = $0.keepActive ? .matchingActive : .matchingStopped; if $0.invalidateAfterReport { $0.invalidHost = true } }
                        return report
                    } catch { value.withLock { $0.job = $0.keepActive ? .matchingActive : .matchingStopped }; throw error }
                }, cleanup: { [self] in
                    event("cleanup")
                    return try scope.withCurrent {
                        try GatewayJournalSetupJobRegistration.reconcileCleanup(verifyCurrent: {
                            try scope.verifyCurrent()
                            if self.value.withLock({ $0.job != .absent }) {
                                try GatewayJournalSetupJobArtifacts.validateRetainedJob(self.job, jobs: self.jobs, owner: getuid(), verifyCurrent: { try scope.verifyCurrent() })
                            }
                        }, inspect: { self.value.withLock { $0.job } }, bootout: { self.value.withLock { $0.job = .absent } })
                    }
                }, remove: { [self] in
                    event("remove")
                    _ = try scope.withCurrent {
                        try GatewayJournalSetupJobArtifacts.removeJobFile(job: job, jobs: jobs, owner: getuid(),
                            jobIsAbsent: { self.value.withLock { $0.job == .absent } }, verifyCurrent: { try scope.verifyCurrent() })
                    }
                })
        }
    }
    private actor Gate {
        private var continuation: CheckedContinuation<Void, Never>?
        private var released = false
        private(set) var entered = false
        func wait(started: XCTestExpectation) async {
            entered = true; started.fulfill()
            guard !released else { return }
            await withCheckedContinuation { continuation = $0 }
        }
        func release() { released = true; continuation?.resume(); continuation = nil }
    }
    private static let exchangeReadinessSeconds: TimeInterval = 10
    func testOwnedOperationCompletesTheJournalAndRemovesOnlyItsStoppedJob() async throws {
        let h = try Harness(), scope = try h.scope(), inventory = try h.fixture.runtime.machine.inventory()
        let result = try await GatewayJournalSetupRootOperation.resume(scope: scope, operations: h.operations(scope))
        XCTAssertTrue(result.state.initialized); XCTAssertTrue(result.cleanupComplete)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: h.jobs.path), [])
        XCTAssertTrue(FileManager.default.fileExists(atPath: h.fixture.parent.path + "/" + GatewayJournalSetupServiceConfiguration.fileName))
        XCTAssertEqual(try h.fixture.runtime.machine.inventory(), inventory)
        XCTAssertThrowsError(try scope.verifyCurrent()) { XCTAssertEqual($0 as? GatewayPreparationError, .incomplete) }
    }
    func testCompletedRetryOnlyCleansAndDoesNotAcquireTheActiveJournalWriter() async throws {
        let h = try Harness(); var scope = try h.scope()
        _ = try await GatewayJournalSetupRootOperation.resume(scope: scope, operations: h.operations(scope))
        let writer = try ProtectedGatewayLease(anchor: h.fixture.root.path, relativeDirectory: "Service/Gateway", serviceUID: getuid(), ancestorUID: getuid())
        defer { writer.close() }
        h.value.withLock { $0.forbidJournal = true; $0.events = [] }; scope = try h.scope()
        let result = try await GatewayJournalSetupRootOperation.resume(scope: scope, operations: h.operations(scope))
        XCTAssertTrue(result.state.initialized); XCTAssertTrue(result.cleanupComplete)
        XCTAssertEqual(h.value.withLock { $0.events }, ["cleanup", "remove"])
    }
    func testLostReportRestoresTheSameJournalOnTheNextPendingAttempt() async throws {
        let h = try Harness(); h.value.withLock { $0.dropReport = true }; var scope = try h.scope()
        do { _ = try await GatewayJournalSetupRootOperation.resume(scope: scope, operations: h.operations(scope)); XCTFail() } catch {}
        XCTAssertFalse(try h.fixture.state().initialized)
        h.value.withLock { $0.dropReport = false }; scope = try h.scope()
        let result = try await GatewayJournalSetupRootOperation.resume(scope: scope, operations: h.operations(scope))
        XCTAssertTrue(result.state.initialized); XCTAssertEqual(h.value.withLock { $0.created }, false)
        try h.fixture.validateFiles()
    }
    func testInterruptedStagesResumeWithoutRepeatingCompletedInitialization() async throws {
        for stop in [GatewayJournalSetupRootOperation.Stage.verified, .filesInspected, .artifactsPublished, .jobRegistered, .reportReceived, .completionRetained, .cleaned] {
            let h = try Harness(); var scope = try h.scope()
            do {
                _ = try await GatewayJournalSetupRootOperation.resume(scope: scope, operations: h.operations(scope), didStage: { if $0 == stop { throw Interrupted() } })
                XCTFail()
            } catch { XCTAssertTrue(error is Interrupted) }
            let completed = try h.fixture.state().initialized
            h.value.withLock { $0.forbidJournal = completed; $0.events = [] }; scope = try h.scope()
            let result = try await GatewayJournalSetupRootOperation.resume(scope: scope, operations: h.operations(scope))
            XCTAssertTrue(result.state.initialized); XCTAssertTrue(result.cleanupComplete)
            if completed { XCTAssertEqual(h.value.withLock { $0.events }, ["cleanup", "remove"]) }
        }
    }
    func testActiveCleanupReturnsPendingAndLaterRetryDoesNotReinitialize() async throws {
        let h = try Harness(); h.value.withLock { $0.keepActive = true }; var scope = try h.scope()
        let first = try await GatewayJournalSetupRootOperation.resume(scope: scope, operations: h.operations(scope))
        XCTAssertTrue(first.state.initialized); XCTAssertFalse(first.cleanupComplete)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: h.jobs.path), [h.job.label + ".plist"])
        h.value.withLock { $0.keepActive = false; $0.job = .matchingStopped; $0.forbidJournal = true; $0.events = [] }; scope = try h.scope()
        let next = try await GatewayJournalSetupRootOperation.resume(scope: scope, operations: h.operations(scope))
        XCTAssertTrue(next.cleanupComplete); XCTAssertEqual(h.value.withLock { $0.events }, ["cleanup", "remove"])
    }
    func testChangedHostAfterReportPreventsCompletionAndCleanupMutation() async throws {
        let h = try Harness(); h.value.withLock { $0.invalidateAfterReport = true }; var scope = try h.scope()
        do { _ = try await GatewayJournalSetupRootOperation.resume(scope: scope, operations: h.operations(scope)); XCTFail() }
        catch { XCTAssertEqual(error as? GatewayPreparationError, .changedScope) }
        XCTAssertFalse(try h.fixture.state().initialized)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: h.jobs.path), [h.job.label + ".plist"])
        h.value.withLock { $0.invalidHost = false; $0.invalidateAfterReport = false }; scope = try h.scope()
        let result = try await GatewayJournalSetupRootOperation.resume(scope: scope, operations: h.operations(scope))
        XCTAssertTrue(result.state.initialized); XCTAssertEqual(h.value.withLock { $0.created }, false)
    }
    func testCancellationRetainsTheMachineScopeUntilTheExchangeActuallySettles() async throws {
        try await cancellationAtHeldExchange(preparationDelay: 0)
    }
    func testSlowPreparationStillChecksCancellationAtTheHeldExchange() async throws {
        try await cancellationAtHeldExchange(preparationDelay: 2.2)
    }
    private func cancellationAtHeldExchange(preparationDelay: TimeInterval) async throws {
        let h = try Harness(), scope = try h.scope(), gate = Gate(), started = expectation(description: "exchange entered")
        let operations = h.operations(scope, exchange: {
            h.value.withLock { $0.job = .matchingActive }
            await gate.wait(started: started)
            h.value.withLock { $0.job = .matchingStopped }
            try Task.checkCancellation(); throw Interrupted()
        })
        let beginning = ContinuousClock.now, phases = Mutex<[(String, Int64)]>([]), delayed = Mutex(false)
        let task = Task {
            try await GatewayJournalSetupRootOperation.resume(scope: scope, operations: operations, didStage: { stage in
                if stage == .verified, preparationDelay > 0 {
                    delayed.withLock { $0 = true }; Thread.sleep(forTimeInterval: preparationDelay)
                }
                let elapsed = beginning.duration(to: ContinuousClock.now).components
                let milliseconds = elapsed.seconds * 1000 + elapsed.attoseconds / 1_000_000_000_000_000
                phases.withLock { if $0.count < 16 { $0.append((String(describing: stage), milliseconds)) } }
            })
        }
        await fulfillment(of: [started], timeout: Self.exchangeReadinessSeconds)
        let entered = await gate.entered
        task.cancel()
        guard entered else {
            XCTFail("Exchange readiness phases in milliseconds: \(phases.withLock { $0 })")
            await gate.release(); _ = await task.result; return
        }
        print("Root cancellation fixture phases in milliseconds: \(phases.withLock { $0 })")
        XCTAssertEqual(delayed.withLock { $0 }, preparationDelay > 0)
        XCTAssertNoThrow(try scope.verifyPending())
        await gate.release()
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertThrowsError(try scope.verifyCurrent()) { XCTAssertEqual($0 as? GatewayPreparationError, .incomplete) }
        XCTAssertFalse(try h.fixture.state().initialized)
    }
    func testEarlyGateReleaseDoesNotStrandTheRootOperation() async throws {
        let h = try Harness(), scope = try h.scope(), gate = Gate()
        let started = expectation(description: "exchange entered"), finished = expectation(description: "operation settled")
        await gate.release()
        let task = Task {
            defer { finished.fulfill() }
            return try await GatewayJournalSetupRootOperation.resume(scope: scope, operations: h.operations(scope, exchange: {
                h.value.withLock { $0.job = .matchingActive }
                await gate.wait(started: started)
                h.value.withLock { $0.job = .matchingStopped }; throw Interrupted()
            }))
        }
        await fulfillment(of: [started, finished], timeout: Self.exchangeReadinessSeconds)
        await gate.release()
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is Interrupted) }
        XCTAssertFalse(try h.fixture.state().initialized)
    }
    func testOrdinaryIdentityCannotOpenTheNativeRootOperation() async throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner Root entry refusal") }
        let path = "/private/tmp/remozio-root-scope-" + UUID().uuidString
        do {
            _ = try await GatewayJournalSetupRootOperation.resumeNative(machineDirectory: path, macID: Data(repeating: 1, count: 16),
                ownerUID: getuid(), expectedIntentDigest: Data(repeating: 2, count: 32), verifyHost: { _ in XCTFail("Native guard must run first") })
            XCTFail()
        } catch { XCTAssertEqual(error as? JournalLeaseError, .rootRequired) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    }
}
