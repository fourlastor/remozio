import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySetupAsyncOwnerTests: XCTestCase, @unchecked Sendable {
    private struct Interrupted: Error {}
    final class Counter: Sendable { let value = Mutex(0) }
    actor Gate {
        private var continuation: CheckedContinuation<Void, Never>?
        func wait(_ started: XCTestExpectation) async {
            await withCheckedContinuation { continuation in self.continuation = continuation; started.fulfill() }
        }
        func release() { continuation?.resume(); continuation = nil }
    }
    final class Backend: @unchecked Sendable {
        struct State {
            var entered = 0
            var beforeOpenGate: Gate?
            var beforeOpenStarted: XCTestExpectation?
            var gate: Gate?
            var started: XCTestExpectation?
            var checkCancellation = false
            var loseReply = false
            var wrongDigest = false
            var cleanupComplete = true
        }
        let state = Mutex(State())
        let fixture: GatewayJournalSetupExchangeTests.Fixture
        init(_ fixture: GatewayJournalSetupExchangeTests.Fixture) { self.fixture = fixture }
        var operation: GatewaySetupJournalOperations {
            .init(resume: { [self] uid, digest, verify in
                let opening = state.withLock { $0 }
                if let gate = opening.beforeOpenGate, let started = opening.beforeOpenStarted { await gate.wait(started) }
                let machine = try fixture.runtime.f.open()
                defer { try? machine.close() }
                let current = try machine.gatewayJournalPreparation(accountID: fixture.intent.accountID)
                guard uid == fixture.runtime.account.ownerUID, try current.intent?.digest == digest else {
                    throw AdministrativeSetupError.staleProgress
                }
                try verify(XCTUnwrap(machine.inventory()))
                let snapshot = state.withLock { $0.entered += 1; return $0 }
                XCTAssertThrowsError(try fixture.runtime.f.open()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
                if let gate = snapshot.gate, let started = snapshot.started { await gate.wait(started) }
                try verify(XCTUnwrap(machine.inventory()))
                if snapshot.checkCancellation { try Task.checkCancellation() }
                // The owned service journal was initialized before the owner released its first machine writer.
                // This injected backend proves owner lifetime and recovery, not native report authentication.
                _ = try machine.completeGatewayJournalInitialization(fixture.intent,
                    head: .init(registration: fixture.intent.configuration.registration, revision: 0, receipt: nil))
                if snapshot.loseReply { throw Interrupted() }
                return .init(intentDigest: snapshot.wrongDigest ? Data(repeating: 99, count: 32) : digest, cleanupComplete: snapshot.cleanupComplete)
            })
        }
    }
    final class Harness: @unchecked Sendable {
        let fixture: GatewayJournalSetupExchangeTests.Fixture
        let activity: ReleaseActivityFixture
        let backend: Backend
        let owner: SetupAccountOwner
        let machineOpens: Counter
        init() throws {
            let f = try GatewayJournalSetupExchangeTests.Fixture(); fixture = f
            _ = try f.initialize(); try f.runtime.machine.close()
            let a = try ReleaseActivityFixture(); activity = a
            let backend = Backend(f); self.backend = backend
            let identity = f.runtime.f.identity, opens = Counter(); machineOpens = opens
            owner = try .init(openMachine: { opens.value.withLock { $0 += 1 }; return try f.runtime.f.open() }, expectedReleaseDigest: f.runtime.f.release,
                resume: { _, _ in throw Interrupted() }, accountCodePolicy: f.runtime.f.policy,
                lookupAccount: { uid in guard uid == identity.uid else { throw AdministrativeSetupError.wrongAccount }; return identity },
                activationOperations: .init(prepare: { _, _, _, _, _ in throw Interrupted() },
                    validate: { _, _, _, _, _ in throw Interrupted() }, register: { _, _ in throw Interrupted() }, didStage: { _ in }),
                releaseActivity: a.open(), gatewayJournalOperation: backend.operation)
        }
        deinit { try? owner.close() }
        func read() throws -> SetupGatewayProgress { try XCTUnwrap(owner.gatewayProgress(callerUID: getuid())) }
        func hold(_ gate: Gate, _ started: XCTestExpectation) { backend.state.withLock { $0.gate = gate; $0.started = started } }
    }
    func testBackendReceivesNoPriorMachineWriterAndOwnerReadsCommittedCompletion() async throws {
        let h = try Harness(), expected = try h.read()
        let result = try await h.owner.resumeGatewayJournal(callerUID: getuid(), expected: expected)
        XCTAssertTrue(result.progress.journalInitialized); XCTAssertTrue(result.cleanupComplete)
        XCTAssertEqual(try h.read(), result.progress); XCTAssertEqual(h.backend.state.withLock { $0.entered }, 1)
        let machine = try h.fixture.runtime.f.open(); try machine.close()
    }
    func testWrongCallerAndStaleProgressCannotEnterTheAsyncBackend() async throws {
        let h = try Harness(), expected = try h.read()
        do { _ = try await h.owner.resumeGatewayJournal(callerUID: getuid() + 1, expected: expected); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .wrongAccount) }
        _ = try await h.owner.resumeGatewayJournal(callerUID: getuid(), expected: expected)
        do { _ = try await h.owner.resumeGatewayJournal(callerUID: getuid(), expected: expected); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
        XCTAssertEqual(h.backend.state.withLock { $0.entered }, 1)
    }
    func testLostOrMisboundReportRetainsCompletionButCannotReturnSuccess() async throws {
        for lose in [false,true] {
            let h = try Harness(), expected = try h.read()
            h.backend.state.withLock { $0.loseReply = lose; $0.wrongDigest = !lose }
            do { _ = try await h.owner.resumeGatewayJournal(callerUID: getuid(), expected: expected); XCTFail() }
            catch { if lose { XCTAssertTrue(error is Interrupted) } else { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) } }
            XCTAssertTrue(try h.read().journalInitialized)
        }
    }
    func testCancellationRetainsTheReleaseActivityUntilTheBackendActuallySettles() async throws {
        let h = try Harness(), expected = try h.read(), gate = Gate(), started = expectation(description: "backend entered")
        h.hold(gate, started); h.backend.state.withLock { $0.checkCancellation = true }
        let installer = try h.activity.open()
        let task = Task { try await h.owner.resumeGatewayJournal(callerUID: getuid(), expected: expected) }
        await fulfillment(of: [started], timeout: 5); task.cancel()
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        XCTAssertThrowsError(try h.fixture.runtime.f.open()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        await gate.release()
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertFalse(try h.read().journalInitialized)
        let update = try installer.acquireExclusive(); update.close()
    }
    func testSecondAsyncOperationCannotEnterWhileTheFirstOwnsTheMachine() async throws {
        let h = try Harness(), expected = try h.read(), gate = Gate(), started = expectation(description: "backend entered")
        h.hold(gate, started)
        let task = Task { try await h.owner.resumeGatewayJournal(callerUID: getuid(), expected: expected) }
        await fulfillment(of: [started], timeout: 5)
        do { _ = try await h.owner.resumeGatewayJournal(callerUID: getuid(), expected: expected); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
        XCTAssertEqual(h.backend.state.withLock { $0.entered }, 1)
        await gate.release(); _ = try await task.value
    }
    func testOnlyTheLiveReservationFromThisOwnerCanEnterItsMachinePhases() throws {
        let owner = SetupOwnerAsyncWork(), other = SetupOwnerAsyncWork()
        XCTAssertTrue(owner.permits(nil))
        let token = try owner.admit(), foreign = try other.admit()
        XCTAssertFalse(owner.permits(nil)); XCTAssertTrue(owner.permits(token)); XCTAssertFalse(owner.permits(foreign))
        owner.closeAdmission()
        XCTAssertTrue(owner.permits(token)); XCTAssertThrowsError(try owner.admit())
        token.close(); XCTAssertFalse(owner.permits(token)); XCTAssertTrue(owner.permits(nil))
        foreign.close()
    }
    func testEveryCompetingMachineOperationIsExcludedAcrossTheAsyncWriterHandoff() async throws {
        let h = try Harness(), expected = try h.read(), activation = try XCTUnwrap(h.owner.activationProgress(callerUID: getuid()))
        let beforeOpen = Gate(), beforeStarted = expectation(description: "before backend opens writer")
        let active = Gate(), activeStarted = expectation(description: "backend owns writer")
        h.backend.state.withLock { $0.beforeOpenGate = beforeOpen; $0.beforeOpenStarted = beforeStarted }
        h.hold(active, activeStarted)
        let uid = getuid()
        let operation = Task { try await h.owner.resumeGatewayJournal(callerUID: uid, expected: expected) }
        defer { Task { await beforeOpen.release(); await active.release() } }
        let competitors: [() throws -> Void] = [
            { try h.owner.verifyCurrent() },
            { _ = try h.owner.gatewayProgress(callerUID: uid) },
            { _ = try h.owner.activationProgress(callerUID: uid) },
            { _ = try h.owner.enrollment(callerUID: uid) },
            { _ = try h.owner.resumeActivation(callerUID: uid, expected: activation) },
            { _ = try h.owner.prepareGateway(callerUID: uid, expected: expected, prepare: { _, _, _ in
                XCTFail("Competing mutation entered the writer"); throw Interrupted()
            }) }
        ]
        for entered in [beforeStarted, activeStarted] {
            await fulfillment(of: [entered], timeout: 5)
            let count = h.machineOpens.value.withLock { $0 }
            for competitor in competitors {
                XCTAssertThrowsError(try competitor()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
            }
            XCTAssertEqual(h.machineOpens.value.withLock { $0 }, count)
            if entered === beforeStarted { await beforeOpen.release() }
        }
        await active.release(); let completed = try await operation.value
        XCTAssertTrue(completed.progress.journalInitialized)
        XCTAssertEqual(try h.read(), completed.progress)
    }
    func testShutdownRetainsPlacementAndActivityUntilTheOperationSettlesEvenWhenCancelled() async throws {
        let h = try Harness(), expected = try h.read(), gate = Gate(), started = expectation(description: "backend entered")
        h.hold(gate, started)
        let placement = try ReleaseDestinationLease(anchor: h.activity.root.path, relativeDirectory: "Machine", owner: getuid())
        let shutdown = AdministrativeSetupShutdown(owner: h.owner, placement: placement), installer = try h.activity.open()
        let task = Task { try await h.owner.resumeGatewayJournal(callerUID: getuid(), expected: expected) }
        await fulfillment(of: [started], timeout: 5)
        // Synchronous close closes admission but must refuse to release active resources.
        XCTAssertThrowsError(try h.owner.close()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
        let closed = Mutex(false)
        let closing = Task { try await shutdown.close(); closed.withLock { $0 = true } }
        closing.cancel(); await Task.yield()
        XCTAssertFalse(closed.withLock { $0 }); XCTAssertNoThrow(try placement.validate())
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        XCTAssertThrowsError(try h.owner.gatewayProgress(callerUID: getuid()))
        await gate.release()
        do { _ = try await task.value; XCTFail() } catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
        try await closing.value
        XCTAssertTrue(closed.withLock { $0 }); XCTAssertThrowsError(try placement.validate())
        let update = try installer.acquireExclusive(); update.close()
        let machine = try h.fixture.runtime.f.open(); defer { try? machine.close() }
        XCTAssertTrue(try machine.gatewayJournalPreparation(accountID: h.fixture.intent.accountID).initialized)
    }
    func testCleanupPendingRemainsDistinctAndACompletedRetryLeavesTheJournalWriterAlone() async throws {
        let h = try Harness(), expected = try h.read()
        h.backend.state.withLock { $0.cleanupComplete = false }
        let pending = try await h.owner.resumeGatewayJournal(callerUID: getuid(), expected: expected)
        XCTAssertTrue(pending.progress.journalInitialized); XCTAssertFalse(pending.cleanupComplete)
        let lease = try ProtectedGatewayLease(anchor: h.fixture.root.path, relativeDirectory: "Service/Gateway", serviceUID: getuid(), ancestorUID: getuid())
        defer { lease.close() }
        h.backend.state.withLock { $0.cleanupComplete = true }
        let completed = try await h.owner.resumeGatewayJournal(callerUID: getuid(), expected: pending.progress)
        XCTAssertEqual(completed.progress, pending.progress); XCTAssertTrue(completed.cleanupComplete)
    }
    func testNativeFactoryRefusesOrdinaryIdentityBeforeOpeningAnyPath() async throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner native entry refusal") }
        let path = "/private/tmp/remozio-native-gateway-owner-" + UUID().uuidString
        let operation = GatewaySetupJournalOperations.native(machineDirectory: path, macID: Data(repeating: 1, count: 16))
        do { _ = try await operation.resume(getuid(), Data(repeating: 2, count: 32), { _ in XCTFail() }); XCTFail() }
        catch { XCTAssertEqual(error as? JournalLeaseError, .rootRequired) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    }
}
