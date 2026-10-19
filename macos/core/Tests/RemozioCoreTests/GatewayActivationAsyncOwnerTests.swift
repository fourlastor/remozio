import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewayActivationAsyncOwnerTests: XCTestCase {
    private struct Interrupted: Error {}
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
            var journalEntered = 0
            var gate: Gate?
            var started: XCTestExpectation?
            var loseReply = false
            var wrongDigest = false
        }
        let state = Mutex(State())
        let fixture: GatewayJournalSetupExchangeTests.Fixture
        init(_ fixture: GatewayJournalSetupExchangeTests.Fixture) { self.fixture = fixture }
        var operation: GatewaySetupActivationOperations {
            .init(resume: { [self] uid, expected, settings, verify in
                let machine = try fixture.runtime.f.open()
                try verify(XCTUnwrap(machine.inventory())); try machine.close()
                let snapshot = state.withLock { $0.entered += 1; return $0 }
                if let gate = snapshot.gate, let started = snapshot.started { await gate.wait(started) }
                let identity = fixture.runtime.f.identity
                let operations = GatewayRuntimeActivationOperations(verifyInitializerAbsent: { _, checked in
                    try checked(); let writer = try self.fixture.runtime.f.open(); try writer.close(); try checked()
                }, prepare: { _, _, checked in try checked() }, validate: { _, checked in try checked() },
                    register: { _, checked in try checked(); let writer = try self.fixture.runtime.f.open(); try writer.close(); try checked() })
                let result = try GatewayRuntimeActivationRootOperation.resume(ownerUID: uid, expected: expected, settings: settings,
                    openMachine: { try self.fixture.runtime.f.open() }, verifyHost: verify,
                    lookupAccount: { _ in identity }, operations: operations)
                if snapshot.loseReply { throw Interrupted() }
                return .init(planDigest: snapshot.wrongDigest ? Data(repeating: 99, count: 32) : try XCTUnwrap(result.planDigest))
            })
        }
        var journalOperation: GatewaySetupJournalOperations {
            .init(resume: { [self] _, digest, verify in
                let machine = try fixture.runtime.f.open(); try verify(XCTUnwrap(machine.inventory())); try machine.close()
                let snapshot = state.withLock { $0.journalEntered += 1; return $0 }
                if let gate = snapshot.gate, let started = snapshot.started { await gate.wait(started) }
                return .init(intentDigest: digest, cleanupComplete: true)
            })
        }
    }
    final class Harness: @unchecked Sendable {
        let fixture: GatewayJournalSetupExchangeTests.Fixture
        let activity: ReleaseActivityFixture
        let backend: Backend
        let owner: SetupAccountOwner
        let settings = try! GatewayRuntimeActivationSettings(wakePollMilliseconds: 2000, wakeTimeoutMilliseconds: 6000)
        init(hasBackend: Bool = true) throws {
            let f = try GatewayJournalSetupExchangeTests.Fixture(); fixture = f
            try f.retainCompletion(.decode(f.initialize())); try f.runtime.machine.close()
            let a = try ReleaseActivityFixture(); activity = a
            let backend = Backend(f); self.backend = backend; let identity = f.runtime.f.identity
            owner = try .init(openMachine: { try f.runtime.f.open() }, expectedReleaseDigest: f.runtime.f.release,
                resume: { _, _ in throw Interrupted() }, accountCodePolicy: f.runtime.f.policy,
                lookupAccount: { uid in guard uid == identity.uid else { throw AdministrativeSetupError.wrongAccount }; return identity },
                releaseActivity: a.open(), gatewayJournalOperation: backend.journalOperation,
                gatewayActivationOperation: hasBackend ? backend.operation : nil)
        }
        deinit { try? owner.close() }
        func read() throws -> SetupGatewayActivationProgress { try XCTUnwrap(owner.gatewayActivationProgress(callerUID: getuid())) }
        func hold(_ gate: Gate, _ started: XCTestExpectation) { backend.state.withLock { $0.gate = gate; $0.started = started } }
    }
    func testBackendStartsWithoutAPriorWriterAndOwnerReturnsFreshCommittedProgress() async throws {
        let h = try Harness(), expected = try h.read()
        let result = try await h.owner.resumeGatewayActivation(callerUID: getuid(), expected: expected, settings: h.settings)
        XCTAssertTrue(result.jobRegistered); XCTAssertTrue(result.filesPublished); XCTAssertEqual(result.settings, h.settings)
        XCTAssertEqual(try h.read(), result); XCTAssertEqual(h.backend.state.withLock { $0.entered }, 1)
        let machine = try h.fixture.runtime.f.open(); try machine.close()
    }
    func testWrongCallerAndStaleProgressCannotEnterTheBackend() async throws {
        let h = try Harness(), expected = try h.read()
        do { _ = try await h.owner.resumeGatewayActivation(callerUID: getuid() + 1, expected: expected, settings: h.settings); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .wrongAccount) }
        _ = try await h.owner.resumeGatewayActivation(callerUID: getuid(), expected: expected, settings: h.settings)
        do { _ = try await h.owner.resumeGatewayActivation(callerUID: getuid(), expected: expected, settings: h.settings); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) }
        XCTAssertEqual(h.backend.state.withLock { $0.entered }, 1)
    }
    func testLostOrMisboundReportCannotReturnSuccessEvenWhenTheStoreCommitted() async throws {
        for lose in [false, true] {
            let h = try Harness(), expected = try h.read()
            h.backend.state.withLock { $0.loseReply = lose; $0.wrongDigest = !lose }
            do { _ = try await h.owner.resumeGatewayActivation(callerUID: getuid(), expected: expected, settings: h.settings); XCTFail() }
            catch { if lose { XCTAssertTrue(error is Interrupted) } else { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) } }
            XCTAssertTrue(try h.read().jobRegistered)
        }
    }
    func testCancellationKeepsTheReleaseTokenUntilTheBackendSettles() async throws {
        let h = try Harness(), expected = try h.read(), gate = Gate(), started = expectation(description: "activation entered")
        h.hold(gate, started); let installer = try h.activity.open()
        let task = Task { try await h.owner.resumeGatewayActivation(callerUID: getuid(), expected: expected, settings: h.settings) }
        await fulfillment(of: [started], timeout: 5); task.cancel()
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        let writer = try h.fixture.runtime.f.open(); try writer.close()
        await gate.release()
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertFalse(try h.read().jobRegistered)
        let update = try installer.acquireExclusive(); update.close()
    }
    func testJournalSetupAndActivationCannotOverlapInEitherOrder() async throws {
        for journalFirst in [false, true] {
            let h = try Harness(), expected = try h.read(), gate = Gate(), started = expectation(description: "first operation entered")
            h.hold(gate, started)
            let first = Task {
                if journalFirst { _ = try await h.owner.resumeGatewayJournal(callerUID: getuid(), expected: expected.setup) }
                else { _ = try await h.owner.resumeGatewayActivation(callerUID: getuid(), expected: expected, settings: h.settings) }
            }
            await fulfillment(of: [started], timeout: 5)
            do {
                if journalFirst { _ = try await h.owner.resumeGatewayActivation(callerUID: getuid(), expected: expected, settings: h.settings) }
                else { _ = try await h.owner.resumeGatewayJournal(callerUID: getuid(), expected: expected.setup) }
                XCTFail()
            } catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
            XCTAssertEqual(h.backend.state.withLock { $0.entered + $0.journalEntered }, 1)
            await gate.release(); try await first.value
        }
    }
    func testShutdownKeepsPlacementUntilTheAdmittedActivationActuallySettles() async throws {
        let h = try Harness(), expected = try h.read(), gate = Gate(), started = expectation(description: "activation entered")
        h.hold(gate, started); let installer = try h.activity.open()
        let placement = try ReleaseDestinationLease(anchor: h.activity.root.path, relativeDirectory: "Machine", owner: getuid())
        let shutdown = AdministrativeSetupShutdown(owner: h.owner, placement: placement)
        let task = Task { try await h.owner.resumeGatewayActivation(callerUID: getuid(), expected: expected, settings: h.settings) }
        await fulfillment(of: [started], timeout: 5)
        XCTAssertThrowsError(try h.owner.close()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
        let closed = Mutex(false)
        let closing = Task { try await shutdown.close(); closed.withLock { $0 = true } }; closing.cancel(); await Task.yield()
        XCTAssertFalse(closed.withLock { $0 }); XCTAssertNoThrow(try placement.validate())
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        await gate.release(); _ = try? await task.value; try await closing.value
        XCTAssertTrue(closed.withLock { $0 }); XCTAssertThrowsError(try placement.validate())
        let update = try installer.acquireExclusive(); update.close()
    }
    func testRetainedSettingsCannotChangeBeforeTheBackendRunsAgain() async throws {
        let h = try Harness(), expected = try h.read()
        let done = try await h.owner.resumeGatewayActivation(callerUID: getuid(), expected: expected, settings: h.settings)
        let different = try GatewayRuntimeActivationSettings(wakePollMilliseconds: 3000)
        do { _ = try await h.owner.resumeGatewayActivation(callerUID: getuid(), expected: done, settings: different); XCTFail() }
        catch { XCTAssertEqual(error as? GatewayPreparationError, .conflictingMaterial) }
        XCTAssertEqual(h.backend.state.withLock { $0.entered }, 1); XCTAssertEqual(try h.read(), done)
    }
    func testMissingBackendDoesNotDisableForegroundProgressOrClaimActivation() async throws {
        let h = try Harness(hasBackend: false), expected = try h.read()
        XCTAssertTrue(expected.setup.journalInitialized); XCTAssertFalse(expected.jobRegistered)
        do { _ = try await h.owner.resumeGatewayActivation(callerUID: getuid(), expected: expected, settings: h.settings); XCTFail() }
        catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
        XCTAssertEqual(try h.read(), expected); XCTAssertNotNil(try h.owner.activationProgress(callerUID: getuid()))
    }
    func testActivationReservationBlocksOrdinaryMachineOperationsUntilCancelledWorkSettles() async throws {
        let h = try Harness(), uid = getuid(), expected = try h.read()
        let foreground = try XCTUnwrap(h.owner.activationProgress(callerUID: uid))
        let gate = Gate(), started = expectation(description: "activation released its first writer")
        h.hold(gate, started)
        let task = Task { try await h.owner.resumeGatewayActivation(callerUID: uid, expected: expected, settings: h.settings) }
        defer { Task { await gate.release() } }
        await fulfillment(of: [started], timeout: 5)
        let competing: [() throws -> Void] = [
            { try h.owner.verifyCurrent() },
            { _ = try h.owner.gatewayProgress(callerUID: uid) },
            { _ = try h.owner.gatewayActivationProgress(callerUID: uid) },
            { _ = try h.owner.activationProgress(callerUID: uid) },
            { _ = try h.owner.enrollment(callerUID: uid) },
            { _ = try h.owner.resumeActivation(callerUID: uid, expected: foreground) },
            { _ = try h.owner.prepareGateway(callerUID: uid, expected: expected.setup, prepare: { _, _, _ in
                XCTFail("Competing setup reached its mutation"); throw Interrupted()
            }) }
        ]
        for cancelled in [false, true] {
            if cancelled { task.cancel() }
            let writer = try h.fixture.runtime.f.open(); try writer.close()
            for operation in competing {
                XCTAssertThrowsError(try operation()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
            }
        }
        await gate.release()
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertFalse(try h.read().jobRegistered)
        XCTAssertNotNil(try h.owner.activationProgress(callerUID: uid))
    }

}
