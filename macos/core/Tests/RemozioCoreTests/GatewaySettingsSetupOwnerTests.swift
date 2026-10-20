import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewaySettingsSetupOwnerTests: XCTestCase, @unchecked Sendable {
    private struct Interrupted: Error {}
    actor Gate {
        private var continuation: CheckedContinuation<Void, Never>?
        func wait(_ started: XCTestExpectation) async {
            await withCheckedContinuation { continuation = $0; started.fulfill() }
        }
        func release() { continuation?.resume(); continuation = nil }
    }
    final class Backend: @unchecked Sendable {
        struct State {
            var entered = 0
            var loseReply = false
            var wrongDigest = false
            var gate: Gate?
            var started: XCTestExpectation?
        }
        let state = Mutex(State())
        let ready: GatewayRuntimeSettingsStoreTests.Ready
        init(_ ready: GatewayRuntimeSettingsStoreTests.Ready) { self.ready = ready }
        var operation: GatewaySetupSettingsOperations {
            .init(resume: { [self] uid, expected, revision, verify in
                let first = try ready.fixture.runtime.f.open()
                try verify(XCTUnwrap(first.inventory()))
                _ = try GatewaySettingsTransitionSnapshot.load(machine: first, ownerUID: uid, expected: expected, revision: revision)
                try first.close()
                let current = state.withLock { $0.entered += 1; return $0 }
                if let gate = current.gate, let started = current.started { await gate.wait(started) }
                try Task.checkCancellation()
                // This owned backend proves admission and writer lifetime. It makes no native barrier claim.
                let machine = try ready.fixture.runtime.f.open(); defer { try? machine.close() }
                try verify(XCTUnwrap(machine.inventory()))
                for phase in GatewayRuntimeSettingsPhase.allCases.dropFirst() {
                    try machine.markGatewaySettingsTransition(revision, phase: phase)
                }
                try machine.completeGatewaySettingsTransition(revision)
                if current.loseReply { throw Interrupted() }
                return try .init(revisionDigest: current.wrongDigest ? Data(repeating: 99, count: 32) : revision.digest)
            })
        }
    }
    final class Harness: @unchecked Sendable {
        let ready: GatewayRuntimeSettingsStoreTests.Ready
        let activity: ReleaseActivityFixture
        let backend: Backend
        let owner: SetupAccountOwner
        let selection: GatewayRuntimeSettingsSelection
        init(native: Bool = true) throws {
            ready = try .init(nativeConsumerHosts: native)
            selection = try ready.revision().selection
            try ready.fixture.runtime.machine.close()
            let backend = Backend(ready); self.backend = backend
            activity = try .init()
            let f = ready.fixture.runtime.f, identity = f.identity
            owner = try .init(openMachine: { try f.open() }, expectedReleaseDigest: f.release,
                resume: { _, _ in throw Interrupted() }, accountCodePolicy: f.policy,
                lookupAccount: { uid in guard uid == identity.uid else { throw AdministrativeSetupError.wrongAccount }; return identity },
                releaseActivity: activity.open(), gatewaySettingsOperation: backend.operation)
        }
        deinit { try? owner.close() }
        func read() throws -> SetupGatewaySettingsProgress { try XCTUnwrap(owner.gatewaySettingsProgress(callerUID: getuid())) }
        func retain() throws -> SetupGatewaySettingsProgress {
            try owner.retainGatewaySettings(callerUID: getuid(), expected: read(), selection: selection)
        }
        func hold(_ gate: Gate, _ started: XCTestExpectation) { backend.state.withLock { $0.gate = gate; $0.started = started } }
    }
    func testLegacyAccountReadsItsSettingsWithoutClaimingLiveMutationSupport() throws {
        let h = try Harness(native: false), before = try h.read()
        XCTAssertFalse(before.supportsSettingsChanges)
        XCTAssertEqual(try SetupGatewaySettingsProgress.decode(before.bytes), before)
        XCTAssertThrowsError(try h.owner.retainGatewaySettings(callerUID: getuid(), expected: before, selection: h.selection)) {
            XCTAssertEqual($0 as? GatewayPreparationError, .incomplete)
        }
        XCTAssertEqual(try h.read(), before)
        XCTAssertEqual(h.backend.state.withLock { $0.entered }, 0)
        XCTAssertEqual(try h.ready.fixture.runtime.f.sql("PRAGMA user_version"), 10)
    }
    func testReadDoesNotMigrateAndExplicitRetentionDoesNotEnterTheBackend() throws {
        let h = try Harness(), before = try h.read()
        XCTAssertNil(try before.pendingDigest); XCTAssertNil(try before.activeDigest)
        XCTAssertEqual(try h.ready.fixture.runtime.f.sql("PRAGMA user_version"), 10)
        let pending = try h.retain()
        XCTAssertEqual(pending.stage, .retained); XCTAssertNotNil(try pending.pendingDigest)
        XCTAssertEqual(try pending.pendingSelection?.bytes, try h.selection.bytes)
        XCTAssertEqual(h.backend.state.withLock { $0.entered }, 0)
        XCTAssertThrowsError(try h.owner.retainGatewaySettings(callerUID: getuid(), expected: before, selection: h.selection))
        XCTAssertThrowsError(try h.owner.retainGatewaySettings(callerUID: getuid(), expected: pending, selection: h.selection))
        XCTAssertEqual(try h.read(), pending)
    }
    func testFreshCompletionMatchesTheExactRetainedRevisionAndClosesEachWriter() async throws {
        let h = try Harness(), pending = try h.retain()
        let result = try await h.owner.resumeGatewaySettings(callerUID: getuid(), expected: pending)
        XCTAssertEqual(try result.activeDigest, try pending.pendingDigest); XCTAssertNil(result.stage)
        XCTAssertNil(try result.pendingDigest); XCTAssertEqual(result.activation, pending.activation)
        XCTAssertEqual(try h.read(), result)
        let reopened = try h.ready.fixture.runtime.f.open(); try reopened.close()
    }
    func testWrongCallerAndAStaleRevisionCannotEnterTheBackend() async throws {
        let h = try Harness(), empty = try h.read(), pending = try h.retain()
        for (uid, expected) in [(getuid() + 1, pending), (getuid(), empty)] {
            do { _ = try await h.owner.resumeGatewaySettings(callerUID: uid, expected: expected); XCTFail() } catch {}
        }
        XCTAssertEqual(h.backend.state.withLock { $0.entered }, 0)
        XCTAssertThrowsError(try h.owner.retainGatewaySettings(callerUID: getuid() + 1, expected: pending, selection: h.selection))
        XCTAssertEqual(try h.read(), pending)
    }
    func testLostOrMisboundReportCannotReturnSuccessAfterAStoreCommit() async throws {
        for lose in [false, true] {
            let h = try Harness(), pending = try h.retain()
            h.backend.state.withLock { $0.loseReply = lose; $0.wrongDigest = !lose }
            do { _ = try await h.owner.resumeGatewaySettings(callerUID: getuid(), expected: pending); XCTFail() }
            catch { if lose { XCTAssertTrue(error is Interrupted) } else { XCTAssertEqual(error as? AdministrativeSetupError, .staleProgress) } }
            XCTAssertEqual(try h.read().activeDigest, try pending.pendingDigest)
        }
    }
    func testCancellationKeepsTheActivityUntilTheAdmittedBackendSettles() async throws {
        let h = try Harness(), pending = try h.retain(), gate = Gate(), started = expectation(description: "settings backend entered")
        h.hold(gate, started); let installer = try h.activity.open()
        let task = Task { try await h.owner.resumeGatewaySettings(callerUID: getuid(), expected: pending) }
        await fulfillment(of: [started], timeout: 5); task.cancel()
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        let writer = try h.ready.fixture.runtime.f.open(); try writer.close()
        await gate.release()
        do { _ = try await task.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(try h.read(), pending)
        let update = try installer.acquireExclusive(); update.close()
    }
    func testAnAdmittedTransitionBlocksRetentionAndOtherSetupMutationsUntilShutdownJoins() async throws {
        let h = try Harness(), pending = try h.retain(), gate = Gate(), started = expectation(description: "settings backend entered")
        h.hold(gate, started)
        let task = Task { try await h.owner.resumeGatewaySettings(callerUID: getuid(), expected: pending) }
        await fulfillment(of: [started], timeout: 5)
        XCTAssertThrowsError(try h.owner.retainGatewaySettings(callerUID: getuid(), expected: pending, selection: h.selection))
        do { _ = try await h.owner.resumeGatewaySettings(callerUID: getuid(), expected: pending); XCTFail() } catch {}
        do { _ = try await h.owner.resumeGatewayActivation(callerUID: getuid(), expected: pending.activation, settings: h.selection.activation); XCTFail() } catch {}
        let closing = Task { try await h.owner.closeWhenIdle() }
        await Task.yield(); XCTAssertThrowsError(try h.owner.close())
        await gate.release()
        do { _ = try await task.value } catch { XCTAssertEqual(error as? AdministrativeSetupError, .unavailable) }
        try await closing.value
        let installer = try h.activity.open(), update = try installer.acquireExclusive(); update.close()
        XCTAssertEqual(h.backend.state.withLock { $0.entered }, 1)
    }
    func testProgressRoundTripsPendingAndCompleteWithoutClaimingLiveHealth() async throws {
        let h = try Harness()
        for progress in [try h.read(), try h.retain()] {
            XCTAssertEqual(try SetupGatewaySettingsProgress.decode(progress.bytes), progress)
        }
        let done = try await h.owner.resumeGatewaySettings(callerUID: getuid(), expected: h.read())
        XCTAssertEqual(try SetupGatewaySettingsProgress.decode(done.bytes), done)
        XCTAssertThrowsError(try SetupGatewaySettingsProgress.decode(Data()))
        XCTAssertThrowsError(try SetupGatewaySettingsProgress.decode(Data(repeating: 0, count: SetupGatewaySettingsProgress.maximumByteCount + 1)))
    }
}
