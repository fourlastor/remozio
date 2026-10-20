import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityWakeRecoveryTests: XCTestCase, @unchecked Sendable {
    private struct Denied: Error {}
    private final class Counter: Sendable { let value = Mutex(0) }
    private typealias Fixture = AuthorityWakeSettingsTests.Fixture
    private typealias Driver = AuthorityWakeSettingsTests.Driver
    private func waitUntil(_ condition: () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !(await condition()) { guard ContinuousClock.now < deadline else { throw Denied() }; try await Task.sleep(for: .milliseconds(2)) }
    }
    func testCompletedStartupHoldKeepsForegroundAvailableAndRejectsOrdinaryMonitorInstallation() async throws {
        let f = try Fixture(install: false), driver = Driver(), service = try f.service([driver])
        let state = try f.state()
        try await service.restorePhonePushStartup(f.options, commitDigest: f.old, pendingChange: nil,
            requiresConsumerRecovery: true, verifyCurrent: {})
        let restoredStatus = await service.wakeStatus; XCTAssertEqual(restoredStatus, .suspendedForRecovery)
        try await service.start()
        XCTAssertEqual(f.starts.withLock { $0 }, 1); XCTAssertEqual(f.attempts.withLock { $0 }, 0)
        XCTAssertEqual(f.capability.retainedCommitDigest, f.old); XCTAssertNil(f.capability.publication)
        do { try await service.installPhonePush(f.options, commitDigest: f.old, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        XCTAssertThrowsError(try f.capability.install(f.options, commitDigest: f.old, verifyCurrent: { XCTFail() }))
        do { try await service.restorePhonePushStartup(f.options, commitDigest: f.old, pendingChange: nil,
            requiresConsumerRecovery: false, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        let ticket = try await service.quiescePhonePushRecovery(commitDigest: f.old, verifyCurrent: {})
        XCTAssertEqual(ticket.commitDigest, f.old)
        let resumed = try await service.resumePhonePushRecovery(ticket, verifyCurrent: {}); XCTAssertTrue(resumed)
        XCTAssertNil(f.capability.publication)
        try await service.installPhonePush(f.options, commitDigest: f.old, verifyCurrent: {})
        try await waitUntil { await service.wakeStatus == .running }
        XCTAssertNotNil(f.capability.publication); XCTAssertEqual(try f.state(), state)
        XCTAssertEqual(f.starts.withLock { $0 }, 1); XCTAssertEqual(f.closes.withLock { $0 }, 0)
        try await service.close(); XCTAssertThrowsError(try ticket.requireValid())
    }
    func testConcurrentRecoveryWaitersJoinActualPublisherCreationAndCancelledWaiterCannotAcknowledgeEarly() async throws {
        let f = try Fixture(), gate = DispatchSemaphore(value: 0), service = try f.service([Driver()], creationGate: gate)
        defer { gate.signal() }
        try await service.start(); try await waitUntil { f.attempts.withLock { $0 } == 1 }
        let finished = Counter()
        let first = Task { let ticket = try await service.quiescePhonePushRecovery(commitDigest: f.old, verifyCurrent: {}); finished.value.withLock { $0 += 1 }; return ticket }
        try await waitUntil { await service.wakeStatus == .quiescingForRecovery }
        let second = Task { let ticket = try await service.quiescePhonePushRecovery(commitDigest: f.old, verifyCurrent: {}); finished.value.withLock { $0 += 1 }; return ticket }
        first.cancel()
        XCTAssertNil(f.capability.publication); XCTAssertEqual(finished.value.withLock { $0 }, 0)
        XCTAssertEqual(f.closes.withLock { $0 }, 0)
        gate.signal()
        do { _ = try await first.value; XCTFail() } catch { XCTAssertTrue(error is CancellationError) }
        let ticket = try await second.value
        try ticket.requireValid(); XCTAssertEqual(finished.value.withLock { $0 }, 1)
        let status = await service.wakeStatus; XCTAssertEqual(status, .suspendedForRecovery)
        try await service.close()
    }
    func testSettingsTakeoverDuringRecoveryDrainCannotBeUndoneByTheOldWaiter() async throws {
        let f = try Fixture(), gate = DispatchSemaphore(value: 0), service = try f.service([Driver(), Driver()], creationGate: gate)
        defer { gate.signal(); gate.signal() }
        try await service.start(); try await waitUntil { f.attempts.withLock { $0 } == 1 }
        let recovery = Task { try await service.quiescePhonePushRecovery(commitDigest: f.old, verifyCurrent: {}) }
        try await waitUntil { await service.wakeStatus == .quiescingForRecovery }
        let change = try f.change(), settings = Task { try await service.quiescePhonePushSettings(change, verifyCurrent: {}) }
        try await waitUntil { await service.wakeStatus == .quiescingForSettings }
        gate.signal(); gate.signal()
        do { _ = try await recovery.value; XCTFail() } catch {}
        try await settings.value
        let accepted = try await service.acceptPhonePushSettings(change, verifyCurrent: {}); XCTAssertTrue(accepted)
        try await service.installPhonePush(f.options, commitDigest: f.selected, verifyCurrent: {})
        try await waitUntil { await service.wakeStatus == .running }
        XCTAssertEqual(f.capability.installedCommitDigest, f.selected); XCTAssertEqual(f.starts.withLock { $0 }, 1)
        try await service.close()
    }
    func testRevokedRecoveryTicketAndOldFloorCannotPauseOrResumeAnAcceptedSettingsSuccessor() async throws {
        let f = try Fixture(), service = try f.service([Driver(), Driver()])
        try await service.start(); try await waitUntil { await service.wakeStatus == .running }
        let ticket = try await service.quiescePhonePushRecovery(commitDigest: f.old, verifyCurrent: {})
        let change = try f.change()
        try await service.quiescePhonePushSettings(change, verifyCurrent: {})
        XCTAssertThrowsError(try ticket.requireValid())
        try await service.acceptPhonePushSettings(change, verifyCurrent: {})
        try await service.installPhonePush(f.options, commitDigest: f.selected, verifyCurrent: {})
        do { _ = try await service.resumePhonePushRecovery(ticket, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        do { _ = try await service.quiescePhonePushRecovery(commitDigest: f.old, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        XCTAssertEqual(f.capability.installedCommitDigest, f.selected); XCTAssertNotNil(f.capability.publication)
        try await service.close()
    }
    func testCloseOwnsAnUnsettledRecoveryDrainBeforeClosingTheForegroundJournal() async throws {
        let f = try Fixture(), gate = DispatchSemaphore(value: 0), service = try f.service([Driver()], creationGate: gate), completed = Mutex(false)
        defer { gate.signal() }
        try await service.start(); try await waitUntil { f.attempts.withLock { $0 } == 1 }
        let pause = Task { try await service.quiescePhonePushRecovery(commitDigest: f.old, verifyCurrent: {}) }
        try await waitUntil { await service.wakeStatus == .quiescingForRecovery }
        let close = Task { try await service.close(); completed.withLock { $0 = true } }
        try await waitUntil { await service.wakeStatus == .closed }
        XCTAssertFalse(completed.withLock { $0 }); XCTAssertEqual(f.closes.withLock { $0 }, 0)
        gate.signal(); try await close.value
        do { _ = try await pause.value; XCTFail() } catch {}
        XCTAssertTrue(completed.withLock { $0 }); XCTAssertEqual(f.closes.withLock { $0 }, 1)
    }
    func testARealRequestRetirementDuringRecoveryCannotRestartOptionalPublication() async throws {
        let f = try Fixture(), service = try f.service([Driver(), Driver()])
        try await service.start(); try await waitUntil { await service.wakeStatus == .running }
        let ticket = try await service.quiescePhonePushRecovery(commitDigest: f.old, verifyCurrent: {})
        f.retired.withLock { $0 = true }
        do { _ = try await service.resumePhonePushRecovery(ticket, verifyCurrent: { XCTFail() }); XCTFail() } catch {}
        let retired = await service.isRetired; XCTAssertTrue(retired)
        XCTAssertNil(f.capability.publication); XCTAssertEqual(f.attempts.withLock { $0 }, 1)
        try await service.close()
    }
    func testCapabilityRecoveryFailureKeepsTheHoldAndRetainedFloorWithoutReenrollment() throws {
        let f = try Fixture(), cap = f.capability, before = try f.state(), checkpoint = try f.h.store.read()
        try f.journal.withRequests { _ in
            XCTAssertThrowsError(try cap.quiesceRecovery(commitDigest: f.old, verifyCurrent: {})) {
                XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
            }
        }
        XCTAssertNil(cap.publication); XCTAssertEqual(cap.retainedCommitDigest, f.old)
        XCTAssertThrowsError(try cap.install(f.options, commitDigest: f.old, verifyCurrent: { XCTFail() }))
        XCTAssertFalse(try cap.quiesceRecovery(commitDigest: f.old, verifyCurrent: {}))
        XCTAssertThrowsError(try cap.releaseRecovery(commitDigest: f.old, verifyCurrent: { throw Denied() }))
        XCTAssertThrowsError(try cap.install(f.options, commitDigest: f.old, verifyCurrent: { XCTFail() }))
        XCTAssertTrue(try cap.releaseRecovery(commitDigest: f.old, verifyCurrent: {})); XCTAssertNil(cap.publication)
        try cap.install(f.options, commitDigest: f.old, verifyCurrent: {})
        XCTAssertEqual(cap.installedCommitDigest, f.old); XCTAssertEqual(try f.state(), before)
        let after = try f.h.store.read()
        XCTAssertEqual(after.committed.ledgerDigest, checkpoint.committed.ledgerDigest)
        XCTAssertEqual(after.committed.authorityDigest, checkpoint.committed.authorityDigest)
    }
    func testCapabilityRecoveryWaitsForTheActualJournalOwner() throws {
        let f = try Fixture(), entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), checking = DispatchSemaphore(value: 0)
        let ownerDone = expectation(description: "owner drained"), pauseDone = expectation(description: "recovery drained"), finished = Mutex(false)
        defer { release.signal() }
        DispatchQueue.global().async {
            defer { ownerDone.fulfill() }
            do { try f.journal.withRequests { _ in entered.signal(); guard release.wait(timeout: .now() + 5) == .success else { throw Denied() } } }
            catch { XCTFail("Owner failed: \(error)") }
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 5), .success)
        DispatchQueue.global().async {
            defer { pauseDone.fulfill() }
            do { try f.capability.quiesceRecovery(commitDigest: f.old, verifyCurrent: { checking.signal() }); finished.withLock { $0 = true } }
            catch { XCTFail("Recovery failed: \(error)") }
        }
        XCTAssertEqual(checking.wait(timeout: .now() + 5), .success)
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while f.capability.publication != nil && ContinuousClock.now < deadline { Thread.sleep(forTimeInterval: 0.001) }
        XCTAssertNil(f.capability.publication); XCTAssertFalse(finished.withLock { $0 })
        release.signal(); wait(for: [ownerDone, pauseDone], timeout: 5)
        XCTAssertTrue(finished.withLock { $0 })
    }
    func testOnlyCompletedActiveSettingsRequireTheConsumerRecoveryStartupHold() throws {
        let r = try GatewayRuntimeSettingsStoreTests.Ready(), store = r.fixture.runtime.machine, authority = r.fixture.runtime.plan.host
        XCTAssertFalse(try XCTUnwrap(AuthorityGatewaySettingsStartupPlan.load(machine: store, authority: authority)).requiresConsumerRecovery)
        let revision = try r.revision(); try store.retainGatewaySettingsTransition(revision)
        XCTAssertFalse(try XCTUnwrap(AuthorityGatewaySettingsStartupPlan.load(machine: store, authority: authority)).requiresConsumerRecovery)
        for phase in GatewayRuntimeSettingsPhase.allCases.dropFirst() { try store.markGatewaySettingsTransition(revision, phase: phase) }
        try store.completeGatewaySettingsTransition(revision)
        XCTAssertTrue(try XCTUnwrap(AuthorityGatewaySettingsStartupPlan.load(machine: store, authority: authority)).requiresConsumerRecovery)
    }
}
