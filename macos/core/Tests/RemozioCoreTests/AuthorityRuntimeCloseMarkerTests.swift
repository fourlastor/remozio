import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityRuntimeCloseMarkerTests: XCTestCase, @unchecked Sendable {
    private enum Fault: Error { case startup, close }
    private actor Gate {
        var entered = false
        private var continuation: CheckedContinuation<Void, Never>?
        func hold() async { await withCheckedContinuation { entered = true; continuation = $0 } }
        func release() { continuation?.resume(); continuation = nil }
    }
    private final class Probe: Sendable {
        struct State { var closed = false, retired = false, failStart = false, failClose = false, bound = true; var events: [String] = [] }
        let state = Mutex(State())
        let file: MaintenanceCloseFileFixture, marker: AuthorityMaintenanceCloseMarker
        let closeGate: Gate?, prepareGate: Gate?
        init(closeGate: Gate? = nil, prepareGate: Gate? = nil) throws {
            file = try .init(); marker = try maintenanceCloseMarker(); self.closeGate = closeGate; self.prepareGate = prepareGate
        }
        var events: [String] { state.withLock { $0.events } }
        var instance: AuthorityRuntimeInstance {
            var value = AuthorityRuntimeInstance(start: {
                try self.state.withLock { if $0.failStart { throw Fault.startup } }
            }, close: {
                self.state.withLock { $0.events.append("closeStarted") }; await self.closeGate?.hold()
                try self.state.withLock {
                    if $0.failClose { $0.failClose = false; throw Fault.close }; $0.closed = true; $0.events.append("closeSucceeded")
                }
            }, retired: { self.state.withLock { $0.retired } })
            value.prepareCloseMarker = {
                self.state.withLock { $0.events.append("prepare") }; await self.prepareGate?.hold()
                guard self.state.withLock({ $0.bound }) else { return nil }
                return {
                    try self.state.withLock {
                        guard $0.closed else { XCTFail("Marker preceded successful close"); throw Fault.close }
                        try self.file.publish(self.marker); try self.file.readback(self.marker); $0.events.append("published")
                    }
                }
            }
            return value
        }
    }
    private func waitUntil(_ condition: () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !(await condition()) {
            guard ContinuousClock.now < deadline else { throw GatewayRootChannelError.timedOut }
            try await Task.sleep(for: .milliseconds(5))
        }
    }
    private func runner(_ probe: Probe) throws -> AuthorityRuntimeRunner {
        try .init(monitorMilliseconds: 10, open: { probe.instance }, report: { _ in })
    }
    private func noMarker(_ probe: Probe) {
        XCTAssertFalse(FileManager.default.fileExists(atPath: probe.file.path)); XCTAssertFalse(probe.events.contains("published"))
    }
    func testOnlySuccessfulBoundTerminationPublishesAfterTheActualRunnerClose() async throws {
        let p = try Probe(); defer { try? p.file.close() }; let r = try runner(p)
        try await r.start(); try await waitUntil { r.status == .running }; try await r.closeForTermination()
        XCTAssertEqual(p.events, ["prepare", "closeStarted", "closeSucceeded", "published"])
        try p.file.readback(p.marker); try await r.closeForTermination(); XCTAssertEqual(p.events.filter { $0 == "published" }.count, 1)
    }
    func testActualRunTaskCancellationReachesTheTerminationCatchAsCancellationError() async throws {
        let p = try Probe(); defer { try? p.file.close() }; let r = try runner(p)
        let caught = Mutex(false)
        let run = Task {
            do { _ = try await r.runUntilExit(); XCTFail("The running task returned without cancellation") }
            catch {
                caught.withLock { $0 = error is CancellationError }
                if error is CancellationError { try await r.closeForTermination() }
                else { try await r.close(); throw error }
            }
        }
        try await waitUntil { r.status == .running }; run.cancel(); try await run.value
        XCTAssertTrue(caught.withLock { $0 }); try p.file.readback(p.marker)
        XCTAssertEqual(p.events, ["prepare", "closeStarted", "closeSucceeded", "published"])
    }
    func testRealRegistrationCloseWithRecoveryLeavesThePublicationSharedTokenValid() async throws {
        let f = try BoundAdmissionRegistrationFixture(), record = try f.prepare()
        let initial = try f.machine.store.updateAdmissionState(), inventory = try XCTUnwrap(initial.inventory)
        let activity = try f.activity(), observer = try f.activity(), placement = try f.directory()
        let startup = try XCTUnwrap(AuthorityUpdateAdmissionStartup.capture(machine: f.machine.store, macID: f.machine.mac,
            installationID: inventory.installationID, accountID: f.machine.account, activity: activity, readCurrent: { initial },
            openBarrier: { scope, identity in
                try UpdateAdmissionBarrier(directory: f.directory(), owner: getuid(), expected: identity, scope: scope)
            }))
        XCTAssertEqual(startup.registration, record)
        let registration = try InstalledAuthorityCommandConfigurationTests.makeOwnedCloseRegistration(activity: activity,
            placement: placement, machine: f.machine.store, admission: startup)
        let held = try activity.acquireShared(); defer { held.close(); try? registration.close() }
        let file = try MaintenanceCloseFileFixture(); defer { try? file.close() }
        let marker = try maintenanceCloseMarker(), closed = Mutex(false), published = Mutex(false)
        var instance = AuthorityRuntimeInstance(start: {}, close: {
            try registration.close(); closed.withLock { $0 = true }
        }, retired: { false })
        instance.prepareCloseMarker = {
            try held.validate()
            return {
                XCTAssertTrue(closed.withLock { $0 }); try held.validate()
                XCTAssertThrowsError(try observer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
                try file.publish(marker); try file.readback(marker); try held.validate(); published.withLock { $0 = true }
            }
        }
        let configured = instance
        let runner = try AuthorityRuntimeRunner(open: { configured }, report: { _ in })
        try await runner.start(); try await waitUntil { runner.status == .running }; try await runner.closeForTermination()
        XCTAssertTrue(published.withLock { $0 }); try held.validate(); try file.readback(marker)
        XCTAssertThrowsError(try f.machine.store.inventory()); XCTAssertThrowsError(try startup.recovery.validate())
        held.close(); let exclusive = try observer.acquireExclusive(); try exclusive.validateExclusive(); exclusive.close()
    }
    func testOrdinaryAndUnboundCloseNeverPublish() async throws {
        for bound in [true, false] {
            let p = try Probe(); defer { try? p.file.close() }; p.state.withLock { $0.bound = bound }; let r = try runner(p)
            try await r.start(); try await waitUntil { r.status == .running }
            if bound { try await r.close() } else { try await r.closeForTermination() }
            noMarker(p)
        }
    }
    func testAnIncoherentArmedMarkerClosesTheRunnerButPropagatesShutdownFailure() async throws {
        let p = try Probe(); defer { try? p.file.close() }
        let admission = try AuthorityMaintenancePairingAdmission(accountID: maintenanceCloseBytes(1), incarnation: maintenanceCloseBytes(4))
        let owner = try admission.openConnection(attemptID: maintenanceCloseBytes(2), revision: maintenanceCloseBytes(3))
        _ = try owner.blockNewStages(matching: owner.binding); let shutdown = try owner.transferToShutdown(matching: owner.binding)
        var instance = p.instance
        instance.prepareCloseMarker = {
            _ = try admission.claimCloseMarker(); XCTFail("An armed owner without its marker was accepted"); return nil
        }
        let configured = instance, runner = try AuthorityRuntimeRunner(open: { configured }, report: { _ in })
        try await runner.start(); try await waitUntil { runner.status == .running }
        do { try await runner.closeForTermination(); XCTFail() }
        catch { XCTAssertEqual(error as? RuntimePreparationError, .changedScope) }
        XCTAssertEqual(runner.status, .closed); XCTAssertTrue(p.events.contains("closeSucceeded")); noMarker(p)
        withExtendedLifetime(shutdown) {}
    }
    func testFailedCloseAndLaterOrdinaryRetryNeverPublish() async throws {
        let p = try Probe(); defer { try? p.file.close() }; let r = try runner(p)
        try await r.start(); try await waitUntil { r.status == .running }; p.state.withLock { $0.failClose = true }
        do { try await r.closeForTermination(); XCTFail() } catch { XCTAssertTrue(error is Fault) }
        noMarker(p); XCTAssertEqual(r.status, .shutdownFailed); try await r.close(); noMarker(p)
    }
    func testTerminationDuringAnAlreadyRunningCloseCannotPrepareOrPublish() async throws {
        let gate = Gate(), p = try Probe(closeGate: gate); defer { try? p.file.close() }; let r = try runner(p)
        try await r.start(); try await waitUntil { r.status == .running }
        let ordinary = Task { try await r.close() }; try await waitUntil { await gate.entered }
        let signal = Task { try await r.closeForTermination() }
        try await Task.sleep(for: .milliseconds(30)); noMarker(p); XCTAssertFalse(p.events.contains("prepare"))
        await gate.release(); try await ordinary.value; try await signal.value; noMarker(p)
        XCTAssertEqual(p.events.filter { $0 == "closeSucceeded" }.count, 1)
    }
    func testOrdinaryCloseRacingSuspendedPreparationDiscardsTheMarker() async throws {
        let gate = Gate(), p = try Probe(prepareGate: gate); defer { try? p.file.close() }; let r = try runner(p)
        try await r.start(); try await waitUntil { r.status == .running }
        let signal = Task { try await r.closeForTermination() }; try await waitUntil { await gate.entered }
        try await r.close(); await gate.release(); try await signal.value; noMarker(p)
    }
    func testSuspendedCloseHasNoMarkerBeyondTheObservationBound() async throws {
        let gate = Gate(), p = try Probe(closeGate: gate); defer { try? p.file.close() }; let r = try runner(p)
        try await r.start(); try await waitUntil { r.status == .running }
        let signal = Task { try await r.closeForTermination() }; try await waitUntil { await gate.entered }
        try await Task.sleep(for: .milliseconds(60)); noMarker(p); XCTAssertFalse(p.events.contains("closeSucceeded"))
        await gate.release(); try await signal.value; try p.file.readback(p.marker)
    }
    func testStartupFailureAndRetirementCannotPublishEvenThroughTerminationClose() async throws {
        for startup in [true, false] {
            let p = try Probe(); defer { try? p.file.close() }; p.state.withLock { $0.failStart = startup }; let r = try runner(p)
            try await r.start()
            if startup { try await waitUntil { if case .failed = r.status { return true }; return false } }
            else { try await waitUntil { r.status == .running }; p.state.withLock { $0.retired = true }; try await waitUntil { r.status == .retired } }
            try await r.closeForTermination(); noMarker(p); XCTAssertFalse(p.events.contains("prepare"))
        }
    }
    func testDeinitializationClosesWithoutPublishing() async throws {
        let p = try Probe(); defer { try? p.file.close() }
        var r: AuthorityRuntimeRunner? = try runner(p); try await r?.start(); try await waitUntil { r?.status == .running }
        r = nil; try await waitUntil { p.events.contains("closeSucceeded") }; noMarker(p); XCTAssertFalse(p.events.contains("prepare"))
    }
}
