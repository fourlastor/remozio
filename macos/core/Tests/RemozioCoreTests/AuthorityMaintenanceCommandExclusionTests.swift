import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityMaintenanceCommandExclusionTests: XCTestCase, @unchecked Sendable {
    private func waitUntil(_ condition: () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !(await condition()) {
            guard ContinuousClock.now < deadline else { throw GatewayRootChannelError.timedOut }
            try await Task.sleep(for: .milliseconds(5))
        }
    }
    func testIndependentAccountsProceedButOneAccountHasOneCommand() throws {
        let first = AuthorityMaintenanceCommandExclusion(), second = AuthorityMaintenanceCommandExclusion()
        let a = try first.acquire(), b = try second.acquire()
        XCTAssertThrowsError(try first.acquire()) { XCTAssertEqual($0 as? AuthorityMaintenanceCommandExclusion.AcquisitionError, .busy) }
        try a.validate(); try b.validate(); a.close(); a.close(); b.close()
        let next = try first.acquire(); next.close(); XCTAssertThrowsError(try a.validate())
    }
    func testActualStopWaitsForCommandReturnAndPublishesTheMarkerOnce() async throws {
        let f = try BoundAdmissionRegistrationFixture(), record = try f.prepare()
        let initial = try f.machine.store.updateAdmissionState(), inventory = try XCTUnwrap(initial.inventory)
        let activity = try f.activity()
        let startup = try XCTUnwrap(AuthorityUpdateAdmissionStartup.capture(machine: f.machine.store, macID: f.machine.mac,
            installationID: inventory.installationID, accountID: f.machine.account, activity: activity, readCurrent: { initial },
            openBarrier: { scope, identity in try .init(directory: f.directory(), owner: getuid(), expected: identity, scope: scope) }))
        XCTAssertEqual(startup.registration, record)
        let registration = try InstalledAuthorityCommandConfigurationTests.makeOwnedCloseRegistration(activity: activity,
            placement: f.directory(), machine: f.machine.store, admission: startup)
        defer { try? registration.close() }
        let commands = registration.maintenanceCommands, events = Mutex<[String]>([])
        let file = try MaintenanceCloseFileFixture(); defer { try? file.close() }
        let pairing = try AuthorityMaintenancePairingAdmission(accountID: maintenanceCloseBytes(1), incarnation: maintenanceCloseBytes(4))
        let connection = try pairing.openConnection(attemptID: maintenanceCloseBytes(2), revision: maintenanceCloseBytes(3))
        _ = try connection.blockNewStages(matching: connection.binding)
        let shutdown = try connection.transferToShutdown(matching: connection.binding)
        let marker = try maintenanceCloseMarker(binding: shutdown.binding); try shutdown.retainCloseMarker(marker)
        let instance = InstalledAuthorityCommandRegistration.maintenanceRuntimeInstance(commands: commands, start: {}, close: {
            try registration.close(); events.withLock { $0.append("closed") }
        }, retired: { false }, prepareCloseMarker: {
            guard let publish = try await InstalledAuthorityCommandRegistration.prepareOwnedCloseMarker(owner: getuid(), commands: commands,
                admission: pairing, activity: activity, directory: file.directory) else { return nil }
            return { @Sendable in
                XCTAssertEqual(events.withLock { $0.last }, "closed")
                try publish(); try file.readback(marker)
                events.withLock { $0.append("published") }
            }
        })
        let configured = instance
        let runner = try AuthorityRuntimeRunner(monitorMilliseconds: 10, open: { configured }, report: { _ in })
        try await runner.start(); try await waitUntil { runner.status == .running }
        let command = try commands.acquire()
        let stop = Task { try await runner.closeForTermination() }
        try await waitUntil { commands.isStopping }
        XCTAssertEqual(events.withLock { $0 }, [])
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
        XCTAssertThrowsError(try commands.acquire())
        try command.validate(); events.withLock { $0.append("commandReturned") }; command.close()
        try await stop.value; try await runner.closeForTermination()
        XCTAssertEqual(events.withLock { $0 }, ["commandReturned", "closed", "published"])
        XCTAssertEqual(events.withLock { $0.filter { $0 == "published" }.count }, 1)
        try file.readback(marker); XCTAssertThrowsError(try commands.acquire()); withExtendedLifetime(shutdown) {}
    }
    func testCancellationCannotPretendTheActiveCommandReturned() async throws {
        let commands = AuthorityMaintenanceCommandExclusion(), returned = Mutex(false)
        let command = try commands.acquire()
        let stop = Task {
            let token = try await commands.beginStop(); try token.validate(); returned.withLock { $0 = true }
        }
        try await waitUntil { commands.isStopping && commands.waitingStops == 1 }; stop.cancel()
        await Task.yield(); XCTAssertEqual(commands.waitingStops, 1)
        XCTAssertFalse(returned.withLock { $0 }); XCTAssertThrowsError(try commands.acquire())
        command.close(); try await stop.value; XCTAssertTrue(returned.withLock { $0 })
    }
    func testJoiningTheSameStopDoesNotAcquireRecursivelyOrPublishTwice() async throws {
        let commands = AuthorityMaintenanceCommandExclusion()
        let first = try await commands.beginStop(), second = try await commands.beginStop()
        try first.validate(); try second.validate()
        XCTAssertTrue(try first.claimClosePublication()); XCTAssertFalse(try second.claimClosePublication())
        XCTAssertThrowsError(try commands.acquire())
    }
    func testPairingReservationPreventsActualHoldMutationUntilItCloses() throws {
        let records = try UnboundAuthorityRecords()
        let pairing = try AuthorityMaintenancePairingAdmission(accountID: records.authorized.scope.authority.accountID,
            incarnation: unboundAuthorityBytes(41))
        let hold = AuthorityMaintenanceAdmissionHold(projection: try records.projection(records.authorized))
        try hold.bindUnboundAuthority(unboundAuthorityBytes(41))
        let reserved = DispatchSemaphore(value: 0), attempted = DispatchSemaphore(value: 0)
        let released = DispatchSemaphore(value: 0), finished = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            defer { finished.signal() }
            do {
                let stage = try pairing.reserveStage(); reserved.signal()
                XCTAssertEqual(attempted.wait(timeout: .now() + 3), .success)
                XCTAssertThrowsError(try hold.requireOpen())
                stage.close(); released.signal()
            } catch { XCTFail("The pairing stage failed: \(error)"); reserved.signal(); released.signal() }
        }
        XCTAssertEqual(reserved.wait(timeout: .now() + 3), .success)
        XCTAssertThrowsError(try hold.releaseUnbound(records.pending, incarnation: unboundAuthorityBytes(41), pairing: pairing))
        XCTAssertEqual(try hold.unboundObservation(records.pending, incarnation: unboundAuthorityBytes(41)), .held)
        attempted.signal(); XCTAssertEqual(released.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(try hold.releaseUnbound(records.pending, incarnation: unboundAuthorityBytes(41), pairing: pairing), .released)
        let next = try pairing.reserveStage(); try hold.requireOpen(); next.close()
        XCTAssertEqual(finished.wait(timeout: .now() + 3), .success)
    }
    func testOwnedMarkerEntryRejectsRootBeforeReadingClosedDirectoryOrClaimingStop() async throws {
        let file = try MaintenanceCloseFileFixture(); defer { try? file.close() }; file.directory.close()
        let files = try UpdateAdmissionTestFixture(), commands = AuthorityMaintenanceCommandExclusion()
        let activity = try files.activity.open()
        let pairing = try AuthorityMaintenancePairingAdmission(accountID: maintenanceCloseBytes(1), incarnation: maintenanceCloseBytes(4))
        do {
            _ = try await InstalledAuthorityCommandRegistration.prepareOwnedCloseMarker(owner: 0, commands: commands,
                admission: pairing, activity: activity, directory: file.directory)
            XCTFail("Root entered the ordinary-owner preparer")
        } catch { XCTAssertEqual(error as? JournalLeaseError, .unsafeMetadata) }
        XCTAssertFalse(commands.isStopping); let command = try commands.acquire(); command.close()
    }
    func testCancelledCommandWaitRemovesItsReservationWithoutAcquiringOwnership() async throws {
        let commands = AuthorityMaintenanceCommandExclusion(), command = try commands.acquire()
        let waiting = Task { try await commands.acquireWhenAvailable() }
        try await waitUntil { commands.waitingCommands == 1 }; waiting.cancel()
        do { _ = try await waiting.value; XCTFail("A cancelled waiter acquired a command") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(commands.waitingCommands, 0); try command.validate(); command.close()
        let next = try commands.acquire(); next.close()
    }
    func testStopRejectsAQueuedCommandBeforeTheActiveCommandReturns() async throws {
        let commands = AuthorityMaintenanceCommandExclusion(), command = try commands.acquire()
        let waiting = Task { try await commands.acquireWhenAvailable() }
        try await waitUntil { commands.waitingCommands == 1 }
        let stop = Task { try await commands.beginStop() }
        do { _ = try await waiting.value; XCTFail("A queued command survived stop") }
        catch { XCTAssertEqual(error as? AuthorityMaintenanceCommandExclusion.AcquisitionError, .stopping) }
        XCTAssertEqual(commands.waitingCommands, 0); XCTAssertEqual(commands.waitingStops, 1)
        command.close(); let token = try await stop.value; try token.validate()
    }
    func testUnarmedPreparationDoesNotConsumeALaterValidPublication() async throws {
        let file = try MaintenanceCloseFileFixture(); defer { try? file.close() }
        let files = try UpdateAdmissionTestFixture(), activity = try files.activity.open()
        let commands = AuthorityMaintenanceCommandExclusion()
        let pairing = try AuthorityMaintenancePairingAdmission(accountID: maintenanceCloseBytes(1), incarnation: maintenanceCloseBytes(4))
        let absent = try await InstalledAuthorityCommandRegistration.prepareOwnedCloseMarker(owner: getuid(), commands: commands,
            admission: pairing, activity: activity, directory: file.directory)
        XCTAssertNil(absent)
        let connection = try pairing.openConnection(attemptID: maintenanceCloseBytes(2), revision: maintenanceCloseBytes(3))
        _ = try connection.blockNewStages(matching: connection.binding)
        let shutdown = try connection.transferToShutdown(matching: connection.binding)
        let marker = try maintenanceCloseMarker(binding: shutdown.binding); try shutdown.retainCloseMarker(marker)
        let publish = try await InstalledAuthorityCommandRegistration.prepareOwnedCloseMarker(owner: getuid(), commands: commands,
            admission: pairing, activity: activity, directory: file.directory)
        try XCTUnwrap(publish)(); try file.readback(marker); withExtendedLifetime(shutdown) {}
    }

    func testAStageArrivingInsideTheActualHoldMutationSeesTheNewState() throws {
        let records = try UnboundAuthorityRecords()
        let pairing = try AuthorityMaintenancePairingAdmission(accountID: records.authorized.scope.authority.accountID,
            incarnation: unboundAuthorityBytes(41))
        let hold = AuthorityMaintenanceAdmissionHold(projection: try records.projection(records.authorized))
        try hold.bindUnboundAuthority(unboundAuthorityBytes(41))
        let inside = DispatchSemaphore(value: 0), continueMutation = DispatchSemaphore(value: 0)
        let stageArriving = DispatchSemaphore(value: 0), group = DispatchGroup(), events = Mutex<[String]>([])
        group.enter(); DispatchQueue.global().async {
            defer { group.leave() }
            do {
                let outcome = try hold.releaseUnboundOwned(records.pending, incarnation: unboundAuthorityBytes(41), pairing: pairing) { boundary in
                    switch boundary {
                    case .before: inside.signal(); XCTAssertEqual(continueMutation.wait(timeout: .now() + 3), .success)
                    case .after: events.withLock { $0.append("mutated") }
                    }
                }
                XCTAssertEqual(outcome, .released)
            } catch { XCTFail("The actual hold mutation failed: \(error)"); inside.signal() }
        }
        XCTAssertEqual(inside.wait(timeout: .now() + 3), .success)
        group.enter(); DispatchQueue.global().async {
            defer { group.leave() }
            stageArriving.signal()
            do {
                let stage = try pairing.reserveStage(); defer { stage.close() }
                events.withLock { $0.append("stageReturned") }; try hold.requireOpen()
            } catch { XCTFail("The arriving stage failed: \(error)") }
        }
        XCTAssertEqual(stageArriving.wait(timeout: .now() + 3), .success)
        // Give the stage thread a chance to enter reserveStage.
        // This detects a wrong order with high probability, not certainty.
        Thread.sleep(forTimeInterval: 0.03)
        continueMutation.signal(); XCTAssertEqual(group.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(events.withLock { $0 }, ["mutated", "stageReturned"])
        XCTAssertEqual(try pairing.stagedReservations(), 0); try hold.requireOpen()
    }

}
