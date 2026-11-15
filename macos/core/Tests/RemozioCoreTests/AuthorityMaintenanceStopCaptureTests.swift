import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityMaintenanceStopCaptureTests: XCTestCase, @unchecked Sendable {
    func testOwnedCaptureRetainsTheActualBindingWitnessAndPolicyWithoutReadingOpaqueDigests() async throws {
        let f = try MaintenanceStopTestFixture(), client = try f.client(), result = try await f.capture(client)
        XCTAssertTrue(result.witness === f.witness)
        XCTAssertEqual(result.window.scope, f.window.scope); XCTAssertNotEqual(result.window.revision, f.window.revision)
        XCTAssertEqual(result.window.shutdownBinding, result.marker.binding); try result.window.requireReplacing(f.window)
        XCTAssertEqual(result.marker.binding, f.driver.requests.last?.binding)
        XCTAssertEqual(result.marker.gate, f.cohort.accountIdentity)
        XCTAssertEqual(try result.configuration.codePolicy.bytes, try f.runtime.plan.host.codePolicy.bytes)
        try result.validate(); await client.close()
        XCTAssertEqual(f.driver.requests.map(\.action), [.open, .observe, .arm])
    }
    func testBusyWorkIsObservedUntilItSettlesBeforeTheOnlyArm() async throws {
        let f = try MaintenanceStopTestFixture(); f.driver.state.withLock { $0.busyObservations = 2 }
        let client = try f.client(); _ = try await f.capture(client)
        XCTAssertEqual(f.driver.requests.map(\.action), [.open, .observe, .observe, .observe, .arm])
        await client.close()
    }
    func testPairingReadinessAloneDoesNotDecideWhetherWorkHasSettled() throws {
        XCTAssertTrue(try MaintenanceStopTestDriver.work().allowsMaintenanceStop)
        XCTAssertTrue(try MaintenanceStopTestDriver.work(ready: false).allowsMaintenanceStop)
        XCTAssertFalse(try MaintenanceStopTestDriver.work(busy: true).allowsMaintenanceStop)
    }
    func testProcessChangeAfterAppliedArmSendsCancelToTheNewIncarnationAndRequiresRecovery() async throws {
        let f = try MaintenanceStopTestFixture(), client = try f.client()
        do {
            _ = try await f.capture(client, requireProcess: { _ in
                guard f.driver.requests.contains(where: { $0.action == .arm }) else { return }
                f.driver.state.withLock { $0.incarnation = maintenanceCloseBytes(63) }
                throw MaintenanceStopTestFault.changedProcess
            })
            XCTFail("A changed original process produced captured arm evidence")
        } catch { XCTAssertEqual(error as? AuthorityMaintenanceClientError, .needsOwnerRecovery) }
        let requests = f.driver.requests
        XCTAssertEqual(requests.map(\.action), [.open, .observe, .arm, .cancel])
        XCTAssertEqual(requests.last?.binding?.incarnation, maintenanceCloseBytes(61))
        XCTAssertNotEqual(requests.last?.binding?.incarnation, f.driver.state.withLock { $0.incarnation })
    }
    func testChangedWindowRevisionCannotReachObservationOrArm() async throws {
        let f = try MaintenanceStopTestFixture(), client = try f.client(revision: maintenanceCloseBytes(82))
        do { _ = try await f.capture(client); XCTFail() }
        catch { XCTAssertEqual(error as? RuntimePreparationError, .changedScope) }
        XCTAssertEqual(f.driver.requests.map(\.action), [.open]); await client.close()
    }
    func testLostAccountDrainCannotObserveOrArmAndKeepsMachineAdmissionShared() async throws {
        let f = try MaintenanceStopTestFixture(), client = try f.client(); f.drain.close()
        do { _ = try await f.capture(client); XCTFail() } catch { }
        XCTAssertEqual(f.driver.requests.map(\.action), [.open])
        try f.ordinary.validate(); await client.close()
    }
    func testCapturedEvidenceDoesNotSurviveItsActualOwner() async throws {
        let f = try MaintenanceStopTestFixture(), client = try f.client(), result = try await f.capture(client)
        f.ownerValid.withLock { $0 = false }
        XCTAssertThrowsError(try result.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        await client.close()
    }
    func testCopiedAppliedReplyCannotSelectTheNativeCaptureFactory() async throws {
        let f = try MaintenanceStopTestFixture(), client = try f.client()
        _ = try await client.start(until: .now.advanced(by: .seconds(2)))
        do {
            _ = try await client.captureNativeStop(window: f.window, cohort: f.cohort, admission: f.ordinary,
                drain: f.drain, directory: f.directory, until: .now.advanced(by: .seconds(2)),
                persistBinding: { _ in throw MaintenanceStopTestFault.expected }, verifyOwner: {})
            XCTFail()
        } catch { XCTAssertEqual(error as? JournalLeaseError, .rootRequired) }
        XCTAssertEqual(f.driver.requests.map(\.action), [.open]); await client.close()
    }
    func testPersistenceCompletesBeforeTheFirstBoundObserveAndRunsOnlyOnce() async throws {
        let f = try MaintenanceStopTestFixture(), client = try f.client(), calls = Mutex(0)
        f.driver.state.withLock { $0.busyObservations = 2; $0.pendingArms = 2; $0.ready = false }
        let result = try await f.capture(client, persistBinding: { binding in
            calls.withLock { $0 += 1 }; XCTAssertEqual(f.driver.requests.map(\.action), [.open])
            return try f.window.retainingShutdownBinding(binding)
        })
        XCTAssertEqual(calls.withLock { $0 }, 1); XCTAssertEqual(result.window.shutdownBinding, result.marker.binding)
        XCTAssertEqual(f.driver.requests.map(\.action), [.open, .observe, .observe, .observe, .arm, .arm, .arm])
        await client.close()
    }
    func testUncertainPersistenceRetiresTheClientWithoutObservationArmOrReplay() async throws {
        let f = try MaintenanceStopTestFixture(), client = try f.client(), calls = Mutex(0)
        do {
            _ = try await f.capture(client, persistBinding: { _ in calls.withLock { $0 += 1 }; throw MaintenanceStopTestFault.expected })
            XCTFail()
        } catch { XCTAssertEqual(error as? AuthorityMaintenanceClientError, .needsOwnerRecovery) }
        do { _ = try await f.capture(client); XCTFail() } catch { }
        XCTAssertEqual(calls.withLock { $0 }, 1); XCTAssertEqual(f.driver.requests.map(\.action), [.open])
    }
    func testUnchangedReadbackAndForeignBindingCannotReachObserveOrArm() async throws {
        for foreign in [false, true] {
            let f = try MaintenanceStopTestFixture(), client = try f.client()
            do {
                _ = try await f.capture(client, persistBinding: { value in
                    if !foreign { return f.window }
                    let other = try AuthorityMaintenanceBinding(accountID: value.accountID, attemptID: value.attemptID,
                        revision: value.revision, incarnation: value.incarnation, connectionID: maintenanceCloseBytes(99))
                    return try f.window.retainingShutdownBinding(other)
                }); XCTFail()
            } catch { XCTAssertEqual(error as? AuthorityMaintenanceClientError, .needsOwnerRecovery) }
            XCTAssertEqual(f.driver.requests.map(\.action), [.open]); await client.close()
        }
    }

}
