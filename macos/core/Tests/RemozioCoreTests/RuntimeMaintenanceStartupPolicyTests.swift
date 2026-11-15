import Foundation
import XCTest
@testable import RemozioCore

/// Exercises legal record transitions. These metadata tests grant no native custody or RPC proof.
final class RuntimeMaintenanceStartupPolicyTests: XCTestCase {
    private typealias Row = RuntimeMaintenanceWindowRecord
    private typealias Policy = RuntimeMaintenanceStartupPolicy
    private func bytes(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private func row(_ phase: Row.Phase, bound: Bool = true) throws -> Row {
        let scope = try Row.Scope(macID: bytes(1), installationID: bytes(2),
            authority: .init(accountID: bytes(3), ownerUID: 501, directoryID: bytes(4)),
            target: .init(accountID: bytes(5), ownerUID: 502, directoryID: bytes(6)),
            releaseDigest: bytes(7, 32), candidateDigest: bytes(8, 32), authorityPolicyDigest: bytes(9, 32),
            operationDigest: bytes(10, 32), restorationDigest: bytes(11, 32), mutationFootprintDigest: bytes(12, 32),
            authorityGrantDigest: bytes(13, 32), targetConsentDigest: bytes(14, 32), administratorIntentDigest: bytes(15, 32))
        let binding = try AuthorityMaintenanceBinding(accountID: scope.authority.accountID, attemptID: bytes(16),
            revision: bytes(17), incarnation: bytes(18), connectionID: bytes(19))
        let operation: Row.OperationOutcome = phase == .executing || phase == .workSettled
            || phase == .restoring || phase == .reopenPending || phase == .needsOwnerRecovery ? .unknown : .notStarted
        let service: Row.ServiceOutcome = phase == .reopenPending ? .healthy : .stopped
        return try Row(id: bytes(16), revision: bytes(20), purpose: .retainedRuntime, scope: scope, phase: phase,
            operation: operation, service: service, failure: phase == .needsOwnerRecovery ? .cleanupPending : nil,
            shutdownBinding: bound && phase != .authorized ? binding : nil)
    }
    func testAuthorizedHasNoBindingAndNeedsManualCleanup() throws {
        let value = try row(.authorized)
        XCTAssertNil(value.shutdownBinding)
        XCTAssertEqual(try Policy.initial(value), .ownerRecovery(.cleanupPending))
    }
    func testDrainingSameEpochChoosesOnlySavedReopen() throws {
        XCTAssertEqual(try Policy.afterProbe(row(.draining), sameIncarnation: true), .cancelAndReopen)
    }
    func testStoppingSameEpochCannotUsePreStopCleanup() throws {
        XCTAssertEqual(try Policy.afterProbe(row(.stopping), sameIncarnation: true), .ownerRecovery(.cleanupPending))
    }
    func testRestartOfEitherEarlyPhaseChoosesTheLegalRecoveryEdge() throws {
        for phase in [Row.Phase.draining, .stopping] {
            let before = try row(phase)
            XCTAssertEqual(try Policy.afterProbe(before, sameIncarnation: false), .restartRestoration)
            let failed = try Policy.row(before, phase: .needsOwnerRecovery, service: .notStopped, failure: .serviceUnavailable)
            let restoring = try Policy.row(failed, phase: .restoring, service: .restartPending)
            XCTAssertEqual(restoring.operation, .notStarted)
            XCTAssertEqual(restoring.shutdownBinding, before.shutdownBinding)
            XCTAssertThrowsError(try Policy.row(before, phase: .workSettled, service: .stopped))
        }
    }
    func testStoppedSkipsObservationAndCanRestoreWithNotStarted() throws {
        let before = try row(.stopped)
        XCTAssertEqual(try Policy.initial(before), .restore)
        let after = try Policy.row(before, phase: .restoring, service: .restartPending)
        XCTAssertEqual(after.operation, .notStarted)
    }
    func testExecutingRequiresObservationBeforeWorkSettled() throws {
        let before = try row(.executing)
        XCTAssertEqual(try Policy.initial(before), .observeOperation)
        for state in [RuntimeMaintenanceRuntimeObservation.State.old, .new, .partial, .unknown] {
            let settled = try Policy.row(before, phase: .workSettled, operation: Policy.operation(state), service: .stopped)
            XCTAssertNotEqual(settled.operation, .notStarted)
            let after = try Policy.row(settled, phase: .restoring, service: .restartPending)
            XCTAssertEqual(after.operation, settled.operation)
        }
    }
    func testPartialAndUnknownNeverBecomeCommitted() {
        XCTAssertEqual(Policy.operation(.new), .committed)
        XCTAssertEqual(Policy.operation(.old), .failed)
        XCTAssertEqual(Policy.operation(.partial), .unknown)
        XCTAssertEqual(Policy.operation(.unknown), .unknown)
    }
    func testExistingOwnerRecoveryDoesNothing() throws {
        XCTAssertEqual(try Policy.initial(row(.needsOwnerRecovery)), .nothing)
        XCTAssertThrowsError(try Policy.afterProbe(row(.needsOwnerRecovery), sameIncarnation: false))
    }
    func testPendingNeverResumesAnOldConnection() throws {
        XCTAssertEqual(try Policy.initial(row(.reopenPending)), .ownerRecovery(.admissionUnconfirmed))
        XCTAssertThrowsError(try Policy.afterProbe(row(.reopenPending), sameIncarnation: false))
    }
    func testMissingBindingNeverRestoresOrProbes() throws {
        for phase in [Row.Phase.draining, .stopping, .stopped, .executing, .workSettled, .restoring] {
            XCTAssertEqual(try Policy.initial(row(phase, bound: false)), .ownerRecovery(.cleanupPending))
        }
    }
}
