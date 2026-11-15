import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class RuntimeMaintenanceBootstrapAdmissionTests: XCTestCase {
    private enum Fault: Error { case changedConfiguration, maintenancePhase, callback }
    private final class CaptureLifetime { var reads = 0 }
    private let accountID = Data(repeating: 31, count: 16)
    private func fixture(_ body: (UpdateAdmissionTestFixture, UpdateAdmissionBarrier, UpdateAdmissionRegistrationRecord.Account) throws -> Void) throws {
        let f = try UpdateAdmissionTestFixture(), (barrier, identity) = try f.provisionAccount(accountID)
        try body(f, barrier, .init(accountID: accountID, identity: identity))
    }
    private func busy(_ barrier: UpdateAdmissionBarrier) {
        XCTAssertThrowsError(try barrier.beginDrain()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
    }
    func testHeldAccountDrainReportsMaintenanceWhileStoreAndMetadataErrorsStayDistinct() throws {
        try fixture { _, barrier, account in
            let drain = try barrier.beginDrain()
            XCTAssertThrowsError(try RuntimeMaintenanceBootstrapGuard.withOwnedRegistration(capture: { account },
                acquire: { _ in try barrier.acquireAdmission() }, body: { _ in XCTFail() })) {
                XCTAssertEqual($0 as? RuntimeActivationError, .maintenancePending)
            }
            drain.close()
            XCTAssertThrowsError(try RuntimeMaintenanceBootstrapGuard.withOwnedRegistration(capture: { throw JournalLeaseError.busy },
                acquire: { _ in XCTFail(); return try barrier.acquireAdmission() }, body: { _ in XCTFail() })) {
                XCTAssertEqual($0 as? JournalLeaseError, .busy)
            }
            XCTAssertThrowsError(try RuntimeMaintenanceBootstrapGuard.withOwnedRegistration(capture: { account },
                acquire: { _ in throw JournalLeaseError.system(ENOENT) }, body: { _ in XCTFail() })) {
                XCTAssertEqual($0 as? JournalLeaseError, .system(ENOENT))
            }
            let resumed = try barrier.acquireAdmission(); try resumed.validate(); resumed.close()
        }
    }
    func testAdmissionStaysHeldForEveryReconcileCallbackAndClosesOnReturn() throws {
        try fixture { _, barrier, account in
            let job = try InstalledAccountJobManifest(accountID: accountID, role: .authority, executionUID: 0,
                userName: "root", bundlePath: "/Applications/Remozio.app")
            var inspections = 0, callbacks = 0
            try RuntimeMaintenanceBootstrapGuard.withOwnedRegistration(capture: { account }, acquire: { _ in
                try barrier.acquireAdmission()
            }) { verify in
                try RuntimeJobRegistration.reconcile(job: job, verifyCurrent: { self.busy(barrier) },
                    requireMaintenanceOpen: { _ in try verify() }, inspect: {
                        self.busy(barrier); callbacks += 1; inspections += 1
                        return inspections == 1 ? .absent : .matching
                    }, bootstrap: { self.busy(barrier); callbacks += 1 })
            }
            XCTAssertEqual(callbacks, 3)
            let drain = try barrier.beginDrain(); try drain.validate(); drain.close()
        }
    }
    func testAdmissionClosesAfterEachNativeCallbackError() throws {
        try fixture { _, barrier, account in
            let job = try InstalledAccountJobManifest(accountID: accountID, role: .authority, executionUID: 0,
                userName: "root", bundlePath: "/Applications/Remozio.app")
            for failAt in 1...3 {
                var callbacks = 0, inspections = 0
                func callback() throws {
                    self.busy(barrier); callbacks += 1
                    if callbacks == failAt { throw Fault.callback }
                }
                func attempt() throws {
                    try RuntimeMaintenanceBootstrapGuard.withOwnedRegistration(capture: { account },
                        acquire: { _ in try barrier.acquireAdmission() }) { verify in
                        try RuntimeJobRegistration.reconcile(job: job, verifyCurrent: {}, requireMaintenanceOpen: { _ in try verify() },
                            inspect: { try callback(); inspections += 1; return inspections == 1 ? .absent : .matching },
                            bootstrap: callback)
                    }
                }
                if failAt == 2 { try attempt() }
                else { XCTAssertThrowsError(try attempt()) { XCTAssertTrue($0 is Fault) } }
                XCTAssertEqual(callbacks, failAt == 2 ? 3 : failAt)
                let drain = try barrier.beginDrain(); try drain.validate(); drain.close()
            }
        }
    }
    func testThrowingSynchronousOwnerReleasesTheCaptureAndAdmissionBeforeReturning() throws {
        try fixture { _, barrier, account in
            weak var released: CaptureLifetime?
            do {
                let lifetime = CaptureLifetime(); released = lifetime
                XCTAssertThrowsError(try RuntimeMaintenanceBootstrapGuard.withOwnedRegistration(capture: { [lifetime] in
                    lifetime.reads += 1; return account
                }, acquire: { _ in try barrier.acquireAdmission() }, body: { verify in
                    try verify(); self.busy(barrier); throw Fault.callback
                })) { XCTAssertTrue($0 is Fault) }
                XCTAssertEqual(lifetime.reads, 3)
            }
            XCTAssertNil(released)
            let drain = try barrier.beginDrain(); try drain.validate(); drain.close()
        }
    }
    func testGateAppearingDisappearingOrChangingBetweenCaptureAndAcquireRefuses() throws {
        try fixture { _, barrier, account in
            let changed = UpdateAdmissionRegistrationRecord.Account(accountID: accountID,
                identity: .init(device: account.identity.device, inode: account.identity.inode ^ 1))
            for after in [nil, changed] as [UpdateAdmissionRegistrationRecord.Account?] {
                var current: UpdateAdmissionRegistrationRecord.Account? = account
                XCTAssertThrowsError(try RuntimeMaintenanceBootstrapGuard.withOwnedRegistration(capture: { current },
                    acquire: { _ in current = after; return try barrier.acquireAdmission() }, body: { _ in XCTFail() })) {
                    XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
                }
                let drain = try barrier.beginDrain(); drain.close()
            }
            var captures = 0
            XCTAssertThrowsError(try RuntimeMaintenanceBootstrapGuard.withOwnedRegistration(capture: {
                captures += 1; return captures == 1 ? nil : account
            }, acquire: { _ in XCTFail(); return try barrier.acquireAdmission() }, body: { _ in XCTFail() }))
        }
    }
    func testConfigurationAndPhaseFailureAfterAcquireReleaseTheToken() throws {
        try fixture { _, barrier, account in
            for failure in [Fault.changedConfiguration, .maintenancePhase] {
                var captures = 0
                XCTAssertThrowsError(try RuntimeMaintenanceBootstrapGuard.withOwnedRegistration(capture: {
                    captures += 1; if captures > 1 { throw failure }; return account
                }, acquire: { _ in try barrier.acquireAdmission() }, body: { _ in XCTFail() })) { XCTAssertTrue($0 is Fault) }
                let drain = try barrier.beginDrain(); drain.close()
            }
        }
    }
    func testClosedMachineAndWrongAccountTokensCannotEnterTheBody() throws {
        try fixture { f, barrier, account in
            let (other, _) = try f.provisionAccount(Data(repeating: 32, count: 16))
            for kind in 0..<3 {
                XCTAssertThrowsError(try RuntimeMaintenanceBootstrapGuard.withOwnedRegistration(capture: { account }, acquire: { _ in
                    let token = try (kind == 0 ? f.open() : kind == 1 ? other : barrier).acquireAdmission()
                    if kind == 2 { token.close() }; return token
                }, body: { _ in XCTFail() }))
                let drain = try barrier.beginDrain(); drain.close()
            }
        }
    }
    func testUnsafeGateMetadataCannotEnterTheBodyOrRetainAdmission() throws {
        try fixture { f, barrier, account in
            let path = f.activity.directory.appendingPathComponent(try UpdateAdmissionScope.account(accountID).fileName).path
            XCTAssertThrowsError(try RuntimeMaintenanceBootstrapGuard.withOwnedRegistration(capture: { account }, acquire: { _ in
                let token = try barrier.acquireAdmission(); XCTAssertEqual(chmod(path, 0o644), 0); return token
            }, body: { _ in XCTFail() }))
            XCTAssertEqual(chmod(path, 0o600), 0)
            let identity = account.identity
            let directory = try ReleaseDestinationLease(anchor: f.activity.root.path, relativeDirectory: "Machine", owner: getuid())
            let fresh = try UpdateAdmissionBarrier(directory: directory, owner: getuid(), expected: identity, scope: .account(accountID))
            let drain = try fresh.beginDrain(); drain.close()
        }
    }
    func testFinalCaptureFailureRefusesConfirmationAndReleasesAdmission() throws {
        try fixture { _, barrier, account in
            var valid = true
            XCTAssertThrowsError(try RuntimeMaintenanceBootstrapGuard.withOwnedRegistration(capture: {
                guard valid else { throw Fault.changedConfiguration }; return account
            }, acquire: { _ in try barrier.acquireAdmission() }, body: { verify in
                try verify(); valid = false
            })) { XCTAssertTrue($0 is Fault) }
            let drain = try barrier.beginDrain(); drain.close()
        }
    }
    func testLegacyWithoutAnAccountNeverAcquiresAGateAndVerifiesBothSidesOfTheBody() throws {
        var captures = 0, bodies = 0
        try RuntimeMaintenanceBootstrapGuard.withOwnedRegistration(capture: { captures += 1; return nil }, acquire: { _ in
            XCTFail(); throw Fault.callback
        }) { verify in bodies += 1; try verify() }
        XCTAssertEqual(captures, 4); XCTAssertEqual(bodies, 1)
        XCTAssertNotEqual(getuid(), 0)
    }
}
