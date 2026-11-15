import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class RuntimeMaintenanceBootstrapTests: XCTestCase {
    private typealias Record = RuntimeMaintenanceWindowRecord
    private enum Fault: Error { case configuration }
    private func fixture(_ body: (RuntimeMaintenanceReaderFixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withMaintenanceReaderFixture(body)
    }
    private func data(_ byte: UInt8, _ count: Int = 16) -> Data { Data(repeating: byte, count: count) }
    private func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
    private func job(_ f: RuntimeMaintenanceReaderFixture, role: AuthorityCodeRole = .authority,
        account: Data? = nil, bundle: String? = nil) throws -> InstalledAccountJobManifest {
        let id = account ?? f.authority.accountID
        return try .init(accountID: id, role: role, executionUID: role == .authority ? 0 : 65001,
            userName: role == .authority ? "root" : ServiceAccountClaim.recordName(accountID: id, role: role == .transport ? .transport : .gateway),
            bundlePath: bundle ?? XCTUnwrap(f.machine().inventory()).bundlePath)
    }
    private func record(_ f: RuntimeMaintenanceReaderFixture, phase: Record.Phase = .authorized,
        foreign: Bool = false, badMac: Bool = false, badInstallation: Bool = false, badDirectory: Bool = false) throws -> Record {
        let current = try XCTUnwrap(f.machine().inventory())
        let authority = try Record.Account(accountID: foreign ? data(91) : f.authority.accountID,
            ownerUID: f.authority.ownerUID, directoryID: badDirectory ? data(99) : f.authority.directoryID)
        let scope = try Record.Scope(macID: badMac ? data(99) : current.macID,
            installationID: badInstallation ? data(99) : current.installationID, authority: authority,
            target: .init(accountID: data(92), ownerUID: 65001, directoryID: data(93)),
            releaseDigest: current.releaseDigest, candidateDigest: data(2, 32), authorityPolicyDigest: data(3, 32),
            operationDigest: data(4, 32), restorationDigest: data(5, 32), mutationFootprintDigest: data(6, 32),
            authorityGrantDigest: data(7, 32), targetConsentDigest: data(8, 32), administratorIntentDigest: data(9, 32))
        let early = [Record.Phase.authorized, .draining, .stopping, .stopped].contains(phase)
        let healthy = [Record.Phase.reopenPending, .restored].contains(phase)
        let registration = try XCTUnwrap(f.machine().updateAdmissionRegistration())
        let identity = try XCTUnwrap(registration.accounts.first { $0.accountID == f.authority.accountID }).identity
        let gate: Record.GateReadback? = phase == .restored ? try .init(attemptID: data(80), requestRevision: data(81),
            identity: identity, authorityIncarnation: data(82), challenge: data(83), responseDigest: data(84, 32),
            hold: .released, admission: .available) : nil
        return try .init(id: data(80), revision: data(81), purpose: .retainedRuntime, scope: scope, phase: phase,
            operation: phase == .executing ? .unknown : early ? .notStarted : .committed,
            service: healthy ? .healthy : .unknown, failure: phase == .needsOwnerRecovery ? .healthFailed : nil, gate: gate)
    }
    private func retain(_ record: Record, _ f: RuntimeMaintenanceReaderFixture, create: Bool = true) throws {
        var sql = create ? [RuntimeMaintenanceWindowStorage.createSQL, "PRAGMA user_version=29"] : ["DELETE FROM runtime_maintenance_windows_v1"]
        sql.append("INSERT INTO runtime_maintenance_windows_v1 VALUES(X'\(hex(record.scope.authority.accountID))',X'\(hex(record.id))',X'\(hex(record.revision))',\(record.phase.rawValue),X'\(try hex(record.encoded))')")
        try f.edit(sql)
    }
    private func requireOpen(_ job: InstalledAccountJobManifest, _ f: RuntimeMaintenanceReaderFixture) throws {
        try f.machine().requireRuntimeMaintenanceBootstrap(job, installationID: XCTUnwrap(f.machine().inventory()).installationID)
    }
    func testLegacyAndAbsentWindowDoNotChangeProtectedRows() throws {
        try fixture { f in
            let job = try job(f), before = try runtimeMaintenanceFixtureRows(f.databasePath)
            try requireOpen(job, f); XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), before)
            try f.edit([RuntimeMaintenanceWindowStorage.createSQL, "PRAGMA user_version=29"])
            let schema29 = try runtimeMaintenanceFixtureRows(f.databasePath)
            try requireOpen(job, f); XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), schema29)
        }
    }
    func testEveryActivePhaseIncludingRestorationRefusesBeforeNativeCallbacks() throws {
        try fixture { f in
            let job = try job(f); var create = true
            for phase in Record.Phase.allCases where phase != .restored {
                try retain(record(f, phase: phase), f, create: create); create = false
                var callbacks = 0
                XCTAssertThrowsError(try RuntimeJobRegistration.reconcile(job: job, verifyCurrent: {},
                    requireMaintenanceOpen: { try self.requireOpen($0, f) }, inspect: { callbacks += 1; return .absent },
                    bootstrap: { callbacks += 1 })) { XCTAssertEqual($0 as? RuntimeActivationError, .maintenancePending) }
                XCTAssertEqual(callbacks, 0)
            }
        }
    }
    func testExactRestoredWindowPreservesMatchingAndAbsentRegistration() throws {
        try fixture { f in
            let job = try job(f); try retain(record(f, phase: .restored), f)
            var bootstraps = 0, reads = 0
            try RuntimeJobRegistration.reconcile(job: job, verifyCurrent: {}, requireMaintenanceOpen: { try self.requireOpen($0, f) },
                inspect: { .matching }, bootstrap: { XCTFail() })
            try RuntimeJobRegistration.reconcile(job: job, verifyCurrent: {}, requireMaintenanceOpen: { try self.requireOpen($0, f) },
                inspect: { reads += 1; return reads == 1 ? .absent : .matching }, bootstrap: { bootstraps += 1 })
            XCTAssertEqual(bootstraps, 1)
        }
    }
    func testOtherAccountWindowAndOtherRolesDoNotRestrictTheSelectedJob() throws {
        try fixture { f in
            let job = try job(f); try retain(record(f, foreign: true), f); try requireOpen(job, f)
            try retain(record(f), f, create: false)
            for role in [AuthorityCodeRole.transport, .notificationGateway] { try requireOpen(self.job(f, role: role), f) }
        }
    }
    func testChangedMachineInstallationAndDirectoryCannotAdoptARestoredWindow() throws {
        try fixture { f in
            let job = try job(f)
            for change in 0..<3 {
                try retain(record(f, phase: .restored, badMac: change == 0, badInstallation: change == 1, badDirectory: change == 2), f, create: change == 0)
                XCTAssertThrowsError(try requireOpen(job, f)) { XCTAssertEqual($0 as? RuntimePreparationError, .changedScope) }
            }
        }
    }
    func testChangedJobAccountBundleAndInstallationCannotUseAnAbsentWindow() throws {
        try fixture { f in
            XCTAssertThrowsError(try requireOpen(job(f, account: data(99)), f))
            XCTAssertThrowsError(try requireOpen(job(f, bundle: "/private/other.app"), f))
            XCTAssertThrowsError(try f.machine().requireRuntimeMaintenanceBootstrap(job(f), installationID: data(99)))
        }
    }
    func testCorruptIndexedRowRefusesBeforeInspectionOrBootstrap() throws {
        try fixture { f in
            let job = try job(f); try retain(record(f), f)
            try f.mutate("UPDATE runtime_maintenance_windows_v1 SET revision=randomblob(16)")
            XCTAssertThrowsError(try RuntimeJobRegistration.reconcile(job: job, verifyCurrent: {},
                requireMaintenanceOpen: { try self.requireOpen($0, f) }, inspect: { XCTFail(); return .absent }, bootstrap: { XCTFail() }))
        }
    }
    func testWindowAppearingAfterPreflightStopsBeforeBootstrap() throws {
        try fixture { f in
            let job = try job(f), window = try record(f)
            var reads = 0
            XCTAssertThrowsError(try RuntimeJobRegistration.reconcile(job: job, verifyCurrent: {},
                requireMaintenanceOpen: { try self.requireOpen($0, f) }, inspect: {
                    reads += 1; try self.retain(window, f); return .absent
                }, bootstrap: { XCTFail() })) { XCTAssertEqual($0 as? RuntimeActivationError, .maintenancePending) }
            XCTAssertEqual(reads, 1)
        }
    }
    func testWindowAppearingAfterBootstrapPreventsRegistrationConfirmation() throws {
        try fixture { f in
            let job = try job(f), window = try record(f); var inspections = 0
            XCTAssertThrowsError(try RuntimeJobRegistration.reconcile(job: job, verifyCurrent: {},
                requireMaintenanceOpen: { try self.requireOpen($0, f) }, inspect: { inspections += 1; return .absent },
                bootstrap: { try self.retain(window, f) })) { XCTAssertEqual($0 as? RuntimeActivationError, .maintenancePending) }
            XCTAssertEqual(inspections, 1)
        }
    }
    func testTheProtectedStoreClosesBeforeNativeContinuationAndConfigurationFailure() throws {
        try fixture { f in
            let job = try job(f), installation = try XCTUnwrap(f.machine().inventory()).installationID
            try RuntimeMaintenanceBootstrapGuard.requireOpen(job, installationID: installation, openMachine: { f.machine() },
                verifyConfiguration: { XCTAssertThrowsError(try f.machine().inventory()) })
            try f.reopen()
            XCTAssertThrowsError(try RuntimeMaintenanceBootstrapGuard.requireOpen(job, installationID: installation,
                openMachine: { f.machine() }, verifyConfiguration: { throw Fault.configuration }))
            XCTAssertThrowsError(try f.machine().inventory())
        }
    }
    func testNativeGuardRefusesOrdinaryUsersBeforeReadingProtectedConfiguration() throws {
        try fixture { f in
            XCTAssertThrowsError(try RuntimeMaintenanceBootstrapGuard.requireNativeOpen(job(f))) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        }
    }

    func testAnotherWriterOpensDuringEverySimulatedNativeCallback() throws {
        try fixture { f in
            let job = try job(f), inventory = try XCTUnwrap(f.machine().inventory())
            let anchor = URL(fileURLWithPath: f.databasePath).deletingLastPathComponent().deletingLastPathComponent().path
            try f.machine().close()
            func fresh() throws -> PreparationIntentStore {
                try .init(lease: InstallationStorageLease(anchor: anchor, relativeDirectory: "machine", owner: getuid()),
                    macID: inventory.macID, maximumRecords: 64, initialize: false)
            }
            var callbacks = 0, inspections = 0
            func anotherWriter() throws {
                let other = try fresh(); defer { try? other.close() }
                XCTAssertEqual(try other.inventory()?.installationID, inventory.installationID)
                callbacks += 1; try other.close()
            }
            try RuntimeJobRegistration.reconcile(job: job, verifyCurrent: {}, requireMaintenanceOpen: {
                try RuntimeMaintenanceBootstrapGuard.requireOpen($0, installationID: inventory.installationID,
                    openMachine: fresh, verifyConfiguration: {})
            }, inspect: {
                try anotherWriter(); inspections += 1; return inspections == 1 ? .absent : .matching
            }, bootstrap: { try anotherWriter() })
            XCTAssertEqual(callbacks, 3)
        }
    }
    func testUncertainStoreOpeningNeverLooksLikeAnAbsentWindow() throws {
        try fixture { f in
            let job = try job(f), installation = try XCTUnwrap(f.machine().inventory()).installationID
            XCTAssertThrowsError(try RuntimeJobRegistration.reconcile(job: job, verifyCurrent: {}, requireMaintenanceOpen: {
                try RuntimeMaintenanceBootstrapGuard.requireOpen($0, installationID: installation,
                    openMachine: { throw Fault.configuration }, verifyConfiguration: { XCTFail() })
            }, inspect: { XCTFail(); return .absent }, bootstrap: { XCTFail() })) {
                XCTAssertTrue($0 is Fault)
            }
        }
    }
    func testOtherRolesDoNotReadTheMachineStore() throws {
        try fixture { f in
            for role in [AuthorityCodeRole.transport, .notificationGateway] {
                try RuntimeMaintenanceBootstrapGuard.requireOpen(job(f, role: role), installationID: data(99),
                    openMachine: { XCTFail(); throw Fault.configuration }, verifyConfiguration: { XCTFail() })
            }
        }
    }
}
