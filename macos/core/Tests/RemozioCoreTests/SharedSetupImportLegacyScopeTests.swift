import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Trusted owned-file fixtures exercise isolation guards. They prove no native administrator or Root admission.
final class SharedSetupImportLegacyScopeTests: XCTestCase {
    func testAbsentImportDoesNotCreateStorageOrChangeLegacyDefaults() throws {
        let f = try SharedSetupImportFixture(), machine = try f.accountFixture.open()
        defer { try? machine.close() }
        try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: machine, account: f.account)
        XCTAssertNil(try SharedSetupImportGatewayScope.completedDefaults(machine: machine, account: f.account))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.accountFixture.root.path + "/machine/SharedSetupImport"))
    }
    func testPendingMarkersBlockLegacyChangesAndCompletedHistoryRetainsDefaults() throws {
        let f = try SharedSetupImportFixture(relativeDirectory: "machine/SharedSetupImport")
        let machine = try f.accountFixture.open(); defer { try? machine.close() }
        var current = try f.intent()
        let first = try f.open(initialize: true); try first.begin(current); try first.close()
        for next in [SharedSetupImportIntent.Phase.runtimePublished, .gatewayPrepared, .relayPrepared, .rootComplete] {
            XCTAssertThrowsError(try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: machine, account: f.account)) {
                XCTAssertEqual($0 as? SharedSetupImportError, .conflict)
            }
            XCTAssertThrowsError(try SharedSetupImportGatewayScope.completedDefaults(machine: machine, account: f.account))
            let journal = try f.open(); current = try journal.advance(current, to: next); try journal.close()
        }
        try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: machine, account: f.account)
        XCTAssertEqual(try SharedSetupImportGatewayScope.completedDefaults(machine: machine, account: f.account)?.bytes,
            try f.proposal().defaults.gateway?.bytes)
    }
    func testBusyAndForeignJournalsAreErrorsInsteadOfPermissionToMutate() throws {
        let f = try SharedSetupImportFixture(relativeDirectory: "machine/SharedSetupImport")
        let machine = try f.accountFixture.open(); defer { try? machine.close() }
        let journal = try f.open(initialize: true); try journal.begin(f.intent())
        XCTAssertThrowsError(try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: machine, account: f.account)) {
            XCTAssertEqual($0 as? JournalLeaseError, .busy)
        }
        try journal.close()
        let g = try SharedSetupImportFixture(relativeDirectory: "machine/SharedSetupImport")
        let foreign = try g.open(initialize: true, macID: Data(repeating: 0x72, count: 16)); try foreign.close()
        let other = try g.accountFixture.open(); defer { try? other.close() }
        XCTAssertThrowsError(try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: other, account: g.account))
    }
    func testGatewaySettingsOwnerRejectsAPendingImportBeforeEnteringTheBackend() throws {
        let h = try GatewaySettingsSetupOwnerTests.Harness(), expected = try h.read()
        let machine = try h.ready.fixture.runtime.f.open()
        let account = try XCTUnwrap(machine.accountPreparation(ownerUID: getuid()))
        let inventory = try XCTUnwrap(machine.inventory())
        let proposal = try PortableSetup(defaults: .init(presence: .init(idleMilliseconds: 420_000,
            observationLifetimeMilliseconds: 5000, unavailableGraceMilliseconds: 30_000), gateway: h.selection))
        let intent = try SharedSetupImportIntent(scope: .init(account: account, inventory: inventory), proposal: proposal)
        // Only this trusted storage fixture can inject a pending record beside an existing runtime.
        // The import owner must reject starting that combination through its normal admission path.
        _ = try machine.publishSharedImport(intent, verifyCurrent: {}, didStage: { _ in })
        try machine.close()
        XCTAssertThrowsError(try h.owner.retainGatewaySettings(callerUID: getuid(), expected: expected, selection: h.selection)) {
            XCTAssertEqual($0 as? SharedSetupImportError, .conflict)
        }
        XCTAssertEqual(h.backend.state.withLock { $0.entered }, 0)
        XCTAssertEqual(try h.read(), expected)
    }
}
