import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class AuthorityUpdateAdmissionStartupTests: XCTestCase {
    // These scope tests use a fixed reader. The recovery suite exercises actual short machine leases.
    private func reader(_ f: BoundAdmissionRegistrationFixture) throws -> @Sendable () throws -> MachineUpdateAdmissionState {
        let snapshot = try f.machine.store.updateAdmissionState()
        return { snapshot }
    }
    private func capture(_ f: BoundAdmissionRegistrationFixture, account: Data? = nil) throws -> AuthorityUpdateAdmissionStartup? {
        let inventory = try XCTUnwrap(f.machine.store.inventory())
        return try .capture(machine: f.machine.store, macID: f.machine.mac, installationID: inventory.installationID,
            accountID: account ?? f.machine.account, activity: f.activity(), readCurrent: reader(f), openBarrier: { scope, identity in
                try UpdateAdmissionBarrier(directory: f.directory(), owner: getuid(), expected: identity, scope: scope)
            })
    }
    private func barrier(_ f: BoundAdmissionRegistrationFixture, _ record: UpdateAdmissionRegistrationRecord,
        _ scope: UpdateAdmissionScope) throws -> UpdateAdmissionBarrier {
        let identity: PreparationFileIdentity
        switch scope {
        case .machine: identity = record.machine
        case .account(let id): identity = try XCTUnwrap(record.accounts.first { $0.accountID == id }).identity
        }
        return try .init(directory: f.directory(), owner: getuid(), expected: identity, scope: scope)
    }
    func testCapturedAdmissionSurvivesTheClosedStartupWriter() throws {
        let f = try BoundAdmissionRegistrationFixture(), record = try f.prepare(), selected = try XCTUnwrap(capture(f))
        XCTAssertEqual(selected.registration, record); XCTAssertEqual(selected.boundary.accountID, f.machine.account)
        try f.machine.store.close()
        let admitted = try selected.boundary.acquireAdmission(); try admitted.validate(); admitted.close()
        XCTAssertThrowsError(try selected.requireCurrent(machine: f.machine.store))
    }
    func testAbsentRegistrationDoesNotOpenFilesOrMigrateStorage() throws {
        let f = try BoundAdmissionRegistrationFixture(enable: false), inventory = try XCTUnwrap(f.machine.store.inventory())
        XCTAssertNil(try AuthorityUpdateAdmissionStartup.capture(machine: f.machine.store, macID: f.machine.mac,
            installationID: inventory.installationID, accountID: f.machine.account, activity: f.activity(), readCurrent: reader(f), openBarrier: { _, _ in
                XCTFail("Absent registration opened a file"); throw JournalLeaseError.invalidated
            }))
        XCTAssertEqual(try f.machine.store.retainedRuntimeCompatibilityInputs().schemaVersion, 15)
    }
    func testAccountDrainStopsOnlyItsAccountAndMachineDrainStopsBoth() throws {
        let f = try BoundAdmissionRegistrationFixture(), first = try f.prepare(), other = Data(repeating: 91, count: 16)
        try f.addAccount(other); let record = try f.prepare(accountID: other, replacing: first)
        let a = try XCTUnwrap(capture(f)), b = try XCTUnwrap(capture(f, account: other))
        let drain = try barrier(f, record, .account(f.machine.account)).beginDrain()
        XCTAssertThrowsError(try a.boundary.acquireAdmission()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        let admitted = try b.boundary.acquireAdmission(); try admitted.validate(); admitted.close(); drain.close()
        let global = try barrier(f, record, .machine).beginDrain()
        XCTAssertThrowsError(try a.boundary.acquireAdmission()); XCTAssertThrowsError(try b.boundary.acquireAdmission())
        global.close(); let resumed = try a.boundary.acquireAdmission(); resumed.close()
    }
    func testFailedAccountAdmissionReleasesItsTemporaryMachineToken() throws {
        let f = try BoundAdmissionRegistrationFixture(), record = try f.prepare(), selected = try XCTUnwrap(capture(f))
        let accountDrain = try barrier(f, record, .account(f.machine.account)).beginDrain()
        defer { accountDrain.close() }
        XCTAssertThrowsError(try selected.boundary.acquireAdmission())
        let machineDrain = try barrier(f, record, .machine).beginDrain(); try machineDrain.validate(); machineDrain.close()
    }
    func testLeaseDeinitReleasesBothScopesAndCloseIsIdempotent() throws {
        let f = try BoundAdmissionRegistrationFixture(), record = try f.prepare(), selected = try XCTUnwrap(capture(f))
        var admitted: UpdateAdmissionLease? = try selected.boundary.acquireAdmission()
        XCTAssertNotNil(admitted)
        XCTAssertThrowsError(try barrier(f, record, .machine).beginDrain())
        XCTAssertThrowsError(try barrier(f, record, .account(f.machine.account)).beginDrain())
        admitted = nil
        let global = try barrier(f, record, .machine).beginDrain(), scoped = try barrier(f, record, .account(f.machine.account)).beginDrain()
        global.close(); scoped.close()
        let next = try selected.boundary.acquireAdmission(); next.close(); next.close()
        XCTAssertThrowsError(try next.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
    }
    func testEitherFileReplacementRefusesNewAdmissionWithoutAdoptingIt() throws {
        for accountScoped in [false, true] {
            let f = try BoundAdmissionRegistrationFixture(), record = try f.prepare(), selected = try XCTUnwrap(capture(f))
            let actualScope: UpdateAdmissionScope = accountScoped ? .account(f.machine.account) : .machine
            try f.replace(f.path(actualScope))
            XCTAssertThrowsError(try selected.boundary.acquireAdmission())
            XCTAssertEqual(try f.machine.store.updateAdmissionRegistration(), record)
        }
    }
    func testRestartHealthCanCaptureClosedMachineAdmissionWithoutOpeningIt() throws {
        let f = try BoundAdmissionRegistrationFixture(), record = try f.prepare()
        let drain = try barrier(f, record, .machine).beginDrain(); defer { drain.close() }
        let selected = try XCTUnwrap(capture(f)); try selected.requireCurrent(machine: f.machine.store)
        XCTAssertThrowsError(try selected.boundary.acquireAdmission()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        XCTAssertNotNil(try f.machine.store.inventory())
    }
    func testCaptureRechecksTheRegistrationAfterOpeningItsScopes() throws {
        let f = try BoundAdmissionRegistrationFixture(), first = try f.prepare(), inventory = try XCTUnwrap(f.machine.store.inventory())
        var replaced = false
        XCTAssertThrowsError(try AuthorityUpdateAdmissionStartup.capture(machine: f.machine.store, macID: f.machine.mac,
            installationID: inventory.installationID, accountID: f.machine.account, activity: f.activity(), readCurrent: reader(f), openBarrier: { scope, identity in
                if !replaced {
                    replaced = true
                    let next = try UpdateAdmissionRegistrationRecord(macID: first.macID, installationID: first.installationID,
                        machine: first.machine, accounts: first.accounts, designatedOwner: f.machine.account)
                    _ = try f.machine.store.retainUpdateAdmissionRegistration(next, replacing: first,
                        runtime: f.machine.store.retainedRuntimeCompatibilityInputs(), verifyFiles: {})
                }
                return try UpdateAdmissionBarrier(directory: f.directory(), owner: getuid(), expected: identity, scope: scope)
            })) { XCTAssertEqual($0 as? RuntimePreparationError, .changedScope) }
    }
    func testWrongInstallationAndUnknownAccountAreRejectedBeforeOpening() throws {
        let f = try BoundAdmissionRegistrationFixture(); _ = try f.prepare(); let inventory = try XCTUnwrap(f.machine.store.inventory())
        for (installation, account) in [(Data(repeating: 92, count: 16), f.machine.account),
                                        (inventory.installationID, Data(repeating: 93, count: 16))] {
            XCTAssertThrowsError(try AuthorityUpdateAdmissionStartup.capture(machine: f.machine.store, macID: f.machine.mac,
                installationID: installation, accountID: account, activity: f.activity(), readCurrent: reader(f), openBarrier: { _, _ in
                    XCTFail("Wrong scope opened admission files"); throw JournalLeaseError.invalidated
                }))
        }
    }
    func testAnUnprovisionedAccountStillUsesTheMachineBoundary() throws {
        let f = try BoundAdmissionRegistrationFixture(), record = try f.prepare(), other = Data(repeating: 94, count: 16)
        try f.addAccount(other); let selected = try XCTUnwrap(capture(f, account: other))
        XCTAssertNil(selected.boundary.accountID)
        let admitted = try selected.boundary.acquireAdmission(); admitted.close()
        let global = try barrier(f, record, .machine).beginDrain(); defer { global.close() }
        XCTAssertThrowsError(try selected.boundary.acquireAdmission())
    }
    func testScopeRolesCannotBeExchangedInACombinedBoundary() throws {
        let f = try BoundAdmissionRegistrationFixture(), record = try f.prepare()
        let global = try barrier(f, record, .machine), account = try barrier(f, record, .account(f.machine.account))
        XCTAssertThrowsError(try UpdateAdmissionBoundary(machine: account))
        XCTAssertThrowsError(try UpdateAdmissionBoundary(machine: global, account: global))
    }
    func testCaptureRejectsAForeignAccountReturnedByTheFactory() throws {
        let f = try BoundAdmissionRegistrationFixture(), first = try f.prepare(), other = Data(repeating: 95, count: 16)
        try f.addAccount(other); let record = try f.prepare(accountID: other, replacing: first)
        let inventory = try XCTUnwrap(f.machine.store.inventory())
        XCTAssertThrowsError(try AuthorityUpdateAdmissionStartup.capture(machine: f.machine.store, macID: f.machine.mac,
            installationID: inventory.installationID, accountID: f.machine.account, activity: f.activity(), readCurrent: reader(f), openBarrier: { scope, identity in
                if case .account = scope { return try self.barrier(f, record, .account(other)) }
                return try UpdateAdmissionBarrier(directory: f.directory(), owner: getuid(), expected: identity, scope: scope)
            })) { XCTAssertEqual($0 as? RuntimePreparationError, .changedScope) }
    }
}
