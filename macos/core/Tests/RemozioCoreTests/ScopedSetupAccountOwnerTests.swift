import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class ScopedSetupAccountOwnerTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Fixture {
        let root: URL
        let mac = Data(repeating: 1, count: 16)
        let account = Data(repeating: 2, count: 16)
        let release = Data(repeating: 8, count: 32)
        init() throws {
            root = URL(fileURLWithPath: "/private/tmp/remozio-scoped-machine-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o700) == 0 else { throw JournalLeaseError.system(errno) }
            try prepare()
        }
        func prepare(installation: UInt8 = 5) throws {
            let directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: "machine", owner: getuid())
            defer { directory.close() }
            _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .installation, owner: getuid())
            let machine = try open(initialize: true); defer { try? machine.close() }
            try machine.upgradeInventoryStorage()
            _ = try machine.writeInventory(.init(macID: mac, installationID: Data(repeating: installation, count: 16),
                revision: Data(repeating: 6, count: 16), bundlePath: "/Library/Remozio/Remozio.app", releaseDigest: release,
                accounts: [.init(accountID: account, ownerUID: getuid())], services: [.init(role: .authority, kind: .daemon,
                    domainUID: nil, executionUID: 0, label: "dev.remozio.authority", plistName: "dev.remozio.authority.plist", accountID: account)]),
                expectedRevision: nil)
        }
        func open(initialize: Bool = false, didCommit: (() throws -> Void)? = nil) throws -> PreparationIntentStore {
            try .init(lease: InstallationStorageLease(anchor: root.path, relativeDirectory: "machine", owner: getuid()),
                macID: mac, maximumRecords: 10, initialize: initialize, didCommit: didCommit)
        }
        func owner(verify: @escaping (InstallationInventory) throws -> Void = { _ in },
                   resume: @escaping (PreparationIntentStore, AuthorityInitializationIntent) throws -> AuthorityInitializationIntent = { _, _ in throw Interrupted() }) throws -> SetupAccountOwner {
            try .init(openMachine: { try self.open() }, expectedReleaseDigest: release, resume: resume, verifyHost: verify)
        }
        func begin() throws -> AuthorityInitializationIntent {
            let machine = try open(); defer { try? machine.close() }
            let limits = try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
            let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
                0: .unsigned(1), 1: .bytes(mac), 2: .bytes(account), 3: .bytes(Data(repeating: 3, count: 16)),
                4: .unsigned(1), 5: .unsigned(1), 6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
            let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 3)
            let policy = try AuthorityCodePolicy(entries: [.init(role: .authority, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.authority",
                installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 4, count: 20), active: true)])
            let initial = AuthorityJournalInitialization(descriptor: descriptor, codePolicy: policy,
                capabilities: .init(contracts: [contract: []]), allowedContracts: [contract], installCommandReplay: true)
            let inventory = try XCTUnwrap(machine.inventory())
            return try machine.beginInitialization(initial: initial, journalPath: root.path + "/journal/journal.sqlite",
                continuityPath: root.path + "/continuity/continuity.sqlite", expectedInventoryRevision: inventory.revision)
        }
        func change(releaseDigest: Data? = nil, ownerUID: uid_t? = nil) throws {
            let machine = try open(); defer { try? machine.close() }
            let current = try XCTUnwrap(machine.inventory())
            _ = try machine.writeInventory(.init(macID: current.macID, installationID: current.installationID,
                revision: current.revision, bundlePath: current.bundlePath, releaseDigest: releaseDigest ?? current.releaseDigest,
                accounts: [.init(accountID: account, ownerUID: ownerUID ?? getuid())], services: current.services),
                expectedRevision: current.revision)
        }
        func requireAvailableWriter() throws {
            let machine = try open(); defer { try? machine.close() }
            XCTAssertNotNil(try machine.inventory())
        }
        func close() { try? FileManager.default.removeItem(at: root) }
    }
    private func fixture(_ body: (Fixture) throws -> Void) throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Same-owner protected storage") }
        let f = try Fixture(); defer { f.close() }; try body(f)
    }
    func testIdleOwnersReleaseTheActualWriterAndReadFreshProgress() throws {
        try fixture { f in
            let one = try f.owner(), two = try f.owner()
            defer { try? one.close(); try? two.close() }
            try f.requireAvailableWriter()
            try one.verifyCurrent(); try two.verifyCurrent()
            XCTAssertNil(try one.progress(accountID: f.account, callerUID: getuid()))
            let expected = try f.begin()
            XCTAssertEqual(try two.progress(accountID: f.account, callerUID: getuid()), expected)
            XCTAssertEqual(try one.progress(accountID: f.account, callerUID: getuid()), expected)
            try f.requireAvailableWriter()
        }
    }
    func testAnOperationRetainsTheSingleWriterUntilHostVerificationFinishes() throws {
        try fixture { f in
            var checks = 0
            let owner = try f.owner(verify: { _ in
                checks += 1
                XCTAssertThrowsError(try f.open()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            })
            defer { try? owner.close() }
            try owner.verifyCurrent(); XCTAssertEqual(checks, 1)
            try f.requireAvailableWriter()
        }
    }
    func testHostFailureReleasesTheWriterAndAllowsFreshRecovery() throws {
        try fixture { f in
            var reject = true
            let owner = try f.owner(verify: { _ in if reject { throw Interrupted() } })
            defer { try? owner.close() }
            XCTAssertThrowsError(try owner.verifyCurrent())
            try f.requireAvailableWriter()
            reject = false
            XCTAssertNoThrow(try owner.verifyCurrent())
        }
    }
    func testWriterContentionDoesNotCloseTheOtherOwnerOrPoisonSetup() throws {
        try fixture { f in
            let owner = try f.owner(); defer { try? owner.close() }
            let other = try f.open()
            XCTAssertThrowsError(try owner.verifyCurrent()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            XCTAssertNotNil(try other.inventory()); try other.close()
            XCTAssertNoThrow(try owner.verifyCurrent())
        }
    }
    func testClosingAnIdleOwnerDoesNotReleaseAnotherOperationsWriter() throws {
        try fixture { f in
            let idle = try f.owner()
            let active = try f.owner(verify: { _ in
                try idle.close()
                XCTAssertThrowsError(try f.open()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            })
            defer { try? active.close() }
            try active.verifyCurrent()
            XCTAssertThrowsError(try idle.verifyCurrent()) { XCTAssertEqual($0 as? AdministrativeSetupError, .unavailable) }
            try f.requireAvailableWriter()
        }
    }
    func testEachOperationRejectsChangedReleaseAndAccountOwnership() throws {
        for changeRelease in [false, true] { try fixture { f in
            let owner = try f.owner(); defer { try? owner.close() }
            if changeRelease { try f.change(releaseDigest: Data(repeating: 9, count: 32)) }
            else { try f.change(ownerUID: getuid() + 1) }
            XCTAssertThrowsError(try owner.progress(accountID: f.account, callerUID: getuid())) {
                XCTAssertEqual($0 as? AdministrativeSetupError, changeRelease ? .changedInstallation : .wrongAccount)
            }
            try f.requireAvailableWriter()
        } }
    }
    func testReplacedMachineIdentityIsNotAdoptedByAnIdleOwner() throws {
        try fixture { f in
            let owner = try f.owner(); defer { try? owner.close() }
            try FileManager.default.moveItem(at: f.root.appendingPathComponent("machine"), to: f.root.appendingPathComponent("old-machine"))
            try f.prepare(installation: 9)
            XCTAssertThrowsError(try owner.verifyCurrent()) { XCTAssertEqual($0 as? AdministrativeSetupError, .changedInstallation) }
            try f.requireAvailableWriter()
        }
    }
    func testControllerFailureReleasesWriterAndPreservesTheRetainedIntent() throws {
        try fixture { f in
            let expected = try f.begin()
            var calls = 0
            let owner = try f.owner(resume: { _, actual in
                calls += 1; XCTAssertEqual(actual, expected)
                XCTAssertThrowsError(try f.open()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
                throw Interrupted()
            })
            defer { try? owner.close() }
            XCTAssertThrowsError(try owner.resumeAccount(accountID: expected.accountID, setupID: expected.setupID,
                expectedRevision: expected.revision, callerUID: getuid()))
            XCTAssertEqual(calls, 1)
            let machine = try f.open(); defer { try? machine.close() }
            XCTAssertEqual(try machine.initialization(accountID: f.account), expected)
        }
    }
    func testClosedOwnerNeverOpensAnotherConnection() throws {
        try fixture { f in
            var opened = 0
            let owner = try SetupAccountOwner(openMachine: { opened += 1; return try f.open() },
                expectedReleaseDigest: f.release, resume: { _, _ in throw Interrupted() })
            XCTAssertEqual(opened, 1); try owner.close()
            XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertEqual(opened, 1)
            try f.requireAvailableWriter()
        }
    }
    private func receivePort() throws -> mach_port_t {
        var port = mach_port_t(MACH_PORT_NULL)
        guard mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &port) == KERN_SUCCESS else { throw Interrupted() }
        return port
    }
    func testSuccessfulCheckInReleasesOnlyMachineWriterAndTransfersLiveReceiveRight() throws {
        try fixture { f in
            let setup = try f.owner(); defer { try? setup.close() }
            let machine = try f.open()
            let journalDirectory = try ProtectedSetupDirectory(anchor: f.root.path, relativePath: "journal", owner: getuid())
            _ = try SetupDatabaseFileProvisioning.prepare(directory: journalDirectory, kind: .journal, owner: getuid())
            journalDirectory.close()
            let journal = try ProtectedJournalLease(anchor: f.root.path, relativeDirectory: "journal", owner: getuid())
            defer { journal.close() }
            let port = try InstalledCommandMachineHandoff.take(machine: machine) {
                XCTAssertThrowsError(try f.open()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
                XCTAssertThrowsError(try setup.verifyCurrent()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
                return try self.receivePort()
            }
            defer { _ = mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1) }
            try f.requireAvailableWriter(); try setup.verifyCurrent()
            XCTAssertThrowsError(try machine.inventory())
            var kind: mach_port_type_t = 0
            XCTAssertEqual(mach_port_type(mach_task_self_, port, &kind), KERN_SUCCESS)
            var references: mach_port_urefs_t = 0
            XCTAssertEqual(mach_port_get_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, &references), KERN_SUCCESS)
            XCTAssertEqual(references, 1)
            XCTAssertThrowsError(try ProtectedJournalLease(anchor: f.root.path, relativeDirectory: "journal", owner: getuid())) {
                XCTAssertEqual($0 as? JournalLeaseError, .busy)
            }
            try journal.validate()
        }
    }
    func testCommandFirstStartupAllowsSetupAfterValidatedHandoff() throws {
        try fixture { f in
            let machine = try f.open()
            XCTAssertThrowsError(try f.owner()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            let port = try InstalledCommandMachineHandoff.take(machine: machine) { try self.receivePort() }
            defer { _ = mach_port_mod_refs(mach_task_self_, port, MACH_PORT_RIGHT_RECEIVE, -1) }
            let setup = try f.owner(); defer { try? setup.close() }
            XCTAssertNoThrow(try setup.verifyCurrent())
            try f.requireAvailableWriter()
        }
    }
    func testRestartedSetupOwnerReadsTheSameInstallationAndIntent() throws {
        try fixture { f in
            let expected = try f.begin()
            let first = try f.owner()
            XCTAssertEqual(try first.progress(accountID: f.account, callerUID: getuid()), expected)
            try first.close()
            let restarted = try f.owner(); defer { try? restarted.close() }
            XCTAssertEqual(try restarted.progress(accountID: f.account, callerUID: getuid()), expected)
            try f.requireAvailableWriter()
        }
    }
    func testFailedCheckInKeepsWriterForTheExistingStartupCleanupOwner() throws {
        try fixture { f in
            let machine = try f.open()
            XCTAssertThrowsError(try InstalledCommandMachineHandoff.take(machine: machine) { throw Interrupted() })
            XCTAssertThrowsError(try f.open()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            XCTAssertNotNil(try machine.inventory())
            try machine.close(); try f.requireAvailableWriter()
        }
    }
    func testFailedStoreReleaseDisposesTheUntransferredReceiveRight() throws {
        try fixture { f in
            var duringCommit: (() throws -> Void)?
            let machine = try f.open(didCommit: { try duringCommit?() }); defer { try? machine.close() }
            let current = try XCTUnwrap(machine.inventory())
            var port = mach_port_t(MACH_PORT_NULL)
            duringCommit = {
                XCTAssertThrowsError(try InstalledCommandMachineHandoff.take(machine: machine) {
                    port = try self.receivePort(); return port
                }) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
            }
            _ = try machine.writeInventory(current, expectedRevision: current.revision)
            duringCommit = nil
            var kind: mach_port_type_t = 0
            XCTAssertEqual(mach_port_type(mach_task_self_, port, &kind), KERN_INVALID_NAME)
            XCTAssertNotNil(try machine.inventory())
        }
    }
    func testMachineSQLiteFailuresKeepTheirExistingTransientOrPermanentMeaning() {
        for code in [SQLITE_BUSY, SQLITE_LOCKED, SQLITE_IOERR, SQLITE_FULL, SQLITE_NOMEM, SQLITE_INTERRUPT] {
            XCTAssertEqual(AuthorityStartupFailure(error: PreparationStoreError.storage(code)), .temporaryStorageFailure)
        }
        for error in [PreparationStoreError.wrongMac, .incompatibleStore, .corruptRecord, .storage(SQLITE_CORRUPT), .storage(SQLITE_NOTADB)] {
            XCTAssertEqual(AuthorityStartupFailure(error: error), .configurationFailure)
        }
    }
}
