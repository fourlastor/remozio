import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class AuthorityAccountInitializationTests: XCTestCase {
    private struct Interrupted: Error {}
    private let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16), epoch = Data(repeating: 3, count: 16)
    private var limits: CBORLimits { get throws { try .init(maxBytes: 16384, maxDepth: 8, maxItems: 512) } }
    private func initial(replay: Bool = true, feature: UInt64? = nil) throws -> AuthorityJournalInitialization {
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(mac), 2: .bytes(account), 3: .bytes(epoch), 4: .unsigned(1),
            5: .unsigned(1), 6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 3)
        let policy = try AuthorityCodePolicy(entries: [.init(role: .authority, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.authority",
            installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 4, count: 20), active: true)])
        return .init(descriptor: descriptor, codePolicy: policy, capabilities: .init(contracts: [contract: feature.map { [$0] } ?? []]),
            allowedContracts: [contract], installCommandReplay: replay)
    }
    private func fixture(_ body: (URL) throws -> Void) throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-owner fixture") }
        let root = URL(fileURLWithPath: "/private/tmp/remozio-initialization-intent-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(root.path, 0o700), 0)
        defer { try? FileManager.default.removeItem(at: root) }
        for (name, kind): (String, SetupDatabaseKind) in [("machine", .installation), ("journal", .journal), ("continuity", .continuity)] {
            let directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: name, owner: getuid())
            defer { directory.close() }
            _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: kind, owner: getuid())
        }
        try body(root)
    }
    private func store(_ root: URL, initialize: Bool = false, hook: (() throws -> Void)? = nil) throws -> PreparationIntentStore {
        try .init(lease: InstallationStorageLease(anchor: root.path, relativeDirectory: "machine", owner: getuid()),
            macID: mac, maximumRecords: 10, initialize: initialize, didCommit: hook)
    }
    private func inventory(_ store: PreparationIntentStore, release: UInt8 = 8) throws -> InstallationInventory {
        let value = try InstallationInventory(macID: mac, installationID: Data(repeating: 5, count: 16), revision: Data(repeating: 6, count: 16),
            bundlePath: "/Library/Remozio/Remozio.app", releaseDigest: Data(repeating: release, count: 32),
            accounts: [.init(accountID: account, ownerUID: getuid())], services: [.init(role: .authority, kind: .daemon,
                domainUID: nil, executionUID: 0, label: "dev.remozio.authority", plistName: "dev.remozio.authority.plist", accountID: account)])
        try store.upgradeInventoryStorage()
        return try store.writeInventory(value, expectedRevision: nil)
    }
    private func begin(_ root: URL, _ store: PreparationIntentStore, _ inventory: InstallationInventory,
                       seed: AuthorityJournalInitialization? = nil) throws -> AuthorityInitializationIntent {
        try store.beginInitialization(initial: seed ?? initial(), journalPath: root.path + "/journal/journal.sqlite",
            continuityPath: root.path + "/continuity/continuity.sqlite", expectedInventoryRevision: inventory.revision)
    }
    private func journal(_ root: URL, seed: AuthorityJournalInitialization? = nil, recordByteLimit: Int = 16384) throws -> JournalDatabase {
        try .init(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "journal", owner: getuid()),
            macID: mac, accountID: account, recordLimits: .init(maxBytes: recordByteLimit, maxDepth: 8, maxItems: 512), descriptorLimits: limits, decisionLimits: limits,
            maximumConsumptions: 10, busyMilliseconds: 100, initialize: seed != nil, initialAuthority: seed)
    }
    private func continuity(_ root: URL, checkpoint: ContinuityCheckpoint? = nil) throws -> ContinuityStore {
        try .init(lease: ProtectedContinuityLease(anchor: root.path, relativeDirectory: "continuity", owner: getuid()),
            macID: mac, accountID: account, initialize: checkpoint)
    }
    private func sql(_ root: URL, file: String = "machine/installation.sqlite", query: String) throws -> Int64 {
        var db: OpaquePointer?
        XCTAssertEqual(sqlite3_open_v2(root.path + "/" + file, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW, nil), SQLITE_OK)
        let connection = try XCTUnwrap(db); defer { sqlite3_close(connection) }
        var statement: OpaquePointer?
        XCTAssertEqual(sqlite3_prepare_v2(connection, query, -1, &statement, nil), SQLITE_OK)
        let row = try XCTUnwrap(statement); defer { sqlite3_finalize(row) }
        let result = sqlite3_step(row)
        guard result == SQLITE_ROW || result == SQLITE_DONE else { throw PreparationStoreError.storage(result) }
        return result == SQLITE_ROW ? sqlite3_column_int64(row, 0) : 0
    }
    private func resume(_ root: URL, machine: PreparationIntentStore, expected: AuthorityInitializationIntent,
                        observe: (String) throws -> Void = { _ in },
                        hook: (AuthorityAccountInitialization.Stage) throws -> Void = { _ in }) throws -> AuthorityInitializationIntent {
        let journalRelative = String((expected.journalPath as NSString).deletingLastPathComponent.dropFirst(root.path.count + 1))
        let continuityRelative = String((expected.continuityPath as NSString).deletingLastPathComponent.dropFirst(root.path.count + 1))
        return try AuthorityAccountInitialization.resume(machine: machine, expected: expected,
            prepareJournal: {
                try observe("prepareJournal")
                let directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: journalRelative, owner: getuid())
                defer { directory.close() }
                _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .journal, owner: getuid())
            },
            openDirectories: {
                let journal = try ProtectedSetupDirectory(anchor: root.path, relativePath: journalRelative, owner: getuid(), createIfMissing: false)
                do {
                    return try .init(journal: journal,
                        continuity: ProtectedSetupDirectory(anchor: root.path, relativePath: continuityRelative, owner: getuid()))
                } catch { journal.close(); throw error }
            },
            openJournal: { initialize, seed, scope in
                try observe(initialize ? "initializeJournal" : "openJournal")
                let lease = try ProtectedJournalLease(anchor: root.path, relativeDirectory: journalRelative, owner: getuid())
                do { try scope.validate(journal: lease) } catch { lease.close(); throw error }
                return try JournalDatabase(lease: lease,
                    macID: expected.macID, accountID: expected.accountID, recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                    maximumConsumptions: 10, busyMilliseconds: 100, initialize: initialize, initialAuthority: initialize ? seed : nil)
            },
            prepareContinuity: {
                try observe("prepareContinuity")
                let directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: continuityRelative, owner: getuid())
                defer { directory.close() }
                _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .continuity, owner: getuid())
            },
            openContinuity: { checkpoint, scope in
                try observe(checkpoint == nil ? "openContinuity" : "initializeContinuity")
                let lease = try ProtectedContinuityLease(anchor: root.path, relativeDirectory: continuityRelative, owner: getuid())
                do { try scope.validate(continuity: lease) } catch { lease.close(); throw error }
                return try ContinuityStore(lease: lease,
                    macID: expected.macID, accountID: expected.accountID, initialize: checkpoint)
            }, didStage: hook)
    }
    private func requireReleasedAccountLeases(_ root: URL) throws {
        let journal = try ProtectedJournalLease(anchor: root.path, relativeDirectory: "journal", owner: getuid())
        defer { journal.close() }
        let continuity = try ProtectedContinuityLease(anchor: root.path, relativeDirectory: "continuity", owner: getuid())
        continuity.close()
    }
    func testCompleteCompositionProvisionsInitializesAndReopensBothActualStores() throws {
        try fixture { root in
            let machine = try store(root, initialize: true), inventory = try inventory(machine)
            let expected = try begin(root, machine, inventory)
            for path in ["journal/journal.sqlite", "continuity/continuity.sqlite"] {
                try FileManager.default.removeItem(at: root.appendingPathComponent(path))
            }
            var steps = [String]()
            let completed = try resume(root, machine: machine, expected: expected, observe: { steps.append($0) })
            XCTAssertTrue(completed.complete)
            XCTAssertEqual(steps.filter { $0 == "initializeJournal" }.count, 1)
            XCTAssertEqual(steps.filter { $0 == "initializeContinuity" }.count, 1)
            try requireReleasedAccountLeases(root)
            try machine.close()
            let restored = try store(root); defer { try? restored.close() }
            XCTAssertEqual(try restored.initialization(accountID: account), completed)
            let journal = try journal(root); defer { try? journal.close() }
            let continuity = try continuity(root); defer { continuity.close() }
            XCTAssertEqual(try JournalCheckpointRecovery.reconcile(journal: journal, continuity: continuity), .unchanged(try XCTUnwrap(completed.checkpoint)))
            XCTAssertTrue(try journal.read { try $0.approvalTrustSnapshot().enrollments.isEmpty })
        }
    }
    func testEveryStageInterruptionReleasesStoresAndResumesRetainedProgress() throws {
        for stage in AuthorityAccountInitialization.Stage.allCases {
            try fixture { root in
                let machine = try store(root, initialize: true), inventory = try inventory(machine)
                let expected = try begin(root, machine, inventory)
                XCTAssertThrowsError(try resume(root, machine: machine, expected: expected, hook: {
                    if $0 == stage { throw Interrupted() }
                })) { XCTAssertTrue($0 is Interrupted) }
                try requireReleasedAccountLeases(root)
                try machine.close()
                let restored = try store(root); defer { try? restored.close() }
                let retained = try XCTUnwrap(restored.initialization(accountID: account))
                var initialized = [String]()
                let completed = try resume(root, machine: restored, expected: retained, observe: {
                    if $0.hasPrefix("initialize") { initialized.append($0) }
                })
                XCTAssertTrue(completed.complete)
                if stage != .journalProvisioned && stage != .directoriesOpened { XCTAssertFalse(initialized.contains("initializeJournal")) }
                if stage == .continuityOpened || stage == .completed { XCTAssertFalse(initialized.contains("initializeContinuity")) }
                try requireReleasedAccountLeases(root)
            }
        }
    }
    func testCompletedIntentNeverReinitializesOrRepairsAccountStorage() throws {
        try fixture { root in
            let machine = try store(root, initialize: true); defer { try? machine.close() }
            let inventory = try inventory(machine), expected = try begin(root, machine, inventory)
            let completed = try resume(root, machine: machine, expected: expected)
            let changed = Data("retained storage requires separate repair".utf8)
            try changed.write(to: root.appendingPathComponent("journal/journal.sqlite"))
            XCTAssertEqual(try resume(root, machine: machine, expected: completed, observe: { _ in throw Interrupted() }), completed)
            XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("journal/journal.sqlite")), changed)
        }
    }
    func testStaleIntentAndChangedReleaseRefuseBeforeAnyAccountFactory() throws {
        try fixture { root in
            let machine = try store(root, initialize: true); defer { try? machine.close() }
            let inventory = try inventory(machine), expected = try begin(root, machine, inventory)
            let completed = try resume(root, machine: machine, expected: expected)
            XCTAssertThrowsError(try resume(root, machine: machine, expected: expected, observe: { _ in XCTFail("Account storage accessed") })) {
                XCTAssertEqual($0 as? AuthorityInitializationError, .staleRevision)
            }
            let changed = try InstallationInventory(macID: inventory.macID, installationID: inventory.installationID, revision: inventory.revision,
                bundlePath: inventory.bundlePath, releaseDigest: Data(repeating: 9, count: 32), accounts: inventory.accounts, services: inventory.services)
            _ = try machine.writeInventory(changed, expectedRevision: inventory.revision)
            XCTAssertThrowsError(try resume(root, machine: machine, expected: completed, observe: { _ in XCTFail("Account storage accessed") })) {
                XCTAssertEqual($0 as? AuthorityInitializationError, .conflictingIntent)
            }
        }
    }
    func testReleaseChangeBetweenStagesStopsBeforeJournalInitialization() throws {
        try fixture { root in
            let machine = try store(root, initialize: true); defer { try? machine.close() }
            let inventory = try inventory(machine), expected = try begin(root, machine, inventory)
            XCTAssertThrowsError(try resume(root, machine: machine, expected: expected, hook: { stage in
                if stage == .journalProvisioned {
                    let changed = try InstallationInventory(macID: inventory.macID, installationID: inventory.installationID, revision: inventory.revision,
                        bundlePath: inventory.bundlePath, releaseDigest: Data(repeating: 9, count: 32), accounts: inventory.accounts, services: inventory.services)
                    _ = try machine.writeInventory(changed, expectedRevision: inventory.revision)
                }
            })) { XCTAssertEqual($0 as? AuthorityInitializationError, .conflictingIntent) }
            XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("journal/journal.sqlite")), Data())
            XCTAssertEqual(try machine.initialization(accountID: account), expected)
        }
    }
    func testCapturedJournalLossCannotRecreateOrReinitializeIt() throws {
        for loss in ["emptyFile", "missingFile", "missingDirectory"] {
            try fixture { root in
                let machine = try store(root, initialize: true); defer { try? machine.close() }
                let inventory = try inventory(machine), expected = try begin(root, machine, inventory)
                XCTAssertThrowsError(try resume(root, machine: machine, expected: expected, hook: {
                    if $0 == .checkpointCaptured { throw Interrupted() }
                }))
                let retained = try XCTUnwrap(machine.initialization(accountID: account))
                XCTAssertNotNil(retained.checkpoint)
                let path = root.appendingPathComponent("journal/journal.sqlite")
                if loss == "missingDirectory" { try FileManager.default.removeItem(at: root.appendingPathComponent("journal")) }
                else if loss == "missingFile" { try FileManager.default.removeItem(at: path) }
                else { try Data().write(to: path) }
                var steps = [String]()
                XCTAssertThrowsError(try resume(root, machine: machine, expected: retained, observe: { steps.append($0) }))
                XCTAssertEqual(steps, loss == "missingDirectory" ? [] : ["openJournal"])
                XCTAssertEqual(FileManager.default.fileExists(atPath: path.path), loss == "emptyFile")
                if loss == "emptyFile" { XCTAssertEqual(try Data(contentsOf: path), Data()) }
                if loss == "missingDirectory" { XCTAssertFalse(FileManager.default.fileExists(atPath: root.path + "/journal")) }
                XCTAssertEqual(try machine.initialization(accountID: account), retained)
            }
        }
    }
    func testUnknownRetainedJournalRefusesInitializationAndPreservesBytes() throws {
        try fixture { root in
            let machine = try store(root, initialize: true); defer { try? machine.close() }
            let inventory = try inventory(machine), seed = try initial(), expected = try begin(root, machine, inventory, seed: seed)
            let existing = try journal(root, seed: seed); try existing.close()
            _ = try sql(root, file: "journal/journal.sqlite", query: "PRAGMA user_version=99")
            let before = try Data(contentsOf: root.appendingPathComponent("journal/journal.sqlite"))
            XCTAssertThrowsError(try resume(root, machine: machine, expected: expected))
            XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("journal/journal.sqlite")), before)
            XCTAssertEqual(try machine.initialization(accountID: account), expected)
            XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("continuity/continuity.sqlite")), Data())
            try requireReleasedAccountLeases(root)
        }
    }
    func testExistingMismatchedContinuityIsNeverReplacedOrMarkedRepaired() throws {
        try fixture { root in
            let machine = try store(root, initialize: true); defer { try? machine.close() }
            let inventory = try inventory(machine), expected = try begin(root, machine, inventory)
            XCTAssertThrowsError(try resume(root, machine: machine, expected: expected, hook: {
                if $0 == .checkpointCaptured { throw Interrupted() }
            }))
            let retained = try XCTUnwrap(machine.initialization(accountID: account)), original = try XCTUnwrap(retained.checkpoint)
            let wrong = try ContinuityCheckpoint(generation: 2, authorityDigest: original.authorityDigest, ledgerDigest: original.ledgerDigest,
                journalEpoch: original.journalEpoch, journalHead: original.journalHead, authorityGeneration: 1)
            let other = try continuity(root, checkpoint: wrong); other.close()
            let before = try Data(contentsOf: root.appendingPathComponent("continuity/continuity.sqlite"))
            var steps = [String]()
            XCTAssertThrowsError(try resume(root, machine: machine, expected: retained, observe: { steps.append($0) }))
            XCTAssertFalse(steps.contains("initializeContinuity"))
            XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("continuity/continuity.sqlite")), before)
            let restored = try continuity(root); defer { restored.close() }
            XCTAssertEqual(try restored.read().committed, wrong); XCTAssertFalse(try restored.read().recoveryRequired)
            XCTAssertEqual(try machine.initialization(accountID: account), retained)
        }
    }
    func testBusyJournalDoesNotStartInitializationAndCanResumeAfterRelease() throws {
        try fixture { root in
            let machine = try store(root, initialize: true); defer { try? machine.close() }
            let inventory = try inventory(machine), expected = try begin(root, machine, inventory)
            let owner = try ProtectedJournalLease(anchor: root.path, relativeDirectory: "journal", owner: getuid())
            XCTAssertThrowsError(try resume(root, machine: machine, expected: expected)) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            XCTAssertEqual(try machine.initialization(accountID: account), expected)
            XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("journal/journal.sqlite")), Data())
            owner.close()
            XCTAssertTrue(try resume(root, machine: machine, expected: expected).complete)
        }
    }
    func testCaseAliasedNestedDirectoriesRefuseBeforeEitherDatabaseInitializes() throws {
        for nestedJournal in [false, true] {
            try fixture { root in
                guard FileManager.default.fileExists(atPath: root.path + "/JOURNAL"),
                      FileManager.default.fileExists(atPath: root.path + "/CONTINUITY") else { throw XCTSkip("Case-sensitive fixture volume") }
                let relative = nestedJournal ? "continuity/nested" : "journal/nested"
                let nested = try ProtectedSetupDirectory(anchor: root.path, relativePath: relative, owner: getuid())
                defer { nested.close() }
                _ = try SetupDatabaseFileProvisioning.prepare(directory: nested, kind: nestedJournal ? .journal : .continuity, owner: getuid())
                let machine = try store(root, initialize: true); defer { try? machine.close() }
                let inventory = try inventory(machine)
                let journalPath = root.path + (nestedJournal ? "/CONTINUITY/nested/journal.sqlite" : "/journal/journal.sqlite")
                let continuityPath = root.path + (nestedJournal ? "/continuity/continuity.sqlite" : "/JOURNAL/nested/continuity.sqlite")
                let expected = try machine.beginInitialization(initial: initial(), journalPath: journalPath,
                    continuityPath: continuityPath, expectedInventoryRevision: inventory.revision)
                var steps = [String]()
                XCTAssertThrowsError(try resume(root, machine: machine, expected: expected, observe: { steps.append($0) }))
                XCTAssertFalse(steps.contains("initializeJournal")); XCTAssertFalse(steps.contains("initializeContinuity"))
                XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: journalPath)), Data())
                XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: continuityPath)), Data())
                XCTAssertEqual(try machine.initialization(accountID: account), expected)
            }
        }
    }
    func testPublicCompositionRefusesOrdinaryUserBeforeFileProvisioning() throws {
        try fixture { root in
            let machine = try store(root, initialize: true); defer { try? machine.close() }
            let inventory = try inventory(machine), expected = try begin(root, machine, inventory)
            XCTAssertThrowsError(try AuthorityAccountInitialization.resume(machine: machine, expected: expected)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertEqual(try machine.initialization(accountID: account), expected)
            XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("journal/journal.sqlite")), Data())
        }
    }
}
