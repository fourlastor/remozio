import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class SharedSetupImportFixture {
    let accountFixture: AccountPreparationFixture
    let account: AccountPreparationIntent
    let inventory: InstallationInventory
    let scope: SharedSetupImportIntent.Scope
    let relativeDirectory: String
    var path: String { accountFixture.root.path + "/" + relativeDirectory + "/setup-import.sqlite" }
    init(relativeDirectory: String = "imports", policy: AuthorityCodePolicy? = nil) throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner import journal fixture") }
        self.relativeDirectory = relativeDirectory
        accountFixture = try .init(policy: policy)
        let machine = try accountFixture.open(initialize: true)
        defer { try? machine.close() }
        account = try accountFixture.resume(machine, accountFixture.begin(machine))
        inventory = try XCTUnwrap(machine.inventory())
        scope = try .init(account: account, inventory: inventory)
        try accountFixture.prepare(relativeDirectory, .sharedSetupImport)
    }
    func open(initialize: Bool = false, macID: Data? = nil, installationID: Data? = nil,
              maximumRecords: Int = 64, hook: (() throws -> Void)? = nil) throws -> SharedSetupImportJournal {
        let lease = try ProtectedStorageLease(anchor: accountFixture.root.path, relativeDirectory: relativeDirectory,
            owner: getuid(), ancestorOwner: getuid(), databaseName: "setup-import.sqlite")
        return try .init(lease: lease, owner: getuid(), macID: macID ?? scope.macID,
            installationID: installationID ?? scope.installationID, initialize: initialize, maximumRecords: maximumRecords, didCommit: hook)
    }
    func proposal() throws -> PortableSetup {
        try .init(defaults: .init(presence: .init(idleMilliseconds: 420_000, observationLifetimeMilliseconds: 5000,
            unavailableGraceMilliseconds: 30_000), gateway: GatewaySetupForm().settingsSelection()),
            cloudflare: .init(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32),
                dnsSuffix: "remozio.example.invalid", apiToken: "synthetic-provider-token-only"),
            appPreferences: .init(preferences: [PortableAppPreferences.menuBarKey: false]))
    }
    func intent() throws -> SharedSetupImportIntent { try .init(scope: scope, proposal: proposal()) }
    func sql(_ query: String) throws {
        var connection: OpaquePointer?
        let result = sqlite3_open_v2(path, &connection, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW, nil)
        guard result == SQLITE_OK, let db = connection else { throw SharedSetupImportError.storage(result) }
        defer { sqlite3_close(db) }
        let code = sqlite3_exec(db, query, nil, nil, nil)
        guard code == SQLITE_OK else { throw SharedSetupImportError.storage(code) }
    }
    // Synthetic trusted-writer records test only row isolation, operation uniqueness and capacity.
    // Native account lookup and authorization remain separate unproven gates.
    func another(_ source: SharedSetupImportIntent, account: UInt8, operation: Data? = nil) throws -> SharedSetupImportIntent {
        let limits = try CBORLimits(maxBytes: 70_000, maxDepth: 2, maxItems: 40)
        guard case var .map(fields) = try DeterministicCBOR.decode(source.bytes, limits: limits) else { throw SharedSetupImportError.invalidRecord }
        fields[5] = .bytes(Data(repeating: account, count: 16)); fields[7] = .bytes(Data(repeating: account, count: 32))
        fields[8] = .bytes(operation ?? AccountPreparationIntent.randomID()); fields[9] = .bytes(AccountPreparationIntent.randomID())
        return try .decode(DeterministicCBOR.encode(.map(fields), limits: limits))
    }
}

final class SharedSetupImportJournalTests: XCTestCase {
    private struct LostCommitReply: Error {}
    func testNativeOpenRefusesOrdinaryAccountBeforeTouchingAnyPath() throws {
        guard getuid() > 0 else { throw XCTSkip("Ordinary account refusal") }
        XCTAssertThrowsError(try SharedSetupImportJournal.open(machineDirectory: "/not-opened", macID: Data(repeating: 1, count: 16),
            installationID: Data(repeating: 2, count: 16), initialize: true)) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
    }
    func testReopenRetainsExactProposalAndLeavesInstallationStateUntouched() throws {
        let f = try SharedSetupImportFixture(), intent = try f.intent()
        let original = try Data(contentsOf: URL(fileURLWithPath: f.accountFixture.root.path + "/machine/installation.sqlite"))
        let journal = try f.open(initialize: true); XCTAssertNil(try journal.current(scope: f.scope))
        try journal.begin(intent); try journal.begin(intent); try journal.close()
        let reopened = try f.open(); defer { try? reopened.close() }
        XCTAssertEqual(try reopened.current(scope: f.scope), intent)
        XCTAssertEqual(try reopened.current(scope: f.scope)?.matches(f.proposal()), true)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.accountFixture.root.path + "/machine/installation.sqlite")), original)
        let machine = try f.accountFixture.open(); defer { try? machine.close() }
        XCTAssertEqual(try machine.accountPreparation(ownerUID: f.account.ownerUID), f.account)
        XCTAssertEqual(try machine.runtimePreparation(accountID: f.account.accountID).configurationPublished, false)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.accountFixture.root.path + "/imports").sorted(), ["setup-import.sqlite", "writer.lock"])
    }
    func testStaleWriterCannotReplaceProposalSkipPhasesOrClearCompletion() throws {
        let f = try SharedSetupImportFixture(), first = try f.intent(), journal = try f.open(initialize: true)
        defer { try? journal.close() }; try journal.begin(first)
        XCTAssertThrowsError(try journal.begin(f.intent())) { XCTAssertEqual($0 as? SharedSetupImportError, .conflict) }
        XCTAssertThrowsError(try journal.advance(first, to: .relayPrepared)) { XCTAssertEqual($0 as? SharedSetupImportError, .invalidTransition) }
        var current = try journal.advance(first, to: .runtimePublished)
        XCTAssertThrowsError(try journal.advance(first, to: .runtimePublished)) { XCTAssertEqual($0 as? SharedSetupImportError, .staleRevision) }
        for phase in [SharedSetupImportIntent.Phase.gatewayPrepared, .relayPrepared, .rootComplete] {
            let next = try journal.advance(current, to: phase)
            XCTAssertNotEqual(next.revision, current.revision); XCTAssertEqual(next.operationID, first.operationID)
            XCTAssertEqual(next.proposalDigest, first.proposalDigest); current = next
        }
        XCTAssertThrowsError(try journal.begin(first)) { XCTAssertEqual($0 as? SharedSetupImportError, .conflict) }
        XCTAssertEqual(try journal.current(scope: f.scope), current)
    }
    func testUnknownBeginCommitRetiresWriterAndRecoversCommittedRecord() throws {
        let f = try SharedSetupImportFixture(), intent = try f.intent(); var fail = false
        let journal = try f.open(initialize: true) { if fail { throw LostCommitReply() } }
        fail = true
        XCTAssertThrowsError(try journal.begin(intent)) { XCTAssertTrue($0 is LostCommitReply) }
        XCTAssertThrowsError(try journal.current(scope: f.scope)) { XCTAssertEqual($0 as? SharedSetupImportError, .unavailable) }
        let restored = try f.open(); defer { try? restored.close() }
        XCTAssertEqual(try restored.current(scope: f.scope), intent)
    }
    func testUnknownAdvanceCommitRecoversNewRevisionWithoutRepeatingEffects() throws {
        let f = try SharedSetupImportFixture(), intent = try f.intent(); var fail = false
        let journal = try f.open(initialize: true) { if fail { throw LostCommitReply() } }
        try journal.begin(intent); fail = true
        XCTAssertThrowsError(try journal.advance(intent, to: .runtimePublished)) { XCTAssertTrue($0 is LostCommitReply) }
        XCTAssertThrowsError(try journal.records()) { XCTAssertEqual($0 as? SharedSetupImportError, .unavailable) }
        let restored = try f.open(); defer { try? restored.close() }
        let retained = try XCTUnwrap(restored.current(scope: f.scope))
        XCTAssertEqual(retained.phase, .runtimePublished); XCTAssertNotEqual(retained.revision, intent.revision)
        XCTAssertEqual(retained.operationID, intent.operationID); XCTAssertEqual(retained.proposalDigest, intent.proposalDigest)
        XCTAssertThrowsError(try restored.advance(intent, to: .runtimePublished)) { XCTAssertEqual($0 as? SharedSetupImportError, .staleRevision) }
    }
    func testDifferentDestinationAndReinitializationRefuseWithoutReplacingFiles() throws {
        let f = try SharedSetupImportFixture(), intent = try f.intent(), first = try f.open(initialize: true)
        try first.begin(intent); try first.close()
        let original = try Data(contentsOf: URL(fileURLWithPath: f.path))
        XCTAssertThrowsError(try f.open(macID: Data(repeating: 9, count: 16))) { XCTAssertEqual($0 as? SharedSetupImportError, .wrongScope) }
        XCTAssertThrowsError(try f.open(installationID: Data(repeating: 9, count: 16))) { XCTAssertEqual($0 as? SharedSetupImportError, .wrongScope) }
        XCTAssertThrowsError(try f.open(initialize: true)) { XCTAssertEqual($0 as? SharedSetupImportError, .incompatibleStore) }
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.path)), original)
    }
    func testCorruptDigestRetiresConnectionAndCannotBeReadAsValidProposal() throws {
        let f = try SharedSetupImportFixture(), intent = try f.intent(), journal = try f.open(initialize: true)
        try journal.begin(intent)
        try f.sql("UPDATE shared_setup_import_v2 SET digest=zeroblob(32)")
        XCTAssertThrowsError(try journal.records()) { XCTAssertEqual($0 as? SharedSetupImportError, .corruptRecord) }
        XCTAssertThrowsError(try journal.records()) { XCTAssertEqual($0 as? SharedSetupImportError, .unavailable) }
        XCTAssertThrowsError(try f.open()) { XCTAssertEqual($0 as? SharedSetupImportError, .corruptRecord) }
    }
    func testUnknownSchemaRefusesWithoutRepair() throws {
        let f = try SharedSetupImportFixture(), journal = try f.open(initialize: true)
        try journal.close(); try f.sql("PRAGMA user_version=1")
        let bytes = try Data(contentsOf: URL(fileURLWithPath: f.path))
        XCTAssertThrowsError(try f.open()) { XCTAssertEqual($0 as? SharedSetupImportError, .incompatibleStore) }
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.path)), bytes)
    }
    func testWriterLeaseAndDirectoryIdentityPreventConcurrentOrSubstitutedStorage() throws {
        let f = try SharedSetupImportFixture(), journal = try f.open(initialize: true)
        XCTAssertThrowsError(try f.open()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        let path = f.accountFixture.root.path + "/imports", archived = path + "-original"
        XCTAssertEqual(rename(path, archived), 0); try f.accountFixture.prepare("imports", .sharedSetupImport)
        XCTAssertThrowsError(try journal.records()) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertThrowsError(try journal.records()) { XCTAssertEqual($0 as? SharedSetupImportError, .unavailable) }
        XCTAssertTrue(FileManager.default.fileExists(atPath: archived + "/setup-import.sqlite"))
    }
    func testSymlinkAndUnsafePermissionsRefuseWithoutRepairingTarget() throws {
        let f = try SharedSetupImportFixture(), target = f.accountFixture.root.path + "/machine/installation.sqlite"
        let original = try Data(contentsOf: URL(fileURLWithPath: target))
        XCTAssertEqual(unlink(f.path), 0); XCTAssertEqual(symlink(target, f.path), 0)
        XCTAssertThrowsError(try f.open(initialize: true))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: target)), original)
        XCTAssertEqual(unlink(f.path), 0); try f.accountFixture.prepare("imports", .sharedSetupImport)
        XCTAssertEqual(chmod(f.path, 0o666), 0)
        XCTAssertThrowsError(try f.open(initialize: true)) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
        var info = stat(); XCTAssertEqual(lstat(f.path, &info), 0); XCTAssertEqual(info.st_mode & 0o777, 0o666)
    }
    func testDistinctAccountRowsOperationUniquenessAndBoundedCapacity() throws {
        let f = try SharedSetupImportFixture(), first = try f.intent(), journal = try f.open(initialize: true, maximumRecords: 2)
        defer { try? journal.close() }; try journal.begin(first)
        let collision = try f.another(first, account: 11, operation: first.operationID)
        XCTAssertThrowsError(try journal.begin(collision)) { XCTAssertEqual($0 as? SharedSetupImportError, .conflict) }
        let second = try f.another(first, account: 11); try journal.begin(second)
        XCTAssertEqual(try journal.current(scope: second.scope), second)
        XCTAssertEqual(try journal.current(scope: first.scope), first)
        XCTAssertThrowsError(try journal.begin(f.another(first, account: 12))) { XCTAssertEqual($0 as? SharedSetupImportError, .capacity) }
        XCTAssertEqual(try journal.records().count, 2)
    }
    func testChangedLocalAccountScopeCannotReadOrAdvanceAnExistingIntent() throws {
        let f = try SharedSetupImportFixture(), first = try f.intent(), journal = try f.open(initialize: true)
        defer { try? journal.close() }; try journal.begin(first)
        let limits = try CBORLimits(maxBytes: 70_000, maxDepth: 2, maxItems: 40)
        guard case var .map(fields) = try DeterministicCBOR.decode(first.bytes, limits: limits) else { return XCTFail("Missing record") }
        fields[7] = .bytes(Data(repeating: 19, count: 32))
        let changed = try SharedSetupImportIntent.decode(DeterministicCBOR.encode(.map(fields), limits: limits))
        XCTAssertThrowsError(try journal.current(scope: changed.scope)) { XCTAssertEqual($0 as? SharedSetupImportError, .wrongScope) }
        XCTAssertThrowsError(try journal.advance(changed, to: .runtimePublished)) { XCTAssertEqual($0 as? SharedSetupImportError, .staleRevision) }
        XCTAssertEqual(try journal.current(scope: first.scope), first)
    }
}
