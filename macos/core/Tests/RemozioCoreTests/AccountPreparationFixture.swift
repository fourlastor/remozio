import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import Security
import XCTest
@testable import RemozioCore

final class AccountPreparationFixture {
    let root: URL
    let mac = Data(repeating: 1, count: 16)
    let release: Data
    let identity = LocalAccountIdentity(uid: getuid(), primaryGroupID: getgid(), directoryID: UUID())
    // Public fixture pin only. This does not claim hardware key provisioning.
    let key = P256.Signing.PrivateKey().publicKey.x963Representation
    let policy: AuthorityCodePolicy
    let limits = try! CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
    init(policy suppliedPolicy: AuthorityCodePolicy? = nil, releaseDigest: Data? = nil) throws {
        release = releaseDigest ?? Data(repeating: 8, count: 32)
        root = URL(fileURLWithPath: "/private/tmp/remozio-account-preparation-" + UUID().uuidString)
        if let suppliedPolicy { policy = suppliedPolicy }
        else {
            policy = try .init(entries: [.init(role: .authority, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.authority",
                installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 4, count: 20), active: true)])
        }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        guard chmod(root.path, 0o700) == 0 else { throw JournalLeaseError.system(errno) }
        try prepare("machine", .installation)
    }
    deinit { try? FileManager.default.removeItem(at: root) }
    func prepare(_ relative: String, _ kind: SetupDatabaseKind) throws {
        let directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: relative, owner: getuid())
        defer { directory.close() }
        _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: kind, owner: getuid())
    }
    func open(initialize: Bool = false, hook: (() throws -> Void)? = nil) throws -> PreparationIntentStore {
        let store = try PreparationIntentStore(lease: .init(anchor: root.path, relativeDirectory: "machine", owner: getuid()),
            macID: mac, maximumRecords: 64, initialize: initialize, didCommit: hook)
        if initialize {
            try store.upgradeInventoryStorage()
            _ = try store.writeInventory(.init(macID: mac, installationID: Data(repeating: 5, count: 16),
                revision: Data(repeating: 6, count: 16), bundlePath: "/Library/Remozio/Remozio.app", releaseDigest: release,
                accounts: [], services: [.init(role: .setupController, kind: .daemon, domainUID: nil, executionUID: 0,
                    label: AdministrativeSetupConfiguration.serviceName, plistName: AdministrativeSetupConfiguration.plistName)], formatVersion: 2),
                expectedRevision: nil)
        }
        return store
    }
    func initial(mac: Data, account: Data, epoch: Data? = nil, replay: Bool = true) throws -> AuthorityJournalInitialization {
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(mac), 2: .bytes(account), 3: .bytes(epoch ?? AccountPreparationIntent.randomID()),
            4: .unsigned(1), 5: .unsigned(AuditEpochCause.initial.rawValue), 6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 3)
        return .init(descriptor: descriptor, codePolicy: policy, capabilities: .init(contracts: [contract: []]),
            allowedContracts: [contract], installCommandReplay: replay)
    }
    func begin(_ machine: PreparationIntentStore, identity: LocalAccountIdentity? = nil, targets: Set<UInt32> = [0],
               accepted: Bool = true) throws -> AccountPreparationIntent {
        try machine.beginAccountPreparation(owner: identity ?? self.identity, allowedTargetUIDs: targets, disclosureAccepted: accepted,
            expectedInventoryRevision: XCTUnwrap(machine.inventory()).revision, makeInitial: { try self.initial(mac: $0, account: $1) })
    }
    func directory(_ value: AccountPreparationIntent) -> String { value.accountID.map { String(format: "%02x", $0) }.joined() }
    func beginStores(_ machine: PreparationIntentStore, _ value: AccountPreparationIntent) throws -> AuthorityInitializationIntent {
        let relative = directory(value)
        let scope = try ProtectedSetupDirectory(anchor: root.path, relativePath: relative, owner: getuid()); scope.close()
        return try machine.beginInitialization(initial: value.initialAuthority, journalPath: root.path + "/" + relative + "/journal/journal.sqlite",
            continuityPath: root.path + "/" + relative + "/continuity/continuity.sqlite",
            expectedInventoryRevision: XCTUnwrap(machine.inventory()).revision)
    }
    func resumeStores(_ machine: PreparationIntentStore, _ expected: AuthorityInitializationIntent) throws -> AuthorityInitializationIntent {
        let journal = String((expected.journalPath as NSString).deletingLastPathComponent.dropFirst(root.path.count + 1))
        let continuity = String((expected.continuityPath as NSString).deletingLastPathComponent.dropFirst(root.path.count + 1))
        return try AuthorityAccountInitialization.resume(machine: machine, expected: expected,
            prepareJournal: { try self.prepare(journal, .journal) }, openDirectories: {
                let a = try ProtectedSetupDirectory(anchor: self.root.path, relativePath: journal, owner: getuid(), createIfMissing: false)
                do { return try .init(journal: a, continuity: .init(anchor: self.root.path, relativePath: continuity, owner: getuid())) }
                catch { a.close(); throw error }
            }, openJournal: { initialize, seed, scope in
                let lease = try ProtectedJournalLease(anchor: self.root.path, relativeDirectory: journal, owner: getuid())
                do {
                    try scope.validate(journal: lease)
                    return try JournalDatabase(lease: lease, macID: expected.macID, accountID: expected.accountID,
                        recordLimits: self.limits, descriptorLimits: self.limits, decisionLimits: self.limits,
                        maximumConsumptions: 10, busyMilliseconds: 100, initialize: initialize, initialAuthority: initialize ? seed : nil)
                } catch { lease.close(); throw error }
            }, prepareContinuity: { try self.prepare(continuity, .continuity) }, openContinuity: { checkpoint, scope in
                let lease = try ProtectedContinuityLease(anchor: self.root.path, relativeDirectory: continuity, owner: getuid())
                do {
                    try scope.validate(continuity: lease)
                    return try ContinuityStore(lease: lease, macID: expected.macID, accountID: expected.accountID, initialize: checkpoint)
                } catch { lease.close(); throw error }
            })
    }
    func resume(_ machine: PreparationIntentStore, _ expected: AccountPreparationIntent,
                verify: () throws -> Void = {}, provision: ((AccountPreparationIntent) throws -> Data)? = nil,
                stage: (AccountPreparationController.Stage) throws -> Void = { _ in }) throws -> AccountPreparationIntent {
        try AccountPreparationController.resume(machine: machine, expected: expected, verifyCurrent: verify,
            provisionKey: provision ?? { _ in self.key }, beginInitialization: { try self.beginStores(machine, $0) },
            resumeInitialization: { try self.resumeStores(machine, $0) }, didStage: stage)
    }
    func sql(_ query: String) throws -> Int64 {
        var connection: OpaquePointer?
        guard sqlite3_open_v2(root.path + "/machine/installation.sqlite", &connection, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK,
              let db = connection else { throw PreparationStoreError.corruptRecord }
        defer { sqlite3_close(db) }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, query, -1, &statement, nil) == SQLITE_OK, let row = statement else { throw PreparationStoreError.corruptRecord }
        defer { sqlite3_finalize(row) }
        let result = sqlite3_step(row)
        guard result == SQLITE_ROW || result == SQLITE_DONE else { throw PreparationStoreError.storage(result) }
        return result == SQLITE_ROW ? sqlite3_column_int64(row, 0) : 0
    }
}
