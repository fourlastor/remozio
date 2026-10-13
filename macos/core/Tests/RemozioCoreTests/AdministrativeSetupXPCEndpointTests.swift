import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import Security
import XCTest
@testable import RemozioCore

final class AdministrativeSetupXPCEndpointTests: XCTestCase {
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
    private final class Reply<Value>: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: Value?
        func put(_ value: Value) { lock.withLock { stored = value } }
        var value: Value? { lock.withLock { stored } }
    }
    private func owner(_ root: URL, machine: PreparationIntentStore, release: Data,
                       observe: @escaping () -> Void = {}) throws -> SetupAccountOwner {
        try .init(machine: machine, expectedReleaseDigest: release, resume: { store, expected in
            observe(); return try self.resume(root, machine: store, expected: expected)
        })
    }
    private func hello(_ endpoint: AdministrativeSetupXPCEndpoint) -> UInt64? {
        let reply = Reply<UInt64>(); endpoint.hello { reply.put($0) }; return reply.value
    }
    private func progress(_ endpoint: AdministrativeSetupXPCEndpoint, accountID: Data? = nil) throws -> SetupAccountProgress? {
        let reply = Reply<Data?>(); endpoint.accountStorageProgress(accountID ?? account) { reply.put($0) }
        guard let bytes = reply.value ?? nil, !bytes.isEmpty else { return nil }; return try .decode(bytes)
    }
    private func execute(_ endpoint: AdministrativeSetupXPCEndpoint, expected: AuthorityInitializationIntent,
                         form: Data = Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)) throws -> SetupAccountProgress? {
        let reply = Reply<Data?>()
        endpoint.resumeAccountStorage(expected.accountID, setupID: expected.setupID, expectedRevision: expected.revision,
            authorization: form) { reply.put($0) }
        guard let bytes = reply.value ?? nil else { return nil }; return try .decode(bytes)
    }
    func testHandshakeAndScopedProgressExposeNoCredentialOrStoragePath() throws {
        try fixture { root in
            let machine = try store(root, initialize: true), inventory = try inventory(machine), expected = try begin(root, machine, inventory)
            let owner = try owner(root, machine: machine, release: inventory.releaseDigest); defer { try? owner.close() }
            var authorizations = 0
            let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in authorizations += 1 }, invalidate: {})
            XCTAssertEqual(hello(endpoint), 1)
            let state = try XCTUnwrap(progress(endpoint))
            XCTAssertEqual(state.accountID, account); XCTAssertEqual(state.setupID, expected.setupID); XCTAssertEqual(state.revision, expected.revision)
            XCTAssertFalse(state.checkpointCaptured); XCTAssertFalse(state.complete); XCTAssertEqual(authorizations, 0)
            XCTAssertLessThan(try state.bytes.count, 128)
            XCTAssertNil(try state.bytes.range(of: Data(root.path.utf8)))
        }
    }
    func testRequestBeforeHandshakeNeverImportsAuthorizationOrMutatesStorage() throws {
        try fixture { root in
            let machine = try store(root, initialize: true), inventory = try inventory(machine), expected = try begin(root, machine, inventory)
            var executions = 0, authorizations = 0, invalidations = 0
            let owner = try owner(root, machine: machine, release: inventory.releaseDigest, observe: { executions += 1 }); defer { try? owner.close() }
            let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in authorizations += 1 }, invalidate: { invalidations += 1 })
            XCTAssertNil(try execute(endpoint, expected: expected))
            XCTAssertEqual(authorizations, 0); XCTAssertEqual(executions, 0); XCTAssertEqual(invalidations, 1)
            XCTAssertEqual(try machine.initialization(accountID: account), expected)
            XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("journal/journal.sqlite")), Data())
            XCTAssertEqual(hello(endpoint), 0)
        }
    }
    func testNativeUncredentialledAuthorizationRefusesBeforeControllerRuns() throws {
        try fixture { root in
            let machine = try store(root, initialize: true), inventory = try inventory(machine), expected = try begin(root, machine, inventory)
            var executions = 0
            let owner = try owner(root, machine: machine, release: inventory.releaseDigest, observe: { executions += 1 }); defer { try? owner.close() }
            let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() },
                authorize: { try SetupAdministratorNative.validate(externalForm: $0) }, invalidate: {})
            XCTAssertEqual(hello(endpoint), 1)
            XCTAssertNil(try execute(endpoint, expected: expected)); XCTAssertEqual(executions, 0)
            XCTAssertEqual(try machine.initialization(accountID: account), expected)
            XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("journal/journal.sqlite")), Data())
        }
    }
    func testLogicalFixtureAuthorizationRunsActualStorageControllerAndRetainsCompletion() throws {
        try fixture { root in
            let machine = try store(root, initialize: true), inventory = try inventory(machine), expected = try begin(root, machine, inventory)
            var authorizations = 0, executions = 0
            let owner = try owner(root, machine: machine, release: inventory.releaseDigest, observe: {
                XCTAssertEqual(authorizations, 1); executions += 1
            }); defer { try? owner.close() }
            let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in authorizations += 1 }, invalidate: {})
            XCTAssertEqual(hello(endpoint), 1)
            let result = try XCTUnwrap(execute(endpoint, expected: expected))
            XCTAssertTrue(result.complete); XCTAssertTrue(result.checkpointCaptured); XCTAssertEqual(executions, 1)
            XCTAssertEqual(try progress(endpoint), result)
            XCTAssertTrue(try XCTUnwrap(machine.initialization(accountID: account)).complete)
            try requireReleasedAccountLeases(root)
        }
    }
    func testKernelUIDAccountMismatchCannotReadOrResumeAnotherAccount() throws {
        for read in [false, true] {
            try fixture { root in
                let machine = try store(root, initialize: true), inventory = try inventory(machine), expected = try begin(root, machine, inventory)
                var executions = 0
                let owner = try owner(root, machine: machine, release: inventory.releaseDigest, observe: { executions += 1 }); defer { try? owner.close() }
                let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() + 1 }, authorize: { _ in }, invalidate: {})
                XCTAssertEqual(hello(endpoint), 1)
                if read { XCTAssertNil(try progress(endpoint)) } else { XCTAssertNil(try execute(endpoint, expected: expected)) }
                XCTAssertEqual(executions, 0); XCTAssertEqual(try machine.initialization(accountID: account), expected)
            }
        }
    }
    func testEveryInvocationRechecksIdentityAfterSuccessfulHandshake() throws {
        try fixture { root in
            let machine = try store(root, initialize: true), inventory = try inventory(machine), expected = try begin(root, machine, inventory)
            var accepted = true, checks = 0, executions = 0, authorizations = 0
            let owner = try owner(root, machine: machine, release: inventory.releaseDigest, observe: { executions += 1 }); defer { try? owner.close() }
            let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: {
                checks += 1; if !accepted { throw Interrupted() }; return getuid()
            }, authorize: { _ in authorizations += 1 }, invalidate: {})
            XCTAssertEqual(hello(endpoint), 1); accepted = false
            XCTAssertNil(try execute(endpoint, expected: expected))
            XCTAssertEqual(checks, 2); XCTAssertEqual(authorizations, 0); XCTAssertEqual(executions, 0)
        }
    }
    func testStaleRevisionAndChangedInstallationDoNotInvokeController() throws {
        try fixture { root in
            let machine = try store(root, initialize: true), inventory = try inventory(machine), expected = try begin(root, machine, inventory)
            var executions = 0
            let owner = try owner(root, machine: machine, release: inventory.releaseDigest, observe: { executions += 1 }); defer { try? owner.close() }
            let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in }, invalidate: {})
            XCTAssertEqual(hello(endpoint), 1)
            let reply = Reply<Data?>()
            endpoint.resumeAccountStorage(account, setupID: expected.setupID, expectedRevision: Data(repeating: 9, count: 16),
                authorization: Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size)) { reply.put($0) }
            XCTAssertNil(reply.value ?? nil); XCTAssertEqual(executions, 0)
            let another = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in }, invalidate: {})
            XCTAssertEqual(hello(another), 1)
            let changed = try InstallationInventory(macID: inventory.macID, installationID: inventory.installationID, revision: inventory.revision,
                bundlePath: inventory.bundlePath, releaseDigest: Data(repeating: 9, count: 32), accounts: inventory.accounts, services: inventory.services)
            _ = try machine.writeInventory(changed, expectedRevision: inventory.revision)
            XCTAssertNil(try execute(another, expected: expected)); XCTAssertEqual(executions, 0)
            XCTAssertEqual(try machine.initialization(accountID: account), expected)
        }
    }
    func testMalformedAuthorizationNeverReachesImporterAndClosingOneEndpointPreservesOwner() throws {
        try fixture { root in
            let machine = try store(root, initialize: true), inventory = try inventory(machine), expected = try begin(root, machine, inventory)
            var authorizations = 0
            let owner = try owner(root, machine: machine, release: inventory.releaseDigest); defer { try? owner.close() }
            let first = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in authorizations += 1 }, invalidate: {})
            XCTAssertEqual(hello(first), 1); XCTAssertNil(try execute(first, expected: expected, form: Data(count: 4096)))
            XCTAssertEqual(authorizations, 0)
            let second = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in }, invalidate: {})
            XCTAssertEqual(hello(second), 1); XCTAssertNotNil(try progress(second))
        }
    }
    func testTwoConnectionsShareOneSerializedStoreAndOnlyOneRevisionWins() throws {
        try fixture { root in
            let machine = try store(root, initialize: true), inventory = try inventory(machine), expected = try begin(root, machine, inventory)
            var executions = 0
            let owner = try owner(root, machine: machine, release: inventory.releaseDigest, observe: { executions += 1 }); defer { try? owner.close() }
            let first = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in }, invalidate: {})
            let second = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in }, invalidate: {})
            XCTAssertEqual(hello(first), 1); XCTAssertEqual(hello(second), 1)
            let one = Reply<Data?>(), two = Reply<Data?>(), group = DispatchGroup()
            for (endpoint, result) in [(first, one), (second, two)] {
                group.enter()
                DispatchQueue.global().async {
                    endpoint.resumeAccountStorage(expected.accountID, setupID: expected.setupID, expectedRevision: expected.revision,
                        authorization: Data(count: MemoryLayout<AuthorizationExternalForm>.size)) {
                            result.put($0); group.leave()
                        }
                }
            }
            XCTAssertEqual(group.wait(timeout: .now() + 10), .success)
            XCTAssertEqual([one.value ?? nil, two.value ?? nil].compactMap { $0 }.count, 1)
            XCTAssertEqual(executions, 1)
            XCTAssertTrue(try XCTUnwrap(machine.initialization(accountID: account)).complete)
        }
    }
    func testPublicOwnerAndEndpointRejectOrdinaryUserBeforeAccessingResources() throws {
        try fixture { root in
            XCTAssertThrowsError(try SetupAccountOwner.open(machineDirectory: root.path + "/not-created", macID: mac,
                expectedReleaseDigest: Data(repeating: 8, count: 32))) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
            let machine = try store(root, initialize: true), inventory = try inventory(machine)
            let owner = try owner(root, machine: machine, release: inventory.releaseDigest); defer { try? owner.close() }
            let connection = NSXPCConnection(machServiceName: "dev.remozio.not.registered")
            let policy = try XPCPeerPolicy(teamID: "ABCDEFGHIJ", componentIdentifier: "dev.remozio.app",
                approvedCodeDirectoryHashes: [Data(repeating: 4, count: 20)], expectedUserID: getuid())
            XCTAssertThrowsError(try AdministrativeSetupXPCEndpoint(connection: connection, peerPolicy: policy, owner: owner)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: root.path + "/not-created"))
        }
    }
    func testProgressDecoderRejectsImpossibleCompletionAndUnknownVersion() throws {
        for value in [CBORValue.map([0: .unsigned(2), 1: .bytes(account), 2: .bytes(mac), 3: .bytes(epoch), 4: .unsigned(0), 5: .unsigned(0)]),
                      .map([0: .unsigned(1), 1: .bytes(account), 2: .bytes(mac), 3: .bytes(epoch), 4: .unsigned(0), 5: .unsigned(1)])] {
            XCTAssertThrowsError(try SetupAccountProgress.decode(DeterministicCBOR.encode(value, limits: limits)))
        }
    }
    func testChangedHostPolicyRefusesStorageBeforeResume() throws {
        try fixture { root in
            let machine = try store(root, initialize: true)
            let installed = try inventory(machine)
            let expected = try begin(root, machine, installed)
            var changed = false, resumes = 0
            let owner = try SetupAccountOwner(machine: machine, expectedReleaseDigest: installed.releaseDigest,
                resume: { _, _ in resumes += 1; throw AdministrativeSetupError.unavailable },
                verifyHost: { _ in if changed { throw AdministrativeSetupServiceError.changedConfiguration } })
            defer { try? owner.close() }
            XCTAssertNoThrow(try owner.verifyCurrent())
            changed = true
            XCTAssertThrowsError(try owner.verifyCurrent())
            XCTAssertThrowsError(try owner.progress(accountID: expected.accountID, callerUID: getuid()))
            XCTAssertThrowsError(try owner.resumeAccount(accountID: expected.accountID, setupID: expected.setupID,
                expectedRevision: expected.revision, callerUID: getuid()))
            XCTAssertEqual(resumes, 0)
            changed = false
            XCTAssertNoThrow(try owner.verifyCurrent())
        }
    }

    func testHostValidationReceivesCurrentBundleAndServiceInventory() throws {
        try fixture { root in
            let machine = try store(root, initialize: true)
            let base = try inventory(machine)
            let original = try machine.writeInventory(.init(macID: base.macID, installationID: base.installationID,
                revision: base.revision, bundlePath: base.bundlePath, releaseDigest: base.releaseDigest, accounts: base.accounts,
                services: base.services + [.init(role: .setupController, kind: .daemon, domainUID: nil, executionUID: 0,
                    label: "dev.remozio.setup", plistName: "dev.remozio.setup.plist")]), expectedRevision: base.revision)
            let expected = try begin(root, machine, original)
            var observed: InstallationInventory?
            let owner = try SetupAccountOwner(machine: machine, expectedReleaseDigest: original.releaseDigest,
                resume: { _, _ in XCTFail("Changed installation must not resume"); throw AdministrativeSetupError.unavailable },
                verifyHost: { current in
                    observed = current
                    guard current.bundlePath == original.bundlePath, current.services == original.services else {
                        throw AdministrativeSetupServiceError.wrongRelease
                    }
                })
            defer { try? owner.close() }
            XCTAssertNoThrow(try owner.verifyCurrent())
            var retained = original
            for change in 0..<3 {
                let services: [InstallationService]
                if change == 1 { services = original.services.filter { $0.role != .setupController } }
                else if change == 2 {
                    services = original.services.filter { $0.role != .setupController } + [try .init(role: .setupController,
                        kind: .daemon, domainUID: nil, executionUID: 0, label: "dev.remozio.other", plistName: "dev.remozio.setup.plist")]
                } else { services = original.services }
                let next = try InstallationInventory(macID: original.macID, installationID: original.installationID,
                    revision: original.revision, bundlePath: change == 0 ? "/Library/Other/Remozio.app" : original.bundlePath,
                    releaseDigest: original.releaseDigest, accounts: original.accounts,
                    services: services)
                retained = try machine.writeInventory(next, expectedRevision: retained.revision)
                XCTAssertThrowsError(try owner.verifyCurrent())
                XCTAssertEqual(observed, retained)
                XCTAssertThrowsError(try owner.progress(accountID: expected.accountID, callerUID: getuid()))
                XCTAssertThrowsError(try owner.resumeAccount(accountID: expected.accountID, setupID: expected.setupID,
                    expectedRevision: expected.revision, callerUID: getuid()))
            }
        }
    }

}
