import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import Security
import XCTest
@testable import RemozioCore

final class AdministrativeSetupListenerTests: XCTestCase {
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
    private final class Reply<Value>: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: Value?
        func put(_ value: Value) { lock.withLock { stored = value } }
        var value: Value? { lock.withLock { stored } }
    }
    private func owner(_ root: URL, machine: PreparationIntentStore, release: Data) throws -> SetupAccountOwner {
        try .init(machine: machine, expectedReleaseDigest: release, resume: { _, _ in
            XCTFail("Lifecycle controls must not resume account storage"); throw Interrupted()
        })
    }
    private func hello(_ endpoint: AdministrativeSetupXPCEndpoint) -> UInt64? {
        let reply = Reply<UInt64>(); endpoint.hello { reply.put($0) }; return reply.value
    }
    private final class Connection: OwnedAuthorityConnection, @unchecked Sendable {
        let endpoint: AdministrativeSetupXPCEndpoint
        let activateHandshake: Bool
        init(endpoint: AdministrativeSetupXPCEndpoint, activateHandshake: Bool) {
            self.endpoint = endpoint; self.activateHandshake = activateHandshake
        }
        func activate() { if activateHandshake { endpoint.hello { _ in } } }
        func close() { endpoint.close() }
    }
    private final class Count: @unchecked Sendable {
        private let lock = NSLock()
        private var stored = 0
        func increment() { lock.withLock { stored += 1 } }
        var value: Int { lock.withLock { stored } }
    }
    func testSuccessfulEndpointHandshakeRetainsItsSlotUntilClosure() throws {
        try fixture { root in
            let machine = try store(root, initialize: true), inventory = try inventory(machine)
            _ = try begin(root, machine, inventory)
            let owner = try owner(root, machine: machine, release: inventory.releaseDigest); defer { try? owner.close() }
            let registry = try AuthorityConnectionRegistry(maximum: 1, timeoutMilliseconds: 5000); try registry.start()
            let id = try XCTUnwrap(registry.reserve()), closes = Count()
            let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in },
                invalidate: { closes.increment(); registry.remove(id) }, onHandshake: { registry.handshake(id) })
            XCTAssertTrue(registry.install(Connection(endpoint: endpoint, activateHandshake: true), id: id))
            registry.expire(id)
            XCTAssertNil(registry.reserve()); XCTAssertEqual(closes.value, 0)
            endpoint.close(); endpoint.close()
            XCTAssertEqual(closes.value, 1); XCTAssertNotNil(registry.reserve())
            registry.close()
        }
    }
    func testStalledEndpointDeadlineClosesExactlyOnceAndReturnsCapacity() throws {
        try fixture { root in
            let machine = try store(root, initialize: true), inventory = try inventory(machine)
            let owner = try owner(root, machine: machine, release: inventory.releaseDigest); defer { try? owner.close() }
            let registry = try AuthorityConnectionRegistry(maximum: 1, timeoutMilliseconds: 100); try registry.start()
            let id = try XCTUnwrap(registry.reserve()), closes = Count(), ended = expectation(description: "stalled setup connection closes")
            let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in }, invalidate: {
                closes.increment(); registry.remove(id); ended.fulfill()
            }, onHandshake: { registry.handshake(id) })
            XCTAssertTrue(registry.install(Connection(endpoint: endpoint, activateHandshake: false), id: id))
            wait(for: [ended], timeout: 2)
            XCTAssertEqual(closes.value, 1); XCTAssertEqual(hello(endpoint), 0)
            XCTAssertNotNil(registry.reserve()); registry.close()
        }
    }
    func testRejectedHandshakeReleasesItsSlotAndDoesNotNotifySuccess() throws {
        try fixture { root in
            let machine = try store(root, initialize: true), inventory = try inventory(machine)
            let owner = try owner(root, machine: machine, release: inventory.releaseDigest); defer { try? owner.close() }
            let registry = try AuthorityConnectionRegistry(maximum: 1, timeoutMilliseconds: 5000); try registry.start()
            let id = try XCTUnwrap(registry.reserve()), ready = Count()
            let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { throw Interrupted() }, authorize: { _ in },
                invalidate: { registry.remove(id) }, onHandshake: { ready.increment(); registry.handshake(id) })
            XCTAssertFalse(registry.install(Connection(endpoint: endpoint, activateHandshake: true), id: id))
            XCTAssertEqual(ready.value, 0); XCTAssertNotNil(registry.reserve()); registry.close()
        }
    }
    func testRegistryShutdownClosesAllEndpointsWithoutClosingTheSharedStore() throws {
        try fixture { root in
            let machine = try store(root, initialize: true), inventory = try inventory(machine)
            let expected = try begin(root, machine, inventory)
            let owner = try owner(root, machine: machine, release: inventory.releaseDigest); defer { try? owner.close() }
            let registry = try AuthorityConnectionRegistry(maximum: 2, timeoutMilliseconds: 5000); try registry.start()
            let closes = Count()
            for _ in 0..<2 {
                let id = try XCTUnwrap(registry.reserve())
                let endpoint = AdministrativeSetupXPCEndpoint(owner: owner, verify: { getuid() }, authorize: { _ in },
                    invalidate: { closes.increment(); registry.remove(id) }, onHandshake: { registry.handshake(id) })
                XCTAssertTrue(registry.install(Connection(endpoint: endpoint, activateHandshake: true), id: id))
            }
            registry.close(); registry.close()
            XCTAssertEqual(closes.value, 2); XCTAssertNil(registry.reserve())
            XCTAssertEqual(try owner.progress(accountID: account, callerUID: getuid()), expected)
        }
    }
    func testPublicListenerRequiresRootBeforeCreatingAMachListener() throws {
        try fixture { root in
            let machine = try store(root, initialize: true), inventory = try inventory(machine)
            let owner = try owner(root, machine: machine, release: inventory.releaseDigest); defer { try? owner.close() }
            XCTAssertThrowsError(try AdministrativeSetupXPCListener(serviceName: "dev.remozio.not.registered", teamID: "ABCDEFGHIJ",
                appIdentifier: "dev.remozio.app", appHashes: [Data(repeating: 4, count: 20)], owner: owner)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertNoThrow(try owner.verifyCurrent())
        }
    }
}
