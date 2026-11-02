import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityJournalTests: XCTestCase {
    private enum Failure: Error { case injected }
    private func owner(_ fixture: Fixture, initialize: Bool = true) throws -> AuthorityJournal {
        let anchor = fixture.root.path
        let limits = try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
        return AuthorityJournal(database: try JournalDatabase(lease: ProtectedJournalLease(anchor: anchor, relativeDirectory: "store", owner: getuid()),
            macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
            maximumConsumptions: 10, busyMilliseconds: 100, initialize: initialize))
    }
    private func configure(_ owner: AuthorityJournal) throws -> UUID {
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let capabilities = ContractCapabilities(contracts: [contract: []])
        return try owner.write { try $0.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract]) }
    }
    func testSnapshotUsesCommittedStoreAndCloseReleasesLease() throws {
        let fixture = try Fixture(), journal = try owner(fixture)
        XCTAssertThrowsError(try journal.trustSnapshot(maximumPayloadBytes: 1024)) {
            XCTAssertEqual($0 as? EnrollmentJournalError, .unconfigured)
        }
        let revision = try configure(journal)
        let trust = try journal.trustSnapshot(maximumPayloadBytes: 1024)
        XCTAssertEqual(trust.revision, revision); XCTAssertTrue(trust.peers.isEmpty)
        XCTAssertThrowsError(try journal.trustSnapshot(maximumPayloadBytes: 0))
        try journal.close(); try journal.close()
        XCTAssertThrowsError(try journal.trustSnapshot(maximumPayloadBytes: 1024)) {
            XCTAssertEqual($0 as? JournalDatabaseError, .closed)
        }
        let reopened = try owner(fixture, initialize: false)
        XCTAssertEqual(try reopened.trustSnapshot(maximumPayloadBytes: 1024).revision, revision)
        try reopened.close()
    }
    func testDeniedBindingDoesNotHideStorageFailure() throws {
        let fixture = try Fixture(), journal = try owner(fixture), revision = try configure(journal)
        let scope = try ChannelScope(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16))
        let key = P256.Signing.PrivateKey().publicKey.derRepresentation
        let missing = try AuthorityPeerBinding(scope: scope, transportPublicKey: key, revision: revision)
        let stale = try AuthorityPeerBinding(scope: scope, transportPublicKey: key, revision: UUID())
        XCTAssertFalse(try journal.validatePeer(missing)); XCTAssertFalse(try journal.validatePeer(stale))
        XCTAssertEqual(try journal.trustSnapshot(maximumPayloadBytes: 1024).revision, revision)
        try journal.close()
        XCTAssertThrowsError(try journal.validatePeer(missing)) { XCTAssertEqual($0 as? JournalDatabaseError, .closed) }
    }
    func testNestedTransactionsAndCloseFailWithoutDeadlockOrRetiringOuterRead() throws {
        let fixture = try Fixture(), journal = try owner(fixture), revision = try configure(journal)
        let result = try journal.read { tx in
            XCTAssertThrowsError(try journal.read { try $0.approvalTrustSnapshot().revision }) {
                XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
            }
            XCTAssertThrowsError(try journal.close()) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive) }
            return try tx.approvalTrustSnapshot().revision
        }
        XCTAssertEqual(result, revision)
        XCTAssertEqual(try journal.trustSnapshot(maximumPayloadBytes: 1024).revision, revision)
        try journal.close()
    }
    func testEndpointReadsJournalAndRetiresAfterStorageCloses() throws {
        let fixture = try Fixture(), journal = try owner(fixture), revision = try configure(journal)
        let mac = Data(repeating: 1, count: 16), account = Data(repeating: 2, count: 16)
        let endpoint = try AuthorityXPCEndpoint(macID: mac, accountID: account, budget: AuthorityXPCWorkBudget(),
            verify: {}, invalidate: {}, snapshot: { try journal.trustSnapshot(maximumPayloadBytes: 1024) },
            validate: { try journal.validatePeer($0) })
        endpoint.hello { XCTAssertEqual($0, 1) }
        endpoint.trustSnapshot { bytes in
            do {
                let trust = try AuthorityTrustCodec.decodeSnapshot(XCTUnwrap(bytes), expectedMacID: mac, expectedAccountID: account)
                XCTAssertEqual(trust.revision, revision)
            } catch { XCTFail("snapshot failed: \(error)") }
        }
        try journal.close()
        endpoint.trustSnapshot { XCTAssertNil($0) }
        endpoint.hello { XCTAssertEqual($0, 0) }
    }
    func testListenerRejectsWrongJournalScopeBeforeActivation() throws {
        let fixture = try Fixture(), journal = try owner(fixture)
        _ = try configure(journal)
        let policy = try XPCPeerPolicy(teamID: "ABCDEFGHIJ", componentIdentifier: "dev.sebastiano.remozio.macos.transport",
            approvedCodeDirectoryHashes: [Data(repeating: 1, count: 20)], expectedUserID: 501)
        XCTAssertThrowsError(try AuthorityXPCListener(serviceName: "dev.sebastiano.remozio.macos.authority", peerPolicy: policy,
            macID: Data(repeating: 9, count: 16), accountID: Data(repeating: 2, count: 16), journal: journal,
            maximumPayloadBytes: 1024)) { XCTAssertEqual($0 as? AuthorityXPCEndpointError, .invalidConfiguration) }
        try journal.close()
    }
    func testConcurrentSnapshotWaitsForTransactionAndSeesCommit() throws {
        let fixture = try Fixture(), journal = try owner(fixture)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let capabilities = ContractCapabilities(contracts: [contract: []])
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let attempted = DispatchSemaphore(value: 0), finished = DispatchSemaphore(value: 0)
        let writer = expectation(description: "write completes"), reader = expectation(description: "read completes")
        DispatchQueue.global().async {
            defer { writer.fulfill() }
            do {
                _ = try journal.write { tx in
                    let revision = try tx.configureApprovalAuthority(capabilities: capabilities, allowedContracts: [contract])
                    entered.signal()
                    guard release.wait(timeout: .now() + 5) == .success else { throw Failure.injected }
                    return revision
                }
            } catch { XCTFail("write failed: \(error)") }
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 2), .success)
        DispatchQueue.global().async {
            defer { finished.signal(); reader.fulfill() }
            attempted.signal()
            do {
                let trust = try journal.trustSnapshot(maximumPayloadBytes: 1024)
                XCTAssertTrue(trust.peers.isEmpty)
            } catch { XCTFail("read failed: \(error)") }
        }
        XCTAssertEqual(attempted.wait(timeout: .now() + 2), .success)
        XCTAssertEqual(finished.wait(timeout: .now() + 0.05), .timedOut)
        release.signal()
        wait(for: [writer, reader], timeout: 3)
        try journal.close()
    }
    func testTransportAccessRequiresRetainedActiveCodeMatchingTheConfiguredSignatureRequirement() throws {
        let fixture = try Fixture(), journal = try owner(fixture)
        _ = try configure(journal)
        defer { try? journal.close() }
        let peer = try transportPeer()
        XCTAssertThrowsError(try transportAccess(journal, peer: peer)) {
            XCTAssertEqual($0 as? AuthorityTransportAccessError, .unconfigured)
        }
        var stored = try install(transportEntry(active: false), journal: journal)
        XCTAssertThrowsError(try transportAccess(journal, peer: peer)) {
            XCTAssertEqual($0 as? AuthorityTransportAccessError, .policyMismatch)
        }
        stored = try install(transportEntry(), journal: journal, revision: stored.revision)
        let access = try transportAccess(journal, peer: peer)
        XCTAssertNoThrow(try access.verifyCurrent())
        XCTAssertTrue(try access.snapshot().peers.isEmpty)
        XCTAssertThrowsError(try transportAccess(journal, peer: transportPeer(hash: 9))) {
            XCTAssertEqual($0 as? AuthorityTransportAccessError, .policyMismatch)
        }
        let broad = try XPCPeerPolicy(teamID: "ABCDEFGHIJ", componentIdentifier: "dev.sebastiano.remozio.macos.transport",
            approvedCodeDirectoryHashes: [Data(repeating: 3, count: 20), Data(repeating: 9, count: 20)], expectedUserID: 501)
        XCTAssertThrowsError(try transportAccess(journal, peer: broad)) {
            XCTAssertEqual($0 as? AuthorityTransportAccessError, .policyMismatch)
        }
        XCTAssertEqual(try journal.read { try $0.codePolicy() }, stored)
    }

    func testEveryTransportOperationRejectsCommittedFloorGenerationHashOrActiveChanges() throws {
        let changes = [try transportEntry(minimum: 2), try transportEntry(installed: 3),
                       try transportEntry(hash: 9), try transportEntry(active: false)]
        for changed in changes {
            let fixture = try Fixture(), journal = try owner(fixture), revision = try configure(journal)
            let initial = try install(transportEntry(), journal: journal)
            let access = try transportAccess(journal, peer: transportPeer())
            let scope = try ChannelScope(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
                phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16))
            let binding = try AuthorityPeerBinding(scope: scope, transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation,
                revision: revision)
            XCTAssertFalse(try access.validate(binding))
            let endpoint = try AuthorityXPCEndpoint(macID: scope.macID, accountID: scope.accountID, budget: AuthorityXPCWorkBudget(),
                verify: {}, verifyHandshakePolicy: { try access.verifyCurrent() }, invalidate: {},
                snapshot: { try access.snapshot() }, validate: { try access.validate($0) })
            endpoint.hello { XCTAssertEqual($0, 1) }
            XCTAssertNoThrow(try access.verifyCurrent())
            _ = try install(changed, journal: journal, revision: initial.revision)
            // A prior guard success cannot authorize a later transaction after policy changes.
            for operation in [{ try access.verifyCurrent() }, { _ = try access.snapshot() }, { _ = try access.validate(binding) }] {
                XCTAssertThrowsError(try operation()) { XCTAssertEqual($0 as? AuthorityTransportAccessError, .policyMismatch) }
            }
            endpoint.trustSnapshot { XCTAssertNil($0) }
            endpoint.hello { XCTAssertEqual($0, 0) }
            if changed.active {
                let next = try transportAccess(journal, peer: transportPeer(hash: changed.codeDirectoryHash.first!))
                XCTAssertNoThrow(try next.verifyCurrent())
            }
            try journal.close()
        }
    }

    func testTransportPolicyABAInvalidatesPreTransitionListener() throws {
        for intermediate in [try transportEntry(active: false), try transportEntry(hash: 9)] {
            let fixture = try Fixture(), journal = try owner(fixture)
            _ = try configure(journal)
            let original = try transportEntry()
            let initial = try install(original, journal: journal)
            let access = try transportAccess(journal, peer: transportPeer())
            let changed = try install(intermediate, journal: journal, revision: initial.revision)
            let restored = try install(original, journal: journal, revision: changed.revision)
            XCTAssertEqual(restored.policy, initial.policy)
            XCTAssertNotEqual(restored.roleRevisions[.transport], initial.roleRevisions[.transport])
            XCTAssertNotEqual(restored.roleRevisions[.transport], changed.roleRevisions[.transport])
            XCTAssertThrowsError(try access.verifyCurrent()) { XCTAssertEqual($0 as? AuthorityTransportAccessError, .policyMismatch) }
            XCTAssertThrowsError(try access.snapshot()) { XCTAssertEqual($0 as? AuthorityTransportAccessError, .policyMismatch) }
            XCTAssertNoThrow(try transportAccess(journal, peer: transportPeer()).snapshot())
            try journal.close()
            let reopened = try owner(fixture, initialize: false)
            XCTAssertEqual(try reopened.read { try $0.codePolicy()?.roleRevisions }, restored.roleRevisions)
            try reopened.close()
        }
    }

    func testUnrelatedCodeUpdateAndRolledBackTransportUpdatePreserveAccess() throws {
        let fixture = try Fixture(), journal = try owner(fixture)
        _ = try configure(journal)
        let initial = try install(transportEntry(), journal: journal)
        let access = try transportAccess(journal, peer: transportPeer())
        let unrelated = try AuthorityCodeEntry(role: .tunnelClient, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.tunnel",
            installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: 8, count: 20), active: true)
        let policy = try AuthorityCodePolicy(entries: initial.policy.entries + [unrelated])
        let added = try journal.write { try $0.installCodePolicy(policy, expectedRevision: initial.revision) }
        XCTAssertEqual(added.roleRevisions[.transport], initial.roleRevisions[.transport])
        XCTAssertNoThrow(try access.verifyCurrent())
        XCTAssertTrue(try access.snapshot().peers.isEmpty)
        let changed = try AuthorityCodePolicy(entries: [transportEntry(minimum: 2), unrelated])
        XCTAssertThrowsError(try journal.write { transaction in
            _ = try transaction.installCodePolicy(changed, expectedRevision: added.revision)
            throw Failure.injected
        })
        XCTAssertNoThrow(try access.verifyCurrent())
        XCTAssertTrue(try access.snapshot().peers.isEmpty)
        try journal.close()
        XCTAssertThrowsError(try access.verifyCurrent()) { XCTAssertEqual($0 as? JournalDatabaseError, .closed) }
    }

    func testTransportReadWaitsForConcurrentPolicyCommitAndRejectsOldBinding() throws {
        let fixture = try Fixture(), journal = try owner(fixture)
        _ = try configure(journal)
        let initial = try install(transportEntry(), journal: journal)
        let access = try transportAccess(journal, peer: transportPeer())
        let next = try AuthorityCodePolicy(entries: [transportEntry(minimum: 2)])
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let attempted = DispatchSemaphore(value: 0), finished = DispatchSemaphore(value: 0)
        let writer = expectation(description: "policy commit"), reader = expectation(description: "old binding rejected")
        DispatchQueue.global().async {
            defer { writer.fulfill() }
            do {
                _ = try journal.write { transaction in
                    let value = try transaction.installCodePolicy(next, expectedRevision: initial.revision)
                    entered.signal()
                    guard release.wait(timeout: .now() + 5) == .success else { throw Failure.injected }
                    return value
                }
            } catch { XCTFail("policy write failed: \(error)") }
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 2), .success)
        DispatchQueue.global().async {
            defer { finished.signal(); reader.fulfill() }
            attempted.signal()
            do { _ = try access.snapshot(); XCTFail("obsolete policy served trust") }
            catch { XCTAssertEqual(error as? AuthorityTransportAccessError, .policyMismatch) }
        }
        XCTAssertEqual(attempted.wait(timeout: .now() + 2), .success)
        XCTAssertEqual(finished.wait(timeout: .now() + 0.05), .timedOut)
        release.signal()
        wait(for: [writer, reader], timeout: 3)
        try journal.close()
    }

    private func transportEntry(installed: UInt64 = 2, minimum: UInt64 = 1, hash: UInt8 = 3, active: Bool = true) throws -> AuthorityCodeEntry {
        try AuthorityCodeEntry(role: .transport, teamID: "ABCDEFGHIJ", identifier: "dev.sebastiano.remozio.macos.transport",
            installedGeneration: installed, minimumGeneration: minimum, codeDirectoryHash: Data(repeating: hash, count: 20), active: active)
    }
    private func install(_ entry: AuthorityCodeEntry, journal: AuthorityJournal, revision: UUID? = nil) throws -> AuthorityCodePolicySnapshot {
        let policy = try AuthorityCodePolicy(entries: [entry])
        return try journal.write { try $0.installCodePolicy(policy, expectedRevision: revision) }
    }
    private func transportPeer(hash: UInt8 = 3) throws -> XPCPeerPolicy {
        try XPCPeerPolicy(teamID: "ABCDEFGHIJ", componentIdentifier: "dev.sebastiano.remozio.macos.transport",
            approvedCodeDirectoryHashes: [Data(repeating: hash, count: 20)], expectedUserID: 501)
    }
    private func transportAccess(_ journal: AuthorityJournal, peer: XPCPeerPolicy) throws -> AuthorityTransportAccess {
        try AuthorityTransportAccess(journal: journal, peerPolicy: peer, macID: Data(repeating: 1, count: 16),
            accountID: Data(repeating: 2, count: 16), maximumPayloadBytes: 1024, minimumEnvelopeVersion: 1, auditVersions: [])
    }

    private final class Fixture {
        let root: URL
        var directory: String { root.appendingPathComponent("store").path }
        var path: String { directory + "/journal.sqlite" }
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw Failure.injected }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            for name in ["writer.lock", "journal.sqlite"] {
                let fd = Darwin.open(directory + "/" + name, O_CREAT | O_EXCL | O_WRONLY, 0o600)
                guard fd >= 0 else { throw JournalLeaseError.system(errno) }
                Darwin.close(fd)
            }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func lease() throws -> ProtectedJournalLease { try ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()) }
    }
}
