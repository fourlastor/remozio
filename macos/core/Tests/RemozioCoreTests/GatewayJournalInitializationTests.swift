import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class GatewayJournalInitializationTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Fixture {
        let root: URL
        let parent: ProtectedSetupDirectory
        let files: GatewayJournalFileIdentity
        let registration: GatewayRegistrationIdentity
        let key = P256.Signing.PrivateKey()
        let epoch = UUID()
        var path: String { parent.path + "/Gateway/gateway.sqlite" }
        var limits: CBORLimits { get throws { try .init(maxBytes: 65536, maxDepth: 8, maxItems: 256) } }
        init() throws {
            guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner gateway initialization fixture") }
            root = URL(fileURLWithPath: "/private/tmp/remozio-gateway-initialize-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            parent = try .init(anchor: root.path, relativePath: "Service", owner: getuid(), visibility: .sharedMetadata)
            files = try GatewayJournalFileProvisioning.prepare(parent: parent, processOwner: getuid(), serviceUID: getuid(), serviceGID: getgid(),
                mode: .createIfAbsent, expected: nil, verifyCurrent: {}).identity
            registration = try .init(ownerID: Data(repeating: 1, count: 16), macID: Data(repeating: 2, count: 16),
                accountID: Data(repeating: 3, count: 16), gatewayID: Data(repeating: 4, count: 16), lifecycleEpoch: Data(repeating: 5, count: 16),
                rootPublicKey: key.publicKey.x963Representation)
        }
        deinit { parent.close(); try? FileManager.default.removeItem(at: root) }
        func lease() throws -> ProtectedGatewayLease {
            try .init(anchor: root.path, relativeDirectory: "Service/Gateway", serviceUID: getuid(), ancestorUID: getuid())
        }
        func open(_ initialize: Bool) throws -> GatewayDatabase {
            let lease = try lease()
            do {
                guard try lease.fileIdentity() == files else { throw JournalLeaseError.identityChanged }
                return try .init(lease: lease, identity: registration, payloadLimits: limits, signingLimits: limits,
                    maximumOperations: 10, maximumPendingPerEnrollment: 2, maximumLifetimeMillis: 1000,
                    clockEpoch: epoch, busyMilliseconds: 100, initialize: initialize)
            } catch { lease.close(); throw error }
        }
        func resume(_ allowed: Bool, verify: () throws -> Void = {},
                    stage: (GatewayJournalInitialization.Stage) throws -> Void = { _ in }) throws -> GatewayJournalInitialization.Result {
            try GatewayJournalInitialization.resume(registration: registration, mayInitializeEmpty: allowed,
                verifyCurrent: verify, openJournal: open, didStage: stage)
        }
        func sql(_ sql: String) throws -> Int64 {
            var db: OpaquePointer?
            guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK, let db else { throw Interrupted() }
            defer { sqlite3_close(db) }
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else { throw Interrupted() }
            defer { sqlite3_finalize(stmt) }
            let rc = sqlite3_step(stmt); guard rc == SQLITE_ROW || rc == SQLITE_DONE else { throw Interrupted() }
            return sqlite3_column_int64(stmt, 0)
        }
    }
    private func bytes(_ value: UInt8, _ count: Int = 16) -> Data { Data(repeating: value, count: count) }

    func testEmptyInitializationRequiresPermissionAndReopeningPreservesIdentity() throws {
        let f = try Fixture()
        XCTAssertThrowsError(try f.resume(false)) { XCTAssertEqual($0 as? GatewayDatabaseError, .incompatibleStore) }
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.path)).count, 0)
        let first = try f.resume(true)
        XCTAssertTrue(first.initialized); XCTAssertEqual(first.head.registration, f.registration); XCTAssertEqual(first.head.revision, 0)
        let retained = try f.resume(false)
        XCTAssertFalse(retained.initialized); XCTAssertEqual(retained.head.revision, 0)
        let lease = try f.lease(); defer { lease.close() }
        XCTAssertEqual(try lease.fileIdentity(), f.files)
    }
    func testLostCompletionReplyRetainsTheCommittedJournalAndReleasesItsWriter() throws {
        for stage in 0...1 {
            let f = try Fixture()
            XCTAssertThrowsError(try f.resume(true, stage: {
                switch (stage, $0) { case (0, .opened), (1, .closed): throw Interrupted(); default: break }
            })) { XCTAssertTrue($0 is Interrupted) }
            let next = try f.resume(false)
            XCTAssertFalse(next.initialized); XCTAssertEqual(next.head.revision, 0)
        }
    }
    func testExistingSignedHistoryCannotBeResetEvenWhenInitializationIsAllowed() throws {
        let f = try Fixture(); _ = try f.resume(true)
        let binding = try GatewayTokenBinding(ownerID: f.registration.ownerID, macID: f.registration.macID, accountID: f.registration.accountID,
            gatewayID: f.registration.gatewayID, lifecycleEpoch: f.registration.lifecycleEpoch, phoneID: bytes(6), enrollmentEpoch: bytes(7),
            candidateID: bytes(8), tokenDigest: Data(SHA256.hash(data: Data("synthetic-token".utf8))), challenge: bytes(9, 32), enrollmentTag: bytes(10, 32))
        let candidate = try GatewayTokenCandidate(binding: binding, revision: 1, operationID: bytes(11), issuedAtUnixMillis: 1000, expiresAtUnixMillis: 2000)
        let payload = try candidate.encode(limits: f.limits)
        let signature = try f.key.signature(for: GatewayTokenCandidateSigningInput.make(wireVersion: 1, canonicalPayload: payload,
            payloadLimits: f.limits, inputLimits: f.limits)).rawRepresentation
        let trust = try GatewayCandidateTrust(ownerID: f.registration.ownerID, macID: f.registration.macID, accountID: f.registration.accountID,
            gatewayID: f.registration.gatewayID, lifecycleEpoch: f.registration.lifecycleEpoch, rootPublicKey: f.registration.rootPublicKey,
            active: true, revision: UUID(), appliedControlRevision: 0,
            enrollment: GatewayPhoneEnrollment(phoneID: binding.phoneID, epoch: binding.enrollmentEpoch, tag: binding.enrollmentTag, active: true))
        let db = try f.open(false)
        _ = try db.admitCandidate(canonicalPayload: payload, signature: signature, wireVersion: 1, registrationToken: "synthetic-token", trust: trust,
            nowUnixMillis: 1000, now: AuthorityMoment(epoch: f.epoch, milliseconds: 100))
        try db.close()
        let resumed = try f.resume(true)
        XCTAssertFalse(resumed.initialized); XCTAssertEqual(resumed.head.revision, 1)
        XCTAssertEqual(try f.sql("SELECT COUNT(*) FROM gateway_candidates_v1"), 1)
        let reopened = try f.open(false); defer { try? reopened.close() }
        XCTAssertEqual(try reopened.receipt(operationID: candidate.operationID)?.canonicalPayload, payload)
    }
    func testIncompatibleNonemptyStoreAndForeignRegistrationAreNeverReinitialized() throws {
        let f = try Fixture()
        _ = try f.sql("CREATE TABLE retained_fixture(value INTEGER)")
        _ = try f.sql("INSERT INTO retained_fixture VALUES(47)")
        _ = try f.sql("PRAGMA user_version=999")
        XCTAssertThrowsError(try f.resume(true)) { XCTAssertEqual($0 as? GatewayDatabaseError, .incompatibleStore) }
        XCTAssertEqual(try f.sql("PRAGMA user_version"), 999); XCTAssertEqual(try f.sql("SELECT value FROM retained_fixture"), 47)
        let other = try Fixture(); _ = try other.resume(true)
        let changed = try GatewayRegistrationIdentity(ownerID: bytes(99), macID: other.registration.macID, accountID: other.registration.accountID,
            gatewayID: other.registration.gatewayID, lifecycleEpoch: other.registration.lifecycleEpoch, rootPublicKey: other.registration.rootPublicKey)
        XCTAssertThrowsError(try GatewayJournalInitialization.resume(registration: changed, mayInitializeEmpty: true,
            verifyCurrent: {}, openJournal: { initialize in
                let lease = try other.lease()
                return try GatewayDatabase(lease: lease, identity: changed, payloadLimits: other.limits, signingLimits: other.limits,
                    maximumOperations: 10, maximumPendingPerEnrollment: 2, maximumLifetimeMillis: 1000,
                    clockEpoch: other.epoch, busyMilliseconds: 100, initialize: initialize)
            })) { XCTAssertEqual($0 as? GatewayDatabaseError, .wrongScope) }
        XCTAssertEqual(try other.resume(false).head.registration, other.registration)
    }
    func testReplacementBetweenOpenAndInitializationCannotPassTheRetainedIdentity() throws {
        let f = try Fixture(); var attempts = 0
        XCTAssertThrowsError(try GatewayJournalInitialization.resume(registration: f.registration, mayInitializeEmpty: true, verifyCurrent: {},
            openJournal: { initialize in
                attempts += 1
                if initialize {
                    try FileManager.default.moveItem(atPath: f.path, toPath: f.path + ".original")
                    XCTAssertTrue(FileManager.default.createFile(atPath: f.path, contents: Data(), attributes: [.posixPermissions: 0o600]))
                }
                return try f.open(initialize)
            })) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertEqual(attempts, 2)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.path)).count, 0)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.path + ".original")).count, 0)
    }
    func testMissingFilesOrBusyWriterNeverTriggerInitialization() throws {
        let f = try Fixture(); let lease = try f.lease(); var attempts = 0
        XCTAssertThrowsError(try GatewayJournalInitialization.resume(registration: f.registration, mayInitializeEmpty: true,
            verifyCurrent: {}, openJournal: { value in attempts += 1; return try f.open(value) })) {
            XCTAssertEqual($0 as? JournalLeaseError, .busy)
        }
        XCTAssertEqual(attempts, 1); lease.close()
        try FileManager.default.removeItem(atPath: f.path)
        XCTAssertThrowsError(try f.resume(true))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.path))
    }
    func testScopeFailureBeforeOpenOrFallbackCannotInitialize() throws {
        let f = try Fixture(); var reads = 0, opens = 0
        XCTAssertThrowsError(try GatewayJournalInitialization.resume(registration: f.registration, mayInitializeEmpty: true,
            verifyCurrent: { reads += 1; if reads == 2 { throw Interrupted() } },
            openJournal: { initialize in opens += 1; return try f.open(initialize) })) { XCTAssertTrue($0 is Interrupted) }
        XCTAssertEqual(opens, 1); XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.path)).count, 0)
    }
    func testNativeEntryRefusesTheForegroundUserBeforeAnyStorageAccess() throws {
        let f = try RuntimeActivationFixture(), reference = try f.material.reference
        let settings = try GatewayServiceSettings(delivery: .init(maximumFlights: 4, minimumSendIntervalMillis: 1000),
            probe: .init(maximumAttempts: 3, minimumRetryDelayMillis: 1000, maximumTTLSeconds: 300),
            wake: .init(maximumEntries: 32, maximumAttempts: 3, minimumEnrollmentIntervalMillis: 1000,
                maximumLifetimeMillis: 300000, maximumTTLSeconds: 300))
        let config = try GatewayServiceConfiguration(registration: reference.gateway, receiptPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            directoryPath: "/Library/Remozio/unused", providerPath: "/Library/Remozio/provider.json", receiptKeyPath: "/Library/Remozio/receipt.cbor",
            serviceUID: f.services.claims.first(where: { $0.role == .gateway })!.number, ownerUID: f.account.ownerUID,
            serviceName: "dev.remozio.fixture.gateway", teamID: "ABCDEFGHIJ", authorityIdentifier: "dev.remozio.authority",
            authorityHashes: [Data(repeating: 1, count: 20)], project: "synthetic-project", packageName: "dev.remozio.android", settings: settings)
        let identity = GatewayJournalFileIdentity(directory: .init(device: 0, inode: 0), writer: .init(device: 0, inode: 0), database: .init(device: 0, inode: 0))
        XCTAssertThrowsError(try GatewayJournalInitialization.resume(configuration: config, expected: identity, mayInitializeEmpty: true)) {
            XCTAssertEqual($0 as? GatewayServiceError, .wrongAccount)
        }
    }
}
