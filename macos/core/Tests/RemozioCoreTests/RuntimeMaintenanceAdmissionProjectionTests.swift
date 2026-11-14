import Foundation
import RemozioProtocol
import SQLite3
import XCTest
@testable import RemozioCore

final class RuntimeMaintenanceAdmissionProjectionTests: XCTestCase {
    private typealias Record = RuntimeMaintenanceWindowRecord
    private typealias Storage = RuntimeMaintenanceWindowStorage
    private typealias Projection = RuntimeMaintenanceAdmissionProjection
    private func data(_ byte: UInt8, _ count: Int = 16) -> Data { Data(repeating: byte, count: count) }
    private func account(_ other: Bool = false) throws -> Record.Account {
        try .init(accountID: data(other ? 31 : 11), ownerUID: other ? 2501 : 501, directoryID: data(other ? 32 : 12))
    }
    private func scope(mac: Data? = nil, installation: Data? = nil) throws -> Record.Scope {
        try .init(macID: mac ?? data(1), installationID: installation ?? data(2), authority: account(),
            target: .init(accountID: data(21), ownerUID: 1501, directoryID: data(22)),
            releaseDigest: data(31, 32), candidateDigest: data(32, 32), authorityPolicyDigest: data(33, 32),
            operationDigest: data(34, 32), restorationDigest: data(35, 32), mutationFootprintDigest: data(36, 32),
            authorityGrantDigest: data(37, 32), targetConsentDigest: data(38, 32), administratorIntentDigest: data(39, 32))
    }
    private let gateIdentity = PreparationFileIdentity(device: 9, inode: 91)
    private func record(_ phase: Record.Phase = .authorized, gate: PreparationFileIdentity? = nil,
                        mac: Data? = nil, installation: Data? = nil) throws -> Record {
        let early = [Record.Phase.authorized, .draining, .stopping, .stopped].contains(phase)
        let outcome: Record.OperationOutcome = phase == .executing ? .unknown : early ? .notStarted : .committed
        let readback: Record.GateReadback? = try (phase == .restored || gate != nil) ? .init(attemptID: data(3),
            requestRevision: data(4), identity: gate ?? gateIdentity, authorityIncarnation: data(5), challenge: data(6),
            responseDigest: data(7, 32), hold: .released, admission: .available) : nil
        return try .init(id: data(3), revision: data(4), purpose: .retainedRuntime, scope: scope(mac: mac, installation: installation),
            phase: phase, operation: outcome, service: [Record.Phase.reopenPending, .restored].contains(phase) ? .healthy : .unknown,
            failure: phase == .needsOwnerRecovery ? .healthFailed : nil, gate: readback)
    }
    private func registration(identity: PreparationFileIdentity? = nil, omitA: Bool = false,
                              mac: Data? = nil, installation: Data? = nil) throws -> UpdateAdmissionRegistrationRecord {
        var accounts: [UpdateAdmissionRegistrationRecord.Account] = [
            .init(accountID: data(31), identity: .init(device: 9, inode: 92))]
        if !omitA { accounts.append(.init(accountID: data(11), identity: identity ?? gateIdentity)) }
        return try .init(macID: mac ?? data(1), installationID: installation ?? data(2),
            machine: .init(device: 9, inode: 90), accounts: accounts, designatedOwner: nil)
    }
    private func projection(_ record: Record?, other: Bool = false,
                            registration: UpdateAdmissionRegistrationRecord? = nil) throws -> Projection {
        try .init(record: record, macID: data(1), installationID: data(2), account: account(other),
            registration: registration ?? self.registration())
    }
    func testEveryPhaseHoldsOnlyAUntilRestored() throws {
        for phase in Record.Phase.allCases {
            let value = try record(phase), a = try projection(value), other = try projection(value, other: true)
            XCTAssertEqual(a.requiresLocalHold, phase != .restored)
            XCTAssertEqual(a.attemptID, value.id); XCTAssertEqual(a.revision, value.revision)
            XCTAssertFalse(other.requiresLocalHold); XCTAssertNil(other.attemptID); XCTAssertNil(other.revision)
            XCTAssertEqual(a.description, "RuntimeMaintenanceAdmissionProjection(redacted)")
            XCTAssertEqual(a.debugDescription, a.description)
        }
        XCTAssertFalse(try projection(nil).requiresLocalHold)
        XCTAssertFalse(try projection(record(.reopenPending), other: true, registration: registration(omitA: true)).requiresLocalHold)
        XCTAssertTrue(try projection(record(.reopenPending)).requiresLocalHold)
    }
    func testMachineAccountAndGateMismatchesRefuseWithoutBlockingOtherAccounts() throws {
        for value in [try record(mac: data(99)), try record(installation: data(99))] {
            XCTAssertThrowsError(try projection(value))
        }
        for registration in [try registration(mac: data(99)), try registration(installation: data(99)),
                             try registration(omitA: true)] { XCTAssertThrowsError(try projection(record(), registration: registration)) }
        let wrongGate = PreparationFileIdentity(device: 9, inode: 93)
        for phase in Record.Phase.allCases {
            let value = try record(phase, gate: wrongGate)
            XCTAssertThrowsError(try projection(value)) { XCTAssertEqual($0 as? RuntimePreparationError, .changedScope) }
            XCTAssertFalse(try projection(value, other: true).requiresLocalHold)
        }
        for changed in [try Record.Account(accountID: data(11), ownerUID: 1001, directoryID: data(12)),
                        try Record.Account(accountID: data(11), ownerUID: 501, directoryID: data(99))] {
            XCTAssertThrowsError(try Projection(record: record(), macID: data(1), installationID: data(2),
                account: changed, registration: registration()))
        }
        XCTAssertThrowsError(try projection(record(.restored), registration: registration(identity: wrongGate)))
        XCTAssertFalse(try projection(nil, other: true, registration: registration(omitA: true)).requiresLocalHold)
    }
    func testStartupScopeFailureHoldsAAndExposesRecoveryWithoutThrowing() throws {
        for value in [try record(mac: data(99)), try record(installation: data(99)),
                      try record(.restored, gate: .init(device: 99, inode: 99))] {
            let actual = try Projection.startup(record: value, macID: data(1), installationID: data(2),
                account: account(), registration: registration())
            XCTAssertTrue(actual.requiresLocalHold); XCTAssertTrue(actual.needsOwnerRecovery)
            XCTAssertNil(actual.attemptID); XCTAssertNil(actual.revision)
        }
        let recovery = try projection(record(.needsOwnerRecovery))
        XCTAssertTrue(recovery.requiresLocalHold); XCTAssertTrue(recovery.needsOwnerRecovery)
        let other = try Projection.startup(record: record(.reopenPending), macID: data(1), installationID: data(2),
            account: account(true), registration: registration(omitA: true))
        XCTAssertFalse(other.requiresLocalHold); XCTAssertFalse(other.needsOwnerRecovery)
    }
    func testIndexedReaderRequiresExactCanonicalRecordAndColumns() throws {
        let value = try record(.draining), encoded = try value.encoded
        func read(account: Data? = nil, attempt: Data? = nil, revision: Data? = nil,
                  phase: UInt64? = nil, bytes: Data? = nil) throws -> Record {
            try Storage.decode(accountID: account ?? value.scope.authority.accountID, attemptID: attempt ?? value.id,
                revision: revision ?? value.revision, phase: phase ?? value.phase.rawValue, bytes: bytes ?? encoded)
        }
        XCTAssertEqual(try read(), value)
        XCTAssertThrowsError(try read(account: data(21)))
        XCTAssertThrowsError(try read(attempt: data(99))); XCTAssertThrowsError(try read(revision: data(99)))
        for phase in [UInt64(0), 1, 11, .max] { XCTAssertThrowsError(try read(phase: phase)) }
        for bytes in [Data(), Data(encoded.dropLast()), encoded + Data([0]), data(0, 4097)] {
            XCTAssertThrowsError(try read(bytes: bytes)) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
        }
        let nonminimal = Data([0xab, 0, 0x18, 1]) + encoded.dropFirst(3)
        XCTAssertThrowsError(try read(bytes: nonminimal))
        for phase in Record.Phase.allCases {
            let current = try record(phase)
            XCTAssertEqual(try Storage.decode(accountID: current.scope.authority.accountID, attemptID: current.id,
                revision: current.revision, phase: phase.rawValue, bytes: current.encoded), current)
        }
    }
    func testReaderDeclarationsRequireBothRolesAndPreviousFormats() throws {
        let all = try Storage.readerRequirements + MachineUpdateRetainedSetupPromotionReadyStorage.readerRequirements
            + MachineUpdateRetainedSetupPromotionStorage.readerRequirements + MachineUpdateRetainedSetupCompletionStorage.readerRequirements
        func candidate(omitRole: AuthorityCodeRole? = nil, omitName: String? = nil,
                       omitVersion: UInt64? = nil) throws -> SignedReleaseEvidence {
            let roles: [AuthorityCodeRole] = [.app, .authority, .setupController]
            let components = try roles.filter { $0 == .app || omitName != nil || $0 != omitRole }.map { role in
                var formats: [ReleaseFormat] = []
                for name in Set(all.filter { $0.role == role }.map(\.name)).sorted() {
                    if omitRole == role && omitName == name && omitVersion == nil { continue }
                    var readers = Set(all.filter { $0.role == role && $0.name == name }.flatMap(\.readVersions))
                    if omitRole == role && omitName == name, let omitVersion { readers.remove(omitVersion) }
                    if readers.isEmpty { readers = [99] }
                    formats.append(try .init(name: name, readers: readers, writers: []))
                }
                return try ReleaseComponent(role: role, identifier: "dev.sebastiano.remozio.test-role-\(role.rawValue)",
                    generation: 4, relativePath: "Contents/Helpers/role-\(role.rawValue)",
                    codeDirectoryHash: role == .app ? nil : data(1, 20), build: "4", teamID: "ABCDEFGHIJ", formats: formats, requests: [])
            }
            return SignedReleaseEvidence(manifest: try .init(release: "0.1.0", build: "4", components: components),
                codeDirectoryHashes: [.app: data(1, 20), .authority: data(1, 20), .setupController: data(1, 20)])
        }
        try Storage.requireReaderFormats(candidate())
        for role in [AuthorityCodeRole.authority, .setupController] {
            XCTAssertThrowsError(try Storage.requireReaderFormats(candidate(omitRole: role)))
            for name in ["authority.installation-preparation", Record.formatName] {
                XCTAssertThrowsError(try Storage.requireReaderFormats(candidate(omitRole: role, omitName: name)))
            }
            for version in UInt64(26)...29 {
                XCTAssertThrowsError(try Storage.requireReaderFormats(candidate(omitRole: role,
                    omitName: "authority.installation-preparation", omitVersion: version)))
            }
        }
        XCTAssertEqual(Storage.schemaVersion, 29)
        XCTAssertTrue(PreparationIntentStore.supportedSchemaVersions.contains(Storage.schemaVersion))
    }
    func testDeclaredSQLBoundsAndUniqueAttemptsAndRevisions() throws {
        var db: OpaquePointer?
        XCTAssertEqual(sqlite3_open(":memory:", &db), SQLITE_OK); defer { sqlite3_close(db) }
        XCTAssertEqual(sqlite3_exec(db, Storage.createSQL, nil, nil, nil), SQLITE_OK)
        func insert(account: Int = 16, attempt: Int = 16, revision: Int = 16, phase: Int = 1, record: Int = 1) -> Int32 {
            sqlite3_exec(db, "INSERT INTO \(Storage.tableName) VALUES(zeroblob(\(account)),zeroblob(\(attempt)),zeroblob(\(revision)),\(phase),zeroblob(\(record)))", nil, nil, nil)
        }
        XCTAssertEqual(insert(), SQLITE_OK)
        let other = "x'01010101010101010101010101010101'"
        XCTAssertEqual(sqlite3_exec(db, "INSERT INTO \(Storage.tableName) VALUES(\(other),zeroblob(16),\(other),1,zeroblob(1))", nil, nil, nil), SQLITE_CONSTRAINT)
        XCTAssertEqual(sqlite3_exec(db, "INSERT INTO \(Storage.tableName) VALUES(\(other),\(other),zeroblob(16),1,zeroblob(1))", nil, nil, nil), SQLITE_CONSTRAINT)
        for sizes in [(15, 16, 16, 1, 1), (16, 15, 16, 1, 1), (16, 16, 15, 1, 1),
                      (16, 16, 16, 0, 1), (16, 16, 16, 11, 1), (16, 16, 16, 1, 0), (16, 16, 16, 1, 4097)] {
            XCTAssertEqual(sqlite3_exec(db, "DELETE FROM \(Storage.tableName)", nil, nil, nil), SQLITE_OK)
            XCTAssertEqual(insert(account: sizes.0, attempt: sizes.1, revision: sizes.2, phase: sizes.3, record: sizes.4), SQLITE_CONSTRAINT)
        }
        XCTAssertEqual(Record.limits.maxBytes, 4096)
    }
}
