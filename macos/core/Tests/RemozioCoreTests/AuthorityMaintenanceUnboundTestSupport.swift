import Darwin
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

func unboundAuthorityBytes(_ value: UInt8, _ count: Int = 16) -> Data { Data(repeating: value, count: count) }

struct UnboundAuthorityRecords {
    typealias Row = RuntimeMaintenanceWindowRecord
    let authorized: Row, pending: Row
    let registration: UpdateAdmissionRegistrationRecord
    let gate: PreparationFileIdentity
    init(scope: Row.Scope? = nil, registration: UpdateAdmissionRegistrationRecord? = nil,
        windowID: Data = unboundAuthorityBytes(16)) throws {
        let scope = try scope ?? Row.Scope(macID: unboundAuthorityBytes(1), installationID: unboundAuthorityBytes(2),
            authority: .init(accountID: unboundAuthorityBytes(3), ownerUID: 501, directoryID: unboundAuthorityBytes(4)),
            target: .init(accountID: unboundAuthorityBytes(5), ownerUID: 1501, directoryID: unboundAuthorityBytes(6)),
            releaseDigest: unboundAuthorityBytes(7, 32), candidateDigest: unboundAuthorityBytes(8, 32),
            authorityPolicyDigest: unboundAuthorityBytes(9, 32), operationDigest: unboundAuthorityBytes(10, 32),
            restorationDigest: unboundAuthorityBytes(11, 32), mutationFootprintDigest: unboundAuthorityBytes(12, 32),
            authorityGrantDigest: unboundAuthorityBytes(13, 32), targetConsentDigest: unboundAuthorityBytes(14, 32),
            administratorIntentDigest: unboundAuthorityBytes(15, 32))
        authorized = try Row(id: windowID, revision: unboundAuthorityBytes(17), purpose: .retainedRuntime, scope: scope)
        let descriptor = try RuntimeMaintenanceUnboundRelease(authorized: authorized, previous: authorized,
            pendingRevision: unboundAuthorityBytes(18), intentID: unboundAuthorityBytes(19))
        pending = try Row(id: authorized.id, revision: descriptor.pendingRevision, purpose: .retainedRuntime,
            scope: scope, phase: .reopenPending, unboundRelease: descriptor)
        self.registration = try registration ?? .init(macID: scope.macID, installationID: scope.installationID,
            machine: .init(device: 1, inode: 1), accounts: [.init(accountID: scope.authority.accountID,
                identity: .init(device: 1, inode: 2))], designatedOwner: nil)
        gate = try XCTUnwrap(self.registration.accounts.first { $0.accountID == scope.authority.accountID }).identity
    }
    func projection(_ row: Row?) throws -> RuntimeMaintenanceAdmissionProjection {
        try .init(record: row, macID: authorized.scope.macID, installationID: authorized.scope.installationID,
            account: authorized.scope.authority, registration: registration)
    }
    func request(_ kind: AuthorityMaintenanceUnboundRequest.Kind, row: Row? = nil,
        incarnation: Data = unboundAuthorityBytes(41), gate: PreparationFileIdentity? = nil) throws -> AuthorityMaintenanceUnboundRequest {
        let row = row ?? pending, descriptor = try XCTUnwrap(row.unboundRelease)
        return try .init(kind: kind, installationID: row.scope.installationID, accountID: row.scope.authority.accountID,
            attemptID: row.id, revision: row.revision, rowDigest: RuntimeMaintenanceUnboundRelease.digest(row),
            pendingRevision: descriptor.pendingRevision, intentID: descriptor.intentID, gate: gate ?? self.gate,
            authorityIncarnation: incarnation, challenge: unboundAuthorityBytes(42))
    }
}

/// Real ordinary-owner SQLite and gates. The records and peer identity remain synthetic fixture inputs.
final class UnboundAuthorityMachine: @unchecked Sendable {
    private final class Reader: @unchecked Sendable {
        let fixture: RuntimeMaintenanceReaderFixture
        init(_ fixture: RuntimeMaintenanceReaderFixture) { self.fixture = fixture }
    }
    let fixture: RuntimeMaintenanceReaderFixture, records: UnboundAuthorityRecords
    let startup: AuthorityUpdateAdmissionStartup, hold: AuthorityMaintenanceAdmissionHold
    let commands = AuthorityMaintenanceCommandExclusion(), admission: AuthorityMaintenancePairingAdmission
    let reads = Mutex(0)
    let accountObserver: UpdateAdmissionBarrier
    private let activity: ReleaseActivityBarrier
    init(_ fixture: RuntimeMaintenanceReaderFixture, startupHeld: Bool) throws {
        self.fixture = fixture
        let reader = Reader(fixture)
        let snapshot = try fixture.machine().stableMachineUpdateSnapshot(candidate: fixture.candidate)
        let scope = try RuntimeMaintenanceWindowRecord.Scope(macID: snapshot.inventory.macID,
            installationID: snapshot.inventory.installationID, authority: fixture.authority,
            target: .init(accountID: unboundAuthorityBytes(92), ownerUID: 65001, directoryID: unboundAuthorityBytes(93)),
            releaseDigest: snapshot.inventory.releaseDigest, candidateDigest: unboundAuthorityBytes(1, 32),
            authorityPolicyDigest: unboundAuthorityBytes(2, 32), operationDigest: unboundAuthorityBytes(3, 32),
            restorationDigest: unboundAuthorityBytes(4, 32), mutationFootprintDigest: unboundAuthorityBytes(5, 32),
            authorityGrantDigest: unboundAuthorityBytes(6, 32), targetConsentDigest: unboundAuthorityBytes(7, 32),
            administratorIntentDigest: unboundAuthorityBytes(8, 32))
        records = try .init(scope: scope, registration: snapshot.admission)
        let parent = URL(fileURLWithPath: fixture.databasePath).deletingLastPathComponent()
        let anchor = parent.deletingLastPathComponent().path, name = parent.lastPathComponent
        func directory() throws -> ReleaseDestinationLease { try .init(anchor: anchor, relativeDirectory: name, owner: getuid()) }
        activity = try .init(directory: directory(), owner: getuid())
        let current = records.authorized
        try fixture.edit([RuntimeMaintenanceWindowStorage.createSQL, "PRAGMA user_version=29"])
        if startupHeld { try Self.insert(current, fixture: fixture) }
        startup = try XCTUnwrap(AuthorityUpdateAdmissionStartup.capture(machine: fixture.machine(), macID: scope.macID,
            installationID: scope.installationID, accountID: scope.authority.accountID, activity: activity,
            candidate: fixture.candidate, readCurrent: { try reader.fixture.machine().updateAdmissionState(candidate: reader.fixture.candidate) },
            readMaintenance: { $0.runtimeMaintenanceStartupProjection(account: reader.fixture.authority, candidate: reader.fixture.candidate) },
            openBarrier: { scope, identity in try .init(directory: directory(), owner: getuid(), expected: identity, scope: scope) }))
        hold = try XCTUnwrap(startup.maintenanceHold)
        accountObserver = try .init(directory: directory(), owner: getuid(), expected: records.gate, scope: .account(scope.authority.accountID))
        admission = try .init(accountID: scope.authority.accountID, incarnation: unboundAuthorityBytes(41))
        if startupHeld { try persist(records.pending) } else { try Self.insert(records.pending, fixture: fixture) }
    }
    private static func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
    private static func insert(_ row: RuntimeMaintenanceWindowRecord, fixture: RuntimeMaintenanceReaderFixture) throws {
        try fixture.mutate("INSERT INTO runtime_maintenance_windows_v1 VALUES(X'\(hex(row.scope.authority.accountID))',X'\(hex(row.id))',X'\(hex(row.revision))',\(row.phase.rawValue),X'\(try hex(row.encoded))')")
    }
    func persist(_ row: RuntimeMaintenanceWindowRecord) throws {
        try fixture.mutate("UPDATE runtime_maintenance_windows_v1 SET revision=X'\(Self.hex(row.revision))',phase=\(row.phase.rawValue),record=X'\(try Self.hex(row.encoded))'")
    }
    func operation(afterRead: (@Sendable (Int, RuntimeMaintenanceWindowRecord) throws -> Void)? = nil) throws -> AuthorityMaintenanceUnboundOperation {
        try .openOwned(admission: admission, commands: commands, hold: hold, boundary: startup.boundary,
            accountID: records.authorized.scope.authority.accountID, gateIdentity: records.gate,
            read: { [self] request, actual in
                let row = try fixture.machine().runtimeMaintenanceUnboundCommandRecord(request,
                    account: fixture.authority, incarnation: actual, candidate: fixture.candidate)
                let count = reads.withLock { $0 += 1; return $0 }
                try afterRead?(count, row); return row
            })
    }
    func close() { startup.recovery.close(); hold.close() }
}
