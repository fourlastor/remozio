import Foundation
import XCTest
@testable import RemozioCore

/// A real owned SQLite store supplies the observation scope. These rows do not prove a native writer or peer.
final class AuthorityMaintenanceGateReaderTests: XCTestCase {
    func testProtectedReadbackRequiresExactPendingRevisionBindingAndGateWithoutChangingRows() throws {
        try MachineUpdateReplacementTests.withMaintenanceReaderFixture(releasingRestartAdmission: true) { f in
            let before = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            func bytes(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
            func hex(_ value: Data) -> String { value.map { String(format: "%02x", $0) }.joined() }
            let identity = try XCTUnwrap(before.admission.accounts.first { $0.accountID == f.authority.accountID }).identity
            let target = try AuthorityMaintenanceBinding(accountID: f.authority.accountID, attemptID: bytes(10), revision: bytes(11),
                incarnation: bytes(12), connectionID: bytes(13))
            let scope = try RuntimeMaintenanceWindowRecord.Scope(macID: before.inventory.macID, installationID: before.inventory.installationID,
                authority: f.authority, target: .init(accountID: bytes(14), ownerUID: 65001, directoryID: bytes(15)),
                releaseDigest: before.inventory.releaseDigest, candidateDigest: bytes(1, 32), authorityPolicyDigest: bytes(2, 32),
                operationDigest: bytes(3, 32), restorationDigest: bytes(4, 32), mutationFootprintDigest: bytes(5, 32),
                authorityGrantDigest: bytes(6, 32), targetConsentDigest: bytes(7, 32), administratorIntentDigest: bytes(8, 32))
            let row = try RuntimeMaintenanceWindowRecord(id: target.attemptID, revision: bytes(16), purpose: .retainedRuntime,
                scope: scope, phase: .reopenPending, service: .notStopped, shutdownBinding: target)
            try f.edit([RuntimeMaintenanceWindowStorage.createSQL, "PRAGMA user_version=29",
                "INSERT INTO runtime_maintenance_windows_v1 VALUES(X'\(hex(f.authority.accountID))',X'\(hex(row.id))',X'\(hex(row.revision))',\(row.phase.rawValue),X'\(try hex(row.encoded))')"])
            func request(revision: Data? = nil, gate: PreparationFileIdentity? = nil, binding: AuthorityMaintenanceBinding? = nil) throws -> AuthorityMaintenanceGateRequest {
                try .init(accountID: f.authority.accountID, attemptID: row.id, revision: revision ?? row.revision,
                    installationID: scope.installationID, gate: gate ?? identity, target: binding ?? target, challenge: bytes(17))
            }
            let rows = try runtimeMaintenanceFixtureRows(f.databasePath)
            XCTAssertEqual(try f.machine().runtimeMaintenanceGateRecord(request(), account: f.authority, candidate: f.candidate), row)
            let foreign = try AuthorityMaintenanceBinding(accountID: target.accountID, attemptID: target.attemptID, revision: target.revision,
                incarnation: bytes(99), connectionID: target.connectionID)
            for q in [try request(revision: target.revision), try request(gate: .init(device: identity.device, inode: identity.inode + 1)),
                      try request(binding: foreign)] {
                XCTAssertThrowsError(try f.machine().runtimeMaintenanceGateRecord(q, account: f.authority, candidate: f.candidate))
            }
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), rows)
        }
    }
}
